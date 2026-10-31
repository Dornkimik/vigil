//! Admin mode. A small part of Vigil runs as SYSTEM, started at boot by a scheduled task,
//! and does one thing: it reports every program the moment it starts. Windows only hands
//! out those events (ETW, Microsoft-Windows-Kernel-Process) to administrators.
//!
//! The helper writes process IDs to a pipe that only carries data out of it, so nothing can
//! send it input, and it never opens a file. Scanning stays in the normal, unprivileged
//! Vigil, which reads the pipe (`daemon::procwatch::listen`).
//!
//! The task runs a copy in Program Files, which only administrators can change. Pointing it
//! at vigil.exe wherever the user keeps it would let anything that can write there run as SYSTEM.
//!
//! A second task starts Vigil itself at login, with the user's own rights. Windows skips the
//! Run key's startup programs after some logons; Task Scheduler doesn't depend on that.

use crate::winapi::{self, CREATE_NO_WINDOW, wide};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;
use windows_sys::core::GUID;

pub const PIPE: &str = r"\\.\pipe\Vigil.ProcessEvents";
const TASK: &str = r"\Vigil\Process events";
const LOGIN_TASK: &str = r"\Vigil\Start at login";
const SESSION: &str = "Vigil Process Events";
const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const KEYWORD_PROCESS: u64 = 0x10;
const PROCESS_START: u16 = 1;
/// `FlushTimer` counts milliseconds. Real-time events otherwise sit in their buffer for up
/// to a second when few arrive.
const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x10;
const FLUSH_MS: u32 = 10;

/// Exit codes of `--admin-mode`, run elevated.
const DONE: u32 = 0;
const COPY_FAILED: u32 = 2;
const TASK_FAILED: u32 = 3;
const LOGIN_TASK_FAILED: u32 = 4;

/// Connected readers' pipe handles (stored as integers: raw handles aren't `Send`).
static READERS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Where the task runs Vigil from.
pub fn helper_path() -> PathBuf {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")).unwrap_or_else(|| r"C:\Program Files".into());
    PathBuf::from(base).join("Vigil").join("vigil.exe")
}

/// Whether admin mode is turned on (its copy in Program Files exists).
pub fn installed() -> bool {
    helper_path().is_file()
}

// ------------------------------------------------------------------ turning it on and off

/// Turns admin mode on or off, asking for admin approval (UAC) when not elevated already.
pub fn set(enabled: bool) -> Result<(), String> {
    let arg = if enabled { "on" } else { "off" };
    // The approval may come from another account; the login task is for this one.
    let user = winapi::user_sid().unwrap_or_default();
    let code = if winapi::is_elevated() {
        apply(enabled, Some(user))
    } else {
        winapi::run_elevated(&["--admin-mode", arg, &user]).ok_or("Admin approval was declined.")?
    };
    match code {
        DONE => Ok(()),
        COPY_FAILED => Err(format!("Could not copy Vigil to {}.", helper_path().display())),
        TASK_FAILED => Err("Could not set up the scheduled task that starts admin mode.".into()),
        LOGIN_TASK_FAILED => Err("Admin mode is on, but the task that starts Vigil at login could not be set up.".into()),
        c => Err(format!("Admin mode setup failed (code {c}).")),
    }
}

/// `vigil.exe --admin-mode on|off [user SID]`. Elevated, it does the work and exits with its
/// code for the instance that asked; otherwise it asks for approval first.
pub fn cli(args: &[String]) -> i32 {
    let enabled = match args.first().map(String::as_str) {
        Some("on") => true,
        Some("off") => false,
        _ => return 1,
    };
    if winapi::is_elevated() {
        let user = args.get(1).cloned().filter(|s| is_sid(s)).or_else(winapi::user_sid);
        return apply(enabled, user) as i32;
    }
    winapi::attach_parent_console();
    match set(enabled) {
        Ok(()) => {
            println!("Admin mode is {}.", if enabled { "on" } else { "off" });
            0
        }
        Err(e) => {
            println!("{e}");
            1
        }
    }
}

/// A security identifier like `S-1-5-21-…`, and nothing that could break out of the task XML.
fn is_sid(s: &str) -> bool {
    s.strip_prefix("S-1-").is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

/// `user` is the account whose Vigil the login task starts.
fn apply(enabled: bool, user: Option<String>) -> u32 {
    stop_helper();
    let helper = helper_path();
    if !enabled {
        let _ = schtasks(&["/delete", "/tn", TASK, "/f"]);
        let _ = schtasks(&["/delete", "/tn", LOGIN_TASK, "/f"]);
        // The helper's file stays locked for a moment after it exits.
        for _ in 0..20 {
            if !helper.exists() || std::fs::remove_file(&helper).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if let Some(dir) = helper.parent() {
            let _ = std::fs::remove_dir(dir);
        }
        return DONE;
    }
    let Ok(exe) = std::env::current_exe() else { return COPY_FAILED };
    if !helper.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok()) {
        return COPY_FAILED;
    }
    // An older helper may still be exiting and holding its file.
    let mut copied = false;
    for _ in 0..20 {
        copied = std::fs::copy(&exe, &helper).is_ok();
        if copied {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    if !copied {
        return COPY_FAILED;
    }
    if !register(TASK, &helper_task_xml(&helper)) || !schtasks(&["/run", "/tn", TASK]) {
        return TASK_FAILED;
    }
    match user.filter(|u| is_sid(u)) {
        Some(user) if register(LOGIN_TASK, &login_task_xml(&helper, &user)) => DONE,
        _ => LOGIN_TASK_FAILED,
    }
}

/// Creates or replaces a scheduled task from its XML definition.
fn register(name: &str, definition: &str) -> bool {
    // Next to the helper: only administrators can write there, so the definition can't be swapped.
    let xml = helper_path().with_file_name("task.xml");
    let utf16: Vec<u8> = [0xFEFF].into_iter().chain(definition.encode_utf16()).flat_map(u16::to_le_bytes).collect();
    let created = std::fs::write(&xml, utf16).is_ok() && schtasks(&["/create", "/tn", name, "/xml", &xml.to_string_lossy(), "/f"]);
    let _ = std::fs::remove_file(&xml);
    created
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Starts Vigil when `user` logs on, with their own rights, through the protected copy (see
/// [`logon`]). Normal priority: Vigil's tray and scans set their own.
fn login_task_xml(helper: &std::path::Path, user: &str) -> String {
    let command = xml_escape(&helper.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Vigil admin mode: starts Vigil at login, also when Windows skips its startup programs.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="User"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="User"><Exec><Command>{command}</Command><Arguments>--logon</Arguments></Exec></Actions>
</Task>
"#
    )
}

/// `vigil.exe --logon`, run by the login task as the user: starts Vigil the way its autostart
/// entry says. The entry decides: it is gone when autostart is turned off in Settings, and it
/// names the vigil.exe the user runs. When Windows does run the entry too, the second Vigil
/// finds the first one running and exits.
pub fn logon() -> i32 {
    let Some(command) = winapi::autostart_command() else { return 0 };
    if winapi::NamedMutex::exists(crate::daemon::DAEMON_MUTEX) {
        return 0;
    }
    let args = winapi::split_args(&command);
    let Some((exe, rest)) = args.split_first() else { return 1 };
    // Task Scheduler may keep its programs in a job; Vigil has to outlive this launcher.
    let spawn = |flags| Command::new(exe).args(rest).creation_flags(flags).spawn();
    match spawn(CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(0)) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// The helper's task: SYSTEM, at boot, never stopped for running long or for battery power,
/// restarted if it fails.
fn helper_task_xml(helper: &std::path::Path) -> String {
    let command = xml_escape(&helper.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Vigil admin mode: reports each program the moment it starts.</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>10</Count></RestartOnFailure>
  </Settings>
  <Actions Context="System"><Exec><Command>{command}</Command><Arguments>--process-events</Arguments></Exec></Actions>
</Task>
"#
    )
}

/// Runs Windows' own schtasks.exe by full path: this runs elevated, so PATH can't choose it.
fn schtasks(args: &[&str]) -> bool {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Command::new(PathBuf::from(root).join(r"System32\schtasks.exe"))
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .is_ok_and(|s| s.success())
}

/// Ends the helper's event session, which makes a running helper exit.
fn stop_helper() {
    let _ = schtasks(&["/end", "/tn", TASK]);
    unsafe {
        let mut props = Properties::new();
        ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, props.name.as_ptr(), props.ptr(), EVENT_TRACE_CONTROL_STOP);
    }
}

// ------------------------------------------------------------------ the helper

/// `vigil.exe --process-events`: the part that runs as SYSTEM.
pub fn run_helper() -> i32 {
    // Only one helper. If the name is taken, another helper runs, or something tries to pose as one.
    let Some(first) = create_pipe(true) else { return 1 };
    let first = first as usize;
    thread::spawn(move || accept(first as HANDLE));
    unsafe { trace() as i32 }
}

fn create_pipe(first: bool) -> Option<HANDLE> {
    let name = wide(PIPE);
    let mode = PIPE_ACCESS_OUTBOUND | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // The default security lets everyone read and only administrators write.
    let h = unsafe {
        CreateNamedPipeW(name.as_ptr(), mode, PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 64 << 10, 0, 0, null())
    };
    (h != INVALID_HANDLE_VALUE).then_some(h)
}

/// Waits for readers, one pipe instance each.
fn accept(mut pipe: HANDLE) {
    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED };
        if connected {
            // A reader that stops reading loses events instead of holding up the others.
            let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
            unsafe { SetNamedPipeHandleState(pipe, &mode, null(), null()) };
            READERS.lock().unwrap().push(pipe as usize);
        } else {
            unsafe { CloseHandle(pipe) };
        }
        pipe = loop {
            match create_pipe(false) {
                Some(p) => break p,
                None => thread::sleep(Duration::from_secs(1)),
            }
        };
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let r = unsafe { &*record };
    let p = &r.EventHeader.ProviderId;
    let ours = (p.data1, p.data2, p.data3, p.data4) == (KERNEL_PROCESS.data1, KERNEL_PROCESS.data2, KERNEL_PROCESS.data3, KERNEL_PROCESS.data4);
    if !ours || r.EventHeader.EventDescriptor.Id != PROCESS_START || r.UserDataLength < 4 || r.UserData.is_null() {
        return;
    }
    // ProcessStart's first field is the new process's ID, in every version of the event.
    let pid = unsafe { std::ptr::read_unaligned(r.UserData as *const u32) }.to_le_bytes();
    // A full pipe drops the message and still succeeds; a failed write means the reader is gone.
    READERS.lock().unwrap().retain(|&h| unsafe {
        let mut written = 0;
        let ok = WriteFile(h as HANDLE, pid.as_ptr(), 4, &mut written, null_mut()) != 0;
        if !ok {
            DisconnectNamedPipe(h as HANDLE);
            CloseHandle(h as HANDLE);
        }
        ok
    });
}

/// EVENT_TRACE_PROPERTIES followed by the session name, as StartTrace wants them.
#[repr(C)]
struct Properties {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; 64],
}

impl Properties {
    fn new() -> Box<Self> {
        let mut p: Box<Self> = Box::new(unsafe { std::mem::zeroed() });
        let name = wide(SESSION);
        p.name[..name.len()].copy_from_slice(&name);
        p.props.Wnode.BufferSize = size_of::<Self>() as u32;
        p.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p.props.Wnode.ClientContext = 1;
        p.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_MS_FLUSH_TIMER;
        p.props.FlushTimer = FLUSH_MS;
        p.props.LoggerNameOffset = std::mem::offset_of!(Self, name) as u32;
        p
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        &mut self.props
    }
}

/// Runs the event session until it is stopped (admin mode turned off). Returns its error.
unsafe fn trace() -> u32 {
    unsafe {
        let mut props = Properties::new();
        let mut session = CONTROLTRACE_HANDLE { Value: 0 };
        let mut status = StartTraceW(&mut session, props.name.as_ptr(), props.ptr());
        if status == ERROR_ALREADY_EXISTS {
            // Left over from a helper that crashed.
            ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, props.name.as_ptr(), props.ptr(), EVENT_TRACE_CONTROL_STOP);
            props = Properties::new();
            status = StartTraceW(&mut session, props.name.as_ptr(), props.ptr());
        }
        if status != ERROR_SUCCESS {
            return status;
        }
        status = EnableTraceEx2(session, &KERNEL_PROCESS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION as u8, KEYWORD_PROCESS, 0, 0, null());
        if status == ERROR_SUCCESS {
            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = props.name.as_mut_ptr();
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(on_event);
            let reader = OpenTraceW(&mut logfile);
            if reader.Value == u64::MAX {
                status = GetLastError();
            } else {
                status = ProcessTrace(&reader, 1, null(), null());
                CloseTrace(reader);
            }
        }
        ControlTraceW(session, null(), props.ptr(), EVENT_TRACE_CONTROL_STOP);
        status
    }
}

// ------------------------------------------------------------------ reading the events

/// Vigil's end of the pipe.
pub struct Events {
    pipe: HANDLE,
    rest: Vec<u8>,
}

impl Events {
    /// Connects to the helper. `None` when admin mode isn't running, or when whatever holds
    /// the pipe name doesn't run in session 0, where services and SYSTEM tasks run.
    pub fn connect() -> Option<Self> {
        let name = wide(PIPE);
        let pipe = unsafe { CreateFileW(name.as_ptr(), GENERIC_READ, 0, null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, null_mut()) };
        if pipe == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut session = u32::MAX;
        if unsafe { GetNamedPipeServerSessionId(pipe, &mut session) } == 0 || session != 0 {
            unsafe { CloseHandle(pipe) };
            return None;
        }
        Some(Self { pipe, rest: Vec::new() })
    }

    /// The next process IDs. `None` once the helper is gone.
    pub fn next(&mut self) -> Option<Vec<u32>> {
        let mut buf = [0u8; 4096];
        let mut read = 0;
        if unsafe { ReadFile(self.pipe, buf.as_mut_ptr(), buf.len() as u32, &mut read, null_mut()) } == 0 && unsafe { GetLastError() } != ERROR_MORE_DATA {
            return None;
        }
        self.rest.extend_from_slice(&buf[..read as usize]);
        Some(take_ids(&mut self.rest))
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.pipe) };
    }
}

/// Whole 4-byte process IDs from the front of `buf`; a partial one stays for the next read.
fn take_ids(buf: &mut Vec<u8>) -> Vec<u32> {
    let whole = buf.len() / 4 * 4;
    let ids = buf[..whole].as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
    buf.drain(..whole);
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_ids_survive_split_reads() {
        let mut buf = vec![1, 0, 0, 0, 0x10, 0x27, 0, 0, 7];
        assert_eq!(take_ids(&mut buf), [1, 10_000]);
        assert_eq!(buf, [7]);
        buf.extend_from_slice(&[0, 0, 0]);
        assert_eq!(take_ids(&mut buf), [7]);
        assert!(buf.is_empty());
    }

    #[test]
    fn task_runs_the_protected_copy_as_system_without_limits() {
        let xml = helper_task_xml(std::path::Path::new(r"C:\Program Files\Vigil & Co\vigil.exe"));
        for part in [
            r"<Command>C:\Program Files\Vigil &amp; Co\vigil.exe</Command>",
            "<Arguments>--process-events</Arguments>",
            "<UserId>S-1-5-18</UserId>",
            "<BootTrigger>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
        ] {
            assert!(xml.contains(part), "{part}");
        }
        assert!(helper_path().ends_with(r"Vigil\vigil.exe") && helper_path().is_absolute());
    }

    #[test]
    fn login_task_starts_vigil_as_the_user_with_their_own_rights() {
        let user = "S-1-5-21-1004336348-1177238915-682003330-1001";
        let xml = login_task_xml(std::path::Path::new(r"C:\Program Files\Vigil\vigil.exe"), user);
        for part in [
            &format!("<LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger>"),
            &format!("<UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>"),
            "<Arguments>--logon</Arguments>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
        ] {
            assert!(xml.contains(part), "{part}");
        }
        assert!(!xml.contains("HighestAvailable"));
    }

    #[test]
    fn only_real_security_identifiers_reach_the_task() {
        assert!(is_sid("S-1-5-21-1004336348-1177238915-682003330-1001"));
        for bad in ["", "S-1-", "S-1-5-18</UserId><RunLevel>HighestAvailable", "s-1-5-18", "Administrator"] {
            assert!(!is_sid(bad), "{bad}");
        }
    }
}
