//! Thin wrappers around the Win32 APIs Vigil needs.

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};

use crate::engine::cmdline;

use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows_sys::Win32::Security::WinTrust::*;
use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W, Process32FirstW, Process32NextW,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx,
};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::UI::Shell::{CommandLineToArgvW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ------------------------------------------------------------------ Authenticode

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    /// Valid, trusted signature. Contains the signer's display name.
    Valid(String),
    Unsigned,
    /// The file carries a signature, but it does not verify.
    Invalid(InvalidReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    /// The file was modified after it was signed.
    Tampered,
    /// Self-signed or otherwise untrusted certificate chain.
    Untrusted,
    /// The certificate was revoked, typically because it was stolen and used to sign malware.
    Revoked,
    Other(i32),
}

const CERT_E_REVOKED: u32 = 0x800B_010C;

pub fn verify_signature(path: &Path) -> Signature {
    let path_w = wide(path);
    let (status, signer) = win_verify_trust(&path_w, false);
    match status {
        0 => {
            // Revocation is checked against what Windows has cached (it never goes online
            // from a background scan), so only a confirmed revocation counts; a missing
            // or stale revocation list leaves the signature valid.
            if win_verify_trust(&path_w, true).0 == CERT_E_REVOKED {
                return Signature::Invalid(InvalidReason::Revoked);
            }
            Signature::Valid(signer.unwrap_or_else(|| "Unknown publisher".into()))
        }
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => Signature::Unsigned,
        0x8009_6010 | 0x8009_6019 => Signature::Invalid(InvalidReason::Tampered),
        CERT_E_REVOKED => Signature::Invalid(InvalidReason::Revoked),
        0x800B_0109 | 0x800B_010F | 0x800B_0111 => Signature::Invalid(InvalidReason::Untrusted),
        _ => Signature::Invalid(InvalidReason::Other(status as i32)),
    }
}

/// One WinVerifyTrust pass over a file's embedded signature. Returns the status and,
/// when it verifies, the signer's display name.
fn win_verify_trust(path_w: &[u16], revocation: bool) -> (u32, Option<String>) {
    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = path_w.as_ptr();

        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = if revocation { WTD_REVOKE_WHOLECHAIN } else { WTD_REVOKE_NONE };
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        // Never hit the network from a background scan.
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            INVALID_HANDLE_VALUE as HWND,
            &mut action,
            &mut data as *mut _ as *mut c_void,
        ) as u32;
        let signer = if status == 0 && !revocation { signer_name(data.hWVTStateData) } else { None };

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(INVALID_HANDLE_VALUE as HWND, &mut action, &mut data as *mut _ as *mut c_void);
        (status, signer)
    }
}

unsafe fn signer_name(state: HANDLE) -> Option<String> {
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), buf.as_mut_ptr(), buf.len() as u32);
        (n > 1).then(|| from_wide(&buf))
    }
}

// ------------------------------------------------------------------ Mark of the Web

#[derive(Clone, Debug, Default)]
pub struct Origin {
    pub zone: u32,
    pub url: Option<String>,
}

/// Reads the `Zone.Identifier` alternate data stream browsers attach to downloads.
pub fn zone_identifier(path: &Path) -> Option<Origin> {
    let mut ads = path.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    let text = std::fs::read_to_string(PathBuf::from(ads)).ok()?;
    let mut origin = Origin::default();
    let (mut host, mut referrer) = (None, None);
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ZoneId=") {
            origin.zone = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("HostUrl=") {
            host = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("ReferrerUrl=") {
            referrer = Some(v.trim().to_string());
        }
    }
    // Chromium writes "about:internet" when it has no real URL to record.
    origin.url = host.filter(|u| u.starts_with("http")).or(referrer);
    Some(origin)
}

// ------------------------------------------------------------------ process / threads

/// Lowers CPU *and* I/O priority of the calling thread so scans never cause stutter in games.
pub fn set_background_priority() {
    unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}

/// IDs of all running processes.
pub fn process_ids() -> Vec<u32> {
    processes().into_iter().map(|(pid, _)| pid).collect()
}

/// All running processes as (process ID, ID of the process that started it).
fn processes() -> Vec<(u32, u32)> {
    let mut all = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return all;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut entry);
        while ok != 0 {
            all.push((entry.th32ProcessID, entry.th32ParentProcessID));
            ok = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
    }
    all
}

unsafe fn created_at(process: HANDLE) -> u64 {
    let mut times = [FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 }; 4];
    let [created, exited, kernel, user] = &mut times;
    if unsafe { GetProcessTimes(process, created, exited, kernel, user) } == 0 {
        return u64::MAX;
    }
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

/// Ends everything the process `root` (created at `root_created`) started, and what
/// those started in turn. Parent IDs outlive their processes and get reused, so a
/// process only counts as a child if it started after its parent. Returns false if one
/// of them could not be stopped.
unsafe fn stop_descendants(root: u32, root_created: u64) -> bool {
    let mut all = true;
    let mut parents = vec![(root, root_created)];
    let mut seen = std::collections::HashSet::new();
    // A child may have started another process while the previous round ended it.
    for _ in 0..3 {
        let snapshot = processes();
        let before = parents.len();
        let mut i = 0;
        while i < parents.len() {
            let (parent, parent_created) = parents[i];
            i += 1;
            let children: Vec<u32> = snapshot.iter().filter(|(pid, ppid)| *ppid == parent && *pid != parent && !seen.contains(pid)).map(|(pid, _)| *pid).collect();
            for pid in children {
                unsafe {
                    let mut h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
                    let can_stop = !h.is_null();
                    if !can_stop {
                        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                        if h.is_null() {
                            continue;
                        }
                    }
                    let created = created_at(h);
                    if created >= parent_created && created != u64::MAX {
                        seen.insert(pid);
                        parents.push((pid, created));
                        all &= can_stop && TerminateProcess(h, 1) != 0 && WaitForSingleObject(h, 5000) == WAIT_OBJECT_0;
                    }
                    CloseHandle(h);
                }
            }
        }
        if parents.len() == before {
            break;
        }
    }
    all
}

unsafe fn image_of(process: HANDLE) -> Option<PathBuf> {
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

/// Full path of the program a process runs. `None` for processes we may not query
/// (System, protected processes) or that already exited.
pub fn process_image(pid: u32) -> Option<PathBuf> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let image = image_of(h);
        CloseHandle(h);
        image
    }
}

/// Arguments a process was started with, split the way the C runtime splits them.
pub fn process_args(pid: u32) -> Option<Vec<String>> {
    process_command_line(pid).map(|line| split_args(&line))
}

/// The command line a process was started with, as it was given.
pub fn process_command_line(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let line = command_line_of(h);
        CloseHandle(h);
        line
    }
}

unsafe fn command_line_of(h: HANDLE) -> Option<String> {
    unsafe {
        // The first call reports the size; u64 storage keeps the UNICODE_STRING header aligned.
        let mut buf: Vec<u64> = Vec::new();
        let mut len = 0u32;
        let mut status = STATUS_INFO_LENGTH_MISMATCH;
        for _ in 0..2 {
            status = NtQueryInformationProcess(h, ProcessCommandLineInformation, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len);
            if status != STATUS_INFO_LENGTH_MISMATCH {
                break;
            }
            buf = vec![0; (len as usize).div_ceil(8)];
        }
        if status < 0 || buf.is_empty() {
            return None;
        }
        let line = &*(buf.as_ptr() as *const UNICODE_STRING);
        if line.Buffer.is_null() {
            return None;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(line.Buffer, line.Length as usize / 2)))
    }
}

/// Splits a command line the way the C runtime does.
pub fn split_args(line: &str) -> Vec<String> {
    let w = wide(line);
    unsafe {
        let mut n = 0;
        let argv = CommandLineToArgvW(w.as_ptr(), &mut n);
        if argv.is_null() {
            return Vec::new();
        }
        let args = (0..n.max(0) as usize)
            .map(|i| {
                let arg = *argv.add(i);
                let len = (0..).take_while(|&j| *arg.add(j) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(arg, len))
            })
            .collect();
        LocalFree(argv.cast());
        args
    }
}

/// Files of the modules (the program and its DLLs) loaded into a process. Empty for
/// processes we may not inspect (elevated, protected) or that already exited.
pub fn process_modules(pid: u32) -> Vec<PathBuf> {
    module_entries(pid).into_iter().map(|(path, ..)| path).collect()
}

/// File, base address and size of each module, the program itself first.
fn module_entries(pid: u32) -> Vec<(PathBuf, usize, usize)> {
    let mut modules = Vec::new();
    unsafe {
        // Fails with ERROR_BAD_LENGTH while the process is still loading modules.
        let mut snap = INVALID_HANDLE_VALUE;
        for _ in 0..3 {
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH {
                break;
            }
        }
        if snap == INVALID_HANDLE_VALUE {
            return modules;
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut ok = Module32FirstW(snap, &mut entry);
        while ok != 0 {
            modules.push((PathBuf::from(from_wide(&entry.szExePath)), entry.modBaseAddr as usize, entry.modBaseSize as usize));
            ok = Module32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
    }
    modules
}

/// A committed range of another process's address space with the same protection.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: usize,
    pub size: usize,
    /// Start of the allocation the range belongs to.
    pub allocation: usize,
    /// Mapped from a program or DLL file.
    pub image: bool,
    /// Not backed by any file.
    pub private: bool,
    pub executable: bool,
    pub readable: bool,
}

/// Read access to another process's memory. Works without admin rights for the user's
/// own processes, but not for elevated or protected ones.
pub struct ProcessMemory {
    handle: HANDLE,
    pid: u32,
}

impl ProcessMemory {
    pub fn open(pid: u32) -> Option<Self> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        (!handle.is_null()).then_some(Self { handle, pid })
    }

    /// The program the process runs.
    pub fn image(&self) -> Option<PathBuf> {
        unsafe { image_of(self.handle) }
    }

    /// Base address and size of the program's own image, where the loader mapped it.
    pub fn main_module(&self) -> Option<(usize, usize)> {
        module_entries(self.pid).first().map(|&(_, base, size)| (base, size))
    }

    pub fn regions(&self) -> Vec<Region> {
        const EXECUTE: u32 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let n = unsafe { VirtualQueryEx(self.handle, address as *const c_void, &mut info, size_of::<MEMORY_BASIC_INFORMATION>()) };
            if n == 0 {
                break;
            }
            let (base, size) = (info.BaseAddress as usize, info.RegionSize);
            if info.State == MEM_COMMIT {
                regions.push(Region {
                    base,
                    size,
                    allocation: info.AllocationBase as usize,
                    image: info.Type == MEM_IMAGE,
                    private: info.Type == MEM_PRIVATE,
                    executable: info.Protect & EXECUTE != 0,
                    readable: info.Protect != 0 && info.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0,
                });
            }
            match base.checked_add(size) {
                Some(next) if next > address => address = next,
                _ => break,
            }
        }
        regions
    }

    /// Up to `len` bytes at `base`, or `None` when the range can't be read.
    pub fn read(&self, base: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read = 0;
        let ok = unsafe { ReadProcessMemory(self.handle, base as *const c_void, buf.as_mut_ptr().cast(), len, &mut read) };
        (ok != 0 && read > 0).then(|| {
            buf.truncate(read);
            buf
        })
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Ends every process running `file`, or, when none runs it, every process that has it
/// loaded as a DLL, or else every script host told to run it. Matches by path rather
/// than PID so a reused PID never hits an unrelated program. Returns false if one of
/// them could not be stopped.
/// Processes we cannot open (elevated ones) are skipped; quarantine then fails visibly.
pub fn stop_processes_using(file: &Path) -> bool {
    let same = |p: &Path| p.as_os_str().eq_ignore_ascii_case(file.as_os_str());
    let mut all = true;
    let mut found = false;
    for pass in 0..3 {
        for pid in process_ids() {
            unsafe {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
                if h.is_null() {
                    continue;
                }
                let uses = match pass {
                    0 => image_of(h).is_some_and(|p| same(&p)),
                    1 => process_modules(pid).iter().any(|m| same(m)),
                    _ => image_of(h).filter(|i| cmdline::is_script_host(i)).is_some_and(|image| {
                        command_line_of(h).and_then(|l| cmdline::script_file(&image, &split_args(&l))).is_some_and(|s| same(&s))
                    }),
                };
                if uses {
                    found = true;
                    let created = created_at(h);
                    all &= TerminateProcess(h, 1) != 0 && WaitForSingleObject(h, 5000) == WAIT_OBJECT_0;
                    // A script host has likely started the script's next stage already.
                    if pass == 2 {
                        all &= stop_descendants(pid, created);
                    }
                }
                CloseHandle(h);
            }
        }
        if found {
            break;
        }
    }
    all
}

/// Ends the process `pid` if it still runs `command_line` (so a reused PID is never hit),
/// and everything it started. `None` when it has exited already, `Some(false)` when it
/// or one of its children could not be stopped (they run elevated).
pub fn stop_process(pid: u32, command_line: &str) -> Option<bool> {
    unsafe {
        let mut h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
        let can_stop = !h.is_null();
        if !can_stop {
            h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
        }
        if !command_line_of(h).is_some_and(|l| l == command_line) {
            CloseHandle(h);
            return None;
        }
        let created = created_at(h);
        let stopped = can_stop && TerminateProcess(h, 1) != 0 && WaitForSingleObject(h, 5000) == WAIT_OBJECT_0;
        CloseHandle(h);
        Some(stop_descendants(pid, created) && stopped)
    }
}

/// Whether this process runs with admin rights (elevated).
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0;
        let ok = GetTokenInformation(token, TokenElevation, (&raw mut elevation).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0;
        CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Runs this program again with admin rights (a UAC prompt), waits for it and returns its
/// exit code. `None` when the user declined.
pub fn run_elevated(args: &[&str]) -> Option<u32> {
    let exe = wide(std::env::current_exe().ok()?);
    let params = wide(args.join(" "));
    let verb = wide("runas");
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = exe.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() {
            return None;
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Some(code)
    }
}

pub struct NamedMutex(HANDLE);
unsafe impl Send for NamedMutex {}

impl NamedMutex {
    /// Returns `None` if another process already holds the mutex.
    pub fn acquire(name: &str) -> Option<Self> {
        let w = wide(name);
        unsafe {
            let h = CreateMutexW(null(), 0, w.as_ptr());
            if h.is_null() {
                return None;
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(h);
                return None;
            }
            Some(Self(h))
        }
    }

    pub fn exists(name: &str) -> bool {
        let w = wide(name);
        unsafe {
            let h = OpenMutexW(0x0010_0000 /* SYNCHRONIZE */, 0, w.as_ptr());
            if h.is_null() {
                false
            } else {
                CloseHandle(h);
                true
            }
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn attach_parent_console() -> bool {
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}

pub fn spawn_self(args: &[&str]) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = Command::new(exe).args(args).spawn();
    }
}

pub fn show_in_explorer(path: &Path) {
    let mut arg = std::ffi::OsString::from("/select,\"");
    arg.push(path.as_os_str());
    arg.push("\"");
    let _ = Command::new("explorer.exe").raw_arg(arg).spawn();
}

pub fn open_folder(path: &Path) {
    let _ = Command::new("explorer.exe").arg(path).spawn();
}

pub fn open_url(url: &str) {
    let _ = Command::new("cmd").args(["/c", "start", "", url]).creation_flags(CREATE_NO_WINDOW).spawn();
}

// ------------------------------------------------------------------ registry

fn reg_get_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(subkey), wide(value));
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(root, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr() as *mut c_void, &mut size)
    };
    (rc == ERROR_SUCCESS).then(|| from_wide(&buf))
}

pub fn steam_install_path() -> Option<PathBuf> {
    reg_get_string(HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath")
        .map(|s| PathBuf::from(s.replace('/', "\\")))
        .or_else(|| reg_get_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath").map(PathBuf::from))
}

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Vigil";

pub fn autostart_enabled() -> bool {
    reg_get_string(HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE).is_some()
}

pub fn set_autostart(enabled: bool) -> bool {
    let (k, v) = (wide(RUN_KEY), wide(RUN_VALUE));
    unsafe {
        if enabled {
            let Ok(exe) = std::env::current_exe() else { return false };
            let cmd = wide(format!("\"{}\" --background", exe.display()));
            RegSetKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), REG_SZ, cmd.as_ptr() as *const c_void, (cmd.len() * 2) as u32)
                == ERROR_SUCCESS
        } else {
            RegDeleteKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr()) == ERROR_SUCCESS
        }
    }
}

// ------------------------------------------------------------------ Microsoft Defender

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefenderResult {
    Clean,
    Threat(String),
    Error(String),
}

fn mpcmdrun_path() -> Option<PathBuf> {
    // The platform folder holds the up-to-date engine; pick the newest version.
    let platform = Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Platform");
    let newest = std::fs::read_dir(platform)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("MpCmdRun.exe"))
        .filter(|p| p.exists())
        .max();
    newest.or_else(|| {
        let legacy = PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe");
        legacy.exists().then_some(legacy)
    })
}

/// Asks Microsoft Defender for a second opinion on a single file (no remediation).
pub fn defender_scan(path: &Path) -> DefenderResult {
    let Some(exe) = mpcmdrun_path() else {
        return DefenderResult::Error("MpCmdRun.exe not found".into());
    };
    let out = Command::new(exe)
        .args(["-Scan", "-ScanType", "3", "-DisableRemediation", "-File"])
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            match o.status.code() {
                Some(0) => DefenderResult::Clean,
                Some(2) => {
                    let name = text
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("Threat").map(|r| r.trim_start_matches([' ', ':']).trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "threat detected".into());
                    DefenderResult::Threat(name)
                }
                code => DefenderResult::Error(format!("MpCmdRun exited with {code:?}")),
            }
        }
        Err(e) => DefenderResult::Error(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_splits_a_command_line() {
        let me = std::process::id();
        let line = process_command_line(me).unwrap();
        assert_eq!(split_args(&line), std::env::args().collect::<Vec<_>>());
        assert_eq!(process_args(me), Some(std::env::args().collect()));
        // Only the process still running the scanned command is stopped.
        assert_eq!(stop_process(me, "some other command"), None);
    }

    #[test]
    fn stopping_a_script_host_stops_what_it_started() {
        let mut host = Command::new("cmd.exe").args(["/c", "ping -n 30 127.0.0.1 >nul"]).creation_flags(CREATE_NO_WINDOW).spawn().unwrap();
        let pid = host.id();
        let is_ping = |p: u32| process_image(p).is_some_and(|i| i.file_name().is_some_and(|n| n.eq_ignore_ascii_case("PING.EXE")));
        let ping = (0..50)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                processes().into_iter().find(|&(p, parent)| parent == pid && is_ping(p)).map(|(p, _)| p)
            })
            .expect("cmd started ping");
        let line = process_command_line(pid).unwrap();
        assert_eq!(stop_process(pid, &line), Some(true));
        host.wait().unwrap();
        assert!(!is_ping(ping), "ping outlived the cmd that started it");
    }
}
