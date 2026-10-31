//! Scans programs as they start. Polls the process list once a second (no admin rights
//! needed) and queues the image of every process that wasn't there on the last pass.
//! A program that starts and exits between two polls is missed. For a few seconds after
//! a script host starts, or a script is saved in a user folder (droppers write their
//! script and run it right away), it polls every 50 ms instead: what the script starts
//! (a hidden PowerShell, a downloaded payload) is seen before it gets far.
//!
//! `rundll32.exe` and `regsvr32.exe` are Windows' own, but run whatever DLL they are
//! given, so for them the DLLs come next: the one named on the command line, and every
//! DLL from outside the Windows folder they load while they run.
//!
//! PowerShell, cmd, mshta, Windows Script Host and conhost run code given on their
//! command line, which never touches the disk, so their command lines are scanned too,
//! right here rather than behind the worker's queue, along with the script file they are
//! told to run.
//!
//! In admin mode a helper running as SYSTEM reports every program the moment it starts
//! (see `admin`), and polling stays at once a second as a safety net.
//!
//! Each program is also reported with its process ID, so its memory can be checked
//! once it has had time to unpack itself.

use super::{Shared, Work};
use crate::admin;
use crate::engine::{cmdline, filetype};
use crate::winapi;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_secs(1);
/// PowerShell runs the first line of its command about 110 ms after it starts.
const FAST_POLL: Duration = Duration::from_millis(50);
/// How long polling stays fast after a script host starts or a script is saved.
const BURST: Duration = Duration::from_secs(5);
/// Windows programs that run code from a DLL named on their command line.
const DLL_HOSTS: &[&str] = &["rundll32.exe", "regsvr32.exe"];

/// What gets the process watcher going before its next poll: a burst of fast polling (a
/// script host started, or a script was saved), and the processes admin mode reports.
pub(crate) struct Burst {
    signals: Mutex<Signals>,
    wake: Condvar,
    /// Admin mode's helper is connected. Every start is reported then, so polling stays slow.
    pub events: AtomicBool,
}

struct Signals {
    until: Instant,
    started: Vec<u32>,
}

impl Burst {
    pub fn new() -> Self {
        Self { signals: Mutex::new(Signals { until: Instant::now(), started: Vec::new() }), wake: Condvar::new(), events: AtomicBool::new(false) }
    }

    pub fn start(&self) {
        self.signals.lock().unwrap().until = Instant::now() + BURST;
        self.wake.notify_all();
    }

    /// Processes admin mode reported as they started.
    fn started(&self, pids: Vec<u32>) {
        self.signals.lock().unwrap().started.extend(pids);
        self.wake.notify_all();
    }

    /// How long polls are apart now.
    fn interval(&self) -> Duration {
        let fast = !self.events.load(Ordering::Relaxed) && Instant::now() < self.signals.lock().unwrap().until;
        if fast { FAST_POLL } else { POLL }
    }

    /// Waits until `deadline`, a burst begins or processes are reported, and returns those.
    fn wait(&self, deadline: Instant) -> Vec<u32> {
        let signals = self.signals.lock().unwrap();
        let idle = signals.until;
        let timeout = deadline.saturating_duration_since(Instant::now());
        let (mut signals, _) = self.wake.wait_timeout_while(signals, timeout, |s| s.started.is_empty() && s.until == idle).unwrap();
        std::mem::take(&mut signals.started)
    }
}

/// Reads admin mode's process-start events while its helper runs (see `admin`).
pub fn listen(shared: Arc<Shared>) {
    loop {
        if admin::installed()
            && let Some(mut events) = admin::Events::connect()
        {
            shared.burst.events.store(true, Ordering::Relaxed);
            while let Some(pids) = events.next() {
                if !pids.is_empty() {
                    shared.burst.started(pids);
                }
            }
            shared.burst.events.store(false, Ordering::Relaxed);
        }
        thread::sleep(Duration::from_secs(5));
    }
}

pub fn run(shared: Arc<Shared>, tx: Sender<Work>) {
    winapi::set_background_priority();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let own_exe = std::env::current_exe().ok();
    // Starts empty, so everything already running is scanned once.
    let mut known = HashSet::new();
    // Running DLL hosts and the modules already queued for each.
    let mut hosts: HashMap<u32, HashSet<PathBuf>> = HashMap::new();
    let mut modules_checked = Instant::now();
    let mut last_poll = Instant::now() - POLL;
    loop {
        let reported = shared.burst.wait(last_poll + shared.burst.interval());
        let enabled = {
            let cfg = shared.config.read().unwrap();
            cfg.watch_launches && !cfg.paused
        };
        if !enabled {
            // Whatever started meanwhile gets scanned once protection is back on.
            known.clear();
            hosts.clear();
            last_poll = Instant::now();
            continue;
        }
        let mut queue = Vec::new();
        // Reported by admin mode the moment they started; polling is the safety net.
        for pid in reported {
            if known.insert(pid) {
                inspect(&shared, pid, &system_root, own_exe.as_deref(), &mut hosts, &mut queue);
            }
        }
        if last_poll.elapsed() >= shared.burst.interval() {
            last_poll = Instant::now();
            let current: HashSet<u32> = winapi::process_ids().into_iter().collect();
            for &pid in current.difference(&known) {
                inspect(&shared, pid, &system_root, own_exe.as_deref(), &mut hosts, &mut queue);
            }
            // DLLs load after the host starts, so hosts are re-checked while they run, at the
            // normal pace: listing a process's modules costs far more than listing processes.
            hosts.retain(|pid, _| current.contains(pid));
            let modules_due = modules_checked.elapsed() >= POLL;
            if modules_due {
                modules_checked = Instant::now();
            }
            for (&pid, queued) in hosts.iter_mut().filter(|_| modules_due) {
                for module in winapi::process_modules(pid).into_iter().map(long_path) {
                    if !is_system(&module, &system_root) && queued.insert(module.clone()) {
                        queue.push(Work::Launched(module));
                    }
                }
            }
            known = current;
        }
        for work in queue {
            if tx.send(work).is_err() {
                return;
            }
        }
    }
}

/// Checks a process that just started: scans a script host's command line right away and
/// queues the program's file, the DLL a DLL host runs and the script a script host runs.
fn inspect(shared: &Shared, pid: u32, system_root: &str, own_exe: Option<&Path>, hosts: &mut HashMap<u32, HashSet<PathBuf>>, queue: &mut Vec<Work>) {
    let Some(image) = winapi::process_image(pid).map(long_path) else { return };
    if is_dll_host(&image) {
        // The command line still names the DLL if the host exits before it is inspected.
        let named = winapi::process_args(pid).map(|args| hosted_dlls(&image, &args)).unwrap_or_default();
        let named: HashSet<PathBuf> = named.into_iter().map(long_path).collect();
        queue.extend(named.iter().filter(|dll| !is_system(dll, system_root)).cloned().map(Work::Launched));
        hosts.insert(pid, named);
    }
    if cmdline::is_script_host(&image)
        && let Some(line) = winapi::process_command_line(pid)
    {
        shared.burst.start();
        let script = cmdline::script_file(&image, &winapi::split_args(&line)).map(long_path);
        queue.extend(script.filter(|s| !is_system(s, system_root)).map(Work::Launched));
        super::check_command(shared, pid, &image, &line);
    }
    if is_system(&image, system_root) || own_exe.is_some_and(|e| e.as_os_str().eq_ignore_ascii_case(image.as_os_str())) {
        return;
    }
    queue.push(Work::Launched(image.clone()));
    queue.push(Work::Started(pid, image));
}

/// Programs under %SystemRoot% are Windows' own, apart from folders standard users can write to.
fn is_system(image: &Path, system_root: &str) -> bool {
    filetype::in_protected_windows_folder(image, system_root)
}

fn is_dll_host(image: &Path) -> bool {
    image.file_name().is_some_and(|n| DLL_HOSTS.iter().any(|h| n.eq_ignore_ascii_case(h)))
}

/// DLLs a host's command line names with a full path. Relative names depend on the
/// host's working directory; those are picked up from its loaded modules instead.
///
///   rundll32.exe <dll>,<entry point> [arguments]
///   regsvr32.exe [/s] [/u] [/n] [/i[:cmdline]] <dll>...
fn hosted_dlls(image: &Path, args: &[String]) -> Vec<PathBuf> {
    let rundll = image.file_name().is_some_and(|n| n.eq_ignore_ascii_case("rundll32.exe"));
    let named: Vec<&str> = if rundll {
        args.get(1).map(|a| a.split(',').next().unwrap_or("").trim()).into_iter().collect()
    } else {
        args.iter().skip(1).filter(|a| !a.starts_with(['/', '-'])).map(|a| a.trim()).collect()
    };
    let mut dlls = Vec::new();
    for name in named.into_iter().filter(|n| Path::new(n).is_absolute()) {
        dlls.push(PathBuf::from(name));
        // LoadLibrary appends .dll to a name without an extension (a trailing dot means none).
        if Path::new(name).extension().is_none() && !name.ends_with('.') {
            dlls.push(PathBuf::from(format!("{name}.dll")));
        }
    }
    dlls
}

/// Expands 8.3 short names (`REGIST~1`) so they can't slip past the folder check.
pub(super) fn long_path(image: PathBuf) -> PathBuf {
    if !image.to_string_lossy().contains('~') {
        return image;
    }
    match std::fs::canonicalize(&image) {
        Ok(p) => p.to_str().and_then(|s| s.strip_prefix(r"\\?\")).map(PathBuf::from).unwrap_or(p),
        Err(_) => image,
    }
}

#[cfg(test)]
mod tests {
    use super::{hosted_dlls, is_dll_host, is_system};
    use std::path::{Path, PathBuf};

    #[test]
    fn skips_only_the_windows_folder() {
        let root = r"C:\Windows";
        assert!(is_system(Path::new(r"C:\WINDOWS\System32\svchost.exe"), root));
        assert!(is_system(Path::new(r"c:\windows\explorer.exe"), r"C:\Windows\"));
        assert!(!is_system(Path::new(r"C:\WindowsApps\x.exe"), root));
        assert!(!is_system(Path::new(r"C:\Users\me\AppData\Local\Temp\x.exe"), root));
        assert!(!is_system(Path::new(r"D:\Windows\x.exe"), root));
    }

    #[test]
    fn user_writable_windows_folders_are_scanned() {
        let root = r"C:\Windows";
        assert!(!is_system(Path::new(r"C:\Windows\Temp\x.exe"), root));
        assert!(!is_system(Path::new(r"C:\WINDOWS\Tasks\x.exe"), root));
        assert!(!is_system(Path::new(r"C:\Windows\System32\spool\drivers\color\x.exe"), root));
        assert!(!is_system(Path::new(r"C:\Windows\SysWOW64\Tasks\Microsoft\x.exe"), root));
        assert!(is_system(Path::new(r"C:\Windows\System32\Taskmgr.exe"), root));
        assert!(is_system(Path::new(r"C:\Windows\TempHelper\x.exe"), root));
    }

    fn dlls(image: &str, args: &[&str]) -> Vec<PathBuf> {
        hosted_dlls(Path::new(image), &args.iter().map(|a| a.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn finds_the_dll_a_host_is_told_to_run() {
        let rundll = r"C:\Windows\System32\rundll32.exe";
        let regsvr = r"C:\Windows\SysWOW64\REGSVR32.EXE";
        assert!(is_dll_host(Path::new(rundll)) && is_dll_host(Path::new(regsvr)));
        assert!(!is_dll_host(Path::new(r"C:\Users\me\rundll32.exe.lnk")));

        // CommandLineToArgvW has already removed the quotes: "C:\a b\x.dll",Start -> C:\a b\x.dll,Start
        assert_eq!(dlls(rundll, &["rundll32", r"C:\a b\evil.dll,Start", "arg"]), [PathBuf::from(r"C:\a b\evil.dll")]);
        assert_eq!(dlls(rundll, &["rundll32", r"C:\Users\me\AppData\Roaming\x.dat", "#1"]), [PathBuf::from(r"C:\Users\me\AppData\Roaming\x.dat")]);
        assert_eq!(
            dlls(rundll, &["rundll32", r"C:\Users\me\payload,Run"]),
            [PathBuf::from(r"C:\Users\me\payload"), PathBuf::from(r"C:\Users\me\payload.dll")]
        );
        assert_eq!(
            dlls(regsvr, &["regsvr32", "/s", "/i:install", r"C:\ProgramData\a.ocx", "-u", r"D:\b.dll"]),
            [PathBuf::from(r"C:\ProgramData\a.ocx"), PathBuf::from(r"D:\b.dll")]
        );
        // Relative names are resolved from the loaded modules instead.
        assert!(dlls(rundll, &["rundll32", "shell32.dll,Control_RunDLL"]).is_empty());
        assert!(dlls(rundll, &["rundll32", r"javascript:\..\mshtml,RunHTMLApplication"]).is_empty());
        assert!(dlls(rundll, &["rundll32"]).is_empty());
    }
}
