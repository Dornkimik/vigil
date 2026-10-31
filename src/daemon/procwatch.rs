//! Scans programs as they start. Polls the process list once a second (no admin rights
//! needed) and queues the image of every process that wasn't there on the last pass.
//! A program that starts and exits between two polls is missed.
//!
//! `rundll32.exe` and `regsvr32.exe` are Windows' own, but run whatever DLL they are
//! given, so for them the DLLs come next: the one named on the command line, and every
//! DLL from outside the Windows folder they load while they run.
//!
//! PowerShell, cmd, mshta and Windows Script Host run code given on their command line,
//! which never touches the disk, so their command lines are scanned too, along with the
//! script file they are told to run.
//!
//! Each program is also reported with its process ID, so its memory can be checked
//! once it has had time to unpack itself.

use super::{Shared, Work};
use crate::engine::{cmdline, filetype};
use crate::winapi;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

const POLL: Duration = Duration::from_secs(1);
/// Windows programs that run code from a DLL named on their command line.
const DLL_HOSTS: &[&str] = &["rundll32.exe", "regsvr32.exe"];

pub fn run(shared: Arc<Shared>, tx: Sender<Work>) {
    winapi::set_background_priority();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let own_exe = std::env::current_exe().ok();
    // Starts empty, so everything already running is scanned once.
    let mut known = HashSet::new();
    // Running DLL hosts and the modules already queued for each.
    let mut hosts: HashMap<u32, HashSet<PathBuf>> = HashMap::new();
    loop {
        let enabled = {
            let cfg = shared.config.read().unwrap();
            cfg.watch_launches && !cfg.paused
        };
        if enabled {
            let current: HashSet<u32> = winapi::process_ids().into_iter().collect();
            let mut queue = Vec::new();
            for &pid in current.difference(&known) {
                let Some(image) = winapi::process_image(pid).map(long_path) else { continue };
                if is_dll_host(&image) {
                    // The command line still names the DLL if the host exits before it is inspected.
                    let named = winapi::process_args(pid).map(|args| hosted_dlls(&image, &args)).unwrap_or_default();
                    let named: HashSet<PathBuf> = named.into_iter().map(long_path).collect();
                    queue.extend(named.iter().filter(|dll| !is_system(dll, &system_root)).cloned().map(Work::Launched));
                    hosts.insert(pid, named);
                }
                if cmdline::is_script_host(&image)
                    && let Some(line) = winapi::process_command_line(pid)
                {
                    let script = cmdline::script_file(&image, &winapi::split_args(&line)).map(long_path);
                    queue.extend(script.filter(|s| !is_system(s, &system_root)).map(Work::Launched));
                    queue.push(Work::Command(pid, image.clone(), line));
                }
                if is_system(&image, &system_root) || own_exe.as_ref().is_some_and(|e| e.as_os_str().eq_ignore_ascii_case(image.as_os_str())) {
                    continue;
                }
                queue.push(Work::Launched(image.clone()));
                queue.push(Work::Started(pid, image));
            }
            // DLLs load after the host starts, so hosts are re-checked on every pass while they run.
            hosts.retain(|pid, _| current.contains(pid));
            for (&pid, queued) in &mut hosts {
                for module in winapi::process_modules(pid).into_iter().map(long_path) {
                    if !is_system(&module, &system_root) && queued.insert(module.clone()) {
                        queue.push(Work::Launched(module));
                    }
                }
            }
            for work in queue {
                if tx.send(work).is_err() {
                    return;
                }
            }
            known = current;
        } else {
            // Whatever started meanwhile gets scanned once protection is back on.
            known.clear();
            hosts.clear();
        }
        thread::sleep(POLL);
    }
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
