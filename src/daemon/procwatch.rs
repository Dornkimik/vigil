//! Scans programs as they start. Polls the process list once a second (no admin rights
//! needed) and queues the image of every process that wasn't there on the last pass.
//! A program that starts and exits between two polls is missed.

use super::{Shared, Work};
use crate::engine::filetype;
use crate::winapi;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

const POLL: Duration = Duration::from_secs(1);

pub fn run(shared: Arc<Shared>, tx: Sender<Work>) {
    winapi::set_background_priority();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let own_exe = std::env::current_exe().ok();
    // Starts empty, so everything already running is scanned once.
    let mut known = HashSet::new();
    loop {
        let enabled = {
            let cfg = shared.config.read().unwrap();
            cfg.watch_launches && !cfg.paused
        };
        if enabled {
            let current: HashSet<u32> = winapi::process_ids().into_iter().collect();
            for &pid in current.difference(&known) {
                let Some(image) = winapi::process_image(pid).map(long_path) else { continue };
                if is_system(&image, &system_root) || own_exe.as_ref().is_some_and(|e| e.as_os_str().eq_ignore_ascii_case(image.as_os_str())) {
                    continue;
                }
                if tx.send(Work::Launched(image)).is_err() {
                    return;
                }
            }
            known = current;
        } else {
            // Whatever started meanwhile gets scanned once protection is back on.
            known.clear();
        }
        thread::sleep(POLL);
    }
}

/// Programs under %SystemRoot% are Windows' own, apart from folders standard users can write to.
fn is_system(image: &Path, system_root: &str) -> bool {
    filetype::in_protected_windows_folder(image, system_root)
}

/// Expands 8.3 short names (`REGIST~1`) so they can't slip past the folder check.
fn long_path(image: PathBuf) -> PathBuf {
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
    use super::is_system;
    use std::path::Path;

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
}
