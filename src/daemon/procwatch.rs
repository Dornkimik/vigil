//! Scans programs as they start. Polls the process list once a second (no admin rights
//! needed) and queues the image of every process that wasn't there on the last pass.
//! A program that starts and exits between two polls is missed.

use super::{Shared, Work};
use crate::winapi;
use std::collections::HashSet;
use std::path::Path;
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
                let Some(image) = winapi::process_image(pid) else { continue };
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

/// Programs under %SystemRoot% are Windows' own; standard users cannot write there.
fn is_system(image: &Path, system_root: &str) -> bool {
    let image = image.to_string_lossy().to_ascii_lowercase();
    let root = system_root.trim_end_matches('\\').to_ascii_lowercase();
    image.strip_prefix(&root).is_some_and(|rest| rest.starts_with('\\'))
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
}
