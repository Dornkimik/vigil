#![windows_subsystem = "windows"]
//! Vigil - a lightweight background malware scanner that supplements Microsoft Defender,
//! focused on browser downloads and Steam games / Workshop content.
//!
//!   vigil.exe                 start the background service (if needed) and open the dashboard
//!   vigil.exe --background    start only the background service (used for autostart)
//!   vigil.exe --gui           open only the dashboard
//!   vigil.exe --scan <paths>  scan from the command line [--json] [--fast] [--out <file>]
//!                             (--fast only opens code-like extensions, as for Steam folders)
//!   vigil.exe --update-hashes download the MalwareBazaar hash database now
//!   vigil.exe --update-yara   download and compile the YARA Forge rules now
//!   vigil.exe --admin-mode on|off  turn admin mode on or off (asks for admin approval)
//!   vigil.exe --process-events     admin mode's helper, run as SYSTEM by its scheduled task

mod admin;
mod config;
mod daemon;
mod engine;
mod gui;
mod icon;
mod steam;
mod store;
mod winapi;

use engine::{Engine, ScanOptions, Source, Verdict};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--background") => daemon::run(false),
        Some("--gui") => gui::run(),
        Some("--scan") => std::process::exit(cli_scan(&args[1..])),
        Some("--update-hashes") => std::process::exit(cli_update_hashes()),
        Some("--update-yara") => std::process::exit(cli_update_yara()),
        Some("--admin-mode") => std::process::exit(admin::cli(&args[1..])),
        Some("--process-events") => std::process::exit(admin::run_helper()),
        _ if winapi::NamedMutex::exists(daemon::DAEMON_MUTEX) => gui::run(),
        _ => daemon::run(true),
    }
}

/// Depth-first walk over files; `f` returns false to stop.
pub fn walk_files(root: &Path, f: &mut dyn FnMut(&Path) -> bool) -> bool {
    if root.is_file() {
        return f(root);
    }
    let Ok(entries) = std::fs::read_dir(root) else { return true };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let keep_going = if ft.is_dir() {
            walk_files(&entry.path(), f)
        } else if ft.is_file() {
            f(&entry.path())
        } else {
            true
        };
        if !keep_going {
            return false;
        }
    }
    true
}

fn cli_update_hashes() -> i32 {
    winapi::attach_parent_console();
    match engine::hashdb::update(&config::Config::load().malwarebazaar_key, true) {
        Ok(n) => {
            println!("Hash database updated: {n} known-malware hashes");
            if let Some(warning) = engine::hashdb::Meta::load().error {
                println!("Warning: {warning}");
            }
            0
        }
        Err(e) => {
            println!("Hash database update failed: {e}");
            1
        }
    }
}

fn cli_update_yara() -> i32 {
    winapi::attach_parent_console();
    match engine::yara::update(true, false) {
        Ok(n) => {
            println!("YARA rules updated: {n} rules");
            if let Some(warning) = engine::yara::Meta::load().error {
                println!("Warning: {warning}");
            }
            0
        }
        Err(e) => {
            println!("YARA rule update failed: {e}");
            1
        }
    }
}

/// Exit code: 0 clean, 1 suspicious, 2 malicious, 3 nothing flagged but something could not be scanned.
fn cli_scan(args: &[String]) -> i32 {
    winapi::attach_parent_console();
    let json = args.iter().any(|a| a == "--json");
    let sniff_all = !args.iter().any(|a| a == "--fast");
    let out_file = args.iter().position(|a| a == "--out").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let paths: Vec<PathBuf> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| !a.starts_with("--") && !(*i > 0 && args[i - 1] == "--out"))
        .map(|(_, a)| PathBuf::from(a))
        .collect();

    let engine = Engine::new(&config::Config::load());
    let mut out = String::new();
    let mut worst = Verdict::Clean;
    let mut failed = false;
    for p in &paths {
        if let Err(e) = std::fs::metadata(p) {
            out += &format!("[ERROR         ] {}: {e}\n", p.display());
            failed = true;
            continue;
        }
        walk_files(p, &mut |file| {
            match engine.scan_file(file, ScanOptions { source: steam::source_for(file, Source::Manual), sniff_all }) {
                Ok(r) if r.analyzed => {
                    worst = worst.max(r.verdict);
                    if json {
                        out += &serde_json::to_string(&r).unwrap_or_default();
                        out.push('\n');
                    } else {
                        out += &format!("[{:<10} {:>3}] {}\n", r.verdict.label().to_uppercase(), r.score, r.path.display());
                        for f in &r.findings {
                            out += &format!("        {:>+4}  {}\n", f.weight, f.title);
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    out += &format!("[ERROR         ] {}: {e}\n", file.display());
                    failed = true;
                }
            }
            true
        });
    }
    print!("{out}");
    if let Some(f) = out_file {
        let _ = std::fs::write(f, &out);
    }
    match worst {
        // A file that couldn't be read wasn't shown to be clean.
        Verdict::Clean if failed => 3,
        Verdict::Clean => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
    }
}
