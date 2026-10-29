//! On-disk state shared between the background service and the UI:
//! the activity log, the service status heartbeat and the quarantine vault.

use crate::config::{self, write_atomic};
use crate::engine::{Report, Source, Verdict};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ------------------------------------------------------------------ activity log

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    None,
    Quarantined,
    QuarantineFailed,
    Restored,
    Deleted,
    Allowed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub time: i64,
    pub source: Source,
    pub action: Action,
    pub report: Report,
}

const LOG_MAX_BYTES: u64 = 2 << 20;
const LOG_KEEP_LINES: usize = 2000;

pub fn append_event(e: &Event) {
    let path = config::events_path();
    let Ok(line) = serde_json::to_string(e) else { return };
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
    if std::fs::metadata(&path).map(|m| m.len() > LOG_MAX_BYTES).unwrap_or(false) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let lines: Vec<&str> = text.lines().collect();
            let keep = lines[lines.len().saturating_sub(LOG_KEEP_LINES)..].join("\n") + "\n";
            let _ = write_atomic(&path, keep.as_bytes());
        }
    }
}

/// Newest first.
pub fn load_events(max: usize) -> Vec<Event> {
    let text = std::fs::read_to_string(config::events_path()).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(max).collect()
}

// ------------------------------------------------------------------ service status

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchedDir {
    pub path: PathBuf,
    pub source: Source,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub pid: u32,
    pub started: i64,
    pub heartbeat: i64,
    pub scanned: u64,
    pub threats: u64,
    pub queued: usize,
    pub rules: usize,
    pub watched: Vec<WatchedDir>,
    pub current: Option<String>,
}

impl Status {
    pub fn load() -> Self {
        std::fs::read(config::status_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    pub fn save(&self) {
        if let Ok(b) = serde_json::to_vec(self) {
            let _ = write_atomic(&config::status_path(), &b);
        }
    }
}

// ------------------------------------------------------------------ quarantine

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub name: String,
    pub sha256: Option<String>,
    pub size: u64,
    pub time: i64,
    pub verdict: Verdict,
    pub score: i32,
    pub reason: String,
}

const MAGIC: &[u8; 8] = b"VIGILQ1\0";

/// Quarantined files are XOR-encoded so they can't be executed or re-detected by accident.
fn transcode(input: &mut impl Read, output: &mut impl Write) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1 << 20];
    let mut offset = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        for b in &mut buf[..n] {
            *b ^= (offset as u8).wrapping_mul(13) ^ 0x5C;
            offset += 1;
        }
        output.write_all(&buf[..n])?;
    }
}

fn vault_paths(id: &str) -> (PathBuf, PathBuf) {
    let dir = config::quarantine_dir();
    (dir.join(format!("{id}.vq")), dir.join(format!("{id}.json")))
}

pub fn quarantine(report: &Report) -> Result<QuarantineEntry, String> {
    let id = format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let (blob, meta) = vault_paths(&id);
    let encode = || -> std::io::Result<()> {
        let mut src = BufReader::new(File::open(&report.path)?);
        let mut dst = BufWriter::new(File::create(&blob)?);
        dst.write_all(MAGIC)?;
        transcode(&mut src, &mut dst)?;
        dst.flush()
    };
    if let Err(e) = encode() {
        let _ = std::fs::remove_file(&blob);
        return Err(format!("could not copy file: {e}"));
    }
    if let Err(e) = std::fs::remove_file(&report.path) {
        let _ = std::fs::remove_file(&blob);
        return Err(format!("file is in use and could not be removed: {e}"));
    }
    let entry = QuarantineEntry {
        id,
        original_path: report.path.clone(),
        name: report.name.clone(),
        sha256: report.sha256.clone(),
        size: report.size,
        time: now(),
        verdict: report.verdict,
        score: report.score,
        reason: report
            .findings
            .iter()
            .filter(|f| f.weight > 0)
            .max_by_key(|f| f.weight)
            .map(|f| f.title.clone())
            .unwrap_or_default(),
    };
    let _ = std::fs::write(&meta, serde_json::to_vec_pretty(&entry).unwrap_or_default());
    Ok(entry)
}

/// Newest first.
pub fn list_quarantine() -> Vec<QuarantineEntry> {
    let mut v: Vec<QuarantineEntry> = std::fs::read_dir(config::quarantine_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| serde_json::from_slice(&b).ok())
        .collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.time));
    v
}

/// Restores to the original location (or next to it if that name is taken).
pub fn restore(entry: &QuarantineEntry) -> Result<PathBuf, String> {
    let (blob, meta) = vault_paths(&entry.id);
    let mut target = entry.original_path.clone();
    if target.exists() {
        target = unique_sibling(&target);
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let decode = || -> std::io::Result<()> {
        let mut src = BufReader::new(File::open(&blob)?);
        let mut magic = [0u8; 8];
        src.read_exact(&mut magic)?;
        let mut dst = BufWriter::new(File::create(&target)?);
        transcode(&mut src, &mut dst)?;
        dst.flush()
    };
    decode().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(blob);
    let _ = std::fs::remove_file(meta);
    Ok(target)
}

pub fn delete(entry: &QuarantineEntry) -> Result<(), String> {
    let (blob, meta) = vault_paths(&entry.id);
    std::fs::remove_file(blob).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(meta);
    Ok(())
}

fn unique_sibling(path: &Path) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    (1..)
        .map(|i| path.with_file_name(format!("{stem} (restored {i}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}
