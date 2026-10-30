//! Offline MalwareBazaar hash database.
//!
//! The full export is imported once (and refreshed monthly); the 48-hour "recent"
//! export is merged in twice a day. Lookups run against a sorted, memory-mapped file,
//! so a million-plus hashes cost almost no RAM and no hash ever leaves the machine.
//!
//! File layout (little-endian): `VIGILHD1`, record count (u64), family table offset (u64),
//! then sorted 34-byte records (SHA-256 + u16 family index), then the family table
//! (u32 count, each name as u16 length + UTF-8). Family 0 is "unnamed".

use crate::config::{self, write_atomic};
use crate::winapi::NamedMutex;
use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;
use std::time::Duration;

const MAGIC: &[u8; 8] = b"VIGILHD1";
const HEADER: usize = 24;
const RECORD: usize = 34;
const EXPORTS: &str = "https://mb-api.abuse.ch/v2/files/exports";
const FULL_EXPORT: &str = "full.csv.zip";
const RECENT_EXPORT: &str = "recent.csv";
/// The recent export covers 48 hours, so this leaves room for missed runs.
const RECENT_EVERY: i64 = 12 * 3600;
const FULL_EVERY: i64 = 30 * 24 * 3600;
/// Minimum gap between attempts, so a bad key or outage doesn't hammer abuse.ch.
const RETRY_AFTER: i64 = 3600;
/// Shared by the service and the dashboard so only one process updates at a time.
const UPDATE_MUTEX: &str = r"Local\Vigil.HashDbUpdate";

/// Sync state, kept in `hashdb.json` next to the database files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    /// Current database file name inside the data folder.
    pub file: String,
    pub hashes: usize,
    pub full_sync: i64,
    pub recent_sync: i64,
    /// Last update attempt, successful or not.
    pub checked: i64,
    pub error: Option<String>,
}

impl Meta {
    pub fn load() -> Self {
        std::fs::read(config::hashdb_meta_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self) {
        if let Ok(b) = serde_json::to_vec_pretty(self) {
            let _ = write_atomic(&config::hashdb_meta_path(), &b);
        }
    }

    pub fn due(&self, now: i64) -> bool {
        now - self.recent_sync >= RECENT_EVERY && now - self.checked >= RETRY_AFTER
    }
}

pub struct HashDb {
    map: Mmap,
    count: usize,
    families: Vec<String>,
}

impl HashDb {
    /// Opens the database named in `hashdb.json`, if one has been downloaded.
    pub fn open_current() -> Option<Self> {
        let meta = Meta::load();
        if meta.file.is_empty() {
            return None;
        }
        Self::open(&config::data_dir().join(meta.file)).ok()
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: read-only mapping of a file that is never rewritten in place (updates use a new file).
        let map = unsafe { Mmap::map(&file)? };
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "corrupt hash database");
        if map.len() < HEADER || &map[..8] != MAGIC {
            return Err(bad());
        }
        let count = u64::from_le_bytes(map[8..16].try_into().unwrap()) as usize;
        let table = u64::from_le_bytes(map[16..24].try_into().unwrap()) as usize;
        if count.checked_mul(RECORD).and_then(|n| n.checked_add(HEADER)) != Some(table) || table + 4 > map.len() {
            return Err(bad());
        }
        let mut families = Vec::new();
        let n = u32::from_le_bytes(map[table..table + 4].try_into().unwrap());
        let mut pos = table + 4;
        for _ in 0..n {
            let len = u16::from_le_bytes(map.get(pos..pos + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
            let name = map.get(pos + 2..pos + 2 + len).ok_or_else(bad)?;
            families.push(String::from_utf8_lossy(name).into_owned());
            pos += 2 + len;
        }
        Ok(Self { map, count, families })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    fn record(&self, i: usize) -> (&[u8], u16) {
        let r = &self.map[HEADER + i * RECORD..HEADER + (i + 1) * RECORD];
        (&r[..32], u16::from_le_bytes([r[32], r[33]]))
    }

    fn family(&self, idx: u16) -> &str {
        self.families.get(idx as usize).map(String::as_str).unwrap_or("")
    }

    /// Returns the malware family ("" when MalwareBazaar has none) if the hash is known.
    pub fn lookup(&self, sha256: &[u8; 32]) -> Option<&str> {
        let (mut lo, mut hi) = (0, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (hash, family) = self.record(mid);
            match hash.cmp(sha256) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(self.family(family)),
            }
        }
        None
    }
}

/// Collects hashes, interning family names, and writes the sorted database file.
pub(crate) struct Builder {
    entries: Vec<([u8; 32], u16)>,
    families: Vec<String>,
    index: HashMap<String, u16>,
}

impl Builder {
    pub(crate) fn new() -> Self {
        Self { entries: Vec::new(), families: vec![String::new()], index: HashMap::from([(String::new(), 0)]) }
    }

    pub(crate) fn add(&mut self, hash: [u8; 32], family: &str) {
        let idx = match self.index.get(family) {
            Some(&i) => i,
            None if self.families.len() < u16::MAX as usize => {
                let i = self.families.len() as u16;
                self.families.push(family.to_string());
                self.index.insert(family.to_string(), i);
                i
            }
            None => 0,
        };
        self.entries.push((hash, idx));
    }

    fn merge_from(&mut self, db: &HashDb) {
        self.entries.reserve(db.len());
        for i in 0..db.len() {
            let (hash, family) = db.record(i);
            self.add(hash.try_into().unwrap(), db.family(family));
        }
    }

    /// Sorts and de-duplicates; a named family wins over an unnamed duplicate.
    fn finish(&mut self) -> usize {
        self.entries.sort_by_key(|e| e.0);
        self.entries.dedup_by(|later, kept| {
            let same = later.0 == kept.0;
            if same && kept.1 == 0 {
                kept.1 = later.1;
            }
            same
        });
        self.entries.len()
    }

    pub(crate) fn write(&mut self, path: &Path) -> io::Result<usize> {
        let count = self.finish();
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(MAGIC)?;
        out.write_all(&(count as u64).to_le_bytes())?;
        out.write_all(&((HEADER + count * RECORD) as u64).to_le_bytes())?;
        for (hash, family) in &self.entries {
            out.write_all(hash)?;
            out.write_all(&family.to_le_bytes())?;
        }
        out.write_all(&(self.families.len() as u32).to_le_bytes())?;
        for name in &self.families {
            let mut end = name.len().min(255);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            out.write_all(&(end as u16).to_le_bytes())?;
            out.write_all(&name.as_bytes()[..end])?;
        }
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(count)
    }
}

/// Imports a MalwareBazaar CSV export. Columns come from the (usually `#`-commented)
/// header line; without one, the SHA-256 is the first field of 64 hex digits.
pub(crate) fn import_csv(reader: impl BufRead, b: &mut Builder) -> io::Result<usize> {
    let (mut sha_col, mut sig_col) = (None, None);
    let mut added = 0;
    for line in reader.split(b'\n') {
        let line = line?;
        let line = String::from_utf8_lossy(&line);
        let line = line.trim();
        let (header, body) = match line.strip_prefix('#') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        if body.is_empty() {
            continue;
        }
        let fields = split_csv(body);
        if let Some(i) = fields.iter().position(|f| f == "sha256_hash" || f == "sha256") {
            sha_col = Some(i);
            sig_col = fields.iter().position(|f| f == "signature");
            continue;
        }
        if header {
            continue;
        }
        let hash = sha_col.and_then(|i| fields.get(i)).and_then(|f| parse_sha256(f)).or_else(|| fields.iter().find_map(|f| parse_sha256(f)));
        let Some(hash) = hash else { continue };
        let family = sig_col.and_then(|i| fields.get(i)).map(String::as_str).filter(|s| !matches!(*s, "n/a" | "null" | "None")).unwrap_or("");
        b.add(hash, family);
        added += 1;
    }
    Ok(added)
}

/// Imports a downloaded export, either a plain CSV or a ZIP of CSV files.
fn import_file(path: &Path, b: &mut Builder) -> io::Result<usize> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 2];
    let zipped = file.read_exact(&mut magic).is_ok() && &magic == b"PK";
    file.rewind()?;
    if !zipped {
        return import_csv(BufReader::new(file), b);
    }
    let mut zip = zip::ZipArchive::new(BufReader::new(file)).map_err(io::Error::other)?;
    let mut added = 0;
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(io::Error::other)?;
        if !entry.is_dir() {
            added += import_csv(BufReader::new(entry), b)?;
        }
    }
    Ok(added)
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur).trim().to_string()),
            c => cur.push(c),
        }
    }
    fields.push(cur.trim().to_string());
    fields
}

pub fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != 64 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(s[2 * i])? << 4) | nibble(s[2 * i + 1])?;
    }
    Some(out)
}

/// Downloads whatever exports are due and swaps in a new database.
/// Returns the number of known hashes.
pub fn update(key: &str, force: bool) -> Result<usize, String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("No MalwareBazaar Auth-Key set".into());
    }
    if !key.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err("The MalwareBazaar Auth-Key contains unexpected characters".into());
    }
    let Some(_lock) = NamedMutex::acquire(UPDATE_MUTEX) else {
        return Err("An update is already running".into());
    };
    let mut meta = Meta::load();
    let now = crate::store::now();
    if !force && !meta.due(now) {
        return Ok(meta.hashes);
    }
    meta.checked = now;
    let result = sync(key, &mut meta, now);
    meta.error = match &result {
        Ok((_, warning)) => warning.clone(),
        Err(e) => Some(e.clone()),
    };
    meta.save();
    result.map(|(n, _)| n)
}

/// Returns the hash count and a warning when only part of the update worked.
fn sync(key: &str, meta: &mut Meta, now: i64) -> Result<(usize, Option<String>), String> {
    let dir = config::data_dir();
    let tmp = dir.join("hashdb-download.tmp");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(Duration::from_secs(120)))
        .build()
        .into();
    let current = HashDb::open_current();
    let mut b = Builder::new();
    let mut warning = None;

    let full_ok = if current.is_none() || now - meta.full_sync >= FULL_EVERY {
        match fetch(&agent, key, FULL_EXPORT, &tmp).and_then(|_| import_file(&tmp, &mut b).map_err(|e| e.to_string())) {
            Ok(n) if n > 0 => true,
            Ok(_) => {
                warning = Some("The full MalwareBazaar dump contained no hashes".to_string());
                false
            }
            Err(e) => {
                warning = Some(format!("Full dump failed: {e}"));
                false
            }
        }
    } else {
        false
    };
    if !full_ok {
        b = Builder::new();
        if let Some(db) = &current {
            b.merge_from(db);
        }
    }
    drop(current);

    let recent = fetch(&agent, key, RECENT_EXPORT, &tmp).and_then(|_| import_file(&tmp, &mut b).map_err(|e| e.to_string()));
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = &recent {
        if !full_ok {
            return Err(match warning {
                Some(w) => format!("{w}; recent export failed: {e}"),
                None => e.clone(),
            });
        }
        warning = Some(format!("Recent export failed: {e}"));
    }

    let name = format!("hashdb-{}.bin", chrono::Utc::now().timestamp_millis());
    let count = b.write(&dir.join(&name)).map_err(|e| format!("Could not write the hash database: {e}"))?;
    if count == 0 {
        let _ = std::fs::remove_file(dir.join(&name));
        return Err("MalwareBazaar returned no hashes".into());
    }
    meta.file = name;
    meta.hashes = count;
    if full_ok {
        meta.full_sync = now;
    }
    if recent.is_ok() {
        meta.recent_sync = now;
    }
    meta.save();
    remove_stale(&dir, &meta.file);
    Ok((count, warning))
}

fn fetch(agent: &ureq::Agent, key: &str, export: &str, dest: &Path) -> Result<(), String> {
    let mut resp = agent.get(&format!("{EXPORTS}/{key}/{export}")).call().map_err(|e| match e {
        ureq::Error::StatusCode(401 | 403) => "MalwareBazaar rejected the Auth-Key".to_string(),
        ureq::Error::StatusCode(code) => format!("MalwareBazaar returned HTTP {code}"),
        // The key is part of the URL; keep it out of anything shown or logged.
        e => e.to_string().replace(key, "***"),
    })?;
    let mut write = || -> io::Result<()> {
        let mut out = BufWriter::new(File::create(dest)?);
        io::copy(&mut resp.body_mut().as_reader(), &mut out)?;
        out.flush()
    };
    write().map_err(|e| format!("Download of {export} failed: {}", e.to_string().replace(key, "***")))
}

/// Deletes older database files. Files still mapped by another process fail to
/// delete on Windows; they are retried after the next update.
fn remove_stale(dir: &Path, current: &str) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("hashdb-") && name.ends_with(".bin") && name != current {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
