//! ZIP inspection: flags classic delivery tricks and scans executables inside.

use super::filetype::{self, Kind};
use super::{Engine, Finding};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read};

const MAX_ENTRIES: usize = 5000;
const MAX_INNER_SIZE: u64 = 64 << 20;
/// Unpacked bytes analyzed per archive, so a small ZIP that inflates to gigabytes can't
/// hold up the scan queue (a few seconds of work at most).
const MAX_TOTAL_INFLATED: u64 = 256 << 20;
/// Members analyzed per archive; each one costs a full rule and YARA pass.
const MAX_INSPECTED: usize = 500;

pub fn analyze(engine: &Engine, data: &[u8], depth: u32) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(data)) else {
        return findings;
    };

    let mut encrypted_code = None;
    let mut risky = None;
    let mut worst: Option<(String, i32, Vec<Finding>)> = None;
    let mut inspected = 0usize;
    let mut skipped = 0usize;
    let mut budget = MAX_TOTAL_INFLATED;
    // Entries that share their data (a classic ZIP bomb) are unpacked once.
    let mut offsets = HashSet::new();

    for i in 0..zip.len().min(MAX_ENTRIES) {
        let (name, encrypted, size, is_dir, offset) = match zip.by_index_raw(i) {
            Ok(e) => (e.name().map(|n| n.into_owned()).unwrap_or_default(), e.encrypted(), e.size(), e.is_dir(), e.header_start()),
            Err(_) => continue,
        };
        if is_dir {
            continue;
        }
        let base = name.rsplit(['/', '\\']).next().unwrap_or(&name).to_string();
        let ext = filetype::ext_of(&base);
        let code_like = filetype::is_code_ext(&ext);

        // Only disguise tricks here; risky member types are reported once below.
        for f in filetype::name_findings(&base, guess_kind(&ext)).into_iter().filter(|f| f.id.starts_with("name.") && f.id != "name.risky_ext") {
            if !findings.iter().any(|x: &Finding| x.id == f.id) {
                findings.push(Finding::new(f.id, format!("{base}: {}", f.title), f.weight));
            }
        }
        if encrypted && code_like && encrypted_code.is_none() {
            encrypted_code = Some(base.clone());
        }
        if matches!(ext.as_str(), "lnk" | "hta" | "js" | "jse" | "vbs" | "vbe" | "wsf" | "scr") && risky.is_none() {
            risky = Some(base.clone());
        }

        if encrypted || !code_like || size > MAX_INNER_SIZE || depth > 0 || !offsets.insert(offset) {
            continue;
        }
        // The declared size can lie, so what is actually unpacked is charged too.
        if size > budget || inspected >= MAX_INSPECTED {
            skipped += 1;
            continue;
        }
        let mut buf = Vec::with_capacity(size as usize);
        let Ok(entry) = zip.by_index(i) else { continue };
        let read = entry.take(MAX_INNER_SIZE.min(budget)).read_to_end(&mut buf);
        budget -= buf.len() as u64;
        if read.is_err() {
            continue;
        }
        let known = engine.known_hash(&super::hex(&Sha256::digest(&buf)));
        let kind = filetype::classify(&base, &buf[..buf.len().min(512)]);
        if kind == Kind::Other && known.is_none() {
            continue;
        }
        inspected += 1;
        let (mut score, mut inner) = if kind == Kind::Other { (0, Vec::new()) } else { engine.analyze_buffer(&base, &buf, kind, depth + 1) };
        if let Some(f) = known {
            score += f.weight;
            inner.insert(0, f);
        }
        if worst.as_ref().is_none_or(|w| score > w.1) {
            worst = Some((base, score, inner));
        }
    }

    if let Some(name) = encrypted_code {
        findings.push(Finding::new(
            "zip.encrypted_code",
            format!("Password-protected archive hides a program ({name}); a common way to sneak malware past scanners"),
            35,
        ));
    }
    if let Some(name) = risky {
        findings.push(Finding::new("zip.risky_member", format!("Archive contains {name}, a file type rarely legitimate in downloads"), 20));
    }
    if let Some((name, score, inner)) = worst {
        if score > 0 {
            findings.extend(inner.into_iter().map(|f| Finding::new(f.id, format!("{name}: {}", f.title), f.weight)));
        }
    }
    if inspected > 0 {
        findings.push(Finding::new("zip.inspected", format!("Inspected {inspected} program(s) inside the archive"), 0));
    }
    if skipped > 0 {
        findings.push(Finding::new(
            "zip.partial",
            format!("{skipped} more program(s) inside were not inspected: the archive is too large to unpack completely"),
            0,
        ));
    }
    findings
}

fn guess_kind(ext: &str) -> Kind {
    match ext {
        "lnk" => Kind::Shortcut,
        "zip" => Kind::Zip,
        "msi" => Kind::Installer,
        e if filetype::SCRIPT_EXTS.contains(&e) => Kind::Script,
        e if filetype::is_code_ext(e) => Kind::Pe,
        _ => Kind::Other,
    }
}
