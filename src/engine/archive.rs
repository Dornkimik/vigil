//! ZIP inspection: flags classic delivery tricks and scans executables inside.

use super::filetype::{self, Kind};
use super::{Engine, Finding};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const MAX_ENTRIES: usize = 5000;
const MAX_INNER_SIZE: u64 = 64 << 20;

pub fn analyze(engine: &Engine, data: &[u8], depth: u32) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(data)) else {
        return findings;
    };

    let mut encrypted_code = None;
    let mut risky = None;
    let mut worst: Option<(String, i32, Vec<Finding>)> = None;
    let mut inspected = 0usize;

    for i in 0..zip.len().min(MAX_ENTRIES) {
        let (name, encrypted, size, is_dir) = match zip.by_index_raw(i) {
            Ok(e) => (e.name().map(|n| n.into_owned()).unwrap_or_default(), e.encrypted(), e.size(), e.is_dir()),
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

        if encrypted || !code_like || size > MAX_INNER_SIZE || depth > 0 {
            continue;
        }
        let mut buf = Vec::with_capacity(size as usize);
        let Ok(entry) = zip.by_index(i) else { continue };
        if entry.take(MAX_INNER_SIZE).read_to_end(&mut buf).is_err() {
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
