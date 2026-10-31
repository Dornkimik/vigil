//! The scanning engine: classifies a file, runs heuristics, checks reputation
//! and turns everything into a scored [`Report`].

pub mod archive;
mod deobfuscate;
pub mod filetype;
pub mod hashdb;
pub mod pe;
pub mod rules;
#[cfg(test)]
mod tests;

use crate::config::{self, Config};
use crate::winapi::{self, InvalidReason, Signature};
pub use filetype::Kind;
use rules::{RuleSet, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const SUSPICIOUS: i32 = 35;
pub const MALICIOUS: i32 = 70;
/// Files larger than this only get name/signature/hash checks.
const MAX_CONTENT_SCAN: u64 = 512 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn from_score(score: i32) -> Self {
        match score {
            s if s >= MALICIOUS => Verdict::Malicious,
            s if s >= SUSPICIOUS => Verdict::Suspicious,
            _ => Verdict::Clean,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "Clean",
            Verdict::Suspicious => "Suspicious",
            Verdict::Malicious => "Malicious",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub weight: i32,
}

impl Finding {
    pub fn new(id: impl Into<String>, title: impl Into<String>, weight: i32) -> Self {
        Self { id: id.into(), title: title.into(), weight }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Downloads,
    Steam,
    Workshop,
    /// Steam's staging folders (`steamapps\downloading`, `steamapps\temp`): files may still be partial.
    SteamDownload,
    Folder,
    Manual,
    Launch,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Downloads => "Downloads",
            Source::Steam => "Steam game",
            Source::Workshop => "Steam Workshop",
            Source::SteamDownload => "Steam download",
            Source::Folder => "Watched folder",
            Source::Manual => "Manual scan",
            Source::Launch => "Program started",
        }
    }

    pub fn is_steam(self) -> bool {
        matches!(self, Source::Steam | Source::Workshop | Source::SteamDownload)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScanOptions {
    pub source: Source,
    /// Sniff file headers of every file instead of only code-like extensions.
    pub sniff_all: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub path: PathBuf,
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub sha256: Option<String>,
    pub score: i32,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub signer: Option<String>,
    /// Download URL from the Mark-of-the-Web, if any.
    pub origin: Option<String>,
    /// False when the file was skipped (not a code-carrying file type).
    pub analyzed: bool,
}

impl Report {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            kind: Kind::Other,
            size: 0,
            sha256: None,
            score: 0,
            verdict: Verdict::Clean,
            findings: Vec::new(),
            signer: None,
            origin: None,
            analyzed: false,
        }
    }
}

pub struct Engine {
    rules: RuleSet,
    rule_errors: Vec<String>,
    blocklist: HashSet<String>,
    allowlist: HashSet<String>,
    hashdb: Option<hashdb::HashDb>,
    mb_key: String,
    mb_cache: Mutex<HashMap<String, Option<String>>>,
    agent: ureq::Agent,
}

impl Engine {
    pub fn new(cfg: &Config) -> Self {
        let custom = std::fs::read_to_string(config::custom_rules_path()).ok();
        let (rules, rule_errors) = RuleSet::load(custom.as_deref());
        let blocklist = std::fs::read_to_string(config::blocklist_path())
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|l| l.len() == 64 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        let agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).build().into();
        Self {
            rules,
            rule_errors,
            blocklist,
            allowlist: cfg.allowlist.iter().map(|h| h.to_ascii_lowercase()).collect(),
            hashdb: hashdb::HashDb::open_current(),
            mb_key: cfg.malwarebazaar_key.trim().to_string(),
            mb_cache: Mutex::new(HashMap::new()),
            agent,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rule_errors(&self) -> &[String] {
        &self.rule_errors
    }

    /// Local known-bad checks: the user's blocklist and the offline MalwareBazaar database.
    pub(crate) fn known_hash(&self, sha256: &str) -> Option<Finding> {
        if self.blocklist.contains(sha256) {
            return Some(Finding::new("hash.blocklist", "Hash is on your local blocklist", 100));
        }
        let family = self.hashdb.as_ref()?.lookup(&hashdb::parse_sha256(sha256)?)?;
        Some(malwarebazaar_finding(family))
    }

    /// Scans one file. I/O errors (e.g. the file is still locked by the browser)
    /// are returned so the caller can retry later.
    pub fn scan_file(&self, path: &Path, opts: ScanOptions) -> io::Result<Report> {
        let mut r = Report::new(path);
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() || meta.len() == 0 {
            return Ok(r);
        }
        r.size = meta.len();
        let ext = filetype::ext_of(&r.name);
        if !opts.sniff_all && !filetype::is_code_ext(&ext) {
            return Ok(r);
        }

        let mut file = File::open(path)?;
        let mut head = [0u8; 512];
        let n = read_up_to(&mut file, &mut head)?;
        r.kind = filetype::classify(&r.name, &head[..n]);
        if r.kind == Kind::Other {
            return Ok(r);
        }
        r.analyzed = true;

        if let Some(o) = winapi::zone_identifier(path).filter(|o| o.zone >= 3) {
            r.origin = Some(o.url.unwrap_or_else(|| "the internet".into()));
        }

        let mut findings = filetype::name_findings(&r.name, r.kind);
        if opts.source.is_steam() {
            // Games legitimately ship .js (Electron/web UIs); the extension alone means nothing there.
            findings.retain(|f| f.id != "name.risky_ext");
        }
        if opts.source == Source::Workshop && matches!(r.kind, Kind::Pe | Kind::Script) {
            findings.push(Finding::new("steam.workshop_code", "Steam Workshop item ships executable code", 10));
        }

        // Content analysis works on a memory map so large game DLLs never sit on the heap.
        let file = File::open(path)?;
        let map = if r.size <= MAX_CONTENT_SCAN && r.kind != Kind::DiskImage {
            // SAFETY: read-only mapping; Windows refuses to truncate a mapped file.
            unsafe { memmap2::Mmap::map(&file) }.ok()
        } else {
            None
        };
        r.sha256 = match &map {
            Some(m) => Some(hex(&Sha256::digest(&m[..]))),
            None if r.kind != Kind::DiskImage => sha256_stream(file).ok(),
            None => None,
        };

        if let Some(h) = &r.sha256 {
            if self.allowlist.contains(h) {
                r.findings.push(Finding::new("allowlist", "You marked this file as safe", 0));
                return Ok(r);
            }
            findings.extend(self.known_hash(h));
        }

        if let Some(m) = &map {
            findings.extend(self.analyze_buffer(&r.name, m, r.kind, 0).1);
        }
        drop(map);

        if matches!(r.kind, Kind::Pe | Kind::Installer) {
            match winapi::verify_signature(path) {
                Signature::Valid(s) => r.signer = Some(s),
                sig => findings.extend(signature_finding(&sig, r.kind, opts.source)),
            }
        }

        let mut known_bad = findings.iter().any(|f| f.id.starts_with("hash."));
        // Online lookups only bridge the gap until the offline database has been downloaded.
        if r.signer.is_none()
            && !known_bad
            && self.hashdb.is_none()
            && let Some(family) = r.sha256.as_deref().and_then(|h| self.reputation(h))
        {
            findings.push(malwarebazaar_finding(&family));
            known_bad = true;
        }

        let mut score: i32 = findings.iter().map(|f| f.weight).sum();
        if let Some(signer) = &r.signer {
            // A valid signature from a real publisher removes most heuristic suspicion
            // (security and anti-cheat tools legitimately contain many indicators).
            let credit = if known_bad { 0 } else { score.max(0) * 3 / 5 };
            findings.push(Finding::new("sig.valid", format!("Signed by {signer}"), -credit));
            score -= credit;
        }
        if known_bad {
            score = score.max(100);
        }
        r.score = score.max(0);
        r.verdict = Verdict::from_score(r.score);
        r.findings = findings;
        Ok(r)
    }

    /// Content heuristics for an in-memory buffer (a file or an archive member).
    pub(crate) fn analyze_buffer(&self, name: &str, data: &[u8], kind: Kind, depth: u32) -> (i32, Vec<Finding>) {
        let mut findings = Vec::new();
        let scope = match kind {
            Kind::Pe | Kind::Installer => Some(Scope::Pe),
            Kind::Script => Some(Scope::Script),
            Kind::Shortcut => Some(Scope::Shortcut),
            _ => None,
        };
        if let Some(scope) = scope {
            let views = match kind {
                Kind::Script => deobfuscate::views(name, data),
                Kind::Shortcut => deobfuscate::views("shortcut.lnk", data),
                _ => Vec::new(),
            };
            let matches = if views.is_empty() { self.rules.scan(data, scope) } else { self.rules.scan_views(data, &views, scope) };
            for m in matches {
                let shown: Vec<&str> = m.matched.iter().take(4).copied().collect();
                let more = if m.matched.len() > 4 { format!(" +{} more", m.matched.len() - 4) } else { String::new() };
                let recovered = if m.decoded { " (recovered from encoded/obfuscated text)" } else { "" };
                let title = format!("{}{recovered} [{}{more}]", m.rule.desc, shown.join(", "));
                findings.push(Finding::new(format!("rule.{}", m.rule.id), title, m.rule.weight));
            }
            correlate(&mut findings);
        }
        match kind {
            Kind::Pe => findings.extend(pe::analyze(data)),
            Kind::Script => findings.extend(filetype::script_findings(name, data)),
            Kind::Zip => findings.extend(archive::analyze(self, data, depth)),
            _ => {}
        }
        (findings.iter().map(|f| f.weight).sum(), findings)
    }

    /// Optional hash lookup on abuse.ch MalwareBazaar. Only the SHA-256 leaves the machine.
    fn reputation(&self, sha256: &str) -> Option<String> {
        if self.mb_key.is_empty() {
            return None;
        }
        if let Some(hit) = self.mb_cache.lock().unwrap().get(sha256) {
            return hit.clone();
        }
        let body = self
            .agent
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", &self.mb_key)
            .send_form([("query", "get_info"), ("hash", sha256)])
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()?;
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let result = match v["query_status"].as_str()? {
            "ok" => Some(v["data"][0]["signature"].as_str().unwrap_or("").to_string()),
            "hash_not_found" => None,
            _ => return None, // auth/rate-limit errors: don't cache
        };
        self.mb_cache.lock().unwrap().insert(sha256.to_string(), result.clone());
        result
    }
}

fn malwarebazaar_finding(family: &str) -> Finding {
    let family = if family.is_empty() { "unnamed sample" } else { family };
    Finding::new("hash.malwarebazaar", format!("Known malware on MalwareBazaar: {family}"), 100)
}

/// Independent capabilities corroborate one another. A filename, packer,
/// encoding scheme or family name never earns a behavioral correlation bonus.
fn correlate(findings: &mut Vec<Finding>) {
    let has = |id: &str| findings.iter().any(|f| f.id == id);
    let theft = [
        "browser_credentials",
        "discord_tokens",
        "crypto_wallets",
        "telegram_session",
        "steam_session",
        "keylogger",
        "keylogger_hook",
        "credential_dump",
    ]
    .iter()
    .any(|id| has(&format!("rule.stealer.{id}")));
    let exfil = has("rule.stealer.exfil_channel");
    let loader = has("rule.loader.download_cradle") || has("rule.loader.script_dropper") || has("rule.loader.memory_payload");
    let tamper = ["defender_tamper", "amsi_tamper", "kill_security_tools", "ifeo_hijack"].iter().any(|id| has(&format!("rule.evasion.{id}")));
    let ransom = has("rule.impact.ransomware") && has("rule.impact.ransom_note");
    let hidden_desktop = has("rule.impact.hidden_desktop");
    if theft && exfil {
        findings.push(Finding::new("behavior.theft_exfil", "Credential/session collection combined with an exfiltration endpoint", 30));
    }
    if loader && tamper {
        findings.push(Finding::new("behavior.loader_evasion", "Payload execution combined with security tampering", 25));
    }
    if theft && tamper {
        findings.push(Finding::new("behavior.theft_evasion", "Credential/session collection combined with security tampering", 25));
    }
    if theft && hidden_desktop {
        findings.push(Finding::new("behavior.hidden_remote_control", "Credential/session collection combined with hidden-desktop remote control", 20));
    }
    if ransom {
        findings.push(Finding::new("behavior.ransomware", "Backup destruction combined with a ransom demand", 35));
    }
}

/// Finding for a signature that is missing or does not verify.
fn signature_finding(sig: &Signature, kind: Kind, source: Source) -> Option<Finding> {
    match sig {
        Signature::Valid(_) => None,
        Signature::Unsigned => (kind == Kind::Pe).then(|| Finding::new("sig.unsigned", "Not digitally signed", 5)),
        // Steam is still writing the file, so its hash can't match yet; the finished file
        // is scanned again once Steam moves it into steamapps\common.
        Signature::Invalid(InvalidReason::Tampered | InvalidReason::Other(_)) if source == Source::SteamDownload => None,
        Signature::Invalid(InvalidReason::Tampered) => {
            Some(Finding::new("sig.tampered", "Digital signature is broken: file was modified after signing", 30))
        }
        Signature::Invalid(InvalidReason::Untrusted) => {
            Some(Finding::new("sig.untrusted", "Signed with an untrusted or self-signed certificate", 15))
        }
        Signature::Invalid(InvalidReason::Other(c)) => {
            Some(Finding::new("sig.invalid", format!("Digital signature does not verify (0x{c:08X})"), 10))
        }
    }
}

fn read_up_to(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn sha256_stream(mut f: File) -> io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf)? {
            0 => break,
            n => h.update(&buf[..n]),
        }
    }
    Ok(hex(&h.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
