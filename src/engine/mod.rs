//! The scanning engine: classifies a file, runs heuristics, checks reputation
//! and turns everything into a scored [`Report`].

pub mod archive;
mod deobfuscate;
pub mod filetype;
pub mod hashdb;
pub mod memory;
pub mod pe;
pub mod rules;
#[cfg(test)]
mod tests;
pub mod yara;

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
/// Chromium-based programs are well over 100 MB of code; a small program that
/// merely mentions the engine's marker strings is not a browser engine.
const BROWSER_ENGINE_SIZE: usize = 64 << 20;
/// Capabilities every Chromium build has (sandbox desktops, window capture, input
/// hooks, writing into its own child processes, its password manager and importer
/// for other browsers' profiles), so they say nothing about the app. Rules for other
/// people's data (Discord, wallets, exfiltration endpoints) still apply.
const BROWSER_ENGINE_EXPECTED: &[&str] = &[
    "rule.impact.hidden_desktop",
    "rule.stealer.keylogger_hook",
    "rule.stealer.browser_credentials",
    "rule.stealer.browser_profiles",
    "pe.injection",
];

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
    yara: yara::Yara,
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
            yara: yara::Yara::load(),
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

    pub fn yara(&self) -> &yara::Yara {
        &self.yara
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
            // Nothing to analyze, but known samples (Linux/macOS/Android malware, payloads
            // under a harmless name) are still flagged. Steam's asset files stay unread.
            if opts.sniff_all && r.size <= MAX_CONTENT_SCAN {
                let file = File::open(path)?;
                // SAFETY: read-only mapping; Windows refuses to truncate a mapped file.
                let map = unsafe { memmap2::Mmap::map(&file)? };
                let h = hex(&Sha256::digest(&map[..]));
                let mut findings: Vec<Finding> = self.known_hash(&h).into_iter().collect();
                // Programs for Linux and macOS can't run here, but YARA rules still recognize them.
                if findings.is_empty() && filetype::is_foreign_executable(&head[..n]) {
                    findings = self.yara.scan(&map);
                }
                let score = findings.iter().map(|f| f.weight).sum::<i32>().max(0);
                if score > 0 && !self.allowlist.contains(&h) {
                    r.analyzed = true;
                    r.origin = origin(path);
                    r.sha256 = Some(h);
                    r.score = score;
                    r.verdict = Verdict::from_score(score);
                    r.findings = findings;
                }
            }
            return Ok(r);
        }
        r.analyzed = true;
        r.origin = origin(path);

        let downloaded = r.origin.is_some() || opts.source == Source::Downloads;
        let mut findings = name_findings(&r.name, r.kind, opts.source, downloaded);

        if r.kind == Kind::Pe {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            findings.extend(filetype::impostor_finding(path, &root));
        }

        // Content analysis works on a memory map so large game DLLs never sit on the heap.
        // Oversized programs are mapped too, so padding them past the limit doesn't skip analysis.
        let file = File::open(path)?;
        let map = if (r.size <= MAX_CONTENT_SCAN || r.kind == Kind::Pe) && r.kind != Kind::DiskImage {
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

        if matches!(r.kind, Kind::Pe | Kind::Installer) {
            match winapi::verify_signature(path) {
                Signature::Valid(s) => r.signer = Some(s),
                sig => findings.extend(signature_finding(&sig, r.kind, opts.source)),
            }
        }

        if let Some(m) = &map {
            let body = if r.size > MAX_CONTENT_SCAN { &m[..pe::image_end(m).min(MAX_CONTENT_SCAN as usize)] } else { &m[..] };
            // The signature credit below would cancel a YARA match on a signed program, and
            // signed engines and drivers are the bulk of a Steam library: skip it there.
            findings.extend(self.analyze(&r.name, body, r.kind, 0, r.signer.is_none()).1);
            if body.len() < m.len() && !findings.iter().any(|f| f.id == "pe.inflated") {
                findings.extend(pe::inflated(m));
            }
        }
        drop(map);

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
            // (security and anti-cheat tools legitimately contain many indicators),
            // unless something is hidden inside the signature itself.
            let smuggled = findings.iter().any(|f| f.id == "pe.cert_smuggling");
            let credit = if known_bad || smuggled { 0 } else { score.max(0) * 3 / 5 };
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
        self.analyze(name, data, kind, depth, true)
    }

    fn analyze(&self, name: &str, data: &[u8], kind: Kind, depth: u32, yara: bool) -> (i32, Vec<Finding>) {
        let mut findings = Vec::new();
        let mut browser_engine = false;
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
            if yara {
                findings.extend(self.yara.scan(data));
            }
            findings.extend(matches.iter().map(rule_finding));
            browser_engine = kind == Kind::Pe
                && data.len() >= BROWSER_ENGINE_SIZE
                && findings.iter().any(|f| f.id == "rule.info.chromium_engine")
                && pe::inflated(data).is_none();
            if browser_engine {
                findings.retain(|f| !BROWSER_ENGINE_EXPECTED.contains(&f.id.as_str()));
            } else {
                findings.retain(|f| f.id != "rule.info.chromium_engine");
            }
            correlate(&mut findings);
        }
        match kind {
            Kind::Pe => {
                let structural = pe::analyze(data).into_iter();
                findings.extend(structural.filter(|f| !browser_engine || !BROWSER_ENGINE_EXPECTED.contains(&f.id.as_str())))
            }
            Kind::Script => findings.extend(filetype::script_findings(name, data)),
            Kind::Zip => findings.extend(archive::analyze(self, data, depth)),
            _ => {}
        }
        (findings.iter().map(|f| f.weight).sum(), findings)
    }

    /// Findings in a running program's memory that its file scan (`file`) didn't already
    /// make. Structure checks are left out: memory layout says nothing about packing.
    pub fn scan_memory(&self, file: &[Finding], blocks: &[memory::Block]) -> Vec<Finding> {
        let in_file = |id: &str| file.iter().any(|f| f.id == id);
        let mut found = Vec::new();
        let mut yara = Vec::new();
        for block in blocks {
            match block.kind {
                memory::BlockKind::Replaced => found.push(Finding::new(
                    "memory.hollowed",
                    "The program's code was replaced in memory after it started (process hollowing)",
                    60,
                )),
                memory::BlockKind::Private if pe::native_header(&block.data) => found.push(Finding::new(
                    "memory.unbacked_program",
                    "Runs a program loaded straight into memory, with no file behind it",
                    25,
                )),
                _ => {}
            }
            found.extend(self.rules.scan(&block.data, Scope::Pe).iter().map(rule_finding));
            yara.extend(self.yara.scan(&block.data));
        }
        // Several blocks can match the same rule; the strongest match counts.
        yara.sort_by_key(|f| -f.weight);
        found.append(&mut yara);
        let mut seen = HashSet::new();
        found.retain(|f| seen.insert(f.id.clone()) && !in_file(&f.id) && f.id != "rule.info.chromium_engine");
        if in_file("rule.info.chromium_engine") {
            found.retain(|f| !BROWSER_ENGINE_EXPECTED.contains(&f.id.as_str()));
        }
        let (mut yara, mut found): (Vec<_>, Vec<_>) = found.into_iter().partition(|f| f.id.starts_with("yara."));
        yara::cap_extra_matches(&mut yara, file.iter().any(|f| f.id.starts_with("yara.") && f.weight > 0));
        found.append(&mut yara);
        for f in &mut found {
            if f.id.starts_with("rule.") || f.id.starts_with("yara.") {
                f.title = format!("In memory: {}", f.title);
            }
        }
        // What memory revealed can complete a combination the file only showed half of.
        let mut all: Vec<Finding> = file.iter().chain(&found).cloned().collect();
        let before = all.len();
        correlate(&mut all);
        found.extend(all.drain(before..).filter(|f| !in_file(&f.id)));
        found
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

/// Filename findings, adjusted for where the file lives.
fn name_findings(name: &str, kind: Kind, source: Source, downloaded: bool) -> Vec<Finding> {
    let mut findings = filetype::name_findings(name, kind);
    // Games and Electron/Node apps ship .js (web UIs, bundles); the extension alone means
    // nothing there. A .js that arrived from the internet is still the classic WSH dropper.
    if source.is_steam() || (filetype::ext_of(name) == "js" && !downloaded) {
        findings.retain(|f| f.id != "name.risky_ext");
    }
    if source == Source::Workshop && matches!(kind, Kind::Pe | Kind::Script) {
        findings.push(Finding::new("steam.workshop_code", "Steam Workshop item ships executable code", 10));
    }
    findings
}

fn rule_finding(m: &rules::RuleMatch) -> Finding {
    let shown: Vec<&str> = m.matched.iter().take(4).copied().collect();
    let more = if m.matched.len() > 4 { format!(" +{} more", m.matched.len() - 4) } else { String::new() };
    let recovered = if m.decoded { " (recovered from encoded/obfuscated text)" } else { "" };
    let title = format!("{}{recovered} [{}{more}]", m.rule.desc, shown.join(", "));
    Finding::new(format!("rule.{}", m.rule.id), title, m.rule.weight)
}

fn malwarebazaar_finding(family: &str) -> Finding {
    let family = if family.is_empty() { "unnamed sample" } else { family };
    Finding::new("hash.malwarebazaar", format!("Known malware on MalwareBazaar: {family}"), 100)
}

/// Independent capabilities corroborate one another. A filename, packer,
/// encoding scheme or family name never earns a behavioral correlation bonus.
fn correlate(findings: &mut Vec<Finding>) {
    let has = |id: &str| findings.iter().any(|f| f.id == id);
    // keylogger_hook is left out: overlays, macro tools and browsers install keyboard
    // hooks, so a hook alone is not collected data.
    let theft = [
        "browser_credentials",
        "discord_tokens",
        "crypto_wallets",
        "telegram_session",
        "steam_session",
        "keylogger",
        "credential_dump",
    ]
    .iter()
    .any(|id| has(&format!("rule.stealer.{id}")));
    let exfil = has("rule.stealer.exfil_channel");
    let loader = ["download_cradle", "curl_cradle", "script_cradle", "script_dropper", "memory_payload"].iter().any(|id| has(&format!("rule.loader.{id}")));
    let tamper = [
        "defender_tamper",
        "defender_policy",
        "defender_exclusion_key",
        "defender_service",
        "amsi_tamper",
        "kill_security_tools",
        "ifeo_hijack",
        "log_clearing",
        "firewall_off",
        "script_logging_tamper",
        "etw_patch",
        "ntdll_unhook",
        "byovd",
    ]
    .iter()
    .any(|id| has(&format!("rule.evasion.{id}")));
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
        Signature::Invalid(InvalidReason::Revoked) => {
            Some(Finding::new("sig.revoked", "Signed with a revoked certificate (revoked certificates are often stolen ones)", 30))
        }
        Signature::Invalid(InvalidReason::Other(c)) => {
            Some(Finding::new("sig.invalid", format!("Digital signature does not verify (0x{c:08X})"), 10))
        }
    }
}

/// Download URL from the Mark-of-the-Web, for files that came from the internet.
fn origin(path: &Path) -> Option<String> {
    winapi::zone_identifier(path).filter(|o| o.zone >= 3).map(|o| o.url.unwrap_or_else(|| "the internet".into()))
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
