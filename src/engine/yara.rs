//! YARA rules: the YARA Forge "core" package (curated, low false-positive rules from
//! many public repositories), refreshed weekly, plus the user's own rule files in
//! `%LOCALAPPDATA%\Vigil\yara`. Matching runs offline with YARA-X.
//!
//! The package is downloaded and compiled in memory. Only the compiled rules are kept,
//! XOR-encoded, so the malware strings in them never sit on disk in plain form (antivirus
//! products otherwise flag the rule file itself).

use super::Finding;
use crate::config::{self, write_atomic};
use crate::winapi::NamedMutex;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use yara_x::{Compiler, MetaValue, Rules, Scanner};

const FORGE_URL: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
const UPDATE_EVERY: i64 = 7 * 24 * 3600;
/// Minimum gap between attempts, so an outage doesn't mean a download every minute.
const RETRY_AFTER: i64 = 3600;
const MAX_DOWNLOAD: u64 = 64 << 20;
const MAGIC: &[u8; 8] = b"VIGILYR1";
/// Shared by the service and the dashboard so only one process updates at a time.
const UPDATE_MUTEX: &str = r"Local\Vigil.YaraUpdate";
/// Per file and rule set; a pathological file must not stall the scan queue.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// Score for rules without a `score` meta value (typically the user's own).
const DEFAULT_SCORE: i64 = 75;
/// Every match after the strongest one adds this much, so several weak hits don't add
/// up to "malicious" on their own.
const EXTRA_MATCH: i32 = 5;
/// Machine-generated code-signature rules (Malpedia's yara-signator). They see through
/// string encryption, but also match library code that malware and ordinary programs
/// share (seen on game DLLs), so on their own they never reach "suspicious".
const GENERATED_MAX: i32 = 25;

/// Sync state, kept in `yara.json` next to the compiled rules.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    /// Compiled rules file inside the data folder.
    pub file: String,
    pub rules: usize,
    pub synced: i64,
    /// Last update attempt, successful or not.
    pub checked: i64,
    pub error: Option<String>,
}

impl Meta {
    pub fn load() -> Self {
        std::fs::read(config::yara_meta_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self) {
        if let Ok(b) = serde_json::to_vec_pretty(self) {
            let _ = write_atomic(&config::yara_meta_path(), &b);
        }
    }

    /// `unusable`: the compiled rules exist but can't be loaded (e.g. built by an older YARA-X).
    pub fn due(&self, now: i64, unusable: bool) -> bool {
        (unusable || now - self.synced >= UPDATE_EVERY) && now - self.checked >= RETRY_AFTER
    }
}

#[derive(Default)]
pub struct Yara {
    forge: Option<Arc<Rules>>,
    custom: Option<Rules>,
    custom_count: usize,
    forge_unusable: bool,
    custom_errors: Vec<String>,
}

impl Yara {
    pub fn load() -> Self {
        let mut y = Self::default();
        let meta = Meta::load();
        if !meta.file.is_empty() {
            y.forge = load_compiled(&meta.file);
            y.forge_unusable = y.forge.is_none();
        }
        let (custom, errors) = compile_custom();
        y.custom_count = custom.as_ref().map_or(0, |r| r.iter().len());
        y.custom = custom.filter(|_| y.custom_count > 0);
        y.custom_errors = errors;
        y
    }

    /// Rules compiled from a package, as if they had been downloaded.
    #[cfg(test)]
    pub(crate) fn from_package(rules: Rules) -> Self {
        Self { forge: Some(Arc::new(rules)), ..Self::default() }
    }

    pub fn custom_len(&self) -> usize {
        self.custom_count
    }

    pub fn forge_unusable(&self) -> bool {
        self.forge_unusable
    }

    pub fn custom_errors(&self) -> &[String] {
        &self.custom_errors
    }

    /// One finding per matching rule. The strongest keeps its weight, every further
    /// match adds [`EXTRA_MATCH`] at most.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rules in [self.forge.as_deref(), self.custom.as_ref()].into_iter().flatten() {
            let mut scanner = Scanner::new(rules);
            scanner.set_timeout(SCAN_TIMEOUT);
            let Ok(results) = scanner.scan(data) else { continue };
            for rule in results.matching_rules() {
                let (mut score, mut desc, mut author) = (DEFAULT_SCORE, None, None);
                for (key, value) in rule.metadata() {
                    match (key, value) {
                        ("score", MetaValue::Integer(s)) => score = s,
                        ("description", MetaValue::String(s)) => desc = Some(s),
                        ("author", MetaValue::String(s)) => author = Some(s),
                        _ => {}
                    }
                }
                let name = rule.identifier();
                let generated = name.ends_with("_Auto") || desc.is_some_and(|d| d.contains("yara-signator"));
                let mut weight = weight(name, score);
                let title = if generated {
                    weight = weight.min(GENERATED_MAX);
                    format!("Contains code also found in a malware family [YARA {name}]")
                } else {
                    let by = author.map(|a| format!(", by {a}")).unwrap_or_default();
                    format!("{} [YARA {name}{by}]", desc.unwrap_or("Matches a YARA rule"))
                };
                findings.push(Finding::new(format!("yara.{name}"), title, weight));
            }
        }
        findings.sort_by_key(|f| -f.weight);
        for f in findings.iter_mut().skip(1) {
            f.weight = f.weight.min(EXTRA_MATCH);
        }
        findings
    }
}

/// Weight of a match. Malware-family rules count fully (a typical score of 75 means
/// "malicious"); dual-use tools (pentest kits, remote-admin software, vulnerable drivers)
/// and generic hunting heuristics only count as hints. Rule names follow the
/// `REPO_CATEGORY_Name` convention YARA Forge and most public rule sets use.
pub(crate) fn weight(name: &str, score: i64) -> i32 {
    let tokens: Vec<String> = name.split('_').map(|t| t.to_ascii_uppercase()).collect();
    let has = |set: &[&str]| tokens.iter().any(|t| set.contains(&t.as_str()));
    let score = score.clamp(0, 100) as i32;
    if has(&["HKTL", "HACKTOOL", "TOOL", "TOOLS", "PUA", "RMM", "VULN"]) {
        score.min(30)
    } else if has(&["SUSP", "SUSPICIOUS", "INDICATOR", "GENERIC", "GEN", "OBF", "EXPL", "EXPLOIT", "ANOMALY", "HUNT", "HUNTING"]) {
        score / 2
    } else {
        score
    }
}

/// Compiled rules are shared by every engine in the process: the service rebuilds its
/// engine on each config change, and loading thousands of rules isn't free.
fn load_compiled(file: &str) -> Option<Arc<Rules>> {
    static CACHE: Mutex<Option<(String, Arc<Rules>)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap();
    if let Some((cached, rules)) = cache.as_ref()
        && cached == file
    {
        return Some(rules.clone());
    }
    let data = std::fs::read(config::data_dir().join(file)).ok()?;
    let rules = Arc::new(Rules::deserialize(xor(data.strip_prefix(MAGIC)?)).ok()?);
    *cache = Some((file.to_string(), rules.clone()));
    Some(rules)
}

fn xor(data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ (0x3Cu8.wrapping_add((i as u8).wrapping_mul(29)))).collect()
}

fn compiler<'a>() -> Compiler<'a> {
    let mut c = Compiler::new();
    // Public rules are written for libyara, which accepts some regex syntax YARA-X rejects.
    c.relaxed_re_syntax(true);
    c
}

/// `.yar`/`.yara` files in the user's rule folder. Errors name the file and the first problem.
fn compile_custom() -> (Option<Rules>, Vec<String>) {
    let mut files: Vec<PathBuf> = std::fs::read_dir(config::yara_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| matches!(super::filetype::ext_of(&p.to_string_lossy()).as_str(), "yar" | "yara"))
        .collect();
    if files.is_empty() {
        return (None, Vec::new());
    }
    files.sort();
    let mut c = compiler();
    let mut errors = Vec::new();
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("{name}: {e}"));
                continue;
            }
        };
        // A namespace per file, so two files may use the same rule name.
        c.new_namespace(&name);
        if let Err(e) = c.add_source(src.as_str()) {
            errors.push(format!("{name}: {}", e.to_string().lines().next().unwrap_or("compile error")));
        }
    }
    (Some(c.build()), errors)
}

/// Newest modification time in the user's rule folder, so the service notices edits.
pub fn custom_stamp() -> Option<SystemTime> {
    std::fs::read_dir(config::yara_dir()).ok()?.flatten().filter_map(|e| e.metadata().ok()?.modified().ok()).max()
}

/// Downloads and compiles the YARA Forge package when it is due (or `force`).
/// Returns the number of compiled rules.
pub fn update(force: bool, unusable: bool) -> Result<usize, String> {
    let Some(_lock) = NamedMutex::acquire(UPDATE_MUTEX) else {
        return Err("An update is already running".into());
    };
    let mut meta = Meta::load();
    let now = crate::store::now();
    if !force && !meta.due(now, unusable) {
        return Ok(meta.rules);
    }
    meta.checked = now;
    let result = download().and_then(|zip| compile_package(&zip)).and_then(|(rules, count, skipped)| Ok((store(&rules)?, count, skipped)));
    match &result {
        Ok((file, count, skipped)) => {
            meta.file = file.clone();
            meta.rules = *count;
            meta.synced = now;
            meta.error = (*skipped > 0).then(|| format!("{skipped} rule(s) in the package could not be compiled and were skipped"));
        }
        Err(e) => meta.error = Some(e.clone()),
    }
    meta.save();
    if result.is_ok() {
        remove_stale(&config::data_dir(), &meta.file);
    }
    result.map(|(_, n, _)| n)
}

fn download() -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(Duration::from_secs(120)))
        .build()
        .into();
    let mut resp = agent.get(FORGE_URL).call().map_err(|e| match e {
        ureq::Error::StatusCode(code) => format!("GitHub returned HTTP {code}"),
        e => format!("Download failed: {e}"),
    })?;
    resp.body_mut().with_config().limit(MAX_DOWNLOAD).read_to_vec().map_err(|e| format!("Download failed: {e}"))
}

/// Compiles every rule file in the package ZIP.
/// Returns the rules, their count and how many rules failed to compile.
pub(crate) fn compile_package(zip: &[u8]) -> Result<(Rules, usize, usize), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(zip)).map_err(|e| format!("Not a valid rule package: {e}"))?;
    let mut c = compiler();
    let mut sources = 0;
    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else { continue };
        let name = entry.name().map(|n| n.into_owned()).unwrap_or_default();
        if entry.is_dir() || !(name.ends_with(".yar") || name.ends_with(".yara")) {
            continue;
        }
        let mut src = String::new();
        if entry.read_to_string(&mut src).is_err() {
            continue;
        }
        // Rules that fail to compile are left out; the rest of the file still counts.
        let _ = c.add_source(src.as_str());
        sources += 1;
    }
    if sources == 0 {
        return Err("The rule package contained no rule files".into());
    }
    let skipped = c.errors().len();
    let rules = c.build();
    let count = rules.iter().len();
    if count == 0 {
        return Err("No rule in the package could be compiled".into());
    }
    Ok((rules, count, skipped))
}

/// Writes the encoded rules to a new file in the data folder and returns its name.
fn store(rules: &Rules) -> Result<String, String> {
    let mut out = MAGIC.to_vec();
    out.extend(xor(&rules.serialize().map_err(|e| format!("Could not store the rules: {e}"))?));
    let file = format!("yara-{}.bin", chrono::Utc::now().timestamp_millis());
    write_atomic(&config::data_dir().join(&file), &out).map_err(|e| format!("Could not write the rules: {e}"))?;
    Ok(file)
}

/// Deletes older compiled rule files.
fn remove_stale(dir: &Path, current: &str) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("yara-") && name.ends_with(".bin") && name != current {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Inert fixture rules: they match marker strings, not malware.
    pub(crate) const RULES: &str = r#"
rule TEST_Win_Marker_Family : FILE {
    meta:
        description = "Test marker family"
        author = "Vigil tests"
        score = 80
    strings:
        $a = "VIGIL-YARA-FAMILY-MARKER"
    condition:
        $a
}
rule TEST_SUSP_Marker_Generic {
    meta:
        score = 70
    strings:
        $a = "VIGIL-YARA-GENERIC-MARKER"
    condition:
        $a
}
rule TEST_Elf_Marker {
    strings:
        $a = "VIGIL-YARA-ELF-MARKER"
    condition:
        uint32(0) == 0x464c457f and $a
}
rule TEST_Win_Marker_Auto {
    meta:
        description = "autogenerated rule brought to you by yara-signator"
        score = 75
    strings:
        $a = "VIGIL-YARA-AUTO-MARKER"
    condition:
        $a
}
"#;

    pub(crate) fn package(files: &[(&str, &str)]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, src) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(src.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn rule_names_decide_how_much_a_match_counts() {
        assert_eq!(weight("ELASTIC_Windows_Trojan_Redline_1", 75), 75);
        assert_eq!(weight("SIGNATURE_BASE_HKTL_Mimikatz_Strings", 75), 30);
        assert_eq!(weight("DITEKSHEN_INDICATOR_TOOL_LTM_Ladongo", 75), 30);
        assert_eq!(weight("DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Discord", 75), 37);
        assert_eq!(weight("COD3NYM_SUSP_OBF_NET_Confuserex_Packer_Jan24", 70), 35);
        assert_eq!(weight("MY_OWN_RULE", 250), 100);
    }

    #[test]
    fn packages_compile_and_broken_rules_are_skipped() {
        let zip = package(&[("packages/core/rules.yar", RULES), ("broken.yar", "rule Broken { condition: nope }"), ("readme.txt", "x")]);
        let (rules, count, skipped) = compile_package(&zip).unwrap();
        assert_eq!((count, skipped), (4, 1));
        // The stored form decodes back into working rules.
        let stored = xor(&rules.serialize().unwrap());
        let rules = Rules::deserialize(xor(&stored)).unwrap();
        let yara = Yara::from_package(rules);

        let findings = yara.scan(b"MZ .. VIGIL-YARA-GENERIC-MARKER .. VIGIL-YARA-FAMILY-MARKER ..");
        let ids: Vec<(&str, i32)> = findings.iter().map(|f| (f.id.as_str(), f.weight)).collect();
        assert_eq!(ids, [("yara.TEST_Win_Marker_Family", 80), ("yara.TEST_SUSP_Marker_Generic", EXTRA_MATCH)]);
        assert!(findings[0].title.contains("Test marker family") && findings[0].title.contains("by Vigil tests"));
        assert!(yara.scan(b"nothing to see").is_empty());
        // Machine-generated code signatures stay below "suspicious" on their own.
        let generated = yara.scan(b"MZ .. VIGIL-YARA-AUTO-MARKER ..");
        assert_eq!(generated[0].weight, GENERATED_MAX);
        assert!(generated[0].title.starts_with("Contains code also found in a malware family"));

        assert!(compile_package(&package(&[("readme.txt", "x")])).is_err());
        assert!(compile_package(b"not a zip").is_err());
    }
}
