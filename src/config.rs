use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// %LOCALAPPDATA%\Vigil
pub fn data_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
    let dir = base.join("Vigil");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}
pub fn events_path() -> PathBuf {
    data_dir().join("events.jsonl")
}
pub fn status_path() -> PathBuf {
    data_dir().join("status.json")
}
pub fn quarantine_dir() -> PathBuf {
    let d = data_dir().join("quarantine");
    let _ = std::fs::create_dir_all(&d);
    d
}
pub fn custom_rules_path() -> PathBuf {
    data_dir().join("custom.rules")
}
pub fn blocklist_path() -> PathBuf {
    data_dir().join("blocklist.txt")
}
pub fn hashdb_meta_path() -> PathBuf {
    data_dir().join("hashdb.json")
}
pub fn yara_meta_path() -> PathBuf {
    data_dir().join("yara.json")
}
/// The user's own YARA rule files.
pub fn yara_dir() -> PathBuf {
    let d = data_dir().join("yara");
    let _ = std::fs::create_dir_all(&d);
    d
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub watch_downloads: bool,
    pub watch_steam: bool,
    pub extra_folders: Vec<PathBuf>,
    /// Scan the program file of every process that starts (outside the Windows folder).
    pub watch_launches: bool,
    /// Move files with a "malicious" verdict to quarantine automatically.
    pub auto_quarantine: bool,
    pub notify_suspicious: bool,
    pub notifications: bool,
    pub paused: bool,
    /// Optional abuse.ch MalwareBazaar Auth-Key, used to download the offline hash database.
    pub malwarebazaar_key: String,
    /// Download the YARA Forge rule package from GitHub once a week.
    pub yara_updates: bool,
    /// SHA-256 hashes the user marked as safe.
    pub allowlist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch_downloads: true,
            watch_steam: true,
            extra_folders: Vec::new(),
            watch_launches: true,
            auto_quarantine: true,
            notify_suspicious: true,
            notifications: true,
            paused: false,
            malwarebazaar_key: String::new(),
            yara_updates: true,
            allowlist: Vec::new(),
        }
    }
}

impl Config {
    pub fn load() -> Self {
        Self::load_from(&config_path())
    }

    /// Defaults when there is no config yet. A config that doesn't parse (e.g. a typo from
    /// editing it by hand) is moved aside to `config.json.broken` first, since the defaults
    /// are saved over it next and would otherwise wipe the allow-list and the API key.
    fn load_from(path: &Path) -> Self {
        let Ok(bytes) = std::fs::read(path) else { return Self::default() };
        match serde_json::from_slice(&bytes) {
            Ok(c) => c,
            Err(_) => {
                let mut broken = path.as_os_str().to_owned();
                broken.push(".broken");
                let _ = std::fs::rename(path, PathBuf::from(broken));
                Self::default()
            }
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        write_atomic(&config_path(), &serde_json::to_vec_pretty(self)?)
    }

    /// Re-reads the config from disk, applies `f` and saves it. The daemon and GUI
    /// both write the config, so always mutate the freshest copy. The updated config
    /// is returned even when saving fails, together with the save result.
    pub fn update(f: impl FnOnce(&mut Config)) -> (Config, std::io::Result<()>) {
        let mut c = Self::load();
        f(&mut c);
        let saved = c.save();
        (c, saved)
    }

    pub fn is_allowed(&self, sha256: &str) -> bool {
        self.allowlist.iter().any(|h| h.eq_ignore_ascii_case(sha256))
    }
}

pub fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Writes a temporary file and renames it over `path`. The temporary name is unique per
/// process and call: the service and the dashboard write the same files, and a shared name
/// would let one rename the other's half-written file into place.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{n}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_config_is_kept_aside_instead_of_overwritten() {
        let dir = std::env::temp_dir().join(format!("vigil-test-{}-config", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let good = Config { allowlist: vec!["ab".repeat(32)], ..Config::default() };
        write_atomic(&path, &serde_json::to_vec(&good).unwrap()).unwrap();
        assert_eq!(Config::load_from(&path).allowlist, good.allowlist);
        // No temporary files are left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::write(&path, br#"{"allowlist": ["abc"], oops}"#).unwrap();
        let loaded = Config::load_from(&path);
        assert!(loaded.allowlist.is_empty());
        assert!(!path.exists());
        assert_eq!(std::fs::read(dir.join("config.json.broken")).unwrap(), br#"{"allowlist": ["abc"], oops}"#);
        let _ = std::fs::remove_dir_all(dir);
    }
}
