use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
        std::fs::read(config_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
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

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
