//! Discovers Steam library folders so game installs and Workshop downloads can be watched.

use crate::engine::Source;
use crate::winapi;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct SteamDirs {
    /// `<library>\steamapps\common` folders (installed games).
    pub games: Vec<PathBuf>,
    /// `<library>\steamapps\workshop\content` folders (Workshop items).
    pub workshop: Vec<PathBuf>,
}

pub fn discover() -> SteamDirs {
    let libraries = library_roots();
    let existing = |p: PathBuf| p.is_dir().then_some(p);
    SteamDirs {
        games: libraries.iter().filter_map(|l| existing(l.join(r"steamapps\common"))).collect(),
        workshop: libraries.iter().filter_map(|l| existing(l.join(r"steamapps\workshop\content"))).collect(),
    }
}

/// Every Steam library folder (the Steam install and the extra libraries it lists).
fn library_roots() -> Vec<PathBuf> {
    let mut libraries: Vec<PathBuf> = Vec::new();
    if let Some(steam) = winapi::steam_install_path() {
        // libraryfolders.vdf has properly cased paths; the registry value is often lowercase.
        let vdf = steam.join("steamapps").join("libraryfolders.vdf");
        if let Ok(text) = std::fs::read_to_string(vdf) {
            libraries.extend(parse_library_paths(&text));
        }
        libraries.push(steam);
    }
    let mut seen = Vec::<String>::new();
    libraries.retain(|p| {
        let key = p.to_string_lossy().to_lowercase();
        !seen.contains(&key) && {
            seen.push(key);
            true
        }
    });
    libraries
}

/// Lowercased library folders, re-read every few minutes so new libraries are picked up.
fn library_keys() -> Vec<String> {
    static CACHE: Mutex<Option<(Instant, Vec<String>)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap();
    match cache.as_ref() {
        Some((at, keys)) if at.elapsed() < Duration::from_secs(300) => keys.clone(),
        _ => {
            let keys: Vec<String> = library_roots().iter().map(|p| p.to_string_lossy().to_lowercase().trim_end_matches('\\').to_string()).collect();
            *cache = Some((Instant::now(), keys.clone()));
            keys
        }
    }
}

/// Extracts `"path"  "D:\\SteamLibrary"` entries from libraryfolders.vdf.
fn parse_library_paths(vdf: &str) -> Vec<PathBuf> {
    vdf.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("\"path\"")?;
            let value = rest.trim().trim_matches('"');
            Some(PathBuf::from(value.replace("\\\\", "\\")))
        })
        .collect()
}

/// Steam content gets Steam-specific heuristics even when scanned manually. Only folders of a
/// real Steam library count: anyone can name a folder `steamapps\common` to get the leniency.
pub fn source_for(path: &Path, default: Source) -> Source {
    source_in(path, default, &library_keys())
}

fn source_in(path: &Path, default: Source, libraries: &[String]) -> Source {
    let p = path.to_string_lossy().to_lowercase().replace('/', "\\");
    let Some(rest) = libraries.iter().find_map(|lib| p.strip_prefix(lib.as_str()).and_then(|r| r.strip_prefix(r"\steamapps\"))) else {
        return default;
    };
    if rest.starts_with(r"downloading\") || rest.starts_with(r"temp\") {
        Source::SteamDownload
    } else if rest.starts_with(r"workshop\") {
        Source::Workshop
    } else if rest.starts_with(r"common\") {
        Source::Steam
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_vdf() {
        let vdf = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t}\n}";
        let p = super::parse_library_paths(vdf);
        assert_eq!(p, vec![std::path::PathBuf::from(r"C:\Program Files (x86)\Steam"), std::path::PathBuf::from(r"D:\SteamLibrary")]);
    }

    #[test]
    fn steam_staging_folders_are_downloads() {
        use crate::engine::Source;
        let libraries = [r"c:\program files (x86)\steam".to_string(), r"d:\steamlibrary".to_string()];
        let src = |p: &str| super::source_in(std::path::Path::new(p), Source::Manual, &libraries);
        let lib = r"C:\Program Files (x86)\Steam\steamapps";
        assert_eq!(src(&format!(r"{lib}\downloading\381210\Engine\Extras\Redist\en-us\vc_redist.x64.exe")), Source::SteamDownload);
        assert_eq!(src(&format!(r"{lib}\temp\381210\game.exe")), Source::SteamDownload);
        assert_eq!(src(&format!(r"{lib}\common\Game\game.exe")), Source::Steam);
        assert_eq!(src(&format!(r"{lib}\workshop\content\1\2\mod.dll")), Source::Workshop);
        assert_eq!(src(r"D:/SteamLibrary/steamapps/common/Game/game.exe"), Source::Steam);
        assert_eq!(src(r"C:\Users\me\Downloads\downloading\setup.exe"), Source::Manual);
    }

    #[test]
    fn folders_named_like_steam_outside_a_library_are_not_steam() {
        use crate::engine::Source;
        let libraries = [r"c:\program files (x86)\steam".to_string()];
        let src = |p: &str| super::source_in(std::path::Path::new(p), Source::Downloads, &libraries);
        assert_eq!(src(r"C:\Users\me\AppData\Local\Temp\steamapps\common\x\payload.dat"), Source::Downloads);
        assert_eq!(src(r"C:\Users\me\Downloads\steamapps\downloading\1\setup.exe"), Source::Downloads);
        assert_eq!(src(r"C:\Program Files (x86)\Steam2\steamapps\common\x.exe"), Source::Downloads);
        assert_eq!(src(r"C:\Program Files (x86)\Steam\steamapps\common\Game\game.exe"), Source::Steam);
    }
}
