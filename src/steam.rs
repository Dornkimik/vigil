//! Discovers Steam library folders so game installs and Workshop downloads can be watched.

use crate::engine::Source;
use crate::winapi;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct SteamDirs {
    /// `<library>\steamapps\common` folders (installed games).
    pub games: Vec<PathBuf>,
    /// `<library>\steamapps\workshop\content` folders (Workshop items).
    pub workshop: Vec<PathBuf>,
}

pub fn discover() -> SteamDirs {
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

    let existing = |p: PathBuf| p.is_dir().then_some(p);
    SteamDirs {
        games: libraries.iter().filter_map(|l| existing(l.join(r"steamapps\common"))).collect(),
        workshop: libraries.iter().filter_map(|l| existing(l.join(r"steamapps\workshop\content"))).collect(),
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

/// Steam content gets Steam-specific heuristics even when scanned manually.
pub fn source_for(path: &Path, default: Source) -> Source {
    let p = path.to_string_lossy().to_ascii_lowercase();
    if p.contains(r"\steamapps\downloading\") || p.contains(r"\steamapps\temp\") {
        Source::SteamDownload
    } else if p.contains(r"\steamapps\workshop\") {
        Source::Workshop
    } else if p.contains(r"\steamapps\common\") {
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
        let src = |p: &str| super::source_for(std::path::Path::new(p), Source::Manual);
        let lib = r"C:\Program Files (x86)\Steam\steamapps";
        assert_eq!(src(&format!(r"{lib}\downloading\381210\Engine\Extras\Redist\en-us\vc_redist.x64.exe")), Source::SteamDownload);
        assert_eq!(src(&format!(r"{lib}\temp\381210\game.exe")), Source::SteamDownload);
        assert_eq!(src(&format!(r"{lib}\common\Game\game.exe")), Source::Steam);
        assert_eq!(src(&format!(r"{lib}\workshop\content\1\2\mod.dll")), Source::Workshop);
        assert_eq!(src(r"C:\Users\me\Downloads\downloading\setup.exe"), Source::Manual);
    }
}
