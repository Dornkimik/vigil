//! File classification and filename-based heuristics.

use super::Finding;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Pe,
    Script,
    Shortcut,
    Zip,
    Installer,
    DiskImage,
    OfficeMacro,
    /// The command line a script host was started with, not a file.
    Command,
    Other,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Pe => "Executable",
            Kind::Script => "Script",
            Kind::Shortcut => "Shortcut",
            Kind::Zip => "Archive",
            Kind::Installer => "Installer",
            Kind::DiskImage => "Disk image",
            Kind::OfficeMacro => "Office document",
            Kind::Command => "Command line",
            Kind::Other => "File",
        }
    }
}

pub const SCRIPT_EXTS: &[&str] = &["ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg", "py", "pyw"];
const PE_EXTS: &[&str] = &["exe", "dll", "scr", "com", "cpl", "ocx", "sys", "asi", "xll", "pif", "drv", "efi", "mui"];
/// Extensions that run when double-clicked (DLLs are excluded: names like Ionic.Zip.dll are normal).
const LAUNCH_EXTS: &[&str] =
    &["exe", "scr", "com", "pif", "cpl", "bat", "cmd", "ps1", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "msi"];
/// Extensions a user expects to be harmless documents/media.
const DECOY_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "mkv",
    "avi", "mov", "wav", "zip", "rar", "7z",
];
const RISKY_EXTS: &[&str] = &["scr", "pif", "cpl", "hta", "jse", "vbe", "wsf", "wsh", "js", "vbs"];
/// Script types Windows runs on a double-click or at login, scanned the moment one is saved
/// anywhere in the user's folders. `.js` and `.py` are left out: developer tools write
/// thousands of them (node_modules, virtual environments).
pub const USER_SCRIPT_EXTS: &[&str] = &["bat", "cmd", "ps1", "vbs", "vbe", "jse", "wsf", "wsh", "hta", "lnk"];
/// Temporary files browsers write while a download is in progress.
pub const TEMP_EXTS: &[&str] = &["crdownload", "part", "partial", "download", "tmp", "opdownload", "!ut", "aria2"];

pub fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Cheap pre-filter for folders with huge numbers of asset files (Steam games):
/// only files with these extensions are opened at all.
pub fn is_code_ext(ext: &str) -> bool {
    PE_EXTS.contains(&ext) || SCRIPT_EXTS.contains(&ext) || matches!(ext, "lnk" | "zip" | "msi")
}

/// ELF (Linux, Android) and Mach-O (macOS) programs. Fat Mach-O binaries are left out:
/// their magic is shared with Java class files.
pub fn is_foreign_executable(head: &[u8]) -> bool {
    const MACHO: [[u8; 4]; 4] = [[0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF], [0xCE, 0xFA, 0xED, 0xFE], [0xCF, 0xFA, 0xED, 0xFE]];
    head.starts_with(b"\x7fELF") || MACHO.iter().any(|m| head.starts_with(m))
}

pub fn classify(name: &str, head: &[u8]) -> Kind {
    let ext = ext_of(name);
    if head.starts_with(b"MZ") {
        return Kind::Pe;
    }
    if head.starts_with(&[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0]) {
        return Kind::Shortcut;
    }
    match ext.as_str() {
        e if SCRIPT_EXTS.contains(&e) => Kind::Script,
        "zip" if head.starts_with(b"PK") => Kind::Zip,
        "msi" if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) => Kind::Installer,
        "iso" | "img" | "vhd" | "vhdx" => Kind::DiskImage,
        "docm" | "xlsm" | "pptm" | "dotm" | "xlam" | "ppam" => Kind::OfficeMacro,
        _ => Kind::Other,
    }
}

pub fn name_findings(name: &str, kind: Kind) -> Vec<Finding> {
    let mut f = Vec::new();
    let ext = ext_of(name);

    if name.contains('\u{202E}') {
        f.push(Finding::new("name.rtlo", "Filename uses a right-to-left override character to fake its extension", 60));
    }

    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 && kind != Kind::Other {
        let decoy = parts[parts.len() - 2].trim().to_ascii_lowercase();
        if DECOY_EXTS.contains(&decoy.as_str()) && LAUNCH_EXTS.contains(&ext.as_str()) {
            f.push(Finding::new("name.double_ext", format!("Double extension: looks like .{decoy} but is .{ext}"), 45));
        }
    }

    if kind != Kind::Other && name.contains("     .") {
        f.push(Finding::new("name.padding", "Filename is padded with spaces to hide the real extension", 30));
    }

    if kind == Kind::Pe && DECOY_EXTS.contains(&ext.as_str()) {
        f.push(Finding::new("name.masquerade", format!("Program disguised as a .{ext} file"), 50));
    }

    if RISKY_EXTS.contains(&ext.as_str()) {
        f.push(Finding::new("name.risky_ext", format!("Uncommon .{ext} file type that runs code when opened"), 20));
    }

    match kind {
        Kind::Shortcut => f.push(Finding::new("kind.shortcut", "Shortcut file (often used to hide commands)", 10)),
        Kind::DiskImage => f.push(Finding::new("kind.disk_image", "Disk image; files inside can bypass download protections", 10)),
        Kind::OfficeMacro => {
            f.push(Finding::new("kind.office_macro", "Macro-enabled Office document; don't enable macros unless you trust it", 20))
        }
        _ => {}
    }
    f
}

/// Core Windows programs. Malware takes these names so it blends into the process list.
const SYSTEM_PROGRAMS: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe", "spoolsv.exe",
    "dllhost.exe", "conhost.exe", "taskhostw.exe", "runtimebroker.exe", "sihost.exe", "fontdrvhost.exe", "dwm.exe",
    "ctfmon.exe", "searchindexer.exe", "wuauclt.exe", "explorer.exe", "rundll32.exe", "regsvr32.exe",
];

/// Folders under %SystemRoot% that standard users can create files in. Malware runs from
/// these to get past tools that trust everything in the Windows folder.
const USER_WRITABLE: &[&str] = &[
    r"\tasks\",
    r"\temp\",
    r"\tracing\",
    r"\debug\wia\",
    r"\pla\",
    r"\registration\crmlog\",
    r"\system32\fxstmp\",
    r"\system32\com\dmp\",
    r"\system32\microsoft\crypto\rsa\machinekeys\",
    r"\system32\spool\drivers\color\",
    r"\system32\spool\printers\",
    r"\system32\spool\servers\",
    r"\system32\tasks\",
    r"\system32\tasks_migrated\",
    r"\syswow64\fxstmp\",
    r"\syswow64\com\dmp\",
    r"\syswow64\tasks\",
];

/// True for files under %SystemRoot% that only Windows itself can write, i.e. not
/// in one of the user-writable folders above.
pub fn in_protected_windows_folder(path: &Path, system_root: &str) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    let root = system_root.trim_end_matches('\\').to_ascii_lowercase();
    path.strip_prefix(&root)
        .is_some_and(|rest| rest.starts_with('\\') && !USER_WRITABLE.iter().any(|dir| rest.starts_with(dir)))
}

/// A program named like a core Windows process, stored somewhere Windows doesn't keep them.
pub fn impostor_finding(path: &Path, system_root: &str) -> Option<Finding> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    (SYSTEM_PROGRAMS.contains(&name.as_str()) && !in_protected_windows_folder(path, system_root))
        .then(|| Finding::new("name.system_impostor", format!("Uses the name of a Windows system program ({name}) outside the Windows folder"), 30))
}

/// Script-only obfuscation heuristics.
pub fn script_findings(name: &str, data: &[u8]) -> Vec<Finding> {
    let mut f = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(16 << 20)]).to_ascii_lowercase();

    // Longest base64-looking run, ignoring data: URIs (fonts/images embedded in web bundles).
    let bytes = text.as_bytes();
    let (mut run, mut start, mut longest) = (0usize, 0usize, 0usize);
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            if run == 0 {
                start = i;
            }
            run += 1;
            if !bytes[..start].ends_with(b"base64,") {
                longest = longest.max(run);
            }
        } else {
            run = 0;
        }
    }
    if longest >= 1500 {
        f.push(Finding::new(
            "script.encoded_blob",
            format!("Contains a large encoded blob ({longest} chars); encoding alone is not malicious"),
            0,
        ));
    }

    let char_calls: usize = ["chr(", "chrw(", "fromcharcode", "[char]", "charcodeat"].iter().map(|p| text.matches(p).count()).sum();
    // Density matters: big minified libraries use these legitimately, droppers use little else.
    if char_calls > 25 && char_calls * 1024 / text.len().max(1) >= 2 {
        f.push(Finding::new("script.char_obfuscation", "Builds strings character by character (obfuscation alone is not malicious)", 0));
    }

    let ext = ext_of(name);
    if matches!(ext.as_str(), "bat" | "cmd") && text.matches('^').count() > 60 {
        f.push(Finding::new("script.caret_obfuscation", "Batch file uses caret obfuscation", 0));
    }
    f
}
