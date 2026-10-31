# Vigil

A lightweight background malware scanner for Windows 11, written in Rust. It is a
**supplement to Microsoft Defender**, not a replacement, and it covers two common ways
malware gets onto a gaming PC, plus a safety net for programs that arrive any other way:

- **Browser downloads**: new files in your Downloads folder are checked as soon as the
  browser finishes writing them.
- **Steam games and the Workshop**: game installs, updates and Workshop items are checked
  as Steam writes them (for example, indie games that ship an info-stealer).
- **Programs you run**: every program that starts is checked once, wherever it is stored
  (a USB stick, an archive extracted to `%TEMP%`, a file another program dropped). Programs
  in the Windows folder are skipped.

## How it works

Vigil runs as two parts of one small executable:

| Part | What it does | Footprint |
|---|---|---|
| Background service (`--background`) | Tray icon, folder watchers, program-start watcher, scanning on a low-priority (background I/O) thread | A few MB of RAM, idle when nothing changes |
| Dashboard (`--gui`) | Status, manual scans, activity log, quarantine and settings | Runs only while the window is open |

When you close the dashboard, protection keeps running in the notification area.

### Detection layers

Each file gets a score. **35 or more is suspicious, 70 or more is malicious.** The dashboard
shows every finding that added to the score.

1. **Behavioral string rules** (`rules/default.rules`) look for combinations of indicators,
   matched case-insensitively in ASCII and UTF-16LE/BE (including .NET string literals):
   - Info-stealer behavior: browser credential and cookie stores, Discord tokens, crypto
     wallets, Telegram and Steam sessions, Discord webhook and Telegram bot exfiltration.
   - Loaders: PowerShell and LOLBin download cradles, Windows Script Host droppers,
     paste-site payloads, AutoIt.
   - Evasion: tampering with Defender or adding exclusions, UAC bypasses, sandbox and VM
     checks, killing security tools (including .NET `GetProcessesByName` killers), and
     Image File Execution Options hijacks that stop security tools from starting.
   - Impact: backup deletion paired with ransom demands, reverse-shell capability
     combinations, miners paired with security tampering, and hidden-desktop (HVNC)
     remote control.
   - Persistence: Run keys, scheduled tasks, hidden copies, and push-button reset hooks
     (`C:\Recovery\OEM\ResetConfig.xml`) that survive "Reset this PC".
   - Credential dumping, keylogging with window context, and in-memory .NET loaders.
   Required evidence groups distinguish capabilities: downloading alone is different
   from downloading **and** executing. Independent combinations (credential collection
   plus an exfiltration endpoint, security tampering or hidden-desktop control, or payload
   execution plus security tampering) add corroboration points. Family names, AutoIt/PyInstaller packaging, and encoding alone
   do not trigger alerts; ordinary mining configuration stays below the alert threshold.
   These are static indicators of possible behavior, not proof that a command ran.
2. **Static script recovery**: scripts (including `.py`/`.pyw`) and shortcut command text
   are checked for nested Base64/UTF-16 payloads, Base64-wrapped gzip/zlib/Deflate streams,
   adjacent quoted string concatenation, JavaScript/Python hex and Unicode escapes,
   and selected PowerShell backtick/batch caret escapes. Nothing is executed. Recovered
   evidence is labeled in findings and each rule scores only once across representations.
   Recovery examines the first 2 MiB, at most three transformation levels and 16 views,
   with separate 4 MiB budgets for recovered views and decoding/decompression work.
3. **Executable structure**: process injection and hollowing imports, packers, high-entropy
   code, writable+executable sections, and files padded to hundreds of MB to dodge AV size
   limits.
4. **Disguise tricks**: `invoice.pdf.exe`, right-to-left-override filenames, programs
   renamed to `.jpg`, extensions hidden behind padding spaces, shortcut (`.lnk`) droppers,
   ISO/IMG containers, macro-enabled Office files.
5. **Archives**: password-protected ZIPs that hide programs (a classic way past scanners).
   Programs and scripts inside ZIPs are unpacked in memory and scanned.
6. **Authenticode**: a valid signature removes 60% of the heuristic score. Broken or
   untrusted signatures add to it.
7. **Known-malware hashes (optional)**: add a free [abuse.ch MalwareBazaar](https://auth.abuse.ch/)
   key in Settings. Vigil downloads MalwareBazaar's full hash export once (refreshed monthly)
   and merges in the 48-hour export twice a day. Every file, signed or not, and every program
   inside a ZIP, is checked offline against this database. No hashes are sent anywhere. The
   database is a sorted, memory-mapped file (`hashdb-*.bin`, about 35 bytes per hash), so it
   costs almost no RAM. Until the first download finishes, unsigned files are looked up online
   instead. `vigil.exe --update-hashes` forces an update. You can also put your own SHA-256
   blocklist in `%LOCALAPPDATA%\Vigil\blocklist.txt`.
8. **Defender cross-check**: the *Ask Defender* button sends a single file to
   `MpCmdRun.exe` for a second opinion. Defender does not remediate during this check.

Malicious files are quarantined automatically (configurable). If the file is a program that is
running, Vigil stops every process running it first, since Windows locks a running program's file.
Suspicious files only trigger a notification. Quarantined files are XOR-encoded in `%LOCALAPPDATA%\Vigil\quarantine` so they
can't run by accident. Restoring a file also marks it as safe.

The rules are obfuscated at build time (`build.rs`), so `vigil.exe` does not contain the
plaintext malware indicators. Otherwise Defender or Vigil itself could flag it.

## Build

Requirements: Rust (stable, MSVC toolchain) on Windows 10/11.

```bash
cargo build --release
```

The binary is `target\release\vigil.exe` (about 8 MB, no installer or runtime needed).

## Usage

```bash
target/release/vigil.exe
```

This starts the background service and opens the dashboard. In the dashboard, go to
**Settings → Start with Windows** to have the service start at sign-in (it writes to
`HKCU\...\Run`, so no admin rights are needed).

| Command | Purpose |
|---|---|
| `vigil.exe` | Start the service if needed and open the dashboard |
| `vigil.exe --background` | Service and tray icon only (used for autostart) |
| `vigil.exe --gui` | Dashboard only |
| `vigil.exe --scan <paths…> [--fast] [--json] [--out file]` | Command-line scan. Exit code 0 = clean, 1 = suspicious, 2 = malicious |
| `vigil.exe --update-hashes` | Download the MalwareBazaar hash database now (needs the Auth-Key) |

Tray icon: left-click opens the dashboard. Right-click shows *Scan Downloads now*,
*Pause protection* and *Exit*.

## Custom rules

**Settings → Custom rules** opens `%LOCALAPPDATA%\Vigil\custom.rules`, which uses the same
format as `rules/default.rules`:

```
rule my.rule
  desc   What this detects
  weight 40          # points added when it fires
  min    2           # how many of the patterns must appear
  scope  any         # any | pe | script | shortcut
  str    first pattern
  str    second pattern
end
```

The service reloads rules, the blocklist and settings within a few seconds of a change.

For rules that need independent capabilities, add one `require` line per group.
At least one alternative on **every** line must match, as well as the `min` threshold:

```
rule example.download_execute
  desc   Downloads and evaluates a script
  weight 35
  scope  script
  require DownloadString( | Invoke-WebRequest
  require Invoke-Expression | IEX(
end
```

Alternatives are separated by ` | ` (with spaces). Required patterns count toward
`min`, which defaults to 1. Repeated patterns and repeated encodings do not increase
the match count. Existing rules using only `str` and `min` remain supported.

## Detection regression tests

Run `cargo test --locked`. The fixtures are inert strings and in-memory archives;
tests never execute payloads or contact malware hosts. They cover common capability
combinations, encoded/compressed variants, decoder limits, and benign administration,
browser, Steam, mining and web-asset examples. They do not establish a real-world
detection rate or false-positive rate; that requires a representative labeled corpus.

References: [Microsoft's EncodedCommand format](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
and [MITRE ATT&CK obfuscation techniques](https://attack.mitre.org/techniques/T1027/).

## Limitations

- The program-start check is a static scan of the program file when it starts, not runtime
  behavior monitoring. Vigil checks the process list once a second without admin rights, so the
  program is already running when it is scanned, and one that starts and exits within a second
  can be missed. Programs running as administrator cannot be stopped; Vigil notifies you instead.

- Static heuristics cannot determine intent or observe runtime behavior. Custom encryption,
  runtime-built strings, arbitrary character-code expressions, native packers, and payloads
  beyond the recovery limits can get through. Script recovery is not a complete language
  parser or sandbox. Keep Defender's real-time protection and cloud protection on.
- Only ZIP archives are unpacked. 7z and RAR archives are not, but their contents are
  scanned once extracted into a watched folder.
- Quarantining a file from a Steam game breaks that game until you restore it, or until
  Steam's "Verify integrity of game files" downloads it again. If the file really is
  malicious, uninstall the game.
- Some Workshop items legitimately ship DLLs (code mods). Vigil notes this, but it does not
  count as a threat by itself.

## Project layout

```
rules/default.rules   detection rules (obfuscated into the binary at build time)
build.rs              rule obfuscation + generated .ico embedding
src/engine/           scanner: rules, PE analysis, ZIP inspection, file-type heuristics,
                      offline MalwareBazaar hash database (hashdb.rs)
src/daemon/           background service: watchers, program-start watcher, debounced worker, Win32 tray
src/gui/              egui dashboard and theme
src/store.rs          activity log, status heartbeat, quarantine vault
src/winapi.rs         Authenticode, Mark-of-the-Web, registry, Defender (MpCmdRun)
src/steam.rs          Steam library discovery (libraryfolders.vdf)
```
