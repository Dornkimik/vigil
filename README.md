# Vigil

A lightweight background malware scanner for Windows 11, written in Rust. It is a
**supplement to Microsoft Defender**, not a replacement, and it covers two common ways
malware gets onto a gaming PC:

- **Browser downloads**: new files in your Downloads folder are checked as soon as the
  browser finishes writing them.
- **Steam games and the Workshop**: game installs, updates and Workshop items are checked
  as Steam writes them (for example, indie games that ship an info-stealer).

## How it works

Vigil runs as two parts of one small executable:

| Part | What it does | Footprint |
|---|---|---|
| Background service (`--background`) | Tray icon, folder watchers, scanning on a low-priority (background I/O) thread | A few MB of RAM, idle when nothing changes |
| Dashboard (`--gui`) | Status, manual scans, activity log, quarantine and settings | Runs only while the window is open |

When you close the dashboard, protection keeps running in the notification area.

### Detection layers

Each file gets a score. **35 or more is suspicious, 70 or more is malicious.** The dashboard
shows every finding that added to the score.

1. **Behavioral string rules** (`rules/default.rules`) look for combinations of indicators,
   matched case-insensitively in ASCII and UTF-16 (so .NET stealers are covered):
   - Info-stealer behavior: browser credential and cookie stores, Discord tokens, crypto
     wallets, Telegram and Steam sessions, Discord webhook and Telegram bot exfiltration.
   - Loaders: PowerShell and LOLBin download cradles, Windows Script Host droppers,
     paste-site payloads, AutoIt.
   - Evasion: tampering with Defender or adding exclusions, UAC bypasses, sandbox and VM
     checks, killing security tools.
   - Impact: deleting shadow copies (ransomware), crypto miners, known RAT families.
2. **Executable structure**: process injection and hollowing imports, packers, high-entropy
   code, writable+executable sections, and files padded to hundreds of MB to dodge AV size
   limits.
3. **Disguise tricks**: `invoice.pdf.exe`, right-to-left-override filenames, programs
   renamed to `.jpg`, extensions hidden behind padding spaces, shortcut (`.lnk`) droppers,
   ISO/IMG containers, macro-enabled Office files.
4. **Archives**: password-protected ZIPs that hide programs (a classic way past scanners).
   Programs and scripts inside ZIPs are unpacked in memory and scanned.
5. **Authenticode**: a valid signature removes 60% of the heuristic score. Broken or
   untrusted signatures add to it.
6. **Hash reputation (optional)**: add a free [abuse.ch MalwareBazaar](https://auth.abuse.ch/)
   key in Settings. Only SHA-256 hashes of unsigned files are sent. You can also put your own
   SHA-256 blocklist in `%LOCALAPPDATA%\Vigil\blocklist.txt`.
7. **Defender cross-check**: the *Ask Defender* button sends a single file to
   `MpCmdRun.exe` for a second opinion. Defender does not remediate during this check.

Malicious files are quarantined automatically (configurable). Suspicious files only trigger a
notification. Quarantined files are XOR-encoded in `%LOCALAPPDATA%\Vigil\quarantine` so they
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

## Limitations

- Heuristics catch common, lazily built malware. Heavily obfuscated or encrypted payloads
  can get through. Keep Defender's real-time protection and cloud protection on.
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
src/engine/           scanner: rules, PE analysis, ZIP inspection, file-type heuristics
src/daemon/           background service: watchers, debounced worker, Win32 tray
src/gui/              egui dashboard and theme
src/store.rs          activity log, status heartbeat, quarantine vault
src/winapi.rs         Authenticode, Mark-of-the-Web, registry, Defender (MpCmdRun)
src/steam.rs          Steam library discovery (libraryfolders.vdf)
```
