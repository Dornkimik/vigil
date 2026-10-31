# Vigil: technical reference

This is the detailed description of how Vigil works, how to build and configure it, and
where its limits are. For an overview, see the [README](../README.md).

## What is scanned

- **Browser downloads**: new files in your Downloads folder are checked as soon as the
  browser finishes writing them.
- **Steam games and the Workshop**: game installs, updates and Workshop items are checked
  as Steam writes them (for example, indie games that ship an info-stealer).
- **Programs you run**: every program that starts is checked once, wherever it is stored
  (a USB stick, an archive extracted to `%TEMP%`, a file another program dropped). Programs
  in the Windows folder are skipped, except in its subfolders that standard users can write
  to (such as `C:\Windows\Temp` and `C:\Windows\Tasks`), where malware hides to look trusted.
  `rundll32.exe` and `regsvr32.exe` are Windows' own but run any DLL they are given, so the
  DLL they are told to run, and every DLL from outside the Windows folder they load, is
  checked too. A malicious one is stopped together with the process hosting it.
  Unsigned programs also get their **memory** checked a few seconds after they start, where
  packed and encrypted malware has to show its real code.

## Architecture

Vigil runs as two parts of one small executable:

| Part | What it does | Footprint |
|---|---|---|
| Background service (`--background`) | Tray icon, folder watchers, program-start watcher, scanning on a low-priority (background I/O) thread | About 15 MB of RAM, about 70 MB once the YARA rules are loaded; idle when nothing changes |
| Dashboard (`--gui`) | Status, manual scans, activity log, quarantine and settings | Runs only while the window is open |

When you close the dashboard, protection keeps running in the notification area.

### Detection layers

Each file gets a score. **35 or more is suspicious, 70 or more is malicious.** The dashboard
shows every finding that added to the score.

1. **Behavioral string rules** (`rules/default.rules`) look for combinations of indicators,
   matched case-insensitively in ASCII and UTF-16LE/BE (including .NET string literals):
   - Info-stealer behavior: browser credential and cookie stores, Discord tokens, crypto
     wallets, Telegram and Steam sessions, Discord webhook and Telegram bot exfiltration.
   - Loaders: PowerShell and LOLBin download cradles, downloads that are saved and started,
     web requests from a hidden PowerShell window, remote or inline `mshta` applications,
     Windows Script Host droppers, paste-site payloads, AutoIt.
   - Evasion: turning off Defender or adding exclusions (through PowerShell, policy registry
     keys, the exclusions key, or by stopping its service or removing its definitions),
     UAC bypasses, sandbox and VM checks, killing security tools (including .NET
     `GetProcessesByName` killers), Image File Execution Options hijacks that stop security
     tools from starting, clearing event logs, switching the firewall off, disabling
     PowerShell script logging, patching ETW in memory, starting the AMSI-less PowerShell 2.0
     engine, replacing ntdll's security hooks with a clean copy, and installing
     known-vulnerable drivers to kill security software (BYOVD).
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
   and selected PowerShell backtick/batch caret escapes. PowerShell switches are written out
   in full however they are abbreviated or dashed (`-w 1`, `/win hidden` and `–WindowStyle Hidden`
   all read as `-WindowStyle Hidden`), and the cradle aliases (`iwr`, `irm`, `iex`, `saps`) in
   PowerShell code are spelled out. Nothing is executed. Recovered
   evidence is labeled in findings and each rule scores only once across representations.
   Recovery examines the first 2 MiB, at most three transformation levels and 16 views,
   with separate 4 MiB budgets for recovered views and decoding/decompression work.
3. **Executable structure**: process injection and hollowing imports, packers, high-entropy
   code, writable+executable sections, direct system calls that skip ntdll (and the
   security hooks in it), and encrypted payloads hidden inside the signature block, where
   they leave the signature valid. Programs padded to hundreds of MB to dodge AV size limits
   are flagged, and when the padding pushes them past the 512 MB content limit, the code
   before the padding is still analyzed.
4. **Memory of started programs**: malware that is packed or encrypted on disk looks harmless
   to every check above, but it has to decrypt itself in memory before it can run. Five seconds
   and again one minute after an unsigned program starts, Vigil reads its private memory that can
   run code (where injected code, shellcode and payloads loaded without a file end up) and, when
   the file looked packed, the program's own unpacked image. The string rules and YARA rules run
   over it, and only evidence the file scan didn't already show adds to the file's score, marked
   *In memory*. A native program loaded straight into memory with no file behind it adds 25
   points, and a program whose own code was replaced after it started (process hollowing) adds 60.
   At most 64 MB is read per process, nothing is written to it, and elevated programs are left
   out because reading them would need admin rights. Programs that unpack in steps and only
   decrypt strings while they use them, or that wait longer than a minute, can still get past it.
5. **Disguise tricks**: `invoice.pdf.exe`, right-to-left-override filenames, programs
   renamed to `.jpg`, extensions hidden behind padding spaces, Windows system program names
   (`svchost.exe`, `lsass.exe`…) outside the Windows folder, shortcut (`.lnk`) droppers,
   ISO/IMG containers, macro-enabled Office files.
6. **Archives**: password-protected ZIPs that hide programs (a classic way past scanners).
   Programs and scripts inside ZIPs are unpacked in memory and scanned, up to 500 of them and
   256 MB of unpacked data per archive, so a small ZIP bomb can't stall scanning. Entries that
   share their data are unpacked once.
7. **Authenticode**: a valid signature removes 60% of the heuristic score, unless an
   encrypted payload is hidden inside the signature block. Broken, untrusted or revoked
   signatures add to it. Revocation is checked against the lists Windows has cached, without
   going online, so a revoked certificate is only caught once Windows knows about it.
8. **Known-malware hashes (optional)**: add a free [abuse.ch MalwareBazaar](https://auth.abuse.ch/)
   key in Settings. Vigil downloads MalwareBazaar's full hash export once (refreshed monthly)
   and merges in the 48-hour export twice a day. Every file, signed or not, and every program
   inside a ZIP, is checked offline against this database. No hashes are sent anywhere. The
   database is a sorted, memory-mapped file (`hashdb-*.bin`, about 35 bytes per hash), so it
   costs almost no RAM. Until the first download finishes, unsigned files are looked up online
   instead. `vigil.exe --update-hashes` forces an update. You can also put your own SHA-256
   blocklist in `%LOCALAPPDATA%\Vigil\blocklist.txt`.
9. **YARA rules**: the [YARA Forge](https://github.com/YARAHQ/yara-forge) *core* package
   (about 5,000 curated rules from public repositories) is downloaded from GitHub once a week
   and matched offline with [YARA-X](https://github.com/VirusTotal/yara-x). Many of these rules
   match a malware family's code rather than its text, so they still recognize samples whose
   strings are encrypted. They run on programs, installers, scripts, shortcuts, ZIP members,
   and Linux/macOS executables, but not on validly signed programs: the signature credit would
   cancel a match there anyway, and signed engines and drivers make up most of a game library,
   so skipping them keeps a full Steam scan about 1.5x as long instead of 3x. A match counts by the rule's `score` and kind: malware-family
   rules fully (usually enough for *malicious*), generic `SUSP`/`INDICATOR` heuristics at half,
   dual-use tools (`HKTL`, RMM, vulnerable drivers) at 30 points, and machine-generated code
   signatures (Malpedia `_Auto` rules) at 25, since those also match library code that games
   share with malware. The package is compiled in memory and only the compiled, XOR-encoded rules
   are stored (`yara-*.bin`, about 9 MB). `vigil.exe --update-yara` forces an update. Updates can
   be turned off in Settings.
10. **Defender cross-check**: the *Ask Defender* button sends a single file to
   `MpCmdRun.exe` for a second opinion. Defender does not remediate during this check.

### Quarantine

Malicious files are quarantined automatically (configurable). If the file is a program that is
running, Vigil stops every process running it first, since Windows locks a running program's file.
When a file can't be moved (it is in use, or its program runs as administrator), Vigil tries again
every 30 seconds for ten minutes, and a malicious program is checked again every time it starts.
Suspicious files only trigger a notification. Quarantined files are XOR-encoded in
`%LOCALAPPDATA%\Vigil\quarantine` so they can't run by accident. Restoring a file also marks it as safe.

### Script hosts and command lines

PowerShell, `cmd`, `mshta`, Windows Script Host and `conhost` run code given on their command
line, which never touches the disk, so the command line of each one that starts is scanned like
a script, and so is the script file it is told to run (`-File x.ps1`, `wscript x.vbs`,
`cmd /c x.bat`). A hidden window or `-ExecutionPolicy Bypass` alone is normal for installers and
background tools and only adds a few points; a hidden window that makes a web request is
suspicious, and one that downloads and runs code is malicious. A malicious command gets that
process and everything it started stopped (nothing is quarantined, since the program is Windows'
own), and *Mark as safe* allows that exact command line. YARA rules don't run on command lines:
their PowerShell rules flag encoded commands as such, and developer tools (VS Code, Claude Code,
management agents) pass every command encoded. The string rules decode the command and judge what
it does instead.

### Stopping script droppers early

Droppers write a script and run it straight away, so scripts that Windows runs on a double-click
or at login (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.lnk`…) are scanned the moment they are saved
anywhere in your user folders (Documents, Desktop, AppData, Temp, Startup). `.js` and `.py` are
left out there, since developer tools write thousands of them. A new script there, or a script
host starting, also makes the program-start check poll every 50 ms instead of once a second for
the next five seconds. PowerShell needs about 110 ms after it starts before it runs the first line
of its command, so a hidden PowerShell started by a freshly written script is stopped before it
runs anything: in testing, 40 to 80 ms after it started, every time.

### Admin mode (optional)

Windows only tells administrators the moment a program starts, so without admin rights Vigil
has to look for new programs (once a second, or every 50 ms around script activity). Admin mode,
in Settings or with `vigil.exe --admin-mode on`, asks for admin approval once and then removes
that wait for every program, including commands started directly by a Run key, a scheduled task
or another program:

- A small helper (`vigil.exe --process-events`) runs as SYSTEM, started at boot by the scheduled
  task `\Vigil\Process events`. It listens to Windows' process-start events (ETW,
  Microsoft-Windows-Kernel-Process) and writes each new process ID to the pipe
  `\\.\pipe\Vigil.ProcessEvents`. That is all it does: the pipe only carries data out of it, so
  nothing can send it input, and it never opens a file.
- Scanning stays in the normal Vigil without admin rights, so a bug in a file parser can't hand
  malware admin rights. Vigil only accepts the pipe from a process in session 0, where services and
  SYSTEM tasks run, so a program in your session can't pose as the helper.
- The task runs a copy of `vigil.exe` in `C:\Program Files\Vigil\`, which only administrators can
  change. Pointing it at `vigil.exe` wherever you keep it would let anything that can write there
  run as SYSTEM. Turning admin mode on again updates the copy.
- Polling stays on at once a second as a safety net, and fast polling isn't needed while the helper
  is connected.
- A second task, `\Vigil\Start at login`, starts Vigil when you log in, with your normal rights.
  Windows skips the startup programs in the Run key after some logins, and Task Scheduler doesn't
  depend on that. The task runs `vigil.exe --logon` from the protected copy, which starts whatever
  Vigil's autostart entry names, so turning autostart off in Settings still keeps Vigil from
  starting, and a Vigil you moved is still found. When Windows does run the entry too, the second
  Vigil sees the first and exits.

Admin mode still can't stop programs that run as administrator, or read their memory: Vigil
itself doesn't have admin rights. `vigil.exe --admin-mode off` removes the task and the copy.

### Rule obfuscation

The rules are obfuscated at build time (`build.rs`), so `vigil.exe` does not contain the
plaintext malware indicators. Otherwise Defender or Vigil itself could flag it.

## Build

Requirements: Rust (stable, MSVC toolchain) on Windows 10/11.

```bash
cargo build --release
```

The binary is `target\release\vigil.exe` (about 8 MB, no installer or runtime needed).

## Command-line usage

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
| `vigil.exe --scan <paths…> [--fast] [--json] [--out file]` | Command-line scan. Exit code 0 = clean, 1 = suspicious, 2 = malicious, 3 = nothing flagged but a path or file could not be scanned |
| `vigil.exe --update-hashes` | Download the MalwareBazaar hash database now (needs the Auth-Key) |
| `vigil.exe --update-yara` | Download and compile the YARA Forge rules now |
| `vigil.exe --admin-mode on\|off` | Turn admin mode on or off (asks for admin approval) |

Tray icon: left-click opens the dashboard. Right-click shows *Scan Downloads now*,
*Pause protection* and *Exit*. Files that arrive while protection is paused are scanned once it
resumes.

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

### Your own YARA rules

Put `.yar` or `.yara` files in `%LOCALAPPDATA%\Vigil\yara` (**Settings → YARA rules → Open
folder**). Each file gets its own namespace, and a file with errors is reported in Settings
without affecting the others. A match counts by the rule's `score` meta value (75, enough for
*malicious*, when there is none), adjusted by the naming rules above:

```
rule MAL_Example_Loader {
  meta:
    description = "Example loader"
    score = 80
  strings:
    $a = "some unique string"
  condition:
    uint16(0) == 0x5A4D and $a
}
```

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
  can be missed. Fast polling narrows that to 50 ms around script activity, but only after a
  script was saved in a user folder or a script host was seen: a command started directly by
  another program (a Run key, a scheduled task, a dropper's own process) can still run for up to
  a second before it is checked, unless admin mode is on. A check costs about 5 ms of CPU, so during those five seconds of
  fast polling Vigil uses about a tenth of one core. Programs running as administrator cannot be
  stopped; Vigil notifies you instead.
  DLLs are only checked for `rundll32.exe` and `regsvr32.exe`, and only under those names:
  DLLs that other programs load (DLL sideloading) and renamed copies of these hosts are not.

- YARA rules only know families someone has written a rule for. A new or heavily reworked
  family, or a packer that hides all of the code, still gets past them. Rule packages also
  carry the licenses of their source repositories, which are listed in each package.

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
                      offline MalwareBazaar hash database (hashdb.rs), YARA-X rules (yara.rs)
src/daemon/           background service: watchers, program-start watcher, debounced worker, Win32 tray
src/gui/              egui dashboard and theme
src/store.rs          activity log, status heartbeat, quarantine vault
src/winapi.rs         Authenticode, Mark-of-the-Web, registry, Defender (MpCmdRun)
src/steam.rs          Steam library discovery (libraryfolders.vdf)
```
