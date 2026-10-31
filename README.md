# Vigil

**A free, lightweight extra layer of malware protection for Windows 11, made with gamers in mind.**

Vigil runs quietly in your notification area and checks the things that most often bring
malware onto a gaming PC: files you download, Steam games and Workshop items, and the programs
and scripts that start on your computer. It works **alongside Microsoft Defender**, not instead
of it, catching the kind of threats that slip through: password and Discord-token stealers,
fake game cheats and cracks, and scripts that quietly download more malware.

- **Free and open source** (MIT license), no ads, no account, no upsell
- **Tiny**: one 8 MB program, no installer, no admin rights needed
- **Light**: runs at low priority and sits idle when nothing changes
- **Private**: scans happen on your PC; your files are never uploaded

## What Vigil watches

| | |
|---|---|
| **Your downloads** | Every new file in your Downloads folder is checked the moment your browser finishes saving it. |
| **Steam games and the Workshop** | Game installs, updates and Workshop items are checked as Steam writes them, so an indie game that ships with an info-stealer gets caught before you launch it. |
| **Every program you start** | Whether it came from a USB stick, a ZIP you extracted or another program, it is checked when it runs. |
| **Scripts saved to your PC** | Batch files, PowerShell scripts, shortcuts and similar files are checked the moment they appear in your user folders, so a "dropper" can be stopped before it gets going. |

## How it catches malware

Malware authors constantly rename, repack and disguise their programs, so Vigil doesn't rely on
recognizing a name. It combines several kinds of checks:

**It looks at what a program is built to do.** Vigil looks for the tell-tale combinations
behind real attacks: reading your saved browser passwords and cookies, grabbing Discord, Steam
or Telegram sessions, emptying crypto wallets, sending loot to a Discord webhook, switching off
Defender, or deleting your backups next to a ransom note. One harmless-looking trait on its own
isn't enough; it takes evidence that adds up.

**It sees through disguises.** `invoice.pdf.exe`, a program renamed to `.jpg`, a file pretending
to be a Windows system program, a password-protected ZIP that hides an `.exe`, a program padded
to hundreds of megabytes to dodge scanners: these are classic tricks, and Vigil flags them.

**It unwraps hidden code without running it.** Scripts are often scrambled or encoded several
layers deep so scanners only see gibberish. Vigil peels those layers back and checks what's
underneath, and it also looks inside ZIP files.

**It checks programs once they're running.** Packed or encrypted malware looks harmless on disk,
but it has to reveal its real code in memory to run. A few seconds after an unknown program
starts, Vigil takes a look at what it unpacked.

**It acts fast on scripts.** Many attacks hide in a single PowerShell command that never touches
the disk. Vigil checks those commands as they start, and when a fresh script launches a hidden
PowerShell window, Vigil can stop it in a few hundredths of a second, before it runs a single
line.

**It uses the community's knowledge.** Vigil downloads about 5,000 curated
[YARA Forge](https://github.com/YARAHQ/yara-forge) rules each week that recognize known malware
families, even when their text is encrypted. Add a free
[MalwareBazaar](https://auth.abuse.ch/) key and it also checks files against a database of
known malware fingerprints, kept on your PC and matched offline.

**It trusts real publishers.** Programs with a valid digital signature from their publisher get
the benefit of the doubt, which keeps false alarms on your game library low, while broken,
untrusted or revoked signatures count against a file.

**It can ask Defender for a second opinion.** One click sends a single file to Microsoft Defender
for an independent check.

## When something is found

Each file gets a score, and the dashboard shows exactly which findings added to it.

- **Malicious** files are moved to quarantine automatically. If the program is running, Vigil
  stops it first. Quarantined files are stored encoded, so they can't run by accident.
- **Suspicious** files get a notification, and you decide what to do.
- **False alarm?** Restore the file from quarantine or mark it as safe, and Vigil won't flag it
  again.

## Getting started

Vigil doesn't have a prebuilt download yet, so for now you build it yourself. You'll need
[Rust](https://www.rust-lang.org/tools/install) on Windows 10 or 11, then run:

```bash
cargo build --release
```

Start `target\release\vigil.exe`. The dashboard opens and protection starts right away. Then,
in the dashboard:

1. Go to **Settings → Start with Windows** so Vigil runs every time you sign in.
2. Optionally add a free **MalwareBazaar** key in Settings for known-malware lookups.
3. Optionally turn on **admin mode** in Settings. With one admin approval, Windows tells Vigil the
   instant any program starts, instead of Vigil having to look for new programs once a second.
   The scanning itself still runs without admin rights.

Closing the dashboard keeps protection running in the notification area. Left-click the tray
icon to reopen it; right-click to scan your Downloads, pause protection or exit.

## Your privacy

Vigil scans everything on your own PC and never uploads your files. It goes online only to
download its detection data: the YARA rules from GitHub, and, if you add a MalwareBazaar key,
MalwareBazaar's database of known-malware fingerprints. Until that database's first download
finishes, the fingerprints (SHA-256 hashes) of unsigned files are looked up online; after
that, lookups happen offline. Rule updates can be turned off in Settings.

## What Vigil isn't

Vigil is a second line of defense, so keep Defender's real-time and cloud protection switched
on. It inspects files and programs rather than sandboxing them, so brand-new or heavily
disguised malware can still get past it, and without admin mode a program that starts and exits
within a second can be missed. Quarantining a file from a Steam game breaks that game until you
restore it or verify the game files in Steam; if the file really is malicious, uninstall the
game.

## Learn more

The [technical reference](docs/TECHNICAL.md) covers every detection layer and its scoring,
admin mode internals, command-line scanning, writing your own rules, the test suite, the full
list of limitations and the project layout.

## AI disclosure

Vigil was developed with substantial assistance from AI coding tools, including Anthropic's
Claude, which helped write its code, detection rules and documentation. Commits in the project
history that were made with AI assistance carry a `Co-Authored-By` line naming the model.

As with any security software, the source code is open for you to review, and Vigil has not
been independently audited. It is provided "as is", without warranty of any kind, as set out in
the [license](LICENSE). If you find a bug, a false alarm or a missed detection, please
[open an issue](https://github.com/Dornkimik/vigil/issues).

## License

[MIT](LICENSE)
