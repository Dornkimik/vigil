//! The background service: watches Downloads, Steam libraries and custom folders,
//! scans new files and newly started programs on a low-priority thread and reacts to detections.

mod procwatch;
pub mod tray;

use crate::config::{self, Config};
use crate::engine::filetype::{TEMP_EXTS, ext_of};
use crate::engine::{Engine, Report, ScanOptions, Source, Verdict, hashdb, memory, yara};
use crate::store::{self, Action, Event, Status, WatchedDir};
use crate::{steam, winapi};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

pub const DAEMON_MUTEX: &str = r"Local\Vigil.Daemon";

/// Wait this long after the last change before scanning, so downloads/installs finish first.
const SETTLE: Duration = Duration::from_secs(2);
const MAX_RETRIES: u32 = 40;
/// A malicious file that couldn't be quarantined is tried again this often, for ten minutes.
const QUARANTINE_RETRY: Duration = Duration::from_secs(30);
const QUARANTINE_RETRIES: u32 = 20;
/// When a started program's memory is checked, counted from its start. Packers unpack
/// within milliseconds; the second look catches loaders that wait before they decrypt.
const MEMORY_PASSES: [Duration; 2] = [Duration::from_secs(5), Duration::from_secs(60)];
/// File findings that mean the program unpacks itself, so its image in memory differs from its file.
const PACKED: &[&str] = &["pe.packer", "pe.high_entropy", "pe.few_imports", "pe.rwx"];

pub struct Shared {
    pub config: RwLock<Config>,
    pub engine: RwLock<Arc<Engine>>,
    pub scanned: AtomicU64,
    pub threats: AtomicU64,
    pub queued: AtomicUsize,
    pub current: Mutex<Option<String>>,
    pub watched: Mutex<Vec<WatchedDir>>,
}

pub enum Work {
    /// A filesystem change reported by a watcher.
    Changed(PathBuf, Source),
    /// An explicit request to (re)scan a file or folder, ignoring the scan cache.
    Scan(PathBuf, Source),
    /// The image of a program that just started, or a DLL that rundll32/regsvr32 runs.
    /// Scanned right away, ahead of other work.
    Launched(PathBuf),
    /// A program that just started, by process ID. Its memory is checked once it has had
    /// time to unpack itself.
    Started(u32, PathBuf),
}

pub fn run(open_gui: bool) {
    let Some(_lock) = winapi::NamedMutex::acquire(DAEMON_MUTEX) else { return };
    if open_gui {
        winapi::spawn_self(&["--gui"]);
    }
    let cfg = Config::load();
    let _ = cfg.save();
    let prev = Status::load();
    let shared = Arc::new(Shared {
        engine: RwLock::new(Arc::new(Engine::new(&cfg))),
        config: RwLock::new(cfg),
        scanned: AtomicU64::new(prev.scanned),
        threats: AtomicU64::new(prev.threats),
        queued: AtomicUsize::new(0),
        current: Mutex::new(None),
        watched: Mutex::new(Vec::new()),
    });

    let (tx, rx) = mpsc::channel();
    {
        let shared = shared.clone();
        thread::spawn(move || worker(shared, rx));
    }
    {
        let (shared, tx) = (shared.clone(), tx.clone());
        thread::spawn(move || supervisor(shared, tx));
    }
    {
        let shared = shared.clone();
        thread::spawn(move || signature_updater(shared));
    }
    {
        let (shared, tx) = (shared.clone(), tx.clone());
        thread::spawn(move || procwatch::run(shared, tx));
    }
    queue_recent_downloads(&tx);

    tray::run(shared.clone(), tx);

    let mut status = Status::load();
    status.heartbeat = 0;
    status.save();
}

/// Catch files that arrived while Vigil wasn't running.
fn queue_recent_downloads(tx: &Sender<Work>) {
    let Some(dl) = dirs::download_dir() else { return };
    let cutoff = SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
    for entry in std::fs::read_dir(dl).into_iter().flatten().flatten() {
        let recent = entry.metadata().ok().and_then(|m| m.modified().ok()).is_some_and(|t| t > cutoff);
        if recent && entry.path().is_file() {
            let _ = tx.send(Work::Changed(entry.path(), Source::Downloads));
        }
    }
}

pub fn desired_watches(cfg: &Config) -> Vec<WatchedDir> {
    let mut v = Vec::new();
    if cfg.watch_downloads {
        if let Some(d) = dirs::download_dir() {
            v.push(WatchedDir { path: d, source: Source::Downloads });
        }
    }
    if cfg.watch_steam {
        let s = steam::discover();
        v.extend(s.games.into_iter().map(|path| WatchedDir { path, source: Source::Steam }));
        v.extend(s.workshop.into_iter().map(|path| WatchedDir { path, source: Source::Workshop }));
    }
    v.extend(cfg.extra_folders.iter().filter(|p| p.is_dir()).map(|p| WatchedDir { path: p.clone(), source: Source::Folder }));
    v
}

fn start_watchers(dirs: &[WatchedDir], tx: &Sender<Work>) -> Vec<RecommendedWatcher> {
    let mut watchers = Vec::new();
    for d in dirs {
        let (tx, source) = (tx.clone(), d.source);
        let handler = move |res: notify::Result<notify::Event>| {
            let Ok(ev) = res else { return };
            if matches!(ev.kind, notify::EventKind::Create(_) | notify::EventKind::Modify(_)) {
                for p in ev.paths {
                    let _ = tx.send(Work::Changed(p, source));
                }
            }
        };
        if let Ok(mut w) = notify::recommended_watcher(handler) {
            if w.watch(&d.path, RecursiveMode::Recursive).is_ok() {
                watchers.push(w);
            }
        }
    }
    watchers
}

/// Reloads config/rules when they change, keeps watchers in sync and writes the status heartbeat.
fn supervisor(shared: Arc<Shared>, tx: Sender<Work>) {
    let started = store::now();
    let stamp = || {
        let mut s: Vec<_> =
            [config::config_path(), config::custom_rules_path(), config::blocklist_path(), config::hashdb_meta_path(), config::yara_meta_path()]
                .iter()
                .map(|p| config::modified(p))
                .collect();
        s.push(yara::custom_stamp());
        s
    };
    let mut last_stamp = stamp();
    let mut dirs = desired_watches(&shared.config.read().unwrap());
    let mut watchers = start_watchers(&dirs, &tx);
    *shared.watched.lock().unwrap() = dirs.clone();
    let mut last_discovery = Instant::now();

    loop {
        let s = stamp();
        let rediscover = last_discovery.elapsed() > Duration::from_secs(600);
        if s != last_stamp || rediscover {
            last_stamp = s;
            last_discovery = Instant::now();
            let cfg = Config::load();
            *shared.engine.write().unwrap() = Arc::new(Engine::new(&cfg));
            let wanted = desired_watches(&cfg);
            *shared.config.write().unwrap() = cfg;
            let changed = wanted.len() != dirs.len() || wanted.iter().zip(&dirs).any(|(a, b)| a.path != b.path);
            if changed {
                watchers.clear();
                dirs = wanted;
                watchers = start_watchers(&dirs, &tx);
                *shared.watched.lock().unwrap() = dirs.clone();
            }
            tray::refresh();
        }

        Status {
            pid: std::process::id(),
            started,
            heartbeat: store::now(),
            scanned: shared.scanned.load(Ordering::Relaxed),
            threats: shared.threats.load(Ordering::Relaxed),
            queued: shared.queued.load(Ordering::Relaxed),
            rules: shared.engine.read().unwrap().rule_count(),
            watched: dirs.clone(),
            current: shared.current.lock().unwrap().clone(),
        }
        .save();
        thread::sleep(Duration::from_secs(2));
    }
}

/// Keeps the offline MalwareBazaar hash database and the YARA rules current. A finished
/// update rewrites hashdb.json / yara.json, which makes the supervisor load a fresh engine.
fn signature_updater(shared: Arc<Shared>) {
    winapi::set_background_priority();
    thread::sleep(Duration::from_secs(30));
    loop {
        let (key, yara_updates) = {
            let cfg = shared.config.read().unwrap();
            (cfg.malwarebazaar_key.clone(), cfg.yara_updates)
        };
        if !key.trim().is_empty() && hashdb::Meta::load().due(store::now()) {
            let _ = hashdb::update(&key, false);
        }
        let unusable = shared.engine.read().unwrap().yara().forge_unusable();
        if yara_updates && yara::Meta::load().due(store::now(), unusable) {
            let _ = yara::update(false, unusable);
        }
        thread::sleep(Duration::from_secs(60));
    }
}

struct Pending {
    source: Source,
    due: Instant,
    attempts: u32,
    force: bool,
    /// The file is the image or a DLL of a running program, which gets stopped if it is malicious.
    launched: bool,
    /// A malicious file that could not be quarantined (it was locked, or its program runs
    /// elevated). Quarantine is tried again with this report while the file is unchanged.
    unresolved: Option<Unresolved>,
}

struct Unresolved {
    key: FileKey,
    report: Report,
    failures: u32,
}

struct MemoryScan {
    pid: u32,
    path: PathBuf,
    started: Instant,
    /// Index into [`MEMORY_PASSES`].
    pass: usize,
}

type FileKey = (u64, Option<SystemTime>);

struct Worker {
    shared: Arc<Shared>,
    rx: Receiver<Work>,
    pending: HashMap<PathBuf, Pending>,
    /// path -> (size, mtime) of files already scanned, so Steam's churn doesn't trigger rescans.
    seen: HashMap<PathBuf, FileKey>,
    /// Latest report for each program that started, which its memory scans build on.
    launches: HashMap<PathBuf, (FileKey, Report)>,
    memory: Vec<MemoryScan>,
    data_dir: PathBuf,
}

fn worker(shared: Arc<Shared>, rx: Receiver<Work>) {
    winapi::set_background_priority();
    let mut w = Worker {
        shared,
        rx,
        pending: HashMap::new(),
        seen: HashMap::new(),
        launches: HashMap::new(),
        memory: Vec::new(),
        data_dir: config::data_dir(),
    };
    loop {
        match w.rx.recv_timeout(Duration::from_millis(500)) {
            Ok(work) => w.enqueue(work),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        while let Ok(work) = w.rx.try_recv() {
            w.enqueue(work);
        }
        w.shared.queued.store(w.pending.len(), Ordering::Relaxed);
        w.process_due();
        w.scan_memory();
        if w.pending.is_empty() {
            *w.shared.current.lock().unwrap() = None;
        }
        if w.seen.len() > 200_000 {
            w.seen.clear();
        }
        if w.launches.len() > 10_000 {
            w.launches.clear();
        }
    }
}

impl Worker {
    /// Scans a batch of the work that is due.
    fn process_due(&mut self) {
        let now = Instant::now();
        let ready: Vec<PathBuf> = self.pending.iter().filter(|(_, p)| p.due <= now).map(|(k, _)| k.clone()).take(256).collect();
        for path in ready {
            // While paused, work stays queued and is scanned once protection resumes.
            if self.shared.config.read().unwrap().paused {
                break;
            }
            // Already taken by `scan_launches` during this batch.
            let Some(p) = self.pending.remove(&path) else { continue };
            self.process(&path, p);
            self.scan_launches();
        }
    }

    fn enqueue(&mut self, work: Work) {
        let (path, source, force, launched) = match work {
            Work::Started(pid, path) => {
                self.memory.push(MemoryScan { pid, path, started: Instant::now(), pass: 0 });
                return;
            }
            Work::Changed(p, s) => (p, s, false, false),
            Work::Scan(p, s) => (p, s, true, false),
            Work::Launched(p) => (p, Source::Launch, false, true),
        };
        // Unfinished downloads and Vigil's own files are skipped, but never a program that runs:
        // Windows starts a program whatever its name, and droppers like to call theirs `.tmp`.
        if !launched && (path.starts_with(&self.data_dir) || TEMP_EXTS.contains(&ext_of(&path.to_string_lossy()).as_str())) {
            return;
        }
        // A finished download or a running program won't change any more; no need to let it settle.
        let due = Instant::now() + if force || launched { Duration::ZERO } else { SETTLE };
        let entry = self.pending.entry(path).or_insert(Pending { source, due, attempts: 0, force, launched, unresolved: None });
        entry.due = due;
        entry.force |= force;
        entry.launched |= launched;
        // New activity on a file waiting for another quarantine attempt gets a full, reported scan.
        if entry.unresolved.take().is_some() {
            entry.force = true;
        }
    }

    /// Picks up new work and scans programs that just started right away, so a big
    /// folder scan or Steam install doesn't hold them up.
    fn scan_launches(&mut self) {
        while let Ok(work) = self.rx.try_recv() {
            self.enqueue(work);
        }
        if self.shared.config.read().unwrap().paused {
            return;
        }
        let now = Instant::now();
        let due: Vec<PathBuf> = self.pending.iter().filter(|(_, p)| p.launched && p.due <= now).map(|(k, _)| k.clone()).collect();
        for path in due {
            if let Some(p) = self.pending.remove(&path) {
                self.process(&path, p);
            }
        }
        self.scan_memory();
    }

    /// Checks the memory of programs that started a while ago.
    fn scan_memory(&mut self) {
        if self.memory.is_empty() || self.shared.config.read().unwrap().paused {
            return;
        }
        let now = Instant::now();
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.memory).into_iter().partition(|m| m.started + MEMORY_PASSES[m.pass] <= now);
        self.memory = waiting;
        for scan in due {
            if self.scan_process(&scan) && scan.pass + 1 < MEMORY_PASSES.len() {
                self.memory.push(MemoryScan { pass: scan.pass + 1, ..scan });
            }
        }
    }

    /// Checks one program's memory against what its file scan found. Returns whether
    /// it is worth another look later.
    fn scan_process(&mut self, scan: &MemoryScan) -> bool {
        // The file scan comes first; it may still be waiting for the file to unlock.
        let Some(&(key, ref file)) = self.launches.get(&scan.path) else { return true };
        // Signed programs get the same pass as for YARA on files. Malicious ones were
        // already stopped, and the user vouched for allowlisted ones.
        if file.signer.is_some() || file.verdict == Verdict::Malicious || file.findings.iter().any(|f| f.id == "allowlist") {
            return false;
        }
        // Elevated programs can't be read, and the program may have exited already.
        let Some(process) = winapi::ProcessMemory::open(scan.pid) else { return false };
        // The process ID may belong to another program by now.
        let same = process.image().map(procwatch::long_path).is_some_and(|p| p.as_os_str().eq_ignore_ascii_case(scan.path.as_os_str()));
        if !same {
            return false;
        }
        *self.shared.current.lock().unwrap() = Some(format!("{} (memory)", scan.path.display()));
        let packed = file.findings.iter().any(|f| PACKED.contains(&f.id.as_str()));
        let blocks = memory::read(&process, packed);
        drop(process);
        let engine = self.shared.engine.read().unwrap().clone();
        let found = engine.scan_memory(&file.findings, &blocks);
        if found.is_empty() {
            return true;
        }
        let mut report = file.clone();
        report.score += found.iter().map(|f| f.weight).sum::<i32>();
        report.findings.extend(found);
        let raised = Verdict::from_score(report.score) > report.verdict;
        report.verdict = Verdict::from_score(report.score);
        if let Some((_, stored)) = self.launches.get_mut(&scan.path) {
            *stored = report.clone();
        }
        if raised && handle_report(&self.shared, &report, Source::Launch, true, false) == Action::QuarantineFailed {
            self.retry_quarantine(&scan.path, Source::Launch, true, key, report, 1);
        }
        true
    }

    fn process(&mut self, path: &Path, mut p: Pending) {
        if let Some(u) = p.unresolved.take() {
            match std::fs::metadata(path) {
                Ok(meta) if (meta.len(), meta.modified().ok()) == u.key => {
                    if handle_report(&self.shared, &u.report, p.source, p.launched, true) == Action::QuarantineFailed {
                        self.retry_quarantine(path, p.source, p.launched, u.key, u.report, u.failures + 1);
                    }
                    return;
                }
                // Gone: removed by the user or another tool.
                Err(_) => return,
                // Changed since: scan it again.
                Ok(_) => {}
            }
        }
        if path.is_dir() {
            let mut stack = vec![path.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                    let Ok(ft) = entry.file_type() else { continue };
                    if ft.is_dir() {
                        stack.push(entry.path());
                    } else if ft.is_file() {
                        if self.shared.config.read().unwrap().paused {
                            // Walked again once protection resumes; files already scanned are skipped.
                            self.pending.insert(path.to_path_buf(), p);
                            return;
                        }
                        let _ = self.scan_one(&entry.path(), p.source, p.force, false);
                        self.scan_launches();
                    }
                }
            }
            return;
        }
        if let Err(e) = self.scan_one(path, p.source, p.force, p.launched) {
            // Locked by the writer (sharing violation / access denied): try again shortly.
            let retry = matches!(e.raw_os_error(), Some(32) | Some(33) | Some(5));
            if retry && p.attempts < MAX_RETRIES {
                self.pending.insert(
                    path.to_path_buf(),
                    Pending { due: Instant::now() + Duration::from_secs(3), attempts: p.attempts + 1, ..p },
                );
            }
        }
    }

    fn scan_one(&mut self, path: &Path, source: Source, force: bool, launched: bool) -> std::io::Result<()> {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() || meta.len() == 0 {
            return Ok(());
        }
        let key = (meta.len(), meta.modified().ok());
        // A started program needs its report for the memory scans that follow. A malicious one
        // that runs again (auto-quarantine is off, or it could not be quarantined) is reported again.
        let have_report = !launched || self.launches.get(path).is_some_and(|(k, r)| *k == key && r.verdict != Verdict::Malicious);
        if !force && self.seen.get(path) == Some(&key) && have_report {
            return Ok(());
        }
        let source = match steam::source_for(path, source) {
            // A program that runs is complete, whatever folder Steam keeps it in.
            Source::SteamDownload if launched => Source::Steam,
            s => s,
        };
        // A running program is read whatever its extension; only Steam's asset files stay unopened.
        let opts = ScanOptions { source, sniff_all: launched || !source.is_steam() };
        let engine = self.shared.engine.read().unwrap().clone();
        *self.shared.current.lock().unwrap() = Some(path.display().to_string());

        let report = engine.scan_file(path, opts)?;
        self.seen.insert(path.to_path_buf(), key);
        if report.analyzed {
            if launched {
                self.launches.insert(path.to_path_buf(), (key, report.clone()));
            }
            self.shared.scanned.fetch_add(1, Ordering::Relaxed);
            if handle_report(&self.shared, &report, source, launched, false) == Action::QuarantineFailed {
                self.retry_quarantine(path, source, launched, key, report, 1);
            }
        }
        Ok(())
    }

    /// Queues another quarantine attempt for a malicious file that couldn't be moved.
    fn retry_quarantine(&mut self, path: &Path, source: Source, launched: bool, key: FileKey, report: Report, failures: u32) {
        if failures > QUARANTINE_RETRIES {
            return;
        }
        let unresolved = Some(Unresolved { key, report, failures });
        self.pending.insert(
            path.to_path_buf(),
            Pending { source, due: Instant::now() + QUARANTINE_RETRY, attempts: 0, force: true, launched, unresolved },
        );
    }
}

/// Counts, quarantines, notifies and logs. A `retry` of a failed quarantine stays quiet
/// unless the file could be quarantined this time.
fn handle_report(shared: &Shared, report: &Report, source: Source, launched: bool, retry: bool) -> Action {
    let cfg = shared.config.read().unwrap().clone();
    let mut action = Action::None;
    if report.verdict >= Verdict::Suspicious && !retry {
        shared.threats.fetch_add(1, Ordering::Relaxed);
    }
    if report.verdict == Verdict::Malicious && cfg.auto_quarantine {
        // A running program locks its file, so it has to be stopped before it can be moved.
        let stopped = launched && winapi::stop_processes_using(&report.path);
        let mut result = store::quarantine(report);
        // The image can stay mapped for a moment after the process exits.
        for _ in 0..5 {
            if result.is_ok() || !stopped {
                break;
            }
            thread::sleep(Duration::from_millis(300));
            result = store::quarantine(report);
        }
        action = match result {
            Ok(_) => Action::Quarantined,
            Err(_) => Action::QuarantineFailed,
        };
    }
    if retry && action != Action::Quarantined {
        return action;
    }

    let reason = report.findings.iter().filter(|f| f.weight > 0).max_by_key(|f| f.weight).map(|f| f.title.as_str()).unwrap_or("");
    if cfg.notifications {
        let note = match (report.verdict, action) {
            (Verdict::Malicious, Action::Quarantined) if launched => {
                Some(("Threat stopped and quarantined", format!("{}\n{reason}", report.name), true))
            }
            (Verdict::Malicious, Action::Quarantined) => Some(("Threat quarantined", format!("{}\n{reason}", report.name), true)),
            (Verdict::Malicious, Action::QuarantineFailed) if launched => Some((
                "Threat detected - action needed",
                format!("{} is running and could not be stopped or quarantined.", report.name),
                true,
            )),
            (Verdict::Malicious, Action::QuarantineFailed) => {
                Some(("Threat detected - action needed", format!("{} is in use and could not be quarantined.", report.name), true))
            }
            (Verdict::Malicious, _) => Some(("Threat detected", format!("{}\n{reason}", report.name), true)),
            (Verdict::Suspicious, _) if cfg.notify_suspicious => Some(("Suspicious file", format!("{}\n{reason}", report.name), false)),
            _ => None,
        };
        if let Some((title, body, severe)) = note {
            tray::notify(title, &body, severe);
        }
    }

    // Steam installs and everyday program launches produce lots of clean files; only log what matters there.
    let noisy = source.is_steam() || source == Source::Launch;
    if !noisy || report.verdict != Verdict::Clean {
        store::append_event(&Event { time: store::now(), source, action, report: report.clone() });
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker(cfg: Config) -> Worker {
        let shared = Arc::new(Shared {
            engine: RwLock::new(Arc::new(Engine::new(&cfg))),
            config: RwLock::new(cfg),
            scanned: AtomicU64::new(0),
            threats: AtomicU64::new(0),
            queued: AtomicUsize::new(0),
            current: Mutex::new(None),
            watched: Mutex::new(Vec::new()),
        });
        // The sender is dropped: these tests feed the worker directly.
        let (_, rx) = mpsc::channel();
        Worker { shared, rx, pending: HashMap::new(), seen: HashMap::new(), launches: HashMap::new(), memory: Vec::new(), data_dir: config::data_dir() }
    }

    /// Detections in these tests are only logged: nothing is quarantined or shown.
    fn quiet() -> Config {
        Config { auto_quarantine: false, notifications: false, ..Config::default() }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vigil-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An inert stand-in for a program: PE headers and padding, never run.
    fn program() -> Vec<u8> {
        let mut exe = crate::engine::pe::tests::headers(false);
        exe.extend_from_slice(&[0u8; 4096]);
        exe
    }

    #[test]
    fn programs_that_run_are_scanned_whatever_their_name_or_folder() {
        let mut w = worker(quiet());
        for path in [r"C:\Users\me\AppData\Local\Temp\is-ABCDE.tmp", r"C:\Users\me\AppData\Local\Temp\payload.part"] {
            w.enqueue(Work::Launched(PathBuf::from(path)));
        }
        w.enqueue(Work::Launched(config::data_dir().join("yara").join("x.exe")));
        assert_eq!(w.pending.len(), 3);
        // Unfinished downloads and Vigil's own files are still skipped when they merely change.
        let mut w = worker(quiet());
        w.enqueue(Work::Changed(PathBuf::from(r"C:\Users\me\Downloads\setup.exe.crdownload"), Source::Downloads));
        w.enqueue(Work::Changed(config::data_dir().join("status.json"), Source::Folder));
        assert!(w.pending.is_empty());
    }

    #[test]
    fn programs_in_folders_named_like_steam_are_analyzed() {
        let root = scratch("steam-lookalike");
        let dir = root.join(r"steamapps\common\x");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.dat");
        std::fs::write(&path, program()).unwrap();
        let mut w = worker(quiet());
        w.scan_one(&path, Source::Launch, false, true).unwrap();
        assert!(w.launches.contains_key(&path));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn work_queued_while_paused_is_kept() {
        let dir = scratch("paused");
        let path = dir.join("tool.exe");
        std::fs::write(&path, program()).unwrap();
        let mut w = worker(Config { paused: true, ..quiet() });
        // Clean Steam files aren't logged, so the test leaves the activity log alone.
        w.enqueue(Work::Scan(path.clone(), Source::Steam));
        w.process_due();
        assert!(w.pending.contains_key(&path) && w.seen.is_empty());
        w.shared.config.write().unwrap().paused = false;
        w.process_due();
        assert!(w.pending.is_empty() && w.seen.contains_key(&path));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quarantine_retries_end_when_the_file_is_gone_and_restart_on_new_activity() {
        let dir = scratch("unresolved");
        let path = dir.join("tool.exe");
        std::fs::write(&path, program()).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let key = (meta.len(), meta.modified().ok());
        let mut w = worker(quiet());
        let scanned = w.shared.engine.read().unwrap().scan_file(&path, ScanOptions { source: Source::Manual, sniff_all: true }).unwrap();
        let report = Report { verdict: Verdict::Malicious, ..scanned };

        w.retry_quarantine(&path, Source::Manual, false, key, report.clone(), QUARANTINE_RETRIES + 1);
        assert!(w.pending.is_empty(), "retries give up after a while");
        w.retry_quarantine(&path, Source::Manual, false, key, report.clone(), 1);
        assert!(w.pending[&path].unresolved.is_some() && w.pending[&path].force);
        // The program running again means a full, reported scan instead.
        w.enqueue(Work::Launched(path.clone()));
        assert!(w.pending[&path].unresolved.is_none() && w.pending[&path].force);
        // A retry for a file that was removed meanwhile is dropped.
        w.retry_quarantine(&path, Source::Manual, false, key, report, 1);
        let p = w.pending.remove(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        w.process(&path, p);
        assert!(w.pending.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_malicious_program_that_runs_again_is_scanned_again() {
        let dir = scratch("relaunch");
        let path = dir.join("tool.exe");
        std::fs::write(&path, program()).unwrap();
        let mut w = worker(quiet());
        w.scan_one(&path, Source::Launch, false, true).unwrap();
        let before = w.shared.scanned.load(Ordering::Relaxed);
        w.scan_one(&path, Source::Launch, false, true).unwrap();
        assert_eq!(w.shared.scanned.load(Ordering::Relaxed), before, "a clean program is scanned once");
        w.launches.get_mut(&path).unwrap().1.verdict = Verdict::Malicious;
        w.scan_one(&path, Source::Launch, false, true).unwrap();
        assert_eq!(w.shared.scanned.load(Ordering::Relaxed), before + 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
