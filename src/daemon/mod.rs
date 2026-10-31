//! The background service: watches Downloads, Steam libraries and custom folders,
//! scans new files and newly started programs on a low-priority thread and reacts to detections.

mod procwatch;
pub mod tray;

use crate::config::{self, Config};
use crate::engine::filetype::{TEMP_EXTS, ext_of};
use crate::engine::{Engine, Report, ScanOptions, Source, Verdict, hashdb};
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
        [config::config_path(), config::custom_rules_path(), config::blocklist_path(), config::hashdb_meta_path()]
            .map(|p| config::modified(&p))
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

/// Keeps the offline MalwareBazaar hash database current. A finished update rewrites
/// hashdb.json, which makes the supervisor load a fresh engine.
fn signature_updater(shared: Arc<Shared>) {
    winapi::set_background_priority();
    thread::sleep(Duration::from_secs(30));
    loop {
        let key = shared.config.read().unwrap().malwarebazaar_key.clone();
        if !key.trim().is_empty() && hashdb::Meta::load().due(store::now()) {
            let _ = hashdb::update(&key, false);
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
}

struct Worker {
    shared: Arc<Shared>,
    rx: Receiver<Work>,
    pending: HashMap<PathBuf, Pending>,
    /// path -> (size, mtime) of files already scanned, so Steam's churn doesn't trigger rescans.
    seen: HashMap<PathBuf, (u64, Option<SystemTime>)>,
    data_dir: PathBuf,
}

fn worker(shared: Arc<Shared>, rx: Receiver<Work>) {
    winapi::set_background_priority();
    let mut w = Worker { shared, rx, pending: HashMap::new(), seen: HashMap::new(), data_dir: config::data_dir() };
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

        let now = Instant::now();
        let ready: Vec<PathBuf> = w.pending.iter().filter(|(_, p)| p.due <= now).map(|(k, _)| k.clone()).take(256).collect();
        for path in ready {
            // Already taken by `scan_launches` during this batch.
            let Some(p) = w.pending.remove(&path) else { continue };
            if w.shared.config.read().unwrap().paused {
                continue;
            }
            w.process(&path, p);
            w.scan_launches();
        }
        if w.pending.is_empty() {
            *w.shared.current.lock().unwrap() = None;
        }
        if w.seen.len() > 200_000 {
            w.seen.clear();
        }
    }
}

impl Worker {
    fn enqueue(&mut self, work: Work) {
        let (path, source, force, launched) = match work {
            Work::Changed(p, s) => (p, s, false, false),
            Work::Scan(p, s) => (p, s, true, false),
            Work::Launched(p) => (p, Source::Launch, false, true),
        };
        if path.starts_with(&self.data_dir) || TEMP_EXTS.contains(&ext_of(&path.to_string_lossy()).as_str()) {
            return;
        }
        // A finished download or a running program won't change any more; no need to let it settle.
        let due = Instant::now() + if force || launched { Duration::ZERO } else { SETTLE };
        let entry = self.pending.entry(path).or_insert(Pending { source, due, attempts: 0, force, launched });
        entry.due = due;
        entry.force |= force;
        entry.launched |= launched;
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
    }

    fn process(&mut self, path: &Path, p: Pending) {
        if path.is_dir() {
            let mut stack = vec![path.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                    let Ok(ft) = entry.file_type() else { continue };
                    if ft.is_dir() {
                        stack.push(entry.path());
                    } else if ft.is_file() {
                        if self.shared.config.read().unwrap().paused {
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
        if !force && self.seen.get(path) == Some(&key) {
            return Ok(());
        }
        let source = steam::source_for(path, source);
        let opts = ScanOptions { source, sniff_all: !source.is_steam() };
        let engine = self.shared.engine.read().unwrap().clone();
        *self.shared.current.lock().unwrap() = Some(path.display().to_string());

        let report = engine.scan_file(path, opts)?;
        self.seen.insert(path.to_path_buf(), key);
        if report.analyzed {
            self.shared.scanned.fetch_add(1, Ordering::Relaxed);
            handle_report(&self.shared, report, source, launched);
        }
        Ok(())
    }
}

fn handle_report(shared: &Shared, report: Report, source: Source, launched: bool) {
    let cfg = shared.config.read().unwrap().clone();
    let mut action = Action::None;
    if report.verdict >= Verdict::Suspicious {
        shared.threats.fetch_add(1, Ordering::Relaxed);
    }
    if report.verdict == Verdict::Malicious && cfg.auto_quarantine {
        // A running program locks its file, so it has to be stopped before it can be moved.
        let stopped = launched && winapi::stop_processes_using(&report.path);
        let mut result = store::quarantine(&report);
        // The image can stay mapped for a moment after the process exits.
        for _ in 0..5 {
            if result.is_ok() || !stopped {
                break;
            }
            thread::sleep(Duration::from_millis(300));
            result = store::quarantine(&report);
        }
        action = match result {
            Ok(_) => Action::Quarantined,
            Err(_) => Action::QuarantineFailed,
        };
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
        store::append_event(&Event { time: store::now(), source, action, report });
    }
}
