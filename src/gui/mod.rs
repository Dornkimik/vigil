//! The dashboard window. It is a separate, short-lived process: the background
//! service keeps running in the tray when this window is closed.

mod theme;

use crate::config::{self, Config};
use crate::daemon::DAEMON_MUTEX;
use crate::engine::{Engine, Report, ScanOptions, Source, Verdict, hashdb, yara};
use crate::store::{self, Action, Event, QuarantineEntry, Status};
use crate::winapi::{self, DefenderResult, NamedMutex};
use crate::{icon, steam};
use eframe::egui::{self, Align, Color32, Layout, RichText, ScrollArea, Ui, vec2};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use theme::*;

const GUI_MUTEX: &str = r"Local\Vigil.Gui";
const WINDOW_TITLE: &str = "Vigil";

pub fn run() {
    let Some(_lock) = NamedMutex::acquire(GUI_MUTEX) else {
        focus_existing_window();
        return;
    };
    let rgba = icon::shield_rgba(64, icon::GREEN_TOP, icon::GREEN_BOTTOM);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([860.0, 560.0])
            .with_icon(Arc::new(egui::IconData { rgba, width: 64, height: 64 })),
        ..Default::default()
    };
    let _ = eframe::run_native(WINDOW_TITLE, options, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))));
}

/// Brings an already open dashboard to the front. Returns false if none is open.
pub fn focus_existing_window() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    if !NamedMutex::exists(GUI_MUTEX) {
        return false;
    }
    let title = winapi::wide(WINDOW_TITLE);
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return false;
        }
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }
    true
}

/// Dark title bar whose color matches the app background (Windows 11).
fn style_title_bar() {
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId};
    let title = winapi::wide(WINDOW_TITLE);
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != std::process::id() {
            return;
        }
        let dark: i32 = 1;
        DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as _, 4);
        let bg = BG;
        let colorref: u32 = bg.r() as u32 | (bg.g() as u32) << 8 | (bg.b() as u32) << 16;
        DwmSetWindowAttribute(hwnd, 35, &colorref as *const _ as _, 4); // caption color
        DwmSetWindowAttribute(hwnd, 34, &colorref as *const _ as _, 4); // border color
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Scan,
    Activity,
    Quarantine,
    Settings,
}

#[derive(Clone)]
enum DefenderState {
    Running,
    Done(DefenderResult),
}

#[derive(Default)]
struct ScanProgress {
    files: usize,
    current: String,
    results: Vec<Report>,
    done: bool,
}

struct ScanJob {
    progress: Arc<Mutex<ScanProgress>>,
    cancel: Arc<AtomicBool>,
    started: Instant,
}

/// UI intents collected during rendering and applied afterwards (avoids borrow conflicts).
enum Intent {
    Quarantine(Report),
    Allow(Report),
    ShowInFolder(PathBuf),
    AskDefender(PathBuf),
    Restore(QuarantineEntry),
    Delete(QuarantineEntry),
}

type UpdateSlot = Arc<Mutex<Option<Result<usize, String>>>>;

struct App {
    page: Page,
    status: Status,
    running: bool,
    last_poll: Option<Instant>,
    events: Vec<Event>,
    events_stamp: Option<SystemTime>,
    quarantine: Vec<QuarantineEntry>,
    config: Config,
    config_stamp: Option<SystemTime>,
    autostart: bool,
    rule_count: usize,
    rule_errors: Vec<String>,
    steam: steam::SteamDirs,
    scan: Option<ScanJob>,
    results: Vec<Report>,
    last_scan: Option<(usize, Duration)>,
    show_clean: bool,
    threats_only: bool,
    expanded: HashSet<String>,
    defender: Arc<Mutex<HashMap<PathBuf, DefenderState>>>,
    key_edit: String,
    hashdb: hashdb::Meta,
    hashdb_stamp: Option<SystemTime>,
    /// Result slot of a running "Update now" request.
    hashdb_update: Option<UpdateSlot>,
    yara: yara::Meta,
    yara_stamp: Option<SystemTime>,
    yara_update: Option<UpdateSlot>,
    /// Rules from the user's own YARA files, and their compile errors.
    yara_custom: usize,
    yara_errors: Vec<String>,
    confirm_delete: Option<String>,
    toast: Option<(String, Instant)>,
    title_bar_styled: bool,
    /// path -> (exists, checked at); avoids a filesystem hit per row per frame.
    exists_cache: HashMap<PathBuf, (bool, Instant)>,
}

impl App {
    fn new(ctx: &egui::Context) -> Self {
        theme::install(ctx);
        let config = Config::load();
        let engine = Engine::new(&config);
        let mut app = Self {
            page: Page::Overview,
            status: Status::default(),
            running: false,
            last_poll: None,
            events: Vec::new(),
            events_stamp: None,
            quarantine: Vec::new(),
            key_edit: config.malwarebazaar_key.clone(),
            hashdb: hashdb::Meta::default(),
            hashdb_stamp: None,
            hashdb_update: None,
            yara: yara::Meta::default(),
            yara_stamp: None,
            yara_update: None,
            yara_custom: engine.yara().custom_len(),
            yara_errors: engine.yara().custom_errors().to_vec(),
            config,
            config_stamp: config::modified(&config::config_path()),
            autostart: winapi::autostart_enabled(),
            rule_count: engine.rule_count(),
            rule_errors: engine.rule_errors().to_vec(),
            steam: steam::discover(),
            scan: None,
            results: Vec::new(),
            last_scan: None,
            show_clean: false,
            threats_only: false,
            expanded: HashSet::new(),
            defender: Arc::default(),
            confirm_delete: None,
            toast: None,
            title_bar_styled: false,
            exists_cache: HashMap::new(),
        };
        app.poll(true);
        app
    }

    /// Refresh state written by the background service (cheap; once per second).
    fn poll(&mut self, force: bool) {
        if !force && self.last_poll.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return;
        }
        self.last_poll = Some(Instant::now());
        self.running = NamedMutex::exists(DAEMON_MUTEX);
        self.status = Status::load();
        let es = config::modified(&config::events_path());
        if force || es != self.events_stamp {
            self.events_stamp = es;
            self.events = store::load_events(400);
            self.quarantine = store::list_quarantine();
        }
        let cs = config::modified(&config::config_path());
        if cs != self.config_stamp {
            self.config_stamp = cs;
            self.config = Config::load();
        }
        let hs = config::modified(&config::hashdb_meta_path());
        if force || hs != self.hashdb_stamp {
            self.hashdb_stamp = hs;
            self.hashdb = hashdb::Meta::load();
        }
        let finished = self.hashdb_update.as_ref().and_then(|slot| slot.lock().unwrap().take());
        if let Some(result) = finished {
            self.hashdb_update = None;
            match result {
                Ok(n) => self.notify(format!("Hash database updated: {n} known-malware hashes")),
                Err(e) => self.notify(format!("Hash database update failed: {e}")),
            }
        }
        let ys = config::modified(&config::yara_meta_path());
        if force || ys != self.yara_stamp {
            self.yara_stamp = ys;
            self.yara = yara::Meta::load();
        }
        let finished = self.yara_update.as_ref().and_then(|slot| slot.lock().unwrap().take());
        if let Some(result) = finished {
            self.yara_update = None;
            match result {
                Ok(n) => self.notify(format!("YARA rules updated: {n} rules")),
                Err(e) => self.notify(format!("YARA rule update failed: {e}")),
            }
        }
    }

    fn update_yara(&mut self) {
        if self.yara_update.is_some() {
            return;
        }
        let slot = Arc::new(Mutex::new(None));
        let s = slot.clone();
        std::thread::spawn(move || *s.lock().unwrap() = Some(yara::update(true, false)));
        self.yara_update = Some(slot);
    }

    /// Recompiles the user's own YARA files to show their status.
    fn reload_custom_yara(&mut self) {
        let y = yara::Yara::load();
        self.yara_custom = y.custom_len();
        self.yara_errors = y.custom_errors().to_vec();
    }

    fn update_hashdb(&mut self) {
        if self.hashdb_update.is_some() {
            return;
        }
        let slot = Arc::new(Mutex::new(None));
        let (s, key) = (slot.clone(), self.config.malwarebazaar_key.clone());
        std::thread::spawn(move || *s.lock().unwrap() = Some(hashdb::update(&key, true)));
        self.hashdb_update = Some(slot);
    }

    /// Returns false (and shows why) when the change could not be saved.
    fn update_config(&mut self, f: impl FnOnce(&mut Config)) -> bool {
        let (config, saved) = Config::update(f);
        self.config = config;
        self.config_stamp = config::modified(&config::config_path());
        if let Err(e) = &saved {
            self.notify(format!("Could not save settings to {}: {e}", config::config_path().display()));
        }
        saved.is_ok()
    }

    fn file_exists(&mut self, path: &Path) -> bool {
        match self.exists_cache.get(path) {
            Some((e, at)) if at.elapsed() < Duration::from_secs(2) => *e,
            _ => {
                let e = path.exists();
                self.exists_cache.insert(path.to_path_buf(), (e, Instant::now()));
                e
            }
        }
    }

    fn notify(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    // ------------------------------------------------------------------ scanning

    fn start_scan(&mut self, paths: Vec<PathBuf>, sniff_all: bool) {
        if self.scan.is_some() || paths.is_empty() {
            return;
        }
        self.results.clear();
        self.expanded.clear();
        let progress = Arc::new(Mutex::new(ScanProgress::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (p, c) = (progress.clone(), cancel.clone());
        std::thread::spawn(move || {
            let engine = Engine::new(&Config::load());
            for root in paths {
                crate::walk_files(&root, &mut |file: &Path| {
                    if c.load(Ordering::Relaxed) {
                        return false;
                    }
                    {
                        let mut g = p.lock().unwrap();
                        g.files += 1;
                        g.current = file.display().to_string();
                    }
                    let source = steam::source_for(file, Source::Manual);
                    if let Ok(r) = engine.scan_file(file, ScanOptions { source, sniff_all }) {
                        if r.analyzed {
                            if r.verdict != Verdict::Clean {
                                store::append_event(&Event { time: store::now(), source, action: Action::None, report: r.clone() });
                            }
                            p.lock().unwrap().results.push(r);
                        }
                    }
                    true
                });
            }
            p.lock().unwrap().done = true;
        });
        self.scan = Some(ScanJob { progress, cancel, started: Instant::now() });
        self.page = Page::Scan;
    }

    fn poll_scan(&mut self) {
        let Some(job) = &self.scan else { return };
        let mut g = job.progress.lock().unwrap();
        if g.done {
            let mut results = std::mem::take(&mut g.results);
            results.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(b.score.cmp(&a.score)));
            self.last_scan = Some((g.files, job.started.elapsed()));
            drop(g);
            self.results = results;
            self.scan = None;
            self.poll(true);
        }
    }

    fn apply(&mut self, intent: Intent) {
        match intent {
            Intent::Quarantine(r) => match store::quarantine(&r) {
                Ok(_) => {
                    store::append_event(&Event { time: store::now(), source: Source::Manual, action: Action::Quarantined, report: r.clone() });
                    self.results.retain(|x| x.path != r.path);
                    self.notify(format!("{} moved to quarantine", r.name));
                }
                Err(e) => self.notify(format!("Could not quarantine: {e}")),
            },
            Intent::Allow(r) => {
                if let Some(h) = r.sha256.clone() {
                    self.update_config(|c| {
                        if !c.is_allowed(&h) {
                            c.allowlist.push(h)
                        }
                    });
                    store::append_event(&Event { time: store::now(), source: Source::Manual, action: Action::Allowed, report: r.clone() });
                    self.notify(format!("{} marked as safe", r.name));
                }
            }
            Intent::ShowInFolder(p) => winapi::show_in_explorer(&p),
            Intent::AskDefender(p) => {
                let map = self.defender.clone();
                map.lock().unwrap().insert(p.clone(), DefenderState::Running);
                std::thread::spawn(move || {
                    let res = winapi::defender_scan(&p);
                    map.lock().unwrap().insert(p, DefenderState::Done(res));
                });
            }
            Intent::Restore(e) => match store::restore(&e) {
                Ok(target) => {
                    // Restoring implies trust; otherwise the service would quarantine it again.
                    if let Some(h) = e.sha256.clone() {
                        self.update_config(|c| {
                            if !c.is_allowed(&h) {
                                c.allowlist.push(h)
                            }
                        });
                    }
                    self.notify(format!("Restored to {}", target.display()));
                }
                Err(err) => self.notify(format!("Restore failed: {err}")),
            },
            Intent::Delete(e) => match store::delete(&e) {
                Ok(()) => self.notify(format!("{} deleted permanently", e.name)),
                Err(err) => self.notify(format!("Delete failed: {err}")),
            },
        }
        self.exists_cache.clear();
        self.poll(true);
    }

    // ------------------------------------------------------------------ layout

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let r = theme::shield_size(ui, 28.0);
            paint_shield(ui, r.center(), 26.0, ACCENT, true);
            ui.add_space(2.0);
            ui.label(RichText::new("Vigil").size(20.0).family(semibold()));
        });
        ui.add_space(26.0);

        let threats = self.events.iter().filter(|e| e.report.verdict != Verdict::Clean && store::now() - e.time < 86400).count();
        let items = [
            (Page::Overview, "Overview", None),
            (Page::Scan, "Scan", None),
            (Page::Activity, "Activity", Some(threats)),
            (Page::Quarantine, "Quarantine", None),
            (Page::Settings, "Settings", None),
        ];
        for (page, label, badge) in items {
            if nav_item(ui, label, self.page == page, badge) {
                self.page = page;
            }
            ui.add_space(2.0);
        }

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(6.0);
            let (color, text) = self.protection_state();
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 4.0, color);
                ui.label(RichText::new(text).color(DIM).size(12.5));
            });
        });
    }

    fn protection_state(&self) -> (Color32, &'static str) {
        match (self.running, self.config.paused) {
            (false, _) => (DANGER, "Protection off"),
            (true, true) => (WARN, "Paused"),
            (true, false) => (ACCENT, "Protected"),
        }
    }

    fn overview(&mut self, ui: &mut Ui, intents: &mut Vec<Intent>) {
        let (color, _) = self.protection_state();
        let watched = if self.running && !self.status.watched.is_empty() {
            self.status.watched.clone()
        } else {
            crate::daemon::desired_watches(&self.config)
        };

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let r = theme::shield_size(ui, 76.0);
                paint_shield(ui, r.center(), 72.0, color, self.running && !self.config.paused);
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.add_space(6.0);
                    let (headline, sub) = match (self.running, self.config.paused) {
                        (false, _) => ("Background protection is off", "Start Vigil to keep watching your downloads and Steam games.".to_string()),
                        (true, true) => ("Protection is paused", "New files are not being checked right now.".to_string()),
                        (true, false) => (
                            "You're protected",
                            format!("Watching {} location{} in the background. Microsoft Defender remains your primary antivirus.", watched.len(), if watched.len() == 1 { "" } else { "s" }),
                        ),
                    };
                    ui.label(RichText::new(headline).size(24.0).family(semibold()));
                    ui.label(RichText::new(sub).color(DIM));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if !self.running {
                            if primary_button(ui, "Start protection").clicked() {
                                winapi::spawn_self(&["--background"]);
                                self.notify("Starting background protection...");
                            }
                        } else if self.config.paused {
                            if primary_button(ui, "Resume").clicked() {
                                self.update_config(|c| c.paused = false);
                            }
                        } else if button(ui, "Pause").clicked() {
                            self.update_config(|c| c.paused = true);
                        }
                        if button(ui, "Scan Downloads").clicked() {
                            if let Some(d) = dirs::download_dir() {
                                self.start_scan(vec![d], true);
                            }
                        }
                    });
                    if self.running && self.status.queued > 0 {
                        ui.label(RichText::new(format!("Checking {} new item(s)...", self.status.queued)).color(DIM).size(12.0));
                    }
                });
            });
        });
        ui.add_space(12.0);

        let stats = [
            (self.status.scanned.to_string(), "Files checked"),
            (self.status.threats.to_string(), "Detections"),
            (self.quarantine.len().to_string(), "In quarantine"),
        ];
        ui.columns(3, |cols| {
            for (col, (value, label)) in cols.iter_mut().zip(stats) {
                card().show(col, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(value).size(28.0).family(semibold()));
                    ui.label(RichText::new(label).color(DIM));
                });
            }
        });
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "Watched locations");
            ui.add_space(4.0);
            if watched.is_empty() {
                ui.label(RichText::new("Nothing is being watched. Enable folders in Settings.").color(DIM));
            }
            for w in &watched {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(vec2(130.0, 20.0), Layout::left_to_right(Align::Center), |ui| {
                        ui.label(RichText::new(w.source.label()).family(semibold()));
                    });
                    ui.add(egui::Label::new(RichText::new(w.path.display().to_string()).color(DIM)).truncate());
                });
            }
        });
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                section_label(ui, "Recent activity");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.link(RichText::new("View all").color(ACCENT).size(12.5)).clicked() {
                        self.page = Page::Activity;
                    }
                });
            });
            ui.add_space(4.0);
            if self.events.is_empty() {
                ui.label(RichText::new("Nothing yet. New downloads and Steam installs will show up here.").color(DIM));
            }
            for e in self.events.iter().take(6) {
                ui.horizontal(|ui| {
                    ui.add_sized([96.0, 22.0], |ui: &mut Ui| chip(ui, e.report.verdict.label(), verdict_color(e.report.verdict)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(ago(e.time)).color(FAINT).size(12.5));
                        ui.label(RichText::new(action_label(e.action)).color(DIM).size(12.5));
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            ui.add(egui::Label::new(RichText::new(&e.report.name).family(semibold())).truncate());
                        });
                    });
                });
            }
        });
        let _ = intents;
    }

    fn scan_page(&mut self, ui: &mut Ui, intents: &mut Vec<Intent>) {
        theme::title(ui, "Scan", "Check files on demand. Drop files or folders anywhere on this window.");

        ui.horizontal(|ui| {
            let busy = self.scan.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                if primary_button(ui, "Scan a file...").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        self.start_scan(files, true);
                    }
                }
                if button(ui, "Scan a folder...").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        self.start_scan(vec![dir], true);
                    }
                }
                if button(ui, "Downloads").clicked() {
                    if let Some(d) = dirs::download_dir() {
                        self.start_scan(vec![d], true);
                    }
                }
                let steam_dirs: Vec<PathBuf> = self.steam.games.iter().chain(&self.steam.workshop).cloned().collect();
                if !steam_dirs.is_empty() && button(ui, "Steam games").on_hover_text("Checks executables and scripts in all Steam libraries").clicked() {
                    self.start_scan(steam_dirs, false);
                }
            });
        });
        ui.add_space(12.0);

        if let Some(job) = &self.scan {
            let (files, current, found) = {
                let g = job.progress.lock().unwrap();
                (g.files, g.current.clone(), g.results.iter().filter(|r| r.verdict != Verdict::Clean).count())
            };
            let cancel = job.cancel.clone();
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(18.0).color(ACCENT));
                    ui.label(RichText::new(format!("Scanning... {files} files, {found} flagged")).family(semibold()));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(ui, "Cancel").clicked() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                    });
                });
                ui.add(egui::Label::new(RichText::new(current).color(FAINT).size(12.0)).truncate());
            });
            return;
        }

        if let Some((files, took)) = self.last_scan {
            let flagged: Vec<&Report> = self.results.iter().filter(|r| r.verdict != Verdict::Clean).collect();
            let clean = self.results.len() - flagged.len();
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                let (c, msg) = if flagged.is_empty() {
                    (ACCENT, "No threats found".to_string())
                } else {
                    (WARN, format!("{} file{} need{} your attention", flagged.len(), if flagged.len() == 1 { "" } else { "s" }, if flagged.len() == 1 { "s" } else { "" }))
                };
                ui.horizontal(|ui| {
                    let r = theme::shield_size(ui, 34.0);
                    paint_shield(ui, r.center(), 32.0, c, flagged.is_empty());
                    ui.vertical(|ui| {
                        ui.label(RichText::new(msg).size(18.0).family(semibold()));
                        ui.label(
                            RichText::new(format!(
                                "{files} files looked at, {} analyzed, in {:.1}s",
                                self.results.len(),
                                took.as_secs_f32()
                            ))
                            .color(DIM),
                        );
                    });
                });
            });
            ui.add_space(10.0);
            let results = self.results.clone();
            for r in results.iter().filter(|r| r.verdict != Verdict::Clean) {
                self.report_card(ui, r, None, intents);
            }
            if clean > 0 {
                ui.add_space(4.0);
                let label = if self.show_clean { format!("Hide {clean} clean files") } else { format!("Show {clean} clean files") };
                if ui.link(RichText::new(label).color(DIM)).clicked() {
                    self.show_clean = !self.show_clean;
                }
                if self.show_clean {
                    for r in results.iter().filter(|r| r.verdict == Verdict::Clean) {
                        self.report_card(ui, r, None, intents);
                    }
                }
            }
        } else {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(160.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("Drop files here").size(18.0).family(semibold()).color(DIM));
                    ui.label(RichText::new("Executables, scripts, shortcuts, installers and ZIP archives are analyzed.").color(FAINT));
                });
            });
        }
    }

    fn activity_page(&mut self, ui: &mut Ui, intents: &mut Vec<Intent>) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| theme::title(ui, "Activity", "Everything Vigil checked in the background."));
            ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                if button(ui, "Clear history").clicked() {
                    let _ = std::fs::write(config::events_path(), b"");
                    self.poll(true);
                }
                ui.selectable_value(&mut self.threats_only, true, "Detections");
                ui.selectable_value(&mut self.threats_only, false, "All");
            });
        });
        let events: Vec<Event> = self
            .events
            .iter()
            .filter(|e| !self.threats_only || e.report.verdict != Verdict::Clean)
            .cloned()
            .collect();
        if events.is_empty() {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("No activity yet.").color(DIM));
            });
        }
        for e in &events {
            self.report_card(ui, &e.report, Some(e), intents);
        }
    }

    fn quarantine_page(&mut self, ui: &mut Ui, intents: &mut Vec<Intent>) {
        theme::title(ui, "Quarantine", "Isolated files are encoded so they can't run. Restore only what you trust.");
        if self.quarantine.is_empty() {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Quarantine is empty.").color(DIM));
            });
        }
        for q in self.quarantine.clone() {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    chip(ui, q.verdict.label(), verdict_color(q.verdict));
                    ui.label(RichText::new(&q.name).family(semibold()));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(datetime(q.time)).color(FAINT).size(12.5));
                    });
                });
                if !q.reason.is_empty() {
                    ui.label(RichText::new(&q.reason).color(DIM));
                }
                ui.add(egui::Label::new(RichText::new(q.original_path.display().to_string()).color(FAINT).size(12.0)).truncate());
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if button(ui, "Restore").on_hover_text("Puts the file back and marks it as safe").clicked() {
                        intents.push(Intent::Restore(q.clone()));
                    }
                    if self.confirm_delete.as_deref() == Some(q.id.as_str()) {
                        if danger_button(ui, "Confirm delete").clicked() {
                            intents.push(Intent::Delete(q.clone()));
                            self.confirm_delete = None;
                        }
                        if button(ui, "Cancel").clicked() {
                            self.confirm_delete = None;
                        }
                    } else if danger_button(ui, "Delete").clicked() {
                        self.confirm_delete = Some(q.id.clone());
                    }
                });
            });
            ui.add_space(8.0);
        }
    }

    fn settings_page(&mut self, ui: &mut Ui) {
        theme::title(ui, "Settings", "");

        let mut c = self.config.clone();
        let mut changed = false;
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "Protection");
            ui.add_space(6.0);
            changed |= toggle_row(ui, "Watch Downloads", "Scan new downloads as soon as your browser finishes saving them.", &mut c.watch_downloads);
            ui.separator();
            let libs = self.steam.games.len();
            let steam_desc = if libs == 0 {
                "No Steam installation found.".to_string()
            } else {
                format!("Scan game installs and Workshop items in {libs} Steam librar{}.", if libs == 1 { "y" } else { "ies" })
            };
            changed |= toggle_row(ui, "Watch Steam libraries", &steam_desc, &mut c.watch_steam);
            ui.separator();
            changed |= toggle_row(ui, "Scan programs when they start", "Check every program and script you run, and scripts as soon as they are saved in your folders.", &mut c.watch_launches);
            ui.separator();
            changed |= toggle_row(
                ui,
                "Quarantine threats automatically",
                "Malicious files are moved to quarantine immediately. Malicious programs that are running are stopped first.",
                &mut c.auto_quarantine,
            );
            ui.separator();
            changed |= toggle_row(ui, "Notifications", "Show a notification when something is found.", &mut c.notifications);
            ui.separator();
            changed |= toggle_row(ui, "Notify about suspicious files", "Files that look unusual but are not clearly malicious.", &mut c.notify_suspicious);
        });
        if changed {
            self.update_config(|cfg| {
                cfg.watch_downloads = c.watch_downloads;
                cfg.watch_steam = c.watch_steam;
                cfg.watch_launches = c.watch_launches;
                cfg.auto_quarantine = c.auto_quarantine;
                cfg.notifications = c.notifications;
                cfg.notify_suspicious = c.notify_suspicious;
            });
        }
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "Additional folders");
            ui.add_space(6.0);
            let mut remove = None;
            for (i, f) in self.config.extra_folders.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(ui, "Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            ui.add(egui::Label::new(f.display().to_string()).truncate());
                        });
                    });
                });
            }
            if let Some(i) = remove {
                self.update_config(|c| {
                    c.extra_folders.remove(i);
                });
            }
            if self.config.extra_folders.is_empty() {
                ui.label(RichText::new("For example a mod-manager or game-launcher folder.").color(DIM));
            }
            if button(ui, "Add folder...").clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.update_config(|c| {
                        if !c.extra_folders.contains(&dir) {
                            c.extra_folders.push(dir)
                        }
                    });
                }
            }
        });
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "Known-malware hashes (optional)");
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Download abuse.ch MalwareBazaar's list of known-malware hashes and check every file against it offline. \
                     It refreshes twice a day; nothing about your files leaves your PC.",
                )
                .color(DIM),
            );
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.key_edit).password(true).hint_text("MalwareBazaar Auth-Key").desired_width(320.0));
                if button(ui, "Save").clicked() {
                    let k = self.key_edit.trim().to_string();
                    let first = self.config.malwarebazaar_key.is_empty() && !k.is_empty();
                    if self.update_config(|c| c.malwarebazaar_key = k) {
                        self.notify("API key saved");
                    }
                    if first && self.hashdb.hashes == 0 {
                        self.update_hashdb();
                    }
                }
                if ui.link(RichText::new("Get a free key").color(ACCENT)).clicked() {
                    winapi::open_url("https://auth.abuse.ch/");
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let status = if self.hashdb_update.is_some() {
                    "Downloading the hash database... the first download can take a few minutes.".to_string()
                } else if self.hashdb.hashes > 0 {
                    format!("{} known-malware hashes, updated {}", self.hashdb.hashes, ago(self.hashdb.recent_sync.max(self.hashdb.full_sync)))
                } else {
                    "No hash database downloaded yet.".to_string()
                };
                ui.label(RichText::new(status).color(DIM).size(12.5));
                if let Some(e) = &self.hashdb.error {
                    ui.label(RichText::new(format!("Last update: {e}")).color(FAINT).size(12.5));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let ready = self.hashdb_update.is_none() && !self.config.malwarebazaar_key.is_empty();
                    if ui.add_enabled_ui(ready, |ui| button(ui, "Update now")).inner.clicked() {
                        self.update_hashdb();
                    }
                });
            });
        });
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "YARA rules");
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Community rules (the YARA Forge core package) that recognize malware families by code patterns, \
                     which often survive obfuscation. Matching runs on your PC; only the rule package is downloaded from GitHub.",
                )
                .color(DIM),
            );
            let mut updates = self.config.yara_updates;
            if toggle_row(ui, "Download rule updates", "Fetch the latest package once a week.", &mut updates) {
                let first = updates && self.yara.rules == 0;
                self.update_config(|c| c.yara_updates = updates);
                if first {
                    self.update_yara();
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let status = if self.yara_update.is_some() {
                    "Downloading and compiling the YARA rules...".to_string()
                } else if self.yara.rules > 0 {
                    format!("{} rules, updated {}", self.yara.rules, ago(self.yara.synced))
                } else {
                    "No YARA rules downloaded yet.".to_string()
                };
                ui.label(RichText::new(status).color(DIM).size(12.5));
                if let Some(e) = &self.yara.error {
                    ui.label(RichText::new(format!("Last update: {e}")).color(FAINT).size(12.5));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add_enabled_ui(self.yara_update.is_none(), |ui| button(ui, "Update now")).inner.clicked() {
                        self.update_yara();
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let mut own = format!("Your own rules: {} from .yar files in the yara folder.", self.yara_custom);
                if let Some(first) = self.yara_errors.first() {
                    own += &format!(" {} file(s) have errors, e.g. {first}", self.yara_errors.len());
                }
                ui.label(RichText::new(own).color(DIM).size(12.5));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(ui, "Reload").on_hover_text("Recompile your own rules to check them").clicked() {
                        self.reload_custom_yara();
                    }
                    if button(ui, "Open folder").clicked() {
                        winapi::open_folder(&config::yara_dir());
                    }
                });
            });
        });
        ui.add_space(12.0);

        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_label(ui, "System");
            ui.add_space(6.0);
            let mut auto = self.autostart;
            if toggle_row(ui, "Start with Windows", "Run quietly in the notification area after you sign in.", &mut auto) {
                if winapi::set_autostart(auto) {
                    self.autostart = auto;
                } else {
                    self.notify("Could not change the startup setting");
                }
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(format!("{} detection rules loaded", self.rule_count)).family(semibold()));
                    let mut detail = format!("{} file(s) on your allow-list.", self.config.allowlist.len());
                    if !self.rule_errors.is_empty() {
                        detail += &format!(" custom.rules has {} error(s).", self.rule_errors.len());
                    }
                    ui.label(RichText::new(detail).color(DIM).size(12.5));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(ui, "Clear allow-list").clicked() {
                        self.update_config(|c| c.allowlist.clear());
                    }
                    if button(ui, "Custom rules").on_hover_text("Opens custom.rules in Notepad").clicked() {
                        let p = config::custom_rules_path();
                        if !p.exists() {
                            let _ = std::fs::write(&p, CUSTOM_RULES_TEMPLATE);
                        }
                        let _ = std::process::Command::new("notepad.exe").arg(p).spawn();
                    }
                    if button(ui, "Data folder").clicked() {
                        winapi::open_folder(&config::data_dir());
                    }
                });
            });
        });
        ui.add_space(12.0);
        ui.label(
            RichText::new(format!(
                "Vigil {} is a supplement to Microsoft Defender. Keep Defender's real-time protection turned on.",
                env!("CARGO_PKG_VERSION")
            ))
            .color(FAINT)
            .size(12.0),
        );
    }

    /// One expandable result card, shared by the Scan and Activity pages.
    fn report_card(&mut self, ui: &mut Ui, r: &Report, event: Option<&Event>, intents: &mut Vec<Intent>) {
        let key = format!("{}|{}", r.path.display(), event.map(|e| e.time).unwrap_or(0));
        let open = self.expanded.contains(&key);
        // A command line's path is the Windows program that ran it: nothing to quarantine or inspect.
        let exists = r.command.is_none() && self.file_exists(&r.path);
        let defender = self.defender.lock().unwrap().get(&r.path).cloned();

        card().inner_margin(egui::Margin::symmetric(16, 12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add_sized([96.0, 22.0], |ui: &mut Ui| chip(ui, r.verdict.label(), verdict_color(r.verdict)));
                // Right-hand labels go first so the name truncates into the space they leave.
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.link(RichText::new(if open { "Hide" } else { "Details" }).color(DIM).size(12.5)).clicked() {
                        if open {
                            self.expanded.remove(&key);
                        } else {
                            self.expanded.insert(key.clone());
                        }
                    }
                    if let Some(e) = event {
                        ui.label(RichText::new(ago(e.time)).color(FAINT).size(12.5));
                        if e.action != Action::None {
                            ui.label(RichText::new(action_label(e.action)).color(action_color(e.action)).size(12.5));
                        }
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.add(egui::Label::new(RichText::new(&r.name).family(semibold())).truncate());
                    });
                });
            });
            let mut meta = vec![r.kind.label().to_string(), human_size(r.size)];
            if let Some(e) = event {
                meta.insert(0, e.source.label().to_string());
            }
            if let Some(s) = &r.signer {
                meta.push(format!("signed by {s}"));
            }
            ui.add(egui::Label::new(RichText::new(meta.join("  ·  ")).color(FAINT).size(12.0)).truncate());

            if !open {
                return;
            }
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(r.path.display().to_string()).color(DIM).size(12.5)).wrap());
            if let Some(c) = &r.command {
                ui.add(egui::Label::new(RichText::new(c).monospace().color(DIM).size(12.0)).wrap().selectable(true));
            }
            if let Some(o) = &r.origin {
                ui.label(RichText::new(format!("Downloaded from {o}")).color(DIM).size(12.5));
            }
            ui.add_space(4.0);
            if r.findings.is_empty() {
                ui.label(RichText::new("Nothing unusual found.").color(DIM));
            }
            for f in &r.findings {
                ui.horizontal(|ui| {
                    let (txt, c) = match f.weight {
                        w if w > 0 => (format!("+{w}"), if w >= 40 { DANGER } else { WARN }),
                        w if w < 0 => (format!("{w}"), ACCENT),
                        _ => ("info".to_string(), FAINT),
                    };
                    ui.add_sized([40.0, 18.0], egui::Label::new(RichText::new(txt).color(c).size(12.5).family(semibold())));
                    ui.add(egui::Label::new(RichText::new(&f.title).size(13.0)).wrap());
                });
            }
            ui.label(RichText::new(format!("Score {}  ·  suspicious at 35, malicious at 70", r.score)).color(FAINT).size(12.0));
            if let Some(h) = &r.sha256 {
                ui.add(egui::Label::new(RichText::new(format!("SHA-256 {h}")).monospace().color(FAINT).size(11.5)).selectable(true));
            }

            match &defender {
                Some(DefenderState::Running) => {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(14.0));
                        ui.label(RichText::new("Asking Microsoft Defender...").color(DIM));
                    });
                }
                Some(DefenderState::Done(DefenderResult::Clean)) => {
                    ui.label(RichText::new("Microsoft Defender: no threats found").color(ACCENT));
                }
                Some(DefenderState::Done(DefenderResult::Threat(t))) => {
                    ui.label(RichText::new(format!("Microsoft Defender: {t}")).color(DANGER));
                }
                Some(DefenderState::Done(DefenderResult::Error(e))) => {
                    ui.label(RichText::new(format!("Microsoft Defender check failed: {e}")).color(WARN));
                }
                None => {}
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if exists {
                    if r.verdict != Verdict::Clean && danger_button(ui, "Quarantine").clicked() {
                        intents.push(Intent::Quarantine(r.clone()));
                    }
                    if button(ui, "Show in folder").clicked() {
                        intents.push(Intent::ShowInFolder(r.path.clone()));
                    }
                    if !matches!(defender, Some(DefenderState::Running)) && button(ui, "Ask Defender").clicked() {
                        intents.push(Intent::AskDefender(r.path.clone()));
                    }
                }
                let allowed = r.sha256.as_deref().is_some_and(|h| self.config.is_allowed(h));
                if r.verdict != Verdict::Clean && r.sha256.is_some() && !allowed && button(ui, "Mark as safe").clicked() {
                    intents.push(Intent::Allow(r.clone()));
                }
            });
        });
        ui.add_space(8.0);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.title_bar_styled {
            self.title_bar_styled = true;
            style_title_bar();
        }
        self.poll(false);
        self.poll_scan();

        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if !dropped.is_empty() {
            self.start_scan(dropped, true);
        }

        let mut intents = Vec::new();
        egui::Panel::left("nav")
            .exact_size(210.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(SIDEBAR).inner_margin(egui::Margin::same(16)))
            .show(ui, |ui| self.sidebar(ui));

        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(32, 26))).show(ui, |ui| {
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(980.0));
                match self.page {
                    Page::Overview => self.overview(ui, &mut intents),
                    Page::Scan => self.scan_page(ui, &mut intents),
                    Page::Activity => self.activity_page(ui, &mut intents),
                    Page::Quarantine => self.quarantine_page(ui, &mut intents),
                    Page::Settings => self.settings_page(ui),
                }
            });
        });

        if let Some((msg, at)) = &self.toast {
            if at.elapsed() > Duration::from_secs(4) {
                self.toast = None;
            } else {
                let msg = msg.clone();
                egui::Area::new(egui::Id::unique("vigil-toast")).anchor(egui::Align2::CENTER_BOTTOM, vec2(0.0, -24.0)).show(&ctx, |ui| {
                    egui::Frame::new()
                        .fill(CARD_HOVER)
                        .stroke(egui::Stroke::new(1.0, BORDER))
                        .corner_radius(egui::CornerRadius::same(10))
                        .inner_margin(egui::Margin::symmetric(16, 10))
                        .show(ui, |ui| ui.label(msg));
                });
            }
        }

        for i in intents {
            self.apply(i);
        }

        let busy = self.scan.is_some() || self.defender.lock().unwrap().values().any(|d| matches!(d, DefenderState::Running));
        ctx.request_repaint_after(if busy { Duration::from_millis(150) } else { Duration::from_secs(1) });
    }
}

const CUSTOM_RULES_TEMPLATE: &str = "# Vigil custom rules - same format as the built-in rules.\n\
# Saved changes are picked up by the background service within a few seconds.\n\
#\n\
# rule my.example\n\
#   desc   Mentions my-evil-domain.example\n\
#   weight 40\n\
#   min    1\n\
#   scope  any\n\
#   str    my-evil-domain.example\n\
# end\n";

fn action_label(a: Action) -> &'static str {
    match a {
        Action::None => "",
        Action::Quarantined => "Quarantined",
        Action::QuarantineFailed => "Quarantine failed",
        Action::Restored => "Restored",
        Action::Deleted => "Deleted",
        Action::Allowed => "Marked safe",
        Action::Stopped => "Stopped",
        Action::StopFailed => "Could not stop",
    }
}

fn action_color(a: Action) -> Color32 {
    match a {
        Action::QuarantineFailed | Action::StopFailed => DANGER,
        Action::Quarantined | Action::Stopped => WARN,
        _ => DIM,
    }
}

fn ago(ts: i64) -> String {
    let d = store::now() - ts;
    match d {
        d if d < 60 => "just now".into(),
        d if d < 3600 => format!("{} min ago", d / 60),
        d if d < 86400 => format!("{} h ago", d / 3600),
        d if d < 7 * 86400 => format!("{} d ago", d / 86400),
        _ => datetime(ts),
    }
}

fn datetime(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn human_size(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.0} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}
