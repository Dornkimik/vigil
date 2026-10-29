//! Native notification-area icon with a context menu and balloon notifications.
//! Plain Win32 keeps the background process at a few MB of RAM.

use super::{Shared, Work};
use crate::config::Config;
use crate::engine::Source;
use crate::{icon, winapi};
use std::collections::VecDeque;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const WM_VIGIL_NOTE: u32 = WM_APP + 2;
const WM_VIGIL_REFRESH: u32 = WM_APP + 3;
const ID_OPEN: usize = 1;
const ID_SCAN_DOWNLOADS: usize = 2;
const ID_PAUSE: usize = 3;
const ID_EXIT: usize = 4;
const NIN_BALLOONUSERCLICK: u32 = WM_USER + 5;

struct State {
    shared: Arc<Shared>,
    tx: Sender<Work>,
}

static STATE: OnceLock<State> = OnceLock::new();
static HWND_TRAY: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
static NOTES: Mutex<VecDeque<(String, String, bool)>> = Mutex::new(VecDeque::new());

fn hwnd() -> HWND {
    HWND_TRAY.load(Ordering::Relaxed) as HWND
}

/// Queue a balloon notification (callable from any thread).
pub fn notify(title: &str, body: &str, severe: bool) {
    NOTES.lock().unwrap().push_back((title.to_string(), body.to_string(), severe));
    unsafe { PostMessageW(hwnd(), WM_VIGIL_NOTE, 0, 0) };
}

/// Re-render icon and tooltip after a state change (callable from any thread).
pub fn refresh() {
    unsafe { PostMessageW(hwnd(), WM_VIGIL_REFRESH, 0, 0) };
}

fn copy_wstr(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn make_icon(size: i32, top: [u8; 3], bottom: [u8; 3]) -> HICON {
    let rgba = icon::shield_rgba(size as u32, top, bottom);
    let dib = icon::ico_dib(size as u32, &rgba);
    unsafe { CreateIconFromResourceEx(dib.as_ptr(), dib.len() as u32, 1, 0x0003_0000, size, size, 0) }
}

fn paused() -> bool {
    STATE.get().is_some_and(|s| s.shared.config.read().unwrap().paused)
}

fn base_data() -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd();
    nid.uID = 1;
    nid
}

fn update_icon(msg: NOTIFY_ICON_MESSAGE) {
    let mut nid = base_data();
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = WM_TRAY;
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) };
    let (top, bottom, tip) = if paused() {
        (icon::GRAY_TOP, icon::GRAY_BOTTOM, "Vigil - protection paused")
    } else {
        (icon::GREEN_TOP, icon::GREEN_BOTTOM, "Vigil - watching downloads & Steam")
    };
    nid.hIcon = make_icon(size, top, bottom);
    copy_wstr(&mut nid.szTip, tip);
    unsafe {
        Shell_NotifyIconW(msg, &nid);
        DestroyIcon(nid.hIcon);
    }
}

fn show_pending_note() {
    let notes: Vec<_> = NOTES.lock().unwrap().drain(..).collect();
    let Some(last) = notes.last() else { return };
    let severe = notes.iter().any(|n| n.2);
    let (title, body) = if notes.len() == 1 {
        (last.0.clone(), last.1.clone())
    } else {
        (format!("{} detections", notes.len()), "Open Vigil to review the details.".to_string())
    };
    let mut nid = base_data();
    nid.uFlags = NIF_INFO;
    copy_wstr(&mut nid.szInfoTitle, &title);
    copy_wstr(&mut nid.szInfo, &body);
    let size = unsafe { GetSystemMetrics(SM_CXICON) };
    let (top, bottom) = if severe { (icon::RED_TOP, icon::RED_BOTTOM) } else { (icon::GREEN_TOP, icon::GREEN_BOTTOM) };
    nid.hBalloonIcon = make_icon(size, top, bottom);
    nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
    unsafe {
        Shell_NotifyIconW(NIM_MODIFY, &nid);
        DestroyIcon(nid.hBalloonIcon);
    }
}

pub fn open_gui() {
    if !crate::gui::focus_existing_window() {
        winapi::spawn_self(&["--gui"]);
    }
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        let add = |id: usize, text: &str| {
            let w = winapi::wide(text);
            AppendMenuW(menu, MF_STRING, id, w.as_ptr());
        };
        add(ID_OPEN, "Open Vigil");
        add(ID_SCAN_DOWNLOADS, "Scan Downloads now");
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        add(ID_PAUSE, if paused() { "Resume protection" } else { "Pause protection" });
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        add(ID_EXIT, "Exit");
        SetMenuDefaultItem(menu, ID_OPEN as u32, 0);

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, null());
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }
}

fn on_command(id: usize) {
    let Some(state) = STATE.get() else { return };
    match id {
        ID_OPEN => open_gui(),
        ID_SCAN_DOWNLOADS => {
            if let Some(dl) = dirs::download_dir() {
                let _ = state.tx.send(Work::Scan(dl, Source::Downloads));
            }
        }
        ID_PAUSE => {
            let cfg = Config::update(|c| c.paused = !c.paused);
            *state.shared.config.write().unwrap() = cfg;
            update_icon(NIM_MODIFY);
        }
        ID_EXIT => unsafe {
            DestroyWindow(hwnd());
        },
        _ => {}
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            match lparam as u32 {
                WM_LBUTTONUP | NIN_BALLOONUSERCLICK => open_gui(),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            on_command(wparam & 0xFFFF);
            0
        }
        WM_VIGIL_NOTE => {
            show_pending_note();
            0
        }
        WM_VIGIL_REFRESH => {
            update_icon(NIM_MODIFY);
            0
        }
        WM_DESTROY => {
            let nid = base_data();
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &nid);
                PostQuitMessage(0);
            }
            0
        }
        // Explorer restarted: our icon is gone, add it again.
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            update_icon(NIM_ADD);
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

pub fn run(shared: Arc<Shared>, tx: Sender<Work>) {
    let _ = STATE.set(State { shared, tx });
    unsafe {
        let hinstance = GetModuleHandleW(null());
        let class = winapi::wide("VigilTrayWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
        let title = winapi::wide("VigilTray");
        let hwnd = CreateWindowExW(0, class.as_ptr(), title.as_ptr(), 0, 0, 0, 0, 0, null_mut(), null_mut(), hinstance, null());
        if hwnd.is_null() {
            return;
        }
        HWND_TRAY.store(hwnd as isize, Ordering::Relaxed);
        TASKBAR_CREATED.store(RegisterWindowMessageW(winapi::wide("TaskbarCreated").as_ptr()), Ordering::Relaxed);
        update_icon(NIM_ADD);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
