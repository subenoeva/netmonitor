//! Win32 bits: window placement in physical pixels (multi-monitor / mixed DPI safe), DWM caption colours,
//! Run-key autostart.
use crate::util::{settings, update_settings};
use serde_json::json;
use std::ffi::c_void;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Point {
    x: i32,
    y: i32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Rect {
    l: i32,
    t: i32,
    r: i32,
    b: i32,
}
#[repr(C)]
#[derive(Default)]
struct WindowPlacement {
    length: u32,
    flags: u32,
    show: u32,
    pmin: Point,
    pmax: Point,
    rc: Rect,
}

#[link(name = "user32")]
extern "system" {
    fn GetWindowPlacement(h: isize, wp: *mut WindowPlacement) -> i32;
    fn SetWindowPlacement(h: isize, wp: *const WindowPlacement) -> i32;
    fn IsWindowVisible(h: isize) -> i32;
}
#[link(name = "dwmapi")]
extern "system" {
    fn DwmSetWindowAttribute(h: isize, attr: u32, v: *const c_void, n: u32) -> i32;
}

const SW_SHOWNORMAL: u32 = 1;
const SW_SHOWMINIMIZED: u32 = 2;
const SW_SHOWMAXIMIZED: u32 = 3;
const SW_SHOWMINNOACTIVE: u32 = 7;
const WPF_RESTORETOMAXIMIZED: u32 = 2;

/// Applies the saved placement and shows the window. Returns false when nothing was saved yet.
pub fn restore_placement(hwnd: isize) -> bool {
    let s = settings();
    let Some(p) = s.get("placement") else { return false };
    let rc: Vec<i32> = p["rc"].as_array().map(|a| a.iter().filter_map(|v| v.as_i64()).map(|v| v as i32).collect()).unwrap_or_default();
    if rc.len() != 4 || rc[2] - rc[0] < 200 || rc[3] - rc[1] < 200 {
        return false;
    }
    let wp = WindowPlacement {
        length: std::mem::size_of::<WindowPlacement>() as u32,
        flags: 0,
        show: if p["max"].as_bool().unwrap_or(false) { SW_SHOWMAXIMIZED } else { SW_SHOWNORMAL },
        rc: Rect { l: rc[0], t: rc[1], r: rc[2], b: rc[3] },
        ..Default::default()
    };
    // SetWindowPlacement also moves the window back on-screen if that monitor is gone.
    unsafe { SetWindowPlacement(hwnd, &wp) != 0 }
}

pub fn save_placement(hwnd: isize) {
    if unsafe { IsWindowVisible(hwnd) } == 0 {
        return;
    }
    let mut wp = WindowPlacement { length: std::mem::size_of::<WindowPlacement>() as u32, ..Default::default() };
    if unsafe { GetWindowPlacement(hwnd, &mut wp) } == 0 {
        return;
    }
    let max = match wp.show {
        SW_SHOWMAXIMIZED => true,
        SW_SHOWMINIMIZED | SW_SHOWMINNOACTIVE => wp.flags & WPF_RESTORETOMAXIMIZED != 0,
        _ => false,
    };
    let cur = json!({"rc": [wp.rc.l, wp.rc.t, wp.rc.r, wp.rc.b], "max": max});
    if settings().get("placement") != Some(&cur) {
        update_settings(|s| {
            s.remove("geometry");
            s.insert("placement".into(), cur);
        });
    }
}

/// Windows 11: caption tinted like the UI background, light text, subtle border. Ignored on older builds.
pub fn style_caption(hwnd: isize) {
    let set = |attr: u32, v: u32| unsafe {
        DwmSetWindowAttribute(hwnd, attr, &v as *const u32 as *const c_void, 4);
    };
    set(20, 1); // DWMWA_USE_IMMERSIVE_DARK_MODE
    set(35, 0x00100D0B); // DWMWA_CAPTION_COLOR  #0B0D10 (COLORREF 0x00BBGGRR)
    set(36, 0x00EFE9E6); // DWMWA_TEXT_COLOR     #E6E9EF
    set(34, 0x002B231E); // DWMWA_BORDER_COLOR   #1E232B
}

// ------------------------------------------------------------------ autostart (HKCU Run)
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

fn run_key(write: bool) -> std::io::Result<winreg::RegKey> {
    use winreg::enums::*;
    let hk = winreg::RegKey::predef(HKEY_CURRENT_USER);
    if write {
        hk.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE | KEY_QUERY_VALUE)
    } else {
        hk.open_subkey(RUN_KEY)
    }
}

pub fn autostart_enabled() -> bool {
    run_key(false).and_then(|k| k.get_value::<String, _>(crate::util::APP)).is_ok()
}

pub fn set_autostart(enable: bool, minimized: bool) {
    let Ok(k) = run_key(true) else { return };
    if enable {
        if let Ok(exe) = std::env::current_exe() {
            let cmd = format!("\"{}\"{}", exe.display(), if minimized { " --minimized" } else { "" });
            let _ = k.set_value(crate::util::APP, &cmd);
        }
    } else {
        let _ = k.delete_value(crate::util::APP);
    }
}
