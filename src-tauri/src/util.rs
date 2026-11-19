//! Data directory, JSON persistence, settings and log helpers.
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const APP: &str = "NetMonitor";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// %APPDATA%\NetMonitor (shared with the old Python build: names, seen MACs and window placement carry over).
pub static DATA: LazyLock<PathBuf> = LazyLock::new(|| {
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    let p = base.join(APP);
    let _ = fs::create_dir_all(&p);
    p
});

pub fn path(name: &str) -> PathBuf {
    DATA.join(name)
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// SID of the interactive user when running elevated on their behalf as another account.
pub static USER_SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// String SID of the account that owns process `pid` (0 = this process).
fn process_sid(pid: u32) -> Option<String> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(p: *mut c_void, access: u32, tok: *mut *mut c_void) -> i32;
        fn GetTokenInformation(t: *mut c_void, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    }
    unsafe {
        let proc_ = if pid == 0 { GetCurrentProcess() } else { OpenProcess(0x1000, 0, pid) }; // QUERY_LIMITED_INFORMATION
        if proc_.is_null() {
            return None;
        }
        let mut tok = std::ptr::null_mut();
        let ok = OpenProcessToken(proc_, 0x0008, &mut tok) != 0; // TOKEN_QUERY
        if pid != 0 {
            CloseHandle(proc_);
        }
        if !ok {
            return None;
        }
        let mut buf = vec![0u64; 64];
        let mut len = 0u32;
        let got = GetTokenInformation(tok, 1, buf.as_mut_ptr() as *mut c_void, 512, &mut len) != 0; // TokenUser
        CloseHandle(tok);
        if !got {
            return None;
        }
        let sid = *(buf.as_ptr() as *const *mut c_void); // TOKEN_USER.User.Sid
        let mut s: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut s) == 0 {
            return None;
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as *mut c_void);
        Some(out)
    }
}

/// When elevated as another account (a standard user approving UAC with admin-k), returns the SID and
/// profile folder of the user who owns the desktop (explorer.exe), so NetMonitor keeps using *their*
/// data, WebView2 folder and router password. None when we already are that user.
pub fn desktop_user() -> Option<(String, String)> {
    #[link(name = "user32")]
    extern "system" {
        fn GetShellWindow() -> isize;
        fn GetWindowThreadProcessId(h: isize, pid: *mut u32) -> u32;
    }
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(GetShellWindow(), &mut pid) };
    if pid == 0 {
        return None;
    }
    let theirs = process_sid(pid)?;
    if Some(&theirs) == process_sid(0).as_ref() {
        return None;
    }
    let profile = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{theirs}"))
        .and_then(|k| k.get_value::<String, _>("ProfileImagePath"))
        .ok()?;
    Some((theirs, profile))
}

pub fn log(msg: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path("netmonitor.log")) {
        let secs = now_ms() / 1000;
        let _ = writeln!(f, "[{secs}] {msg}");
    }
}

pub fn load_json(name: &str, default: Value) -> Value {
    fs::read_to_string(path(name))
        .ok()
        .and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok())
        .unwrap_or(default)
}

pub fn save_json(name: &str, v: &Value) {
    let tmp = path(&format!("{name}.tmp"));
    if let Ok(s) = serde_json::to_string_pretty(v) {
        if fs::write(&tmp, s).is_ok() {
            let _ = fs::rename(&tmp, path(name));
        }
    }
}

// ------------------------------------------------------------------ known device names
const KNOWN_SEED: &str = include_str!("../known_seed.json");

pub fn init_known() {
    if !path("known.json").exists() {
        if let Ok(v) = serde_json::from_str::<Value>(KNOWN_SEED.trim_start_matches('\u{feff}')) {
            save_json("known.json", &v);
        }
    }
}

/// MAC (upper case, dashes) -> label
pub fn known() -> Map<String, Value> {
    let mut out = Map::new();
    if let Value::Object(m) = load_json("known.json", json!({})) {
        for (k, v) in m {
            out.insert(k.to_uppercase(), v);
        }
    }
    out
}

pub fn set_known(mac: &str, label: &str) {
    let mac = mac.to_uppercase();
    let mut m = match load_json("known.json", json!({})) {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    m.retain(|k, _| k.to_uppercase() != mac);
    let label = label.trim();
    if !label.is_empty() {
        m.insert(mac, Value::String(label.to_string()));
    }
    save_json("known.json", &Value::Object(m));
}

// ------------------------------------------------------------------ settings.json
pub fn settings() -> Map<String, Value> {
    match load_json("settings.json", json!({})) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

pub fn setting_bool(key: &str, default: bool) -> bool {
    settings().get(key).and_then(Value::as_bool).unwrap_or(default)
}

pub fn update_settings(f: impl FnOnce(&mut Map<String, Value>)) {
    let mut s = settings();
    f(&mut s);
    save_json("settings.json", &Value::Object(s));
}

#[repr(C)]
#[derive(Default)]
struct SystemTime16 {
    year: u16,
    month: u16,
    dow: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    ms: u16,
}
#[link(name = "kernel32")]
extern "system" {
    fn GetLocalTime(st: *mut SystemTime16);
}

/// (year, month, day, hour, minute) in local time.
pub fn local_time() -> (u16, u16, u16, u16, u16) {
    let mut st = SystemTime16::default();
    unsafe { GetLocalTime(&mut st) };
    (st.year, st.month, st.day, st.hour, st.minute)
}

/// Hidden-console command runner (gh, powershell) returning stdout.
pub fn run_hidden(exe: &str, args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new(exe)
        .args(args)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("{exe}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().chars().take(300).collect())
    }
}

pub fn fmt_rate(bytes_per_s: f64) -> String {
    let b = bytes_per_s * 8.0;
    if b >= 1e9 {
        format!("{:.2} Gb/s", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} Mb/s", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} kb/s", b / 1e3)
    } else {
        format!("{:.0} b/s", b)
    }
}
