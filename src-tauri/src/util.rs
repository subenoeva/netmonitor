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
