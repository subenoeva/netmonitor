//! DNS visibility: domains resolved by this PC (Windows DNS client cache, polled) and, optionally,
//! per-device queries from an AdGuard Home server on the network (its REST API).
use crate::util::{log, now_ms, settings};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: *mut u16,
    typ: u16,
    len: u16,
    flags: u32,
}

#[link(name = "dnsapi")]
extern "system" {
    fn DnsGetCacheDataTable(entry: *mut *mut CacheEntry) -> i32;
    fn DnsFree(p: *mut c_void, kind: i32);
}

#[derive(Clone)]
struct Seen {
    first: u64,
    last: u64,
    polls: u32,
}

static LOCAL: LazyLock<Mutex<HashMap<String, Seen>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

const TRACKERS: &[&str] = &[
    "doubleclick", "googlesyndication", "google-analytics", "googletagmanager", "googleadservices", "adservice",
    "adsystem", "adnxs", "scorecardresearch", "facebook.net", "connect.facebook", "graph.facebook", "app-measurement",
    "crashlytics", "appsflyer", "adjust.com", "branch.io", "hotjar", "mixpanel", "segment.io", "amplitude", "criteo",
    "taboola", "outbrain", "telemetry", "vortex.data.microsoft", "settings-win.data", "metrics", "tracking", "analytics",
    "pixel", "ads.", "ad.", "advert",
];

pub fn is_tracker(d: &str) -> bool {
    let d = d.to_lowercase();
    TRACKERS.iter().any(|t| d.contains(t))
}

fn read_cache() -> Vec<(String, u16)> {
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut CacheEntry = std::ptr::null_mut();
        if DnsGetCacheDataTable(&mut head) == 0 {
            return out;
        }
        let mut p = head;
        while !p.is_null() {
            let e = &*p;
            if !e.name.is_null() {
                let mut n = 0;
                while *e.name.add(n) != 0 && n < 512 {
                    n += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(e.name, n));
                out.push((s.to_lowercase(), e.typ));
                DnsFree(e.name as *mut c_void, 0);
            }
            let next = e.next;
            DnsFree(p as *mut c_void, 0);
            p = next;
        }
    }
    out
}

pub fn worker() {
    loop {
        let now = now_ms();
        let entries = read_cache();
        {
            let mut m = LOCAL.lock().unwrap();
            for (name, _) in entries {
                if name.ends_with(".arpa") || name.ends_with(".local") || !name.contains('.') {
                    continue;
                }
                let e = m.entry(name).or_insert(Seen { first: now, last: now, polls: 0 });
                e.last = now;
                e.polls += 1;
            }
            if m.len() > 5000 {
                let mut v: Vec<_> = m.iter().map(|(k, s)| (k.clone(), s.last)).collect();
                v.sort_by_key(|x| x.1);
                for (k, _) in v.into_iter().take(1000) {
                    m.remove(&k);
                }
            }
        }
        thread::sleep(Duration::from_secs(15));
    }
}

fn local_json() -> Value {
    let m = LOCAL.lock().unwrap();
    let mut v: Vec<(&String, &Seen)> = m.iter().collect();
    v.sort_by(|a, b| b.1.last.cmp(&a.1.last));
    Value::from(
        v.into_iter()
            .take(600)
            .map(|(d, s)| json!({"d": d, "first": s.first, "last": s.last, "n": s.polls, "tracker": is_tracker(d)}))
            .collect::<Vec<_>>(),
    )
}

fn adguard() -> Option<Value> {
    let a = settings().get("adguard").cloned()?;
    let url = a["url"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return None;
    }
    let auth = format!("Basic {}", B64.encode(format!("{}:{}", a["user"].as_str().unwrap_or(""), a["pass"].as_str().unwrap_or(""))));
    let agent = ureq::Agent::new_with_config(ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(6))).build());
    let get = |p: &str| -> Result<Value, String> {
        let mut r = agent.get(&format!("{url}{p}")).header("Authorization", auth.as_str()).call().map_err(|e| e.to_string())?;
        let s = r.body_mut().with_config().limit(16 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
        serde_json::from_str(&s).map_err(|e| e.to_string())
    };
    let stats = match get("/control/stats") {
        Ok(v) => v,
        Err(e) => {
            log(&format!("adguard: {e}"));
            return Some(json!({"ok": false, "error": e}));
        }
    };
    let qlog = get("/control/querylog?limit=300").unwrap_or(json!({}));
    let log: Vec<Value> = qlog["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|q| {
                    let reason = q["reason"].as_str().unwrap_or("");
                    json!({
                        "time": q["time"], "client": q["client"], "d": q["question"]["name"],
                        "blocked": reason.starts_with("Filtered") && reason != "FilteredSafeSearch",
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(json!({
        "ok": true,
        "queries": stats["num_dns_queries"], "blocked": stats["num_blocked_filtering"],
        "avgMs": stats["avg_processing_time"],
        "topClients": stats["top_clients"], "topDomains": stats["top_queried_domains"], "topBlocked": stats["top_blocked_domains"],
        "log": log,
    }))
}

pub fn dns_json() -> Value {
    // recent Windows 11 builds only expose the DNS client cache to elevated processes
    json!({"local": local_json(), "adguard": adguard(), "elevated": crate::net::elevated()})
}
