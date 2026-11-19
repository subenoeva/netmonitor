//! Speed test against speed.cloudflare.com: latency (8 small requests), then download and upload with
//! 4 parallel streams for a fixed time each. Results are stored in history; optional schedule.
use crate::util::{log, settings};
use crate::{alerts, history};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BASE: &str = "https://speed.cloudflare.com";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetMonitor";
const STREAMS: usize = 4;
const PHASE: Duration = Duration::from_secs(7);

static RUNNING: AtomicBool = AtomicBool::new(false);
pub static STATE: LazyLock<Mutex<Value>> = LazyLock::new(|| Mutex::new(json!({"running": false})));

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent(UA)
            .build(),
    )
}

fn set(v: Value) {
    *STATE.lock().unwrap() = v;
}

pub fn state() -> Value {
    let mut v = STATE.lock().unwrap().clone();
    v["last"] = json!(history::last_speed_ts());
    v
}

pub fn start() -> bool {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return false;
    }
    thread::spawn(|| {
        let r = run();
        match &r {
            Ok(v) => {
                set(json!({"running": false, "phase": "done", "result": v}));
                check_contract(v);
            }
            Err(e) => {
                log(&format!("speedtest: {e}"));
                set(json!({"running": false, "phase": "error", "error": e}));
            }
        }
        RUNNING.store(false, Ordering::SeqCst);
    });
    true
}

fn check_contract(v: &Value) {
    let s = settings().get("speed").cloned().unwrap_or(json!({}));
    let want_d = s["contractDown"].as_f64().unwrap_or(0.0);
    let want_u = s["contractUp"].as_f64().unwrap_or(0.0);
    let (d, u) = (v["down"].as_f64().unwrap_or(0.0), v["up"].as_f64().unwrap_or(0.0));
    if (want_d > 0.0 && d < want_d * 0.5) || (want_u > 0.0 && u < want_u * 0.5) {
        alerts::fire(
            "speed",
            "Velocidad por debajo de lo contratado",
            &format!("Medido ↓ {d:.0} / ↑ {u:.0} Mb/s; contratado ↓ {want_d:.0} / ↑ {want_u:.0} Mb/s."),
        );
    }
}

fn run() -> Result<Value, String> {
    let ag = agent();
    set(json!({"running": true, "phase": "ping"}));
    let mut rtts = Vec::new();
    for _ in 0..8 {
        let t = Instant::now();
        let mut r = ag.get(&format!("{BASE}/__down?bytes=0")).call().map_err(|e| format!("ping: {e}"))?;
        let _ = r.body_mut().read_to_vec();
        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    rtts.remove(0); // first one includes TLS handshake
    let mut sorted = rtts.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let ping = sorted[sorted.len() / 2];
    let jitter = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (rtts.len() - 1) as f64;

    let down = transfer(true)?;
    let up = transfer(false)?;
    let res = json!({"down": down, "up": up, "ping": ping, "jitter": jitter, "ts": history::now_s()});
    history::add_speed(history::now_s(), down, up, ping, jitter, "cloudflare");
    Ok(res)
}

/// Runs STREAMS workers for PHASE; ignores the first second (TCP slow start). Returns Mb/s.
fn transfer(download: bool) -> Result<f64, String> {
    let phase = if download { "down" } else { "up" };
    let bytes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for _ in 0..STREAMS {
        let (bytes, stop, errors) = (bytes.clone(), stop.clone(), errors.clone());
        hs.push(thread::spawn(move || {
            let ag = agent();
            let payload = vec![0x5Au8; 4 * 1024 * 1024];
            let mut buf = vec![0u8; 64 * 1024];
            while !stop.load(Ordering::Relaxed) {
                if download {
                    match ag.get(&format!("{BASE}/__down?bytes=50000000")).call() {
                        Ok(mut r) => {
                            let mut rd = r.body_mut().with_config().limit(u64::MAX).reader();
                            loop {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                match rd.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        bytes.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(e) => {
                            errors.lock().unwrap().push(e.to_string());
                            thread::sleep(Duration::from_millis(300));
                        }
                    }
                } else {
                    match ag.post(&format!("{BASE}/__up")).header("Content-Type", "application/octet-stream").send(&payload[..]) {
                        Ok(_) => {
                            bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            errors.lock().unwrap().push(e.to_string());
                            thread::sleep(Duration::from_millis(300));
                        }
                    }
                }
            }
        }));
    }
    let mut base = (0u64, Instant::now());
    let mut warmed = false;
    while t0.elapsed() < PHASE + Duration::from_secs(1) {
        thread::sleep(Duration::from_millis(250));
        let b = bytes.load(Ordering::Relaxed);
        if !warmed && t0.elapsed() >= Duration::from_secs(1) {
            base = (b, Instant::now());
            warmed = true;
        }
        if warmed {
            let secs = base.1.elapsed().as_secs_f64().max(0.25);
            let mbps = (b - base.0) as f64 * 8.0 / secs / 1e6;
            set(json!({"running": true, "phase": phase, "mbps": mbps}));
        }
    }
    stop.store(true, Ordering::SeqCst);
    let total = bytes.load(Ordering::Relaxed) - base.0;
    let secs = base.1.elapsed().as_secs_f64();
    for h in hs {
        let _ = h.join();
    }
    if total == 0 {
        let e = errors.lock().unwrap().first().cloned().unwrap_or_else(|| "sin datos".into());
        return Err(format!("{phase}: {e}"));
    }
    Ok(total as f64 * 8.0 / secs / 1e6)
}

/// Runs a test every `speed.intervalHours` (0 = manual only), never during an outage.
pub fn scheduler() {
    thread::sleep(Duration::from_secs(120));
    loop {
        let h = settings().get("speed").and_then(|s| s["intervalHours"].as_f64()).unwrap_or(0.0);
        if h > 0.0 && !crate::monitor::outage_open() {
            let last = history::last_speed_ts();
            if history::now_s() - last >= (h * 3600.0) as i64 {
                start();
            }
        }
        thread::sleep(Duration::from_secs(300));
    }
}
