//! Minute aggregator and rule engine: persists traffic/latency, detects outages and PPPoE reconnections,
//! unusual uploads and unknown devices at night.
use crate::util::local_time;
use crate::{alerts, history, lan, net};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Default)]
struct PingAcc {
    gw_sum: f64,
    gw_n: u32,
    net_sum: f64,
    net_n: u32,
    total: u32,
    net_fail: u32,
}

#[derive(Default)]
struct OutState {
    net_fails: u32,
    gw_fails: u32,
    open: Option<(i64, String, i64)>, // id, kind, start
    last_ppp_uptime: Option<(u64, i64)>, // (session uptime, when it was read)
}

static ACC: LazyLock<Mutex<HashMap<String, (f64, f64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static PACC: LazyLock<Mutex<PingAcc>> = LazyLock::new(|| Mutex::new(PingAcc::default()));
static OUT: LazyLock<Mutex<OutState>> = LazyLock::new(|| Mutex::new(OutState::default()));

pub fn outage_open() -> bool {
    OUT.lock().unwrap().open.is_some()
}

/// Router sample: per-device B/s over the last `dt` seconds.
pub fn add_router_sample(devs: &[(String, u64, u64)], dt: f64) {
    let dt = dt.clamp(0.5, 15.0);
    let mut a = ACC.lock().unwrap();
    for (mac, rx, tx) in devs {
        let e = a.entry(mac.clone()).or_insert((0.0, 0.0));
        e.0 += *rx as f64 * dt;
        e.1 += *tx as f64 * dt;
    }
}

fn fmt_dur(s: i64) -> String {
    if s < 90 {
        format!("{s} s")
    } else if s < 5400 {
        format!("{} min", (s + 30) / 60)
    } else {
        format!("{:.1} h", s as f64 / 3600.0)
    }
}

/// Called by the latency worker every 2 s.
pub fn on_ping(gw: Option<f64>, netv: Option<f64>) {
    {
        let mut p = PACC.lock().unwrap();
        p.total += 1;
        if let Some(v) = gw {
            p.gw_sum += v;
            p.gw_n += 1;
        }
        match netv {
            Some(v) => {
                p.net_sum += v;
                p.net_n += 1;
            }
            None => p.net_fail += 1,
        }
    }
    let mut o = OUT.lock().unwrap();
    o.gw_fails = if gw.is_none() { o.gw_fails + 1 } else { 0 };
    o.net_fails = if netv.is_none() { o.net_fails + 1 } else { 0 };
    let now = history::now_s();
    if o.open.is_none() && o.net_fails >= 3 {
        let kind = if o.gw_fails >= 3 { "router" } else { "internet" };
        let start = now - 6;
        if let Some(id) = history::outage_start(kind, start) {
            o.open = Some((id, kind.to_string(), start));
        }
        drop(o);
        let what = if kind == "router" { "No se alcanza el router" } else { "Sin conexión a internet" };
        alerts::fire("outage", what, "NetMonitor lo está registrando; avisará cuando vuelva.");
    } else if netv.is_some() {
        if let Some((id, kind, start)) = o.open.take() {
            history::outage_end(id, now);
            drop(o);
            let what = if kind == "router" { "Router accesible de nuevo" } else { "Internet ha vuelto" };
            alerts::fire("outage", what, &format!("El corte duró {}.", fmt_dur(now - start)));
        }
    }
}

/// Called by the router worker with the PPPoE session uptime: a reset means the fibre reconnected.
pub fn on_ppp_uptime(uptime: u64) {
    let mut o = OUT.lock().unwrap();
    let now = history::now_s();
    let prev = o.last_ppp_uptime.replace((uptime, now));
    if let Some((prev, at)) = prev {
        // the router's uptime counter jitters by tens of seconds; a real reconnection means the current
        // session is younger than the time elapsed since the previous reading
        if uptime + 300 < prev && (uptime as i64) < now - at + 120 {
            crate::util::log(&format!("ppp uptime reset: {prev} -> {uptime}"));
            let at = now - uptime as i64;
            if let Some(id) = history::outage_start("ppp", at) {
                history::outage_end(id, at);
            }
            drop(o);
            alerts::fire("outage", "La fibra se ha reconectado", &format!("El router renegoció la sesión PPPoE hace {}.", fmt_dur(uptime as i64)));
        }
    }
}

pub fn worker() {
    let mut last_counters: Option<(u64, u64)> = None;
    let mut p95: HashMap<String, (f64, i64)> = HashMap::new();
    let mut hot: HashMap<String, u32> = HashMap::new();
    let mut cooldown: HashMap<String, i64> = HashMap::new();
    let mut night_done: HashMap<String, (u16, u16)> = HashMap::new();
    let mut last_prune = 0i64;
    loop {
        let now = history::now_s();
        let wait = 60 - now % 60;
        thread::sleep(Duration::from_secs(wait as u64));
        let ts = history::now_s() / 60 * 60 - 60; // the minute that just finished

        let mut rows: Vec<(String, u64, u64)> = Vec::new();
        let (rx, tx) = {
            let r = net::RATE.lock().unwrap();
            (r.rx, r.tx)
        };
        if let Some((lrx, ltx)) = last_counters {
            if rx >= lrx && tx >= ltx && rx > 0 {
                rows.push((history::PC.to_string(), rx - lrx, tx - ltx));
            }
        }
        if rx > 0 {
            last_counters = Some((rx, tx));
        }
        let router_min: Vec<(String, u64, u64)> = ACC.lock().unwrap().drain().map(|(m, (a, b))| (m, a as u64, b as u64)).collect();
        rows.extend(router_min.iter().cloned());
        history::record_traffic(ts, &rows);

        let p = std::mem::take(&mut *PACC.lock().unwrap());
        if p.total > 0 {
            history::record_latency(
                ts,
                (p.gw_n > 0).then(|| p.gw_sum / p.gw_n as f64),
                (p.net_n > 0).then(|| p.net_sum / p.net_n as f64),
                p.net_fail as f64 / p.total as f64,
            );
        }

        // ---- unusual upload (router devices)
        let cfg = alerts::cfg();
        let min_bps = cfg.get("uploadMbps").and_then(Value::as_f64).unwrap_or(2.0) * 1e6 / 8.0;
        for (mac, _, txb) in &router_min {
            let rate = *txb as f64 / 60.0;
            let base = match p95.get(mac) {
                Some((v, at)) if ts - at < 3600 => *v,
                _ => {
                    let v = history::upload_p95(mac, 7).unwrap_or(0.0) / 60.0;
                    p95.insert(mac.clone(), (v, ts));
                    v
                }
            };
            let thr = min_bps.max(base * 4.0);
            let c = hot.entry(mac.clone()).or_insert(0);
            *c = if rate > thr { *c + 1 } else { 0 };
            if *c >= 2 && ts - cooldown.get(mac).copied().unwrap_or(0) > 1800 {
                cooldown.insert(mac.clone(), ts);
                alerts::fire(
                    "upload",
                    &format!("Subida inusual: {}", lan::display_name(mac)),
                    &format!(
                        "{} sostenidos durante {} min (lo habitual en este dispositivo: {}).",
                        crate::util::fmt_rate(rate), c, crate::util::fmt_rate(base)
                    ),
                );
            }
        }

        // ---- unknown devices at night
        let (_, month, day, hour, _) = local_time();
        let ns = cfg.get("nightStart").and_then(Value::as_u64).unwrap_or(0) as u16;
        let ne = cfg.get("nightEnd").and_then(Value::as_u64).unwrap_or(7) as u16;
        let in_night = if ns <= ne { hour >= ns && hour < ne } else { hour >= ns || hour < ne };
        if in_night {
            for d in lan::unknown_up() {
                if night_done.get(&d.0) != Some(&(month, day)) {
                    night_done.insert(d.0.clone(), (month, day));
                    alerts::fire("nightUnknown", "Dispositivo sin identificar conectado de madrugada", &format!("{} ({}) · {}", d.1, d.2, d.0));
                }
            }
        }

        if ts - last_prune > 86400 {
            last_prune = ts;
            history::prune();
        }
    }
}
