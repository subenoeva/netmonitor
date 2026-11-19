//! Persistent history in SQLite (%APPDATA%\NetMonitor\history.db): traffic per minute and device,
//! latency per minute, internet outages, speed tests and fired alerts.
use crate::util::{log, now_ms, path};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};

pub const PC: &str = "PC"; // pseudo-MAC for this computer's NIC totals (IPv4 + IPv6)
const KEEP_DAYS: i64 = 120;

static DB: LazyLock<Mutex<Option<Connection>>> = LazyLock::new(|| Mutex::new(None));

pub fn init() {
    match Connection::open(path("history.db")) {
        Ok(c) => {
            let r = c.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS traffic(ts INTEGER NOT NULL, mac TEXT NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY(ts, mac));
                 CREATE TABLE IF NOT EXISTS latency(ts INTEGER PRIMARY KEY, gw REAL, net REAL, loss REAL);
                 CREATE TABLE IF NOT EXISTS outages(id INTEGER PRIMARY KEY AUTOINCREMENT, start INTEGER NOT NULL, end INTEGER, kind TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS speedtests(ts INTEGER PRIMARY KEY, down REAL, up REAL, ping REAL, jitter REAL, server TEXT);
                 CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT, title TEXT, body TEXT);
                 CREATE INDEX IF NOT EXISTS traffic_mac ON traffic(mac, ts);",
            );
            if let Err(e) = r {
                log(&format!("history init: {e}"));
            }
            // an outage left open by a crash/shutdown is closed at its start (unknown duration)
            let _ = c.execute("UPDATE outages SET end = start WHERE end IS NULL", []);
            *DB.lock().unwrap() = Some(c);
        }
        Err(e) => log(&format!("history open: {e}")),
    }
}

fn with<T>(f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Option<T> {
    let g = DB.lock().unwrap();
    let c = g.as_ref()?;
    match f(c) {
        Ok(v) => Some(v),
        Err(e) => {
            log(&format!("history: {e}"));
            None
        }
    }
}

pub fn now_s() -> i64 {
    (now_ms() / 1000) as i64
}

pub fn record_traffic(ts: i64, rows: &[(String, u64, u64)]) {
    with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut st = tx.prepare_cached("INSERT OR REPLACE INTO traffic(ts, mac, rx, tx) VALUES (?1, ?2, ?3, ?4)")?;
            for (mac, rx, txb) in rows {
                if *rx > 0 || *txb > 0 {
                    st.execute(params![ts, mac, *rx as i64, *txb as i64])?;
                }
            }
        }
        tx.commit()
    });
}

pub fn record_latency(ts: i64, gw: Option<f64>, net: Option<f64>, loss: f64) {
    with(|c| c.execute("INSERT OR REPLACE INTO latency(ts, gw, net, loss) VALUES (?1, ?2, ?3, ?4)", params![ts, gw, net, loss]));
}

pub fn outage_start(kind: &str, ts: i64) -> Option<i64> {
    with(|c| {
        c.execute("INSERT INTO outages(start, kind) VALUES (?1, ?2)", params![ts, kind])?;
        Ok(c.last_insert_rowid())
    })
}

pub fn outage_end(id: i64, ts: i64) {
    with(|c| c.execute("UPDATE outages SET end = ?1 WHERE id = ?2", params![ts, id]));
}

pub fn add_speed(ts: i64, down: f64, up: f64, ping: f64, jitter: f64, server: &str) {
    with(|c| c.execute("INSERT OR REPLACE INTO speedtests VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![ts, down, up, ping, jitter, server]));
}

pub fn last_speed_ts() -> i64 {
    with(|c| c.query_row("SELECT COALESCE(MAX(ts), 0) FROM speedtests", [], |r| r.get(0))).unwrap_or(0)
}

pub fn add_alert(kind: &str, title: &str, body: &str) {
    with(|c| c.execute("INSERT INTO alerts(ts, kind, title, body) VALUES (?1, ?2, ?3, ?4)", params![now_s(), kind, title, body]));
}

pub fn alerts(limit: i64) -> Value {
    with(|c| {
        let mut st = c.prepare("SELECT ts, kind, title, body FROM alerts ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit], |r| {
            Ok(json!({"ts": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)?, "body": r.get::<_, String>(3)?}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .map(Value::from)
    .unwrap_or(json!([]))
}

/// 95th percentile of a device's per-minute upload (bytes/min) over the last `days`.
pub fn upload_p95(mac: &str, days: i64) -> Option<f64> {
    with(|c| {
        let mut st = c.prepare("SELECT tx FROM traffic WHERE mac = ?1 AND ts >= ?2 ORDER BY tx")?;
        let v: Vec<i64> = st.query_map(params![mac, now_s() - days * 86400], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    })
    .filter(|v| v.len() >= 60)
    .map(|v| v[(v.len() as f64 * 0.95) as usize].max(0) as f64)
}

pub fn prune() {
    let cut = now_s() - KEEP_DAYS * 86400;
    with(|c| {
        c.execute("DELETE FROM traffic WHERE ts < ?1", [cut])?;
        c.execute("DELETE FROM latency WHERE ts < ?1", [cut])?;
        c.execute("DELETE FROM alerts WHERE ts < ?1", [cut - 245 * 86400])
    });
}

/// Everything the History view needs for a range: traffic buckets per device, latency, outages, speed tests.
pub fn query(range: &str, off: i64) -> Value {
    let (span, bucket): (i64, i64) = match range {
        "7d" => (7 * 86400, 3 * 3600),
        "30d" => (30 * 86400, 86400),
        "90d" => (90 * 86400, 86400),
        _ => (86400, 3600),
    };
    let now = now_s();
    // buckets aligned to local time: `off` = seconds east of UTC, sent by the UI
    let start = (now - span + off) / bucket * bucket - off;
    let nb = ((now - start) / bucket + 1) as usize;
    let buckets: Vec<i64> = (0..nb).map(|i| start + i as i64 * bucket).collect();

    let traffic = with(|c| {
        let mut st = c.prepare("SELECT ((ts + ?3) / ?1) * ?1 - ?3 AS b, mac, SUM(rx), SUM(tx) FROM traffic WHERE ts >= ?2 GROUP BY b, mac")?;
        let rows = st.query_map(params![bucket, start, off], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .unwrap_or_default();
    let mut series: BTreeMap<String, (Vec<i64>, Vec<i64>)> = BTreeMap::new();
    let mut totals: HashMap<String, (i64, i64)> = HashMap::new();
    for (b, mac, rx, tx) in traffic {
        let i = ((b - start) / bucket) as usize;
        let e = series.entry(mac.clone()).or_insert_with(|| (vec![0; nb], vec![0; nb]));
        if i < nb {
            e.0[i] += rx;
            e.1[i] += tx;
        }
        let t = totals.entry(mac).or_insert((0, 0));
        t.0 += rx;
        t.1 += tx;
    }
    let mut ser = Map::new();
    for (mac, (rx, tx)) in series {
        let (trx, ttx) = totals.get(&mac).copied().unwrap_or((0, 0));
        ser.insert(mac, json!({"rx": rx, "tx": tx, "totalRx": trx, "totalTx": ttx}));
    }

    let lat_bucket = (bucket / 12).max(300);
    let latency = with(|c| {
        let mut st = c.prepare("SELECT (ts / ?1) * ?1 AS b, AVG(gw), AVG(net), AVG(loss), MAX(net) FROM latency WHERE ts >= ?2 GROUP BY b ORDER BY b")?;
        let rows = st.query_map(params![lat_bucket, start], |r| {
            Ok(json!([r.get::<_, i64>(0)?, r.get::<_, Option<f64>>(1)?, r.get::<_, Option<f64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?]))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .unwrap_or_default();

    let outages = with(|c| {
        let mut st = c.prepare("SELECT start, end, kind FROM outages WHERE COALESCE(end, ?2) >= ?1 ORDER BY start DESC")?;
        let rows = st.query_map(params![start, now], |r| Ok(json!({"start": r.get::<_, i64>(0)?, "end": r.get::<_, Option<i64>>(1)?, "kind": r.get::<_, String>(2)?})))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .unwrap_or_default();
    let down_s: i64 = outages
        .iter()
        .filter(|o| o["kind"] != "ppp")
        .map(|o| o["end"].as_i64().unwrap_or(now).min(now) - o["start"].as_i64().unwrap_or(now).max(start))
        .filter(|d| *d > 0)
        .sum();
    // availability over the part of the range we have measurements for
    let first_lat: i64 = with(|c| c.query_row("SELECT COALESCE(MIN(ts), ?1) FROM latency", [now], |r| r.get(0))).unwrap_or(now);
    let measured = (now - start.max(first_lat)).max(1);

    let speeds = with(|c| {
        let mut st = c.prepare("SELECT ts, down, up, ping, jitter FROM speedtests WHERE ts >= ?1 ORDER BY ts")?;
        let rows = st.query_map([start], |r| {
            Ok(json!({"ts": r.get::<_, i64>(0)?, "down": r.get::<_, f64>(1)?, "up": r.get::<_, f64>(2)?, "ping": r.get::<_, f64>(3)?, "jitter": r.get::<_, f64>(4)?}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .unwrap_or_default();

    json!({
        "range": range, "bucket": bucket, "buckets": buckets, "series": ser,
        "latency": latency, "latBucket": lat_bucket,
        "outages": outages, "downSeconds": down_s, "measuredSeconds": measured,
        "uptime": 100.0 * (1.0 - down_s as f64 / measured as f64),
        "speeds": speeds,
    })
}
