//! Offline IP -> country with the DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com),
//! downloaded once a month to %APPDATA%\NetMonitor\geo.
use crate::util::{local_time, log, path};
use flate2::read::GzDecoder;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::{LazyLock, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

struct Db {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
    month: String,
}

static DB: LazyLock<RwLock<Option<Db>>> = LazyLock::new(|| RwLock::new(None));
static STATUS: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("cargando".into()));

fn file() -> std::path::PathBuf {
    path("geo").join("dbip-country-lite.csv.gz")
}

fn load() -> Result<Db, String> {
    let f = std::fs::File::open(file()).map_err(|e| e.to_string())?;
    let mut v4 = Vec::with_capacity(400_000);
    let mut v6 = Vec::with_capacity(200_000);
    for line in BufReader::new(GzDecoder::new(f)).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let mut it = line.split(',');
        let (Some(a), Some(b), Some(cc)) = (it.next(), it.next(), it.next()) else { continue };
        let cc = cc.trim().as_bytes();
        if cc.len() != 2 {
            continue;
        }
        let code = [cc[0], cc[1]];
        match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
            (Ok(IpAddr::V4(s)), Ok(IpAddr::V4(e))) => v4.push((u32::from(s), u32::from(e), code)),
            (Ok(IpAddr::V6(s)), Ok(IpAddr::V6(e))) => v6.push((u128::from(s), u128::from(e), code)),
            _ => {}
        }
    }
    v4.sort_by_key(|r| r.0);
    v6.sort_by_key(|r| r.0);
    let month = std::fs::read_to_string(path("geo").join("month.txt")).unwrap_or_default().trim().to_string();
    Ok(Db { v4, v6, month })
}

fn download() -> Result<String, String> {
    let (y, m, _, _, _) = local_time();
    let agent = ureq::Agent::new_with_config(ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(120))).build());
    let _ = std::fs::create_dir_all(path("geo"));
    // the current month's file appears on the 1st; fall back to the previous month
    let prev = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    for (yy, mm) in [(y, m), prev] {
        let tag = format!("{yy}-{mm:02}");
        let url = format!("https://download.db-ip.com/free/dbip-country-lite-{tag}.csv.gz");
        if let Ok(mut r) = agent.get(&url).call() {
            let bytes = r.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec().map_err(|e| e.to_string())?;
            if bytes.len() > 1_000_000 {
                let tmp = path("geo").join("dl.tmp");
                std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, file()).map_err(|e| e.to_string())?;
                let _ = std::fs::write(path("geo").join("month.txt"), &tag);
                return Ok(tag);
            }
        }
    }
    Err("no se pudo descargar la base de datos de DB-IP".into())
}

fn age_days() -> Option<u64> {
    let m = std::fs::metadata(file()).ok()?.modified().ok()?;
    Some(SystemTime::now().duration_since(m).ok()?.as_secs() / 86400)
}

pub fn worker() {
    loop {
        let need = age_days().map(|d| d > 32).unwrap_or(true);
        if need {
            *STATUS.write().unwrap() = "descargando".into();
            match download() {
                Ok(t) => log(&format!("geo: downloaded {t}")),
                Err(e) => {
                    log(&format!("geo: {e}"));
                    *STATUS.write().unwrap() = e;
                }
            }
        }
        if need || DB.read().unwrap().is_none() {
            match load() {
                Ok(db) => {
                    *STATUS.write().unwrap() = format!("lista ({} rangos)", db.v4.len() + db.v6.len());
                    *DB.write().unwrap() = Some(db);
                }
                Err(e) => {
                    if age_days().is_some() {
                        *STATUS.write().unwrap() = format!("error: {e}");
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(6 * 3600));
    }
}

pub fn country(ip: &IpAddr) -> Option<String> {
    let g = DB.read().unwrap();
    let db = g.as_ref()?;
    let cc = match ip {
        IpAddr::V4(a) => {
            let x = u32::from(*a);
            let i = db.v4.partition_point(|r| r.0 <= x);
            db.v4.get(i.checked_sub(1)?).filter(|r| x <= r.1).map(|r| r.2)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                drop(g);
                return country(&IpAddr::V4(v4));
            }
            let x = u128::from(*a);
            let i = db.v6.partition_point(|r| r.0 <= x);
            db.v6.get(i.checked_sub(1)?).filter(|r| x <= r.1).map(|r| r.2)
        }
    }?;
    Some(String::from_utf8_lossy(&cc).into_owned())
}

pub fn status() -> Value {
    let month = DB.read().unwrap().as_ref().map(|d| d.month.clone()).unwrap_or_default();
    json!({"status": *STATUS.read().unwrap(), "month": month})
}
