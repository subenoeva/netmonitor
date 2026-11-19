//! LAN discovery with ARP sweeps (SendARP) and "never seen before" device detection.
use crate::net::{ifc, rdns};
use crate::util::{known, load_json, log, now_ms, save_json};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Serialize)]
pub struct Dev {
    pub mac: String,
    pub ip: String,
    pub up: bool,
    pub last: Option<u64>,
    pub first: Option<u64>,
    pub h: String,
    pub new: bool,
}

pub struct LanState {
    pub devs: BTreeMap<String, Dev>,
    pub last_scan: u64,
    pub scanning: bool,
}

pub static LAN: LazyLock<Mutex<LanState>> =
    LazyLock::new(|| Mutex::new(LanState { devs: BTreeMap::new(), last_scan: 0, scanning: false }));

#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(dest: u32, src: u32, mac: *mut u8, len: *mut u32) -> u32;
}

fn send_arp(ip: &str) -> Option<String> {
    let a: std::net::Ipv4Addr = ip.parse().ok()?;
    let dest = u32::from_ne_bytes(a.octets());
    let mut buf = [0u8; 8];
    let mut len = 6u32;
    let r = unsafe { SendARP(dest, 0, buf.as_mut_ptr(), &mut len) };
    if r == 0 && len == 6 {
        Some(buf[..6].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-"))
    } else {
        None
    }
}

/// `notify(ip, mac, hostname)` is called for devices that were never seen on this network before.
pub fn scanner(notify: impl Fn(&str, &str, &str) + Send + 'static) {
    let seen_v = load_json("seen.json", Value::Null);
    let mut baseline = seen_v.is_null(); // first ever run: what is here now is the baseline, not "new"
    let mut seen: Map<String, Value> = match seen_v {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    loop {
        let me = ifc();
        if me.ip.is_empty() || !me.ip.contains('.') {
            thread::sleep(Duration::from_secs(3));
            continue;
        }
        LAN.lock().unwrap().scanning = true;
        let subnet = me.ip.rsplit_once('.').map(|x| x.0.to_string()).unwrap_or_default();
        let ips: Vec<String> = (1..255).map(|i| format!("{subnet}.{i}")).filter(|ip| *ip != me.ip).collect();
        let mut found: Vec<(String, Option<String>)> = thread::scope(|s| {
            let hs: Vec<_> = ips
                .chunks(2)
                .map(|c| s.spawn(move || c.iter().map(|ip| (ip.clone(), send_arp(ip))).collect::<Vec<_>>()))
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        if !me.mac.is_empty() {
            found.push((me.ip.clone(), Some(me.mac.clone())));
        }
        let t = now_ms();
        let mut changed = false;
        let mut fresh = Vec::new();
        {
            let mut lan = LAN.lock().unwrap();
            let mut alive = std::collections::HashSet::new();
            for (ip, mac) in &found {
                let Some(mac) = mac else { continue };
                alive.insert(mac.clone());
                let d = lan.devs.entry(mac.clone()).or_insert_with(|| Dev {
                    mac: mac.clone(), ip: ip.clone(), up: true, last: Some(t), first: Some(t), h: String::new(), new: false,
                });
                d.ip = ip.clone();
                d.up = true;
                d.last = Some(t);
                let h = rdns(ip);
                if !h.is_empty() {
                    d.h = h;
                }
                if !seen.contains_key(mac) {
                    seen.insert(mac.clone(), json!(t));
                    changed = true;
                    if !baseline {
                        d.new = true;
                        fresh.push((ip.clone(), mac.clone()));
                    }
                }
            }
            for (mac, d) in lan.devs.iter_mut() {
                if !alive.contains(mac) {
                    d.up = false;
                }
            }
            lan.last_scan = t;
            lan.scanning = false;
        }
        if changed || baseline {
            save_json("seen.json", &Value::Object(seen.clone()));
        }
        baseline = false;
        for (ip, mac) in fresh {
            log(&format!("new device {ip} {mac}"));
            notify(&ip, &mac, &rdns(&ip));
        }
        thread::sleep(Duration::from_secs(25));
    }
}

pub fn lan_json() -> Value {
    let me = ifc();
    let known = known();
    let rdevs = crate::router::devices();
    let names: BTreeMap<String, String> = rdevs.iter().map(|d| (d.mac.clone(), d.name.clone())).collect();
    let blocked = crate::router::ROUTER.lock().unwrap().blocked.clone();
    let lan = LAN.lock().unwrap();
    let mut devs: Vec<Dev> = lan.devs.values().cloned().collect();
    for r in &rdevs {
        // devices the router knows but ARP has not reached (sleeping phones)
        if !lan.devs.contains_key(&r.mac) {
            devs.push(Dev {
                mac: r.mac.clone(), ip: r.ip.clone(), up: r.rate_rx + r.rate_tx > 0, last: None, first: None,
                h: String::new(), new: false,
            });
        }
    }
    let oct = |ip: &str| ip.rsplit('.').next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
    devs.sort_by_key(|d| oct(&d.ip));
    let out: Vec<Value> = devs
        .into_iter()
        .map(|d| {
            let mut v = serde_json::to_value(&d).unwrap();
            let o = v.as_object_mut().unwrap();
            o.insert("label".into(), known.get(&d.mac).cloned().unwrap_or(Value::Null));
            o.insert("known".into(), json!(known.contains_key(&d.mac)));
            o.insert("rname".into(), json!(names.get(&d.mac).cloned().unwrap_or_default()));
            o.insert("randomMac".into(), json!(d.mac.chars().nth(1).map(|c| "26AE".contains(c)).unwrap_or(false)));
            o.insert("me".into(), json!(d.ip == me.ip));
            o.insert("gw".into(), json!(d.ip == me.gw));
            o.insert("vendor".into(), json!(crate::discover::vendor(&d.mac)));
            let f = crate::discover::found(&d.ip).unwrap_or_default();
            o.insert("auto".into(), json!(f.best()));
            o.insert("model".into(), json!(if f.model.is_empty() { None } else { Some(format!("{} {}", f.upnp_vendor, f.model).trim().to_string()) }));
            o.insert("blocked".into(), json!(blocked.contains(&d.mac)));
            v
        })
        .collect();
    json!({"devices": out, "lastScan": lan.last_scan, "scanning": lan.scanning})
}

fn real(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && !matches!(t.to_lowercase().as_str(), "unknown" | "desconocido" | "*" | "-")
}

/// Best human name for a MAC: user label > router hostname > self-announced name > reverse DNS > vendor > MAC.
pub fn display_name(mac: &str) -> String {
    if let Some(l) = known().get(mac).and_then(Value::as_str) {
        return l.to_string();
    }
    if let Some(r) = crate::router::devices().into_iter().find(|d| d.mac == mac).filter(|d| real(&d.name)) {
        return r.name;
    }
    let ip_h = LAN.lock().unwrap().devs.get(mac).map(|d| (d.ip.clone(), d.h.clone()));
    if let Some((ip, h)) = ip_h {
        if let Some(f) = crate::discover::found(&ip) {
            if real(&f.best()) {
                return f.best();
            }
        }
        if real(&h) {
            return h;
        }
    }
    crate::discover::vendor(mac).map(|v| format!("Dispositivo {v}")).unwrap_or_else(|| mac.to_string())
}

/// (mac, name, ip) of devices online right now that the user has not named.
pub fn unknown_up() -> Vec<(String, String, String)> {
    let k = known();
    let me = ifc();
    let lan = LAN.lock().unwrap();
    let list: Vec<(String, String)> = lan
        .devs
        .values()
        .filter(|d| d.up && !k.contains_key(&d.mac) && d.ip != me.ip && d.ip != me.gw)
        .map(|d| (d.mac.clone(), d.ip.clone()))
        .collect();
    drop(lan);
    list.into_iter().map(|(m, ip)| (m.clone(), display_name(&m), ip)).collect()
}
