//! Automatic device identification: manufacturer from the MAC prefix (embedded IEEE list) and names the
//! devices announce themselves: mDNS (reverse PTR, unicast), NetBIOS node status and SSDP/UPnP descriptions.
use crate::util::log;
use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static OUI_GZ: &[u8] = include_bytes!("../data/oui.tsv.gz");

static OUI: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let mut s = String::new();
    let _ = GzDecoder::new(OUI_GZ).read_to_string(&mut s);
    s.lines().filter_map(|l| l.split_once('\t')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
});

/// Manufacturer for a MAC ("AA-BB-CC-DD-EE-FF"). Tries 36-, 28- and 24-bit IEEE blocks.
pub fn vendor(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    let second = u8::from_str_radix(&hex[1..2], 16).ok()?;
    if second & 0x2 != 0 {
        return None; // locally administered (random/private MAC): no manufacturer
    }
    for n in [9usize, 7, 6] {
        if let Some(v) = OUI.get(&hex[..n]) {
            return Some(tidy_vendor(v));
        }
    }
    None
}

fn tidy_vendor(v: &str) -> String {
    let mut s = v.to_string();
    for suf in [", Inc.", " Inc.", " Co.,Ltd", " Co., Ltd.", " CO.,LTD", " Co.,Ltd.", " Corporation", " Technologies", " Technology", " Ltd.", " Limited", " GmbH", " S.A.", " LLC", " Corp."] {
        if let Some(i) = s.find(suf) {
            s.truncate(i);
        }
    }
    s.trim().trim_end_matches(',').to_string()
}

#[derive(Clone, Default, Serialize)]
pub struct Found {
    pub mdns: String,
    pub netbios: String,
    pub upnp: String,
    #[serde(rename = "upnpVendor")]
    pub upnp_vendor: String,
    pub model: String,
}

impl Found {
    pub fn best(&self) -> String {
        [&self.upnp, &self.mdns, &self.netbios].iter().find(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_default()
    }
}

pub static FOUND: LazyLock<Mutex<HashMap<String, Found>>> = LazyLock::new(|| Mutex::new(HashMap::new())); // by IP

pub fn found(ip: &str) -> Option<Found> {
    FOUND.lock().unwrap().get(ip).cloned()
}

// ------------------------------------------------------------------ DNS wire helpers (mDNS)
fn qname(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

fn read_name(buf: &[u8], mut i: usize, depth: u8) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut end = None;
    loop {
        let l = *buf.get(i)? as usize;
        if l == 0 {
            i += 1;
            break;
        }
        if l & 0xC0 == 0xC0 {
            let ptr = ((l & 0x3F) << 8) | *buf.get(i + 1)? as usize;
            if end.is_none() {
                end = Some(i + 2);
            }
            if depth > 8 {
                return None;
            }
            let (rest, _) = read_name(buf, ptr, depth + 1)?;
            if !rest.is_empty() {
                parts.push(rest);
            }
            return Some((parts.join("."), end.unwrap()));
        }
        parts.push(String::from_utf8_lossy(buf.get(i + 1..i + 1 + l)?).into_owned());
        i += 1 + l;
    }
    Some((parts.join("."), end.unwrap_or(i)))
}

/// First PTR answer target in a DNS response.
fn parse_ptr(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        let (_, n) = read_name(buf, i, 0)?;
        i = n + 4;
    }
    for _ in 0..an {
        let (_, n) = read_name(buf, i, 0)?;
        let typ = u16::from_be_bytes([*buf.get(n)?, *buf.get(n + 1)?]);
        let rdlen = u16::from_be_bytes([*buf.get(n + 8)?, *buf.get(n + 9)?]) as usize;
        let rd = n + 10;
        if typ == 12 {
            return read_name(buf, rd, 0).map(|(s, _)| s);
        }
        i = rd + rdlen;
    }
    None
}

fn clean_local(name: &str) -> String {
    let n = name.trim_end_matches('.').trim_end_matches(".local");
    n.replace("\\032", " ").trim().to_string()
}

fn mdns_probe(ips: &[Ipv4Addr]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return out };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    for (n, ip) in ips.iter().enumerate() {
        let o = ip.octets();
        let rev = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
        let mut q = vec![(n >> 8) as u8, n as u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend(qname(&rev));
        q.extend_from_slice(&[0, 12, 0x80, 1]); // PTR, class IN with "unicast response" bit
        let _ = sock.send_to(&q, SocketAddr::from((*ip, 5353)));
    }
    let t = Instant::now();
    let mut buf = [0u8; 1500];
    while t.elapsed() < Duration::from_millis(1800) {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(name) = parse_ptr(&buf[..n]) {
                let c = clean_local(&name);
                if !c.is_empty() {
                    out.insert(from.ip().to_string(), c);
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ NetBIOS node status
fn netbios_probe(ips: &[Ipv4Addr]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return out };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let mut q = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        q.push(b'A' + (b >> 4));
        q.push(b'A' + (b & 0x0F));
    }
    q.extend_from_slice(&[0, 0, 0x21, 0, 1]); // NBSTAT, IN
    for ip in ips {
        let _ = sock.send_to(&q, SocketAddr::from((*ip, 137)));
    }
    let t = Instant::now();
    let mut buf = [0u8; 1500];
    while t.elapsed() < Duration::from_millis(1500) {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let b = &buf[..n];
            if b.len() > 57 {
                let count = b[56] as usize;
                for k in 0..count {
                    let o = 57 + k * 18;
                    if o + 18 > b.len() {
                        break;
                    }
                    let suffix = b[o + 15];
                    let group = b[o + 16] & 0x80 != 0;
                    if suffix == 0 && !group {
                        let s = String::from_utf8_lossy(&b[o..o + 15]).trim().to_string();
                        if !s.is_empty() {
                            out.insert(from.ip().to_string(), s);
                        }
                        break;
                    }
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ SSDP / UPnP description
fn tag(xml: &str, t: &str) -> String {
    let open = format!("<{t}>");
    xml.find(&open)
        .and_then(|i| xml[i + open.len()..].find(&format!("</{t}>")).map(|j| xml[i + open.len()..i + open.len() + j].trim().to_string()))
        .unwrap_or_default()
}

fn ssdp_probe() -> HashMap<String, (String, String, String)> {
    let mut locs: HashMap<String, String> = HashMap::new();
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
        let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        let _ = sock.send_to(msg.as_bytes(), "239.255.255.250:1900");
        let t = Instant::now();
        let mut buf = [0u8; 2048];
        while t.elapsed() < Duration::from_millis(3000) {
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                let s = String::from_utf8_lossy(&buf[..n]);
                for line in s.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("location") {
                            locs.entry(from.ip().to_string()).or_insert_with(|| v.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    let agent = ureq::Agent::new_with_config(ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(3))).build());
    let mut out = HashMap::new();
    for (ip, url) in locs {
        if !url.starts_with("http://") {
            continue;
        }
        if let Ok(mut r) = agent.get(&url).call() {
            if let Ok(xml) = r.body_mut().with_config().limit(256 * 1024).read_to_string() {
                out.insert(ip, (tag(&xml, "friendlyName"), tag(&xml, "manufacturer"), tag(&xml, "modelName")));
            }
        }
    }
    out
}

/// Every 10 minutes probes the devices currently up.
pub fn worker() {
    thread::sleep(Duration::from_secs(40));
    loop {
        let ips: Vec<Ipv4Addr> = crate::lan::LAN
            .lock()
            .unwrap()
            .devs
            .values()
            .filter(|d| d.up)
            .filter_map(|d| d.ip.parse().ok())
            .collect();
        if !ips.is_empty() {
            let m = mdns_probe(&ips);
            let nb = netbios_probe(&ips);
            let up = ssdp_probe();
            let mut f = FOUND.lock().unwrap();
            for ip in &ips {
                let k = ip.to_string();
                let e = f.entry(k.clone()).or_default();
                if let Some(v) = m.get(&k) {
                    e.mdns = v.clone();
                }
                if let Some(v) = nb.get(&k) {
                    e.netbios = v.clone();
                }
                if let Some((n, v, md)) = up.get(&k) {
                    e.upnp = n.clone();
                    e.upnp_vendor = v.clone();
                    e.model = md.clone();
                }
            }
            log(&format!("discovery: mdns {} netbios {} upnp {}", m.len(), nb.len(), up.len()));
        }
        thread::sleep(Duration::from_secs(600));
    }
}
