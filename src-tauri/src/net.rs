//! Local interface, throughput counters, TCP table, process names, reverse DNS, latency, public IP.
use crate::util::{log, now_ms};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{channel, Sender};
use std::sync::{LazyLock, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ interface
#[derive(Clone, Default, Serialize)]
pub struct Ifc {
    #[serde(skip)]
    pub index: u32,
    pub name: String,
    pub ip: String,
    pub gw: String,
    pub mac: String,
    pub speed: String,
    pub desc: String,
}

pub static IFC: LazyLock<RwLock<Ifc>> = LazyLock::new(|| RwLock::new(Ifc::default()));

pub fn ifc() -> Ifc {
    IFC.read().unwrap().clone()
}

fn fmt_speed(bps: u64) -> String {
    let b = bps as f64;
    let (v, u) = if b >= 1e9 { (b / 1e9, "Gbps") } else { (b / 1e6, "Mbps") };
    let s = format!("{v:.1}");
    format!("{} {u}", s.trim_end_matches(".0"))
}

fn norm_mac(s: &str) -> String {
    s.to_uppercase().replace(':', "-")
}

pub fn detect() -> Option<netdev::Interface> {
    let i = netdev::get_default_interface().ok()?;
    let ip = i.ipv4.first().map(|n| n.addr().to_string())?;
    let gw = i
        .gateway
        .as_ref()
        .and_then(|g| g.ipv4.first().map(|a| a.to_string()))
        .unwrap_or_else(|| format!("{}.1", ip.rsplit_once('.').map(|x| x.0).unwrap_or("192.168.0")));
    let f = Ifc {
        index: i.index,
        name: i.friendly_name.clone().unwrap_or_else(|| i.name.clone()),
        ip,
        gw,
        mac: i.mac_addr.map(|m| norm_mac(&m.to_string())).unwrap_or_default(),
        speed: i.transmit_speed.map(fmt_speed).unwrap_or_default(),
        desc: i.description.clone().unwrap_or_default(),
    };
    *IFC.write().unwrap() = f;
    Some(i)
}

/// Fallback when netdev finds no default route yet (boot): ask the OS which source IP reaches the internet.
fn local_ip_guess() -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:53").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

// ------------------------------------------------------------------ throughput
pub struct RateState {
    pub t: u64,
    pub rx: u64,
    pub tx: u64,
    pub err: u64,
    pub drop: u64,
    pub rate_rx: f64,
    pub rate_tx: f64,
    pub start_rx: u64,
    pub start_tx: u64,
    pub start_t: u64,
    pub hist: VecDeque<[f64; 3]>, // t, rx B/s, tx B/s ; 1 s resolution, 15 min
}

pub static RATE: LazyLock<Mutex<RateState>> = LazyLock::new(|| {
    Mutex::new(RateState {
        t: 0, rx: 0, tx: 0, err: 0, drop: 0, rate_rx: 0.0, rate_tx: 0.0,
        start_rx: 0, start_tx: 0, start_t: now_ms(), hist: VecDeque::new(),
    })
});

/// Detects the interface (retrying while the network comes up) and samples its counters every second.
pub fn rate_worker(mut on_tick: impl FnMut(f64, f64) + Send + 'static) {
    let mut iface = loop {
        if let Some(i) = detect() {
            break i;
        }
        if let Some(ip) = local_ip_guess() {
            let mut f = IFC.write().unwrap();
            if f.ip.is_empty() {
                f.ip = ip.clone();
                f.gw = format!("{}.1", ip.rsplit_once('.').map(|x| x.0).unwrap_or("192.168.0"));
            }
        }
        thread::sleep(Duration::from_secs(3));
    };
    let mut last_detect = Instant::now();
    loop {
        if last_detect.elapsed() > Duration::from_secs(60) {
            // interface may change (cable -> Wi-Fi); keep counters continuous only on the same one
            if let Some(i) = detect() {
                if i.index != iface.index {
                    iface = i;
                    let mut r = RATE.lock().unwrap();
                    r.t = 0;
                }
            }
            last_detect = Instant::now();
        }
        if iface.update_stats().is_ok() {
            if let Some(st) = iface.stats.as_ref() {
                let t = now_ms();
                let (rx, tx) = (st.rx_bytes, st.tx_bytes);
                let mut r = RATE.lock().unwrap();
                if r.t > 0 && t > r.t {
                    let dt = (t - r.t) as f64 / 1000.0;
                    r.rate_rx = rx.saturating_sub(r.rx) as f64 / dt;
                    r.rate_tx = tx.saturating_sub(r.tx) as f64 / dt;
                    let (a, b) = (r.rate_rx, r.rate_tx);
                    r.hist.push_back([t as f64, a, b]);
                    while r.hist.len() > 900 {
                        r.hist.pop_front();
                    }
                } else {
                    r.start_rx = rx;
                    r.start_tx = tx;
                }
                r.t = t;
                r.rx = rx;
                r.tx = tx;
                let (a, b) = (r.rate_rx, r.rate_tx);
                drop(r);
                on_tick(a, b);
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }
}

pub fn rate_json() -> Value {
    let r = RATE.lock().unwrap();
    json!({
        "t": r.t, "rx": r.rate_rx, "tx": r.rate_tx,
        "sessRx": r.rx.saturating_sub(r.start_rx), "sessTx": r.tx.saturating_sub(r.start_tx),
        "since": r.start_t,
    })
}

pub fn rate_history() -> Value {
    let r = RATE.lock().unwrap();
    Value::from(r.hist.iter().map(|h| json!([h[0], h[1], h[2]])).collect::<Vec<_>>())
}

// ------------------------------------------------------------------ process names
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(h: *mut c_void, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
}

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    pid: u32,
    heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    prio: i32,
    flags: u32,
    exe: [u16; 260],
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snap: *mut c_void, e: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snap: *mut c_void, e: *mut ProcessEntry32W) -> i32;
}

/// Exe name from a process snapshot: works for protected/elevated processes that OpenProcess refuses.
fn snapshot_name(pid: u32) -> Option<String> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(2, 0); // TH32CS_SNAPPROCESS
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut e: ProcessEntry32W = std::mem::zeroed();
        e.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        let mut found = None;
        while ok != 0 {
            if e.pid == pid {
                let n = e.exe.iter().position(|&c| c == 0).unwrap_or(260);
                let s = String::from_utf16_lossy(&e.exe[..n]);
                found = Some(s.strip_suffix(".exe").map(str::to_string).unwrap_or(s));
                break;
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        found
    }
}

static PROC: LazyLock<Mutex<HashMap<u32, (String, Instant)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn proc_name(pid: u32) -> String {
    if pid == 0 || pid == 4 {
        return "System".into();
    }
    if let Some((n, at)) = PROC.lock().unwrap().get(&pid) {
        if at.elapsed() < Duration::from_secs(60) {
            return n.clone();
        }
    }
    let name = unsafe {
        let h = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if h.is_null() {
            snapshot_name(pid).unwrap_or_else(|| format!("pid {pid}"))
        } else {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            if ok != 0 {
                let full = String::from_utf16_lossy(&buf[..len as usize]);
                let file = full.rsplit('\\').next().unwrap_or(&full).to_string();
                file.strip_suffix(".exe").or(file.strip_suffix(".EXE")).unwrap_or(&file).to_string()
            } else {
                format!("pid {pid}")
            }
        }
    };
    PROC.lock().unwrap().insert(pid, (name.clone(), Instant::now()));
    name
}

// ------------------------------------------------------------------ reverse DNS
static DNS: LazyLock<Mutex<HashMap<String, Option<String>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static DNS_TX: LazyLock<Mutex<Sender<String>>> = LazyLock::new(|| {
    let (tx, rx) = channel::<String>();
    let rx = std::sync::Arc::new(Mutex::new(rx));
    for _ in 0..8 {
        let rx = rx.clone();
        thread::spawn(move || loop {
            let ip = match rx.lock().unwrap().recv() {
                Ok(ip) => ip,
                Err(_) => return,
            };
            let name = ip
                .parse::<IpAddr>()
                .ok()
                .and_then(|a| dns_lookup::lookup_addr(&a).ok())
                .filter(|n| *n != ip)
                .unwrap_or_default();
            DNS.lock().unwrap().insert(ip, Some(name));
        });
    }
    Mutex::new(tx)
});

pub fn rdns(ip: &str) -> String {
    {
        let mut c = DNS.lock().unwrap();
        match c.get(ip) {
            Some(Some(n)) => return n.clone(),
            Some(None) => return String::new(),
            None => {
                c.insert(ip.to_string(), None);
            }
        }
    }
    let _ = DNS_TX.lock().unwrap().send(ip.to_string());
    String::new()
}

// ------------------------------------------------------------------ TCP table
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(table: *mut u8, size: *mut u32, order: i32, af: u32, class: i32, reserved: u32) -> u32;
}

fn tcp_table(af: u32) -> Vec<u8> {
    let mut size = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, af, 5, 0) };
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize + 8192];
        let mut s = buf.len() as u32;
        let r = unsafe { GetExtendedTcpTable(buf.as_mut_ptr(), &mut s, 0, af, 5, 0) }; // TCP_TABLE_OWNER_PID_ALL
        if r == 0 {
            return buf;
        }
        if r != 122 {
            return Vec::new();
        }
        size = s;
    }
    Vec::new()
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn port(b: &[u8], o: usize) -> u16 {
    ((b[o] as u16) << 8) | b[o + 1] as u16
}

pub struct Conn {
    pub state: u32,
    pub laddr: IpAddr,
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
    pub pid: u32,
}

pub fn tcp_conns() -> Vec<Conn> {
    let mut out = Vec::new();
    let b = tcp_table(2);
    if b.len() >= 4 {
        let n = u32le(&b, 0) as usize;
        for i in 0..n {
            let o = 4 + i * 24;
            if o + 24 > b.len() {
                break;
            }
            out.push(Conn {
                state: u32le(&b, o),
                laddr: IpAddr::V4(Ipv4Addr::new(b[o + 4], b[o + 5], b[o + 6], b[o + 7])),
                lport: port(&b, o + 8),
                raddr: IpAddr::V4(Ipv4Addr::new(b[o + 12], b[o + 13], b[o + 14], b[o + 15])),
                rport: port(&b, o + 16),
                pid: u32le(&b, o + 20),
            });
        }
    }
    let b = tcp_table(23);
    if b.len() >= 4 {
        let n = u32le(&b, 0) as usize;
        for i in 0..n {
            let o = 4 + i * 56;
            if o + 56 > b.len() {
                break;
            }
            let mut la = [0u8; 16];
            la.copy_from_slice(&b[o..o + 16]);
            let mut ra = [0u8; 16];
            ra.copy_from_slice(&b[o + 24..o + 40]);
            let v6 = |a: [u8; 16]| {
                let x = Ipv6Addr::from(a);
                x.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(x))
            };
            out.push(Conn {
                laddr: v6(la),
                lport: port(&b, o + 20),
                raddr: v6(ra),
                rport: port(&b, o + 44),
                state: u32le(&b, o + 48),
                pid: u32le(&b, o + 52),
            });
        }
    }
    out
}

pub fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            (s & 0xffc0) == 0xfe80 || (s & 0xfe00) == 0xfc00
        }
    }
}

pub fn conns_json() -> Value {
    let me = std::process::id();
    let mut conns = Vec::new();
    let mut listen: std::collections::BTreeMap<u16, String> = Default::default();
    for c in tcp_conns() {
        if c.pid == me {
            continue;
        }
        if c.state == 2 && !c.laddr.is_loopback() {
            listen.entry(c.lport).or_insert_with(|| proc_name(c.pid));
        } else if c.state == 5 && !c.raddr.is_loopback() {
            let ip = c.raddr.to_string();
            let lan = is_lan(&c.raddr);
            conns.push(json!({
                "p": proc_name(c.pid), "lp": c.lport, "ra": ip, "rp": c.rport,
                "h": rdns(&ip), "lan": lan, "v6": c.raddr.is_ipv6(),
                "cc": if lan { None } else { crate::geo::country(&c.raddr) },
            }));
        }
    }
    json!({
        "conns": conns,
        "listen": listen.into_iter().map(|(p, n)| json!({"port": p, "p": n})).collect::<Vec<_>>(),
    })
}

// ------------------------------------------------------------------ latency
pub static PING: LazyLock<Mutex<(VecDeque<Option<f64>>, VecDeque<Option<f64>>)>> =
    LazyLock::new(|| Mutex::new((VecDeque::new(), VecDeque::new())));

fn tcp_rtt(addr: &str) -> Option<f64> {
    let sa: SocketAddr = addr.parse().ok()?;
    let t = Instant::now();
    TcpStream::connect_timeout(&sa, Duration::from_millis(1500)).ok()?;
    Some((t.elapsed().as_secs_f64() * 10000.0).round() / 10.0)
}

pub fn ping_worker() {
    loop {
        let gw = ifc().gw;
        let a = if gw.is_empty() { None } else { tcp_rtt(&format!("{gw}:80")) };
        let b = tcp_rtt("1.1.1.1:443");
        crate::monitor::on_ping(a, b);
        {
            let mut p = PING.lock().unwrap();
            p.0.push_back(a);
            p.1.push_back(b);
            while p.0.len() > 90 {
                p.0.pop_front();
            }
            while p.1.len() > 90 {
                p.1.pop_front();
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

pub fn ping_json() -> Value {
    let p = PING.lock().unwrap();
    json!({"gw": p.0.iter().collect::<Vec<_>>(), "net": p.1.iter().collect::<Vec<_>>()})
}

// ------------------------------------------------------------------ public IP
pub static PUBLIC_IP: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

pub fn public_ip_worker() {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(8))).build(),
    );
    loop {
        match agent.get("https://api.ipify.org").call() {
            Ok(mut r) => {
                if let Ok(s) = r.body_mut().read_to_string() {
                    let s = s.trim().to_string();
                    if !s.is_empty() && s.len() < 64 {
                        *PUBLIC_IP.lock().unwrap() = Some(s);
                    }
                }
                thread::sleep(Duration::from_secs(600));
            }
            Err(e) => {
                log(&format!("public ip: {e}"));
                thread::sleep(Duration::from_secs(30));
            }
        }
    }
}

// ------------------------------------------------------------------ per-process traffic (TCP EStats)
// Windows only lets an elevated process switch on per-connection byte counters, so this works when
// NetMonitor runs as administrator; otherwise the UI shows connection counts only.
#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}
#[link(name = "iphlpapi")]
extern "system" {
    fn SetPerTcpConnectionEStats(row: *const u8, kind: i32, rw: *const u8, ver: u32, size: u32, off: u32) -> u32;
    fn GetPerTcpConnectionEStats(row: *const u8, kind: i32, rw: *mut u8, rwv: u32, rws: u32, ros: *mut u8, rosv: u32, ross: u32, rod: *mut u8, rodv: u32, rods: u32) -> u32;
    fn SetPerTcp6ConnectionEStats(row: *const u8, kind: i32, rw: *const u8, ver: u32, size: u32, off: u32) -> u32;
    fn GetPerTcp6ConnectionEStats(row: *const u8, kind: i32, rw: *mut u8, rwv: u32, rws: u32, ros: *mut u8, rosv: u32, ross: u32, rod: *mut u8, rodv: u32, rods: u32) -> u32;
}

pub fn elevated() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn be_port(p: u16) -> [u8; 4] {
    [(p >> 8) as u8, p as u8, 0, 0]
}

/// MIB_TCPROW / MIB_TCP6ROW bytes for a connection.
fn row_bytes(c: &Conn) -> (bool, Vec<u8>) {
    match (c.laddr, c.raddr) {
        (IpAddr::V4(l), IpAddr::V4(r)) => {
            let mut v = Vec::with_capacity(20);
            v.extend_from_slice(&c.state.to_le_bytes());
            v.extend_from_slice(&l.octets());
            v.extend_from_slice(&be_port(c.lport));
            v.extend_from_slice(&r.octets());
            v.extend_from_slice(&be_port(c.rport));
            (false, v)
        }
        (l, r) => {
            let six = |a: IpAddr| match a {
                IpAddr::V6(x) => x.octets(),
                IpAddr::V4(x) => x.to_ipv6_mapped().octets(),
            };
            let mut v = Vec::with_capacity(52);
            v.extend_from_slice(&c.state.to_le_bytes());
            v.extend_from_slice(&six(l));
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&be_port(c.lport));
            v.extend_from_slice(&six(r));
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&be_port(c.rport));
            (true, v)
        }
    }
}

pub static PROC_RATES: LazyLock<Mutex<Vec<(String, f64, f64)>>> = LazyLock::new(|| Mutex::new(Vec::new()));

pub fn estats_worker() {
    if !elevated() {
        return;
    }
    let mut enabled: std::collections::HashSet<String> = Default::default();
    let mut prev: HashMap<String, (u64, u64)> = HashMap::new();
    let mut last = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(2));
        let dt = last.elapsed().as_secs_f64();
        last = Instant::now();
        let me = std::process::id();
        let mut cur: HashMap<String, (u64, u64)> = HashMap::new();
        let mut per: HashMap<String, (f64, f64)> = HashMap::new();
        for c in tcp_conns() {
            if c.state != 5 || c.pid == me || c.raddr.is_loopback() {
                continue;
            }
            let key = format!("{}:{}-{}:{}", c.laddr, c.lport, c.raddr, c.rport);
            let (v6, row) = row_bytes(&c);
            unsafe {
                if !enabled.contains(&key) {
                    let on = [1u8];
                    let r = if v6 {
                        SetPerTcp6ConnectionEStats(row.as_ptr(), 1, on.as_ptr(), 0, 1, 0)
                    } else {
                        SetPerTcpConnectionEStats(row.as_ptr(), 1, on.as_ptr(), 0, 1, 0)
                    };
                    if r == 0 {
                        enabled.insert(key.clone());
                    }
                    continue;
                }
                let mut rod = [0u8; 128];
                let r = if v6 {
                    GetPerTcp6ConnectionEStats(row.as_ptr(), 1, std::ptr::null_mut(), 0, 0, std::ptr::null_mut(), 0, 0, rod.as_mut_ptr(), 0, 96)
                } else {
                    GetPerTcpConnectionEStats(row.as_ptr(), 1, std::ptr::null_mut(), 0, 0, std::ptr::null_mut(), 0, 0, rod.as_mut_ptr(), 0, 96)
                };
                if r != 0 {
                    continue;
                }
                let out = u64::from_le_bytes(rod[0..8].try_into().unwrap());
                let inb = u64::from_le_bytes(rod[16..24].try_into().unwrap());
                if let Some((pi, po)) = prev.get(&key) {
                    let e = per.entry(proc_name(c.pid)).or_insert((0.0, 0.0));
                    e.0 += inb.saturating_sub(*pi) as f64 / dt;
                    e.1 += out.saturating_sub(*po) as f64 / dt;
                }
                cur.insert(key, (inb, out));
            }
        }
        enabled.retain(|k| cur.contains_key(k) || prev.contains_key(k));
        prev = cur;
        let mut v: Vec<(String, f64, f64)> = per.into_iter().map(|(k, (a, b))| (k, a, b)).collect();
        v.sort_by(|a, b| (b.1 + b.2).partial_cmp(&(a.1 + a.2)).unwrap());
        *PROC_RATES.lock().unwrap() = v;
    }
}

pub fn procs_json() -> Value {
    let v = PROC_RATES.lock().unwrap();
    json!({
        "elevated": elevated(),
        "rates": v.iter().map(|(p, rx, tx)| json!({"p": p, "rx": rx, "tx": tx})).collect::<Vec<_>>(),
    })
}
