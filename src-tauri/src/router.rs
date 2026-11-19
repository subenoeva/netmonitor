//! TP-Link Archer MR600 client (cgi_gdpr protocol: AES-128-CBC body + raw-RSA signature) and the
//! traffic-monitor poller. Ported from the tplinkrouterc6u MR client, with the MR600 v3 quirks
//! (/cgi/getParm answers JSON, ret values may come as JSON).
use crate::net::ifc;
use crate::util::{known, log, now_ms};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

type Enc = cbc::Encryptor<aes::Aes128>;
type Dec = cbc::Decryptor<aes::Aes128>;
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0";
const GET: u8 = 1;
const SET: u8 = 2;
const ADD: u8 = 3;
const DEL: u8 = 4;
const GL: u8 = 5;

fn rand_digits() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(now_ms());
    format!("{}", 100_000_000 + h.finish() % 900_000_000)
}

fn quote(s: &str) -> String {
    // urllib.parse.quote(s, safe="~()*!.'")
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~()*!'".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn parse_ret(text: &str) -> Option<i64> {
    if let Some(i) = text.find("$.ret=") {
        let d: String = text[i + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
        return d.parse().ok();
    }
    let v: Value = serde_json::from_str(text.trim()).ok()?;
    match &v["ret"] {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

pub struct Client {
    host: String,
    pwd: String,
    hash: String,
    key: String,
    iv: String,
    nn: String,
    ee: String,
    seq: u64,
    token: Option<String>,
    cookies: BTreeMap<String, String>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(host: &str, pwd: &str) -> Self {
        let ts = now_ms().to_string();
        let key = format!("{ts}{}", rand_digits())[..16].to_string();
        let iv = format!("{ts}{}", rand_digits())[..16].to_string();
        let hash = Md5::digest(format!("admin{pwd}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(10)))
                .http_status_as_error(false)
                .build(),
        );
        Client {
            host: host.to_string(), pwd: pwd.to_string(), hash, key, iv, nn: String::new(), ee: String::new(),
            seq: 0, token: None, cookies: BTreeMap::new(), agent,
        }
    }

    fn request(&mut self, url: &str, get: bool, body: Option<&str>) -> Result<(u16, String), String> {
        let cookie: String = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let referer = format!("{}/", self.host);
        let mut last = (0u16, String::new());
        for _ in 0..3 {
            macro_rules! hdrs {
                ($r:expr) => {{
                    let mut r = $r.header("Accept", "*/*").header("User-Agent", UA).header("Referer", referer.as_str());
                    if let Some(t) = &self.token {
                        r = r.header("TokenID", t.as_str());
                    }
                    if !cookie.is_empty() {
                        r = r.header("Cookie", cookie.as_str());
                    }
                    r
                }};
            }
            let res = if get {
                hdrs!(self.agent.get(url)).call()
            } else {
                let r = hdrs!(self.agent.post(url));
                match body {
                    Some(b) => r.send(b),
                    None => r.send_empty(),
                }
            };
            let mut resp = res.map_err(|e| format!("HTTP: {e}"))?;
            let status = resp.status().as_u16();
            for v in resp.headers().get_all("set-cookie") {
                if let Ok(s) = v.to_str() {
                    if let Some((k, val)) = s.split(';').next().and_then(|kv| kv.split_once('=')) {
                        self.cookies.insert(k.trim().to_string(), val.trim().to_string());
                    }
                }
            }
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            let retry = status == 500 || status == 406 || text.contains("<title>500 Internal Server Error</title>")
                || text.contains("<title>406 Not Acceptable</title>");
            last = (status, text);
            if !retry {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(last)
    }

    fn aes_encrypt(&self, data: &str) -> String {
        let enc = Enc::new_from_slices(self.key.as_bytes(), self.iv.as_bytes()).unwrap();
        B64.encode(enc.encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes()))
    }

    fn aes_decrypt(&self, data: &str) -> Result<String, String> {
        let raw = B64.decode(data.trim()).map_err(|e| format!("base64: {e}"))?;
        let dec = Dec::new_from_slices(self.key.as_bytes(), self.iv.as_bytes()).unwrap();
        let out = dec.decrypt_padded_vec_mut::<Pkcs7>(&raw).map_err(|_| "AES: padding".to_string())?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Raw ("NOPADDING") RSA over blocks of the key length, zero padded, hex encoded.
    fn rsa(&self, data: &str) -> String {
        let n = BigUint::parse_bytes(self.nn.as_bytes(), 16).unwrap_or_default();
        let e = BigUint::parse_bytes(self.ee.as_bytes(), 16).unwrap_or_default();
        let blen = self.nn.len() / 2;
        let mut out = String::new();
        for chunk in data.as_bytes().chunks(blen.max(1)) {
            let mut b = chunk.to_vec();
            b.resize(blen, 0);
            let hx = format!("{:x}", BigUint::from_bytes_be(&b).modpow(&e, &n));
            out.push_str(&"0".repeat((blen * 2).saturating_sub(hx.len())));
            out.push_str(&hx);
        }
        out
    }

    fn prepare(&self, data: &str, login: bool) -> (String, String) {
        let enc = self.aes_encrypt(data);
        let s = self.seq + enc.len() as u64;
        let sign_data = if login {
            format!("key={}&iv={}&h={}&s={}", self.key, self.iv, self.hash, s)
        } else {
            format!("h={}&s={}", self.hash, s)
        };
        (self.rsa(&sign_data), enc)
    }

    pub fn authorize(&mut self) -> Result<(), String> {
        let url = format!("{}/cgi/getParm?_={}", self.host, now_ms());
        let (code, text) = self.request(&url, false, None)?;
        let v: Value = serde_json::from_str(text.trim()).map_err(|_| format!("getParm ({code}): {}", &text.chars().take(80).collect::<String>()))?;
        if code != 200 || parse_ret(&text) != Some(0) {
            return Err(format!("getParm ret={:?}", v.get("ret")));
        }
        self.nn = v["nn"].as_str().unwrap_or_default().to_string();
        self.ee = v["ee"].as_str().unwrap_or_default().to_string();
        self.seq = match &v["seq"] {
            Value::Number(n) => n.as_u64().unwrap_or(0),
            Value::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        };
        if self.nn.is_empty() || self.ee.is_empty() {
            return Err("getParm: sin clave RSA".into());
        }

        let (sign, data) = self.prepare(&format!("admin\n{}", self.pwd), true);
        let url = format!(
            "{}/cgi/login?data={}&sign={}&Action=1&LoginStatus=0&isMobile=0&_={}",
            self.host, quote(&data), sign, now_ms()
        );
        let (_, text) = self.request(&url, false, None)?;
        match parse_ret(&text) {
            Some(0) => {}
            Some(71233) => return Err("WRONG_PASSWORD".into()),
            Some(r) => return Err(format!("Login rechazado por el router (código {r})")),
            None => return Err("Login: respuesta inesperada".into()),
        }

        let url = format!("{}/?_={}", self.host, now_ms());
        let (_, text) = self.request(&url, true, None)?;
        let tok = text
            .find("var token=\"")
            .map(|i| &text[i + 11..])
            .and_then(|r| r.find('"').map(|j| r[..j].to_string()))
            .filter(|t| !t.is_empty())
            .ok_or("No se encontró el token de sesión")?;
        self.token = Some(tok);
        Ok(())
    }

    /// Several acts in one request (as the router's own web UI does). Each act returns its objects;
    /// every object carries its "__stack" (needed to SET/DEL list entries).
    pub fn acts(&mut self, list: &[Act]) -> Result<Vec<Vec<Map<String, Value>>>, String> {
        let z = "0,0,0,0,0,0";
        let types: Vec<String> = list.iter().map(|a| a.kind.to_string()).collect();
        let mut plain = format!("{}\r\n", types.join("&"));
        for (i, a) in list.iter().enumerate() {
            plain.push_str(&format!("[{}#{}#{z}]{},{}\r\n", a.oid, a.stack, i, a.attrs.len()));
            for at in &a.attrs {
                plain.push_str(at);
                plain.push_str("\r\n");
            }
        }
        let (sign, data) = self.prepare(&plain, false);
        let body = format!("sign={sign}\r\ndata={data}\r\n");
        let url = format!("{}/cgi_gdpr?_={}", self.host, now_ms());
        let (code, text) = self.request(&url, false, Some(&body))?;
        if code != 200 {
            return Err(format!("cgi_gdpr HTTP {code}"));
        }
        let text = if text.trim().is_empty() { String::new() } else { self.aes_decrypt(&text)? };
        let mut out: Vec<Vec<Map<String, Value>>> = vec![Vec::new(); list.len()];
        let mut cur: Option<(usize, usize)> = None;
        for line in text.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.starts_with('[') {
                // "[1,2,0,0,0,0]0" starts an object of act 0; "[error]0" ends the reply
                cur = None;
                if let Some(j) = line.find(']') {
                    let stack = &line[1..j];
                    if stack.split(',').count() == 6 {
                        if let Ok(idx) = line[j + 1..].trim().parse::<usize>() {
                            if idx < out.len() {
                                let mut m = Map::new();
                                m.insert("__stack".into(), Value::String(stack.to_string()));
                                out[idx].push(m);
                                cur = Some((idx, out[idx].len() - 1));
                            }
                        }
                    }
                }
                continue;
            }
            if let Some((a, b)) = cur {
                if let Some((k, v)) = line.split_once('=') {
                    out[a][b].insert(k.to_string(), Value::String(v.to_string()));
                }
            }
        }
        if let Some(code) = text.split("[error]").nth(1).map(|s| s.trim().to_string()) {
            if code != "0" && !code.is_empty() {
                return Err(format!("router error {code}"));
            }
        }
        Ok(out)
    }

    pub fn act(&mut self, kind: u8, oid: &str) -> Result<Vec<Map<String, Value>>, String> {
        Ok(self.acts(&[Act::new(kind, oid, &[])])?.remove(0))
    }

    /// GET of selected attributes (never pulls credentials the object may also hold).
    pub fn get(&mut self, oid: &str, attrs: &[&str]) -> Result<Map<String, Value>, String> {
        Ok(self.acts(&[Act::new(GET, oid, attrs)])?.remove(0).into_iter().next().unwrap_or_default())
    }
}

pub struct Act {
    pub kind: u8,
    pub oid: String,
    pub stack: String,
    pub attrs: Vec<String>,
}

impl Act {
    pub fn new(kind: u8, oid: &str, attrs: &[&str]) -> Self {
        Act { kind, oid: oid.into(), stack: "0,0,0,0,0,0".into(), attrs: attrs.iter().map(|s| s.to_string()).collect() }
    }
    pub fn at(kind: u8, oid: &str, stack: &str) -> Self {
        Act { kind, oid: oid.into(), stack: stack.into(), attrs: vec![] }
    }
}

fn s(m: &Map<String, Value>, k: &str) -> String {
    m.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

// ------------------------------------------------------------------ state shared with the UI
#[derive(Clone, Serialize)]
pub struct RDev {
    pub mac: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub ip: String,
    #[serde(rename = "totalRx")]
    pub total_rx: u64,
    #[serde(rename = "totalTx")]
    pub total_tx: u64,
    #[serde(rename = "rateRx")]
    pub rate_rx: u64,
    #[serde(rename = "rateTx")]
    pub rate_tx: u64,
}

pub struct RouterState {
    pub ok: bool,
    pub error: String,
    pub enabled: bool,
    pub t: u64,
    pub devices: Vec<RDev>,
    pub hist: VecDeque<(u64, Vec<(String, u64, u64)>)>, // 3 s samples, 10 min
    pub blocked: Vec<String>,
    pub exposure: Value,
    pub ppp: Value,
}

pub static ROUTER: LazyLock<Mutex<RouterState>> = LazyLock::new(|| {
    Mutex::new(RouterState {
        ok: false, error: "Conectando con el router…".into(), enabled: false, t: 0, devices: vec![], hist: VecDeque::new(),
        blocked: vec![], exposure: Value::Null, ppp: Value::Null,
    })
});

pub fn devices() -> Vec<RDev> {
    ROUTER.lock().unwrap().devices.clone()
}

pub fn router_json() -> Value {
    let k = known();
    let r = ROUTER.lock().unwrap();
    let devs: Vec<Value> = r
        .devices
        .iter()
        .map(|d| {
            let mut v = serde_json::to_value(d).unwrap();
            v["label"] = k.get(&d.mac).cloned().unwrap_or(Value::Null);
            v
        })
        .collect();
    json!({"ok": r.ok, "error": r.error, "enabled": r.enabled, "t": r.t, "devices": devs, "blocked": r.blocked, "ppp": r.ppp})
}

pub fn exposure_json() -> Value {
    ROUTER.lock().unwrap().exposure.clone()
}

pub fn router_history() -> Value {
    let r = ROUTER.lock().unwrap();
    Value::from(
        r.hist
            .iter()
            .map(|(t, ds)| {
                let m: Map<String, Value> = ds.iter().map(|(mac, a, b)| (mac.clone(), json!([a, b]))).collect();
                json!({"t": t, "d": m})
            })
            .collect::<Vec<_>>(),
    )
}

fn set_err(msg: &str) {
    let mut r = ROUTER.lock().unwrap();
    r.ok = false;
    r.error = msg.to_string();
}

fn int_to_ip(s: &str) -> String {
    match s.parse::<u64>() {
        Ok(n) => format!("{}.{}.{}.{}", (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255),
        Err(_) => s.to_string(),
    }
}

pub fn password() -> String {
    if let Ok(p) = std::env::var("TPLINK_PASS") {
        if !p.is_empty() {
            return p;
        }
    }
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey("Environment")
        .and_then(|k| k.get_value::<String, _>("TPLINK_PASS"))
        .unwrap_or_default()
}

// ------------------------------------------------------------------ exposure (read-only)
/// Reads the router settings that decide what is reachable from the internet. One object per request:
/// on this firmware an error answer invalidates the whole batch (and the session).
fn read_exposure(c: &mut Client) -> Result<Value, String> {
    let http = c.get("HTTP_CFG", &["httpRemoteEnabled", "httpRemotePort", "httpsRemoteEnabled"])?;
    let upnp = c.get("UPNP_CFG", &["enable"])?;
    let upnp_maps = c.act(GL, "UPNP_PORTMAPPING")?;
    let dmz = c.get("DMZ_HOST_CFG", &["enable", "IPAddress"])?;
    let pm_ip = c.act(GL, "WAN_IP_CONN_PORTMAPPING")?;
    let pm_ppp = c.act(GL, "WAN_PPP_CONN_PORTMAPPING")?;
    let cwmp = c.get("MANAGEMENT_SERVER", &["enableCWMP"])?;
    let snmp = c.get("SNMP_CFG", &["enable", "wanEnable"])?;
    let fw = c.get("FIREWALL", &["enable", "firewallMode", "enableSpiFirewall"])?;
    let fw6 = c.get("IP6_FIREWALL", &["enable", "enableIpv6SpiFirewall"])?;
    let telnet = c.get("TELNET_CFG", &["enableTelnet"])?;
    let ssh = c.get("DROPBEAR_CFG", &["enable"])?;
    let acl = c.act(GL, "ACL_CFG")?;

    let on = |m: &Map<String, Value>, k: &str| s(m, k) == "1";
    let fwds: Vec<String> = pm_ip
        .iter()
        .chain(pm_ppp.iter())
        .filter(|m| s(m, "enable") != "0")
        .map(|m| format!("{} → {}:{}", s(m, "externalPort"), s(m, "internalClient"), s(m, "internalPort")))
        .collect();
    let wan_ping = acl.iter().any(|m| s(m, "enable") == "1" && s(m, "service").eq_ignore_ascii_case("ping") && !s(m, "location").eq_ignore_ascii_case("local"));
    let remote = on(&http, "httpRemoteEnabled");
    let items = vec![
        ("remote", "Gestión remota del router", if remote { format!("Activada (puerto {})", s(&http, "httpRemotePort")) } else { "Desactivada".into() }, !remote),
        ("fwd", "Redirecciones de puertos", if fwds.is_empty() { "Ninguna".into() } else { fwds.join(", ") }, fwds.is_empty()),
        ("dmz", "DMZ", if on(&dmz, "enable") { format!("Activada → {}", s(&dmz, "IPAddress")) } else { "Desactivada".into() }, !on(&dmz, "enable")),
        ("upnp", "UPnP", if on(&upnp, "enable") { format!("Activado ({} puertos abiertos por programas)", upnp_maps.len()) } else { "Desactivado".into() }, !on(&upnp, "enable")),
        ("ping", "Responde a ping desde internet", if wan_ping { "Sí".into() } else { "No".into() }, !wan_ping),
        ("cwmp", "TR-069 (gestión del operador)", if on(&cwmp, "enableCWMP") { "Activado".into() } else { "Desactivado".into() }, !on(&cwmp, "enableCWMP")),
        ("snmp", "SNMP", if on(&snmp, "wanEnable") { "Activado desde internet".into() } else if on(&snmp, "enable") { "Solo LAN".into() } else { "Desactivado".into() }, !on(&snmp, "wanEnable")),
        ("spi", "Cortafuegos SPI IPv4", if on(&fw, "enableSpiFirewall") { "Activado".into() } else { "Desactivado".into() }, on(&fw, "enableSpiFirewall")),
        ("spi6", "Cortafuegos SPI IPv6", if on(&fw6, "enableIpv6SpiFirewall") { "Activado".into() } else { "Desactivado".into() }, on(&fw6, "enableIpv6SpiFirewall")),
        ("lanmgmt", "Telnet / SSH del router (LAN)", format!("Telnet {} · SSH {}", if on(&telnet, "enableTelnet") { "abierto" } else { "cerrado" }, if on(&ssh, "enable") { "abierto" } else { "cerrado" }), !on(&telnet, "enableTelnet")),
        ("acl", "Control de acceso (bloqueos)", if on(&fw, "enable") { if s(&fw, "firewallMode") == "1" { "Activo · lista negra".to_string() } else { "Activo · lista blanca".to_string() } } else { "Desactivado".into() }, true),
    ];
    Ok(json!({
        "t": now_ms(),
        "items": items.iter().map(|(k, t, v, g)| json!({"key": k, "title": t, "value": v, "good": g})).collect::<Vec<_>>(),
    }))
}

fn diff_exposure(old: &Value, new: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(newi) = new["items"].as_array() else { return out };
    let Some(oldi) = old["items"].as_array() else { return out };
    for n in newi {
        if let Some(o) = oldi.iter().find(|o| o["key"] == n["key"]) {
            if o["value"] != n["value"] && n["key"] != "acl" {
                out.push(format!("{}: {} → {}", n["title"].as_str().unwrap_or(""), o["value"].as_str().unwrap_or(""), n["value"].as_str().unwrap_or("")));
            }
        }
    }
    out
}

// ------------------------------------------------------------------ access control (block / unblock)
fn blacklist(c: &mut Client) -> Result<(Vec<Map<String, Value>>, Vec<Map<String, Value>>), String> {
    let hosts = c.act(GL, "INTERNAL_HOST")?;
    let rules = c.act(GL, "RULE")?;
    Ok((hosts.into_iter().filter(|h| s(h, "entryName").ends_with("_bl")).collect(), rules))
}

fn norm_mac(m: &str) -> String {
    m.to_uppercase().replace(':', "-")
}

fn refresh_blocked(c: &mut Client) -> Result<(), String> {
    let (hosts, _) = blacklist(c)?;
    ROUTER.lock().unwrap().blocked = hosts.iter().map(|h| norm_mac(&s(h, "mac"))).collect();
    Ok(())
}

fn block(c: &mut Client, mac: &str, name: &str) -> Result<(), String> {
    let fw = c.get("FIREWALL", &["enable", "firewallMode"])?;
    if s(&fw, "enable") == "1" && s(&fw, "firewallMode") != "1" {
        return Err("El control de acceso del router está en modo lista blanca; NetMonitor no lo cambia.".into());
    }
    let (hosts, _) = blacklist(c)?;
    if hosts.iter().any(|h| norm_mac(&s(h, "mac")) == norm_mac(mac)) {
        return Ok(());
    }
    let mac_c = mac.to_uppercase().replace('-', ":");
    let clean: String = name.chars().filter(|ch| ch.is_alphanumeric() || *ch == ' ' || *ch == '-').take(24).collect();
    let entry = format!("{}#{}_bl", if clean.trim().is_empty() { "NetMonitor" } else { clean.trim() }, mac_c);
    let host = vec![format!("type=1"), format!("entryName={entry}"), format!("mac={mac_c}"), "isParentCtrl=0".into()];
    let rule = vec![
        "isParentCtrl=0".to_string(), format!("ruleName={entry}"), format!("internalHostRef={entry}"),
        "externalHostRef=".into(), "scheduleRef=".into(), "action=1".into(), "enable=1".into(),
    ];
    c.acts(&[
        Act { kind: ADD, oid: "INTERNAL_HOST".into(), stack: "0,0,0,0,0,0".into(), attrs: host },
        Act { kind: ADD, oid: "RULE".into(), stack: "0,0,0,0,0,0".into(), attrs: rule },
    ])?;
    if s(&fw, "enable") != "1" {
        // same as the router's "Access Control: On" switch, in blacklist mode
        c.acts(&[Act::new(SET, "FIREWALL", &["enable=1", "firewallMode=1"])])?;
        c.acts(&[Act::new(SET, "IP6_FIREWALL", &["enable=1"])])?;
        crate::util::update_settings(|st| {
            st.insert("aclEnabledByNetMonitor".into(), json!(true));
        });
    }
    log(&format!("router: blocked {mac}"));
    refresh_blocked(c)
}

fn unblock(c: &mut Client, mac: &str) -> Result<(), String> {
    let (hosts, rules) = blacklist(c)?;
    let mut acts = Vec::new();
    for h in hosts.iter().filter(|h| norm_mac(&s(h, "mac")) == norm_mac(mac)) {
        let name = s(h, "entryName");
        for r in rules.iter().filter(|r| s(r, "internalHostRef") == name) {
            acts.push(Act::at(DEL, "RULE", &s(r, "__stack")));
        }
        acts.push(Act::at(DEL, "INTERNAL_HOST", &s(h, "__stack")));
    }
    if !acts.is_empty() {
        c.acts(&acts)?;
    }
    let (left, _) = blacklist(c)?;
    if left.is_empty() && crate::util::setting_bool("aclEnabledByNetMonitor", false) {
        c.acts(&[Act::new(SET, "FIREWALL", &["enable=0"])])?;
        c.acts(&[Act::new(SET, "IP6_FIREWALL", &["enable=0"])])?;
        crate::util::update_settings(|st| {
            st.remove("aclEnabledByNetMonitor");
        });
    }
    log(&format!("router: unblocked {mac}"));
    refresh_blocked(c)
}

// ------------------------------------------------------------------ worker + jobs
pub enum Job {
    Block { mac: String, name: String, block: bool, reply: Sender<Result<(), String>> },
    Exposure { reply: Sender<Result<Value, String>> },
}

static JOBS: LazyLock<Mutex<Option<Sender<Job>>>> = LazyLock::new(|| Mutex::new(None));

/// Runs a job on the router thread (which owns the session) and waits for the answer.
pub fn block_device(mac: &str, name: &str, block: bool) -> Result<(), String> {
    let (tx, rx) = channel();
    JOBS.lock().unwrap().as_ref().ok_or("router no disponible")?.send(Job::Block { mac: mac.into(), name: name.into(), block, reply: tx }).map_err(|e| e.to_string())?;
    rx.recv_timeout(Duration::from_secs(30)).map_err(|_| "El router no respondió a tiempo".to_string())?
}

pub fn refresh_exposure() -> Result<Value, String> {
    let (tx, rx) = channel();
    JOBS.lock().unwrap().as_ref().ok_or("router no disponible")?.send(Job::Exposure { reply: tx }).map_err(|e| e.to_string())?;
    rx.recv_timeout(Duration::from_secs(60)).map_err(|_| "El router no respondió a tiempo".to_string())?
}

fn do_exposure(c: &mut Client) -> Result<Value, String> {
    let e = read_exposure(c)?;
    let old = ROUTER.lock().unwrap().exposure.clone();
    let changes = diff_exposure(&old, &e);
    if !changes.is_empty() {
        crate::alerts::fire("exposure", "Ha cambiado la configuración de exposición del router", &changes.join("\n"));
    }
    ROUTER.lock().unwrap().exposure = e.clone();
    Ok(e)
}

pub fn worker() {
    let (jtx, jrx): (Sender<Job>, Receiver<Job>) = channel();
    *JOBS.lock().unwrap() = Some(jtx);
    let mut client: Option<Client> = None;
    let mut wrong_pwd: Option<String> = None; // never retry a password the router rejected (avoid lockouts)
    let mut last_slow = 0u64; // exposure / blocked list / PPPoE, every 10 min
    let mut last_ppp = 0u64;
    let mut last_sample = 0u64;
    loop {
        let pwd = password();
        if pwd.is_empty() {
            set_err("Falta la contraseña del router (variable de usuario TPLINK_PASS).");
            thread::sleep(Duration::from_secs(10));
            continue;
        }
        if wrong_pwd.as_deref() == Some(pwd.as_str()) {
            thread::sleep(Duration::from_secs(10));
            continue;
        }
        let gw = ifc().gw;
        if gw.is_empty() {
            thread::sleep(Duration::from_secs(2));
            continue;
        }
        if client.is_none() {
            let mut c = Client::new(&format!("http://{gw}"), &pwd);
            match c.authorize() {
                Ok(()) => client = Some(c),
                Err(e) if e == "WRONG_PASSWORD" => {
                    wrong_pwd = Some(pwd);
                    set_err("Contraseña del router incorrecta (TPLINK_PASS). No se reintentará hasta que cambie.");
                    continue;
                }
                Err(e) => {
                    log(&format!("router login: {e}"));
                    set_err(&e);
                    thread::sleep(Duration::from_secs(15));
                    continue;
                }
            }
        }
        let c = client.as_mut().unwrap();
        let res = c.act(GET, "STAT_CFG").and_then(|cfg| Ok((cfg, c.act(GL, "STAT_ENTRY")?)));
        match res {
            Ok((cfg, entries)) => {
                let k = |e: &Map<String, Value>, f: &str| e.get(f).and_then(Value::as_str).unwrap_or("").to_string();
                let n = |e: &Map<String, Value>, f: &str| k(e, f).parse::<u64>().unwrap_or(0);
                let devs: Vec<RDev> = entries
                    .iter()
                    .filter(|e| !k(e, "macAddress").is_empty())
                    .map(|e| RDev {
                        mac: k(e, "macAddress").to_uppercase().replace(':', "-"),
                        name: k(e, "hostName"),
                        kind: k(e, "hostType"),
                        ip: int_to_ip(&k(e, "ipAddress")),
                        total_rx: n(e, "totalBytesRx"),
                        total_tx: n(e, "totalBytesTx"),
                        rate_rx: n(e, "currBytesRx"),
                        rate_tx: n(e, "currBytesTx"),
                    })
                    .collect();
                let enabled = cfg.first().map(|o| k(o, "enable") != "0").unwrap_or(true);
                let t = now_ms();
                let sample: Vec<(String, u64, u64)> = devs.iter().map(|d| (d.mac.clone(), d.rate_rx, d.rate_tx)).collect();
                if last_sample > 0 {
                    crate::monitor::add_router_sample(&sample, (t - last_sample) as f64 / 1000.0);
                }
                last_sample = t;
                let mut r = ROUTER.lock().unwrap();
                r.ok = true;
                r.enabled = enabled;
                r.error = if enabled { String::new() } else { "El monitor de tráfico del router está apagado.".into() };
                r.t = t;
                r.hist.push_back((t, sample));
                while r.hist.len() > 200 {
                    r.hist.pop_front();
                }
                r.devices = devs;
            }
            Err(e) => {
                log(&format!("router act: {e}"));
                set_err(&format!("Sesión con el router perdida: {e}"));
                client = None;
                last_sample = 0;
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        }
        // PPPoE session uptime every minute (a reset = the fibre reconnected)
        if now_ms() - last_ppp > 60_000 {
            last_ppp = now_ms();
            if let Ok(list) = c.acts(&[Act::new(GL, "WAN_PPP_CONN", &["enable", "connectionStatus", "uptime", "name"])]) {
                // several PPP entries can be enabled and their order is not stable: use the connected one that has been up longest
                let best = list[0].iter().filter(|p| s(p, "enable") == "1" && s(p, "connectionStatus") == "Connected").max_by_key(|p| s(p, "uptime").parse::<u64>().unwrap_or(0));
                if let Some(p) = best {
                    let up = s(p, "uptime").parse::<u64>().unwrap_or(0);
                    ROUTER.lock().unwrap().ppp = json!({"status": s(p, "connectionStatus"), "uptime": up, "t": now_ms()});
                    crate::monitor::on_ppp_uptime(up);
                }
            } else {
                client = None;
                continue;
            }
        }
        if now_ms() - last_slow > 600_000 {
            last_slow = now_ms();
            let r = do_exposure(c).and_then(|_| refresh_blocked(c));
            if let Err(e) = r {
                log(&format!("router exposure: {e}"));
                client = None;
                continue;
            }
        }
        // wait ~3 s, serving jobs meanwhile
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
            match jrx.recv_timeout(left) {
                Ok(Job::Block { mac, name, block: b, reply }) => {
                    let r = if b { block(c, &mac, &name) } else { unblock(c, &mac) };
                    if r.is_err() {
                        // a failed write may have invalidated the session; start clean next round
                        let _ = reply.send(r);
                        client = None;
                        break;
                    }
                    let _ = reply.send(r);
                }
                Ok(Job::Exposure { reply }) => {
                    let r = do_exposure(c);
                    let failed = r.is_err();
                    let _ = reply.send(r);
                    if failed {
                        client = None;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
}
