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
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

type Enc = cbc::Encryptor<aes::Aes128>;
type Dec = cbc::Decryptor<aes::Aes128>;
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0";
const GET: u8 = 1;
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

    /// One act per request; returns the objects of the reply (a GL returns one per entry).
    pub fn act(&mut self, kind: u8, oid: &str) -> Result<Vec<Map<String, Value>>, String> {
        let z = "0,0,0,0,0,0";
        let plain = format!("{kind}\r\n[{oid}#{z}#{z}]0,0\r\n\r\n");
        let (sign, data) = self.prepare(&plain, false);
        let body = format!("sign={sign}\r\ndata={data}\r\n");
        let url = format!("{}/cgi_gdpr?_={}", self.host, now_ms());
        let (code, text) = self.request(&url, false, Some(&body))?;
        if code != 200 {
            return Err(format!("cgi_gdpr HTTP {code}"));
        }
        let text = if text.trim().is_empty() { String::new() } else { self.aes_decrypt(&text)? };
        let mut out: Vec<Map<String, Value>> = Vec::new();
        let mut in_obj = false;
        for line in text.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.starts_with('[') {
                // "[1,2,0,0,0,0]0" starts an object; "[error]0" ends the reply
                in_obj = line.find(']').map(|j| line[1..j].split(',').count() == 6).unwrap_or(false);
                if in_obj {
                    out.push(Map::new());
                }
                continue;
            }
            if in_obj {
                if let (Some(o), Some((k, v))) = (out.last_mut(), line.split_once('=')) {
                    o.insert(k.to_string(), Value::String(v.to_string()));
                }
            }
        }
        if text.contains("[error]") {
            let code = text.split("[error]").nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
            if code != "0" && !code.is_empty() {
                return Err(format!("router error {code}"));
            }
        }
        Ok(out)
    }
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
}

pub static ROUTER: LazyLock<Mutex<RouterState>> = LazyLock::new(|| {
    Mutex::new(RouterState {
        ok: false, error: "Conectando con el router…".into(), enabled: false, t: 0, devices: vec![], hist: VecDeque::new(),
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
    json!({"ok": r.ok, "error": r.error, "enabled": r.enabled, "t": r.t, "devices": devs})
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

pub fn worker() {
    let mut client: Option<Client> = None;
    let mut wrong_pwd: Option<String> = None; // never retry a password the router rejected (avoid lockouts)
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
                let mut r = ROUTER.lock().unwrap();
                r.ok = true;
                r.enabled = enabled;
                r.error = if enabled { String::new() } else { "El monitor de tráfico del router está apagado.".into() };
                r.t = t;
                r.hist.push_back((t, devs.iter().map(|d| (d.mac.clone(), d.rate_rx, d.rate_tx)).collect()));
                while r.hist.len() > 200 {
                    r.hist.pop_front();
                }
                r.devices = devs;
            }
            Err(e) => {
                log(&format!("router act: {e}"));
                set_err(&format!("Sesión con el router perdida: {e}"));
                client = None;
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        }
        thread::sleep(Duration::from_secs(3));
    }
}
