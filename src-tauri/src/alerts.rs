//! Alerts: every alert is logged to history and, depending on settings, shown as a Windows notification
//! and pushed to the phone through ntfy and/or Telegram.
use crate::history;
use crate::util::{log, settings};
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

/// Windows notification sink, installed by main (needs the AppHandle).
pub static NOTIFY: OnceLock<Box<dyn Fn(&str, &str) + Send + Sync>> = OnceLock::new();

pub const KINDS: &[(&str, &str)] = &[
    ("newDevice", "Dispositivo nuevo en la red"),
    ("nightUnknown", "Dispositivo sin identificar de madrugada"),
    ("upload", "Subida inusual de un dispositivo"),
    ("outage", "Cortes de internet"),
    ("exposure", "Cambios en la exposición del router"),
    ("speed", "Velocidad por debajo de lo contratado"),
    ("update", "Actualización disponible"),
];

pub fn cfg() -> Value {
    settings().get("alerts").cloned().unwrap_or(json!({}))
}

pub fn enabled(kind: &str) -> bool {
    cfg().get(kind).and_then(Value::as_bool).unwrap_or(true)
}

pub fn fire(kind: &str, title: &str, body: &str) {
    if !enabled(kind) {
        return;
    }
    history::add_alert(kind, title, body);
    if let Some(n) = NOTIFY.get() {
        n(title, body);
    }
    let (t, b) = (title.to_string(), body.to_string());
    thread::spawn(move || {
        if let Err(e) = push(&t, &b) {
            log(&format!("push: {e}"));
        }
    });
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).build())
}

/// Sends to the configured phone channels. Returns which channels were used.
pub fn push(title: &str, body: &str) -> Result<Vec<&'static str>, String> {
    let n = settings().get("notify").cloned().unwrap_or(json!({}));
    let mut used = Vec::new();
    let mut errs = Vec::new();
    let ntfy = n["ntfyUrl"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    if !ntfy.is_empty() {
        // https://ntfy.sh/mi-tema  ->  POST https://ntfy.sh/ {"topic": "mi-tema", ...} (JSON keeps UTF-8 titles intact)
        match ntfy.rsplit_once('/') {
            Some((base, topic)) if base.starts_with("http") && !topic.is_empty() => {
                let msg = json!({"topic": topic, "title": title, "message": body, "tags": ["satellite"]}).to_string();
                match agent().post(&format!("{base}/")).header("Content-Type", "application/json").send(msg.as_str()) {
                    Ok(_) => used.push("ntfy"),
                    Err(e) => errs.push(format!("ntfy: {e}")),
                }
            }
            _ => errs.push("ntfy: la URL debe ser del tipo https://ntfy.sh/tu-tema".into()),
        }
    }
    let token = n["telegramToken"].as_str().unwrap_or("").trim().to_string();
    let chat = n["telegramChat"].as_str().unwrap_or("").trim().to_string();
    if !token.is_empty() && !chat.is_empty() {
        let msg = json!({"chat_id": chat, "text": format!("{title}\n{body}")}).to_string();
        match agent()
            .post(&format!("https://api.telegram.org/bot{token}/sendMessage"))
            .header("Content-Type", "application/json")
            .send(msg.as_str())
        {
            Ok(_) => used.push("telegram"),
            Err(e) => errs.push(format!("telegram: {}", e.to_string().replace(&token, "***"))),
        }
    }
    if errs.is_empty() {
        Ok(used)
    } else {
        Err(errs.join(" · "))
    }
}

pub fn test() -> Value {
    if let Some(n) = NOTIFY.get() {
        n("Prueba de NetMonitor", "Las notificaciones de Windows funcionan.");
    }
    match push("Prueba de NetMonitor", "Si ves esto en el móvil, las alertas funcionan.") {
        Ok(used) if used.is_empty() => json!({"ok": true, "msg": "Notificación de Windows enviada. No hay canales del móvil configurados."}),
        Ok(used) => json!({"ok": true, "msg": format!("Enviado a Windows y a: {}", used.join(", "))}),
        Err(e) => json!({"ok": false, "msg": e}),
    }
}
