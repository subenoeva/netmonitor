//! Updates from the GitHub releases of the (private) repository, through the gh CLI so no token is ever
//! embedded: `gh release view` to check, `gh release download` + silent NSIS install to update.
use crate::util::{log, run_hidden, VERSION};
use crate::alerts;
use serde_json::{json, Value};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

pub const REPO: &str = "subenoeva/netmonitor";

static STATE: LazyLock<Mutex<Value>> = LazyLock::new(|| Mutex::new(json!({"current": VERSION})));

fn ver(s: &str) -> Vec<u64> {
    s.trim_start_matches('v').split(['.', '-']).map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn state() -> Value {
    STATE.lock().unwrap().clone()
}

pub fn check() -> Value {
    let r = run_hidden("gh", &["release", "view", "--repo", REPO, "--json", "tagName,name,publishedAt,body"]);
    let v = match r {
        Ok(out) => match serde_json::from_str::<Value>(&out) {
            Ok(rel) => {
                let tag = rel["tagName"].as_str().unwrap_or("").to_string();
                let available = !tag.is_empty() && ver(&tag) > ver(VERSION);
                json!({
                    "current": VERSION, "latest": tag, "available": available, "published": rel["publishedAt"],
                    "notes": rel["body"].as_str().unwrap_or("").chars().take(2000).collect::<String>(),
                    "checked": crate::util::now_ms(),
                })
            }
            Err(e) => json!({"current": VERSION, "error": format!("respuesta de gh: {e}")}),
        },
        Err(e) if e.contains("release not found") => json!({"current": VERSION, "latest": null, "available": false, "checked": crate::util::now_ms()}),
        Err(e) => json!({"current": VERSION, "error": if e.contains("program not found") || e.contains("gh:") { "No se encontró gh (GitHub CLI)".to_string() } else { e }}),
    };
    let notify = v["available"].as_bool().unwrap_or(false) && STATE.lock().unwrap()["notified"] != v["latest"];
    let mut s = STATE.lock().unwrap();
    let notified = if notify { v["latest"].clone() } else { s["notified"].clone() };
    *s = v.clone();
    s["notified"] = notified;
    drop(s);
    if notify {
        alerts::fire("update", "Actualización de NetMonitor disponible", &format!("Versión {} lista para instalar desde Ajustes.", v["latest"].as_str().unwrap_or("")));
    }
    v
}

/// Downloads the latest installer and launches it silently; the caller exits the app afterwards.
pub fn install() -> Result<(), String> {
    let s = state();
    let tag = s["latest"].as_str().ok_or("Primero busca actualizaciones")?.to_string();
    let dir = std::env::temp_dir().join("netmonitor-update");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let d = dir.display().to_string();
    run_hidden("gh", &["release", "download", &tag, "--repo", REPO, "--pattern", "*setup.exe", "--dir", &d, "--clobber"])?;
    let setup = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "exe").unwrap_or(false))
        .ok_or("La versión no incluye instalador")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let ps = format!(
        "Start-Sleep -Seconds 2; Start-Process -Wait -FilePath '{}' -ArgumentList '/S'; Start-Process -FilePath '{}'",
        setup.display().to_string().replace('\'', "''"),
        exe.display().to_string().replace('\'', "''")
    );
    use std::os::windows::process::CommandExt;
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps])
        .creation_flags(0x0800_0000 | 0x0000_0008) // CREATE_NO_WINDOW | DETACHED_PROCESS
        .spawn()
        .map_err(|e| e.to_string())?;
    log(&format!("update: installing {tag}"));
    Ok(())
}

pub fn worker() {
    thread::sleep(Duration::from_secs(90));
    loop {
        if crate::util::setting_bool("autoUpdateCheck", true) {
            check();
        }
        thread::sleep(Duration::from_secs(6 * 3600));
    }
}
