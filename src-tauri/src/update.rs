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

/// Downloads the latest installer and runs it silently; the caller exits the app afterwards.
///
/// Everything runs from a small script started through explorer.exe, i.e. as the desktop user and not
/// elevated, even when NetMonitor itself runs elevated as another account (admin-k): that account has no
/// gh login (downloads failed with 401) and the per-user installer would land in its profile.
pub fn install() -> Result<(), String> {
    let s = state();
    let tag = s["latest"].as_str().ok_or("Primero busca actualizaciones")?.to_string();
    // LOCALAPPDATA is the desktop user's even when elevated as another account (see main)
    let local = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?);
    let dir = local.join("Temp").join("netmonitor-update");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // restart the installed copy (the installer may move it), else the one running now
    let installed = local.join("NetMonitor").join("netmonitor.exe");
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let d = dir.display().to_string();
    let script = format!(
        "@echo off\r\n\
         timeout /t 2 /nobreak >nul\r\n\
         gh release download {tag} --repo {REPO} --pattern \"*setup.exe\" --dir \"{d}\" --clobber > \"{d}\\update.log\" 2>&1\r\n\
         for %%f in (\"{d}\\*setup.exe\") do \"%%f\" /S\r\n\
         if exist \"{inst}\" (start \"\" \"{inst}\") else (start \"\" \"{cur}\")\r\n",
        inst = installed.display(),
        cur = current.display(),
    );
    let cmd = dir.join("update.cmd");
    std::fs::write(&cmd, script).map_err(|e| e.to_string())?;
    run_hidden_detached("explorer.exe", &cmd.display().to_string())?;
    log(&format!("update: installing {tag}"));
    Ok(())
}

fn run_hidden_detached(exe: &str, arg: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new(exe)
        .arg(arg)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
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
