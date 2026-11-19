#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! NetMonitor 2 — Tauri shell: samplers run on background threads, the UI polls them through `api`.

mod alerts;
mod discover;
mod dns;
mod geo;
mod history;
mod lan;
mod monitor;
mod net;
mod router;
mod speed;
mod update;
mod util;
mod win;

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;
use util::{now_ms, setting_bool, update_settings};

static APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();
static PLACED: AtomicBool = AtomicBool::new(false);
static DIRTY_AT: AtomicU64 = AtomicU64::new(0);
static PANEL: AtomicBool = AtomicBool::new(false);
/// Running elevated on behalf of another account: HKCU (autostart) belongs to the admin user, not ours.
static FOREIGN: AtomicBool = AtomicBool::new(false);

struct PanelItem(CheckMenuItem<Wry>);

fn hwnd(w: &WebviewWindow) -> Option<isize> {
    w.hwnd().ok().map(|h| h.0 as isize)
}

fn main_window(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window("main")
}

fn show_main(app: &AppHandle) {
    let Some(w) = main_window(app) else { return };
    if !PLACED.swap(true, Ordering::SeqCst) {
        let restored = hwnd(&w).map(win::restore_placement).unwrap_or(false);
        if !restored {
            let _ = w.center();
        }
    }
    let _ = w.show();
    if w.is_minimized().unwrap_or(false) {
        let _ = w.unminimize();
    }
    let _ = w.set_focus();
    let _ = app.emit("visible", true);
}

fn hide_main(app: &AppHandle) {
    let Some(w) = main_window(app) else { return };
    if let Some(h) = hwnd(&w) {
        win::save_placement(h);
    }
    let _ = w.hide();
    let _ = app.emit("visible", false);
    if !setting_bool("trayHint", false) {
        update_settings(|s| {
            s.insert("trayHint".into(), json!(true));
        });
        notify("NetMonitor sigue vigilando", "Está en la bandeja del sistema. Para cerrarlo del todo: clic derecho en el icono → Salir.");
    }
}

fn set_panel(app: &AppHandle, on: bool) {
    PANEL.store(on, Ordering::SeqCst);
    if let Some(w) = main_window(app) {
        let _ = w.set_decorations(!on);
        let _ = w.set_always_on_top(on);
        if !on {
            if let Some(h) = hwnd(&w) {
                win::style_caption(h);
            }
        }
    }
    if let Some(item) = app.try_state::<PanelItem>() {
        let _ = item.0.set_checked(on);
    }
    update_settings(|s| {
        s.insert("panel".into(), json!(on));
    });
    let _ = app.emit("panel", on);
}

fn notify(title: &str, body: &str) {
    if let Some(app) = APP_HANDLE.get() {
        let _ = app.notification().builder().title(title).body(body).show();
    }
}

fn exposure() -> Value {
    // Snapshot of the audit done on 19/11/2026 (router panel + GRC ShieldsUP).
    json!({
        "checked": "2026-11-19",
        "items": [
            ["Puertos abiertos en IPv4 (0-1055, 7547, 8080, 8443)", "Ninguno (TruStealth)", true],
            ["Responde a ping desde internet", "No", true],
            ["Redirecciones de puertos / DMZ", "Ninguna / Desactivada", true],
            ["UPnP", "Desactivado", true],
            ["Gestión remota del router", "Desactivada", true],
            ["TR-069 (CWMP) / SNMP", "Desactivados", true],
            ["Cortafuegos SPI IPv4", "Activado", true],
            ["Cortafuegos IPv6", "Activado, sin reglas de entrada", true],
            ["Telnet y SSH del router en la LAN", "Abiertos (solo desde dentro)", false]
        ]
    })
}

fn settings_json() -> Value {
    json!({
        "autostart": win::autostart_enabled(),
        "startMinimized": setting_bool("startMinimized", true),
        "panel": PANEL.load(Ordering::SeqCst),
        "dataDir": util::DATA.display().to_string(),
        "version": util::VERSION,
        "frozen": !cfg!(debug_assertions),
    })
}

fn config_json() -> Value {
    let s = util::settings();
    let mut notify = s.get("notify").cloned().unwrap_or(json!({}));
    // the UI never gets the Telegram token back, only whether one is set
    if let Some(t) = notify.get("telegramToken").and_then(Value::as_str) {
        let set = !t.is_empty();
        notify["telegramToken"] = json!(if set { "••••••" } else { "" });
    }
    let mut adg = s.get("adguard").cloned().unwrap_or(json!({}));
    if adg.get("pass").and_then(Value::as_str).map(|p| !p.is_empty()).unwrap_or(false) {
        adg["pass"] = json!("••••••");
    }
    json!({
        "alerts": s.get("alerts").cloned().unwrap_or(json!({})),
        "alertKinds": alerts::KINDS.iter().map(|(k, t)| json!({"key": k, "title": t})).collect::<Vec<_>>(),
        "notify": notify, "speed": s.get("speed").cloned().unwrap_or(json!({})), "adguard": adg,
        "autoUpdateCheck": setting_bool("autoUpdateCheck", true),
        "elevated": net::elevated(), "geo": geo::status(),
    })
}

/// Relaunches NetMonitor elevated (UAC prompt). The new process waits for this one to exit first.
fn elevate(owner: isize) -> Result<(), String> {
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(h: isize, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
    }
    let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // A standard account elevates as a *different* user (e.g. admin-k), whose profile is not ours:
    // hand our folders over so the admin instance keeps using this user's data, history and settings.
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let params = format!(
        "--wait-parent {} --user-appdata \"{}\" --user-localappdata \"{}\"",
        std::process::id(), env("APPDATA"), env("LOCALAPPDATA")
    );
    let r = unsafe { ShellExecuteW(owner, w("runas").as_ptr(), w(&exe.display().to_string()).as_ptr(), w(&params).as_ptr(), std::ptr::null(), 1) };
    if r > 32 {
        Ok(())
    } else {
        Err("Se canceló la elevación".into())
    }
}

fn wait_parent() {
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn WaitForSingleObject(h: *mut std::ffi::c_void, ms: u32) -> u32;
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
    }
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--wait-parent") {
        if let Some(pid) = args.get(i + 1).and_then(|p| p.parse::<u32>().ok()) {
            unsafe {
                let h = OpenProcess(0x0010_0000, 0, pid); // SYNCHRONIZE
                if !h.is_null() {
                    WaitForSingleObject(h, 15_000);
                    CloseHandle(h);
                }
            }
        }
    }
}

#[tauri::command]
async fn api(app: AppHandle, path: String, body: Option<Value>) -> Result<Value, String> {
    Ok(match (path.as_str(), body) {
        ("rate", _) => net::rate_json(),
        ("history", _) => json!({"rate": net::rate_history(), "router": router::router_history()}),
        ("conns", _) => net::conns_json(),
        ("lan", _) => lan::lan_json(),
        ("router", _) => router::router_json(),
        ("ping", _) => net::ping_json(),
        ("info", _) => json!({
            "ifc": net::ifc(), "publicIp": net::PUBLIC_IP.lock().unwrap().clone(),
            "exposure": exposure(), "version": util::VERSION, "elevated": net::elevated(),
            "publicCc": net::PUBLIC_IP.lock().unwrap().as_ref().and_then(|ip| ip.parse().ok()).and_then(|ip| geo::country(&ip)),
        }),
        ("settings", Some(b)) => {
            if let Some(v) = b.get("startMinimized").and_then(Value::as_bool) {
                update_settings(|s| {
                    s.insert("startMinimized".into(), json!(v));
                });
            }
            if (b.get("autostart").is_some() || b.get("startMinimized").is_some()) && !FOREIGN.load(Ordering::SeqCst) {
                let want = b.get("autostart").and_then(Value::as_bool).unwrap_or_else(win::autostart_enabled);
                win::set_autostart(want, setting_bool("startMinimized", true));
            }
            if let Some(p) = b.get("panel").and_then(Value::as_bool) {
                set_panel(&app, p);
            }
            settings_json()
        }
        ("settings", None) => settings_json(),
        ("config", Some(b)) => {
            // alert rules, phone channels, speed test, AdGuard: plain objects merged into settings.json
            for key in ["alerts", "notify", "speed", "adguard"] {
                if let Some(Value::Object(patch)) = b.get(key) {
                    update_settings(|s| {
                        let cur = s.entry(key.to_string()).or_insert(json!({}));
                        if let Value::Object(m) = cur {
                            for (k, v) in patch {
                                m.insert(k.clone(), v.clone());
                            }
                        }
                    });
                }
            }
            if let Some(v) = b.get("autoUpdateCheck").and_then(Value::as_bool) {
                update_settings(|s| {
                    s.insert("autoUpdateCheck".into(), json!(v));
                });
            }
            config_json()
        }
        ("config", None) => config_json(),
        ("hist", b) => {
            let b = b.unwrap_or(json!({}));
            history::query(b["range"].as_str().unwrap_or("24h"), b["off"].as_i64().unwrap_or(0))
        }
        ("alerts", _) => history::alerts(200),
        ("speed", Some(_)) => json!({"started": speed::start()}),
        ("speed", None) => speed::state(),
        ("geo", _) => geo::status(),
        ("dns", _) => dns::dns_json(),
        ("procs", _) => net::procs_json(),
        ("exposure", Some(_)) => router::refresh_exposure().unwrap_or_else(|e| json!({"error": e})),
        ("exposure", None) => router::exposure_json(),
        ("block", Some(b)) => {
            let mac = b.get("mac").and_then(Value::as_str).ok_or("mac")?;
            let name = b.get("name").and_then(Value::as_str).unwrap_or("");
            let on = b.get("block").and_then(Value::as_bool).unwrap_or(true);
            match router::block_device(mac, name, on) {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        ("update", Some(b)) => {
            if b.get("install").and_then(Value::as_bool).unwrap_or(false) {
                match update::install() {
                    Ok(()) => {
                        let a = app.clone();
                        thread::spawn(move || {
                            thread::sleep(Duration::from_millis(800));
                            a.exit(0);
                        });
                        json!({"ok": true})
                    }
                    Err(e) => json!({"ok": false, "error": e}),
                }
            } else {
                update::check()
            }
        }
        ("update", None) => update::state(),
        ("notifyTest", _) => alerts::test(),
        // owning the UAC prompt with our window brings it to the front instead of a flashing taskbar button
        ("elevate", _) => match elevate(main_window(&app).as_ref().and_then(hwnd).unwrap_or(0)) {
            Ok(()) => {
                let a = app.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(300));
                    a.exit(0);
                });
                json!({"ok": true})
            }
            Err(e) => json!({"ok": false, "error": e}),
        },
        ("known", Some(b)) => {
            let mac = b.get("mac").and_then(Value::as_str).ok_or("mac")?;
            util::set_known(mac, b.get("label").and_then(Value::as_str).unwrap_or(""));
            json!({"ok": true})
        }
        ("open", Some(b)) => {
            let url = b.get("url").and_then(Value::as_str).unwrap_or("");
            if url.starts_with("https://") {
                let _ = app.opener().open_url(url, None::<&str>);
            }
            json!({"ok": true})
        }
        _ => return Err(format!("unknown api: {path}")),
    })
}

#[tauri::command]
fn toggle_fullscreen(window: WebviewWindow) -> bool {
    let on = !window.is_fullscreen().unwrap_or(false);
    let _ = window.set_fullscreen(on);
    on
}

#[tauri::command]
fn toggle_panel(app: AppHandle) -> bool {
    let on = !PANEL.load(Ordering::SeqCst);
    set_panel(&app, on);
    on
}

#[tauri::command]
fn hide_window(app: AppHandle) {
    hide_main(&app);
}

/// 32x32 tray icon: two live bars (download blue, upload amber) on a dark tile, log-scaled to 1 Gb/s.
fn tray_image(rx: f64, tx: f64) -> Image<'static> {
    const S: usize = 32;
    let mut px = vec![0u8; S * S * 4];
    let lvl = |bps: f64| -> usize {
        let mbit = bps * 8.0 / 1e6;
        if mbit <= 0.01 {
            return 2;
        }
        let f = ((mbit.log10() + 2.0) / 5.0).clamp(0.0, 1.0); // 0.01 Mb/s .. 1000 Mb/s
        (2.0 + f * 22.0).round() as usize
    };
    let put = |px: &mut Vec<u8>, x: usize, y: usize, c: [u8; 4]| {
        let i = (y * S + x) * 4;
        px[i..i + 4].copy_from_slice(&c);
    };
    for y in 0..S {
        for x in 0..S {
            // rounded tile
            let (dx, dy) = ((x as f32 - 15.5).abs() - 10.0, (y as f32 - 15.5).abs() - 10.0);
            let d = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
            if d <= 5.5 {
                put(&mut px, x, y, [0x16, 0x1A, 0x21, 255]);
            }
        }
    }
    let (hr, ht) = (lvl(rx), lvl(tx));
    for y in 0..S {
        for x in 0..S {
            let from_bottom = 27usize.saturating_sub(y);
            if (8..=14).contains(&x) && y <= 27 && from_bottom < hr {
                put(&mut px, x, y, [0x5A, 0xA9, 0xFF, 255]);
            }
            if (17..=23).contains(&x) && y <= 27 && from_bottom < ht {
                put(&mut px, x, y, [0xFF, 0xA9, 0x4D, 255]);
            }
        }
    }
    Image::new_owned(px, S as u32, S as u32)
}

fn main() {
    // release builds have no console: keep panics in the log instead of dying silently
    std::panic::set_hook(Box::new(|info| util::log(&format!("panic: {info}"))));
    wait_parent();
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).filter(|v| !v.is_empty());
    if let (Some(roaming), Some(local)) = (arg("--user-appdata"), arg("--user-localappdata")) {
        // must happen before util::DATA (and gh, for updates) first read them
        std::env::set_var("APPDATA", roaming);
        std::env::set_var("LOCALAPPDATA", local);
        FOREIGN.store(true, Ordering::SeqCst);
    }
    if net::elevated() {
        // WebView2 refuses a user-data folder that a process at another integrity level is (or was just)
        // using, so the admin instance gets its own
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let dir = std::path::Path::new(&local).join("local.netmonitor.desktop").join("EBWebView-admin");
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", dir);
        }
    }
    let r = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![api, toggle_fullscreen, toggle_panel, hide_window])
        .setup(|app| {
            let handle = app.handle().clone();
            let _ = APP_HANDLE.set(handle.clone());
            util::init_known();

            let release = !cfg!(debug_assertions) && !FOREIGN.load(Ordering::SeqCst);
            if !util::path("settings.json").exists() {
                update_settings(|s| {
                    s.insert("startMinimized".into(), json!(true));
                });
                if release {
                    win::set_autostart(true, true);
                }
            } else if release && win::autostart_enabled() {
                win::set_autostart(true, setting_bool("startMinimized", true)); // keep the exe path current
            }

            // ---- tray
            let show = MenuItem::with_id(app, "show", "Mostrar NetMonitor", true, None::<&str>)?;
            let panel = CheckMenuItem::with_id(app, "panel", "Modo panel (sin bordes, siempre encima)", true, false, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &panel, &sep, &quit])?;
            app.manage(PanelItem(panel));
            TrayIconBuilder::with_id("main")
                .icon(tray_image(0.0, 0.0))
                .tooltip("NetMonitor")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, ev| match ev.id.as_ref() {
                    "show" => show_main(app),
                    "panel" => {
                        let on = !PANEL.load(Ordering::SeqCst);
                        set_panel(app, on);
                    }
                    "quit" => {
                        if let Some(h) = main_window(app).as_ref().and_then(hwnd) {
                            win::save_placement(h);
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, ev| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                        let app = tray.app_handle();
                        let visible = main_window(app).and_then(|w| w.is_visible().ok()).unwrap_or(false);
                        let minimized = main_window(app).and_then(|w| w.is_minimized().ok()).unwrap_or(false);
                        if visible && !minimized {
                            hide_main(app);
                        } else {
                            show_main(app);
                        }
                    }
                })
                .build(app)?;

            // ---- samplers
            let h = handle.clone();
            thread::spawn(move || {
                let mut n = 0u64;
                let mut last_icon = (usize::MAX, usize::MAX);
                net::rate_worker(move |rx, tx| {
                    n += 1;
                    if let Some(t) = h.tray_by_id("main") {
                        let key = ((rx * 8.0).max(1.0).log10() * 8.0) as usize * 1000 + ((tx * 8.0).max(1.0).log10() * 8.0) as usize;
                        if key != last_icon.0 {
                            last_icon = (key, 0);
                            let _ = t.set_icon(Some(tray_image(rx, tx)));
                        }
                        if n % 2 == 0 {
                            let _ = t.set_tooltip(Some(format!(
                                "NetMonitor\n↓ {}   ↑ {}", util::fmt_rate(rx), util::fmt_rate(tx)
                            )));
                        }
                    }
                })
            });
            let _ = alerts::NOTIFY.set(Box::new(|t: &str, b: &str| notify(t, b)));
            history::init();
            thread::spawn(|| {
                lan::scanner(|ip, mac, host| {
                    let vendor = discover::vendor(mac).map(|v| format!(" · {v}")).unwrap_or_default();
                    let what = if host.is_empty() { mac.to_string() } else { format!("{host} · {mac}") };
                    alerts::fire("newDevice", "Dispositivo nuevo en la red", &format!("{ip}  {what}{vendor}"));
                })
            });
            thread::spawn(net::ping_worker);
            thread::spawn(net::public_ip_worker);
            thread::spawn(router::worker);
            thread::spawn(monitor::worker);
            thread::spawn(speed::scheduler);
            thread::spawn(discover::worker);
            thread::spawn(geo::worker);
            thread::spawn(dns::worker);
            thread::spawn(net::estats_worker);
            thread::spawn(update::worker);

            // ---- window
            if let Some(w) = main_window(&handle) {
                if let Some(h) = hwnd(&w) {
                    win::style_caption(h);
                }
            }
            if setting_bool("panel", false) {
                set_panel(&handle, true);
            }
            if !std::env::args().any(|a| a == "--minimized") {
                show_main(&handle);
            }

            // debounced placement saver (moves/resizes)
            let h = handle.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_millis(400));
                let d = DIRTY_AT.load(Ordering::SeqCst);
                if d > 0 && now_ms().saturating_sub(d) > 800 && PLACED.load(Ordering::SeqCst) {
                    DIRTY_AT.store(0, Ordering::SeqCst);
                    if let Some(hw) = main_window(&h).as_ref().and_then(hwnd) {
                        win::save_placement(hw);
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                hide_main(window.app_handle());
            }
            WindowEvent::Moved(_) | WindowEvent::Resized(_) => DIRTY_AT.store(now_ms(), Ordering::SeqCst),
            _ => {}
        })
        .run(tauri::generate_context!());
    if let Err(e) = r {
        util::log(&format!("startup failed (elevated={}): {e}", net::elevated()));
        std::process::exit(1);
    }
}
