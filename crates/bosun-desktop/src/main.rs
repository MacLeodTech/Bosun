//! The desktop app. It runs the same engine as `bosun serve`, in-process and on loopback, and shows the
//! same web UI in a native window. The window has no Tauri IPC commands at all, so a bug in the UI cannot
//! reach anything beyond what the authenticated API already allows.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Context;
use bosun::{Config, Engine};
use tauri::{WebviewUrl, WebviewWindowBuilder};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("BOSUN_LOG")
                .unwrap_or_else(|_| "info,hyper=warn".into()),
        )
        .init();

    let mut cfg = Config::load(None)?;
    // New desktop installs keep the data key in the OS keychain; an existing data.key stays until migrated.
    cfg.keychain_default = true;
    // The desktop app always keeps both listeners on loopback, whatever the config says.
    if !cfg.api.listen.ip().is_loopback() {
        cfg.api.listen.set_ip([127, 0, 0, 1].into());
    }
    if !cfg.proxy.listen.ip().is_loopback() && cfg.proxy.auth.is_none() && cfg.proxy.allow_clients.is_empty()
    {
        cfg.proxy.listen.set_ip([127, 0, 0, 1].into());
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let engine = rt
        .block_on(Engine::start(&cfg))
        .context("cannot start the engine")?;
    let url: tauri::Url = engine.ui_url().parse().context("bad UI URL")?;
    let origin = format!("{}://{}", url.scheme(), url.authority());

    let app = tauri::Builder::default()
        .setup(move |app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url.clone()))
                .title("Bosun")
                .inner_size(1400.0, 900.0)
                .min_inner_size(900.0, 600.0)
                // Only our own UI may load in this window; anything else (a link in a response) is refused.
                .on_navigation(move |u| format!("{}://{}", u.scheme(), u.authority()) == origin)
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .context("cannot start the window")?;

    app.run(|_, _| {});
    rt.block_on(engine.shutdown());
    Ok(())
}
