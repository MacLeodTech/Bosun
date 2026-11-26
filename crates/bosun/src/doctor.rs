//! `bosun doctor`: checks an install for common mistakes, without changing anything.

use std::path::Path;

use crate::{Config, Paths};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug)]
pub struct Finding {
    pub level: Level,
    pub what: String,
}

fn push(out: &mut Vec<Finding>, level: Level, what: impl Into<String>) {
    out.push(Finding {
        level,
        what: what.into(),
    });
}

#[cfg(unix)]
fn mode(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).ok().map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode(_: &Path) -> Option<u32> {
    None
}

pub fn run(cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    let paths = Paths::new(cfg.data_dir());
    push(
        &mut out,
        Level::Ok,
        format!("data directory: {}", paths.data.display()),
    );
    if let Some(m) = mode(&paths.data)
        && m & 0o077 != 0
    {
        push(
            &mut out,
            Level::Warn,
            format!("data directory is accessible by other users (mode {m:o}); run chmod 700"),
        );
    }
    let key_source = if std::env::var_os("BOSUN_DATA_KEY").is_some() {
        "BOSUN_DATA_KEY".to_string()
    } else if let Some(f) = &cfg.data_key_file {
        f.display().to_string()
    } else {
        paths.key().display().to_string()
    };
    match crate::load_key(cfg, &paths) {
        Ok(_) => push(&mut out, Level::Ok, format!("data key loaded from {key_source}")),
        Err(e) => push(&mut out, Level::Fail, format!("data key: {e:#}")),
    }
    if paths.ca().join("ca.key.sealed").exists() {
        match crate::load_ca(cfg, &paths) {
            Ok(ca) => {
                push(
                    &mut out,
                    Level::Ok,
                    format!("CA fingerprint (SHA-256): {}", ca.fingerprint()),
                );
                if ca.days_left() < 0 {
                    push(
                        &mut out,
                        Level::Fail,
                        format!(
                            "the CA expired on {}; run `bosun ca rotate`",
                            ca.not_after().date()
                        ),
                    );
                } else if ca.days_left() <= bosun_ca::EXPIRY_WARN_DAYS {
                    push(
                        &mut out,
                        Level::Warn,
                        format!(
                            "the CA expires in {} days ({}); run `bosun ca rotate` and replace it wherever it is installed",
                            ca.days_left(),
                            ca.not_after().date()
                        ),
                    );
                }
                if in_system_store(ca.cert_pem()) {
                    push(
                        &mut out,
                        Level::Warn,
                        "this install's CA is trusted by the system store; anyone holding the data key can \
                         impersonate any site to this machine. Prefer the launched browser, which pins the CA \
                         without installing it",
                    );
                }
            }
            Err(e) => push(&mut out, Level::Fail, format!("CA: {e:#}")),
        }
    } else {
        push(&mut out, Level::Ok, "no CA yet (one is created on first `serve`)");
    }
    if let Err(e) = cfg.proxy.validate() {
        push(&mut out, Level::Fail, format!("proxy configuration: {e}"));
    } else if !cfg.proxy.listen.ip().is_loopback() {
        push(
            &mut out,
            Level::Warn,
            format!("proxy listens on {} (not loopback)", cfg.proxy.listen),
        );
    }
    if !cfg.api.listen.ip().is_loopback() {
        push(
            &mut out,
            Level::Warn,
            format!("UI/API listens on {} (not loopback)", cfg.api.listen),
        );
        if !cfg.api.tls && cfg.api.secure_cookies != Some(true) {
            push(
                &mut out,
                Level::Warn,
                "the UI is reachable from the network over plain HTTP; enable api.tls or put it behind a TLS \
                 reverse proxy and set api.secure_cookies = true",
            );
        }
    }
    if cfg.api.tls {
        match (&cfg.api.tls_cert, &cfg.api.tls_key) {
            (Some(c), Some(k)) => {
                for p in [c, k] {
                    if std::fs::metadata(p).is_err() {
                        push(
                            &mut out,
                            Level::Fail,
                            format!("UI certificate file {} cannot be read", p.display()),
                        );
                    }
                }
            }
            (None, None) => push(
                &mut out,
                Level::Ok,
                "the UI uses its own self-signed certificate (not the interception CA's); browsers will warn once",
            ),
            _ => push(
                &mut out,
                Level::Fail,
                "api.tls_cert and api.tls_key must be set together",
            ),
        }
    }
    if cfg.proxy.verify_upstream_tls {
        push(&mut out, Level::Ok, "upstream TLS certificates are verified");
    }
    let launcher = bosun_api::BrowserLauncher {
        explicit: cfg.browser.path.clone(),
        bundled_dir: std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("browser"))),
        profile_dir: paths.browser_profile(),
    };
    match launcher.find() {
        Some(b) => push(&mut out, Level::Ok, format!("browser: {}", b.display())),
        None => push(
            &mut out,
            Level::Warn,
            "no Chromium-based browser found; \"Open browser\" won't work",
        ),
    }
    out
}

/// Best effort: look for our certificate in the usual system bundle files.
fn in_system_store(pem: &str) -> bool {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    if body.len() < 64 {
        return false;
    }
    let needle = &body[body.len() - 64..];
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/etc/ssl/ca-bundle.pem",
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(p).ok())
    .any(|s| s.lines().collect::<String>().contains(needle))
}
