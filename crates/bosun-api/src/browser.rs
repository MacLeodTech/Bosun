//! Launching a Chromium-family browser that is already set up to use the proxy.
//!
//! The browser gets its own profile directory (separate from the user's everyday profile), the proxy for every
//! scheme including loopback, and `--ignore-certificate-errors-spki-list` with our CA's key hash, so it accepts
//! our certificates without the CA being installed anywhere on the system. Background Google services are
//! switched off so they don't fill history with noise.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::child::clean_command;

#[derive(Debug, Clone)]
pub struct BrowserLauncher {
    /// Explicit browser binary (config or `BOSUN_BROWSER`); otherwise a bundled or system browser is searched.
    pub explicit: Option<PathBuf>,
    /// Where the bundled browser lives (`<install>/browser`).
    pub bundled_dir: Option<PathBuf>,
    pub profile_dir: PathBuf,
}

/// Browsers installed for one user only (no administrator rights needed): Chrome's and Edge's default on Windows
/// is `%LOCALAPPDATA%`, and on macOS `~/Applications`.
fn per_user_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            for rel in [
                r"Google\Chrome\Application\chrome.exe",
                r"Microsoft\Edge\Application\msedge.exe",
                r"BraveSoftware\Brave-Browser\Application\brave.exe",
                r"Chromium\Application\chrome.exe",
            ] {
                out.push(base.join(rel));
            }
        }
    } else if cfg!(target_os = "macos")
        && let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
    {
        for rel in [
            "Applications/Chromium.app/Contents/MacOS/Chromium",
            "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ] {
            out.push(home.join(rel));
        }
    }
    out
}

impl BrowserLauncher {
    pub fn find(&self) -> Option<PathBuf> {
        if let Some(p) = self
            .explicit
            .clone()
            .or_else(|| std::env::var_os("BOSUN_BROWSER").map(PathBuf::from))
        {
            return p.exists().then_some(p);
        }
        if let Some(dir) = &self.bundled_dir {
            for rel in [
                "chrome",
                "chrome.exe",
                "chrome-linux64/chrome",
                "chrome-win64/chrome.exe",
                "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            ] {
                let p = dir.join(rel);
                if p.exists() {
                    return Some(p);
                }
            }
        }
        let fixed: &[&str] = if cfg!(target_os = "macos") {
            &[
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            ]
        } else if cfg!(windows) {
            &[
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Chromium\Application\chrome.exe",
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            ]
        } else {
            &[]
        };
        for f in fixed {
            if Path::new(f).exists() {
                return Some(PathBuf::from(f));
            }
        }
        if let Some(p) = per_user_candidates().into_iter().find(|p| p.exists()) {
            return Some(p);
        }
        let names = [
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
            "brave-browser",
            "microsoft-edge",
        ];
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            for n in names {
                let p = dir.join(n);
                if p.is_file() {
                    return Some(p);
                }
                if cfg!(windows) {
                    let p = dir.join(format!("{n}.exe"));
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
        None
    }

    pub fn args(&self, proxy: SocketAddr, spki: &str) -> Vec<String> {
        let host = if proxy.ip().is_unspecified() {
            "127.0.0.1".to_string()
        } else {
            proxy.ip().to_string()
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        vec![
            format!("--user-data-dir={}", self.profile_dir.display()),
            format!("--proxy-server=http://{host}:{}", proxy.port()),
            // Send loopback through the proxy too (Chromium bypasses it by default).
            "--proxy-bypass-list=<-loopback>".into(),
            format!("--ignore-certificate-errors-spki-list={spki}"),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-background-networking".into(),
            "--disable-component-update".into(),
            "--disable-sync".into(),
            "--disable-domain-reliability".into(),
            "--metrics-recording-only".into(),
            "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication".into(),
            "about:blank".into(),
        ]
    }

    /// Start the browser detached. Returns a short description for the audit log.
    pub fn launch(&self, proxy: SocketAddr, spki: &str) -> Result<String, String> {
        let bin = self.find().ok_or(
            "no Chromium-based browser found: install Chromium or Chrome, set browser.path in the config, \
             or set BOSUN_BROWSER",
        )?;
        std::fs::create_dir_all(&self.profile_dir)
            .map_err(|e| format!("cannot create the browser profile: {e}"))?;
        // Clean environment: the browser loads hostile pages and must not hold BOSUN_DATA_KEY.
        clean_command(&bin)
            .args(self.args(proxy, spki))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", bin.display()))?;
        Ok(bin.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_pin_the_ca_and_proxy_loopback() {
        let b = BrowserLauncher {
            explicit: None,
            bundled_dir: None,
            profile_dir: "/tmp/p".into(),
        };
        let a = b.args("0.0.0.0:8080".parse().unwrap(), "abc=");
        assert!(a.contains(&"--proxy-server=http://127.0.0.1:8080".to_string()));
        assert!(a.contains(&"--ignore-certificate-errors-spki-list=abc=".to_string()));
        assert!(a.iter().any(|x| x == "--proxy-bypass-list=<-loopback>"));
        assert!(
            a.iter().any(|x| x.starts_with("--user-data-dir=")),
            "the SPKI flag only works with a separate profile"
        );
    }
}
