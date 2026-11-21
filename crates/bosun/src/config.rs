//! The configuration file (`bosun.toml`). Every setting has a safe default; an empty file is valid.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bosun_api::ApiConfig;
use bosun_proxy::ProxyConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where keys, the CA, accounts and projects live. Default: `BOSUN_DATA_DIR`, else the platform data dir.
    pub data_dir: Option<PathBuf>,
    /// File holding the base64 data key (for containers with mounted secrets); also `BOSUN_DATA_KEY_FILE`.
    /// `BOSUN_DATA_KEY` (the key itself) wins over both.
    pub data_key_file: Option<PathBuf>,
    /// Project name (under `<data_dir>/projects/`) or a path to a `.bosun` file.
    pub project: String,
    pub proxy: ProxyConfig,
    pub api: ApiConfig,
    pub browser: BrowserConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserConfig {
    /// Browser binary for "Open browser". Default: bundled, then a system Chromium/Chrome/Edge/Brave.
    pub path: Option<PathBuf>,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("BOSUN_CONFIG").map(PathBuf::from));
        let mut cfg: Config = match &path {
            Some(p) => {
                let text =
                    std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("invalid configuration in {}", p.display()))?
            }
            None => Config::default(),
        };
        if cfg.project.is_empty() {
            cfg.project = "default".into();
        }
        if cfg.data_key_file.is_none() {
            cfg.data_key_file = std::env::var_os("BOSUN_DATA_KEY_FILE").map(PathBuf::from);
        }
        Ok(cfg)
    }

    pub fn data_dir(&self) -> PathBuf {
        if let Some(d) = &self.data_dir {
            return d.clone();
        }
        if let Some(d) = std::env::var_os("BOSUN_DATA_DIR") {
            return PathBuf::from(d);
        }
        default_data_dir()
    }
}

fn default_data_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    if cfg!(target_os = "macos") {
        if let Some(h) = home {
            return h.join("Library/Application Support/Bosun");
        }
    } else if cfg!(windows) {
        if let Some(a) = std::env::var_os("APPDATA") {
            return PathBuf::from(a).join("Bosun");
        }
    } else {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(x).join("bosun");
        }
        if let Some(h) = home {
            return h.join(".local/share/bosun");
        }
    }
    PathBuf::from("bosun-data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_example_configs_parse() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.proxy.listen.ip().is_loopback());
        let c: Config = toml::from_str(include_str!("../../../bosun.toml.example")).unwrap();
        assert_eq!(c.proxy.listen.port(), 8080);
        assert!(
            toml::from_str::<Config>("unknown = 1").is_err(),
            "typos are errors, not silently ignored"
        );
    }
}
