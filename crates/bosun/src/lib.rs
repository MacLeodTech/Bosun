//! Assembling a running Bosun engine from a configuration. Used by the CLI (`bosun serve`) and by the
//! desktop shell, so both run exactly the same engine.

pub mod config;
pub mod doctor;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bosun_api::{AppState, BrowserLauncher, Deps};
use bosun_ca::{CertificateAuthority, DataKey};
use bosun_proxy::{InterceptSettings, Proxy, ProxyConfig, RuleSpec};
use bosun_scope::{Gate, Scope, ScopeSpec};
use bosun_store::{AppDb, Project};
use tokio::sync::watch;

pub use config::Config;

/// Paths inside the data directory.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
}

impl Paths {
    pub fn new(data: PathBuf) -> Self {
        Self { data }
    }
    pub fn key(&self) -> PathBuf {
        self.data.join("data.key")
    }
    pub fn ca(&self) -> PathBuf {
        self.data.join("ca")
    }
    /// The UI's own certificate (never the interception CA's).
    pub fn ui_tls(&self) -> PathBuf {
        self.data.join("ui-tls")
    }
    pub fn app_db(&self) -> PathBuf {
        self.data.join("app.db")
    }
    pub fn projects(&self) -> PathBuf {
        self.data.join("projects")
    }
    pub fn browser_profile(&self) -> PathBuf {
        self.data.join("browser-profile")
    }
    /// A project name (`default`) or a path to a `.bosun` file.
    pub fn project(&self, name_or_path: &str) -> PathBuf {
        if name_or_path.contains('/') || name_or_path.contains('\\') || name_or_path.ends_with(".bosun") {
            PathBuf::from(name_or_path)
        } else {
            self.projects().join(format!("{name_or_path}.bosun"))
        }
    }
}

/// Create a directory only the owner can enter. On Windows the directory simply inherits the ACL of its parent
/// (the user's profile); see `bosun_ca::sealed::check_private` for why nothing more is done there.
pub fn private_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p).with_context(|| format!("cannot create {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot set permissions on {}", p.display()))?;
    }
    Ok(())
}

pub fn load_key(cfg: &Config, paths: &Paths) -> Result<DataKey> {
    DataKey::resolve(cfg.data_key_file.as_deref(), &paths.key()).context("cannot load the data key")
}

pub fn load_ca(cfg: &Config, paths: &Paths) -> Result<CertificateAuthority> {
    let key = load_key(cfg, paths)?;
    private_dir(&paths.ca())?;
    CertificateAuthority::load_or_create(&paths.ca(), &key).context("cannot load the CA")
}

/// A running engine.
#[derive(Debug)]
pub struct Engine {
    pub proxy_addr: SocketAddr,
    pub api_addr: SocketAddr,
    pub api_tls: bool,
    /// Present until the first admin is created.
    pub setup_code: Option<String>,
    pub ca_fingerprint: String,
    /// Fingerprint of the certificate the UI serves over HTTPS (none when `api.tls` is off).
    pub ui_fingerprint: Option<String>,
    pub project_path: PathBuf,
    /// SHA-256 of the CA's public key (what a browser is told to trust).
    pub ca_spki: String,
    /// For an embedded engine: the single-use ticket its parent exchanges for a session (`POST /auth/ticket`).
    pub login_ticket: Option<String>,
    proxy: Proxy,
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Engine {
    pub async fn start(cfg: &Config) -> Result<Self> {
        Self::start_with(cfg, false).await
    }

    /// Start the engine. `embedded` is for a desktop app that runs the engine as a child process: it gets a login
    /// ticket (see [`Engine::login_ticket`]) so the user is not asked for a password on every launch.
    pub async fn start_with(cfg: &Config, embedded: bool) -> Result<Self> {
        let paths = Paths::new(cfg.data_dir());
        private_dir(&paths.data)?;
        private_dir(&paths.projects())?;
        let ca = Arc::new(load_ca(cfg, &paths)?);
        let app = Arc::new(AppDb::open(&paths.app_db()).context("cannot open the account database")?);
        let project_path = paths.project(&cfg.project);
        if let Some(parent) = project_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let project = Arc::new(
            Project::open(&project_path)
                .with_context(|| format!("cannot open project {}", project_path.display()))?,
        );

        let scope_spec: ScopeSpec = project.setting(bosun_api::SETTING_SCOPE)?.unwrap_or_default();
        let gate = Gate::new(Scope::compile(scope_spec).context("the saved scope is invalid")?);
        let events = bosun_proxy::EventBus::new(4096);

        // Bind first, so port 0 in the config (tests) resolves before the proxy learns the API address.
        let api_listener = tokio::net::TcpListener::bind(cfg.api.listen)
            .await
            .with_context(|| format!("cannot listen on {} for the UI/API", cfg.api.listen))?;
        let api_addr = api_listener.local_addr()?;
        let proxy_listener = tokio::net::TcpListener::bind(cfg.proxy.listen)
            .await
            .with_context(|| format!("cannot listen on {} for the proxy", cfg.proxy.listen))?;
        let proxy_addr = proxy_listener.local_addr()?;

        let pcfg = ProxyConfig {
            listen: proxy_addr,
            self_addrs: vec![api_addr],
            ..cfg.proxy.clone()
        };
        let proxy = Proxy::new(pcfg, ca.clone(), gate.clone(), project.clone(), events.clone())?;
        if let Some(rules) = project.setting::<Vec<RuleSpec>>(bosun_api::SETTING_RULES)?
            && let Err(e) = proxy.set_rules(rules)
        {
            tracing::warn!(error = %e, "the saved match-and-replace rules are invalid; starting without them");
        }
        if let Some(s) = project.setting::<InterceptSettings>(bosun_api::SETTING_INTERCEPT)? {
            // Never come back up holding traffic: interception starts off, the in-scope choice is kept.
            proxy.intercept().set(InterceptSettings {
                requests: false,
                responses: false,
                ..s
            });
        }

        let browser = BrowserLauncher {
            explicit: cfg.browser.path.clone(),
            bundled_dir: std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|p| p.join("browser"))),
            profile_dir: paths.browser_profile(),
        };
        let api_cfg = bosun_api::ApiConfig {
            listen: api_addr,
            ..cfg.api.clone()
        };
        let ui_tls = if cfg.api.tls {
            Some(Arc::new(match (&cfg.api.tls_cert, &cfg.api.tls_key) {
                (Some(cert), Some(key)) => bosun_ca::UiTls::from_files(cert, key)
                    .context("cannot load the UI certificate (api.tls_cert and api.tls_key)")?,
                (None, None) => bosun_ca::UiTls::self_signed(
                    &paths.ui_tls(),
                    &load_key(cfg, &paths)?,
                    &bosun_api::ui_hosts(&api_cfg),
                )
                .context("cannot make the UI certificate")?,
                _ => bail!("api.tls_cert and api.tls_key must be set together"),
            }))
        } else {
            None
        };
        let ui_fingerprint = ui_tls.as_ref().map(|u| u.fingerprint());
        let (state, setup_code) = AppState::new(
            &api_cfg,
            Deps {
                app,
                projects_dir: paths.projects(),
                project_path: Some(project_path.clone()),
                proxy: proxy.clone(),
                gate,
                ca: ca.clone(),
                events,
                browser: Some(browser),
                ui_tls,
            },
        )?;

        let login_ticket = embedded.then(|| state.issue_login_ticket());
        let (stop, rx) = watch::channel(false);
        let wait = |mut rx: watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|v| *v).await;
        };
        let p = proxy.clone();
        let r1 = rx.clone();
        let t1 = tokio::spawn(async move { p.serve(proxy_listener, wait(r1)).await });
        let t2 = tokio::spawn(bosun_api::serve(state, api_listener, wait(rx)));
        Ok(Self {
            proxy_addr,
            api_addr,
            api_tls: cfg.api.tls,
            setup_code,
            ca_fingerprint: ca.fingerprint(),
            ui_fingerprint,
            project_path,
            ca_spki: ca.spki_hash(),
            login_ticket,
            proxy,
            stop,
            tasks: vec![t1, t2],
        })
    }

    /// The address of the API, without the first-run setup code that [`Engine::ui_url`] carries.
    pub fn api_url(&self) -> String {
        let scheme = if self.api_tls { "https" } else { "http" };
        let ip = if self.api_addr.ip().is_unspecified() {
            std::net::IpAddr::from([127, 0, 0, 1])
        } else {
            self.api_addr.ip()
        };
        let host = if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        format!("{scheme}://{host}:{}", self.api_addr.port())
    }

    /// The URL of the web UI (with the setup code in the fragment on first run; fragments are not sent to the
    /// server or logged by it).
    pub fn ui_url(&self) -> String {
        let scheme = if self.api_tls { "https" } else { "http" };
        let host = if self.api_addr.ip().is_unspecified() {
            "127.0.0.1".to_string()
        } else {
            self.api_addr.ip().to_string()
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        match &self.setup_code {
            Some(c) => format!("{scheme}://{host}:{}/#setup={c}", self.api_addr.port()),
            None => format!("{scheme}://{host}:{}/", self.api_addr.port()),
        }
    }

    /// Stop accepting connections and write out pending history.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        let proxy = self.proxy.clone();
        let _ = tokio::task::spawn_blocking(move || proxy.flush()).await;
    }
}
