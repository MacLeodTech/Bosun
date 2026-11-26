//! What a container needs: non-interactive first-run setup from secret files, the health check and the optional
//! Prometheus listener.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use bosun_proxy::{Proxy, read_secret_file};
use bosun_store::{AppDb, TokenScope};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Create the first admin from `BOSUN_ADMIN_USER` + `BOSUN_ADMIN_PASSWORD_FILE`, and an API token from
/// `BOSUN_BOOTSTRAP_TOKEN_FILE` (the file holds the token, so the orchestrator knows it). Does nothing when
/// users already exist. Audited.
pub fn bootstrap(app: &AppDb) -> Result<()> {
    bootstrap_from(
        app,
        std::env::var("BOSUN_ADMIN_USER").ok().filter(|v| !v.is_empty()),
        env_path("BOSUN_ADMIN_PASSWORD_FILE"),
        env_path("BOSUN_BOOTSTRAP_TOKEN_FILE"),
    )
}

pub fn bootstrap_from(
    app: &AppDb,
    user: Option<String>,
    pw_file: Option<PathBuf>,
    token_file: Option<PathBuf>,
) -> Result<()> {
    if user.is_none() && pw_file.is_none() && token_file.is_none() {
        return Ok(());
    }
    let (Some(user), Some(pw_file)) = (user, pw_file) else {
        bail!("BOSUN_ADMIN_USER and BOSUN_ADMIN_PASSWORD_FILE must be set together");
    };
    if app.user_count()? > 0 {
        tracing::info!("accounts already exist; ignoring BOSUN_ADMIN_USER and the bootstrap files");
        return Ok(());
    }
    bosun_api::auth::check_username(&user).map_err(anyhow::Error::msg)?;
    let pw = read_secret_file(&pw_file).map_err(anyhow::Error::msg)?;
    bosun_api::auth::check_password_policy(&pw).map_err(anyhow::Error::msg)?;
    let hash = bosun_api::auth::hash_password(&pw).map_err(anyhow::Error::msg)?;
    let admin = app.create_first_admin(&user, &hash)?;
    app.audit(
        Some(&admin.username),
        "setup",
        "created the first admin from BOSUN_ADMIN_USER (non-interactive setup)",
        None,
    )?;
    if let Some(f) = token_file {
        let token = read_secret_file(&f).map_err(anyhow::Error::msg)?;
        if token.len() < 32 {
            bail!("the bootstrap token must be at least 32 characters (try `openssl rand -base64 36`)");
        }
        app.create_api_token("bootstrap", &token, admin.id, TokenScope::Full, None)?;
        app.audit(
            Some(&admin.username),
            "token.create",
            "bootstrap (full, no expiry) from BOSUN_BOOTSTRAP_TOKEN_FILE",
            None,
        )?;
    }
    tracing::info!(user = %admin.username, "created the first admin from the environment");
    Ok(())
}

/// `bosun healthcheck`: true when the UI/API listener answers `/healthz`. With TLS on the UI it only checks that
/// the port accepts connections (the check does not do TLS).
pub fn healthcheck(listen: SocketAddr, tls: bool) -> bool {
    use std::io::{Read, Write};
    let ip = if listen.ip().is_unspecified() {
        if listen.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        }
    } else {
        listen.ip()
    };
    let addr = SocketAddr::new(ip, listen.port());
    let t = Duration::from_secs(3);
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, t) else {
        return false;
    };
    if tls {
        return true;
    }
    s.set_read_timeout(Some(t)).ok();
    s.set_write_timeout(Some(t)).ok();
    let req = format!("GET /healthz HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let mut buf = Vec::new();
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let _ = s.take(4096).read_to_end(&mut buf);
    buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200")
}

/// Prometheus text format for the proxy's counters.
pub fn render_metrics(proxy: &Proxy) -> String {
    let s = proxy.stats();
    let mut out = String::new();
    let mut m = |name: &str, kind: &str, help: &str, v: u64| {
        out.push_str(&format!(
            "# HELP bosun_{name} {help}\n# TYPE bosun_{name} {kind}\nbosun_{name} {v}\n"
        ));
    };
    m(
        "memory_budget_bytes",
        "gauge",
        "Bytes buffered traffic may use.",
        s.memory_budget as u64,
    );
    m(
        "memory_used_bytes",
        "gauge",
        "Bytes of the budget in use.",
        s.memory_used as u64,
    );
    m(
        "memory_refused_total",
        "counter",
        "Reservations refused for lack of budget.",
        s.memory_refused,
    );
    m(
        "connections_refused_total",
        "counter",
        "Connections closed at the connection limit.",
        s.connections_refused,
    );
    m(
        "recorder_bodies_dropped_total",
        "counter",
        "Flows stored without bodies.",
        s.recorder_bodies_dropped,
    );
    m(
        "recorder_records_dropped_total",
        "counter",
        "Flows not recorded (queue full).",
        s.recorder_records_dropped,
    );
    m(
        "recorder_write_failures_total",
        "counter",
        "Failed history writes.",
        s.recorder_write_failures,
    );
    m(
        "recorder_records_lost_total",
        "counter",
        "Flows lost to failed writes.",
        s.recorder_records_lost,
    );
    m(
        "intercept_refused_total",
        "counter",
        "Messages refused by the intercept queue.",
        s.intercept_refused,
    );
    m(
        "intercept_queued_bytes",
        "gauge",
        "Bytes held in the intercept queue.",
        s.intercept_queued_bytes as u64,
    );
    out
}

/// Serve `/metrics` (no authentication: bind it to an internal interface) until `stop` resolves.
pub async fn serve_metrics(
    listener: tokio::net::TcpListener,
    proxy: Proxy,
    stop: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(stop);
    loop {
        let (mut s, _) = tokio::select! {
            () = &mut stop => return,
            r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let work = async {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).await?;
                let head = String::from_utf8_lossy(&buf[..n]);
                let resp = if head.starts_with("GET /metrics ") || head.starts_with("GET /metrics?") {
                    let body = render_metrics(&proxy);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
                };
                s.write_all(resp.as_bytes()).await?;
                s.shutdown().await.ok();
                std::io::Result::Ok(())
            };
            let _ = tokio::time::timeout(Duration::from_secs(5), work).await;
        });
    }
}
