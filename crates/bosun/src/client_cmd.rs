//! Commands that talk to a running engine (local or a server) through `bosun-client`: `login`, `status` and
//! `repeater send`. The engine's address and an API token are kept in named profiles in the client's own config
//! directory (not the engine's data directory: a machine can run the client without an engine).

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_client::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Where the profiles live: `$BOSUN_CLIENT_DIR`, else the platform's config directory.
pub fn client_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("BOSUN_CLIENT_DIR") {
        return Ok(d.into());
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    Ok(base
        .context("no config directory: set BOSUN_CLIENT_DIR")?
        .join("bosun"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub server: String,
    /// An API token. Kept in the profiles file, readable by its owner only (an OS keychain comes later).
    pub token: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Profiles {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Profiles {
    fn path() -> Result<PathBuf> {
        Ok(client_dir()?.join("profiles.json"))
    }

    pub fn load() -> Result<Self> {
        match std::fs::read_to_string(Self::path()?) {
            Ok(s) => serde_json::from_str(&s).context("the profiles file is not valid"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        std::fs::create_dir_all(path.parent().context("no parent directory")?)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).context("could not write the profiles file")?;
        f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        // A file that already existed keeps its old mode through `create`: tighten it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// Who to talk to: `--server`/`BOSUN_SERVER` and `BOSUN_TOKEN` win, then the named (or default) profile.
pub fn resolve(server: Option<&str>, profile: Option<&str>) -> Result<(String, Option<String>)> {
    let env_server = std::env::var("BOSUN_SERVER").ok();
    let env_token = std::env::var("BOSUN_TOKEN").ok();
    if let Some(s) = server.map(str::to_string).or(env_server) {
        return Ok((s, env_token));
    }
    let p = Profiles::load()?;
    let name = profile
        .map(str::to_string)
        .or_else(|| p.default.clone())
        .context("no server: run `bosun login --server URL`, or pass --server")?;
    let prof = p
        .profiles
        .get(&name)
        .with_context(|| format!("no profile named `{name}`"))?;
    Ok((
        prof.server.clone(),
        env_token.or_else(|| Some(prof.token.clone())),
    ))
}

pub fn client(server: &str, token: Option<String>) -> Result<Client> {
    let mut b = Client::builder(server.trim_end_matches('/'));
    if let Some(t) = token {
        b = b.token(t);
    }
    Ok(b.build()?)
}

fn read_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Sign in with a password (read from stdin), make an API token for this machine and keep it in a profile.
pub async fn login(server: &str, profile: &str, username: Option<String>) -> Result<ExitCode> {
    let user = match username {
        Some(u) => u,
        None => read_line("username: ")?,
    };
    let password = read_line("password (read from stdin): ")?;
    let c = Client::new(server.trim_end_matches('/'))?;
    match c.login(&user, &password).await {
        Ok(_) => {}
        Err(bosun_client::Error::SecondFactor { pending }) => {
            let code = read_line("second-factor code (or a recovery code): ")?;
            c.login_totp(&pending, code.trim())
                .await
                .context("sign-in failed")?;
        }
        Err(e) => return Err(anyhow::Error::new(e).context("sign-in failed")),
    }
    let name = format!("cli on {}", hostname());
    let made = c
        .create_token(&name, Some(90), None)
        .await
        .context("signed in, but could not create an API token")?;
    let _ = c.logout().await;
    let mut p = Profiles::load()?;
    p.profiles.insert(
        profile.to_string(),
        Profile {
            server: server.trim_end_matches('/').to_string(),
            token: made.token,
        },
    );
    if p.default.is_none() || p.profiles.len() == 1 {
        p.default = Some(profile.to_string());
    }
    p.save()?;
    eprintln!("signed in as {user}; profile `{profile}` saved (token valid for 90 days)");
    Ok(ExitCode::SUCCESS)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "this machine".into())
}

pub async fn status(server: Option<&str>, profile: Option<&str>, json_out: bool) -> Result<ExitCode> {
    let (url, token) = resolve(server, profile)?;
    let c = client(&url, token)?;
    let st = c.status().await?;
    let me = c.me().await.ok();
    if json_out {
        println!(
            "{}",
            json!({ "server": url, "name": st.name, "version": st.version, "user": me.as_ref().map(|m| &m.user.username) })
        );
    } else {
        println!("server   {url}");
        println!("version  {}", st.version);
        match me {
            Some(m) => println!("signed in as {}", m.user.username),
            None => println!("not signed in: run `bosun login`"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `scheme://host[:port][/...]` into its parts. Only http and https.
pub fn parse_target(t: &str) -> Result<(String, String, u16)> {
    let (scheme, rest) = t
        .split_once("://")
        .context("the target must look like https://host[:port]")?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => bail!("the target scheme must be http or https"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').context("unterminated [ in the host")?;
        (h.to_string(), tail.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        bail!("the target has no host");
    }
    let port = match port {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .context("the port must be 1 to 65535")?,
        None => default,
    };
    Ok((scheme, host, port))
}

pub struct SendArgs {
    pub target: String,
    pub file: Option<PathBuf>,
    pub http2: bool,
    pub count: u32,
    pub mode: String,
    pub update_content_length: bool,
    pub verify_tls: bool,
    pub follow: bool,
    pub exact: bool,
    /// Print the status line and headers too.
    pub include: bool,
    pub json_out: bool,
}

/// The request as read: LF becomes CRLF unless the text already has a CRLF (or `--exact`), as in the UI.
pub fn wire(raw: Vec<u8>, exact: bool) -> Vec<u8> {
    if exact || raw.windows(2).any(|w| w == b"\r\n") {
        return raw;
    }
    let mut out = Vec::with_capacity(raw.len() + 16);
    for b in raw {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// Exit codes: 0 a response arrived, 3 the scope gate refused, 4 nothing came back.
pub async fn repeater_send(server: Option<&str>, profile: Option<&str>, a: SendArgs) -> Result<ExitCode> {
    let (scheme, host, port) = parse_target(&a.target)?;
    let mut raw = Vec::new();
    match &a.file {
        Some(p) if p.as_os_str() != "-" => {
            raw = std::fs::read(p).with_context(|| format!("could not read {}", p.display()))?
        }
        _ => {
            std::io::stdin().lock().read_to_end(&mut raw)?;
        }
    }
    if raw.is_empty() {
        bail!("the request is empty");
    }
    let raw = wire(raw, a.exact);
    let (url, token) = resolve(server, profile)?;
    let c = client(&url, token)?;
    let reply = c
        .repeater_send(&json!({
            "scheme": scheme, "host": host, "port": port, "request": B64.encode(&raw),
            "protocol": if a.http2 { "h2" } else { "http1" },
            "update_content_length": a.update_content_length, "verify_tls": a.verify_tls,
            "follow_redirects": a.follow, "count": a.count, "mode": a.mode.replace('-', "_"),
        }))
        .await?;
    let results = reply["results"].as_array().cloned().unwrap_or_default();
    if a.json_out {
        println!("{reply}");
    } else if results.len() == 1 {
        let r = &results[0];
        if let Some(e) = r["error"].as_str() {
            eprintln!("error: {e}");
        }
        eprintln!("{}", summary(r));
        let body = B64
            .decode(r["response"].as_str().unwrap_or(""))
            .unwrap_or_default();
        let mut out = std::io::stdout().lock();
        out.write_all(if a.include { &body } else { body_of(&body) })?;
        out.flush()?;
    } else {
        for r in &results {
            println!("{}", summary(r));
        }
    }
    let first = results.first().unwrap_or(&Value::Null);
    Ok(if results.iter().any(|r| r["status"].is_u64()) {
        ExitCode::SUCCESS
    } else if first["refused"] == true {
        ExitCode::from(3)
    } else {
        ExitCode::from(4)
    })
}

/// What follows the blank line that ends the headers (all of it when there is none).
pub fn body_of(raw: &[u8]) -> &[u8] {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw, |i| &raw[i + 4..])
}

fn summary(r: &Value) -> String {
    let status = if r["refused"] == true {
        "refused".to_string()
    } else {
        r["status"]
            .as_u64()
            .map_or("no response".into(), |s| s.to_string())
    };
    let ms = r["timings"]["total_ms"]
        .as_u64()
        .map_or(String::new(), |m| format!(" {m} ms"));
    let flow = r["flow_id"]
        .as_i64()
        .map_or(String::new(), |f| format!(" flow {f}"));
    format!("#{} {status}{ms}{flow}", r["index"].as_u64().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_with_defaults_and_reject_the_rest() {
        assert_eq!(
            parse_target("https://a.test").unwrap(),
            ("https".into(), "a.test".into(), 443)
        );
        assert_eq!(
            parse_target("http://a.test:8080/x?y").unwrap(),
            ("http".into(), "a.test".into(), 8080)
        );
        assert_eq!(
            parse_target("HTTP://[::1]:9/").unwrap(),
            ("http".into(), "::1".into(), 9)
        );
        assert_eq!(parse_target("http://[::1]").unwrap().2, 80);
        for bad in [
            "a.test",
            "ftp://a.test",
            "http://",
            "http://a:0",
            "http://a:99999",
            "http://[::1",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_body_is_what_follows_the_headers() {
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nx: y\r\n\r\nhi\r\n\r\n"),
            b"hi\r\n\r\n"
        );
        assert_eq!(body_of(b"no headers"), b"no headers");
    }

    #[test]
    fn line_endings_follow_the_ui_rule() {
        assert_eq!(wire(b"a\nb\n".to_vec(), false), b"a\r\nb\r\n");
        assert_eq!(wire(b"a\r\nb\n".to_vec(), false), b"a\r\nb\n");
        assert_eq!(wire(b"a\nb\n".to_vec(), true), b"a\nb\n");
    }
}
