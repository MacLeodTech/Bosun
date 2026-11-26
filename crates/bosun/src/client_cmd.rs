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
    /// An API token, kept in the profiles file (readable by its owner only) when there is no OS keychain.
    /// Empty when `keychain` is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// The token is in the OS keychain, under `keychain_key(name, server)`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keychain: bool,
}

/// A place for secrets other than the profiles file. The OS keychain in practice; a map in tests.
pub trait TokenStore {
    fn set(&self, key: &str, token: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;
}

const KEYCHAIN_SERVICE: &str = "bosun";

pub fn keychain_key(profile: &str, server: &str) -> String {
    format!("{profile}@{}", server.trim_end_matches('/'))
}

/// The OS keychain (Windows Credential Manager, macOS Keychain, the Secret Service on Linux).
pub struct OsKeychain;

impl TokenStore for OsKeychain {
    fn set(&self, key: &str, token: &str) -> Result<()> {
        Ok(keyring::Entry::new(KEYCHAIN_SERVICE, key)?.set_password(token)?)
    }
    fn get(&self, key: &str) -> Result<Option<String>> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, key)?.get_password() {
            Ok(t) => Ok(Some(t)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn delete(&self, key: &str) -> Result<()> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// The keychain to use, unless `BOSUN_KEYCHAIN=off` (or `file`) asks for the profiles file only.
fn default_store() -> Option<OsKeychain> {
    match std::env::var("BOSUN_KEYCHAIN").as_deref() {
        Ok("off" | "file" | "0") => None,
        _ => Some(OsKeychain),
    }
}

impl Profile {
    /// A profile for `token`: in `store` when there is one and it takes the token, else in the file.
    pub fn new(
        name: &str,
        server: &str,
        token: String,
        store: Option<&dyn TokenStore>,
    ) -> (Self, Option<String>) {
        let server = server.trim_end_matches('/').to_string();
        if let Some(st) = store {
            match st.set(&keychain_key(name, &server), &token) {
                Ok(()) => {
                    return (
                        Self {
                            server,
                            token: String::new(),
                            keychain: true,
                        },
                        None,
                    );
                }
                Err(e) => {
                    let note = format!(
                        "no OS keychain ({e:#}): the token is kept in the profiles file, readable by you only"
                    );
                    return (
                        Self {
                            server,
                            token,
                            keychain: false,
                        },
                        Some(note),
                    );
                }
            }
        }
        (
            Self {
                server,
                token,
                keychain: false,
            },
            None,
        )
    }

    pub fn token_from(&self, name: &str, store: Option<&dyn TokenStore>) -> Result<String> {
        if !self.keychain {
            return Ok(self.token.clone());
        }
        let st = store
            .context("this profile's token is in the OS keychain, which BOSUN_KEYCHAIN=off turns off")?;
        st.get(&keychain_key(name, &self.server))
            .context("could not read the OS keychain")?
            .with_context(|| {
                format!("the keychain has no token for profile `{name}`: run `bosun login` again")
            })
    }
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
    resolve_with(
        server,
        profile,
        default_store().as_ref().map(|s| s as &dyn TokenStore),
    )
}

fn resolve_with(
    server: Option<&str>,
    profile: Option<&str>,
    store: Option<&dyn TokenStore>,
) -> Result<(String, Option<String>)> {
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
    let token = match env_token {
        Some(t) => t,
        None => prof.token_from(&name, store)?,
    };
    Ok((prof.server.clone(), Some(token)))
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
    let store = default_store();
    let (entry, note) = Profile::new(
        profile,
        server,
        made.token,
        store.as_ref().map(|s| s as &dyn TokenStore),
    );
    if let Some(n) = note {
        eprintln!("{n}");
    }
    // A token from an earlier login with the same name must not outlive its replacement.
    if let (Some(old), Some(st)) = (p.profiles.get(profile), &store)
        && old.keychain
        && !entry.keychain
    {
        let _ = st.delete(&keychain_key(profile, &old.server));
    }
    p.profiles.insert(profile.to_string(), entry);
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

/// Read an Intruder plan file: the body of `POST /intruder/attacks`. `request_file` (a path, relative to the plan)
/// may stand in for `request` (base64), and is read with the same LF to CRLF rule as `repeater send`.
pub fn load_plan(path: &std::path::Path, exact: bool) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let mut plan: Value = serde_json::from_str(&text).context("the plan is not valid JSON")?;
    let obj = plan.as_object_mut().context("the plan must be a JSON object")?;
    if let Some(f) = obj.remove("request_file") {
        let f = f.as_str().context("request_file must be a path")?;
        let full = path.parent().unwrap_or(std::path::Path::new(".")).join(f);
        let raw = std::fs::read(&full).with_context(|| format!("could not read {}", full.display()))?;
        obj.insert("request".into(), Value::String(B64.encode(wire(raw, exact))));
    }
    if !obj.contains_key("request") {
        bail!("the plan needs `request` (base64) or `request_file`");
    }
    Ok(plan)
}

fn csv_field(s: &str) -> String {
    // Quote when needed, and defuse spreadsheet formulas.
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Rows as CSV: index, payloads (joined by `|`), status, length, time, flow, error, matches, extracts.
pub fn rows_csv(rows: &[Value]) -> String {
    let mut out = String::from("index,payloads,status,length,time_ms,flow_id,error,matches,extracts\n");
    for r in rows {
        let payloads: Vec<&str> = r["payloads"]
            .as_array()
            .map_or(vec![], |a| a.iter().filter_map(Value::as_str).collect());
        let matches: Vec<String> = r["matches"]
            .as_array()
            .map_or(vec![], |a| a.iter().map(|m| m.to_string()).collect());
        let extracts: Vec<&str> = r["extracts"]
            .as_array()
            .map_or(vec![], |a| a.iter().map(|e| e.as_str().unwrap_or("")).collect());
        let cols = [
            r["index"].to_string(),
            payloads.join("|"),
            r["status"].as_u64().map_or(String::new(), |v| v.to_string()),
            r["length"].to_string(),
            r["time_ms"].to_string(),
            r["flow_id"].as_i64().map_or(String::new(), |v| v.to_string()),
            r["error"].as_str().unwrap_or("").to_string(),
            matches.join("|"),
            extracts.join("|"),
        ];
        out.push_str(&cols.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// Run an Intruder attack from a plan file, wait for it, and write the results (CSV or JSON) to `out` or stdout.
/// Exit code 0 when it completed, 4 when it failed or was stopped.
pub async fn intruder_run(
    server: Option<&str>,
    profile: Option<&str>,
    plan: &std::path::Path,
    exact: bool,
    format: &str,
    out: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let body = load_plan(plan, exact)?;
    let (url, token) = resolve(server, profile)?;
    let c = client(&url, token)?;
    let info = c.intruder_start(&body).await?;
    let id = info["id"]
        .as_i64()
        .context("the engine did not return an attack id")?;
    eprintln!("attack {id} started ({} requests)", info["total"]);
    let last = loop {
        let a = c.intruder_attack(id).await?;
        if a["state"].as_str() != Some("running") {
            break a;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    };
    let mut rows: Vec<Value> = Vec::new();
    loop {
        let page = c.intruder_results(id, rows.len() as u64, 1000).await?;
        let got = page["rows"].as_array().cloned().unwrap_or_default();
        if got.is_empty() {
            break;
        }
        rows.extend(got);
    }
    let text = if format == "json" {
        serde_json::to_string_pretty(&rows)? + "\n"
    } else {
        rows_csv(&rows)
    };
    match out {
        Some(p) => std::fs::write(p, text).with_context(|| format!("could not write {}", p.display()))?,
        None => std::io::stdout().lock().write_all(text.as_bytes())?,
    }
    let state = last["state"].as_str().unwrap_or("?");
    eprintln!("attack {id} {state}: {} results", rows.len());
    Ok(if state == "completed" {
        ExitCode::SUCCESS
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

/// `bosun report` against an engine: the report is rendered (and redacted) by the engine.
pub async fn report_remote(
    server: Option<&str>,
    profile: Option<&str>,
    format: &str,
    output: Option<&std::path::Path>,
    no_redact: bool,
) -> Result<ExitCode> {
    bosun_report::Format::parse(format)?;
    let (url, token) = resolve(server, profile)?;
    let c = client(&url, token)?;
    let bytes = c
        .issues_report(&bosun_client::IssueQuery::default(), format, !no_redact)
        .await?;
    write_report(&bytes, output)
}

/// `bosun report --input`: issues in as JSON (an array, or an object with an `issues` array), a report out.
pub fn report(
    input: &str,
    format: &str,
    output: Option<&std::path::Path>,
    no_redact: bool,
) -> Result<ExitCode> {
    let format = bosun_report::Format::parse(format)?;
    let mut text = String::new();
    if input == "-" {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        text = std::fs::read_to_string(input).with_context(|| format!("could not read {input}"))?;
    }
    let value: Value = serde_json::from_str(&text).context("the input is not valid JSON")?;
    let list = match value {
        Value::Array(_) => value,
        Value::Object(mut o) => o
            .remove("issues")
            .context("expected an array of issues or an object with `issues`")?,
        _ => bail!("expected an array of issues"),
    };
    let issues: Vec<bosun_report::Issue> =
        serde_json::from_value(list).context("the issues are not in the expected shape")?;
    let out = bosun_report::render(&issues, format, bosun_report::Options { redact: !no_redact });
    write_report(out.as_bytes(), output)
}

fn write_report(out: &[u8], output: Option<&std::path::Path>) -> Result<ExitCode> {
    match output {
        Some(p) => std::fs::write(p, out).with_context(|| format!("could not write {}", p.display()))?,
        None => std::io::stdout().write_all(out)?,
    }
    Ok(ExitCode::SUCCESS)
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
    fn plan_files_and_csv() {
        let dir = std::env::temp_dir().join(format!("bosun-plan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("req.txt"), "GET /x HTTP/1.1\nHost: x\n\n").unwrap();
        std::fs::write(dir.join("p.json"), r#"{"request_file":"req.txt","host":"x"}"#).unwrap();
        let plan = load_plan(&dir.join("p.json"), false).unwrap();
        let raw = B64.decode(plan["request"].as_str().unwrap()).unwrap();
        assert!(raw.starts_with(b"GET /x HTTP/1.1\r\nHost"));
        std::fs::write(dir.join("bad.json"), "{}").unwrap();
        assert!(load_plan(&dir.join("bad.json"), false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let rows = vec![
            json!({"index":0,"payloads":["=a,b","x"],"status":200,"length":5,"time_ms":3,
            "flow_id":null,"matches":[true],"extracts":[null]}),
        ];
        let csv = rows_csv(&rows);
        assert_eq!(csv.lines().nth(1).unwrap(), "0,\"'=a,b|x\",200,5,3,,,true,");
    }

    #[derive(Default)]
    struct Mem(std::cell::RefCell<BTreeMap<String, String>>);
    impl TokenStore for Mem {
        fn set(&self, k: &str, t: &str) -> Result<()> {
            self.0.borrow_mut().insert(k.into(), t.into());
            Ok(())
        }
        fn get(&self, k: &str) -> Result<Option<String>> {
            Ok(self.0.borrow().get(k).cloned())
        }
        fn delete(&self, k: &str) -> Result<()> {
            self.0.borrow_mut().remove(k);
            Ok(())
        }
    }
    struct Broken;
    impl TokenStore for Broken {
        fn set(&self, _: &str, _: &str) -> Result<()> {
            bail!("no secret service")
        }
        fn get(&self, _: &str) -> Result<Option<String>> {
            bail!("no secret service")
        }
        fn delete(&self, _: &str) -> Result<()> {
            bail!("no secret service")
        }
    }

    #[test]
    fn tokens_go_to_the_keychain_and_fall_back_to_the_file() {
        let mem = Mem::default();
        let (p, note) = Profile::new("work", "http://h/", "tok".into(), Some(&mem));
        assert!(note.is_none() && p.keychain && p.token.is_empty());
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("tok"), "{json}");
        assert_eq!(p.token_from("work", Some(&mem)).unwrap(), "tok");
        // A missing entry is a clear error; a keychain switched off is too.
        assert!(
            p.token_from("work", Some(&Mem::default()))
                .unwrap_err()
                .to_string()
                .contains("bosun login")
        );
        assert!(p.token_from("work", None).is_err());

        let (f, note) = Profile::new("work", "http://h", "tok".into(), Some(&Broken));
        assert!(note.unwrap().contains("profiles file") && !f.keychain);
        assert_eq!(f.token_from("work", Some(&Broken)).unwrap(), "tok");
        let (f, note) = Profile::new("work", "http://h", "tok".into(), None);
        assert!(note.is_none() && f.token == "tok");
        // Old profile files (token only) still load.
        let old: Profile = serde_json::from_str(r#"{"server":"s","token":"t"}"#).unwrap();
        assert!(!old.keychain && old.token == "t");
    }

    #[test]
    fn line_endings_follow_the_ui_rule() {
        assert_eq!(wire(b"a\nb\n".to_vec(), false), b"a\r\nb\r\n");
        assert_eq!(wire(b"a\r\nb\n".to_vec(), false), b"a\r\nb\n");
        assert_eq!(wire(b"a\nb\n".to_vec(), true), b"a\nb\n");
    }
}
