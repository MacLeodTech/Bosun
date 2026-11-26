//! The `bosun` command.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use bosun::{Config, Engine, Paths, doctor};
use bosun_store::{AppDb, Role};
use clap::{CommandFactory, Parser, Subcommand};

mod admin_cmd;
mod banner;
mod client_cmd;
mod client_data;

#[derive(Parser, Debug)]
#[command(
    name = "bosun",
    version,
    about = "A free, low-footprint intercepting proxy and DAST toolkit"
)]
struct Cli {
    /// Configuration file (TOML). Default: $BOSUN_CONFIG, else built-in defaults.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Data directory (overrides the config file and $BOSUN_DATA_DIR).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the proxy and the web UI/API.
    Serve {
        /// Project name or path to a .bosun file.
        #[arg(short, long)]
        project: Option<String>,
        /// Proxy listen address.
        #[arg(long)]
        proxy: Option<std::net::SocketAddr>,
        /// UI/API listen address.
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
        /// Run as the child process of a desktop app: listen on loopback (random ports unless --proxy and --listen
        /// are given), print one JSON line on stdout with `api_url`, `proxy_addr`, `ca_spki` and `login_ticket`,
        /// log to stderr only, and exit when stdin closes.
        #[arg(long)]
        embedded: bool,
        /// Record only: run the proxy without the web UI/API (no accounts, no listener for them).
        #[arg(long, conflicts_with = "embedded")]
        no_ui: bool,
    },
    /// Check the install for common problems.
    Doctor,
    /// Exit 0 when the running server answers its health check (for container HEALTHCHECK; no curl needed).
    Healthcheck,
    /// The install's certificate authority.
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// Manage UI accounts.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage projects in the data directory (no engine needed; refuses when a running Bosun has the project).
    Project {
        #[command(subcommand)]
        cmd: admin_cmd::ProjectCmd,
    },
    /// Manage API tokens.
    Token {
        #[command(subcommand)]
        cmd: admin_cmd::TokenCmd,
    },
    /// Show the audit log.
    Audit(admin_cmd::AuditArgs),
    /// Print a shell completion script.
    Completions { shell: clap_complete::Shell },
    /// Write man pages (bosun.1 and one per subcommand) to a directory.
    Man {
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
    },
    /// Print an example configuration file.
    ExampleConfig,
    /// Sign in to an engine (local or a server) and keep an API token in a profile.
    Login {
        #[arg(long)]
        server: String,
        /// Name for the saved profile.
        #[arg(long, default_value = "default")]
        profile: String,
        /// Username (asked for when omitted; the password is read from stdin).
        #[arg(short, long)]
        username: Option<String>,
    },
    /// Show the engine you are signed in to.
    Status {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        json: bool,
    },
    /// A report of the engine's issues: html (a file with no script), json, sarif, junit or markdown. Secrets are
    /// redacted unless --no-redact (tester role, audited). With --input it renders a JSON file of report-shaped
    /// issues offline instead of asking an engine.
    Report {
        #[command(flatten)]
        conn: Conn,
        /// Render this JSON file of issues (or `-` for stdin) offline instead of asking an engine.
        #[arg(long, short)]
        input: Option<String>,
        #[arg(long, short, default_value = "html")]
        format: String,
        /// Write the report here (else stdout).
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
        /// Keep secrets (cookies, tokens, passwords) in the report.
        #[arg(long)]
        no_redact: bool,
    },
    /// Run the Decoder on a file or stdin, offline (no engine needed). The result goes to stdout.
    ///
    /// STEPS are Decoder operations, applied in order: url_decode, base64_decode, gzip_decode, sha256 and so on
    /// (`--list` shows them all). With `--smart` and no steps, the layers are peeled automatically.
    Decode {
        /// The operations, in order.
        steps: Vec<String>,
        /// Read this file instead of stdin.
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Peel layers automatically (only when no steps are given).
        #[arg(long)]
        smart: bool,
        /// Print the operation names and exit.
        #[arg(long)]
        list: bool,
        /// Largest output of any step, in bytes.
        #[arg(long, default_value_t = 16 << 20)]
        limit: usize,
    },
    /// Browse and export the recorded traffic of an engine.
    History {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        out: client_data::Out,
        #[command(subcommand)]
        cmd: HistoryCmd,
    },
    /// Show or change the scope of an engine.
    Scope {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        out: client_data::Out,
        #[command(subcommand)]
        cmd: ScopeCmd,
    },
    /// Show or change the match-and-replace rules of an engine.
    Rules {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        out: client_data::Out,
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Control interception on an engine.
    Intercept {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        out: client_data::Out,
        #[command(subcommand)]
        cmd: InterceptCmd,
    },
    /// Print the engine's events as JSON lines.
    Events {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        out: client_data::Out,
        /// Keep going (reconnecting) instead of stopping after the engine's hello.
        #[arg(short, long)]
        follow: bool,
        /// Stop after this many messages.
        #[arg(long)]
        count: Option<u64>,
    },
    /// Import requests from an OpenAPI, GraphQL introspection, Postman, HAR, URL list or Burp XML file as Repeater
    /// tabs. Nothing is sent: tabs are sent later from the Repeater, through the scope gate.
    Import {
        /// openapi, graphql, postman, har, urls or burp.
        #[arg(value_parser = ["openapi", "graphql", "postman", "har", "urls", "burp"])]
        format: String,
        /// The file; `-` or omitted reads stdin.
        file: Option<PathBuf>,
        #[command(flatten)]
        conn: Conn,
        /// The server or endpoint to use when the file has none (required for graphql).
        #[arg(long)]
        base_url: Option<String>,
        /// Show what would be imported without saving it.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// The Repeater: send a request again.
    Repeater {
        #[command(subcommand)]
        cmd: RepeaterCmd,
    },
    /// Intruder: run an attack from a plan file.
    Intruder {
        #[command(subcommand)]
        cmd: IntruderCmd,
    },
}

/// Which engine a client command talks to (else `$BOSUN_SERVER`/`$BOSUN_TOKEN`, else the default profile).
#[derive(clap::Args, Debug)]
struct Conn {
    #[arg(long, global = true)]
    server: Option<String>,
    #[arg(long, global = true)]
    profile: Option<String>,
}

/// Which flows `history` commands look at.
#[derive(clap::Args, Debug, Clone)]
struct FlowFilter {
    /// A history query, such as `host:example.com status:4xx -ext:png login`.
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    host: Option<String>,
    /// Comma-separated, such as GET,POST.
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    status_min: Option<u16>,
    #[arg(long)]
    status_max: Option<u16>,
    /// Only flows in scope.
    #[arg(long)]
    in_scope: bool,
    /// proxy, repeater, intruder, ...
    #[arg(long)]
    source: Option<String>,
    /// How many flows at most.
    #[arg(long, default_value_t = 50)]
    limit: u32,
    /// id (default), time, method, host, path, status, size, duration or mime.
    #[arg(long)]
    sort: Option<String>,
    /// Oldest or smallest first.
    #[arg(long)]
    asc: bool,
}

impl FlowFilter {
    fn into_filter(self, query: Option<String>) -> client_data::Filter {
        client_data::Filter {
            query: query.or(self.query),
            host: self.host,
            method: self.method,
            status_min: self.status_min,
            status_max: self.status_max,
            in_scope: self.in_scope,
            source: self.source,
            limit: self.limit,
            sort: self.sort,
            asc: self.asc,
        }
    }
}

#[derive(Subcommand, Debug)]
enum HistoryCmd {
    /// List recent flows.
    List {
        #[command(flatten)]
        f: FlowFilter,
    },
    /// Search with a history query. Exit code 4 when nothing matches.
    Search {
        #[arg(value_name = "QUERY")]
        terms: String,
        #[command(flatten)]
        f: FlowFilter,
    },
    /// Show one flow: the summary and the message heads, or a message with `--part`.
    Show {
        id: i64,
        /// request, response, original-request or original-response: print that message.
        #[arg(long)]
        part: Option<String>,
        /// With --part: the body only, without the head.
        #[arg(long)]
        body_only: bool,
        /// With --part: undo the Content-Encoding.
        #[arg(long)]
        decoded: bool,
    },
    /// Write flows as HAR 1.2 or ndjson (oldest first).
    Export {
        #[arg(long, default_value = "har", value_parser = ["har", "ndjson"])]
        format: String,
        /// Output file; omitted or `-` is stdout.
        #[arg(short, long)]
        file: Option<PathBuf>,
        #[command(flatten)]
        f: FlowFilter,
    },
}

#[derive(Subcommand, Debug)]
enum ScopeCmd {
    /// Show the include and exclude rules.
    Get,
    /// Replace the scope with JSON (`{"include": [...], "exclude": [...]}`) from FILE or stdin (`-`).
    Set { file: PathBuf },
    /// Add a host to the include list (or the exclude list with --exclude).
    Add {
        host: String,
        #[arg(long)]
        exclude: bool,
        #[arg(long, value_parser = ["http", "https"])]
        scheme: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        path: Option<String>,
        /// Let the rule match loopback and private addresses.
        #[arg(long)]
        allow_private: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RulesCmd {
    /// Show the rules.
    Get,
    /// Replace the rules with a JSON array from FILE or stdin (`-`).
    Set { file: PathBuf },
    /// Add the rules in a JSON array (FILE or `-`) after the existing ones.
    Import { file: PathBuf },
}

#[derive(Subcommand, Debug)]
enum InterceptCmd {
    /// Hold requests (and responses with --responses).
    On {
        #[arg(long)]
        responses: bool,
        /// Only hold flows in scope.
        #[arg(long)]
        in_scope_only: Option<bool>,
    },
    /// Hold nothing.
    Off,
    /// Show whether interception is on.
    Status,
    /// List the held messages.
    Queue,
    /// Forward a held message by id, or everything held when no id is given.
    Forward { id: Option<u64> },
    /// Drop a held message.
    Drop { id: u64 },
}

#[derive(Subcommand, Debug)]
enum IntruderCmd {
    /// Run the attack in PLAN (the JSON body of `POST /intruder/attacks`; `request_file` may name the raw request),
    /// wait for it and write the results. Exit code 0 when it completed, 4 when it failed or was stopped.
    Run {
        plan: PathBuf,
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value = "csv", value_parser = ["csv", "json"])]
        format: String,
        /// Write the results here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Send a `request_file` as it is: no LF to CRLF.
        #[arg(long)]
        exact: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RepeaterCmd {
    /// Send a raw request file (or stdin) to TARGET (`https://host[:port]`) and print the response body.
    /// The status line goes to stderr. Exit code 0 when a response arrived, 3 when the scope refused it, 4 when
    /// nothing came back.
    Send {
        target: String,
        /// The raw request; `-` or omitted reads stdin.
        file: Option<PathBuf>,
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        http2: bool,
        /// Send it this many times (a group).
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// sequential, parallel or single-packet.
        #[arg(long, default_value = "sequential", value_parser = ["sequential", "parallel", "single-packet"])]
        mode: String,
        #[arg(long)]
        update_content_length: bool,
        #[arg(long)]
        verify_tls: bool,
        #[arg(long)]
        follow_redirects: bool,
        /// Send the bytes as they are: no LF to CRLF.
        #[arg(long)]
        exact: bool,
        /// Print the status line and headers too, as curl -i does.
        #[arg(short = 'i', long)]
        include: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum CaCmd {
    /// Print the CA certificate (PEM) or write it to a file.
    Export {
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// DER instead of PEM.
        #[arg(long)]
        der: bool,
        /// With --server, --profile or $BOSUN_SERVER: fetch the CA (PEM) from that engine instead of the local data directory.
        #[command(flatten)]
        conn: Conn,
    },
    /// Show the fingerprint, SPKI hash, expiry and name constraint.
    Info,
    /// Replace the CA with a new one. The old certificate is kept under `ca/previous/`, its key is deleted.
    /// Restart Bosun afterwards; the launched browser is pinned to the new key the next time it starts.
    Rotate {
        /// Make the new CA name-constrained: usable only for this domain and its subdomains (repeatable),
        /// never for IP addresses. For installing on test devices.
        #[arg(long = "permit-domain", value_name = "DOMAIN")]
        permit_domain: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum UserCmd {
    /// Add an account (the password is read from stdin).
    Add {
        username: String,
        #[arg(long, default_value = "tester")]
        role: String,
    },
    /// Set a password (read from stdin); signs the user out everywhere.
    Passwd { username: String },
    /// List the accounts.
    List {
        #[arg(long)]
        json: bool,
    },
    #[command(flatten)]
    Admin(admin_cmd::UserAdminCmd),
    /// Remove a user's TOTP second factor and recovery codes (a lost device); signs the user out everywhere.
    TotpReset { username: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter =
        tracing_subscriber::EnvFilter::try_from_env("BOSUN_LOG").unwrap_or_else(|_| "info,hyper=warn".into());
    let log = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    // BOSUN_LOG_FORMAT=json: one JSON object per line, for log collectors.
    if std::env::var("BOSUN_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json")) {
        log.json().init();
    } else {
        log.init();
    }
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            admin_cmd::exit_code(&e)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let mut cfg = Config::load(cli.config.as_deref())?;
    if let Some(d) = cli.data_dir {
        cfg.data_dir = Some(d);
    }
    let paths = Paths::new(cfg.data_dir());
    match cli.cmd {
        Cmd::Serve {
            project,
            proxy,
            listen,
            embedded,
            no_ui,
        } => {
            if let Some(p) = project {
                cfg.project = p;
            }
            if let Some(p) = proxy {
                cfg.proxy.listen = p;
            }
            if let Some(l) = listen {
                cfg.api.listen = l;
            }
            if embedded {
                // The parent talks to the engine over loopback only, whatever the config file says.
                cfg.proxy.listen = proxy.unwrap_or_else(|| ([127, 0, 0, 1], 0).into());
                cfg.api.listen = listen.unwrap_or_else(|| ([127, 0, 0, 1], 0).into());
                cfg.api.tls = false;
                if !cfg.proxy.listen.ip().is_loopback() || !cfg.api.listen.ip().is_loopback() {
                    bail!("--embedded only listens on loopback addresses");
                }
            }
            cfg.proxy.validate().map_err(anyhow::Error::msg)?;
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let r = if no_ui {
                rt.block_on(serve_no_ui(cfg))
            } else if embedded {
                rt.block_on(serve_embedded(cfg))
            } else {
                rt.block_on(serve(cfg))
            };
            // A read of stdin may still be waiting on its thread; do not wait for it.
            rt.shutdown_timeout(std::time::Duration::from_secs(2));
            r?;
        }
        Cmd::Healthcheck => {
            return Ok(if bosun::server_mode::healthcheck(cfg.api.listen, cfg.api.tls) {
                ExitCode::SUCCESS
            } else {
                eprintln!("unhealthy: no answer from {}", cfg.api.listen);
                ExitCode::FAILURE
            });
        }
        Cmd::Doctor => {
            let mut worst = doctor::Level::Ok;
            for f in doctor::run(&cfg) {
                let tag = match f.level {
                    doctor::Level::Ok => "  ok ",
                    doctor::Level::Warn => "warn ",
                    doctor::Level::Fail => "FAIL ",
                };
                println!("{tag} {}", f.what);
                if f.level == doctor::Level::Fail
                    || (f.level == doctor::Level::Warn && worst == doctor::Level::Ok)
                {
                    worst = f.level;
                }
            }
            if worst == doctor::Level::Fail {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Ca {
            cmd: CaCmd::Export { out, conn, .. },
        } if conn.server.is_some()
            || conn.profile.is_some()
            || std::env::var_os("BOSUN_SERVER").is_some() =>
        {
            return tokio::runtime::Runtime::new()?.block_on(client_data::ca_export(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                out,
            ));
        }
        Cmd::Ca { cmd } => {
            bosun::private_dir(&paths.data)?;
            let ca = bosun::load_ca(&cfg, &paths)?;
            if let CaCmd::Rotate { permit_domain } = &cmd {
                let opts = bosun_ca::CaOptions {
                    permitted_domains: permit_domain.clone(),
                };
                let (new, r) = bosun::rotate_ca(&cfg, &paths, &opts)?;
                println!(
                    "old CA:       {} (certificate kept in {})",
                    r.old_fingerprint,
                    r.archived_cert.display()
                );
                println!("new CA:       {}", new.fingerprint());
                println!("SPKI SHA-256: {}", new.spki_hash());
                if !new.permitted_domains().is_empty() {
                    println!("limited to:   {}", new.permitted_domains().join(", "));
                }
                println!(
                    "Restart Bosun to use it. Browsers launched from Bosun pick up the new pin; a CA you installed \
                     anywhere else (system store, test devices) must be replaced with `bosun ca export`."
                );
                return Ok(ExitCode::SUCCESS);
            }
            match cmd {
                CaCmd::Export { out, der, .. } => {
                    let bytes: Vec<u8> = if der {
                        ca.cert_der().to_vec()
                    } else {
                        ca.cert_pem().as_bytes().to_vec()
                    };
                    match out {
                        Some(p) => std::fs::write(&p, bytes)
                            .with_context(|| format!("cannot write {}", p.display()))?,
                        None if der => bail!("DER is binary; use --out"),
                        None => std::io::stdout().write_all(&bytes)?,
                    }
                }
                CaCmd::Info => {
                    println!("certificate:  {}", ca.cert_path().display());
                    println!("SHA-256:      {}", ca.fingerprint());
                    println!("SPKI SHA-256: {}", ca.spki_hash());
                    println!(
                        "expires:      {} ({} days left)",
                        ca.not_after().date(),
                        ca.days_left()
                    );
                    if ca.permitted_domains().is_empty() {
                        println!("constraint:   none (valid for any name)");
                    } else {
                        println!("constraint:   {}", ca.permitted_domains().join(", "));
                    }
                }
                CaCmd::Rotate { .. } => {}
            }
        }
        Cmd::User { cmd } => {
            bosun::private_dir(&paths.data)?;
            let app = AppDb::open(&paths.app_db())?;
            match cmd {
                UserCmd::Add { username, role } => {
                    let role = Role::parse(&role).context("role must be viewer, tester or admin")?;
                    bosun_api::auth::check_username(&username).map_err(anyhow::Error::msg)?;
                    let pw = read_password()?;
                    let hash = bosun_api::auth::hash_password(&pw).map_err(anyhow::Error::msg)?;
                    let u = app.create_user(&username, &hash, role)?;
                    app.audit(
                        None,
                        "user.create",
                        &format!("{} ({}) via CLI", u.username, role.as_str()),
                        None,
                    )?;
                    println!("created {} ({})", u.username, role.as_str());
                }
                UserCmd::Passwd { username } => {
                    let Some((u, _)) = app.user_for_login(&username)? else {
                        bail!("no such user")
                    };
                    let pw = read_password()?;
                    let hash = bosun_api::auth::hash_password(&pw).map_err(anyhow::Error::msg)?;
                    app.set_password(u.id, &hash, true)?;
                    app.audit(None, "user.password", &format!("{} via CLI", u.username), None)?;
                    println!(
                        "password changed; {} is signed out everywhere and its API tokens are revoked",
                        u.username
                    );
                }
                UserCmd::List { json: true } => return admin_cmd::user_list_json(&paths),
                UserCmd::Admin(a) => return admin_cmd::user(&paths, a),
                UserCmd::TotpReset { username } => {
                    let Some((u, _)) = app.user_for_login(&username)? else {
                        bail!("no such user")
                    };
                    if !app.totp_remove(u.id)? {
                        bail!("{} has no second factor", u.username);
                    }
                    app.revoke_sessions(u.id)?;
                    app.audit(None, "user.totp.reset", &format!("{} via CLI", u.username), None)?;
                    println!(
                        "second factor removed; {} is signed out everywhere and can set up a new one in Settings",
                        u.username
                    );
                }
                UserCmd::List { json: false } => {
                    for u in app.list_users()? {
                        println!("{:>4}  {:<24} {}", u.id, u.username, u.role.as_str());
                    }
                }
            }
        }
        Cmd::Login {
            server,
            profile,
            username,
        } => {
            return tokio::runtime::Runtime::new()?.block_on(client_cmd::login(&server, &profile, username));
        }
        Cmd::Report {
            conn,
            input,
            format,
            output,
            no_redact,
        } => {
            return match input {
                Some(input) => client_cmd::report(&input, &format, output.as_deref(), no_redact),
                None => tokio::runtime::Runtime::new()?.block_on(client_cmd::report_remote(
                    conn.server.as_deref(),
                    conn.profile.as_deref(),
                    &format,
                    output.as_deref(),
                    no_redact,
                )),
            };
        }
        Cmd::Status { conn, json } => {
            return tokio::runtime::Runtime::new()?.block_on(client_cmd::status(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                json,
            ));
        }
        Cmd::History { conn, out, cmd } => {
            let (sv, pf) = (conn.server.as_deref(), conn.profile.as_deref());
            return tokio::runtime::Runtime::new()?.block_on(async {
                match cmd {
                    HistoryCmd::List { f } => {
                        client_data::history_list(sv, pf, out, f.into_filter(None), false).await
                    }
                    HistoryCmd::Search { terms, f } => {
                        client_data::history_list(sv, pf, out, f.into_filter(Some(terms)), true).await
                    }
                    HistoryCmd::Show {
                        id,
                        part,
                        body_only,
                        decoded,
                    } => client_data::history_show(sv, pf, out, id, part, body_only, decoded).await,
                    HistoryCmd::Export { format, file, f } => {
                        client_data::history_export(sv, pf, out, f.into_filter(None), &format, file).await
                    }
                }
            });
        }
        Cmd::Scope { conn, out, cmd } => {
            let (sv, pf) = (conn.server.as_deref(), conn.profile.as_deref());
            return tokio::runtime::Runtime::new()?.block_on(async {
                match cmd {
                    ScopeCmd::Get => client_data::scope_get(sv, pf, out).await,
                    ScopeCmd::Set { file } => client_data::scope_set(sv, pf, out, &file).await,
                    ScopeCmd::Add {
                        host,
                        exclude,
                        scheme,
                        port,
                        path,
                        allow_private,
                    } => {
                        client_data::scope_add(
                            sv,
                            pf,
                            out,
                            client_data::ScopeAdd {
                                host,
                                exclude,
                                scheme,
                                port,
                                path,
                                allow_private,
                            },
                        )
                        .await
                    }
                }
            });
        }
        Cmd::Rules { conn, out, cmd } => {
            let (sv, pf) = (conn.server.as_deref(), conn.profile.as_deref());
            return tokio::runtime::Runtime::new()?.block_on(async {
                match cmd {
                    RulesCmd::Get => client_data::rules_get(sv, pf, out).await,
                    RulesCmd::Set { file } => client_data::rules_write(sv, pf, out, &file, false).await,
                    RulesCmd::Import { file } => client_data::rules_write(sv, pf, out, &file, true).await,
                }
            });
        }
        Cmd::Intercept { conn, out, cmd } => {
            let (sv, pf) = (conn.server.as_deref(), conn.profile.as_deref());
            return tokio::runtime::Runtime::new()?.block_on(async {
                match cmd {
                    InterceptCmd::On {
                        responses,
                        in_scope_only,
                    } => {
                        client_data::intercept_set(
                            sv,
                            pf,
                            out,
                            Some(client_data::InterceptOn {
                                responses,
                                in_scope_only,
                            }),
                        )
                        .await
                    }
                    InterceptCmd::Off => client_data::intercept_set(sv, pf, out, None).await,
                    InterceptCmd::Status => client_data::intercept_status(sv, pf, out).await,
                    InterceptCmd::Queue => client_data::intercept_queue(sv, pf, out).await,
                    InterceptCmd::Forward { id } => client_data::intercept_forward(sv, pf, out, id).await,
                    InterceptCmd::Drop { id } => client_data::intercept_drop(sv, pf, out, id).await,
                }
            });
        }
        Cmd::Events {
            conn,
            out,
            follow,
            count,
        } => {
            return tokio::runtime::Runtime::new()?.block_on(client_data::events(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                out,
                follow,
                count,
            ));
        }
        Cmd::Intruder {
            cmd:
                IntruderCmd::Run {
                    plan,
                    conn,
                    format,
                    out,
                    exact,
                },
        } => {
            return tokio::runtime::Runtime::new()?.block_on(client_cmd::intruder_run(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                &plan,
                exact,
                &format,
                out.as_deref(),
            ));
        }
        Cmd::Import {
            format,
            file,
            conn,
            base_url,
            dry_run,
            json,
        } => {
            return tokio::runtime::Runtime::new()?.block_on(client_cmd::import(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                client_cmd::ImportArgs {
                    format,
                    file,
                    base_url,
                    dry_run,
                    json_out: json,
                },
            ));
        }
        Cmd::Repeater {
            cmd:
                RepeaterCmd::Send {
                    target,
                    file,
                    conn,
                    http2,
                    count,
                    mode,
                    update_content_length,
                    verify_tls,
                    follow_redirects,
                    exact,
                    include,
                    json,
                },
        } => {
            let a = client_cmd::SendArgs {
                include,
                target,
                file,
                http2,
                count,
                mode,
                update_content_length,
                verify_tls,
                follow: follow_redirects,
                exact,
                json_out: json,
            };
            return tokio::runtime::Runtime::new()?.block_on(client_cmd::repeater_send(
                conn.server.as_deref(),
                conn.profile.as_deref(),
                a,
            ));
        }
        Cmd::Decode {
            steps,
            file,
            smart,
            list,
            limit,
        } => return decode_cmd(&steps, file.as_deref(), smart, list, limit),
        Cmd::Project { cmd } => return admin_cmd::project(&paths, cmd),
        Cmd::Token { cmd } => return admin_cmd::token(&paths, cmd),
        Cmd::Audit(a) => return admin_cmd::audit_log(&paths, a),
        Cmd::Completions { shell } => return admin_cmd::completions(shell, Cli::command()),
        Cmd::Man { out } => return admin_cmd::man_pages(Cli::command(), &out),
        Cmd::ExampleConfig => print!("{}", include_str!("../../../bosun.toml.example")),
    }
    Ok(ExitCode::SUCCESS)
}

/// `bosun decode`: the Decoder's chain on stdin or a file. Exit code 0 on success, 2 on a failed step.
fn decode_cmd(
    steps: &[String],
    file: Option<&std::path::Path>,
    smart: bool,
    list: bool,
    limit: usize,
) -> Result<ExitCode> {
    use std::io::Read;
    if list {
        for op in bosun_codec::Op::ALL {
            println!("{}", op.name());
        }
        return Ok(ExitCode::SUCCESS);
    }
    let ops = steps
        .iter()
        .map(|s| {
            bosun_codec::Op::from_name(s).with_context(|| format!("unknown operation `{s}` (see --list)"))
        })
        .collect::<Result<Vec<_>>>()?;
    if smart && !ops.is_empty() {
        bail!("--smart is for when no steps are given");
    }
    let mut input = Vec::new();
    match file {
        Some(p) => input = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => {
            std::io::stdin()
                .lock()
                .take(limit as u64 + 1)
                .read_to_end(&mut input)?;
        }
    }
    if input.len() > limit {
        bail!("the input is larger than the {limit}-byte limit");
    }
    let out = if smart || ops.is_empty() {
        let layers = bosun_codec::smart_decode(&input, limit, 16);
        for (op, _) in &layers {
            eprintln!("{}", op.name());
        }
        layers.into_iter().last().map_or(input, |(_, o)| o)
    } else {
        let (mut outs, err) = bosun_codec::apply_chain(&ops, &input, limit);
        if let Some((step, e)) = err {
            eprintln!("step {} ({}): {e}", step + 1, ops[step].name());
            return Ok(ExitCode::from(2));
        }
        outs.pop().unwrap_or(input)
    };
    std::io::stdout().lock().write_all(&out)?;
    Ok(ExitCode::SUCCESS)
}

fn read_password() -> Result<String> {
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        // Typed at a terminal: not echoed.
        rpassword::prompt_password("password (min 12 characters): ")?
    } else {
        eprint!("password (min 12 characters, read from stdin): ");
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    bosun_api::auth::check_password_policy(&pw).map_err(anyhow::Error::msg)?;
    Ok(pw)
}

async fn serve(cfg: Config) -> Result<()> {
    let engine = Engine::start(&cfg).await?;
    banner::print();
    eprintln!();
    eprintln!("  Bosun {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  proxy     http://{}", engine.proxy_addr);
    eprintln!("  web UI    {}", engine.ui_url());
    eprintln!("  project   {}", engine.project_path.display());
    if let Some(f) = &engine.ui_fingerprint {
        eprintln!("  UI cert   {f}");
    }
    eprintln!("  CA        {}", engine.ca_fingerprint);
    if let Some(code) = &engine.setup_code {
        eprintln!();
        eprintln!("  First run: open the link above, or enter this one-time setup code: {code}");
    }
    eprintln!();
    shutdown_signal().await;
    eprintln!("shutting down");
    engine.shutdown().await;
    Ok(())
}

/// `bosun serve --no-ui`: the proxy and the recorder only.
async fn serve_no_ui(cfg: Config) -> Result<()> {
    let engine = Engine::start_opts(&cfg, false, true).await?;
    eprintln!(
        "  Bosun {} (recording only, no web UI)",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  proxy     http://{}", engine.proxy_addr);
    eprintln!("  project   {}", engine.project_path.display());
    eprintln!("  CA        {}", engine.ca_fingerprint);
    shutdown_signal().await;
    eprintln!("shutting down");
    engine.shutdown().await;
    Ok(())
}

/// The embedded mode of `bosun serve`: the parent app reads one JSON line, and ending its end of our stdin (or
/// dying, which closes it) stops the engine.
async fn serve_embedded(cfg: Config) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let engine = Engine::start_with(&cfg, true).await?;
    let handshake = serde_json::json!({
        "api_url": engine.api_url(),
        "proxy_addr": engine.proxy_addr.to_string(),
        "ca_spki": engine.ca_spki,
        "login_ticket": engine.login_ticket,
        "version": env!("CARGO_PKG_VERSION"),
    });
    {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{handshake}")?;
        out.flush()?;
    }
    let parent_gone = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 256];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };
    tokio::select! {
        () = parent_gone => tracing::info!("the parent process closed stdin; shutting down"),
        () = shutdown_signal() => {}
    }
    engine.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        // Ctrl-C, Ctrl-Break, closing the console window, logging off and shutting down all mean "stop cleanly".
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_shutdown};
        match (ctrl_break(), ctrl_close(), ctrl_shutdown()) {
            (Ok(mut brk), Ok(mut close), Ok(mut down)) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = brk.recv() => {}
                    _ = close.recv() => {}
                    _ = down.recv() => {}
                }
            }
            _ => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
