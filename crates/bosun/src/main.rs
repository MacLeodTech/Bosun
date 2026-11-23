//! The `bosun` command.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use bosun::{Config, Engine, Paths, doctor};
use bosun_store::{AppDb, Role};
use clap::{Parser, Subcommand};

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
    },
    /// Check the install for common problems.
    Doctor,
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
    /// Print an example configuration file.
    ExampleConfig,
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
    },
    /// Show the fingerprint and SPKI hash.
    Info,
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
    Passwd {
        username: String,
    },
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("BOSUN_LOG")
                .unwrap_or_else(|_| "info,hyper=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
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
            cfg.proxy.validate().map_err(anyhow::Error::msg)?;
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(serve(cfg))?;
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
        Cmd::Ca { cmd } => {
            bosun::private_dir(&paths.data)?;
            let ca = bosun::load_ca(&cfg, &paths)?;
            match cmd {
                CaCmd::Export { out, der } => {
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
                }
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
                UserCmd::List => {
                    for u in app.list_users()? {
                        println!("{:>4}  {:<24} {}", u.id, u.username, u.role.as_str());
                    }
                }
            }
        }
        Cmd::ExampleConfig => print!("{}", include_str!("../../../bosun.toml.example")),
    }
    Ok(ExitCode::SUCCESS)
}

fn read_password() -> Result<String> {
    eprint!("password (min 12 characters, read from stdin): ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']).to_string();
    bosun_api::auth::check_password_policy(&pw).map_err(anyhow::Error::msg)?;
    Ok(pw)
}

async fn serve(cfg: Config) -> Result<()> {
    let engine = Engine::start(&cfg).await?;
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
