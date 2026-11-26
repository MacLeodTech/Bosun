//! Local administration: projects, API tokens, sessions, roles, the audit log, shell completions and man pages.
//!
//! These commands work on the data directory directly and need no running engine. Anything that opens or moves a
//! project file refuses, with exit code 3, when another Bosun process holds the project (the engine does, while it
//! runs); account commands share the account database with a running engine safely. Everything that changes
//! accounts, tokens, sessions or projects writes an audit entry ("via CLI"), as the API does.
//!
//! Exit codes (all commands in this file):
//!
//! * 0 success
//! * 1 failure (bad input, a name that is taken, a damaged file, an I/O error)
//! * 2 usage error (reported by the argument parser)
//! * 3 refused: the project is open in a running Bosun process
//! * 4 not found: no such project, user, token or session
//! * 5 not confirmed: a delete needs `--yes` when stdin is not a terminal, or the name typed did not match

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use bosun::Paths;
use bosun_store::{ApiToken, AppDb, Project, ProjectLock, Role, StoreError, TokenScope, User};
use clap::{Subcommand, ValueEnum};
use serde::Serialize;

const EXT: &str = "bosun";
/// The key the API keeps its recent-projects list under (names, newest first).
const RECENT_KEY: &str = "recent_projects";

pub const EXIT_LOCKED: u8 = 3;
pub const EXIT_NOT_FOUND: u8 = 4;
pub const EXIT_NOT_CONFIRMED: u8 = 5;

/// An error that carries its exit code.
#[derive(Debug)]
struct Exit(u8, String);

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for Exit {}

/// The exit code for an error from this module (1 for anything else).
pub fn exit_code(e: &anyhow::Error) -> ExitCode {
    ExitCode::from(e.downcast_ref::<Exit>().map_or(1, |x| x.0))
}

fn not_found(what: &str) -> anyhow::Error {
    Exit(EXIT_NOT_FOUND, format!("no such {what}")).into()
}

fn store_err(e: StoreError) -> anyhow::Error {
    match e {
        StoreError::Locked(m) => Exit(
            EXIT_LOCKED,
            format!("{m}; stop the engine that has it open (or use the UI or API) and try again"),
        )
        .into(),
        StoreError::Untrusted(m) => anyhow!("not a usable Bosun project: {m}"),
        e => anyhow!(e),
    }
}

// ---- Command definitions --------------------------------------------------------------------------------------

/// Manage the projects in the data directory. Exit codes: 0 ok, 1 failure, 3 the project is open in a running
/// Bosun, 4 no such project, 5 a delete was not confirmed.
#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    /// List the projects (name, size, last change, and whether a running Bosun has it open).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Create an empty project.
    Create { name: String },
    /// Rename a project.
    Rename { name: String, new_name: String },
    /// Delete a project and its files. Asks you to type the name; with no terminal, `--yes` is required.
    Delete {
        name: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
    /// Write a consistent, compacted copy of a project to FILE (which must not exist).
    Export {
        name: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Import a project file from someone else under NAME (default: the file's name). The file is checked and
    /// rebuilt into a new project; it is never opened in place.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Back a project up into `<projects>/backups/` (or to --out).
    Backup {
        name: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

/// Manage API tokens (the owner is a username). The token itself is shown once, when it is created. Exit codes: 0
/// ok, 1 failure, 4 no such user or token.
#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    /// Create a token for a user. Prints the token on stdout (and nothing else unless --json).
    Create {
        username: String,
        #[arg(long)]
        name: String,
        /// `read` tokens can only make GET requests.
        #[arg(long, value_enum, default_value = "full")]
        scope: ScopeArg,
        /// Days until it stops working (1 to 3650); default: never.
        #[arg(long)]
        expires_days: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// List the tokens of one user, or of everyone.
    List {
        username: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Revoke a token by its id (see `token list`).
    Revoke { id: i64 },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScopeArg {
    Read,
    Full,
}

/// More account commands, next to `user add`, `passwd` and `list`. Exit codes: 0 ok, 1 failure (for instance
/// removing the last admin), 4 no such user, 5 a delete was not confirmed.
#[derive(Subcommand, Debug)]
pub enum UserAdminCmd {
    /// Change a role (viewer, tester or admin). The user is signed out so the new role applies at once.
    Role {
        username: String,
        #[arg(value_parser = ["viewer", "tester", "admin"])]
        role: String,
    },
    /// Delete an account, its sessions and its tokens. Asks you to type the name; with no terminal, `--yes`.
    Delete {
        username: String,
        #[arg(long)]
        yes: bool,
    },
    /// List a user's signed-in sessions, or end them all with --revoke.
    Sessions {
        username: String,
        #[arg(long)]
        revoke: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Show the audit log, newest first. Exit codes: 0 ok, 1 failure.
#[derive(clap::Args, Debug)]
pub struct AuditArgs {
    /// How many entries to show.
    #[arg(short = 'n', long, default_value_t = 50)]
    pub limit: usize,
    /// Only entries older than this id (for the next page).
    #[arg(long)]
    pub before: Option<i64>,
    /// Only actions starting with this text, such as `project.` or `user.role`.
    #[arg(long)]
    pub action: Option<String>,
    /// Only entries by this account (`-` for entries made from the CLI).
    #[arg(long)]
    pub user: Option<String>,
    /// One JSON array.
    #[arg(long)]
    pub json: bool,
}

// ---- Helpers --------------------------------------------------------------------------------------------------

fn open_app(paths: &Paths) -> Result<AppDb> {
    bosun::private_dir(&paths.data)?;
    AppDb::open(&paths.app_db()).context("cannot open the account database")
}

fn audit(app: &AppDb, action: &str, detail: &str) -> Result<()> {
    app.audit(None, action, &format!("{detail} via CLI"), None)?;
    Ok(())
}

fn json_out<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Ask the user to type `expect`, unless `yes`. With no terminal there is nobody to ask.
fn confirm(what: &str, expect: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(Exit(
            EXIT_NOT_CONFIRMED,
            format!("refusing to {what} without confirmation: pass --yes"),
        )
        .into());
    }
    eprint!("To {what}, type {expect}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if line.trim_end_matches(['\r', '\n']) == expect {
        Ok(())
    } else {
        Err(Exit(EXIT_NOT_CONFIRMED, "not confirmed; nothing was changed".into()).into())
    }
}

fn find_user(app: &AppDb, name: &str) -> Result<User> {
    app.list_users()?
        .into_iter()
        .find(|u| u.username.eq_ignore_ascii_case(name))
        .ok_or_else(|| not_found("user"))
}

// ---- Projects -------------------------------------------------------------------------------------------------

struct Entry {
    name: String,
    size: u64,
    modified_ms: i64,
}

/// The projects in the directory. Links, hidden files and other kinds of file are not projects.
fn scan(dir: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    for e in rd {
        let e = e?;
        let Ok(m) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        let file = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = file.strip_suffix(&format!(".{EXT}")) else {
            continue;
        };
        if !m.is_file() || stem.starts_with('.') || bosun_api::projects::valid_name(stem).is_err() {
            continue;
        }
        let modified_ms = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as i64);
        out.push(Entry {
            name: stem.to_string(),
            size: m.len(),
            modified_ms,
        });
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

/// The stored spelling of a project's name (names compare without regard to case, because some file systems do).
fn find_project(dir: &Path, name: &str) -> Result<Option<String>> {
    Ok(scan(dir)?
        .into_iter()
        .map(|e| e.name)
        .find(|n| n.eq_ignore_ascii_case(name)))
}

fn existing_project(dir: &Path, name: &str) -> Result<String> {
    find_project(dir, name)?.ok_or_else(|| not_found("project"))
}

fn file_of(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.{EXT}"))
}

/// Removes a half-made file (and what SQLite keeps beside it) unless told to keep it.
struct Temp(Option<PathBuf>);

impl Temp {
    fn new(dir: &Path, what: &str) -> Self {
        Self(Some(
            dir.join(format!(".{what}-{}.tmp", bosun_api::auth::random_token())),
        ))
    }
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or(Path::new(""))
    }
    /// The file is now a project under its real name: drop only what was kept beside the temporary name.
    fn keep(mut self) {
        if let Some(p) = self.0.take() {
            for suffix in ["-wal", "-shm", "-journal", ".lock"] {
                let mut q = p.as_os_str().to_owned();
                q.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(q));
            }
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            for suffix in ["", "-wal", "-shm", "-journal", ".lock"] {
                let mut q = p.as_os_str().to_owned();
                q.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(q));
            }
        }
    }
}

/// Opening a rebuilt copy may have upgraded it, which first copies it to `<file>.pre-v<N>.bak`; the copy is of a
/// file we made a moment ago, so the extra file is only clutter.
fn remove_upgrade_copies(file: &Path) {
    let (Some(dir), Some(name)) = (
        file.parent(),
        file.file_name().map(|n| n.to_string_lossy().into_owned()),
    ) else {
        return;
    };
    let prefix = format!("{name}.pre-v");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn recent_edit(app: &AppDb, f: impl FnOnce(Vec<String>) -> Vec<String>) {
    let list: Vec<String> = app
        .meta(RECENT_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();
    let new = f(list);
    let _ = app.set_meta(RECENT_KEY, &serde_json::to_string(&new).unwrap_or_default());
}

fn valid_name(n: &str) -> Result<()> {
    bosun_api::projects::valid_name(n).map_err(|e| anyhow!("{e}"))
}

pub fn project(paths: &Paths, cmd: ProjectCmd) -> Result<ExitCode> {
    bosun::private_dir(&paths.data)?;
    let dir = paths.projects();
    match cmd {
        ProjectCmd::List { json } => {
            #[derive(Serialize)]
            struct Row {
                name: String,
                size_bytes: u64,
                modified_ms: i64,
                /// A running Bosun has it open.
                locked: bool,
            }
            let rows: Vec<Row> = scan(&dir)?
                .into_iter()
                .map(|e| {
                    let locked = matches!(
                        ProjectLock::take(&file_of(&dir, &e.name)),
                        Err(StoreError::Locked(_))
                    );
                    Row {
                        name: e.name,
                        size_bytes: e.size,
                        modified_ms: e.modified_ms,
                        locked,
                    }
                })
                .collect();
            if json {
                json_out(&rows)?;
            } else {
                for r in &rows {
                    println!(
                        "{:<32} {:>12} bytes  {}{}",
                        r.name,
                        r.size_bytes,
                        fmt_time(r.modified_ms),
                        if r.locked {
                            "  (open in a running Bosun)"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        ProjectCmd::Create { name } => {
            valid_name(&name)?;
            bosun::private_dir(&dir)?;
            if find_project(&dir, &name)?.is_some() {
                bail!("a project named {name} already exists");
            }
            let path = file_of(&dir, &name);
            Project::open(&path).map(drop).map_err(store_err)?;
            audit(&open_app(paths)?, "project.create", &name)?;
            println!("created {}", path.display());
        }
        ProjectCmd::Rename { name, new_name } => {
            valid_name(&new_name)?;
            let from = existing_project(&dir, &name)?;
            if let Some(t) = find_project(&dir, &new_name)?
                && !t.eq_ignore_ascii_case(&from)
            {
                bail!("a project named {new_name} already exists");
            }
            let (src, dst) = (file_of(&dir, &from), file_of(&dir, &new_name));
            {
                // The lock proves nobody has it open; settling folds a leftover log into the file so it moves whole.
                let _lock = ProjectLock::take(&src).map_err(store_err)?;
                bosun_store::settle(&src).map_err(store_err)?;
                std::fs::rename(&src, &dst).with_context(|| format!("cannot rename {}", src.display()))?;
            }
            let app = open_app(paths)?;
            recent_edit(&app, |l| {
                l.into_iter()
                    .map(|n| {
                        if n.eq_ignore_ascii_case(&from) {
                            new_name.clone()
                        } else {
                            n
                        }
                    })
                    .collect()
            });
            audit(&app, "project.rename", &format!("{from} -> {new_name}"))?;
            println!("renamed {from} to {new_name}");
        }
        ProjectCmd::Delete { name, yes } => {
            let found = existing_project(&dir, &name)?;
            let lock = ProjectLock::take(&file_of(&dir, &found)).map_err(store_err)?;
            confirm(
                &format!("delete project {found} and all it recorded"),
                &found,
                yes,
            )?;
            lock.delete_files().map_err(store_err)?;
            drop(lock);
            let app = open_app(paths)?;
            recent_edit(&app, |l| {
                l.into_iter()
                    .filter(|n| !n.eq_ignore_ascii_case(&found))
                    .collect()
            });
            audit(&app, "project.delete", &found)?;
            println!("deleted {found}");
        }
        ProjectCmd::Export { name, out } => {
            let found = existing_project(&dir, &name)?;
            copy_out(&dir, &found, &out)?;
            audit(
                &open_app(paths)?,
                "project.export",
                &format!("{found} -> {}", out.display()),
            )?;
            println!("exported {found} to {}", out.display());
        }
        ProjectCmd::Backup { name, out, json } => {
            let found = existing_project(&dir, &name)?;
            let dest = match out {
                Some(o) => o,
                None => {
                    let b = dir.join("backups");
                    std::fs::create_dir_all(&b).with_context(|| format!("cannot create {}", b.display()))?;
                    b.join(format!("{found}-{}.{EXT}", bosun_model::now_ms() / 1000))
                }
            };
            copy_out(&dir, &found, &dest)?;
            let size = std::fs::metadata(&dest).map_or(0, |m| m.len());
            audit(
                &open_app(paths)?,
                "project.backup",
                &format!("{found} -> {}", dest.display()),
            )?;
            if json {
                json_out(&serde_json::json!({ "path": dest.display().to_string(), "size_bytes": size }))?;
            } else {
                println!("backed up {found} to {} ({size} bytes)", dest.display());
            }
        }
        ProjectCmd::Import { file, name } => {
            let name = match name {
                Some(n) => n,
                None => file
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .context("cannot derive a project name from that file; pass --name")?,
            };
            valid_name(&name)?;
            if !file.is_file() {
                bail!("{} is not a file", file.display());
            }
            bosun::private_dir(&dir)?;
            if find_project(&dir, &name)?.is_some() {
                bail!("a project named {name} already exists");
            }
            let app = open_app(paths)?;
            let rebuilt = Temp::new(&dir, "rebuilt");
            let fin = file_of(&dir, &name);
            let checked = (|| -> Result<(), StoreError> {
                bosun_store::import_foreign(&file, rebuilt.path())?;
                // Our own opening checks, and the migration to the current schema, on the rebuilt copy.
                Project::open(rebuilt.path()).map(drop)?;
                bosun_store::settle(rebuilt.path())?;
                remove_upgrade_copies(rebuilt.path());
                std::fs::rename(rebuilt.path(), &fin)
                    .map_err(|e| StoreError::Io(fin.display().to_string(), e))
            })();
            if let Err(e) = checked {
                let _ = audit(&app, "project.import.refused", &format!("{name}: {e}"));
                return Err(store_err(e));
            }
            rebuilt.keep();
            audit(&app, "project.import", &format!("{name} from {}", file.display()))?;
            println!("imported {name}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// A snapshot of project `name` at `dest`, which must not exist (SQLite's `VACUUM INTO`, so it is compact and
/// consistent). The project must not be open in a running Bosun.
fn copy_out(dir: &Path, name: &str, dest: &Path) -> Result<()> {
    if dest.exists() {
        bail!("{} already exists; choose a new file", dest.display());
    }
    let p = Project::open(&file_of(dir, name)).map_err(store_err)?;
    let r = p.backup_to(dest);
    drop(p);
    if let Err(e) = r {
        let _ = std::fs::remove_file(dest);
        return Err(store_err(e));
    }
    Ok(())
}

// ---- Users ----------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct SessionRow {
    id: String,
    created_ms: i64,
    expires_ms: i64,
}

pub fn user(paths: &Paths, cmd: UserAdminCmd) -> Result<ExitCode> {
    let app = open_app(paths)?;
    match cmd {
        UserAdminCmd::Role { username, role } => {
            let u = find_user(&app, &username)?;
            let role = Role::parse(&role).context("role must be viewer, tester or admin")?;
            if !app.set_role(u.id, role).map_err(store_err)? {
                return Err(not_found("user"));
            }
            app.revoke_sessions(u.id)?;
            audit(&app, "user.role", &format!("{} -> {}", u.username, role.as_str()))?;
            println!("{} is now {}; signed out everywhere", u.username, role.as_str());
        }
        UserAdminCmd::Delete { username, yes } => {
            let u = find_user(&app, &username)?;
            confirm(&format!("delete the account {}", u.username), &u.username, yes)?;
            if !app.delete_user(u.id).map_err(store_err)? {
                return Err(not_found("user"));
            }
            audit(&app, "user.delete", &u.username)?;
            println!("deleted {}", u.username);
        }
        UserAdminCmd::Sessions {
            username,
            revoke,
            json,
        } => {
            let u = find_user(&app, &username)?;
            if revoke {
                let n = app.revoke_sessions(u.id)?;
                audit(
                    &app,
                    "session.revoke_all",
                    &format!("{}, {n} sessions", u.username),
                )?;
                if json {
                    json_out(&serde_json::json!({ "revoked": n }))?;
                } else {
                    println!("ended {n} session(s) of {}", u.username);
                }
            } else {
                let rows: Vec<SessionRow> = app
                    .list_sessions(u.id)?
                    .into_iter()
                    .map(|s| SessionRow {
                        id: s.id,
                        created_ms: s.created_ms,
                        expires_ms: s.expires_ms,
                    })
                    .collect();
                if json {
                    json_out(&rows)?;
                } else {
                    for r in &rows {
                        println!(
                            "{}  created {}  expires {}",
                            r.id,
                            fmt_time(r.created_ms),
                            fmt_time(r.expires_ms)
                        );
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The users for `bosun user list --json`.
pub fn user_list_json(paths: &Paths) -> Result<ExitCode> {
    json_out(&open_app(paths)?.list_users()?)?;
    Ok(ExitCode::SUCCESS)
}

// ---- Tokens ---------------------------------------------------------------------------------------------------

fn token_line(u: &str, t: &ApiToken) -> String {
    format!(
        "{:>4}  {:<16} {:<5} {:<20} created {}  expires {}  last used {}",
        t.id,
        u,
        t.scope.as_str(),
        t.name,
        fmt_time(t.created_ms),
        t.expires_ms.map_or("never".into(), fmt_time),
        t.last_used_ms.map_or("never".into(), fmt_time),
    )
}

pub fn token(paths: &Paths, cmd: TokenCmd) -> Result<ExitCode> {
    let app = open_app(paths)?;
    match cmd {
        TokenCmd::Create {
            username,
            name,
            scope,
            expires_days,
            json,
        } => {
            let u = find_user(&app, &username)?;
            if name.is_empty() || name.len() > 64 {
                bail!("token names are 1-64 characters");
            }
            if expires_days.is_some_and(|d| d == 0 || d > 3650) {
                bail!("--expires-days must be between 1 and 3650");
            }
            let scope = match scope {
                ScopeArg::Read => TokenScope::Read,
                ScopeArg::Full => TokenScope::Full,
            };
            let expires = expires_days.map(|d| bosun_model::now_ms() + i64::from(d) * 86_400_000);
            let token = format!("bosun_{}", bosun_api::auth::random_token());
            let info = app.create_api_token(&name, &token, u.id, scope, expires)?;
            audit(
                &app,
                "token.create",
                &format!(
                    "{} for {} ({}, {})",
                    name,
                    u.username,
                    scope.as_str(),
                    expires_days.map_or("no expiry".into(), |d| format!("{d} days"))
                ),
            )?;
            if json {
                json_out(&serde_json::json!({ "token": token, "info": info }))?;
            } else {
                // Only the token goes to stdout, so `T=$(bosun token create ...)` works.
                println!("{token}");
                eprintln!(
                    "token {} created for {}; it is shown only now",
                    info.id, u.username
                );
            }
        }
        TokenCmd::List { username, json } => {
            let users = match &username {
                Some(n) => vec![find_user(&app, n)?],
                None => app.list_users()?,
            };
            let mut rows = Vec::new();
            for u in users {
                for t in app.list_api_tokens(u.id)? {
                    rows.push((u.username.clone(), t));
                }
            }
            if json {
                #[derive(Serialize)]
                struct Row<'a> {
                    username: &'a str,
                    #[serde(flatten)]
                    token: &'a ApiToken,
                }
                let out: Vec<Row> = rows
                    .iter()
                    .map(|(u, t)| Row {
                        username: u,
                        token: t,
                    })
                    .collect();
                json_out(&out)?;
            } else {
                for (u, t) in &rows {
                    println!("{}", token_line(u, t));
                }
            }
        }
        TokenCmd::Revoke { id } => {
            for u in app.list_users()? {
                if app.delete_api_token(id, u.id)? {
                    audit(&app, "token.revoke", &format!("user {}, token {id}", u.username))?;
                    println!("revoked token {id} of {}", u.username);
                    return Ok(ExitCode::SUCCESS);
                }
            }
            return Err(not_found("token"));
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---- Audit log ------------------------------------------------------------------------------------------------

pub fn audit_log(paths: &Paths, a: AuditArgs) -> Result<ExitCode> {
    let app = open_app(paths)?;
    let mut out = Vec::new();
    let mut before = a.before;
    'pages: loop {
        let page = app.audit_log(before, 500)?;
        let n = page.len();
        for e in page {
            before = Some(e.id);
            let by = e.username.as_deref().unwrap_or("-");
            if a.action.as_deref().is_some_and(|p| !e.action.starts_with(p))
                || a.user.as_deref().is_some_and(|u| !by.eq_ignore_ascii_case(u))
            {
                continue;
            }
            out.push(e);
            if out.len() >= a.limit {
                break 'pages;
            }
        }
        if n < 500 {
            break;
        }
    }
    if a.json {
        json_out(&out)?;
    } else {
        for e in &out {
            println!(
                "{:>6}  {}  {:<12} {:<22} {}{}",
                e.id,
                fmt_time(e.time_ms),
                e.username.as_deref().unwrap_or("-"),
                e.action,
                e.detail,
                e.remote.as_deref().map_or(String::new(), |r| format!("  [{r}]"))
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---- Completions and man pages --------------------------------------------------------------------------------

pub fn completions(shell: clap_complete::Shell, mut cmd: clap::Command) -> Result<ExitCode> {
    clap_complete::generate(shell, &mut cmd, "bosun", &mut std::io::stdout());
    Ok(ExitCode::SUCCESS)
}

/// Write `bosun.1` and one page per subcommand (`bosun-project-list.1`, ...) to `out`.
pub fn man_pages(cmd: clap::Command, out: &Path) -> Result<ExitCode> {
    std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut n = 0;
    fn walk(cmd: &clap::Command, name: &str, out: &Path, n: &mut usize) -> Result<()> {
        // clap wants 'static names; a few short strings in a one-shot command.
        let name: &'static str = Box::leak(name.to_string().into_boxed_str());
        let cmd = cmd.clone().name(name).bin_name(name);
        let mut buf = Vec::new();
        clap_mangen::Man::new(cmd.clone()).render(&mut buf)?;
        let file = out.join(format!("{name}.1"));
        std::fs::write(&file, buf).with_context(|| format!("cannot write {}", file.display()))?;
        *n += 1;
        for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
            walk(sub, &format!("{name}-{}", sub.get_name()), out, n)?;
        }
        Ok(())
    }
    walk(&cmd, "bosun", out, &mut n)?;
    eprintln!("wrote {n} man pages to {}", out.display());
    Ok(ExitCode::SUCCESS)
}
