//! Projects at run time: list, create, open (switch), close, rename, delete, export, import and back up.
//!
//! Projects are addressed by name only: a name maps to `<projects dir>/<name>.bosun`, so no request can reach a
//! file elsewhere. Everything here needs the admin role (switching changes what every connected user sees) except
//! listing, and every operation is audited.
//!
//! Switching opens the new project first (so a locked, damaged or hostile file leaves the old one running), then
//! swaps the recorder, scope, rules and intercept settings together and tells connected clients to reload. Held
//! intercept messages are dropped, and interception starts off in the new project, as it does at start-up.
//! "Closing" a project opens a temporary one in memory, which is gone when something else is opened.

use std::path::{Path as FsPath, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bosun_proxy::{InterceptSettings, ProxyEvent, ResponseFilter, RuleSpec};
use bosun_scope::{Scope, ScopeSpec};
use bosun_store::{Project, ProjectLock, Role, StoreError};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::auth::Caller;
use crate::security::{empty, reject};
use crate::{AppState, SETTING_INTERCEPT, SETTING_RESPONSE_FILTER, SETTING_RULES, SETTING_SCOPE};

type R = Result<Response, Response>;

const RECENT_KEY: &str = "recent_projects";
const RECENT_MAX: usize = 10;
const EXT: &str = "bosun";
/// Names the router uses for its own routes under `/projects/`.
const RESERVED: &[&str] = &["close", "import"];

/// Where the engine keeps projects, and which one is open.
pub struct Manager {
    dir: PathBuf,
    /// Held for writing while the project is switched, and for reading by anything that saves a setting, so a
    /// setting is never saved to one project and applied to another.
    settings: tokio::sync::RwLock<()>,
    /// One project operation at a time.
    ops: tokio::sync::Mutex<()>,
    current: Mutex<Current>,
    max_upload: u64,
}

#[derive(Clone, Debug)]
struct Current {
    name: Option<String>,
    /// Opened by path from outside the projects directory: it can be used but not managed here.
    external: bool,
}

impl Manager {
    pub(crate) fn new(dir: PathBuf, open: Option<&FsPath>, max_upload: u64) -> Self {
        let current = match open {
            None => Current {
                name: None,
                external: false,
            },
            Some(p) => Current {
                name: p.file_stem().map(|s| s.to_string_lossy().into_owned()),
                external: p.parent() != Some(dir.as_path()) || p.extension().is_none_or(|e| e != EXT),
            },
        };
        Self {
            dir,
            settings: tokio::sync::RwLock::new(()),
            ops: tokio::sync::Mutex::new(()),
            current: Mutex::new(current),
            max_upload,
        }
    }

    /// Taken by handlers that save a project setting.
    pub(crate) async fn settings_guard(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.settings.read().await
    }

    fn current(&self) -> Current {
        self.current.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.{EXT}"))
    }

    fn backups(&self) -> PathBuf {
        self.dir.join("backups")
    }

    /// The projects in the directory: (name, size, modified in ms). Links, hidden files and other kinds of file
    /// are not projects.
    fn scan(&self) -> std::io::Result<Vec<(String, u64, i64)>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(&format!(".{EXT}")) else {
                continue;
            };
            if !m.is_file() || stem.starts_with('.') || valid_name(stem).is_err() {
                continue;
            }
            let modified = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_millis() as i64);
            out.push((stem.to_string(), m.len(), modified));
        }
        out.sort_by_key(|a| a.0.to_lowercase());
        Ok(out)
    }

    /// The stored spelling of `name`, if a project by that name exists (names compare without regard to case,
    /// because some file systems do).
    fn existing(&self, name: &str) -> Option<String> {
        self.scan()
            .ok()?
            .into_iter()
            .map(|e| e.0)
            .find(|n| n.eq_ignore_ascii_case(name))
    }
}

/// A project name: what can go in a file name on every system, and nothing that looks like a path.
pub fn valid_name(n: &str) -> Result<(), &'static str> {
    if n.is_empty() || n.chars().count() > 64 {
        return Err("a project name is 1 to 64 characters");
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
    {
        return Err("a project name may use letters, digits, spaces, dots, dashes and underscores");
    }
    if n.starts_with(['.', '-', ' ']) || n.ends_with(['.', ' ']) || n.contains("..") {
        return Err("a project name cannot start with a dot, dash or space, or end with a dot or space");
    }
    let stem = n.split('.').next().unwrap_or(n).trim_end().to_ascii_uppercase();
    let reserved_device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved_device {
        return Err("that name is reserved by Windows");
    }
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(n)) {
        return Err("that name is used by the API itself");
    }
    Ok(())
}

// ---- Wire types -----------------------------------------------------------------------------------------------

/// The project that is open.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CurrentProject {
    /// Empty for the temporary project.
    pub name: Option<String>,
    /// An in-memory project that is gone when another is opened.
    pub temporary: bool,
    /// Opened by path from outside the projects directory (`bosun serve --project /path/x.bosun`): in use, but
    /// not managed through this API.
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProjectInfo {
    pub name: String,
    pub size_bytes: u64,
    pub modified_ms: i64,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProjectList {
    pub current: CurrentProject,
    pub projects: Vec<ProjectInfo>,
    /// Names last opened, newest first.
    pub recent: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct NewProject {
    pub name: String,
    /// Open it straight away.
    #[serde(default)]
    pub open: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RenameProject {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct BackupInfo {
    /// The backup file, in the `backups` folder of the projects directory.
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Deserialize)]
pub struct ImportQuery {
    pub name: String,
    #[serde(default)]
    pub open: Option<bool>,
}

fn current_json(c: &Current) -> CurrentProject {
    CurrentProject {
        name: c.name.clone(),
        temporary: c.name.is_none(),
        external: c.external,
    }
}

fn store_error(e: StoreError) -> Response {
    match e {
        StoreError::Locked(m) | StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
        StoreError::Untrusted(m) => reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("not a usable Bosun project: {m}"),
        ),
        StoreError::NewerSchema(v) => reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("this project was made by a newer Bosun (schema {v}); update Bosun to open it"),
        ),
        e => {
            tracing::error!(error = %e, "project operation failed");
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not complete that ({e})"),
            )
        }
    }
}

fn io_error(what: &str, e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "{what}");
    reject(StatusCode::INTERNAL_SERVER_ERROR, &format!("{what} ({e})"))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| io_error("a project task failed", e))
}

fn bad_name(why: &str) -> Response {
    reject(StatusCode::BAD_REQUEST, why)
}

/// Removes a half-made file unless told to keep it.
struct Temp(Option<PathBuf>);

impl Temp {
    fn new(p: PathBuf) -> Self {
        Self(Some(p))
    }
    fn path(&self) -> &FsPath {
        self.0.as_deref().unwrap_or(FsPath::new(""))
    }
    fn keep(mut self) -> PathBuf {
        self.0.take().unwrap_or_default()
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

/// Opening the rebuilt copy may have upgraded it, which first copies it to `<file>.pre-v<N>.bak`. The copy is of
/// a file we made ourselves a moment ago and is about to be renamed away, so the extra file is only clutter.
fn remove_upgrade_copies(file: &FsPath) {
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

fn tmp_name(dir: &FsPath, what: &str) -> PathBuf {
    dir.join(format!(".{what}-{}.tmp", crate::auth::random_token()))
}

// ---- Handlers -------------------------------------------------------------------------------------------------

async fn recent(st: &AppState) -> Vec<String> {
    st.with_app(|a| a.meta(RECENT_KEY))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default()
}

async fn touch_recent(st: &AppState, name: &str) {
    let mut list = recent(st).await;
    list.retain(|n| !n.eq_ignore_ascii_case(name));
    list.insert(0, name.to_string());
    list.truncate(RECENT_MAX);
    let json = serde_json::to_string(&list).unwrap_or_default();
    let _ = st.with_app(move |a| a.set_meta(RECENT_KEY, &json)).await;
}

async fn info_for(st: &AppState, name: &str) -> Option<ProjectInfo> {
    let m = st.inner.projects.dir.clone();
    let name = name.to_string();
    let cur = st.inner.projects.current();
    let all = blocking(move || {
        let tmp = Manager::new(m, None, 0);
        tmp.scan()
    })
    .await
    .ok()?
    .ok()?;
    all.into_iter()
        .find(|e| e.0 == name)
        .map(|(n, size, ms)| ProjectInfo {
            current: cur.name.as_deref() == Some(&n) && !cur.external,
            name: n,
            size_bytes: size,
            modified_ms: ms,
        })
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let cur = st.inner.projects.current();
    let m = st.inner.projects.dir.clone();
    let scanned = blocking(move || Manager::new(m, None, 0).scan())
        .await?
        .map_err(|e| io_error("could not read the projects folder", e))?;
    let projects = scanned
        .into_iter()
        .map(|(name, size_bytes, modified_ms)| ProjectInfo {
            current: !cur.external && cur.name.as_deref() == Some(&name),
            name,
            size_bytes,
            modified_ms,
        })
        .collect();
    Ok(Json(ProjectList {
        current: current_json(&cur),
        projects,
        recent: recent(&st).await,
    })
    .into_response())
}

pub async fn create(State(st): State<AppState>, caller: Caller, Json(b): Json<NewProject>) -> R {
    caller.require(Role::Admin)?;
    valid_name(&b.name).map_err(bad_name)?;
    let mgr = &st.inner.projects;
    let _ops = mgr.ops.lock().await;
    let (m, name) = (st.inner.projects.dir.clone(), b.name.clone());
    let path = {
        let name = name.clone();
        let exists = blocking(move || Manager::new(m, None, 0).existing(&name)).await?;
        if exists.is_some() {
            return Err(reject(
                StatusCode::CONFLICT,
                "a project with that name already exists",
            ));
        }
        mgr.file(&b.name)
    };
    blocking(move || Project::open(&path).map(drop))
        .await?
        .map_err(store_error)?;
    caller.audit(&st, "project.create", &b.name).await;
    if b.open == Some(true) {
        switch_to(&st, &caller, Some(&b.name)).await?;
    }
    let info = info_for(&st, &b.name).await;
    Ok((StatusCode::CREATED, Json(info)).into_response())
}

pub async fn open(State(st): State<AppState>, caller: Caller, Path(name): Path<String>) -> R {
    caller.require(Role::Admin)?;
    let _ops = st.inner.projects.ops.lock().await;
    let cur = switch_to(&st, &caller, Some(&name)).await?;
    Ok(Json(cur).into_response())
}

pub async fn close(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Admin)?;
    let _ops = st.inner.projects.ops.lock().await;
    let cur = switch_to(&st, &caller, None).await?;
    Ok(Json(cur).into_response())
}

pub async fn rename(
    State(st): State<AppState>,
    caller: Caller,
    Path(name): Path<String>,
    Json(b): Json<RenameProject>,
) -> R {
    caller.require(Role::Admin)?;
    valid_name(&b.name).map_err(bad_name)?;
    let mgr = &st.inner.projects;
    let _ops = mgr.ops.lock().await;
    let cur = mgr.current();
    let m = mgr.dir.clone();
    let (from_name, to_name) = (name.clone(), b.name.clone());
    let (from, to) = blocking(move || {
        let mgr = Manager::new(m, None, 0);
        (mgr.existing(&from_name), mgr.existing(&to_name))
    })
    .await?;
    let Some(from) = from else {
        return Err(reject(StatusCode::NOT_FOUND, "no such project"));
    };
    if !cur.external && cur.name.as_deref() == Some(&from) {
        return Err(reject(
            StatusCode::CONFLICT,
            "open another project first: the open one cannot be renamed",
        ));
    }
    if to.as_deref().is_some_and(|t| !t.eq_ignore_ascii_case(&from)) {
        return Err(reject(
            StatusCode::CONFLICT,
            "a project with that name already exists",
        ));
    }
    let (src, dst) = (mgr.file(&from), mgr.file(&b.name));
    blocking(move || -> Result<(), StoreError> {
        // The lock proves nobody has it open; settling folds a leftover log into the file so it moves whole.
        let lock = ProjectLock::take(&src)?;
        bosun_store::settle(&src)?;
        std::fs::rename(&src, &dst).map_err(|e| StoreError::Io(src.display().to_string(), e))?;
        drop(lock);
        Ok(())
    })
    .await?
    .map_err(store_error)?;
    caller
        .audit(&st, "project.rename", &format!("{from} -> {}", b.name))
        .await;
    let info = info_for(&st, &b.name).await;
    Ok(Json(info).into_response())
}

pub async fn delete(State(st): State<AppState>, caller: Caller, Path(name): Path<String>) -> R {
    caller.require(Role::Admin)?;
    let mgr = &st.inner.projects;
    let _ops = mgr.ops.lock().await;
    let cur = mgr.current();
    let m = mgr.dir.clone();
    let n = name.clone();
    let Some(found) = blocking(move || Manager::new(m, None, 0).existing(&n)).await? else {
        return Err(reject(StatusCode::NOT_FOUND, "no such project"));
    };
    if !cur.external && cur.name.as_deref() == Some(&found) {
        return Err(reject(
            StatusCode::CONFLICT,
            "open another project first: the open one cannot be deleted",
        ));
    }
    let path = mgr.file(&found);
    blocking(move || -> Result<(), StoreError> {
        let lock = ProjectLock::take(&path)?;
        lock.delete_files()
    })
    .await?
    .map_err(store_error)?;
    let n = found.clone();
    let _ = st
        .with_app(move |a| {
            let list: Vec<String> = a
                .meta(RECENT_KEY)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_default();
            let kept: Vec<_> = list.into_iter().filter(|x| !x.eq_ignore_ascii_case(&n)).collect();
            a.set_meta(RECENT_KEY, &serde_json::to_string(&kept).unwrap_or_default())
        })
        .await;
    caller.audit(&st, "project.delete", &found).await;
    Ok(empty(StatusCode::NO_CONTENT))
}

/// A copy of a project in a temporary file next to the projects (never over a name that exists).
async fn snapshot(st: &AppState, name: &str, dest: PathBuf) -> Result<(), Response> {
    let mgr = &st.inner.projects;
    let cur = mgr.current();
    let path = mgr.file(name);
    if !cur.external && cur.name.as_deref() == Some(name) {
        // The open project: let the recorder catch up so the copy has everything seen so far.
        let proxy = st.inner.proxy.clone();
        let live = proxy.project();
        blocking(move || {
            proxy.flush();
            live.backup_to(&dest)
        })
        .await?
        .map_err(store_error)
    } else {
        blocking(move || Project::open(&path).and_then(|p| p.backup_to(&dest)))
            .await?
            .map_err(store_error)
    }
}

async fn existing_name(st: &AppState, name: &str) -> Result<String, Response> {
    let m = st.inner.projects.dir.clone();
    let n = name.to_string();
    blocking(move || Manager::new(m, None, 0).existing(&n))
        .await?
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such project"))
}

pub async fn export(State(st): State<AppState>, caller: Caller, Path(name): Path<String>) -> R {
    caller.require(Role::Admin)?;
    let found = existing_name(&st, &name).await?;
    let tmp = Temp::new(tmp_name(&st.inner.projects.dir, "export"));
    {
        let _ops = st.inner.projects.ops.lock().await;
        snapshot(&st, &found, tmp.path().to_path_buf()).await?;
    }
    let file = open_for_streaming(tmp).map_err(|e| io_error("could not read the export", e))?;
    let len = file.metadata().map(|m| m.len()).ok();
    caller.audit(&st, "project.export", &found).await;
    let stream = futures_util::stream::unfold(tokio::fs::File::from_std(file), |mut f| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256 * 1024];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(bytes::Bytes::from(buf)), f))
            }
            Err(e) => Some((Err(e), f)),
        }
    });
    let mut r = Response::new(Body::from_stream(stream));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{found}.{EXT}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(len) = len {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(r)
}

/// Open a temporary file for reading and arrange for it to disappear when closed, so an interrupted download
/// leaves nothing behind.
fn open_for_streaming(tmp: Temp) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
        let path = tmp.keep();
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        let f = std::fs::File::open(tmp.path())?;
        drop(tmp); // unlinks the name; the open handle keeps the data until the download ends
        Ok(f)
    }
}

pub async fn backup(State(st): State<AppState>, caller: Caller, Path(name): Path<String>) -> R {
    caller.require(Role::Admin)?;
    let found = existing_name(&st, &name).await?;
    let dir = st.inner.projects.backups();
    let d = dir.clone();
    blocking(move || std::fs::create_dir_all(&d))
        .await?
        .map_err(|e| io_error("could not create the backups folder", e))?;
    let secs = bosun_model::now_ms() / 1000;
    let dest = dir.join(format!("{found}-{secs}.{EXT}"));
    let guard = Temp::new(dest.clone());
    {
        let _ops = st.inner.projects.ops.lock().await;
        snapshot(&st, &found, dest.clone()).await?;
    }
    let size = std::fs::metadata(&dest).map_or(0, |m| m.len());
    guard.keep();
    caller
        .audit(&st, "project.backup", &format!("{found} -> {}", dest.display()))
        .await;
    Ok(Json(BackupInfo {
        path: dest.display().to_string(),
        size_bytes: size,
    })
    .into_response())
}

pub async fn import(
    State(st): State<AppState>,
    caller: Caller,
    Query(q): Query<ImportQuery>,
    body: Body,
) -> R {
    caller.require(Role::Admin)?;
    valid_name(&q.name).map_err(bad_name)?;
    let mgr = &st.inner.projects;
    let m = mgr.dir.clone();
    let n = q.name.clone();
    if blocking(move || Manager::new(m, None, 0).existing(&n))
        .await?
        .is_some()
    {
        return Err(reject(
            StatusCode::CONFLICT,
            "a project with that name already exists",
        ));
    }

    // 1. Receive the upload into a file of its own, within the size limit.
    let upload = Temp::new(tmp_name(&mgr.dir, "import"));
    let mut file = tokio::fs::File::create(upload.path())
        .await
        .map_err(|e| io_error("could not store the upload", e))?;
    let mut total = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| reject(StatusCode::BAD_REQUEST, "the upload was cut off"))?;
        total += chunk.len() as u64;
        if total > mgr.max_upload {
            return Err(reject(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!(
                    "projects over {} MiB cannot be imported here",
                    mgr.max_upload >> 20
                ),
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| io_error("could not store the upload", e))?;
    }
    file.flush()
        .await
        .map_err(|e| io_error("could not store the upload", e))?;
    drop(file);
    if total == 0 {
        return Err(reject(StatusCode::BAD_REQUEST, "the upload was empty"));
    }

    // 2. Check it and rebuild it into a new project file, then put that in place under the name asked for.
    let _ops = mgr.ops.lock().await;
    let m = mgr.dir.clone();
    let n = q.name.clone();
    if blocking(move || Manager::new(m, None, 0).existing(&n))
        .await?
        .is_some()
    {
        return Err(reject(
            StatusCode::CONFLICT,
            "a project with that name already exists",
        ));
    }
    let rebuilt = Temp::new(tmp_name(&mgr.dir, "rebuilt"));
    let (src, dst, fin) = (
        upload.path().to_path_buf(),
        rebuilt.path().to_path_buf(),
        mgr.file(&q.name),
    );
    let checked = blocking(move || -> Result<(), StoreError> {
        bosun_store::import_foreign(&src, &dst)?;
        // Our own opening checks, and the migration to the current schema, on the rebuilt copy.
        Project::open(&dst).map(drop)?;
        bosun_store::settle(&dst)?;
        remove_upgrade_copies(&dst);
        std::fs::rename(&dst, &fin).map_err(|e| StoreError::Io(fin.display().to_string(), e))
    })
    .await?;
    if let Err(e) = checked {
        caller
            .audit(&st, "project.import.refused", &format!("{}: {e}", q.name))
            .await;
        return Err(store_error(e));
    }
    rebuilt.keep();
    drop(upload);
    caller
        .audit(&st, "project.import", &format!("{} ({total} bytes)", q.name))
        .await;
    if q.open == Some(true) {
        switch_to(&st, &caller, Some(&q.name)).await?;
    }
    let info = info_for(&st, &q.name).await;
    Ok((StatusCode::CREATED, Json(info)).into_response())
}

// ---- Switching ------------------------------------------------------------------------------------------------

/// What a project's saved settings turn into. A setting that cannot be used is dropped for its default, which
/// is the safe side (an empty scope allows nothing), and reported.
struct Loaded {
    scope: Scope,
    rules: Vec<RuleSpec>,
    intercept: Option<InterceptSettings>,
    response_filter: ResponseFilter,
    notes: Vec<&'static str>,
}

fn load_settings(p: &Project) -> Loaded {
    let mut notes = Vec::new();
    let spec: ScopeSpec = match p.setting(SETTING_SCOPE) {
        Ok(v) => v.unwrap_or_default(),
        Err(_) => {
            notes.push("scope unreadable, reset");
            ScopeSpec::default()
        }
    };
    let scope = match Scope::compile(spec) {
        Ok(s) => s,
        Err(_) => {
            notes.push("scope invalid, reset");
            Scope::default()
        }
    };
    let rules: Vec<RuleSpec> = match p.setting(SETTING_RULES) {
        Ok(v) => v.unwrap_or_default(),
        Err(_) => {
            notes.push("rules unreadable, reset");
            Vec::new()
        }
    };
    let intercept = p.setting::<InterceptSettings>(SETTING_INTERCEPT).ok().flatten();
    let response_filter = p
        .setting::<ResponseFilter>(SETTING_RESPONSE_FILTER)
        .ok()
        .flatten()
        .filter(|f| f.validate().is_ok())
        .unwrap_or_default();
    Loaded {
        scope,
        rules,
        intercept,
        response_filter,
        notes,
    }
}

/// Open `target` (a name from the projects directory), or a temporary project for `None`, and make it the one
/// everything uses. Callers hold the operations lock.
async fn switch_to(st: &AppState, caller: &Caller, target: Option<&str>) -> Result<CurrentProject, Response> {
    let mgr = &st.inner.projects;
    let (name, path) = match target {
        Some(n) => {
            let found = existing_name(st, n).await?;
            let path = mgr.file(&found);
            (Some(found), Some(path))
        }
        None => (None, None),
    };
    let cur = mgr.current();
    if name.is_some() && !cur.external && cur.name == name {
        return Err(reject(StatusCode::CONFLICT, "that project is already open"));
    }

    // Open first: if it cannot be opened, nothing has changed. The old project may still be finishing a request
    // that began before a recent switch, so a lock held by this very process is waited for briefly.
    let new = {
        let path = path.clone();
        blocking(move || {
            let Some(path) = path else {
                return Project::open_in_memory();
            };
            let mut tries = 0;
            loop {
                match Project::open(&path) {
                    Err(StoreError::Locked(_)) if tries < 15 => {
                        tries += 1;
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    r => return r,
                }
            }
        })
        .await?
        .map_err(store_error)?
    };
    let new = std::sync::Arc::new(new);
    let loaded = {
        let p = new.clone();
        blocking(move || load_settings(&p)).await?
    };

    // Swap everything under the settings lock, so nothing is saved to one project and applied to another.
    let _w = mgr.settings.write().await;
    st.inner.proxy.intercept().drop_all();
    // Attacks belong to the project they started in.
    st.inner.intruder.stop_all();
    let (proxy, p) = (st.inner.proxy.clone(), new.clone());
    let key = st.inner.data_key.clone();
    blocking(move || {
        proxy.switch_project(p);
        // A project carries its own client certificates; a failure leaves the proxy presenting none.
        if let Err(e) = crate::clientcerts::reload(&proxy, &key) {
            tracing::warn!(error = %e, "loading the project's client certificates failed");
        }
        if let Err(e) = crate::maprules::reload(&proxy) {
            tracing::warn!(error = %e, "loading the project's map rules failed");
        }
    })
    .await?;
    st.inner.gate.set_scope(loaded.scope);
    // Sending out of scope from the Repeater is a choice made for the work in front of you, not one a project carries.
    st.inner
        .gate
        .set_repeater_policy(bosun_scope::OutOfScopePolicy::Refuse);
    st.inner.repeater.close_idle();
    let rules_ok = st.inner.proxy.set_rules(loaded.rules).is_ok();
    st.inner
        .proxy
        .intercept()
        .set_response_filter(loaded.response_filter);
    // Interception never comes back on by itself; the in-scope choice is kept.
    st.inner.proxy.intercept().set(InterceptSettings {
        requests: false,
        responses: false,
        ..loaded.intercept.unwrap_or(InterceptSettings {
            in_scope_only: true,
            ..Default::default()
        })
    });
    let now = Current {
        name: name.clone(),
        external: false,
    };
    *mgr.current.lock().unwrap_or_else(|e| e.into_inner()) = now.clone();
    st.inner.events.new_epoch();
    st.inner.events.send(ProxyEvent::ProjectSwitched {
        name: name.clone(),
        temporary: name.is_none(),
    });
    drop(_w);

    let mut detail = name.clone().unwrap_or_else(|| "temporary project".into());
    let mut notes = loaded.notes;
    if !rules_ok {
        notes.push("rules invalid, reset");
    }
    if !notes.is_empty() {
        detail = format!("{detail} ({})", notes.join("; "));
    }
    caller
        .audit(
            st,
            if name.is_some() {
                "project.open"
            } else {
                "project.close"
            },
            &detail,
        )
        .await;
    if let Some(n) = &name {
        touch_recent(st, n).await;
    }
    Ok(current_json(&now))
}
