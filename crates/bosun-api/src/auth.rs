//! Accounts, sessions, API tokens and the per-request [`Caller`].
//!
//! - First run: there are no users. A one-time setup code is printed to the console (and only there); the
//!   first admin is created by presenting it. Without the code, nobody on the network can claim the install.
//! - Browsers authenticate with a session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` under TLS) and send
//!   the session's CSRF token in `X-CSRF-Token` on every state-changing request.
//! - Scripts and the CLI use `Authorization: Bearer <token>` API tokens. Those are not ambient credentials, so
//!   they need no CSRF token.
//! - Passwords are hashed with argon2id. Failed logins are rate-limited per client address and per username,
//!   and a missing user costs the same hashing time as a wrong password.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use bosun_store::{Role, User};
use rand::RngCore;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::security::{is_unsafe, reject};
use crate::{AppState, Peer};

pub const COOKIE: &str = "bosun_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
pub const MIN_PASSWORD: usize = 12;

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn hash_password(pw: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

pub fn check_password_policy(pw: &str) -> Result<(), String> {
    if pw.chars().count() < MIN_PASSWORD {
        return Err(format!("passwords must be at least {MIN_PASSWORD} characters"));
    }
    if pw.len() > 1024 {
        return Err("password too long".into());
    }
    Ok(())
}

pub fn check_username(u: &str) -> Result<(), String> {
    let ok =
        !u.is_empty() && u.len() <= 64 && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c));
    if ok {
        Ok(())
    } else {
        Err("usernames are 1-64 characters: letters, digits, '.', '_', '-', '@'".into())
    }
}

/// Failed-login counters.
#[derive(Debug, Default)]
pub struct Limiter {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Limiter {
    pub(crate) fn blocked(&self, key: &str) -> bool {
        let mut m = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(key) {
            Some((_, t)) if t.elapsed() > FAILURE_WINDOW => {
                m.remove(key);
                false
            }
            Some((n, _)) => *n >= MAX_FAILURES,
            None => false,
        }
    }

    pub(crate) fn fail(&self, key: &str) {
        let mut m = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 100_000 {
            m.retain(|_, (_, t)| t.elapsed() <= FAILURE_WINDOW);
        }
        let e = m.entry(key.to_string()).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }

    fn clear(&self, key: &str) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

/// The authenticated caller of a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub user: User,
    pub via_token: bool,
    pub csrf: Option<String>,
    pub remote: IpAddr,
}

impl Caller {
    pub fn require(&self, role: Role) -> Result<(), Response> {
        if self.user.role >= role {
            Ok(())
        } else {
            Err(reject(
                StatusCode::FORBIDDEN,
                &format!("this needs the {} role", role.as_str()),
            ))
        }
    }

    pub fn audit(&self, st: &AppState, action: &str, detail: &str) {
        let _ = st.inner.app.audit(
            Some(&self.user.username),
            action,
            detail,
            Some(&self.remote.to_string()),
        );
    }
}

pub fn session_cookie_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| cookie::Cookie::parse(c.trim().to_string()).ok())
        .find(|c| c.name() == COOKIE)
        .map(|c| c.value().to_string())
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Response> {
        let remote = parts
            .extensions
            .get::<Peer>()
            .map(|p| p.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let unauth = || reject(StatusCode::UNAUTHORIZED, "sign in first");
        if let Some(auth) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let Some(token) = auth.strip_prefix("Bearer ") else {
                return Err(unauth());
            };
            let app = st.inner.app.clone();
            let token = token.trim().to_string();
            let user = tokio::task::spawn_blocking(move || app.user_for_api_token(&token))
                .await
                .map_err(|_| unauth())?
                .map_err(|_| unauth())?
                .ok_or_else(unauth)?;
            return Ok(Caller {
                user,
                via_token: true,
                csrf: None,
                remote,
            });
        }
        let Some(token) = session_cookie_value(&parts.headers) else {
            return Err(unauth());
        };
        let app = st.inner.app.clone();
        let ttl = st.inner.session_ttl_ms;
        let session = tokio::task::spawn_blocking(move || app.session(&token, ttl))
            .await
            .map_err(|_| unauth())?
            .map_err(|_| unauth())?
            .ok_or_else(unauth)?;
        if is_unsafe(&parts.method) {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .map(|v| v.as_bytes())
                .unwrap_or(b"");
            if !bool::from(sent.ct_eq(session.csrf.as_bytes())) {
                return Err(reject(StatusCode::FORBIDDEN, "missing or wrong CSRF token"));
            }
        }
        Ok(Caller {
            user: session.user,
            via_token: false,
            csrf: Some(session.csrf),
            remote,
        })
    }
}

#[derive(Deserialize)]
pub struct SetupBody {
    pub code: String,
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

fn set_cookie(st: &AppState, token: &str, max_age_secs: i64) -> HeaderValue {
    let mut c = cookie::Cookie::build((COOKIE, token.to_string()))
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .path("/")
        .max_age(cookie::time::Duration::seconds(max_age_secs));
    if st.inner.secure_cookies {
        c = c.secure(true);
    }
    HeaderValue::from_str(&c.build().to_string()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn me_json(user: &User, csrf: Option<&str>) -> serde_json::Value {
    serde_json::json!({ "user": user, "csrf": csrf })
}

pub async fn setup(
    State(st): State<AppState>,
    peer: Option<axum::Extension<Peer>>,
    Json(b): Json<SetupBody>,
) -> Response {
    let remote = peer.map(|p| p.0.0.ip().to_string());
    let expected = st
        .inner
        .setup_code
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(expected) = expected else {
        return reject(StatusCode::CONFLICT, "setup has already been completed");
    };
    if st.inner.limiter.blocked("setup") {
        return reject(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts; wait and try again",
        );
    }
    if !bool::from(b.code.trim().as_bytes().ct_eq(expected.as_bytes())) {
        st.inner.limiter.fail("setup");
        let _ = st
            .inner
            .app
            .audit(None, "setup.failed", "wrong setup code", remote.as_deref());
        return reject(
            StatusCode::FORBIDDEN,
            "wrong setup code (it is printed in the server's log at start-up)",
        );
    }
    if let Err(e) = check_username(&b.username).and_then(|_| check_password_policy(&b.password)) {
        return reject(StatusCode::BAD_REQUEST, &e);
    }
    let pw = b.password.clone();
    let Ok(Ok(hash)) = tokio::task::spawn_blocking(move || hash_password(&pw)).await else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed");
    };
    let user = match st.inner.app.create_first_admin(&b.username, &hash) {
        Ok(u) => u,
        Err(e) => return reject(StatusCode::CONFLICT, &e.to_string()),
    };
    *st.inner.setup_code.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let _ = st.inner.app.audit(
        Some(&user.username),
        "setup",
        "created the first admin",
        remote.as_deref(),
    );
    start_session(&st, user).await
}

async fn start_session(st: &AppState, user: User) -> Response {
    let token = random_token();
    let csrf = random_token();
    if st
        .inner
        .app
        .create_session(&token, user.id, &csrf, st.inner.session_ttl_ms)
        .is_err()
    {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "could not create a session");
    }
    let mut r = Json(me_json(&user, Some(&csrf))).into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(st, &token, st.inner.session_ttl_ms / 1000),
    );
    r
}

/// A session for `user` and the `Set-Cookie` that carries it (single sign-on redirects instead of returning JSON).
pub(crate) fn new_session_cookie(st: &AppState, user: &User) -> Result<HeaderValue, ()> {
    let token = random_token();
    let csrf = random_token();
    st.inner
        .app
        .create_session(&token, user.id, &csrf, st.inner.session_ttl_ms)
        .map_err(|_| ())?;
    Ok(set_cookie(st, &token, st.inner.session_ttl_ms / 1000))
}

pub async fn login(
    State(st): State<AppState>,
    peer: Option<axum::Extension<Peer>>,
    Json(b): Json<LoginBody>,
) -> Response {
    let remote = peer.map(|p| p.0.0.ip().to_string()).unwrap_or_default();
    let ip_key = format!("ip:{remote}");
    let user_key = format!("user:{}", b.username.to_ascii_lowercase());
    if st.inner.limiter.blocked(&ip_key) || st.inner.limiter.blocked(&user_key) {
        return reject(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed sign-ins; wait 15 minutes",
        );
    }
    let app = st.inner.app.clone();
    let (username, password) = (b.username.clone(), b.password.clone());
    let found = tokio::task::spawn_blocking(move || {
        let row = app.user_for_login(&username).ok().flatten();
        // Spend the same time whether or not the user exists.
        let phc = row
            .as_ref()
            .map(|(_, h)| h.clone())
            .unwrap_or_else(|| DUMMY_HASH.clone());
        let ok = verify_password(&password, &phc);
        row.filter(|_| ok).map(|(u, _)| u)
    })
    .await
    .ok()
    .flatten();
    match found {
        Some(user) => {
            st.inner.limiter.clear(&user_key);
            let _ = st
                .inner
                .app
                .audit(Some(&user.username), "login", "signed in", Some(&remote));
            start_session(&st, user).await
        }
        None => {
            st.inner.limiter.fail(&ip_key);
            st.inner.limiter.fail(&user_key);
            let _ = st.inner.app.audit(
                Some(&b.username),
                "login.failed",
                "wrong username or password",
                Some(&remote),
            );
            reject(StatusCode::UNAUTHORIZED, "wrong username or password")
        }
    }
}

static DUMMY_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| hash_password("dummy password for timing").unwrap_or_default());

pub async fn logout(State(st): State<AppState>, headers: HeaderMap, caller: Caller) -> Response {
    if let Some(t) = session_cookie_value(&headers) {
        let _ = st.inner.app.delete_session(&t);
    }
    caller.audit(&st, "logout", "");
    let mut r = crate::security::empty(StatusCode::NO_CONTENT);
    r.headers_mut().insert(header::SET_COOKIE, set_cookie(&st, "", 0));
    r
}

pub async fn me(caller: Caller) -> Response {
    Json(me_json(&caller.user, caller.csrf.as_deref())).into_response()
}

#[derive(Deserialize)]
pub struct PasswordBody {
    pub current: String,
    pub new: String,
}

pub async fn change_password(
    State(st): State<AppState>,
    caller: Caller,
    Json(b): Json<PasswordBody>,
) -> Response {
    if let Err(e) = check_password_policy(&b.new) {
        return reject(StatusCode::BAD_REQUEST, &e);
    }
    let app = st.inner.app.clone();
    let username = caller.user.username.clone();
    let res = tokio::task::spawn_blocking(move || {
        let (u, phc) = app.user_for_login(&username).ok().flatten()?;
        if !verify_password(&b.current, &phc) {
            return Some(Err("the current password is wrong"));
        }
        let h = hash_password(&b.new).ok()?;
        app.set_password(u.id, &h).ok()?;
        Some(Ok(()))
    })
    .await
    .ok()
    .flatten();
    match res {
        Some(Ok(())) => {
            caller.audit(&st, "password.change", "");
            let mut r = crate::security::empty(StatusCode::NO_CONTENT);
            r.headers_mut().insert(header::SET_COOKIE, set_cookie(&st, "", 0));
            r
        }
        Some(Err(e)) => reject(StatusCode::FORBIDDEN, e),
        None => reject(StatusCode::INTERNAL_SERVER_ERROR, "could not change the password"),
    }
}
