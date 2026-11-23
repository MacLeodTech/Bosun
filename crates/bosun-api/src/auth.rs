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
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use bosun_store::{Role, TokenScope, User};
use rand::Rng;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::security::{is_unsafe, reject};
use crate::{AppState, ClientInfo};

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
    Argon2::default()
        .hash_password(pw.as_bytes())
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
    attempts: Mutex<HashMap<String, (u32, Instant)>>,
}

/// Attempts allowed per (address, username) pair before delays start.
const FREE_ATTEMPTS: u32 = 3;
/// Longest delay between attempts on one pair.
const MAX_DELAY: Duration = Duration::from_secs(60);
/// Attempts allowed from one address per window, across all usernames.
const MAX_ATTEMPTS_PER_ADDRESS: u32 = 30;

/// The wait required before the next attempt, after `n` attempts: free for the first few, then 1 s, 2 s, 4 s ...
fn delay_after(n: u32) -> Duration {
    if n < FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let secs = 1u64 << (n - FREE_ATTEMPTS).min(6);
    Duration::from_secs(secs).min(MAX_DELAY)
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

    /// Count an attempt *before* the password is checked. Returns the seconds to wait when the attempt is refused.
    ///
    /// `pair` is one (address, username) pair: attempts on it back off exponentially, so a guesser slows down
    /// but nobody else can lock the real user out from another address. `ip` caps one address overall.
    pub(crate) fn begin(&self, ip: &str, pair: &str) -> Result<(), u64> {
        let mut m = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 100_000 {
            m.retain(|_, (_, t)| t.elapsed() <= FAILURE_WINDOW);
        }
        let now = Instant::now();
        let live = |m: &HashMap<String, (u32, Instant)>, k: &str| match m.get(k) {
            Some((n, t)) if t.elapsed() <= FAILURE_WINDOW => (*n, *t),
            _ => (0, now),
        };
        let (ip_n, _) = live(&m, ip);
        if ip_n >= MAX_ATTEMPTS_PER_ADDRESS {
            let left = FAILURE_WINDOW.saturating_sub(m[ip].1.elapsed());
            return Err(left.as_secs().max(1));
        }
        let (pair_n, pair_t) = live(&m, pair);
        let wait = delay_after(pair_n);
        if pair_n > 0 && pair_t.elapsed() < wait {
            return Err((wait - pair_t.elapsed()).as_secs().max(1));
        }
        m.insert(ip.to_string(), (ip_n + 1, now));
        m.insert(pair.to_string(), (pair_n + 1, now));
        Ok(())
    }

    /// A successful attempt: forget the pair and give the address its attempt back.
    pub(crate) fn succeeded(&self, ip: &str, pair: &str) {
        let mut m = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        m.remove(pair);
        if let Some(e) = m.get_mut(ip) {
            e.0 = e.0.saturating_sub(1);
            if e.0 == 0 {
                m.remove(ip);
            }
        }
    }
}

/// The authenticated caller of a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub user: User,
    pub via_token: bool,
    /// The scope of the API token the request used (always `Full` for browser sessions).
    pub scope: TokenScope,
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

    /// Write an audit entry. Waits for the write (on a blocking thread), so the entry is there when the
    /// response goes out.
    pub async fn audit(&self, st: &AppState, action: &str, detail: &str) {
        st.audit(
            Some(self.user.username.clone()),
            action,
            detail,
            Some(self.remote.to_string()),
        )
        .await;
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
            .get::<ClientInfo>()
            .map(|c| c.ip)
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
            let (user, scope) = tokio::task::spawn_blocking(move || app.user_for_api_token(&token))
                .await
                .map_err(|_| unauth())?
                .map_err(|_| unauth())?
                .ok_or_else(unauth)?;
            // A read-only token may not change anything, whatever role its owner has.
            if scope == TokenScope::Read && is_unsafe(&parts.method) {
                return Err(reject(StatusCode::FORBIDDEN, "this API token is read-only"));
            }
            return Ok(Caller {
                user,
                via_token: true,
                scope,
                csrf: None,
                remote,
            });
        }
        let Some(token) = session_cookie_value(&parts.headers) else {
            return Err(unauth());
        };
        let app = st.inner.app.clone();
        let (ttl, max) = (st.inner.session_ttl_ms, st.inner.session_max_ms);
        let session = tokio::task::spawn_blocking(move || app.session(&token, ttl, max))
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
            scope: TokenScope::Full,
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

/// 429 with a `Retry-After`.
fn too_many(wait_secs: u64) -> Response {
    let mut r = reject(
        StatusCode::TOO_MANY_REQUESTS,
        &format!("too many attempts; wait {wait_secs} seconds and try again"),
    );
    if let Ok(v) = HeaderValue::from_str(&wait_secs.to_string()) {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

/// A slot for one password hash. Hashing takes about 19 MiB and tens of milliseconds, so the number running at
/// once is capped; a request that can't get a slot quickly is turned away rather than queued.
pub(crate) async fn hash_slot(st: &AppState) -> Result<tokio::sync::OwnedSemaphorePermit, Response> {
    match tokio::time::timeout(
        Duration::from_secs(2),
        st.inner.hash_slots.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => Ok(p),
        _ => Err(too_many(2)),
    }
}

fn pair_key(ip: &str, username: &str) -> String {
    let u: String = username.chars().take(64).collect();
    format!("pair:{ip}|{}", u.to_ascii_lowercase())
}

fn set_cookie(st: &AppState, token: &str, max_age_secs: i64, https: bool) -> HeaderValue {
    let mut c = cookie::Cookie::build((COOKIE, token.to_string()))
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .path("/")
        .max_age(cookie::time::Duration::seconds(max_age_secs));
    if st.inner.secure_cookies || https {
        c = c.secure(true);
    }
    HeaderValue::from_str(&c.build().to_string()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn me_json(user: &User, csrf: Option<&str>) -> serde_json::Value {
    serde_json::json!({ "user": user, "csrf": csrf })
}

pub async fn setup(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    Json(b): Json<SetupBody>,
) -> Response {
    let https = info.as_ref().is_some_and(|i| i.https);
    let remote = info.map(|i| i.ip.to_string());
    let expected = st
        .inner
        .setup_code
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(expected) = expected else {
        return reject(StatusCode::CONFLICT, "setup has already been completed");
    };
    let ip_key = format!("ip:{}", remote.as_deref().unwrap_or_default());
    if let Err(w) = st.inner.limiter.begin(&ip_key, "setup") {
        return too_many(w);
    }
    if !bool::from(b.code.trim().as_bytes().ct_eq(expected.as_bytes())) {
        st.audit(None, "setup.failed", "wrong setup code", remote.clone())
            .await;
        return reject(
            StatusCode::FORBIDDEN,
            "wrong setup code (it is printed in the server's log at start-up)",
        );
    }
    if let Err(e) = check_username(&b.username).and_then(|_| check_password_policy(&b.password)) {
        return reject(StatusCode::BAD_REQUEST, &e);
    }
    let pw = b.password.clone();
    let permit = match hash_slot(&st).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Ok(Ok(hash)) = tokio::task::spawn_blocking(move || {
        let _slot = permit;
        hash_password(&pw)
    })
    .await
    else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed");
    };
    let name = b.username.clone();
    let created = match st.with_app(move |a| a.create_first_admin(&name, &hash)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let user = match created {
        Ok(u) => u,
        Err(e) => return reject(StatusCode::CONFLICT, &e.to_string()),
    };
    st.inner.limiter.succeeded(&ip_key, "setup");
    *st.inner.setup_code.lock().unwrap_or_else(|e| e.into_inner()) = None;
    st.audit(
        Some(user.username.clone()),
        "setup",
        "created the first admin",
        remote.clone(),
    )
    .await;
    start_session(&st, user, https).await
}

async fn session_created(st: &AppState, token: &str, user_id: i64, csrf: &str) -> bool {
    let (token, csrf, ttl) = (token.to_string(), csrf.to_string(), st.inner.session_ttl_ms);
    matches!(
        st.with_app(move |a| a.create_session(&token, user_id, &csrf, ttl))
            .await,
        Ok(Ok(_))
    )
}

async fn start_session(st: &AppState, user: User, https: bool) -> Response {
    let token = random_token();
    let csrf = random_token();
    if !session_created(st, &token, user.id, &csrf).await {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "could not create a session");
    }
    let mut r = Json(me_json(&user, Some(&csrf))).into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(st, &token, st.inner.session_ttl_ms / 1000, https),
    );
    r
}

/// A session for `user` and the `Set-Cookie` that carries it (single sign-on redirects instead of returning JSON).
pub(crate) async fn new_session_cookie(st: &AppState, user: &User) -> Result<HeaderValue, ()> {
    let token = random_token();
    let csrf = random_token();
    if !session_created(st, &token, user.id, &csrf).await {
        return Err(());
    }
    Ok(set_cookie(st, &token, st.inner.session_ttl_ms / 1000, false))
}

pub async fn login(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    Json(b): Json<LoginBody>,
) -> Response {
    let https = info.as_ref().is_some_and(|i| i.https);
    let remote = info.map(|i| i.ip.to_string()).unwrap_or_default();
    let ip_key = format!("ip:{remote}");
    let pair = pair_key(&remote, &b.username);
    // Counted before any hashing, so a burst of parallel guesses is throttled as it arrives.
    if let Err(w) = st.inner.limiter.begin(&ip_key, &pair) {
        return too_many(w);
    }
    let permit = match hash_slot(&st).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let app = st.inner.app.clone();
    let (username, password) = (b.username.clone(), b.password.clone());
    let found = tokio::task::spawn_blocking(move || {
        let _slot = permit;
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
            st.inner.limiter.succeeded(&ip_key, &pair);
            st.audit(
                Some(user.username.clone()),
                "login",
                "signed in",
                Some(remote.clone()),
            )
            .await;
            start_session(&st, user, https).await
        }
        None => {
            st.audit(
                Some(b.username.clone()),
                "login.failed",
                "wrong username or password",
                Some(remote.clone()),
            )
            .await;
            reject(StatusCode::UNAUTHORIZED, "wrong username or password")
        }
    }
}

static DUMMY_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| hash_password("dummy password for timing").unwrap_or_default());

pub async fn logout(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    headers: HeaderMap,
    caller: Caller,
) -> Response {
    let https = info.is_some_and(|i| i.https);
    if let Some(t) = session_cookie_value(&headers) {
        let _ = st.with_app(move |a| a.delete_session(&t)).await;
    }
    caller.audit(&st, "logout", "").await;
    let mut r = crate::security::empty(StatusCode::NO_CONTENT);
    r.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&st, "", 0, https));
    r
}

pub async fn me(caller: Caller) -> Response {
    Json(me_json(&caller.user, caller.csrf.as_deref())).into_response()
}

#[derive(Deserialize)]
pub struct PasswordBody {
    pub current: String,
    pub new: String,
    /// End the user's API tokens too (the default): a token made with a stolen password must not survive the reset.
    #[serde(default)]
    pub revoke_tokens: Option<bool>,
}

pub async fn change_password(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    caller: Caller,
    Json(b): Json<PasswordBody>,
) -> Response {
    let https = info.is_some_and(|i| i.https);
    if let Err(e) = check_password_policy(&b.new) {
        return reject(StatusCode::BAD_REQUEST, &e);
    }
    // Same throttle as sign-in: a stolen session must not become an offline-speed password guesser.
    let ip_key = format!("ip:{}", caller.remote);
    let pair = format!("pw:{}", caller.user.id);
    if let Err(w) = st.inner.limiter.begin(&ip_key, &pair) {
        return too_many(w);
    }
    let permit = match hash_slot(&st).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let app = st.inner.app.clone();
    let username = caller.user.username.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _slot = permit;
        let (u, phc) = app.user_for_login(&username).ok().flatten()?;
        if !verify_password(&b.current, &phc) {
            return Some(Err("the current password is wrong"));
        }
        let h = hash_password(&b.new).ok()?;
        app.set_password(u.id, &h, b.revoke_tokens.unwrap_or(true)).ok()?;
        Some(Ok(()))
    })
    .await
    .ok()
    .flatten();
    match res {
        Some(Ok(())) => {
            st.inner.limiter.succeeded(&ip_key, &pair);
            caller.audit(&st, "password.change", "").await;
            let mut r = crate::security::empty(StatusCode::NO_CONTENT);
            r.headers_mut()
                .insert(header::SET_COOKIE, set_cookie(&st, "", 0, https));
            r
        }
        Some(Err(e)) => reject(StatusCode::FORBIDDEN, e),
        None => reject(StatusCode::INTERNAL_SERVER_ERROR, "could not change the password"),
    }
}

// ---- Desktop login tickets ------------------------------------------------------------------------------------

/// How long a login ticket can be exchanged.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// The one outstanding login ticket, if any. Only an embedded engine issues one (`bosun serve --embedded` hands it
/// to its parent on stdout), so a normal server has none and `POST /auth/ticket` always refuses.
#[derive(Default)]
pub struct Tickets {
    slot: Mutex<Option<(String, Instant)>>,
}

impl Tickets {
    pub fn issue(&self) -> String {
        let t = format!("bosun_ticket_{}", random_token());
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((t.clone(), Instant::now()));
        t
    }

    /// Exchange: true once for the right, unexpired ticket. A wrong guess does not use the ticket up (it is 256
    /// bits, and the caller is rate limited); a right one does, and so does an expired one.
    fn redeem(&self, presented: &str) -> bool {
        self.redeem_within(presented, TICKET_TTL)
    }

    fn redeem_within(&self, presented: &str, ttl: Duration) -> bool {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        let Some((t, issued)) = slot.as_ref() else {
            return false;
        };
        if issued.elapsed() > ttl {
            *slot = None;
            return false;
        }
        if bool::from(t.as_bytes().ct_eq(presented.as_bytes())) {
            *slot = None;
            return true;
        }
        false
    }
}

#[derive(Deserialize)]
pub struct TicketBody {
    pub ticket: String,
}

/// The name of the account made for a desktop app when the engine has no users yet.
const LOCAL_ADMIN: &str = "desktop";

/// Exchange the login ticket an embedded engine gave its parent for a session cookie. Loopback only.
pub async fn ticket(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    Json(b): Json<TicketBody>,
) -> Response {
    let https = info.as_ref().is_some_and(|i| i.https);
    let ip = info.as_ref().map(|i| i.ip);
    let remote = ip.map(|i| i.to_string()).unwrap_or_default();
    let ip_key = format!("ip:{remote}");
    if let Err(w) = st.inner.limiter.begin(&ip_key, "ticket") {
        return too_many(w);
    }
    if !ip.is_some_and(|i| i.is_loopback()) || !st.inner.tickets.redeem(b.ticket.trim()) {
        st.audit(
            None,
            "login.ticket.failed",
            "a login ticket was refused",
            Some(remote),
        )
        .await;
        return reject(
            StatusCode::UNAUTHORIZED,
            "that login ticket is not valid (it is single-use and lasts 60 seconds)",
        );
    }
    let made = match st.with_app(|a| a.ticket_user(LOCAL_ADMIN)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let (user, created) = match made {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error = %e, "could not find the account for a login ticket");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "could not sign in");
        }
    };
    if created {
        // The first account exists now, so first-run setup is over.
        *st.inner.setup_code.lock().unwrap_or_else(|e| e.into_inner()) = None;
        st.audit(
            Some(user.username.clone()),
            "setup",
            "created the local admin for the desktop app",
            Some(remote.clone()),
        )
        .await;
    }
    st.inner.limiter.succeeded(&ip_key, "ticket");
    st.audit(
        Some(user.username.clone()),
        "login.ticket",
        "signed in with a login ticket",
        Some(remote),
    )
    .await;
    start_session(&st, user, https).await
}

#[cfg(test)]
mod password_tests {
    use super::*;

    /// A hash made by an earlier build (and independently with Python's `cryptography`) must still verify after a
    /// dependency upgrade, or every existing account would be locked out.
    #[test]
    fn password_hashes_made_earlier_still_verify() {
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0";
        assert!(verify_password("correct horse battery staple", phc));
        assert!(!verify_password("correct horse battery stapl", phc));
    }

    #[test]
    fn new_hashes_are_argon2id_with_the_same_cost_and_verify() {
        let h = hash_password("another long password").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_password("another long password", &h));
        assert!(!verify_password("something else entirely", &h));
        assert_ne!(
            h,
            hash_password("another long password").unwrap(),
            "each hash has its own salt"
        );
    }

    #[test]
    fn a_ticket_works_once_and_only_while_fresh() {
        let t = Tickets::default();
        assert!(!t.redeem("anything"), "none issued");
        let a = t.issue();
        assert!(!t.redeem("wrong"), "a wrong guess");
        assert!(t.redeem(&a), "a wrong guess does not use it up");
        assert!(!t.redeem(&a), "single use");
        let b = t.issue();
        std::thread::sleep(Duration::from_millis(30));
        assert!(!t.redeem_within(&b, Duration::from_millis(10)), "expired");
        assert!(!t.redeem(&b), "an expired ticket is gone, not merely refused");
        let c = t.issue();
        let d = t.issue();
        assert!(!t.redeem(&c), "a newer ticket replaces the older one");
        assert!(t.redeem(&d));
    }
}
