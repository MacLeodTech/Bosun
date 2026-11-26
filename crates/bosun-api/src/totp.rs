//! TOTP second factor (RFC 6238: HMAC-SHA-1, 6 digits, 30-second steps).
//!
//! - The secret is 160 random bits, sealed with the install's data key before it reaches the account database.
//! - Enrolment has two steps: `enroll` makes a secret (shown once, as base32 and as an `otpauth://` URI), and
//!   `confirm` turns the factor on when the first valid code arrives. Until then nothing asks for a code.
//! - A code is accepted for the previous, current and next step, and each step works once: the newest step used
//!   is stored, and an equal or older step is refused (so a code seen over a shoulder cannot be replayed).
//! - Recovery codes (ten, 80 bits each) are shown once, stored as SHA-256 hashes and work once.
//! - Sign-in with a second factor is two requests: the password returns a short-lived pending token, and
//!   `POST /auth/login/totp` trades it plus a code for the session. No session exists in between.
//! - Wrong codes count against the same limiter as passwords, per address and account, plus a cap of failures per
//!   account across all addresses.
//! - The desktop login ticket and single sign-on do not ask for a code: the first is a local single-use exchange,
//!   and the second delegates the factor to the identity provider.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_ca::DataKey;
use bosun_store::{Role, User};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::auth::{Caller, random_token, start_session, too_many};
use crate::security::{empty, reject};
use crate::{AppState, ClientInfo};

/// Length of a time step.
pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;
/// How many recovery codes enrolment makes.
pub const RECOVERY_CODES: usize = 10;
/// How long a password-checked sign-in waits for its code.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// Code attempts one pending sign-in gets.
const PENDING_TRIES: u32 = 5;
/// Pending sign-ins held at once.
const PENDING_MAX: usize = 10_000;
const ISSUER: &str = "Bosun";

// ---- the algorithm ------------------------------------------------------------------------------------------

/// RFC 4226 HOTP with SHA-1 and 6 digits.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(secret) else {
        return 0; // HMAC takes keys of any length, so this does not happen
    };
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The code for the step that contains `unix_secs`.
pub fn code_at(secret: &[u8], unix_secs: u64) -> String {
    format!("{:06}", hotp(secret, unix_secs / STEP_SECS))
}

/// Check `code` against the steps around `unix_secs` (one before, the current one, one after). Returns the step it
/// matched when that step is newer than `last_step` (the newest step already used), so a code works once.
///
/// Every step is compared, in constant time, whatever the first one gave.
pub fn check(secret: &[u8], unix_secs: u64, code: &str, last_step: i64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = unix_secs / STEP_SECS;
    let mut hit = None;
    for step in now.saturating_sub(1)..=now + 1 {
        let want = format!("{:06}", hotp(secret, step));
        let equal = bool::from(want.as_bytes().ct_eq(code.as_bytes()));
        if equal && i64::try_from(step).is_ok_and(|s| s > last_step) {
            hit = Some(step);
        }
    }
    hit
}

/// Whether input looks like a 6-digit code (as opposed to a recovery code).
fn looks_like_code(input: &str) -> bool {
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    s.len() == DIGITS as usize && s.bytes().all(|b| b.is_ascii_digit())
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode base32, ignoring case, spaces, dashes and padding. None for any other character.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = B32.iter().position(|&b| b as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The URI authenticator apps read (shown as text; the user types or pastes the secret).
pub fn otpauth_uri(account: &str, secret_b32: &str) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{issuer}:{acct}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        issuer = ISSUER,
        acct = enc(account)
    )
}

pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut s);
    s
}

/// A recovery code: 16 base32 characters in groups of four (80 bits).
pub fn new_recovery_code() -> String {
    let mut b = [0u8; 10];
    rand::rng().fill_bytes(&mut b);
    let s = base32_encode(&b);
    s.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// The form a recovery code is hashed in: upper case, no separators.
fn normalize_recovery(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn recovery_hash(code: &str) -> Vec<u8> {
    bosun_store::app::token_hash(&format!("bosun-recovery:{}", normalize_recovery(code)))
}

fn seal_purpose(user_id: i64) -> String {
    format!("totp-secret:{user_id}")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- sign-ins waiting for their code ------------------------------------------------------------------------

struct PendingLogin {
    user: User,
    remote: IpAddr,
    created: Instant,
    tries: u32,
}

/// Password-checked sign-ins that are waiting for a second factor. In memory: a restart ends them.
#[derive(Default)]
pub struct Pending {
    map: Mutex<HashMap<String, PendingLogin>>,
}

impl Pending {
    pub fn start(&self, user: User, remote: IpAddr) -> Option<String> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= PENDING_MAX {
            m.retain(|_, p| p.created.elapsed() <= PENDING_TTL);
            if m.len() >= PENDING_MAX {
                return None;
            }
        }
        let token = format!("bosun_pending_{}", random_token());
        m.insert(
            token.clone(),
            PendingLogin {
                user,
                remote,
                created: Instant::now(),
                tries: 0,
            },
        );
        Some(token)
    }

    /// Spend one try of a pending sign-in. None when it is unknown, expired, from another address or out of tries
    /// (the last two end it).
    pub fn attempt(&self, token: &str, remote: IpAddr) -> Option<User> {
        self.attempt_within(token, remote, PENDING_TTL)
    }

    fn attempt_within(&self, token: &str, remote: IpAddr, ttl: Duration) -> Option<User> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let p = m.get_mut(token)?;
        if p.created.elapsed() > ttl || p.remote != remote {
            m.remove(token);
            return None;
        }
        p.tries += 1;
        if p.tries > PENDING_TRIES {
            m.remove(token);
            return None;
        }
        Some(p.user.clone())
    }

    pub fn finish(&self, token: &str) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }
}

// ---- checking a factor ----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Factor {
    Code,
    Recovery,
}

/// Check a TOTP code or a recovery code for a user and use it up. Runs on a blocking thread.
fn use_factor(
    app: &bosun_store::AppDb,
    key: &DataKey,
    user_id: i64,
    input: &str,
    now: u64,
) -> Option<Factor> {
    let row = app.totp_row(user_id).ok().flatten().filter(|r| r.confirmed)?;
    if looks_like_code(input) {
        let secret = key.open(&seal_purpose(user_id), &row.sealed_secret).ok()?;
        let step = check(&secret, now, input, row.last_step)?;
        // The atomic update decides a race between two requests with the same code.
        return app
            .totp_accept_step(user_id, i64::try_from(step).ok()?)
            .ok()?
            .then_some(Factor::Code);
    }
    app.totp_use_recovery(user_id, &recovery_hash(input))
        .ok()?
        .then_some(Factor::Recovery)
}

fn user_key(user_id: i64) -> String {
    format!("totp-user:{user_id}")
}

/// Count a code attempt before checking it. Err is the response to send.
fn throttle(st: &AppState, remote: IpAddr, user_id: i64) -> Result<(String, String), Response> {
    let ip_key = format!("ip:{remote}");
    let pair = format!("totp:{remote}|{user_id}");
    if st.inner.limiter.blocked(&user_key(user_id)) {
        return Err(too_many(60));
    }
    st.inner.limiter.begin(&ip_key, &pair).map_err(too_many)?;
    Ok((ip_key, pair))
}

// ---- sign-in -------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TotpLoginBody {
    pub pending: String,
    pub code: String,
}

/// The second step of sign-in: the pending token from `POST /auth/login` and a code (or a recovery code).
pub async fn login(
    State(st): State<AppState>,
    info: Option<axum::Extension<ClientInfo>>,
    Json(b): Json<TotpLoginBody>,
) -> Response {
    let https = info.as_ref().is_some_and(|i| i.https);
    let remote = info.map(|i| i.ip).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let Some(user) = st.inner.pending.attempt(&b.pending, remote) else {
        return reject(
            StatusCode::UNAUTHORIZED,
            "that sign-in has expired or is not valid; enter the password again",
        );
    };
    let (ip_key, pair) = match throttle(&st, remote, user.id) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let (key, id, code) = (st.inner.data_key.clone(), user.id, b.code.clone());
    let used = match st
        .with_app(move |a| use_factor(a, &key, id, &code, unix_now()))
        .await
    {
        Ok(u) => u,
        Err(r) => return r,
    };
    match used {
        Some(f) => {
            st.inner.limiter.succeeded(&ip_key, &pair);
            st.inner.limiter.clear_failures(&user_key(user.id));
            st.inner.pending.finish(&b.pending);
            let how = if f == Factor::Code {
                "code"
            } else {
                "recovery code"
            };
            st.audit(
                Some(user.username.clone()),
                "login",
                &format!("signed in with a second factor ({how})"),
                Some(remote.to_string()),
            )
            .await;
            if f == Factor::Recovery {
                let id = user.id;
                let left = st.with_app(move |a| a.totp_recovery_left(id)).await;
                if let Ok(Ok(n)) = left {
                    st.audit(
                        Some(user.username.clone()),
                        "totp.recovery.used",
                        &format!("{n} recovery codes left"),
                        Some(remote.to_string()),
                    )
                    .await;
                }
            }
            start_session(&st, user, https).await
        }
        None => {
            st.inner.limiter.fail(&user_key(user.id));
            st.audit(
                Some(user.username.clone()),
                "login.totp.failed",
                "wrong second-factor code",
                Some(remote.to_string()),
            )
            .await;
            reject(StatusCode::UNAUTHORIZED, "wrong code")
        }
    }
}

// ---- enrolment and management ---------------------------------------------------------------------------------

type R = Result<Response, Response>;

fn store_err(e: bosun_store::StoreError) -> Response {
    match e {
        bosun_store::StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
        e => crate::handlers::internal(e),
    }
}

#[derive(Serialize)]
pub struct Status {
    /// A confirmed second factor is on for this account.
    pub enabled: bool,
    /// A secret was made but no code has confirmed it yet.
    pub enrolling: bool,
    pub recovery_codes_left: i64,
    /// An admin requires every password account to have a second factor.
    pub required: bool,
    /// This account must set up a second factor before it can do anything else.
    pub setup_required: bool,
}

async fn status_of(st: &AppState, caller: &Caller) -> Result<Status, Response> {
    let id = caller.user.id;
    let (row, left, missing) = st
        .with_app(move |a| {
            Ok::<_, bosun_store::StoreError>((
                a.totp_row(id)?,
                a.totp_recovery_left(id)?,
                a.totp_missing(id)?,
            ))
        })
        .await?
        .map_err(store_err)?;
    Ok(Status {
        enabled: row.as_ref().is_some_and(|r| r.confirmed),
        enrolling: row.as_ref().is_some_and(|r| !r.confirmed),
        recovery_codes_left: left,
        required: st.inner.totp_required.load(Ordering::Relaxed),
        setup_required: st.inner.totp_required.load(Ordering::Relaxed) && missing,
    })
}

/// Your own second-factor state.
pub async fn status(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(status_of(&st, &caller).await?).into_response())
}

#[derive(Serialize)]
pub struct Enrolment {
    /// The shared secret, base32.
    pub secret: String,
    /// `otpauth://` URI with the same secret.
    pub otpauth_uri: String,
}

/// Make a secret for your own account. Nothing is enforced until `confirm` receives a valid code.
pub async fn enroll(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let secret = new_secret();
    let id = caller.user.id;
    let sealed = st
        .inner
        .data_key
        .seal(&seal_purpose(id), &secret)
        .map_err(crate::handlers::internal)?;
    st.with_app(move |a| a.totp_begin(id, &sealed))
        .await?
        .map_err(store_err)?;
    let b32 = base32_encode(&secret);
    caller
        .audit(&st, "totp.enroll", "started second-factor enrolment")
        .await;
    Ok(Json(Enrolment {
        otpauth_uri: otpauth_uri(&caller.user.username, &b32),
        secret: b32,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct CodeBody {
    pub code: String,
}

#[derive(Serialize)]
pub struct RecoveryCodes {
    /// Shown once. Each works once.
    pub recovery_codes: Vec<String>,
}

fn fresh_recovery() -> (Vec<String>, Vec<Vec<u8>>) {
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let hashes = codes.iter().map(|c| recovery_hash(c)).collect();
    (codes, hashes)
}

/// Check a code for an account that is being enrolled. Returns the matched step.
async fn check_unconfirmed(st: &AppState, user_id: i64, code: &str) -> Result<Option<u64>, Response> {
    let (key, code) = (st.inner.data_key.clone(), code.to_string());
    st.with_app(move |a| {
        let row = a.totp_row(user_id).ok().flatten().filter(|r| !r.confirmed)?;
        let secret = key.open(&seal_purpose(user_id), &row.sealed_secret).ok()?;
        check(&secret, unix_now(), &code, 0)
    })
    .await
}

/// Turn the factor on with the first valid code, and return the recovery codes.
pub async fn confirm(State(st): State<AppState>, caller: Caller, Json(b): Json<CodeBody>) -> R {
    caller.require(Role::Viewer)?;
    let id = caller.user.id;
    let (ip_key, pair) = throttle(&st, caller.remote, id)?;
    let Some(step) = check_unconfirmed(&st, id, &b.code).await? else {
        st.inner.limiter.fail(&user_key(id));
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "that code is wrong, or there is no enrolment in progress",
        ));
    };
    let (codes, hashes) = fresh_recovery();
    let done = st
        .with_app(move |a| a.totp_confirm(id, step as i64, &hashes))
        .await?
        .map_err(store_err)?;
    if !done {
        return Err(reject(StatusCode::CONFLICT, "a second factor is already set up"));
    }
    st.inner.limiter.succeeded(&ip_key, &pair);
    st.inner.limiter.clear_failures(&user_key(id));
    caller.audit(&st, "totp.enable", "second factor turned on").await;
    Ok(Json(RecoveryCodes {
        recovery_codes: codes,
    })
    .into_response())
}

/// Check and use a code (or recovery code) of the caller's own account.
async fn require_own_factor(st: &AppState, caller: &Caller, code: &str) -> Result<(), Response> {
    let id = caller.user.id;
    let (ip_key, pair) = throttle(st, caller.remote, id)?;
    let (key, code) = (st.inner.data_key.clone(), code.to_string());
    let used = st
        .with_app(move |a| use_factor(a, &key, id, &code, unix_now()))
        .await?;
    if used.is_none() {
        st.inner.limiter.fail(&user_key(id));
        caller
            .audit(st, "totp.code.failed", "wrong second-factor code")
            .await;
        return Err(reject(StatusCode::FORBIDDEN, "wrong code"));
    }
    st.inner.limiter.succeeded(&ip_key, &pair);
    st.inner.limiter.clear_failures(&user_key(id));
    Ok(())
}

/// Turn your own second factor off. Needs a valid code or recovery code.
pub async fn disable(State(st): State<AppState>, caller: Caller, Json(b): Json<CodeBody>) -> R {
    caller.require(Role::Viewer)?;
    require_own_factor(&st, &caller, &b.code).await?;
    let id = caller.user.id;
    st.with_app(move |a| a.totp_remove(id))
        .await?
        .map_err(store_err)?;
    caller
        .audit(&st, "totp.disable", "second factor turned off by its owner")
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

/// Make a new set of recovery codes (the old ones stop working). Needs a valid code.
pub async fn recovery_codes(State(st): State<AppState>, caller: Caller, Json(b): Json<CodeBody>) -> R {
    caller.require(Role::Viewer)?;
    require_own_factor(&st, &caller, &b.code).await?;
    let id = caller.user.id;
    let (codes, hashes) = fresh_recovery();
    st.with_app(move |a| a.totp_replace_recovery(id, &hashes))
        .await?
        .map_err(store_err)?;
    caller
        .audit(&st, "totp.recovery.regenerate", "new recovery codes")
        .await;
    Ok(Json(RecoveryCodes {
        recovery_codes: codes,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct RequiredBody {
    pub required: bool,
}

/// Require a second factor of every password account (admin).
pub async fn set_required(State(st): State<AppState>, caller: Caller, Json(b): Json<RequiredBody>) -> R {
    caller.require(Role::Admin)?;
    let v = if b.required { "1" } else { "0" };
    st.with_app(move |a| a.set_meta("totp_required", v))
        .await?
        .map_err(store_err)?;
    st.inner.totp_required.store(b.required, Ordering::Relaxed);
    caller
        .audit(
            &st,
            "totp.policy",
            if b.required {
                "a second factor is required for password accounts"
            } else {
                "a second factor is optional"
            },
        )
        .await;
    Ok(Json(status_of(&st, &caller).await?).into_response())
}

/// Remove a user's second factor (admin), for a lost device. Their sessions end.
pub async fn admin_reset(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Admin)?;
    let removed = st
        .with_app(move |a| {
            let r = a.totp_remove(id);
            if matches!(r, Ok(true)) {
                let _ = a.revoke_sessions(id);
            }
            r
        })
        .await?
        .map_err(store_err)?;
    if !removed {
        return Err(reject(StatusCode::NOT_FOUND, "that user has no second factor"));
    }
    caller.audit(&st, "user.totp.reset", &format!("user {id}")).await;
    Ok(empty(StatusCode::NO_CONTENT))
}

/// Paths a session may use while an admin's policy requires a second factor it does not have yet.
pub(crate) fn exempt_while_enrolling(path: &str) -> bool {
    let p = path.strip_prefix("/api/v1").unwrap_or(path);
    matches!(
        p,
        "/auth/me" | "/auth/logout" | "/auth/totp" | "/auth/totp/enroll" | "/auth/totp/confirm" | "/status"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B: the SHA-1 secret is "12345678901234567890" and the codes there are 8 digits; the
    /// last 6 digits of each are the 6-digit codes.
    const RFC_SECRET: &[u8] = b"12345678901234567890";
    const VECTORS: &[(u64, &str)] = &[
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ];

    #[test]
    fn rfc_6238_test_vectors() {
        for (t, want) in VECTORS {
            assert_eq!(&code_at(RFC_SECRET, *t), want, "t = {t}");
        }
    }

    #[test]
    fn rfc_4226_hotp_vectors() {
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, i as u64), *w, "counter {i}");
        }
    }

    #[test]
    fn the_window_is_one_step_either_side() {
        let t = 1_111_111_109u64;
        let at = |secs| code_at(RFC_SECRET, secs);
        assert!(check(RFC_SECRET, t, &at(t), 0).is_some());
        assert!(
            check(RFC_SECRET, t, &at(t - STEP_SECS), 0).is_some(),
            "previous step"
        );
        assert!(check(RFC_SECRET, t, &at(t + STEP_SECS), 0).is_some(), "next step");
        assert!(
            check(RFC_SECRET, t, &at(t - 2 * STEP_SECS), 0).is_none(),
            "two steps back"
        );
        assert!(
            check(RFC_SECRET, t, &at(t + 2 * STEP_SECS), 0).is_none(),
            "two steps ahead"
        );
    }

    #[test]
    fn a_step_works_once() {
        let t = 1_111_111_109u64;
        let code = code_at(RFC_SECRET, t);
        let step = check(RFC_SECRET, t, &code, 0).unwrap();
        assert_eq!(step, t / STEP_SECS);
        assert!(
            check(RFC_SECRET, t, &code, step as i64).is_none(),
            "replay of the same step"
        );
        let older = code_at(RFC_SECRET, t - STEP_SECS);
        assert!(
            check(RFC_SECRET, t, &older, step as i64).is_none(),
            "an older step after a newer one"
        );
        let newer = code_at(RFC_SECRET, t + STEP_SECS);
        assert!(
            check(RFC_SECRET, t, &newer, step as i64).is_some(),
            "the next step is still fine"
        );
    }

    #[test]
    fn malformed_codes_are_refused() {
        let t = 59;
        for bad in ["", "28708", "2870822", "28708a", "abcdef", "２８７０８２"] {
            assert!(check(RFC_SECRET, t, bad, 0).is_none(), "{bad:?}");
        }
        assert!(
            check(RFC_SECRET, t, " 287 082 ", 0).is_some(),
            "spaces are ignored"
        );
    }

    #[test]
    fn base32_round_trips_and_matches_rfc_4648() {
        for (plain, enc) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(plain.as_bytes()), enc);
            assert_eq!(base32_decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(base32_decode("mzxw 6ytb-oi==").unwrap(), b"foobar");
        assert!(base32_decode("MZXW1").is_none(), "1 is not base32");
        let s = new_secret();
        assert_eq!(base32_decode(&base32_encode(&s)).unwrap(), s);
    }

    #[test]
    fn the_uri_names_the_account_and_the_parameters() {
        let u = otpauth_uri("ann@example.com", "JBSWY3DPEHPK3PXP");
        assert_eq!(
            u,
            "otpauth://totp/Bosun:ann%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Bosun&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_are_grouped_and_compare_without_the_dashes() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 19, "{c}");
        assert_eq!(c.matches('-').count(), 3);
        assert_eq!(
            recovery_hash(&c),
            recovery_hash(&c.to_lowercase().replace('-', " "))
        );
        assert_ne!(recovery_hash(&c), recovery_hash(&new_recovery_code()));
        assert!(!looks_like_code(&c));
        assert!(looks_like_code("123 456"));
    }

    #[test]
    fn a_pending_sign_in_expires_binds_to_an_address_and_runs_out_of_tries() {
        let user = User {
            id: 1,
            username: "ann".into(),
            role: Role::Viewer,
            created_ms: 0,
        };
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let p = Pending::default();
        let t = p.start(user.clone(), a).unwrap();
        assert!(p.attempt("bosun_pending_nope", a).is_none());
        assert!(p.attempt(&t, b).is_none(), "another address");
        assert!(p.attempt(&t, a).is_none(), "and that ended it");
        let t = p.start(user.clone(), a).unwrap();
        for _ in 0..PENDING_TRIES {
            assert!(p.attempt(&t, a).is_some());
        }
        assert!(p.attempt(&t, a).is_none(), "out of tries");
        let t = p.start(user.clone(), a).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            p.attempt_within(&t, a, Duration::from_millis(10)).is_none(),
            "expired"
        );
        let t = p.start(user, a).unwrap();
        assert!(p.attempt(&t, a).is_some());
        p.finish(&t);
        assert!(p.attempt(&t, a).is_none(), "used");
    }
}
