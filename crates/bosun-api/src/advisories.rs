//! The advisory database for known-vulnerable components (WP-82) and its signed feed (see `bosun_checks::advisory`).
//!
//! Anyone with the viewer role can see which database is in force. The admin role sets the public keys that may
//! sign a feed and loads a feed: the feed is accepted only when its detached Ed25519 signature verifies under one of
//! those keys and its `sequence` is higher than the database in force (so an old, validly signed feed cannot be put
//! back). Nothing is fetched from anywhere: the feed is uploaded. Every change is audited.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bosun_checks::advisory::{self, AdvisoryDb, FeedError, MAX_KEYS, Stored};
use bosun_model::now_ms;
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::{empty, reject};

type R = Result<Response, Response>;

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "an advisory task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = AdvisoryStatus)]
pub struct Status {
    /// `bundled` (the small database that ships with the program) or `feed`.
    pub source: String,
    pub sequence: u64,
    /// When the database was made, `YYYY-MM-DD`.
    pub generated: String,
    pub advisories: usize,
    /// Public keys (base64 Ed25519) that may sign a feed.
    pub trusted_keys: Vec<String>,
    /// When the feed was loaded (milliseconds), if one is.
    pub loaded_ms: Option<i64>,
}

fn status_of(p: &bosun_store::Project) -> Status {
    let db = advisory::load(p);
    Status {
        source: db.source.to_string(),
        sequence: db.sequence,
        generated: db.generated.clone(),
        advisories: db.advisories.len(),
        trusted_keys: advisory::trusted_keys(p),
        loaded_ms: (db.source == "feed")
            .then(|| advisory::stored(p).map(|s| s.loaded_ms))
            .flatten(),
    }
}

pub async fn get(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    Ok(Json(blocking(move || status_of(&p)).await?).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = AdvisoryTrustBody)]
pub struct TrustBody {
    /// Base64 Ed25519 public keys (32 bytes each), at most 5. An empty list means no feed can be loaded.
    pub keys: Vec<String>,
}

pub async fn put_trust(State(st): State<AppState>, caller: Caller, Json(b): Json<TrustBody>) -> R {
    caller.require(Role::Admin)?;
    if b.keys.len() > MAX_KEYS {
        return Err(reject(StatusCode::BAD_REQUEST, "at most 5 keys"));
    }
    let keys: Vec<String> = b.keys.iter().map(|k| k.trim().to_string()).collect();
    let engine = base64::engine::general_purpose::STANDARD;
    if keys
        .iter()
        .any(|k| engine.decode(k).map_or(true, |raw| raw.len() != 32))
    {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "a key is not a base64 Ed25519 public key (32 bytes)",
        ));
    }
    let p = st.project();
    let n = keys.len();
    blocking(move || p.set_setting(advisory::SETTING_KEYS, &keys))
        .await?
        .map_err(internal)?;
    caller
        .audit(&st, "advisories.trust", &format!("{n} trusted feed key(s)"))
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = AdvisoryFeedBody)]
pub struct FeedBody {
    /// The feed file, as text: exactly the bytes that were signed.
    pub feed: String,
    /// The detached Ed25519 signature over those bytes, base64.
    pub signature: String,
    /// Queue every recorded flow for the scanner again, so the new advisories apply to recorded traffic (default true).
    #[serde(default)]
    pub rescan: Option<bool>,
}

pub async fn post_feed(State(st): State<AppState>, caller: Caller, Json(b): Json<FeedBody>) -> R {
    caller.require(Role::Admin)?;
    let p = st.project();
    let rescan = b.rescan.unwrap_or(true);
    let out = blocking(
        move || -> Result<Result<Status, (StatusCode, String)>, bosun_store::StoreError> {
            let keys = advisory::trusted_keys(&p);
            let (feed, _) = match advisory::verify(b.feed.as_bytes(), &b.signature, &keys) {
                Ok(v) => v,
                Err(e @ (FeedError::NoKeys | FeedError::Unverified)) => {
                    return Ok(Err((StatusCode::UNPROCESSABLE_ENTITY, e.to_string())));
                }
                Err(e) => return Ok(Err((StatusCode::BAD_REQUEST, e.to_string()))),
            };
            let current: AdvisoryDb = advisory::load(&p);
            if feed.sequence <= current.sequence {
                return Ok(Err((
                    StatusCode::CONFLICT,
                    format!(
                        "the feed's sequence ({}) must be higher than the one in force ({})",
                        feed.sequence, current.sequence
                    ),
                )));
            }
            p.set_setting(
                advisory::SETTING_FEED,
                &Stored {
                    feed: b.feed,
                    signature: b.signature,
                    loaded_ms: now_ms(),
                },
            )?;
            if rescan {
                p.scan_restart()?;
            }
            Ok(Ok(status_of(&p)))
        },
    )
    .await?
    .map_err(internal)?;
    match out {
        Ok(s) => {
            caller
                .audit(
                    &st,
                    "advisories.update",
                    &format!("feed {} loaded: {} advisories", s.sequence, s.advisories),
                )
                .await;
            Ok(Json(s).into_response())
        }
        Err((code, m)) => {
            caller.audit(&st, "advisories.update_refused", &m).await;
            Err(reject(code, &m))
        }
    }
}

pub async fn delete_feed(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Admin)?;
    let p = st.project();
    blocking(move || p.delete_setting(advisory::SETTING_FEED))
        .await?
        .map_err(internal)?;
    caller
        .audit(&st, "advisories.reset", "back to the built-in advisories")
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}
