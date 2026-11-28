//! Client certificates for targets that require mutual TLS. The list shows host, subject and expiry only; the
//! private key is sealed with the data key, loaded into the connector and never returned. Adding and removing
//! are admin actions and are audited. The certificate applies to the proxy's upstream connections and to the
//! tools (Repeater, Intruder, Sequencer, scanner), matched by the target's host.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bosun_ca::DataKey;
use bosun_model::now_ms;
use bosun_proxy::Proxy;
use bosun_proxy::clientcert::{Identity, MAX_INPUT, describe, normalize_pattern, parse_identity};
use bosun_store::{ClientCertMeta, Role, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::{empty, reject};

type R = Result<Response, Response>;

fn purpose(host: &str) -> String {
    format!("clientcert:{host}")
}

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "a client certificate task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

fn store_err(e: StoreError) -> Response {
    match e {
        StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
        e => internal(e),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

/// Load the active project's certificates into the proxy's registry (shared with the tools). Blocking.
pub(crate) fn reload(proxy: &Proxy, key: &DataKey) -> Result<(), StoreError> {
    let rows = proxy.project().client_cert_rows()?;
    let items = rows
        .into_iter()
        .filter_map(|r| {
            let sealed = key.open(&purpose(&r.host), &r.sealed_key).ok()?;
            Some((
                r.host,
                Identity {
                    chain: r.chain_der,
                    key: sealed,
                },
            ))
        })
        .collect();
    proxy.client_certs().replace(items);
    Ok(())
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientCertList {
    pub certs: Vec<ClientCertMeta>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientCertBody {
    /// Host pattern: `api.example.com`, or `*.example.com` for every name under it.
    pub host: String,
    /// A PEM file holding the certificate (and any chain) and the private key.
    #[serde(default)]
    pub pem: Option<String>,
    /// A PKCS#12 file, base64.
    #[serde(default)]
    pub pkcs12_base64: Option<String>,
    /// The PKCS#12 password (may be empty).
    #[serde(default)]
    pub password: Option<String>,
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let certs = blocking(move || p.client_certs()).await?.map_err(internal)?;
    Ok(Json(ClientCertList { certs }).into_response())
}

pub async fn add(State(st): State<AppState>, caller: Caller, Json(b): Json<ClientCertBody>) -> R {
    caller.require(Role::Admin)?;
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    let host = normalize_pattern(&b.host).map_err(|e| bad(&e))?;
    let data = match (&b.pem, &b.pkcs12_base64) {
        (Some(p), None) => p.clone().into_bytes(),
        (None, Some(x)) => {
            if x.len() > MAX_INPUT * 2 {
                return Err(bad("the file is too large"));
            }
            base64::engine::general_purpose::STANDARD
                .decode(x.trim())
                .map_err(|_| bad("the PKCS#12 file is not valid base64"))?
        }
        _ => return Err(bad("give exactly one of `pem` and `pkcs12_base64`")),
    };
    let password = b.password.unwrap_or_default();
    // Parsing untrusted input and key derivation for PKCS#12 are CPU work: off the async workers.
    let id = blocking(move || parse_identity(&data, &password))
        .await?
        .map_err(|e| bad(&e))?;
    let (subject, not_after) = describe(&id).map_err(|e| bad(&e))?;
    let sealed = st
        .inner
        .data_key
        .seal(&purpose(&host), &id.key)
        .map_err(internal)?;
    let (p, h, s) = (st.project(), host.clone(), subject.clone());
    let chain = id.chain;
    let row = blocking(move || {
        let rid = p.client_cert_add(&h, &s, not_after, &chain, &sealed, now_ms())?;
        Ok::<_, StoreError>(ClientCertMeta {
            id: rid,
            host: h,
            subject: s,
            not_after_ms: not_after,
            created_ms: now_ms(),
        })
    })
    .await?
    .map_err(store_err)?;
    refresh(&st).await?;
    caller
        .audit(
            &st,
            "clientcert.add",
            &format!("client certificate for `{host}` ({subject})"),
        )
        .await;
    Ok((StatusCode::CREATED, Json(row)).into_response())
}

pub async fn delete(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Admin)?;
    let p = st.project();
    let host = blocking(move || p.client_cert_delete(id))
        .await?
        .map_err(store_err)?
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such client certificate"))?;
    refresh(&st).await?;
    caller
        .audit(
            &st,
            "clientcert.remove",
            &format!("client certificate for `{host}`"),
        )
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

async fn refresh(st: &AppState) -> Result<(), Response> {
    let (proxy, key) = (st.inner.proxy.clone(), st.inner.data_key.clone());
    blocking(move || reload(&proxy, &key)).await?.map_err(internal)?;
    // Pooled connections were made without (or with the old) certificate.
    st.inner.repeater.close_idle();
    Ok(())
}
