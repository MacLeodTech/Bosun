//! Proxy listeners and live proxy settings: several listeners with their own options, added, changed and removed
//! while running, and the settings that change without a restart. Admin only; every change is audited.
//!
//! Both are install-wide (not per project) and kept in the account database so they come back after a restart.
//! Listener passwords are sealed with the data key; they never appear in a response or an audit entry.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bosun_proxy::{ListenerSpec, LiveSettings, ProxyAuth, RESTART_ONLY};
use bosun_store::Role;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Caller;
use crate::handlers::internal;
use crate::security::reject;

type R = Result<Response, Response>;

const META_LISTENERS: &str = "proxy_listeners";
const META_LIVE: &str = "proxy_live";
const SEAL_PURPOSE: &str = "proxy-listeners";
const MAX_LISTENERS: usize = 32;

/// A listener as kept: the password included.
#[derive(Serialize, Deserialize)]
struct Stored {
    primary: bool,
    spec: StoredSpec,
}

#[derive(Serialize, Deserialize)]
struct StoredSpec {
    addr: std::net::SocketAddr,
    invisible: bool,
    tls_passthrough: Vec<String>,
    auth: Option<(String, String)>,
    allow_clients: Vec<ipnet::IpNet>,
}

impl From<&ListenerSpec> for StoredSpec {
    fn from(s: &ListenerSpec) -> Self {
        Self {
            addr: s.addr,
            invisible: s.invisible,
            tls_passthrough: s.tls_passthrough.clone(),
            auth: s.auth.as_ref().map(|a| (a.username.clone(), a.password.clone())),
            allow_clients: s.allow_clients.clone(),
        }
    }
}

impl From<StoredSpec> for ListenerSpec {
    fn from(s: StoredSpec) -> Self {
        Self {
            addr: s.addr,
            invisible: s.invisible,
            tls_passthrough: s.tls_passthrough,
            auth: s.auth.map(|(username, password)| ProxyAuth {
                username,
                password,
                password_file: None,
            }),
            allow_clients: s.allow_clients,
        }
    }
}

fn describe(s: &ListenerSpec) -> String {
    format!(
        "{} invisible={} passthrough={} auth={} allow_clients={}",
        s.addr,
        s.invisible,
        s.tls_passthrough.len(),
        s.auth.as_ref().map_or("none", |a| a.username.as_str()),
        s.allow_clients.len()
    )
}

impl AppState {
    async fn persist_listeners(&self) -> Result<(), Response> {
        let stored: Vec<Stored> = self
            .inner
            .proxy
            .listener_specs()
            .iter()
            .map(|(_, primary, s)| Stored {
                primary: *primary,
                spec: s.into(),
            })
            .collect();
        let json = serde_json::to_vec(&stored).map_err(internal)?;
        let sealed = self.inner.data_key.seal(SEAL_PURPOSE, &json).map_err(internal)?;
        let text = base64::engine::general_purpose::STANDARD.encode(sealed);
        self.with_app(move |a| a.set_meta(META_LISTENERS, &text))
            .await?
            .map_err(internal)
    }

    /// Bring back the saved live settings and listeners. Call once, after the state is built and before serving.
    /// A saved item that no longer applies (a port now taken) is logged and skipped.
    pub async fn restore_proxy_settings(&self) {
        let proxy = &self.inner.proxy;
        let saved = self
            .with_app(|a| (a.meta(META_LIVE), a.meta(META_LISTENERS)))
            .await
            .ok();
        let Some((live, listeners)) = saved else { return };
        if let Ok(Some(text)) = live {
            match serde_json::from_str::<LiveSettings>(&text) {
                Ok(s) => {
                    if let Err(e) = proxy.set_live(s) {
                        tracing::warn!(error = %e, "the saved proxy settings are invalid; using the config file's");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "cannot read the saved proxy settings"),
            }
        }
        let Ok(Some(text)) = listeners else { return };
        // The configured listener registers itself when its accept loop starts; give it a moment.
        for _ in 0..300 {
            if proxy.listener_specs().iter().any(|(_, p, _)| *p) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stored: Vec<Stored> = match base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .ok()
            .and_then(|b| self.inner.data_key.open(SEAL_PURPOSE, &b).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "cannot read the saved proxy listeners; starting with the configured one only"
                );
                return;
            }
        };
        for s in stored {
            let spec: ListenerSpec = s.spec.into();
            let r = if s.primary {
                // Options only: the configured listener keeps the address from the config file.
                let Some((id, _, cur)) = proxy.listener_specs().into_iter().find(|(_, p, _)| *p) else {
                    continue;
                };
                proxy
                    .update_listener(
                        id,
                        ListenerSpec {
                            addr: cur.addr,
                            ..spec
                        },
                    )
                    .await
            } else {
                proxy.add_listener(spec).await
            };
            if let Err(e) = r {
                tracing::warn!(error = %e, "could not restore a proxy listener");
            }
        }
    }
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.listeners()).into_response())
}

fn bad(e: impl std::fmt::Display) -> Response {
    reject(StatusCode::BAD_REQUEST, &e.to_string())
}

pub async fn add(State(st): State<AppState>, caller: Caller, Json(spec): Json<ListenerSpec>) -> R {
    caller.require(Role::Admin)?;
    let _g = st.inner.projects.settings_guard().await;
    if st.inner.proxy.listeners().len() >= MAX_LISTENERS {
        return Err(bad("too many listeners"));
    }
    let detail = describe(&spec);
    let info = st.inner.proxy.add_listener(spec).await.map_err(bad)?;
    st.persist_listeners().await?;
    caller.audit(&st, "proxy.listener.add", &detail).await;
    Ok(Json(info).into_response())
}

pub async fn update(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<u32>,
    Json(mut spec): Json<ListenerSpec>,
) -> R {
    caller.require(Role::Admin)?;
    let _g = st.inner.projects.settings_guard().await;
    let Some((_, _, current)) = st
        .inner
        .proxy
        .listener_specs()
        .into_iter()
        .find(|(i, _, _)| *i == id)
    else {
        return Err(reject(StatusCode::NOT_FOUND, "no such listener"));
    };
    // The password is never sent out, so an edit that leaves it empty keeps the current one.
    if let (Some(new), Some(old)) = (&mut spec.auth, &current.auth)
        && new.password.is_empty()
        && new.username == old.username
    {
        new.password = old.password.clone();
    }
    let detail = describe(&spec);
    let info = st.inner.proxy.update_listener(id, spec).await.map_err(bad)?;
    st.persist_listeners().await?;
    caller
        .audit(&st, "proxy.listener.update", &format!("{id}: {detail}"))
        .await;
    Ok(Json(info).into_response())
}

pub async fn remove(State(st): State<AppState>, caller: Caller, Path(id): Path<u32>) -> R {
    caller.require(Role::Admin)?;
    let _g = st.inner.projects.settings_guard().await;
    let Some((_, _, current)) = st
        .inner
        .proxy
        .listener_specs()
        .into_iter()
        .find(|(i, _, _)| *i == id)
    else {
        return Err(reject(StatusCode::NOT_FOUND, "no such listener"));
    };
    st.inner.proxy.remove_listener(id).map_err(bad)?;
    st.persist_listeners().await?;
    caller
        .audit(
            &st,
            "proxy.listener.remove",
            &format!("{id}: {}", describe(&current)),
        )
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The live settings, and the names of the settings that need a restart.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ProxyConfigView {
    pub live: LiveSettings,
    pub restart_required: Vec<String>,
}

fn view(st: &AppState) -> ProxyConfigView {
    ProxyConfigView {
        live: st.inner.proxy.live(),
        restart_required: RESTART_ONLY.iter().map(|s| s.to_string()).collect(),
    }
}

pub async fn get_config(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(view(&st)).into_response())
}

pub async fn put_config(
    State(st): State<AppState>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> R {
    caller.require(Role::Admin)?;
    let _g = st.inner.projects.settings_guard().await;
    if let Some(obj) = body.as_object()
        && let Some(k) = obj.keys().find(|k| RESTART_ONLY.contains(&k.as_str()))
    {
        return Err(reject(
            StatusCode::CONFLICT,
            &format!("{k} cannot change while running: edit the config file and restart Bosun"),
        ));
    }
    let new: LiveSettings = serde_json::from_value(body).map_err(bad)?;
    let old = st.inner.proxy.live();
    st.inner.proxy.set_live(new.clone()).map_err(bad)?;
    let text = serde_json::to_string(&new).map_err(internal)?;
    st.with_app(move |a| a.set_meta(META_LIVE, &text))
        .await?
        .map_err(internal)?;
    let changed: Vec<String> = {
        let (o, n) = (
            serde_json::to_value(&old).unwrap_or_default(),
            serde_json::to_value(&new).unwrap_or_default(),
        );
        n.as_object()
            .into_iter()
            .flatten()
            .filter(|(k, v)| o.get(k.as_str()) != Some(v))
            .map(|(k, v)| format!("{k}={v}"))
            .collect()
    };
    caller.audit(&st, "proxy.config.update", &changed.join(" ")).await;
    Ok(Json(view(&st)).into_response())
}
