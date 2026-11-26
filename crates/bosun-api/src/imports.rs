//! Imports (WP-60): request definitions from OpenAPI, GraphQL introspection, Postman, HAR, URL lists and Burp XML,
//! saved as Repeater tabs. Nothing is sent here. A tab is sent only when someone sends it from the Repeater (or the
//! CLI), and that path goes through the scope gate like every other tool request.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_import::{Format, ImportError, Options};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::repeater::{MAX_TABS, MAX_TABS_BYTES, TabsDoc};
use crate::security::reject;

type R = Result<Response, Response>;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportBody {
    pub format: Format,
    /// The file's text (at most 32 MiB).
    pub content: String,
    /// The server or endpoint to use when the file has none: required for GraphQL, overrides an OpenAPI server.
    pub base_url: Option<String>,
    /// Parse and report, but save nothing.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportReply {
    pub format: Format,
    /// Requests found in the file.
    pub parsed: u32,
    /// Requests saved as Repeater tabs (0 for a dry run).
    pub added: u32,
    /// Requests left out because the Repeater already holds the most tabs it can.
    pub not_added: u32,
    /// Requests dropped by the per-import limit (2000).
    pub dropped: u32,
    /// Why entries were skipped.
    pub notes: Vec<String>,
    /// The hosts (`host:port`) the requests go to, so the scope can be checked before anything is sent.
    pub hosts: Vec<String>,
    /// One line per request: method and URL.
    pub requests: Vec<String>,
}

pub async fn import_requests(State(st): State<AppState>, caller: Caller, Json(b): Json<ImportBody>) -> R {
    caller.require(Role::Tester)?;
    if b.content.len() > bosun_import::MAX_INPUT {
        return Err(reject(StatusCode::PAYLOAD_TOO_LARGE, "the file is too large"));
    }
    if let Some(u) = b.base_url.as_deref().filter(|u| !u.trim().is_empty())
        && !url::Url::parse(u.trim()).is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())
    {
        return Err(reject(StatusCode::BAD_REQUEST, "the base URL must be an http or https URL"));
    }
    let format = b.format;
    let opts = Options { base_url: b.base_url };
    let content = b.content;
    let parsed = tokio::task::spawn_blocking(move || bosun_import::parse(format, content.as_bytes(), &opts))
        .await
        .map_err(crate::handlers::internal)?
        .map_err(|e| match e {
            ImportError::TooLarge => reject(StatusCode::PAYLOAD_TOO_LARGE, &e.to_string()),
            e => reject(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
        })?;
    let mut hosts: Vec<String> = Vec::new();
    let mut tabs: Vec<(String, Value)> = Vec::new();
    for it in &parsed.items {
        let (Some(t), Some(raw)) = (it.target(), it.raw()) else {
            continue;
        };
        // The Repeater edits requests as text; a body that is not text would be changed on the way.
        let Ok(request) = String::from_utf8(raw) else {
            continue;
        };
        let host = format!("{}:{}", t.host, t.port);
        if !hosts.contains(&host) && hosts.len() < 100 {
            hosts.push(host);
        }
        tabs.push((
            format!("{} {}", it.method, it.url),
            json!({
                "kind": "http", "frames": [], "listenMs": 1500, "name": it.name,
                "scheme": if t.https { "https" } else { "http" }, "host": t.host, "port": t.port,
                "protocol": "http1", "request": request, "mode": "utf8", "updateLength": false,
                "verifyTls": false, "follow": false, "count": 1, "sendMode": "sequential",
                "history": [], "shown": 0,
            }),
        ));
    }
    let n = tabs.len();
    let mut added = 0usize;
    if !b.dry_run && n > 0 {
        let _settings = st.inner.projects.settings_guard().await;
        let p = st.project();
        let tabs_in: Vec<Value> = tabs.iter().map(|(_, v)| v.clone()).collect();
        added = tokio::task::spawn_blocking(move || -> Result<usize, bosun_store::StoreError> {
            let mut doc = p.setting::<TabsDoc>(crate::SETTING_REPEATER_TABS).unwrap_or(None).unwrap_or_default();
            let mut next = doc
                .next
                .max(doc.tabs.iter().filter_map(|t| t["id"].as_i64()).max().unwrap_or(0) + 1)
                .max(1);
            let room = MAX_TABS.saturating_sub(doc.tabs.len());
            let take = room.min(tabs_in.len());
            // The saved tabs may not outgrow what the Repeater accepts back from the page.
            let mut size = serde_json::to_vec(&doc).map_or(0, |b| b.len());
            let mut took = 0;
            for mut t in tabs_in.into_iter().take(take) {
                t["id"] = json!(next);
                size += t.to_string().len() + 1;
                if size > MAX_TABS_BYTES {
                    break;
                }
                next += 1;
                took += 1;
                doc.tabs.push(t);
            }
            doc.next = next;
            if took > 0 {
                p.set_setting(crate::SETTING_REPEATER_TABS, &doc)?;
            }
            Ok(took)
        })
        .await
        .map_err(crate::handlers::internal)?
        .map_err(crate::handlers::internal)?;
        caller
            .audit(
                &st,
                "import.requests",
                &format!(
                    "{} added={added} parsed={n} hosts={}",
                    format.as_str(),
                    hosts.iter().take(10).cloned().collect::<Vec<_>>().join(",")
                ),
            )
            .await;
    }
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    Ok(Json(ImportReply {
        format,
        parsed: count(n),
        added: count(added),
        not_added: if b.dry_run { 0 } else { count(n - added) },
        dropped: count(parsed.dropped),
        notes: parsed.notes,
        hosts,
        requests: tabs.into_iter().map(|(l, _)| l).take(200).collect(),
    })
    .into_response())
}
