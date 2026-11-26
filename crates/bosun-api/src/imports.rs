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
    /// The file's text (at most 32 MiB). Not needed with `introspection_url`.
    #[serde(default)]
    pub content: String,
    /// The server or endpoint to use when the file has none: required for GraphQL, overrides an OpenAPI server.
    pub base_url: Option<String>,
    /// Parse and report, but save nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// GraphQL only: fetch the introspection result live by POSTing the introspection query to this endpoint
    /// URL (it is also the base URL). The request goes through the scope gate like any Repeater request; an
    /// out-of-scope endpoint is refused. `content` is ignored.
    #[serde(default)]
    pub introspection_url: Option<String>,
    /// HAR and Burp: also store the recorded responses as flows (source `import`). Nothing is sent.
    #[serde(default)]
    pub store_responses: bool,
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
    /// Recorded responses stored as flows (0 unless `store_responses`).
    pub responses_stored: u32,
    /// Why entries were skipped.
    pub notes: Vec<String>,
    /// The hosts (`host:port`) the requests go to, so the scope can be checked before anything is sent.
    pub hosts: Vec<String>,
    /// One line per request: method and URL.
    pub requests: Vec<String>,
}

/// POST the introspection query to `endpoint` through the Repeater's engine (so the gate decides) and return the
/// JSON body.
async fn fetch_introspection(st: &AppState, endpoint: &url::Url) -> Result<String, Response> {
    use bosun_http::SendError;
    use bosun_model::{FlowSource, RawResponse, Scheme, Target};
    let host = endpoint.host_str().unwrap_or_default();
    let port = endpoint.port_or_known_default().unwrap_or(80);
    let scheme = if endpoint.scheme() == "https" { Scheme::Https } else { Scheme::Http };
    let mut path = endpoint.path().to_string();
    if let Some(q) = endpoint.query() {
        path.push('?');
        path.push_str(q);
    }
    let authority = match endpoint.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let body = json!({ "query": bosun_import::INTROSPECTION_QUERY }).to_string();
    let raw = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let opts = bosun_http::SendOptions {
        source: FlowSource::Repeater,
        ..bosun_http::SendOptions::default()
    };
    let ex = st
        .inner
        .repeater
        .send(&Target::new(scheme, host, port), raw.as_bytes(), &opts)
        .await
        .map_err(|e| match e {
            SendError::Refused(e) => reject(StatusCode::FORBIDDEN, &format!("refused by the scope gate: {e}")),
            e => reject(StatusCode::BAD_GATEWAY, &e.to_string()),
        })?;
    let id = st.project().next_flow_id();
    st.inner.proxy.record(ex.to_new_flow(id, FlowSource::Repeater));
    let bad = |m: String| reject(StatusCode::BAD_GATEWAY, &m);
    let r = RawResponse::parse(&ex.response).map_err(|_| bad("the endpoint sent no usable response".into()))?;
    if !(200..300).contains(&r.status) {
        return Err(bad(format!("the endpoint answered {}", r.status)));
    }
    let chunked = r
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().ends_with(b"chunked"));
    let body = if chunked { bosun_crawl::dechunk(&r.body).unwrap_or_default() } else { r.body };
    String::from_utf8(body).map_err(|_| bad("the response is not text".into()))
}

/// Store the recorded responses of imported items as flows; the count stored.
fn store_responses(st: &AppState, items: &[bosun_import::Item]) -> usize {
    use bosun_model::{FlowSource, RawResponse, Scheme};
    let project = st.project();
    let scope = st.inner.repeater.gate().scope();
    let mut flows = Vec::new();
    for it in items {
        let (Some(t), Some(request), Some(response)) = (it.target(), it.raw(), it.response.clone()) else {
            continue;
        };
        let Ok(parsed) = RawResponse::parse(&response) else { continue };
        let scheme = if t.https { Scheme::Https } else { Scheme::Http };
        let path = url::Url::parse(&it.url)
            .map(|u| u.path().to_string() + &u.query().map(|q| format!("?{q}")).unwrap_or_default())
            .unwrap_or_else(|_| "/".into());
        flows.push(bosun_store::NewFlow {
            id: project.next_flow_id(),
            source: FlowSource::Import,
            started_ms: bosun_model::now_ms(),
            duration_ms: None,
            ttfb_ms: None,
            scheme,
            host: t.host.clone(),
            port: t.port,
            method: it.method.clone(),
            in_scope: scope.contains(scheme, &t.host, t.port, &path),
            path,
            http_version: "HTTP/1.1".into(),
            status: Some(parsed.status),
            edited: false,
            error: None,
            request,
            original_request: None,
            response: Some(response),
            original_response: None,
            response_truncated: false,
        });
    }
    let n = flows.len();
    if n > 0 {
        let _ = project.write_batch(&flows, &[]);
    }
    n
}

pub async fn import_requests(State(st): State<AppState>, caller: Caller, Json(mut b): Json<ImportBody>) -> R {
    caller.require(Role::Tester)?;
    let mut fetched: Option<String> = None;
    if let Some(u) = b.introspection_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        if b.format != Format::Graphql {
            return Err(reject(StatusCode::BAD_REQUEST, "introspection_url is for the graphql format"));
        }
        let url = url::Url::parse(u)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())
            .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "the introspection URL must be an http or https URL"))?;
        b.content = fetch_introspection(&st, &url).await?;
        if b.base_url.as_deref().is_none_or(|u| u.trim().is_empty()) {
            b.base_url = Some(url.to_string());
        }
        fetched = Some(url.to_string());
    }
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
    let stored = if b.store_responses && !b.dry_run { store_responses(&st, &parsed.items) } else { 0 };
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
    }
    if fetched.is_some() || (!b.dry_run && n > 0) {
        caller
            .audit(
                &st,
                "import.requests",
                &format!(
                    "{} added={added} parsed={n} responses={stored} hosts={}{}",
                    format.as_str(),
                    hosts.iter().take(10).cloned().collect::<Vec<_>>().join(","),
                    fetched.map(|u| format!(" fetched={u}")).unwrap_or_default()
                ),
            )
            .await;
    }
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    Ok(Json(ImportReply {
        format,
        parsed: count(n),
        responses_stored: count(stored),
        added: count(added),
        not_added: if b.dry_run { 0 } else { count(n - added) },
        dropped: count(parsed.dropped),
        notes: parsed.notes,
        hosts,
        requests: tabs.into_iter().map(|(l, _)| l).take(200).collect(),
    })
    .into_response())
}
