//! Request-level defences that apply before any handler runs.
//!
//! The UI is very often opened in the same browser that is being proxied, and that browser is also loading
//! hostile pages from targets. So:
//! - **Host allowlist**: a request whose Host header is not one of ours is refused. This defeats DNS rebinding,
//!   where a target page re-points its own name at 127.0.0.1 to talk to the API from its own origin.
//! - **Origin check**: a cross-origin request carrying an Origin we don't serve is refused, before auth.
//! - **No CORS**: no `Access-Control-Allow-*` header is ever sent, so other origins can't read responses.
//! - **Strict response headers**: CSP without inline script, no framing, no sniffing, no referrer.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;

pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; \
    font-src 'self'; connect-src 'self'; frame-src 'self' blob: data:; object-src 'none'; base-uri 'none'; \
    form-action 'self'; frame-ancestors 'none'";

/// Host name (no port) from a Host header value, lower-cased.
pub fn host_only(h: &str) -> String {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return format!("[{}]", host.to_ascii_lowercase());
    }
    match h.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            host.to_ascii_lowercase()
        }
        _ => h.to_ascii_lowercase(),
    }
}

pub async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_only);
    // HTTP/2 requests carry the authority in the URI instead.
    let host = host.or_else(|| req.uri().authority().map(|a| host_only(a.as_str())));
    let Some(host) = host else {
        return reject(StatusCode::BAD_REQUEST, "missing Host header");
    };
    if !st.inner.allowed_hosts.iter().any(|h| h == &host) {
        tracing::warn!(
            host,
            "refused a request for a host name this server does not use (DNS rebinding?)"
        );
        return reject(
            StatusCode::MISDIRECTED_REQUEST,
            "this server does not answer to that host name",
        );
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let ok = origin.to_str().ok().is_some_and(|o| origin_allowed(&st, o));
        if !ok {
            return reject(StatusCode::FORBIDDEN, "cross-origin request refused");
        }
    }
    // Browsers send Sec-Fetch-Site; anything but same-origin or a direct navigation is refused for API calls.
    if req.uri().path().starts_with("/api/")
        && let Some(site) = req.headers().get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && !matches!(site, "same-origin" | "none")
    {
        return reject(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    );
    if is_api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if st.inner.tls {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

fn origin_allowed(st: &AppState, origin: &str) -> bool {
    // Origins configured explicitly (the UI behind a reverse proxy on another port or name).
    if st
        .inner
        .extra_origins
        .iter()
        .any(|o| o.eq_ignore_ascii_case(origin.trim_end_matches('/')))
    {
        return true;
    }
    // `null` (sandboxed frames, file: pages) and anything unparsable are refused.
    let Ok(uri) = origin.parse::<http::Uri>() else {
        return false;
    };
    let want = if st.inner.tls { "https" } else { "http" };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(host) = uri.host() else { return false };
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let host = host.to_ascii_lowercase();
    scheme == want && port == st.inner.port && st.inner.allowed_hosts.contains(&host)
}

/// Is this a method that changes state (and so needs a CSRF token under cookie auth)?
pub fn is_unsafe(m: &Method) -> bool {
    !matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub fn reject(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

pub fn empty(status: StatusCode) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_strips_ports() {
        assert_eq!(host_only("LocalHost:8090"), "localhost");
        assert_eq!(host_only("[::1]:8090"), "[::1]");
        assert_eq!(host_only("127.0.0.1"), "127.0.0.1");
        assert_eq!(host_only("evil.test:80:1"), "evil.test:80:1");
    }
}
