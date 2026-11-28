//! HAR: the requests of `log.entries`, with their recorded responses.

use serde_json::Value;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::{ImportError, MAX_BODY, Out, form_body, has_header, text};

/// The recorded response as HTTP/1.1 bytes. The body is stored decoded, so the framing and encoding headers go.
fn response_bytes(r: &Value) -> Option<Vec<u8>> {
    let status = r.get("status")?.as_u64().filter(|s| (100..1000).contains(s))?;
    let content = r.get("content");
    let t = content.and_then(|c| text(c, "text")).unwrap_or("");
    let mut body = if content.and_then(|c| text(c, "encoding")) == Some("base64") {
        B64.decode(t).ok()?
    } else {
        t.as_bytes().to_vec()
    };
    body.truncate(MAX_BODY);
    let reason = text(r, "statusText").unwrap_or("").replace(['\r', '\n'], " ");
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for h in r.get("headers").and_then(Value::as_array).into_iter().flatten() {
        let (Some(k), Some(v)) = (text(h, "name"), text(h, "value")) else {
            continue;
        };
        let k = k.trim();
        if k.is_empty()
            || k.starts_with(':')
            || !k.bytes().all(|b| b.is_ascii_graphic() && b != b':')
            || v.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
            || matches!(
                k.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "content-encoding" | "connection" | "keep-alive"
            )
        {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

pub fn parse(input: &[u8], out: &mut Out) -> Result<(), ImportError> {
    let doc: Value =
        serde_json::from_slice(input).map_err(|e| ImportError::Syntax(format!("invalid JSON: {e}")))?;
    let entries = doc
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::Unsupported("not a HAR file (no log.entries)".into()))?;
    for e in entries {
        let Some(r) = e.get("request") else { continue };
        let (Some(method), Some(url)) = (text(r, "method"), text(r, "url")) else {
            continue;
        };
        let mut headers: Vec<(String, String)> = r
            .get("headers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|h| Some((text(h, "name")?.to_string(), text(h, "value")?.to_string())))
            // HTTP/2 pseudo headers are not header lines.
            .filter(|(k, _)| !k.starts_with(':'))
            .collect();
        let mut body = Vec::new();
        if let Some(pd) = r.get("postData") {
            if let Some(t) = text(pd, "text").filter(|t| !t.is_empty()) {
                body = t.as_bytes().to_vec();
            } else if let Some(ps) = pd.get("params").and_then(Value::as_array) {
                let pairs: Vec<_> = ps
                    .iter()
                    .filter_map(|p| {
                        Some((
                            text(p, "name")?.to_string(),
                            text(p, "value").unwrap_or("").to_string(),
                        ))
                    })
                    .collect();
                body = form_body(&pairs);
            }
            if let Some(ct) = text(pd, "mimeType").filter(|c| !c.is_empty())
                && !body.is_empty()
                && !has_header(&headers, "content-type")
            {
                headers.push(("Content-Type".into(), ct.to_string()));
            }
        }
        let response = e.get("response").and_then(response_bytes);
        out.push_with_response(&format!("{method} {url}"), method, url, headers, body, response);
    }
    Ok(())
}
