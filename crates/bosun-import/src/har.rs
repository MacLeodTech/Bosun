//! HAR: the requests of `log.entries`. Responses are not imported.

use serde_json::Value;

use crate::{ImportError, Out, form_body, has_header, text};

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
                    .filter_map(|p| Some((text(p, "name")?.to_string(), text(p, "value").unwrap_or("").to_string())))
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
        out.push(&format!("{method} {url}"), method, url, headers, body);
    }
    Ok(())
}
