//! Postman collections (v2.x): folders are walked, `{{variables}}` are filled from the collection's own variables.

use std::collections::HashMap;

use serde_json::Value;

use crate::{ImportError, Options, Out, form_body, has_header, json_body, text};

const MAX_DEPTH: u8 = 16;

pub fn parse(input: &[u8], opts: &Options, out: &mut Out) -> Result<(), ImportError> {
    let doc: Value =
        serde_json::from_slice(input).map_err(|e| ImportError::Syntax(format!("invalid JSON: {e}")))?;
    let items = doc
        .get("item")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::Unsupported("not a Postman collection (no item list)".into()))?;
    let vars: HashMap<String, String> = doc
        .get("variable")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| Some((text(v, "key")?.to_string(), v.get("value").map(scalar)?)))
        .collect();
    walk(items, &vars, opts, out, 0);
    Ok(())
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }
}

fn walk(items: &[Value], vars: &HashMap<String, String>, opts: &Options, out: &mut Out, depth: u8) {
    if depth > MAX_DEPTH {
        out.note("folders nested too deeply; the rest was skipped");
        return;
    }
    for it in items {
        if out.full() {
            out.dropped += 1;
            continue;
        }
        if let Some(sub) = it.get("item").and_then(Value::as_array) {
            walk(sub, vars, opts, out, depth + 1);
        } else if let Some(r) = it.get("request") {
            request(text(it, "name").unwrap_or("request"), r, vars, opts, out);
        }
    }
}

/// Replace `{{name}}`. Names that are not collection variables stay as they are.
fn fill(s: &str, vars: &HashMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in vars {
        if out.contains("{{") {
            out = out.replace(&format!("{{{{{k}}}}}"), v);
        }
    }
    out
}

fn request(name: &str, r: &Value, vars: &HashMap<String, String>, opts: &Options, out: &mut Out) {
    // A request may be just a URL string.
    if let Some(u) = r.as_str() {
        return finish(name, "GET", u, Vec::new(), Vec::new(), vars, opts, out);
    }
    let method = text(r, "method").unwrap_or("GET");
    let url = match r.get("url") {
        Some(Value::String(s)) => s.clone(),
        Some(u) => text(u, "raw").unwrap_or("").to_string(),
        None => String::new(),
    };
    let mut headers: Vec<(String, String)> = r
        .get("header")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|h| !h.get("disabled").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|h| {
            Some((
                fill(text(h, "key")?, vars),
                fill(text(h, "value").unwrap_or(""), vars),
            ))
        })
        .collect();
    let mut body = Vec::new();
    if let Some(b) = r.get("body") {
        let enabled = |p: &&Value| !p.get("disabled").and_then(Value::as_bool).unwrap_or(false);
        let pairs = |key: &str| -> Vec<(String, String)> {
            b.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(enabled)
                .filter(|p| text(p, "type") != Some("file"))
                .filter_map(|p| {
                    Some((
                        fill(text(p, "key")?, vars),
                        fill(text(p, "value").unwrap_or(""), vars),
                    ))
                })
                .collect()
        };
        let ct = match text(b, "mode") {
            Some("raw") => {
                body = fill(text(b, "raw").unwrap_or(""), vars).into_bytes();
                let json = b.pointer("/options/raw/language").and_then(Value::as_str) == Some("json");
                json.then_some("application/json")
            }
            Some("urlencoded") => {
                body = form_body(&pairs("urlencoded"));
                Some("application/x-www-form-urlencoded")
            }
            Some("formdata") => {
                const BOUNDARY: &str = "----BosunImportBoundary";
                for (k, v) in pairs("formdata") {
                    // A header-breaking name would split the part; drop those fields.
                    if k.contains(['"', '\r', '\n']) {
                        continue;
                    }
                    body.extend_from_slice(
                        format!(
                            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                        )
                        .as_bytes(),
                    );
                }
                if !body.is_empty() {
                    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
                }
                Some("multipart/form-data; boundary=----BosunImportBoundary")
            }
            Some("graphql") => {
                let g = &b["graphql"];
                let vars_json: Value = text(g, "variables")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_else(|| Value::Object(Default::default()));
                body = json_body(
                    &serde_json::json!({ "query": fill(text(g, "query").unwrap_or(""), vars), "variables": vars_json }),
                );
                Some("application/json")
            }
            _ => None,
        };
        if let Some(ct) = ct
            && !body.is_empty()
            && !has_header(&headers, "content-type")
        {
            headers.push(("Content-Type".into(), ct.into()));
        }
    }
    finish(name, method, &url, headers, body, vars, opts, out);
}

#[allow(clippy::too_many_arguments)]
fn finish(
    name: &str,
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    vars: &HashMap<String, String>,
    opts: &Options,
    out: &mut Out,
) {
    let mut url = fill(url, vars);
    // `{{baseUrl}}/x` with no such variable: the base URL given for the import stands in for it.
    if let (Some(base), true) = (opts.base_url.as_deref(), url.starts_with("{{"))
        && let Some(end) = url.find("}}")
    {
        url = format!("{}{}", base.trim_end_matches('/'), &url[end + 2..]);
    }
    if url.contains("{{") {
        return out.note(format!("{name}: the URL uses a variable with no value"));
    }
    out.push(name, method, &url, headers, body);
}
