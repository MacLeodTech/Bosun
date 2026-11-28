//! OpenAPI 3.x and Swagger 2.0 (JSON or YAML): one request per operation, with example values filled in.

use serde_json::{Map, Value};

use crate::schema::{deref, example, scalar_text};
use crate::{ImportError, Options, Out, form_body, has_header, json_body, text};

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

pub fn parse(input: &[u8], opts: &Options, out: &mut Out) -> Result<(), ImportError> {
    let doc = load(input)?;
    let v3 = text(&doc, "openapi").is_some_and(|v| v.starts_with("3."));
    let v2 = text(&doc, "swagger") == Some("2.0");
    if !v3 && !v2 {
        return Err(ImportError::Unsupported(
            "not an OpenAPI 3.x or Swagger 2.0 document".into(),
        ));
    }
    let base = base_url(&doc, v3, opts)?;
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Ok(());
    };
    for (path, item) in paths {
        let Some(item) = deref(&doc, item).as_object() else {
            continue;
        };
        for m in METHODS {
            let Some(op) = item.get(m).and_then(Value::as_object) else {
                continue;
            };
            if out.full() {
                out.dropped += 1;
                continue;
            }
            operation(&doc, v3, &base, path, m, item, op, out);
        }
    }
    Ok(())
}

/// JSON, or YAML turned into the same value. YAML aliases are refused: expanding them is how a small file becomes
/// a huge one.
fn load(input: &[u8]) -> Result<Value, ImportError> {
    let first = input.iter().find(|b| !b.is_ascii_whitespace());
    if matches!(first, Some(b'{')) {
        return serde_json::from_slice(input).map_err(|e| ImportError::Syntax(format!("invalid JSON: {e}")));
    }
    let text = std::str::from_utf8(input).map_err(|_| ImportError::Syntax("not UTF-8 text".into()))?;
    if has_alias(text) {
        return Err(ImportError::Unsupported(
            "YAML anchors and aliases are not accepted; expand them or use JSON".into(),
        ));
    }
    let y: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| ImportError::Syntax(format!("invalid YAML: {e}")))?;
    Ok(yaml_to_json(&y, 0))
}

/// True when a YAML node starts with `&anchor` or `*alias` (or a `<<` merge key is used).
fn has_alias(text: &str) -> bool {
    let b = text.as_bytes();
    let name = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    for (i, &c) in b.iter().enumerate() {
        if (c == b'*' || c == b'&')
            && b.get(i + 1).is_some_and(|&n| name(n))
            && (i == 0
                || matches!(
                    b[i - 1],
                    b' ' | b'\t' | b'\n' | b'\r' | b'[' | b'{' | b',' | b'-' | b':'
                ))
        {
            return true;
        }
    }
    text.contains("<<:")
}

fn yaml_to_json(y: &serde_yaml_ng::Value, depth: u8) -> Value {
    use serde_yaml_ng::Value as Y;
    if depth > 64 {
        return Value::Null;
    }
    match y {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(*b),
        Y::Number(n) => serde_json::to_value(n).unwrap_or(Value::Null),
        Y::String(s) => Value::String(s.clone()),
        Y::Sequence(s) => Value::Array(s.iter().map(|v| yaml_to_json(v, depth + 1)).collect()),
        Y::Mapping(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let k = match k {
                        Y::String(s) => s.clone(),
                        Y::Number(n) => n.to_string(),
                        Y::Bool(b) => b.to_string(),
                        _ => String::new(),
                    };
                    (k, yaml_to_json(v, depth + 1))
                })
                .collect(),
        ),
        Y::Tagged(t) => yaml_to_json(&t.value, depth + 1),
    }
}

fn base_url(doc: &Value, v3: bool, opts: &Options) -> Result<String, ImportError> {
    if let Some(b) = opts.base_url.as_deref().filter(|b| !b.trim().is_empty()) {
        return Ok(b.trim().trim_end_matches('/').to_string());
    }
    if v3 {
        let server = doc
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .ok_or(ImportError::NoBaseUrl)?;
        let mut url = text(server, "url").ok_or(ImportError::NoBaseUrl)?.to_string();
        if let Some(vars) = server.get("variables").and_then(Value::as_object) {
            for (k, v) in vars {
                if let Some(d) = text(v, "default") {
                    url = url.replace(&format!("{{{k}}}"), d);
                }
            }
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ImportError::NoBaseUrl);
        }
        Ok(url.trim_end_matches('/').to_string())
    } else {
        let host = text(doc, "host").ok_or(ImportError::NoBaseUrl)?;
        let schemes: Vec<&str> = doc
            .get("schemes")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let scheme = if schemes.contains(&"https") || schemes.is_empty() {
            "https"
        } else {
            schemes[0]
        };
        let base = text(doc, "basePath").unwrap_or("").trim_end_matches('/');
        let base = if base.is_empty() || base.starts_with('/') {
            base.to_string()
        } else {
            format!("/{base}")
        };
        Ok(format!("{scheme}://{host}{base}"))
    }
}

fn param_value(doc: &Value, p: &Value) -> String {
    // v3 keeps the schema under `schema`, v2 on the parameter itself.
    let e = p
        .get("example")
        .cloned()
        .unwrap_or_else(|| match p.get("schema") {
            Some(s) => example(doc, s, 0),
            None => example(doc, p, 0),
        });
    scalar_text(&e)
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

#[allow(clippy::too_many_arguments)]
fn operation(
    doc: &Value,
    v3: bool,
    base: &str,
    path: &str,
    method: &str,
    item: &Map<String, Value>,
    op: &Map<String, Value>,
    out: &mut Out,
) {
    let name = op.get("operationId").and_then(Value::as_str).map_or_else(
        || format!("{} {path}", method.to_ascii_uppercase()),
        str::to_string,
    );
    // Path-level parameters first; an operation's own parameter of the same name and place replaces them.
    let mut params: Vec<&Value> = Vec::new();
    for list in [item.get("parameters"), op.get("parameters")] {
        for p in list.and_then(Value::as_array).into_iter().flatten().take(200) {
            let p = deref(doc, p);
            let key = (text(p, "name"), text(p, "in"));
            params.retain(|q| (text(q, "name"), text(q, "in")) != key);
            params.push(p);
        }
    }
    let mut url_path = path.to_string();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut form: Vec<(String, String)> = Vec::new();
    let mut body: Option<(String, Vec<u8>)> = None;
    for p in params {
        let (Some(pname), Some(place)) = (text(p, "name"), text(p, "in")) else {
            continue;
        };
        let required = p.get("required").and_then(Value::as_bool).unwrap_or(false);
        match place {
            "path" => url_path = url_path.replace(&format!("{{{pname}}}"), &enc(&param_value(doc, p))),
            "query" if required || p.get("example").is_some() => {
                query.push((pname.into(), param_value(doc, p)))
            }
            "header" if required => headers.push((pname.into(), param_value(doc, p))),
            "formData" if required => form.push((pname.into(), param_value(doc, p))),
            "body" => {
                let s = p.get("schema").map(|s| example(doc, s, 0)).unwrap_or(Value::Null);
                body = Some(("application/json".into(), json_body(&s)));
            }
            _ => {}
        }
    }
    if !form.is_empty() && body.is_none() {
        body = Some(("application/x-www-form-urlencoded".into(), form_body(&form)));
    }
    if v3 && let Some(rb) = op.get("requestBody").map(|r| deref(doc, r)) {
        body = request_body(doc, rb);
    }
    let mut url = format!("{base}{url_path}");
    if !query.is_empty() {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(&String::from_utf8_lossy(&form_body(&query)));
    }
    if let Some((ct, bytes)) = body {
        if !has_header(&headers, "content-type") {
            headers.push(("Content-Type".into(), ct));
        }
        out.push(&name, method, &url, headers, bytes);
    } else {
        out.push(&name, method, &url, headers, Vec::new());
    }
}

fn request_body(doc: &Value, rb: &Value) -> Option<(String, Vec<u8>)> {
    let content = rb.get("content")?.as_object()?;
    let (ct, media) = content.iter().find(|(k, _)| k.contains("json")).or_else(|| {
        content
            .iter()
            .find(|(k, _)| k.as_str() == "application/x-www-form-urlencoded")
    })?;
    let ex = media
        .get("example")
        .cloned()
        .or_else(|| {
            media
                .get("examples")?
                .as_object()?
                .values()
                .next()
                .and_then(|e| deref(doc, e).get("value").cloned())
        })
        .or_else(|| media.get("schema").map(|s| example(doc, s, 0)))
        .unwrap_or(Value::Null);
    let bytes = if ct.contains("json") {
        json_body(&ex)
    } else {
        let pairs: Vec<(String, String)> = ex
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), scalar_text(v))).collect())
            .unwrap_or_default();
        form_body(&pairs)
    };
    Some((ct.clone(), bytes))
}
