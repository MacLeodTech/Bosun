//! GraphQL introspection results: one POST per query and mutation field. The endpoint is given as the base URL, and
//! the introspection query itself is never sent from here.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::{ImportError, Options, Out, json_body, text};

const MAX_FIELDS: usize = 12;

pub fn parse(input: &[u8], opts: &Options, out: &mut Out) -> Result<(), ImportError> {
    let doc: Value =
        serde_json::from_slice(input).map_err(|e| ImportError::Syntax(format!("invalid JSON: {e}")))?;
    let schema = doc
        .pointer("/data/__schema")
        .or_else(|| doc.get("__schema"))
        .ok_or_else(|| ImportError::Unsupported("not an introspection result (no __schema)".into()))?;
    let endpoint = opts
        .base_url
        .as_deref()
        .filter(|b| !b.trim().is_empty())
        .ok_or(ImportError::NoBaseUrl)?
        .trim();
    let types: HashMap<&str, &Value> = schema
        .get("types")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| Some((text(t, "name")?, t)))
        .collect();
    for (key, keyword) in [("queryType", "query"), ("mutationType", "mutation")] {
        let Some(root) = schema.pointer(&format!("/{key}/name")).and_then(Value::as_str) else {
            continue;
        };
        let Some(fields) = types.get(root).and_then(|t| t.get("fields")).and_then(Value::as_array) else {
            continue;
        };
        for f in fields {
            if out.full() {
                out.dropped += 1;
                continue;
            }
            let Some(name) = text(f, "name").filter(|n| ident(n)) else {
                continue;
            };
            let mut decls = Vec::new();
            let mut uses = Vec::new();
            let mut vars = Map::new();
            let mut ok = true;
            for a in f.get("args").and_then(Value::as_array).into_iter().flatten() {
                let ty = &a["type"];
                if ty.get("kind").and_then(Value::as_str) != Some("NON_NULL") {
                    continue;
                }
                let (Some(an), Some(decl)) = (text(a, "name").filter(|n| ident(n)), type_ref(ty, 0)) else {
                    ok = false;
                    break;
                };
                decls.push(format!("${an}: {decl}"));
                uses.push(format!("{an}: ${an}"));
                vars.insert(an.to_string(), sample(&types, ty, 0));
            }
            if !ok {
                out.note(format!("{keyword} {name}: argument types could not be read"));
                continue;
            }
            let mut q = format!("{keyword} {}", cap(name));
            if !decls.is_empty() {
                q.push_str(&format!("({})", decls.join(", ")));
            }
            q.push_str(&format!(" {{ {name}"));
            if !uses.is_empty() {
                q.push_str(&format!("({})", uses.join(", ")));
            }
            let sel = selection(&types, &f["type"], 1);
            if let Some(s) = sel {
                q.push_str(&format!(" {{ {s} }}"));
            }
            q.push_str(" }");
            let body = json_body(&json!({ "operationName": cap(name), "query": q, "variables": vars }));
            out.push(
                &format!("{keyword} {name}"),
                "POST",
                endpoint,
                vec![("Content-Type".into(), "application/json".into())],
                body,
            );
        }
    }
    Ok(())
}

fn cap(n: &str) -> String {
    let mut c = n.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

/// A GraphQL name. Introspection results are untrusted and the names end up in query text.
fn ident(s: &str) -> bool {
    let mut c = s.chars();
    s.len() <= 128
        && c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
        && !s.starts_with("__")
}

fn type_ref(t: &Value, depth: u8) -> Option<String> {
    if depth > 8 {
        return None;
    }
    match t.get("kind")?.as_str()? {
        "NON_NULL" => Some(format!("{}!", type_ref(t.get("ofType")?, depth + 1)?)),
        "LIST" => Some(format!("[{}]", type_ref(t.get("ofType")?, depth + 1)?)),
        _ => text(t, "name").filter(|n| ident(n)).map(str::to_string),
    }
}

/// The named type under NON_NULL and LIST wrappers.
fn named<'a>(types: &HashMap<&str, &'a Value>, mut t: &'a Value) -> Option<&'a Value> {
    for _ in 0..9 {
        match t.get("ofType").filter(|o| !o.is_null()) {
            Some(o) => t = o,
            None => return types.get(text(t, "name")?).copied().or(Some(t)),
        }
    }
    None
}

fn sample(types: &HashMap<&str, &Value>, t: &Value, depth: u8) -> Value {
    if depth > 4 {
        return Value::Null;
    }
    match t.get("kind").and_then(Value::as_str) {
        Some("NON_NULL") => sample(types, &t["ofType"], depth + 1),
        Some("LIST") => json!([sample(types, &t["ofType"], depth + 1)]),
        Some("ENUM") => types
            .get(text(t, "name").unwrap_or(""))
            .and_then(|e| e.pointer("/enumValues/0/name"))
            .cloned()
            .unwrap_or(Value::Null),
        Some("INPUT_OBJECT") => {
            let mut o = Map::new();
            let fields = types.get(text(t, "name").unwrap_or("")).and_then(|d| d.get("inputFields"));
            for f in fields.and_then(Value::as_array).into_iter().flatten().take(MAX_FIELDS) {
                if f["type"].get("kind").and_then(Value::as_str) == Some("NON_NULL")
                    && let Some(n) = text(f, "name").filter(|n| ident(n))
                {
                    o.insert(n.into(), sample(types, &f["type"], depth + 1));
                }
            }
            Value::Object(o)
        }
        _ => match text(t, "name") {
            Some("Int") => json!(1),
            Some("Float") => json!(1.5),
            Some("Boolean") => json!(true),
            Some("ID") => json!("1"),
            _ => json!("test"),
        },
    }
}

/// Fields to ask for: scalars and enums, plus one level of objects. `None` for a leaf type.
fn selection(types: &HashMap<&str, &Value>, t: &Value, depth: u8) -> Option<String> {
    let nt = named(types, t)?;
    match nt.get("kind").and_then(Value::as_str) {
        Some("SCALAR" | "ENUM") => return None,
        Some("OBJECT") => {}
        _ => return Some("__typename".into()),
    }
    let mut parts = Vec::new();
    for f in nt.get("fields").and_then(Value::as_array).into_iter().flatten() {
        if parts.len() >= MAX_FIELDS {
            break;
        }
        let Some(n) = text(f, "name").filter(|n| ident(n)) else {
            continue;
        };
        let needs_args = f
            .get("args")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x["type"].get("kind").and_then(Value::as_str) == Some("NON_NULL")));
        if needs_args {
            continue;
        }
        match named(types, &f["type"]).and_then(|x| x.get("kind")).and_then(Value::as_str) {
            Some("SCALAR" | "ENUM") => parts.push(n.to_string()),
            Some("OBJECT") if depth > 0 => {
                if let Some(s) = selection(types, &f["type"], depth - 1) {
                    parts.push(format!("{n} {{ {s} }}"));
                }
            }
            _ => {}
        }
    }
    Some(if parts.is_empty() { "__typename".into() } else { parts.join(" ") })
}
