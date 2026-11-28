//! JSON Schema helpers for OpenAPI: following local `$ref`s and building an example value. Everything is depth
//! limited, so a schema that refers to itself ends instead of looping.

use serde_json::{Map, Value};

const MAX_DEPTH: u8 = 6;
const MAX_REFS: u8 = 8;
const MAX_PROPS: usize = 40;

/// Follow `{"$ref": "#/..."}` inside the same document (a bounded number of hops). Other references (files, URLs)
/// are never fetched: they come back as the object itself.
pub fn deref<'a>(root: &'a Value, mut v: &'a Value) -> &'a Value {
    for _ in 0..MAX_REFS {
        let Some(r) = v.get("$ref").and_then(Value::as_str) else {
            return v;
        };
        let Some(ptr) = r.strip_prefix('#') else {
            return v;
        };
        match root.pointer(ptr) {
            Some(t) => v = t,
            None => return v,
        }
    }
    v
}

/// An example value for a schema.
pub fn example(root: &Value, schema: &Value, depth: u8) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    let s = deref(root, schema);
    for k in ["example", "default", "const"] {
        if let Some(v) = s.get(k) {
            return v.clone();
        }
    }
    if let Some(v) = s.get("enum").and_then(Value::as_array).and_then(|a| a.first()) {
        return v.clone();
    }
    if let Some(all) = s.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for part in all.iter().take(MAX_PROPS) {
            if let Value::Object(o) = example(root, part, depth + 1) {
                merged.extend(o);
            }
        }
        if !merged.is_empty() {
            return Value::Object(merged);
        }
    }
    for k in ["oneOf", "anyOf"] {
        if let Some(first) = s.get(k).and_then(Value::as_array).and_then(|a| a.first()) {
            return example(root, first, depth + 1);
        }
    }
    let ty = match s.get("type") {
        Some(Value::String(t)) => t.as_str(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null")
            .unwrap_or("null"),
        _ if s.get("properties").is_some() => "object",
        _ if s.get("items").is_some() => "array",
        _ => "string",
    };
    match ty {
        "object" => {
            let mut o = Map::new();
            if let Some(props) = s.get("properties").and_then(Value::as_object) {
                for (k, p) in props.iter().take(MAX_PROPS) {
                    o.insert(k.clone(), example(root, p, depth + 1));
                }
            }
            Value::Object(o)
        }
        "array" => match s.get("items") {
            Some(i) => Value::Array(vec![example(root, i, depth + 1)]),
            None => Value::Array(Vec::new()),
        },
        "integer" => Value::from(1),
        "number" => Value::from(1.5),
        "boolean" => Value::Bool(true),
        "null" => Value::Null,
        _ => Value::String(
            match s.get("format").and_then(Value::as_str) {
                Some("date-time") => "2024-01-01T00:00:00Z",
                Some("date") => "2024-01-01",
                Some("uuid") => "00000000-0000-4000-8000-000000000000",
                Some("email") => "user@example.com",
                Some("uri" | "url") => "https://example.com/",
                Some("byte") => "dGVzdA==",
                _ => "test",
            }
            .into(),
        ),
    }
}

/// A scalar example as the text of a path segment, query value or header.
pub fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Array(a) => a.first().map(scalar_text).unwrap_or_default(),
        other => other.to_string(),
    }
}
