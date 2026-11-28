//! GraphQL over HTTP: find the operations in a request body and show the query and the variables apart.
//!
//! The body is JSON: an object with `query`, optional `operationName` and `variables`, or an array of those
//! (batching). The operation name is `operationName` when given, else the name in the first operation of the
//! query. This is a scanner, not a GraphQL parser: it only needs the top-level `query`, `mutation`,
//! `subscription` keywords and a following name, so it skips strings and comments and counts braces.

use serde_json::Value;

use crate::CodecError;

/// The most operations taken from one batched body.
const MAX_OPS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub name: Option<String>,
    /// `query`, `mutation` or `subscription`.
    pub kind: String,
    pub query: String,
    pub variables: Option<Value>,
}

/// The top-level operations of a GraphQL document as `(kind, name)`.
fn scan(doc: &str) -> Vec<(&'static str, Option<String>)> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut depth) = (0, 0usize);
    while i < b.len() {
        match b[i] {
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' if b[i..].starts_with(b"\"\"\"") => {
                i += 3;
                while i < b.len() && !b[i..].starts_with(b"\"\"\"") {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 3;
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' && b[i] != b'\n' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'{' | b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b')' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            c if depth == 0 && (c.is_ascii_alphabetic() || c == b'_') => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let kind = match &doc[start..i] {
                    "query" => "query",
                    "mutation" => "mutation",
                    "subscription" => "subscription",
                    _ => continue,
                };
                while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b',') {
                    i += 1;
                }
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push((kind, (i > s).then(|| doc[s..i].to_owned())));
            }
            _ => i += 1,
        }
    }
    out
}

fn one(v: &Value) -> Option<Operation> {
    let o = v.as_object()?;
    let query = o.get("query").and_then(Value::as_str).unwrap_or("");
    let given = o
        .get("operationName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let found = scan(query);
    // With several operations in the document, `operationName` says which one runs.
    let picked = given
        .and_then(|g| found.iter().find(|(_, n)| n.as_deref() == Some(g)))
        .or_else(|| found.first());
    if query.is_empty() && given.is_none() {
        return None;
    }
    Some(Operation {
        name: given
            .map(str::to_owned)
            .or_else(|| picked.and_then(|p| p.1.clone())),
        kind: picked.map_or("query", |p| p.0).to_owned(),
        query: query.to_owned(),
        variables: o.get("variables").filter(|v| !v.is_null()).cloned(),
    })
}

/// The operations in a request body, or none when it is not a GraphQL request.
pub fn operations(body: &[u8]) -> Vec<Operation> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    match &v {
        Value::Array(a) => a.iter().take(MAX_OPS).filter_map(one).collect(),
        other => one(other).into_iter().collect(),
    }
}

/// Does any operation in `body` have this name?
pub fn has_operation(body: &[u8], name: &str) -> bool {
    operations(body).iter().any(|o| o.name.as_deref() == Some(name))
}

/// The body as readable text: for each operation a heading, the query as sent, and the variables indented.
pub fn decode_text(body: &[u8], limit: usize) -> Result<String, CodecError> {
    let ops = operations(body);
    if ops.is_empty() {
        return Err(CodecError::Invalid("GraphQL request"));
    }
    let mut out = String::new();
    for (i, o) in ops.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "# {} {}\n",
            o.kind,
            o.name.as_deref().unwrap_or("(anonymous)")
        ));
        out.push_str(o.query.trim_end());
        out.push('\n');
        if let Some(v) = &o.variables {
            out.push_str("\n# variables\n");
            out.push_str(&serde_json::to_string_pretty(v).unwrap_or_default());
            out.push('\n');
        }
        if out.len() > limit {
            return Err(CodecError::TooLarge(limit));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(b: &str) -> Vec<(String, Option<String>)> {
        operations(b.as_bytes())
            .into_iter()
            .map(|o| (o.kind, o.name))
            .collect()
    }

    #[test]
    fn name_from_operation_name_or_the_document() {
        assert_eq!(
            names(r#"{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"1"}}"#),
            [("query".into(), Some("GetUser".into()))]
        );
        assert_eq!(
            names(r#"{"query":"mutation { x }","operationName":"Named"}"#),
            [("mutation".into(), Some("Named".into()))]
        );
        assert_eq!(names(r#"{"query":"{ me { id } }"}"#), [("query".into(), None)]);
    }

    #[test]
    fn several_operations_pick_by_operation_name() {
        let b = r#"{"query":"query A { a } mutation B { b }","operationName":"B"}"#;
        assert_eq!(names(b), [("mutation".into(), Some("B".into()))]);
    }

    #[test]
    fn keywords_inside_strings_comments_and_fields_do_not_count() {
        let q = r##"{"query":"# query Fake\n{ search(text: \"mutation Evil\") { query } }"}"##;
        assert_eq!(names(q), [("query".into(), None)]);
    }

    #[test]
    fn batches_and_non_graphql() {
        let b = r#"[{"query":"query A { a }"},{"query":"query B { b }"},{"other":1}]"#;
        assert_eq!(names(b).len(), 2);
        assert!(has_operation(b.as_bytes(), "B") && !has_operation(b.as_bytes(), "C"));
        assert!(operations(b"not json").is_empty());
        assert!(operations(br#"{"a":1}"#).is_empty());
        assert!(decode_text(b"{}", 100).is_err());
    }

    #[test]
    fn text_shows_query_and_variables_apart() {
        let t = decode_text(br#"{"query":"query Q { a }","variables":{"x":1}}"#, 4096).unwrap();
        assert!(
            t.starts_with("# query Q\nquery Q { a }\n\n# variables\n{\n  \"x\": 1\n}"),
            "{t}"
        );
    }

    proptest::proptest! {
        #[test]
        fn scanner_never_panics(s in ".{0,200}") {
            let _ = scan(&s);
        }
    }
}
