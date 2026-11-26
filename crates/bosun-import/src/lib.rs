//! Imports (WP-60): turn an OpenAPI or Swagger description, a GraphQL introspection result, a Postman collection, a
//! HAR file, a list of URLs or a Burp XML export into request definitions.
//!
//! This crate only parses. It never opens a connection: what it returns are [`Item`]s that the caller stores (as
//! Repeater tabs) and that are sent later, one by one, through the scope gate like any other tool traffic.
//! Everything here reads hostile input, so every parser is bounded: input size, nesting depth, item count, body
//! size, YAML aliases and XML entities are all capped or refused.

mod burp;
mod graphql;
mod har;
mod openapi;
mod postman;
mod schema;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// The largest input accepted, bytes.
pub const MAX_INPUT: usize = 32 << 20;
/// The most requests one import yields; the rest are counted and dropped.
pub const MAX_ITEMS: usize = 2000;
/// The largest request body kept, bytes.
pub const MAX_BODY: usize = 1 << 20;
/// How many notes (reasons something was skipped) are kept.
const MAX_NOTES: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// OpenAPI 3.x or Swagger 2.0, JSON or YAML.
    Openapi,
    /// A GraphQL introspection result (JSON). Needs a base URL: the endpoint.
    Graphql,
    /// A Postman collection (v2.x).
    Postman,
    /// A HAR file. Only the requests are imported.
    Har,
    /// One URL per line.
    Urls,
    /// A Burp "save items" XML export.
    Burp,
}

impl Format {
    pub const ALL: [Format; 6] = [
        Format::Openapi,
        Format::Graphql,
        Format::Postman,
        Format::Har,
        Format::Urls,
        Format::Burp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Openapi => "openapi",
            Format::Graphql => "graphql",
            Format::Postman => "postman",
            Format::Har => "har",
            Format::Urls => "urls",
            Format::Burp => "burp",
        }
    }
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Format::ALL
            .into_iter()
            .find(|f| f.as_str() == s)
            .ok_or_else(|| format!("unknown format {s:?}: use openapi, graphql, postman, har, urls or burp"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Where relative or missing hosts resolve to (an OpenAPI server, a GraphQL endpoint). Overrides the
    /// document's own servers.
    pub base_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("the file is larger than {} MiB", MAX_INPUT >> 20)]
    TooLarge,
    #[error("{0}")]
    Syntax(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("this needs a base URL (the server or endpoint, such as https://api.example.com)")]
    NoBaseUrl,
    #[error("nothing to import was found")]
    Empty,
}

/// One request definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    /// Upper-case token.
    pub method: String,
    /// Absolute `http` or `https` URL with a host.
    pub url: String,
    /// Header names and values with no control characters. Framing headers (`Host`, `Content-Length`,
    /// `Transfer-Encoding`, `Connection`) are dropped: `raw` writes its own.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The recorded response as HTTP/1.1 bytes (HAR and Burp files carry them).
    pub response: Option<Vec<u8>>,
}

/// The standard GraphQL introspection query (what a client POSTs as `{"query": ...}` to the endpoint).
pub const INTROSPECTION_QUERY: &str = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }";

/// Where an item goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub https: bool,
    pub host: String,
    pub port: u16,
}

impl Item {
    pub fn target(&self) -> Option<Target> {
        let u = url::Url::parse(&self.url).ok()?;
        Some(Target {
            https: u.scheme() == "https",
            host: u.host_str()?.to_string(),
            port: u.port_or_known_default()?,
        })
    }

    /// The request as HTTP/1.1 bytes, ready for the Repeater.
    pub fn raw(&self) -> Option<Vec<u8>> {
        let u = url::Url::parse(&self.url).ok()?;
        let host = u.host_str()?;
        let mut target = u.path().to_string();
        if let Some(q) = u.query() {
            target.push('?');
            target.push_str(q);
        }
        let authority = match u.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let mut out = format!("{} {target} HTTP/1.1\r\nHost: {authority}\r\n", self.method).into_bytes();
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !self.body.is_empty() {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Some(out)
    }
}

#[derive(Debug, Default)]
pub struct Imported {
    pub items: Vec<Item>,
    /// Why things were skipped (at most 50).
    pub notes: Vec<String>,
    /// Items dropped because of the limit on how many one import yields.
    pub dropped: usize,
}

pub fn parse(format: Format, input: &[u8], opts: &Options) -> Result<Imported, ImportError> {
    if input.len() > MAX_INPUT {
        return Err(ImportError::TooLarge);
    }
    let mut out = Out::default();
    match format {
        Format::Openapi => openapi::parse(input, opts, &mut out)?,
        Format::Graphql => graphql::parse(input, opts, &mut out)?,
        Format::Postman => postman::parse(input, opts, &mut out)?,
        Format::Har => har::parse(input, &mut out)?,
        Format::Urls => parse_urls(input, &mut out),
        Format::Burp => burp::parse(input, &mut out)?,
    }
    if out.items.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(Imported {
        items: out.items,
        notes: out.notes,
        dropped: out.dropped,
    })
}

fn parse_urls(input: &[u8], out: &mut Out) {
    for line in String::from_utf8_lossy(input).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(line, "GET", line, Vec::new(), Vec::new());
    }
}

/// Collects validated items.
#[derive(Default)]
pub(crate) struct Out {
    pub items: Vec<Item>,
    pub notes: Vec<String>,
    pub dropped: usize,
}

impl Out {
    pub fn note(&mut self, s: impl Into<String>) {
        if self.notes.len() < MAX_NOTES {
            let mut s: String = s.into();
            s.truncate(s.floor_char_boundary(200));
            self.notes.push(s);
        }
    }

    pub fn full(&self) -> bool {
        self.items.len() >= MAX_ITEMS
    }

    /// Validate and add one request. A request that is not safe or sensible to store is skipped with a note.
    pub fn push(
        &mut self,
        name: &str,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        mut body: Vec<u8>,
    ) {
        if self.full() {
            self.dropped += 1;
            return;
        }
        let method = method.trim().to_ascii_uppercase();
        if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return self.note(format!("{name}: unusable method"));
        }
        let Ok(u) = url::Url::parse(url.trim()) else {
            return self.note(format!("{name}: not an absolute URL"));
        };
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none_or(str::is_empty) {
            return self.note(format!("{name}: only http and https URLs with a host are imported"));
        }
        if body.len() > MAX_BODY {
            body.truncate(MAX_BODY);
            self.note(format!("{name}: body cut to {} KiB", MAX_BODY >> 10));
        }
        let headers = headers
            .into_iter()
            .filter(|(k, v)| {
                let ok_name = !k.is_empty()
                    && k.len() <= 256
                    && k.bytes().all(|b| b.is_ascii_graphic() && b != b':');
                let ok_val = v.len() <= 8192 && !v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
                ok_name
                    && ok_val
                    && !matches!(
                        k.to_ascii_lowercase().as_str(),
                        "host" | "content-length" | "transfer-encoding" | "connection" | "keep-alive"
                    )
            })
            .collect();
        let mut name = name.replace(['\r', '\n'], " ");
        name.truncate(name.floor_char_boundary(120));
        self.items.push(Item {
            name,
            method,
            url: u.to_string(),
            headers,
            body,
            response: None,
        });
    }

    /// Like `push`, and keeps `response` with the item if it was accepted. Over-long responses are dropped.
    pub fn push_with_response(
        &mut self,
        name: &str,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        response: Option<Vec<u8>>,
    ) {
        let before = self.items.len();
        self.push(name, method, url, headers, body);
        if self.items.len() > before
            && let Some(r) = response.filter(|r| !r.is_empty() && r.len() <= 2 * MAX_BODY + 65536)
            && let Some(i) = self.items.last_mut()
        {
            i.response = Some(r);
        }
    }
}

pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

pub(crate) fn has_header(h: &[(String, String)], name: &str) -> bool {
    h.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

pub(crate) fn json_body(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

/// A form body, `a=1&b=2`.
pub(crate) fn form_body(pairs: &[(String, String)]) -> Vec<u8> {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish().into_bytes()
}
