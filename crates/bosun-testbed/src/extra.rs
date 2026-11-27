//! The planted issues added for the rest of the core active checks (WP-55): XXE, upload, JWT, deserialization,
//! prototype pollution, GraphQL, session cookies and TLS. Each has a safe twin.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{Reply, Rq, State, html, read_file};

/// The key the safe JWT endpoints sign with: not on any list of weak secrets.
pub const STRONG_SECRET: &str = "k9$Tz!q2Lw7vXr#8Fm4PbN1cYd6Hs0UeVa5";

fn hs256(secret: &str, input: &str) -> Vec<u8> {
    // HMAC takes a key of any length.
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("any key length");
    m.update(input.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// An HS256 token for `payload` (JSON text) signed with `secret`.
pub fn jwt_hs256(secret: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
        B64.encode(payload)
    );
    let sig = B64.encode(hs256(secret, &input));
    format!("{input}.{sig}")
}

fn json_reply(status: u16, v: &Value) -> Reply {
    Reply::new(status, "application/json", v.to_string())
}

/// `verify`: check the signature; `allow_none`: accept `alg: none`.
fn jwt(rq: &Rq<'_>, secret: &str, verify: bool, allow_none: bool) -> Reply {
    let denied = || json_reply(401, &json!({"error": "invalid token"}));
    let Some(tok) = rq.header("authorization").strip_prefix("Bearer ") else {
        return denied();
    };
    let parts: Vec<&str> = tok.split('.').collect();
    let [h, p, s] = parts[..] else { return denied() };
    let Some(head) = B64
        .decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    else {
        return denied();
    };
    if B64.decode(p).is_err() {
        return denied();
    }
    let alg = head["alg"].as_str().unwrap_or("").to_ascii_lowercase();
    let ok = if alg == "none" {
        allow_none
    } else if alg == "hs256" {
        !verify
            || B64
                .decode(s)
                .is_ok_and(|sig| sig == hs256(secret, &format!("{h}.{p}")))
    } else {
        false
    };
    if ok {
        json_reply(200, &json!({"user": "alice"}))
    } else {
        denied()
    }
}

/// A pretend XML parser: resolves `<!ENTITY n SYSTEM "file:///path">` when `entities` is on, else refuses a DOCTYPE.
fn xml_import(body: &str, entities: bool) -> Reply {
    if body.contains("<!DOCTYPE") && !entities {
        return Reply::new(400, "text/plain", "DOCTYPE is disallowed");
    }
    let mut text = body.to_string();
    let mut rest = body;
    while let Some((_, r)) = rest.split_once("<!ENTITY ") {
        let Some((name, r2)) = r.split_once(" SYSTEM \"file://") else {
            break;
        };
        let Some((path, after)) = r2.split_once('"') else {
            break;
        };
        let value = match read_file("/var/www/docs", path) {
            Some(c) => c.to_string(),
            None => {
                return Reply::new(
                    500,
                    "text/plain",
                    format!("I/O warning : failed to load external entity \"file://{path}\""),
                );
            }
        };
        text = text.replace(&format!("&{};", name.trim()), &value);
        rest = after;
    }
    // Only the text of the document shows in the answer.
    let mut out = String::new();
    let mut tag = false;
    let mut skip = 0;
    for c in text.chars() {
        match c {
            '<' => tag = true,
            '>' => {
                tag = false;
                out.push(' ');
            }
            _ if tag => {}
            '[' => skip += 1,
            ']' if skip > 0 => skip -= 1,
            _ if skip == 0 => out.push(c),
            _ => {}
        }
    }
    html(&format!("Imported: {}", super::escape(out.trim())))
}

fn upload(rq: &Rq<'_>, allow: &[&str]) -> Reply {
    if !rq.header("content-type").starts_with("multipart/form-data") {
        return Reply::new(400, "text/plain", "multipart only");
    }
    let Some(name) = rq
        .body
        .split_once("filename=\"")
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(n, _)| n)
    else {
        return Reply::new(400, "text/plain", "no file");
    };
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if !allow.is_empty() && (!allow.contains(&ext.as_str()) || name.matches('.').count() != 1) {
        return Reply::new(415, "text/plain", "file type not allowed");
    }
    Reply::new(201, "text/plain", format!("Saved as /uploads/{name}"))
}

fn restore(data: &str, verbose: bool) -> Reply {
    let err = if data.starts_with("rO0") {
        "java.io.StreamCorruptedException: invalid stream header: 7F61C3AD"
    } else if data.starts_with("O:") || data.starts_with("a:") {
        "Notice: unserialize(): Error at offset 12 of 30 bytes in /var/www/restore.php"
    } else if data.starts_with("AAEAAAD") {
        "System.Runtime.Serialization.SerializationException: End of Stream encountered before parsing was completed."
    } else if data.starts_with("gAS") {
        "_pickle.UnpicklingError: pickle data was truncated"
    } else if data.is_empty() {
        return html("Welcome back");
    } else {
        "invalid session"
    };
    if verbose {
        Reply::new(500, "text/plain", err)
    } else {
        Reply::new(400, "text/plain", "invalid session")
    }
}

/// Settings merged from JSON. The vulnerable one lets `__proto__` write to the properties every object inherits,
/// which every later answer then carries.
fn settings(body: &str, st: &State, vulnerable: bool) -> Reply {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return json_reply(400, &json!({"error": "bad json"}));
    };
    if vulnerable {
        let polluted = v
            .get("__proto__")
            .or_else(|| v.pointer("/constructor/prototype"))
            .and_then(Value::as_object);
        if let Some(o) = polluted {
            let mut p = st.proto.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (k, x) in o {
                p.retain(|(n, _)| n != k);
                p.push((k.clone(), x.as_str().unwrap_or("").to_string()));
            }
        }
    }
    if vulnerable {
        settings_view(st)
    } else {
        json_reply(200, &json!({"theme": "dark"}))
    }
}

fn settings_view(st: &State) -> Reply {
    let mut o = serde_json::Map::new();
    o.insert("theme".into(), json!("dark"));
    for (k, v) in st
        .proto
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
    {
        o.insert(k.clone(), json!(v));
    }
    json_reply(200, &Value::Object(o))
}

fn gql_one(q: &str, safe: bool) -> Value {
    const KNOWN: [&str; 3] = ["user", "users", "me"];
    if q.contains("__schema") {
        return if safe {
            json!({"errors": [{"message": "GraphQL introspection is not allowed"}]})
        } else {
            json!({"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}})
        };
    }
    if q.contains("__typename") {
        let mut data = serde_json::Map::new();
        for t in q.split([' ', '{', '}', ',']) {
            match t.split_once(':') {
                Some((alias, "__typename")) => data.insert(alias.to_string(), json!("Query")),
                None if t == "__typename" => data.insert(t.to_string(), json!("Query")),
                _ => None,
            };
        }
        if safe && data.len() > 10 {
            return json!({"errors": [{"message": "Too many aliases"}]});
        }
        return json!({"data": data});
    }
    let field = q.trim().trim_start_matches('{').trim_end_matches('}').trim();
    if KNOWN.contains(&field) {
        return json!({"data": {field: null}});
    }
    let mut msg = format!("Cannot query field \"{field}\" on type \"Query\".");
    if !safe
        && !field.is_empty()
        && let Some(k) = KNOWN.iter().find(|k| k.starts_with(field))
    {
        msg.push_str(&format!(" Did you mean \"{k}\"?"));
    }
    json!({"errors": [{"message": msg}]})
}

fn graphql(body: &str, safe: bool) -> Reply {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return json_reply(400, &json!({"errors": [{"message": "bad json"}]}));
    };
    match v {
        Value::Array(_) if safe => {
            json_reply(400, &json!({"errors": [{"message": "batching is not allowed"}]}))
        }
        Value::Array(a) => json_reply(
            200,
            &Value::Array(
                a.iter()
                    .map(|x| gql_one(x["query"].as_str().unwrap_or(""), false))
                    .collect(),
            ),
        ),
        v => json_reply(200, &gql_one(v["query"].as_str().unwrap_or(""), safe)),
    }
}

fn session(rq: &Rq<'_>, st: &State, safe: bool) -> Reply {
    let sent = rq
        .header("cookie")
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == "sid")
        .map(|(_, v)| v.to_string());
    if safe {
        let n = st.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = hex(&hs256(STRONG_SECRET, &n.to_string())[..12]);
        html("welcome").header(format!(
            "Set-Cookie: sid={id}; Path=/; HttpOnly; Secure; SameSite=Lax"
        ))
    } else {
        // Takes the id the client brings and sets no flags.
        let id = sent.unwrap_or_else(|| "fixedsid0001".into());
        html("welcome").header(format!("Set-Cookie: sid={id}; Path=/"))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn route(rq: &Rq<'_>, st: &State) -> Option<Reply> {
    let (path, query) = rq.target.split_once('?').unwrap_or((rq.target, ""));
    Some(match (rq.method, path) {
        ("POST", "/xml/import") => xml_import(rq.body, true),
        ("POST", "/xml/import-safe") => xml_import(rq.body, false),
        // Resolves entities like /xml/import but never shows what they held: only a missing file shows.
        ("POST", "/xml/import-blind") => {
            let r = xml_import(rq.body, true);
            if r.status == 200 { html("Imported") } else { r }
        }
        ("POST", "/upload") => upload(rq, &[]),
        ("POST", "/upload-safe") => upload(rq, &["png", "jpg", "txt"]),
        ("GET", "/api/jwt") => jwt(rq, "secret", true, true),
        ("GET", "/api/jwt-unsigned") => jwt(rq, STRONG_SECRET, false, false),
        ("GET", "/api/jwt-safe") => jwt(rq, STRONG_SECRET, true, false),
        ("GET", "/session/restore") => restore(&super::param(query, "data"), true),
        ("GET", "/session/restore-safe") => restore(&super::param(query, "data"), false),
        ("POST", "/api/settings") => settings(rq.body, st, true),
        ("POST", "/api/settings-safe") => settings(rq.body, st, false),
        ("GET", "/api/settings") => settings_view(st),
        ("POST", "/graphql") => graphql(rq.body, false),
        ("POST", "/graphql-safe") => graphql(rq.body, true),
        ("GET", "/session/start") => session(rq, st, false),
        ("GET", "/session/start-safe") => session(rq, st, true),
        _ => return None,
    })
}

/// The TLS servers the TLS check is tried on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKind {
    /// A certificate from a CA, in date, TLS 1.2 and 1.3 only, modern suites only (the safe twin).
    Good,
    /// A CA-issued certificate that ran out in 2020.
    Expired,
    /// A certificate that is its own issuer, in date.
    SelfSigned,
    /// Answers a TLS 1.0 hello and RC4, 3DES, NULL and export suites with a ServerHello (it never completes a
    /// handshake: the check needs no more than the hello).
    Legacy,
}

/// Start a TLS server on a free loopback port. It answers `200 ok` to any request, except `Legacy`.
pub async fn start_tls(kind: TlsKind) -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    if kind == TlsKind::Legacy {
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                tokio::spawn(legacy(s));
            }
        });
        return Ok(addr);
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config(kind)?));
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let a = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut t) = a.accept(s).await else { return };
                let mut buf = [0u8; 2048];
                let _ = t.read(&mut buf).await;
                let _ = t
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
                let _ = t.shutdown().await;
            });
        }
    });
    Ok(addr)
}

fn server_config(kind: TlsKind) -> std::io::Result<rustls::ServerConfig> {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair};
    let bad = |e: &dyn std::fmt::Display| std::io::Error::other(e.to_string());
    let name = |cn: &str| {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn
    };
    let leaf_key = KeyPair::generate().map_err(|e| bad(&e))?;
    let mut leaf = CertificateParams::new(vec!["127.0.0.1".to_string()]).map_err(|e| bad(&e))?;
    leaf.distinguished_name = name("testbed leaf");
    let der = if kind == TlsKind::SelfSigned {
        leaf.self_signed(&leaf_key).map_err(|e| bad(&e))?.der().clone()
    } else {
        let ca_key = KeyPair::generate().map_err(|e| bad(&e))?;
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(|e| bad(&e))?;
        ca.distinguished_name = name("testbed CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        if kind == TlsKind::Expired {
            leaf.not_before = rcgen::date_time_ymd(2019, 1, 1);
            leaf.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        let issuer = Issuer::new(ca, ca_key);
        leaf.signed_by(&leaf_key, &issuer)
            .map_err(|e| bad(&e))?
            .der()
            .clone()
    };
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| bad(&e))?
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .map_err(|e| bad(&e))
}

/// Suites the legacy server will pick: RC4, 3DES, NULL and export.
const WEAK_SUITES: [u16; 10] = [
    0x0005, 0x0004, 0xc011, 0x000a, 0xc012, 0x0001, 0x0002, 0x0003, 0x0008, 0x0014,
];

async fn legacy(mut s: tokio::net::TcpStream) {
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
        match s.read(&mut buf[n..]).await {
            Ok(0) | Err(_) => return,
            Ok(k) => n += k,
        }
        if n == buf.len() {
            return;
        }
    }
    let _ = match server_hello(&buf[..n]) {
        Some(r) => s.write_all(&r).await,
        None => s.write_all(&[0x15, 3, 3, 0, 2, 2, 70]).await,
    };
    let _ = s.shutdown().await;
}

fn server_hello(h: &[u8]) -> Option<Vec<u8>> {
    if h.len() < 44 || h[0] != 0x16 || h[5] != 0x01 {
        return None;
    }
    let version = [h[9], h[10]];
    let at = 44 + usize::from(h[43]);
    let len = usize::from(u16::from_be_bytes([*h.get(at)?, *h.get(at + 1)?]));
    let suites: Vec<u16> = h
        .get(at + 2..at + 2 + len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    let old = version < [3, 3];
    let suite = match suites.iter().copied().find(|s| WEAK_SUITES.contains(s)) {
        Some(w) => w,
        None if old => *suites.first()?,
        None => return None,
    };
    let mut hello = vec![version[0], version[1]];
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&suite.to_be_bytes());
    hello.push(0);
    let mut hs = vec![0x02, 0, 0, hello.len() as u8];
    hs.extend(hello);
    let mut out = vec![0x16, version[0], version[1], 0, hs.len() as u8];
    out.extend(hs);
    Some(out)
}
