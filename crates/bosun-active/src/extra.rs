//! The rest of the core active checks (WP-55): XXE, file upload, JWT, deserialization, prototype pollution,
//! GraphQL, session cookies and TLS configuration. Like the others they report only what the answer proves.
//! Findings from one request carry a `point` of their own (`jwt:alg-none`, `tls:tls-1.0`) so that two different
//! weaknesses of one URL stay two issues.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bosun_model::Scheme;
use serde_json::{Value, json};

use crate::checks::{self, Hit, file_signature};
use crate::{Answer, Confidence, Finding, Point, Req, Severity, Shared, Strength};

pub const XXE: &str = "active-xxe";
pub const FILE_UPLOAD: &str = "active-file-upload";
pub const JWT: &str = "active-jwt";
pub const DESERIALIZATION: &str = "active-deserialization";
pub const PROTOTYPE_POLLUTION: &str = "active-prototype-pollution";
pub const GRAPHQL: &str = "active-graphql";
pub const SESSION: &str = "active-session";
pub const TLS: &str = "active-tls";

/// The checks that look at a request as a whole.
pub(crate) async fn whole(sh: &Shared, req: &Req) {
    let o = &sh.opts;
    if o.enabled(XXE) {
        xxe(sh, req).await;
    }
    if o.enabled(FILE_UPLOAD) {
        file_upload(sh, req).await;
    }
    if o.enabled(JWT) {
        jwt(sh, req).await;
    }
    if o.enabled(PROTOTYPE_POLLUTION) {
        prototype_pollution(sh, req).await;
    }
    if o.enabled(GRAPHQL) {
        graphql(sh, req).await;
    }
    if o.enabled(SESSION) {
        session(sh, req).await;
    }
    if o.enabled(TLS) {
        tls(sh, req).await;
    }
}

/// Like [`checks::report`], with the finding's own point.
fn report_at(sh: &Shared, req: &Req, point: String, flow_id: i64, h: Hit<'_>) {
    sh.report(Finding {
        check: h.check.into(),
        title: h.title.into(),
        severity: h.severity,
        confidence: h.confidence,
        url: req.base_url(),
        point,
        payload: h.payload,
        detail: h.detail,
        remediation: h.remediation.into(),
        cwe: vec![h.cwe],
        flow_id,
    });
}

// ---- XXE -------------------------------------------------------------------------------------------------------

/// The XML text with a DOCTYPE that declares `xxe` as `system_id` and the first text node replaced by `&xxe;`.
fn with_entity(xml: &str, system_id: &str) -> Option<String> {
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return None;
    }
    let mut doc = xml.trim_start();
    if doc.starts_with("<?xml") {
        doc = doc.split_once("?>")?.1;
    }
    let b = doc.as_bytes();
    let mut i = 0;
    while let Some(gt) = doc[i..].find('>').map(|p| p + i) {
        let end = doc[gt + 1..].find('<').map(|p| p + gt + 1)?;
        let text = &doc[gt + 1..end];
        // Not a tag's own `?>` or `-->` and with something in it.
        if !text.trim().is_empty() && b[gt.saturating_sub(1)] != b'?' && b[gt.saturating_sub(1)] != b'-' {
            return Some(format!(
                "<?xml version=\"1.0\"?><!DOCTYPE bsn [<!ENTITY xxe SYSTEM \"{system_id}\">]>{}&xxe;{}",
                &doc[..=gt],
                &doc[end..]
            ));
        }
        i = gt + 1;
    }
    None
}

const XXE_ERRORS: &[&str] = &[
    "failed to load external entity",
    "failed to open stream",
    "java.io.filenotfoundexception",
    "could not find file",
    "no such file or directory",
    "external entity",
    "entityref: expecting",
];

async fn xxe(sh: &Shared, req: &Req) {
    let ct = req.content_type();
    if !ct.to_ascii_lowercase().contains("xml") {
        return;
    }
    let Some(body) = req.body_text() else { return };
    let send = |doc: String| {
        let r = req.with_body(req.method(), &ct, &doc);
        async move { sh.send(&r, r.bytes(None)).await }
    };
    let mut files = vec!["file:///etc/passwd"];
    if sh.opts.strength != Strength::Low {
        files.push("file:///c:/windows/win.ini");
    }
    for id in files {
        let Some(doc) = with_entity(&body, id) else { return };
        let Some(a) = send(doc.clone()).await else { return };
        if let Some(file) = file_signature(&a.body) {
            report_at(
                sh,
                req,
                "xxe:file-read".into(),
                a.flow_id,
                Hit {
                    check: XXE,
                    title: "XML external entity injection (file read)",
                    severity: Severity::High,
                    confidence: Confidence::Certain,
                    payload: doc,
                    detail: format!("An external entity for `{id}` made the XML parser return {file}."),
                    remediation: "Turn off DTDs and external entities in the XML parser.",
                    cwe: 611,
                },
            );
            return;
        }
    }
    // A file that cannot exist: a parser that tries to load it says so.
    let missing = format!("file:///{}/nofile", sh.marker());
    let Some(doc) = with_entity(&body, &missing) else {
        return;
    };
    let Some(a) = send(doc.clone()).await else { return };
    let low = a.body.to_ascii_lowercase();
    if let Some(e) = XXE_ERRORS.iter().find(|e| low.contains(**e)) {
        // The page must not say so for the document as it was sent.
        let Some(base) = sh.send(req, req.bytes(None)).await else {
            return;
        };
        if base.body.to_ascii_lowercase().contains(e) {
            return;
        }
        report_at(
            sh,
            req,
            "xxe:entity-error".into(),
            a.flow_id,
            Hit {
                check: XXE,
                title: "XML external entity injection (error indicator)",
                severity: Severity::High,
                confidence: Confidence::Firm,
                payload: doc,
                detail: format!(
                    "An external entity for a file that does not exist made the parser answer \"{e}\" (status {}): \
                     it tries to load external entities.",
                    a.status
                ),
                remediation: "Turn off DTDs and external entities in the XML parser.",
                cwe: 611,
            },
        );
    }
}

// ---- file upload -----------------------------------------------------------------------------------------------

/// A multipart body with the first file's name and content replaced.
fn with_upload(body: &str, name: &str, content: &str) -> Option<String> {
    const KEY: &str = "filename=\"";
    let at = body.find(KEY)? + KEY.len();
    let name_end = body[at..].find('"')? + at;
    let mut out = format!("{}{name}{}", &body[..at], &body[name_end..]);
    let head = out[at..].find("\r\n\r\n")? + at + 4;
    let tail = out[head..].find("\r\n--")? + head;
    out.replace_range(head..tail, content);
    Some(out)
}

/// A file with a script extension is accepted and the application confirms the name. Destructive: it uploads.
async fn file_upload(sh: &Shared, req: &Req) {
    let ct = req.content_type();
    if !ct.to_ascii_lowercase().starts_with("multipart/form-data") || req.method() != "POST" {
        return;
    }
    let Some(body) = req.body_text() else { return };
    let mut exts = vec!["php"];
    if sh.opts.strength != Strength::Low {
        exts.extend(["jsp", "aspx"]);
    }
    for ext in exts {
        let name = format!("{}.{ext}", sh.marker());
        let Some(doc) = with_upload(&body, &name, &format!("bosun upload test {name}")) else {
            return;
        };
        let r = req.with_body("POST", &ct, &doc);
        let Some(a) = sh.send(&r, r.bytes(None)).await else {
            return;
        };
        if (200..300).contains(&a.status) && a.body.contains(&name) {
            report_at(
                sh,
                req,
                format!("upload:{ext}"),
                a.flow_id,
                Hit {
                    check: FILE_UPLOAD,
                    title: "Unrestricted file upload",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    payload: name.clone(),
                    detail: format!(
                        "A file named {name} was accepted (status {}) and the answer names it: the application \
                         does not restrict the extension of uploads. The file holds only a line of text.",
                        a.status
                    ),
                    remediation: "Allow only the extensions you need, rename files on save, store uploads outside \
                                  the web root and never run them.",
                    cwe: 434,
                },
            );
            return;
        }
    }
}

// ---- JWT -------------------------------------------------------------------------------------------------------

/// Secrets people really use, as the passive check does (a small list: a weak key is found offline, nothing is
/// sent).
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "123456",
    "changeme",
    "jwt",
    "jwt_secret",
    "jwtsecret",
    "key",
    "admin",
    "test",
    "default",
    "your-256-bit-secret",
    "supersecret",
    "s3cr3t",
    "qwerty",
    "letmein",
    "mysecret",
    "secretkey",
    "token",
    "",
];

/// Whether a token's HMAC signature verifies with a weak secret, and which.
fn weak_secret(alg: &str, signing_input: &str, sig: &[u8]) -> Option<&'static str> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Sha256, Sha384, Sha512};
    macro_rules! find {
        ($h:ty) => {
            WEAK_SECRETS.iter().copied().find(|s| {
                <Hmac<$h> as KeyInit>::new_from_slice(s.as_bytes()).is_ok_and(|mut m| {
                    m.update(signing_input.as_bytes());
                    m.verify_slice(sig).is_ok()
                })
            })
        };
    }
    match alg {
        "HS256" => find!(Sha256),
        "HS384" => find!(Sha384),
        "HS512" => find!(Sha512),
        _ => None,
    }
}

/// JWTs written in the request (a header, a cookie, a value), at most two.
fn tokens(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let mut out: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("eyJ") {
        let t: String = text[i..].chars().take_while(|c| ok(*c)).collect();
        if t.matches('.').count() == 2 && !out.contains(&t) {
            out.push(t);
        }
        if out.len() == 2 {
            break;
        }
    }
    out
}

fn replace(raw: &[u8], from: &str, to: &str) -> Vec<u8> {
    let (f, mut out, mut i) = (from.as_bytes(), Vec::new(), 0);
    while i < raw.len() {
        if raw[i..].starts_with(f) {
            out.extend_from_slice(to.as_bytes());
            i += f.len();
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

async fn jwt(sh: &Shared, req: &Req) {
    let raw = req.bytes(None);
    let mut base: Option<Answer> = None;
    for tok in tokens(&raw) {
        let parts: Vec<&str> = tok.split('.').collect();
        let [h, p, s] = parts[..] else { continue };
        let Some(head) = B64
            .decode(h)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        let alg = head["alg"].as_str().unwrap_or("").to_string();
        if let Some(sig) = B64.decode(s).ok().filter(|s| !s.is_empty())
            && let Some(secret) = weak_secret(&alg, &format!("{h}.{p}"), &sig)
        {
            report_at(
                sh,
                req,
                "jwt:weak-secret".into(),
                0,
                Hit {
                    check: JWT,
                    title: "JWT signed with a weak secret",
                    severity: Severity::High,
                    confidence: Confidence::Certain,
                    payload: format!("{}…", &tok[..tok.len().min(24)]),
                    detail: format!(
                        "The {alg} signature of a token in the request verifies with the secret \"{secret}\": \
                         anyone can sign tokens for any user."
                    ),
                    remediation: "Sign with a random key of at least 256 bits, kept out of source code, and rotate \
                                  the one that was used.",
                    cwe: 521,
                },
            );
        }
        // Tokens whose signature the server is made to ignore need an answer to compare with.
        if base.is_none() {
            base = sh.send(req, raw.clone()).await;
        }
        let Some(b) = &base else { return };
        if !(200..300).contains(&b.status) {
            return;
        }
        // The control: a value that is no token at all must be refused, or the token is not what is checked.
        let junk = format!("{}garbage", sh.marker());
        let Some(c) = sh.send(req, replace(&raw, &tok, &junk)).await else {
            return;
        };
        if c.status == b.status {
            continue;
        }
        let accepted = |a: &Answer| a.status == b.status;
        if !s.is_empty() {
            let last = if s.ends_with('A') { 'B' } else { 'A' };
            let tampered = format!("{h}.{p}.{}{last}", &s[..s.len() - 1]);
            let Some(a) = sh.send(req, replace(&raw, &tok, &tampered)).await else {
                return;
            };
            if accepted(&a) {
                report_at(
                    sh,
                    req,
                    "jwt:signature-not-verified".into(),
                    a.flow_id,
                    Hit {
                        check: JWT,
                        title: "JWT signature not verified",
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        payload: tampered,
                        detail: format!(
                            "A token with a changed signature got the same answer (status {}) as the original, \
                             and a value that is not a token was refused.",
                            a.status
                        ),
                        remediation: "Verify the signature of every token before reading its claims.",
                        cwe: 347,
                    },
                );
                continue;
            }
        }
        let mut algs = vec!["none"];
        if sh.opts.strength != Strength::Low {
            algs.extend(["None", "NONE"]);
        }
        for a_name in algs {
            let forged = format!(
                "{}.{p}.",
                B64.encode(json!({"alg": a_name, "typ": "JWT"}).to_string())
            );
            let Some(a) = sh.send(req, replace(&raw, &tok, &forged)).await else {
                return;
            };
            if accepted(&a) {
                report_at(
                    sh,
                    req,
                    "jwt:alg-none".into(),
                    a.flow_id,
                    Hit {
                        check: JWT,
                        title: "JWT accepted with alg none",
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        payload: forged,
                        detail: format!(
                            "The token with its signature removed and `alg` set to \"{a_name}\" got the same \
                             answer (status {}) as the original.",
                            a.status
                        ),
                        remediation: "Accept only the algorithms you issue, and never `none`.",
                        cwe: 347,
                    },
                );
                break;
            }
        }
    }
}

// ---- deserialization -------------------------------------------------------------------------------------------

/// What each platform says when it is handed a broken serialized object.
const DESERIALIZATION_ERRORS: &[(&str, &[&str])] = &[
    (
        "Java",
        &[
            "java.io.streamcorruptedexception",
            "invalid stream header",
            "java.io.invalidclassexception",
            "java.io.objectinputstream",
        ],
    ),
    (
        "PHP",
        &["unserialize(): error at offset", "__php_incomplete_class"],
    ),
    (
        ".NET",
        &[
            "system.runtime.serialization.serializationexception",
            "binaryformatter",
            "the input stream is not a valid binary format",
            "the state information is invalid for this page",
        ],
    ),
    (
        "Python",
        &[
            "unpicklingerror",
            "pickle data was truncated",
            "invalid load key",
            "yaml.constructor.constructorerror",
        ],
    ),
];

/// Cut-off serialized objects: Java stream, PHP, .NET binary formatter and a Python pickle.
const DESERIALIZATION_PROBES: &[(&str, &str)] = &[
    ("Java", "rO0ABXQAFWJvc3Vu"),
    ("PHP", "O:8:\"stdClass\":1:{s:1:\"a\";"),
    (".NET", "AAEAAAD/////AQAAAAAAAAAMAgAAAA"),
    ("Python", "gASVBQAAAAAAAAB9lC4"),
];

fn deserialization_error(body: &str) -> Option<(&'static str, &'static str)> {
    let low = body.to_ascii_lowercase();
    DESERIALIZATION_ERRORS
        .iter()
        .find_map(|(lang, sigs)| sigs.iter().find(|s| low.contains(**s)).map(|s| (*lang, *s)))
}

pub(crate) async fn deserialization(sh: &Shared, req: &Req, point: &Point) {
    // A cookie or header is a value an application may well hold a serialized object in; a line break is not
    // involved, so every point is tried.
    for (lang, payload) in DESERIALIZATION_PROBES {
        let Some(a) = sh.send(req, req.bytes(Some((point, payload)))).await else {
            return;
        };
        let Some((found, sig)) = deserialization_error(&a.body) else {
            continue;
        };
        // The value as it was must not already show the error.
        let Some(base) = sh.send(req, req.bytes(None)).await else {
            return;
        };
        if deserialization_error(&base.body).is_some() {
            return;
        }
        checks::report(
            sh,
            req,
            point,
            a.flow_id,
            Hit {
                check: DESERIALIZATION,
                title: "Deserialization of untrusted data (indicator)",
                severity: Severity::Medium,
                confidence: Confidence::Firm,
                payload: (*payload).to_string(),
                detail: format!(
                    "A broken {lang} serialized object in {} made the application answer a {found} \
                     deserialization error (\"{sig}\", status {}): it hands the value to a deserializer. This \
                     shows the entry point, not a working exploit.",
                    req.label(point),
                    a.status
                ),
                remediation: "Do not deserialize data from the client; use a data-only format (JSON) and validate \
                              it, or sign the value and verify the signature first.",
                cwe: 502,
            },
        );
        return;
    }
}

// ---- prototype pollution ---------------------------------------------------------------------------------------

/// A JSON body with `__proto__` (or `constructor.prototype`) holding a property of an unlikely name. If a later,
/// plain request of the same kind shows that property, it was set on every object of the server.
async fn prototype_pollution(sh: &Shared, req: &Req) {
    let ct = req.content_type();
    if !ct.to_ascii_lowercase().starts_with("application/json") {
        return;
    }
    let Some(Value::Object(obj)) = req.body_text().and_then(|b| serde_json::from_str(&b).ok()) else {
        return;
    };
    let mut ways = vec![("__proto__", "__proto__")];
    if sh.opts.strength != Strength::Low {
        ways.push(("constructor.prototype", "constructor"));
    }
    let Some(base) = sh.send(req, req.bytes(None)).await else {
        return;
    };
    for (name, key) in ways {
        let (prop, val) = (sh.marker(), sh.marker());
        if base.body.contains(&val) {
            return;
        }
        let mut evil = obj.clone();
        evil.insert(
            key.to_string(),
            if key == "constructor" {
                json!({"prototype": {prop.clone(): val.clone()}})
            } else {
                json!({prop.clone(): val.clone()})
            },
        );
        let r = req.with_body(req.method(), &ct, &Value::Object(evil).to_string());
        let Some(a) = sh.send(&r, r.bytes(None)).await else {
            return;
        };
        // The request as it was, which carries no payload.
        let Some(after) = sh.send(req, req.bytes(None)).await else {
            return;
        };
        if after.body.contains(&val) {
            report_at(
                sh,
                req,
                format!("json:{name}"),
                after.flow_id,
                Hit {
                    check: PROTOTYPE_POLLUTION,
                    title: "Server-side prototype pollution",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    payload: format!("{{\"{key}\": … \"{prop}\": \"{val}\"}}"),
                    detail: format!(
                        "A `{name}` property in the JSON body set {prop} on objects of the server: the plain \
                         request now returns its value ({val}), which it did not before (status {}). The \
                         property is inert and stays until the server restarts.",
                        a.status
                    ),
                    remediation: "Do not merge request data into objects recursively without skipping `__proto__`, \
                                  `constructor` and `prototype`; use `Object.create(null)` or a `Map`, or freeze \
                                  `Object.prototype`.",
                    cwe: 1321,
                },
            );
            return;
        }
    }
}

// ---- GraphQL ---------------------------------------------------------------------------------------------------

async fn graphql(sh: &Shared, req: &Req) {
    let json_body = req.body_text().is_some_and(|b| {
        req.content_type()
            .to_ascii_lowercase()
            .starts_with("application/json")
            && b.contains("\"query\"")
    });
    if !req.base_url().to_ascii_lowercase().contains("graphql") && !json_body {
        return;
    }
    let ask = |body: String| {
        let r = req.with_body("POST", "application/json", &body);
        async move { sh.send(&r, r.bytes(None)).await }
    };
    // Is it GraphQL at all: `__typename` is the one field every endpoint answers.
    let Some(t) = ask(r#"{"query":"{ __typename }"}"#.into()).await else {
        return;
    };
    if !(t.body.contains("\"data\"") && t.body.contains("__typename")) {
        return;
    }
    let hit =
        |what: &str, a: &Answer, title: &'static str, sev: Severity, detail: String, fix: &'static str| {
            report_at(
                sh,
                req,
                format!("graphql:{what}"),
                a.flow_id,
                Hit {
                    check: GRAPHQL,
                    title,
                    severity: sev,
                    confidence: Confidence::Certain,
                    payload: what.into(),
                    detail,
                    remediation: fix,
                    cwe: 200,
                },
            );
        };
    let Some(i) = ask(r#"{"query":"{ __schema { types { name } } }"}"#.into()).await else {
        return;
    };
    if i.body.contains("\"__schema\"") && i.body.contains("\"types\"") {
        hit(
            "introspection",
            &i,
            "GraphQL introspection enabled",
            Severity::Low,
            "The endpoint answers a schema query: anyone can list every type and field.".into(),
            "Turn introspection off in production.",
        );
    }
    let names: &[&str] = if sh.opts.strength == Strength::Low {
        &["user", "users", "me"]
    } else {
        &[
            "user", "users", "me", "viewer", "node", "product", "posts", "account",
        ]
    };
    for name in names {
        let typo = &name[..name.len() - 1];
        let Some(a) = ask(json!({"query": format!("{{ {typo} }}")}).to_string()).await else {
            return;
        };
        if a.body.to_ascii_lowercase().contains("did you mean") {
            hit(
                "suggestions",
                &a,
                "GraphQL field suggestions enabled",
                Severity::Low,
                format!(
                    "A misspelled field (`{typo}`) got a \"Did you mean\" answer: the schema can be read back \
                     from error messages even with introspection off."
                ),
                "Turn off field suggestions in production.",
            );
            break;
        }
    }
    let batch = r#"[{"query":"{ __typename }"},{"query":"{ __typename }"}]"#;
    if let Some(a) = ask(batch.into()).await
        && matches!(serde_json::from_str::<Value>(&a.body), Ok(Value::Array(v)) if v.len() >= 2)
    {
        hit(
            "batching",
            &a,
            "GraphQL query batching enabled",
            Severity::Low,
            "An array of two queries was answered with two results: one request can carry many, which bypasses \
             per-request rate limits (brute force of logins or one-time codes)."
                .into(),
            "Turn batching off, or count each query in a batch against the rate limit.",
        );
    }
    let aliases: String = (1..=25).map(|n| format!("a{n}:__typename ")).collect();
    if let Some(a) = ask(json!({"query": format!("{{ {aliases}}}")}).to_string()).await
        && a.body.contains("\"a25\"")
    {
        hit(
            "aliases",
            &a,
            "GraphQL aliases not limited",
            Severity::Low,
            "Twenty-five aliases of one field in one query were all answered: aliases can repeat an expensive \
             field or a login mutation many times in one request."
                .into(),
            "Limit the number of aliases and the cost of a query.",
        );
    }
}

// ---- session cookies -------------------------------------------------------------------------------------------

/// A `Set-Cookie` value taken apart: name, value and the lowercased attributes.
fn cookie(v: &str) -> Option<(String, String, Vec<String>)> {
    let mut it = v.split(';');
    let (n, val) = it.next()?.split_once('=')?;
    Some((
        n.trim().to_string(),
        val.trim().to_string(),
        it.map(|a| a.trim().to_ascii_lowercase()).collect(),
    ))
}

fn session_name(n: &str) -> bool {
    let n = n.to_ascii_lowercase();
    ["sess", "token", "auth", "jwt", "login"]
        .iter()
        .any(|k| n.contains(k))
        || n == "sid"
        || n.ends_with("sid")
        || n.starts_with("sid")
}

fn cookies(a: &Answer) -> Vec<(String, String, Vec<String>)> {
    a.headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .filter_map(|(_, v)| cookie(v))
        .collect()
}

async fn session(sh: &Shared, req: &Req) {
    let Some(a) = sh.send(req, req.bytes(None)).await else {
        return;
    };
    let set: Vec<_> = cookies(&a).into_iter().filter(|c| session_name(&c.0)).collect();
    for (name, _, attrs) in &set {
        let has = |p: &str| attrs.iter().any(|a| a == p || a.starts_with(&format!("{p}=")));
        let mut missing = Vec::new();
        if !has("httponly") {
            missing.push("HttpOnly");
        }
        if req.scheme == Scheme::Https && !has("secure") {
            missing.push("Secure");
        }
        if !has("samesite") {
            missing.push("SameSite");
        }
        if missing.is_empty() {
            continue;
        }
        report_at(
            sh,
            req,
            format!("cookie:{name}"),
            a.flow_id,
            Hit {
                check: SESSION,
                title: "Session cookie without security attributes",
                severity: Severity::Low,
                confidence: Confidence::Certain,
                payload: format!("Set-Cookie: {name}=…"),
                detail: format!(
                    "The session cookie {name} is set without {}: script can read it (HttpOnly), it travels over \
                     plain HTTP (Secure) or it is sent on cross-site requests (SameSite).",
                    missing.join(", ")
                ),
                remediation: "Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.",
                cwe: if missing[0] == "HttpOnly" {
                    1004
                } else if missing[0] == "Secure" {
                    614
                } else {
                    1275
                },
            },
        );
    }
    // Fixation: an id the client made up comes back as the session's id.
    if let Some((name, _, _)) = set.first() {
        let chosen = sh.marker();
        let r = req.with_cookie(name, &chosen);
        let Some(b) = sh.send(&r, r.bytes(None)).await else {
            return;
        };
        if cookies(&b).iter().any(|(n, v, _)| n == name && *v == chosen) {
            report_at(
                sh,
                req,
                format!("fixation:{name}"),
                b.flow_id,
                Hit {
                    check: SESSION,
                    title: "Session fixation indicator",
                    severity: Severity::Medium,
                    confidence: Confidence::Firm,
                    payload: format!("Cookie: {name}={chosen}"),
                    detail: format!(
                        "A session id invented by the scanner was set again by the server as the value of {name}: \
                         an attacker can plant a known id in a victim's browser and use it after they sign in, \
                         unless the application issues a new id at sign-in."
                    ),
                    remediation: "Ignore ids the server did not issue, and issue a new id when the user signs in.",
                    cwe: 384,
                },
            );
        }
    }
}

// ---- TLS -------------------------------------------------------------------------------------------------------

/// A ClientHello with no extensions: `version` as the highest the client speaks, `suites` the only ones offered.
fn hello(version: [u8; 2], suites: &[u16]) -> Vec<u8> {
    let mut body = vec![version[0], version[1]];
    body.extend((0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(1)));
    body.push(0);
    body.extend(((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend(s.to_be_bytes());
    }
    body.extend([1, 0]);
    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    let record = if version == [3, 0] { [3, 0] } else { [3, 1] };
    let mut out = vec![0x16, record[0], record[1]];
    out.extend((hs.len() as u16).to_be_bytes());
    out.extend(hs);
    out
}

/// The version and suite a ServerHello chose, if the answer is one.
fn server_hello(r: &[u8]) -> Option<([u8; 2], u16)> {
    if r.len() < 44 || r[0] != 0x16 || r[5] != 0x02 {
        return None;
    }
    let at = 44 + usize::from(r[43]);
    Some(([r[9], r[10]], u16::from_be_bytes([*r.get(at)?, *r.get(at + 1)?])))
}

/// A suite group the check offers alone, and what it is.
struct Group {
    name: &'static str,
    suites: &'static [u16],
    why: &'static str,
}

const GROUPS: &[Group] = &[
    Group {
        name: "RC4",
        suites: &[0x0005, 0x0004, 0xc011],
        why: "RC4 is broken: plaintext can be recovered from enough traffic",
    },
    Group {
        name: "NULL or export",
        suites: &[0x0001, 0x0002, 0x003b, 0x0003, 0x0006, 0x0008, 0x0014, 0x0017],
        why: "these suites encrypt nothing or with keys short enough to break",
    },
    Group {
        name: "3DES",
        suites: &[0x000a, 0xc012, 0x0016],
        why: "3DES has a 64-bit block and falls to birthday attacks on long connections (Sweet32)",
    },
];

async fn tls(sh: &Shared, req: &Req) {
    if req.scheme != Scheme::Https || !sh.first_tls(req) {
        return;
    }
    let tls_hit = |what: &str, title: &'static str, sev: Severity, detail: String, cwe: u32, flow: i64| {
        report_at(
            sh,
            req,
            format!("tls:{what}"),
            flow,
            Hit {
                check: TLS,
                title,
                severity: sev,
                confidence: Confidence::Certain,
                payload: what.into(),
                detail,
                remediation: "Offer TLS 1.2 and 1.3 only, with AEAD suites; renew and chain certificates from a \
                              trusted CA.",
                cwe,
            },
        );
    };
    let modern: &[u16] = &[0x002f, 0x0035, 0xc013, 0xc014, 0x000a];
    let mut protocols: Vec<(&str, [u8; 2])> = vec![("TLS 1.0", [3, 1]), ("TLS 1.1", [3, 2])];
    if sh.opts.strength == Strength::High {
        protocols.push(("SSL 3.0", [3, 0]));
    }
    for (name, v) in protocols {
        let Some(r) = sh.probe(req, &hello(v, modern), 128).await else {
            // Nothing came back at all (refused, closed, not TLS): the rest would say nothing either.
            return;
        };
        if server_hello(&r).is_some_and(|(sv, _)| sv == v) {
            tls_hit(
                &name.to_ascii_lowercase().replace(' ', ""),
                "Outdated TLS protocol accepted",
                Severity::Medium,
                format!(
                    "The server answered a {name} hello with a ServerHello: {name} is deprecated and weak."
                ),
                326,
                0,
            );
        }
    }
    let groups = if sh.opts.strength == Strength::Low {
        &GROUPS[..2]
    } else {
        GROUPS
    };
    for g in groups {
        let Some(r) = sh.probe(req, &hello([3, 3], g.suites), 128).await else {
            return;
        };
        if let Some((_, s)) = server_hello(&r)
            && g.suites.contains(&s)
        {
            tls_hit(
                &g.name.to_ascii_lowercase().replace(' ', "-"),
                "Weak cipher suite accepted",
                Severity::Medium,
                format!(
                    "The server picked suite 0x{s:04x} when offered only {} suites: {}.",
                    g.name, g.why
                ),
                327,
                0,
            );
        }
    }
    // The certificate: read from a handshake that accepts any chain.
    let page = req.page(None);
    let Some(a) = sh.send_with(&page, page.bytes(None), false).await else {
        return;
    };
    let Some(der) = a.tls.as_ref().and_then(|t| t.leaf_der.as_ref()) else {
        return;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let v = cert.validity();
    if v.not_after.timestamp() < now {
        tls_hit(
            "expired",
            "Expired certificate",
            Severity::Medium,
            format!("The certificate expired on {}.", v.not_after),
            298,
            a.flow_id,
        );
    } else if v.not_before.timestamp() > now {
        tls_hit(
            "not-yet-valid",
            "Certificate not yet valid",
            Severity::Medium,
            format!("The certificate is valid only from {}.", v.not_before),
            298,
            a.flow_id,
        );
    }
    if cert.subject().as_raw() == cert.issuer().as_raw() {
        tls_hit(
            "self-signed",
            "Self-signed certificate",
            Severity::Low,
            format!(
                "The certificate (\"{}\") is its own issuer: clients cannot tell it from one an attacker made.",
                cert.subject()
            ),
            295,
            a.flow_id,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_goes_into_the_first_text_node() {
        let d = with_entity(
            "<?xml version=\"1.0\"?><order><id/><item>book</item></order>",
            "file:///etc/passwd",
        )
        .unwrap();
        assert!(d.contains("<item>&xxe;</item>"), "{d}");
        assert!(d.contains("SYSTEM \"file:///etc/passwd\""));
        assert!(with_entity("<a><!DOCTYPE x></a>", "x").is_none());
        assert!(with_entity("<a/>", "x").is_none());
    }

    #[test]
    fn upload_name_and_content_are_replaced() {
        let b = "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n";
        let r = with_upload(b, "x.php", "marker").unwrap();
        assert!(
            r.contains("filename=\"x.php\"") && r.contains("\r\n\r\nmarker\r\n--B--"),
            "{r}"
        );
    }

    #[test]
    fn tokens_are_found_and_replaced() {
        let raw = b"GET /?t=eyJhbGciOiJub25lIn0.e30.abc HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJub25lIn0.e30.abc\r\n\r\n";
        assert_eq!(tokens(raw), vec!["eyJhbGciOiJub25lIn0.e30.abc".to_string()]);
        let r = replace(raw, "eyJhbGciOiJub25lIn0.e30.abc", "X");
        assert!(!String::from_utf8_lossy(&r).contains("eyJ"));
    }

    #[test]
    fn hello_parses_back() {
        let h = hello([3, 1], &[0x002f]);
        assert_eq!(h[0], 0x16);
        assert_eq!(usize::from(u16::from_be_bytes([h[3], h[4]])), h.len() - 5);
    }

    #[test]
    fn session_names() {
        assert!(session_name("PHPSESSID") && session_name("sid") && session_name("auth_token"));
        assert!(!session_name("lang") && !session_name("theme"));
    }
}
