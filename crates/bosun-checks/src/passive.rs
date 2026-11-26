//! The passive checks: built-in YAML checks (`builtin/`) and the ones that need code (mixed content, vulnerable
//! JavaScript libraries, JWTs, caching, open-redirect hints). The header, cookie, CSP, CORS and directory-listing
//! rules live in `bosun-scan`. Each reads one recorded flow; none sends anything.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bosun_model::FlowDetail;
use bosun_store::{Confidence, Evidence, EvidencePart, NewIssue, Severity};
use regex::bytes::Regex;

use crate::head::Head;
use crate::issue::{Spec, base_path, make};
use crate::lang::{Compiled, Message, parse};

const BODY_LIMIT: usize = 1 << 20;

static BUILTIN: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    [
        include_str!("builtin/stack-trace-disclosure.yaml"),
        include_str!("builtin/sql-error-disclosure.yaml"),
        include_str!("builtin/private-ip-disclosure.yaml"),
        include_str!("builtin/aws-access-key-id.yaml"),
        include_str!("builtin/debug-page.yaml"),
    ]
    .iter()
    .filter_map(|t| parse(t).ok())
    .collect()
});

/// The built-in YAML checks.
pub fn builtin() -> &'static [Compiled] {
    &BUILTIN
}

/// Rule ids of the checks written in code.
pub const CODE_RULES: &[&str] = &[
    "mixed-content-active",
    "mixed-content-passive",
    "vulnerable-js-library",
    "jwt-alg-none",
    "jwt-no-expiry",
    "jwt-weak-secret",
    "jwt-sensitive-claim",
    "cacheable-sensitive-response",
    "open-redirect-hint",
];

/// The ids of every check in this crate, for filters and docs.
pub fn all_ids() -> Vec<String> {
    builtin()
        .iter()
        .map(|c| c.check.id.clone())
        .chain(CODE_RULES.iter().map(|s| (*s).to_string()))
        .collect()
}

struct Code {
    rule: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: Confidence,
    remediation: &'static str,
    cwe: &'static [u32],
    owasp: &'static [&'static str],
}

const MIXED_ACTIVE: Code = Code {
    rule: "mixed-content-active",
    title: "HTTPS page loads a script, frame or stylesheet over HTTP",
    severity: Severity::Medium,
    confidence: Confidence::Firm,
    remediation: "Load every sub-resource over HTTPS (or with a scheme-relative URL), and consider `upgrade-insecure-requests`.",
    cwe: &[319],
    owasp: &["A02:2021 Cryptographic Failures"],
};
const MIXED_PASSIVE: Code = Code {
    rule: "mixed-content-passive",
    title: "HTTPS page loads an image over HTTP",
    severity: Severity::Info,
    confidence: Confidence::Firm,
    remediation: "Load images over HTTPS.",
    cwe: &[319],
    owasp: &["A02:2021 Cryptographic Failures"],
};
const VULN_JS: Code = Code {
    rule: "vulnerable-js-library",
    title: "JavaScript library with known vulnerabilities",
    severity: Severity::Medium,
    confidence: Confidence::Firm,
    remediation: "Upgrade the library to a release that is not listed as vulnerable.",
    cwe: &[1104],
    owasp: &["A06:2021 Vulnerable and Outdated Components"],
};
const JWT_NONE: Code = Code {
    rule: "jwt-alg-none",
    title: "JWT with the `none` algorithm (unsigned)",
    severity: Severity::High,
    confidence: Confidence::Firm,
    remediation: "Reject unsigned tokens: require a signature and fix the accepted algorithms on the server.",
    cwe: &[347],
    owasp: &[
        "A02:2021 Cryptographic Failures",
        "A07:2021 Identification and Authentication Failures",
    ],
};
const JWT_EXP: Code = Code {
    rule: "jwt-no-expiry",
    title: "JWT without an expiry (`exp`)",
    severity: Severity::Low,
    confidence: Confidence::Tentative,
    remediation: "Give tokens a short `exp` and refresh them.",
    cwe: &[613],
    owasp: &["A07:2021 Identification and Authentication Failures"],
};
const JWT_WEAK: Code = Code {
    rule: "jwt-weak-secret",
    title: "JWT signed with a guessable secret",
    severity: Severity::High,
    confidence: Confidence::Certain,
    remediation: "Sign tokens with a random secret of at least 256 bits (or an asymmetric key), rotate the secret that was guessed, and treat every token signed with it as forgeable.",
    cwe: &[521, 347],
    owasp: &[
        "A02:2021 Cryptographic Failures",
        "A07:2021 Identification and Authentication Failures",
    ],
};
const JWT_CLAIM: Code = Code {
    rule: "jwt-sensitive-claim",
    title: "JWT payload carries a secret-looking claim",
    severity: Severity::Medium,
    confidence: Confidence::Tentative,
    remediation: "A JWT payload is readable by anyone who holds it: keep passwords and secrets out of it.",
    cwe: &[200],
    owasp: &["A02:2021 Cryptographic Failures"],
};
const CACHEABLE: Code = Code {
    rule: "cacheable-sensitive-response",
    title: "Response to an authenticated request can be cached",
    severity: Severity::Low,
    confidence: Confidence::Tentative,
    remediation: "Send `Cache-Control: no-store` (or at least `private`) on responses that depend on a login.",
    cwe: &[525],
    owasp: &["A04:2021 Insecure Design"],
};
const OPEN_REDIRECT: Code = Code {
    rule: "open-redirect-hint",
    title: "Redirect target taken from a request parameter",
    severity: Severity::Low,
    confidence: Confidence::Tentative,
    remediation: "Redirect only to paths on this site or to a fixed list of hosts; never to a URL taken from the request.",
    cwe: &[601],
    owasp: &["A01:2021 Broken Access Control"],
};

struct Ctx<'a> {
    flow: &'a FlowDetail,
    resp: &'a [u8],
    rh: Head<'a>,
    qh: Head<'a>,
    now: i64,
    out: Vec<NewIssue>,
}

impl Ctx<'_> {
    fn emit(&mut self, c: &Code, key: &str, detail: String, evidence: Vec<Evidence>) {
        let owasp: Vec<String> = c.owasp.iter().map(|s| (*s).into()).collect();
        let spec = Spec {
            rule: c.rule,
            title: c.title,
            severity: c.severity,
            confidence: c.confidence,
            remediation: c.remediation,
            cwe: c.cwe,
            owasp: &owasp,
        };
        self.out
            .push(make(self.flow, &spec, key, detail, evidence, self.now));
    }

    fn content_type(&self) -> String {
        self.rh
            .get("content-type")
            .map_or(String::new(), |h| h.value.to_ascii_lowercase())
    }

    /// The body when it can be read as stored: not compressed, at most the limit. `(start, bytes)`.
    fn body(&self) -> Option<(usize, &[u8])> {
        if let Some(e) = self.rh.get("content-encoding")
            && !e.value.is_empty()
            && !e.value.eq_ignore_ascii_case("identity")
        {
            return None;
        }
        let b = self.resp.get(self.rh.body..)?;
        Some((self.rh.body, &b[..b.len().min(BODY_LIMIT)]))
    }
}

fn ev(part: EvidencePart, start: usize, end: usize) -> Evidence {
    Evidence {
        part,
        start: start as u64,
        end: end as u64,
    }
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect("a fixed pattern"));
    };
}

re!(
    MIXED_SCRIPT,
    r#"(?i)<(?:script|iframe)\b[^>]{0,500}?\bsrc\s*=\s*["']?(http://[^"'\s>]{1,300})"#
);
re!(
    MIXED_CSS,
    r#"(?i)<link\b[^>]{0,500}?rel\s*=\s*["']?stylesheet[^>]{0,500}?href\s*=\s*["']?(http://[^"'\s>]{1,300})"#
);
re!(
    MIXED_IMG,
    r#"(?i)<img\b[^>]{0,500}?\bsrc\s*=\s*["']?(http://[^"'\s>]{1,300})"#
);
re!(
    SCRIPT_SRC,
    r#"(?i)<script\b[^>]{0,500}?\bsrc\s*=\s*["']?([^"'\s>]{1,300})"#
);
re!(JWT, r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*");

/// `http://host/path?x` becomes `host`: the part that is safe to show.
fn url_host(u: &str) -> &str {
    let r = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .or_else(|| u.strip_prefix("//"))
        .unwrap_or(u);
    r.split(['/', '?', '#', ':', '@']).next().unwrap_or("")
}

fn mixed_content(c: &mut Ctx<'_>, html: bool) {
    if !html || c.flow.summary.scheme.as_str() != "https" {
        return;
    }
    let Some((base, body)) = c.body() else { return };
    let mut found: Vec<(&Code, usize, usize, String)> = Vec::new();
    for (re, code) in [
        (&MIXED_SCRIPT, &MIXED_ACTIVE),
        (&MIXED_CSS, &MIXED_ACTIVE),
        (&MIXED_IMG, &MIXED_PASSIVE),
    ] {
        for cap in re.captures_iter(body).take(8) {
            let (Some(m), Some(u)) = (cap.get(0), cap.get(1)) else {
                continue;
            };
            let host = url_host(&String::from_utf8_lossy(u.as_bytes()))
                .chars()
                .take(100)
                .collect();
            found.push((code, m.start(), m.end(), host));
        }
    }
    let key = base_path(c.flow).to_string();
    for (code, s, e, host) in found {
        let e = e.min(s + 200);
        c.emit(
            code,
            &format!("{key}|{host}"),
            format!("The page loads a resource from `http://{host}`."),
            vec![ev(EvidencePart::Response, base + s, base + e)],
        );
    }
}

struct Lib {
    name: &'static str,
    /// A file name or path with the version in group 1.
    uri: &'static str,
    /// A header comment with the version in group 1.
    content: &'static str,
    /// Vulnerable ranges: from (included) up to (excluded).
    ranges: &'static [([u32; 3], [u32; 3])],
    issue: &'static str,
    severity: Severity,
}

/// A small, hand-kept table in the style of Retire.js (Apache-2.0 data model, our own entries): library, how to
/// recognise its version, the vulnerable range and the advisory. Grow it by adding rows.
const LIBS: &[Lib] = &[
    Lib {
        name: "jquery",
        uri: r"(?i)jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/jquery/(\d+\.\d+\.\d+)/",
        content: r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [3, 5, 0])],
        issue: "XSS through htmlPrefilter (CVE-2020-11022, CVE-2020-11023); fixed in 3.5.0",
        severity: Severity::Medium,
    },
    Lib {
        name: "angularjs",
        uri: r"(?i)angular(?:js)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/angularjs/(\d+\.\d+\.\d+)/",
        content: r"AngularJS v(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [1, 8, 0])],
        issue: "XSS and ReDoS issues (CVE-2020-7676 and others); AngularJS 1.x is end of life",
        severity: Severity::Medium,
    },
    Lib {
        name: "bootstrap",
        uri: r"(?i)bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/bootstrap/(\d+\.\d+\.\d+)/",
        content: r"Bootstrap v(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [3, 4, 1]), ([4, 0, 0], [4, 3, 1])],
        issue: "XSS in the tooltip and popover data attributes (CVE-2019-8331); fixed in 3.4.1 and 4.3.1",
        severity: Severity::Medium,
    },
    Lib {
        name: "lodash",
        uri: r"(?i)lodash[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/lodash\.js/(\d+\.\d+\.\d+)/",
        content: r"(?i)lodash (?:v)?(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [4, 17, 21])],
        issue: "Prototype pollution and command injection (CVE-2020-8203, CVE-2021-23337); fixed in 4.17.21",
        severity: Severity::High,
    },
    Lib {
        name: "moment",
        uri: r"(?i)moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/moment\.js/(\d+\.\d+\.\d+)/",
        content: r"(?s)moment\.js.{0,60}?version\s*:\s*(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [2, 29, 4])],
        issue: "ReDoS and path traversal (CVE-2022-24785, CVE-2022-31129); fixed in 2.29.4",
        severity: Severity::Medium,
    },
    Lib {
        name: "handlebars",
        uri: r"(?i)handlebars[-.](\d+\.\d+\.\d+)(?:\.min)?\.js|/handlebars\.js/(\d+\.\d+\.\d+)/",
        content: r"(?i)handlebars v(\d+\.\d+\.\d+)",
        ranges: &[([0, 0, 0], [4, 7, 7])],
        issue: "Remote code execution through templates (CVE-2021-23369, CVE-2021-23383); fixed in 4.7.7",
        severity: Severity::High,
    },
];

static LIB_RES: LazyLock<Vec<(Regex, Regex)>> = LazyLock::new(|| {
    LIBS.iter()
        .map(|l| {
            (
                Regex::new(l.uri).expect("a fixed pattern"),
                Regex::new(l.content).expect("a fixed pattern"),
            )
        })
        .collect()
});

fn version(s: &[u8]) -> Option<[u32; 3]> {
    let s = std::str::from_utf8(s).ok()?;
    let mut it = s.split('.').map(|p| p.parse::<u32>().ok());
    Some([it.next()??, it.next()??, it.next()??])
}

/// The version in whichever capture group matched.
fn captured(re: &Regex, hay: &[u8]) -> Option<([u32; 3], usize, usize)> {
    let c = re.captures(hay)?;
    let g = (1..c.len()).find_map(|i| c.get(i))?;
    Some((version(g.as_bytes())?, g.start(), g.end()))
}

fn vulnerable_js(c: &mut Ctx<'_>, html: bool) {
    let mut found: Vec<(usize, [u32; 3], Evidence)> = Vec::new();
    let Some((base, body)) = c.body() else { return };
    if html {
        for cap in SCRIPT_SRC.captures_iter(body).take(64) {
            let Some(src) = cap.get(1) else { continue };
            for (i, (uri, _)) in LIB_RES.iter().enumerate() {
                let s = src.as_bytes();
                let path = &s[..s.iter().position(|b| matches!(b, b'?' | b'#')).unwrap_or(s.len())];
                if let Some((v, _, _)) = captured(uri, path) {
                    found.push((
                        i,
                        v,
                        ev(EvidencePart::Response, base + src.start(), base + src.end()),
                    ));
                }
            }
        }
    } else {
        let ct = c.content_type();
        let p = base_path(c.flow).to_ascii_lowercase();
        if !(ct.contains("javascript") || p.ends_with(".js")) {
            return;
        }
        let head = &body[..body.len().min(4096)];
        for (i, (uri, content)) in LIB_RES.iter().enumerate() {
            if let Some((v, s, e)) = captured(content, head) {
                found.push((i, v, ev(EvidencePart::Response, base + s, base + e)));
            } else if let Some((v, _, _)) = captured(uri, p.as_bytes()) {
                found.push((i, v, ev(EvidencePart::Response, base, base)));
            }
        }
    }
    for (i, v, e) in found {
        let lib = &LIBS[i];
        if !lib.ranges.iter().any(|(lo, hi)| v >= *lo && v < *hi) {
            continue;
        }
        let ver = format!("{}.{}.{}", v[0], v[1], v[2]);
        let evidence = if e.start == e.end { vec![] } else { vec![e] };
        let mut code = VULN_JS;
        code.severity = lib.severity;
        c.emit(
            &code,
            &format!("{}|{ver}", lib.name),
            format!("{} {ver}: {}.", lib.name, lib.issue),
            evidence,
        );
    }
}

/// Secrets that tokens are commonly signed with in examples, tutorials and defaults. Small on purpose: this is a
/// check for the worst case, not a cracker.
const WEAK_SECRETS: &[&str] = &[
    "",
    "secret",
    "Secret",
    "secretkey",
    "secret-key",
    "secret_key",
    "mysecret",
    "my-secret",
    "my_secret",
    "mysecretkey",
    "jwtsecret",
    "jwt-secret",
    "jwt_secret",
    "jwt",
    "key",
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "changeme",
    "admin",
    "test",
    "testing",
    "default",
    "supersecret",
    "super-secret",
    "your-256-bit-secret",
    "your-secret",
    "your_secret_key",
    "s3cr3t",
    "shhhhh",
    "HS256-secret",
];

/// Whether `token`'s HMAC signature (HS256, HS384 or HS512) verifies with one of [`WEAK_SECRETS`].
fn weak_secret(alg: &str, signing_input: &str, sig: &[u8]) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Sha256, Sha384, Sha512};
    macro_rules! check {
        ($h:ty) => {
            WEAK_SECRETS.iter().any(|s| {
                <Hmac<$h> as KeyInit>::new_from_slice(s.as_bytes()).is_ok_and(|mut m| {
                    m.update(signing_input.as_bytes());
                    m.verify_slice(sig).is_ok()
                })
            })
        };
    }
    match alg {
        "HS256" => check!(Sha256),
        "HS384" => check!(Sha384),
        "HS512" => check!(Sha512),
        _ => false,
    }
}

fn jwt(c: &mut Ctx<'_>) {
    let mut found: Vec<(EvidencePart, usize, usize)> = Vec::new();
    let qbody = c.qh.body.min(c.flow.request.len());
    for m in JWT.find_iter(&c.flow.request[..qbody]).take(4) {
        found.push((EvidencePart::Request, m.start(), m.end()));
    }
    if let Some((base, body)) = c.body() {
        let head = &c.resp[..c.rh.body.min(c.resp.len())];
        for m in JWT.find_iter(head).take(4) {
            found.push((EvidencePart::Response, m.start(), m.end()));
        }
        for m in JWT.find_iter(body).take(4) {
            found.push((EvidencePart::Response, base + m.start(), base + m.end()));
        }
    }
    let key = base_path(c.flow).to_string();
    for (part, s, e) in found.into_iter().take(8) {
        let raw = if part == EvidencePart::Request {
            &c.flow.request[s..e]
        } else {
            &c.resp[s..e]
        };
        let text = String::from_utf8_lossy(raw).into_owned();
        let mut it = text.split('.');
        let decode = |p: Option<&str>| -> Option<serde_json::Value> {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p?).ok()?).ok()
        };
        let (Some(h), Some(p)) = (decode(it.next()), decode(it.next())) else {
            continue;
        };
        let evidence = vec![ev(part, s, e)];
        let alg = h.get("alg").and_then(|a| a.as_str()).unwrap_or("");
        if let Some((signing, sig)) = text.rsplit_once('.')
            && let Ok(sig) = URL_SAFE_NO_PAD.decode(sig)
            && !sig.is_empty()
            && weak_secret(alg, signing, &sig)
        {
            c.emit(
                &JWT_WEAK,
                &key,
                format!("A `{alg}` token in the message is signed with a secret from a list of common ones."),
                evidence.clone(),
            );
        }
        if alg.eq_ignore_ascii_case("none") {
            c.emit(
                &JWT_NONE,
                &key,
                "A token in the message declares `alg: none`.".into(),
                evidence.clone(),
            );
        }
        if let Some(obj) = p.as_object() {
            if !obj.contains_key("exp") {
                c.emit(
                    &JWT_EXP,
                    &key,
                    "A token in the message has no `exp` claim.".into(),
                    evidence.clone(),
                );
            }
            let bad: Vec<&str> = obj
                .keys()
                .map(String::as_str)
                .filter(|k| {
                    let k = k.to_ascii_lowercase();
                    [
                        "password",
                        "passwd",
                        "pwd",
                        "secret",
                        "api_key",
                        "apikey",
                        "private_key",
                    ]
                    .iter()
                    .any(|w| k.contains(w))
                })
                .take(3)
                .collect();
            if !bad.is_empty() {
                let names: Vec<String> = bad.iter().map(|k| k.chars().take(40).collect()).collect();
                c.emit(
                    &JWT_CLAIM,
                    &key,
                    format!("The payload has the claim(s) `{}`.", names.join("`, `")),
                    evidence,
                );
            }
        }
    }
}

fn cache_tokens(c: &Ctx<'_>) -> Vec<String> {
    c.rh.all("cache-control")
        .flat_map(|h| h.value.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect()
}

fn cacheable(c: &mut Ctx<'_>) {
    let s = &c.flow.summary;
    if s.method != "GET" || s.status != Some(200) {
        return;
    }
    let ct = c.content_type();
    let is_static = ["image/", "font/", "text/css", "javascript", "audio/", "video/"]
        .iter()
        .any(|p| ct.contains(p));
    let authed = c.qh.get("authorization").is_some();
    let cookie_set = c.rh.get("set-cookie").is_some() && !is_static;
    if !(authed || cookie_set) {
        return;
    }
    let tokens = cache_tokens(c);
    if tokens.iter().any(|t| t == "no-store" || t == "private") {
        return;
    }
    let explicit = tokens.iter().any(|t| {
        t == "public"
            || ["max-age=", "s-maxage="].iter().any(|p| {
                t.strip_prefix(p)
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
            })
    });
    let mut code = CACHEABLE;
    if explicit {
        code.confidence = Confidence::Firm;
    }
    let evidence =
        c.rh.get("cache-control")
            .map(|h| vec![ev(EvidencePart::Response, h.start, h.end)])
            .unwrap_or_default();
    let why = if authed {
        "the request carried an Authorization header"
    } else {
        "the response sets a cookie"
    };
    let key = base_path(c.flow).to_string();
    c.emit(
        &code,
        &key,
        format!("Neither `no-store` nor `private` is sent, and {why}."),
        evidence,
    );
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(h, 16).unwrap_or(b'?'));
                i += 2;
            }
            x => out.push(x),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn open_redirect(c: &mut Ctx<'_>) {
    let s = &c.flow.summary;
    let Some(status) = s.status else { return };
    if !(300..400).contains(&status) {
        return;
    }
    let Some(loc) = c.rh.get("location") else { return };
    let value = loc.value;
    if !(value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")) {
        return;
    }
    let lhost = url_host(value).to_ascii_lowercase();
    if lhost.is_empty() || lhost == s.host.to_ascii_lowercase() {
        return;
    }
    let Some((_, query)) = s.path.split_once('?') else {
        return;
    };
    let query = query.split('#').next().unwrap_or("");
    let ev = vec![ev(EvidencePart::Response, loc.start, loc.end)];
    let key = base_path(c.flow).to_string();
    for pair in query.split('&').take(64) {
        let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(raw);
        let vhost = url_host(v.trim()).to_ascii_lowercase();
        if vhost.contains('.') && vhost == lhost {
            let shown: String = percent_decode(name).chars().take(40).collect();
            c.emit(
                &OPEN_REDIRECT,
                &format!("{key}|{shown}"),
                format!("The `{shown}` parameter names `{lhost}`, and the response redirects there."),
                ev.clone(),
            );
            return;
        }
    }
}

/// Run every check in this crate on one flow. Flows without a response give nothing.
pub fn scan_flow(flow: &FlowDetail, now_ms: i64) -> Vec<NewIssue> {
    scan_flow_with(flow, now_ms, &[])
}

/// [`scan_flow`], and the project's own (custom) passive checks too.
pub fn scan_flow_with(flow: &FlowDetail, now_ms: i64, custom: &[Compiled]) -> Vec<NewIssue> {
    let Some(resp) = flow.response.as_deref() else {
        return Vec::new();
    };
    let mut c = Ctx {
        flow,
        resp,
        rh: Head::parse(resp),
        qh: Head::parse(&flow.request),
        now: now_ms,
        out: Vec::new(),
    };
    let ct = c.content_type();
    let html = ct.contains("text/html") || ct.contains("application/xhtml");
    mixed_content(&mut c, html);
    vulnerable_js(&mut c, html);
    jwt(&mut c);
    cacheable(&mut c);
    open_redirect(&mut c);

    let status = flow.summary.status.unwrap_or(0);
    let msg = Message {
        request: &flow.request,
        response: resp,
        status,
        interaction: None,
    };
    for check in builtin().iter().chain(custom) {
        let Some(hit) = check.eval_passive(&msg) else {
            continue;
        };
        let i = &check.check.info;
        let mut detail = i.description.clone();
        if !hit.extracted.is_empty() {
            let vals: Vec<String> = hit.extracted.iter().map(|(n, v)| format!("{n}={v}")).collect();
            detail = format!("{detail} Extracted: {}.", vals.join(", "));
        }
        let spec = Spec {
            rule: &check.check.id,
            title: &i.name,
            severity: i.severity.to_store(),
            confidence: i.confidence.to_store(),
            remediation: &i.remediation,
            cwe: &i.cwe,
            owasp: &i.owasp,
        };
        let key = base_path(flow).to_string();
        c.out.push(make(flow, &spec, &key, detail, hit.evidence, now_ms));
    }
    c.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bosun_model::{FlowSource, FlowSummary, Scheme};

    fn flow(status: u16, req_extra: &str, path: &str, resp_head: &str, body: &str) -> FlowDetail {
        let resp = format!(
            "HTTP/1.1 {status} X\r\n{resp_head}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        FlowDetail {
            summary: FlowSummary {
                id: 1,
                source: FlowSource::Proxy,
                started_ms: 1,
                duration_ms: Some(1),
                ttfb_ms: None,
                scheme: Scheme::Https,
                host: "shop.test".into(),
                port: 443,
                method: "GET".into(),
                path: path.into(),
                http_version: "HTTP/1.1".into(),
                status: Some(status),
                request_len: 10,
                response_len: Some(resp.len() as i64),
                mime: None,
                in_scope: true,
                edited: false,
                error: None,
                tags: vec![],
                note: None,
            },
            request: format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n{req_extra}\r\n").into_bytes(),
            original_request: None,
            response: Some(resp.into_bytes()),
            original_response: None,
            response_truncated: false,
        }
    }

    fn html(body: &str) -> FlowDetail {
        flow(200, "", "/p", "Content-Type: text/html\r\n", body)
    }

    fn ids(f: &FlowDetail) -> Vec<String> {
        let mut v: Vec<String> = scan_flow(f, 1).into_iter().map(|i| i.rule).collect();
        v.sort_unstable();
        v
    }

    fn jwt_of(h: &str, p: &str) -> String {
        format!("{}.{}.sig", URL_SAFE_NO_PAD.encode(h), URL_SAFE_NO_PAD.encode(p))
    }

    /// A token with a real HS256 signature made with `secret`.
    fn signed_jwt(secret: &str, p: &str) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(p)
        );
        let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
        m.update(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(m.finalize().into_bytes()))
    }

    /// One positive and one negative fixture for every check. `positive` must give at least the id; `negative`
    /// must not give it.
    fn fixtures() -> Vec<(&'static str, FlowDetail, FlowDetail)> {
        let tok_none = jwt_of(r#"{"alg":"none"}"#, r#"{"sub":"a","exp":9999999999}"#);
        let tok_exp = jwt_of(r#"{"alg":"HS256"}"#, r#"{"sub":"a"}"#);
        let tok_claim = jwt_of(r#"{"alg":"HS256"}"#, r#"{"exp":9999999999,"password":"hunter2"}"#);
        let tok_ok = jwt_of(r#"{"alg":"HS256"}"#, r#"{"sub":"a","exp":9999999999}"#);
        let auth = |t: &str| format!("Authorization: Bearer {t}\r\n");
        vec![
            (
                "stack-trace-disclosure",
                html("Traceback (most recent call last):\n  File \"a.py\""),
                html("<p>Welcome</p>"),
            ),
            (
                "sql-error-disclosure",
                html("You have an error in your SQL syntax near"),
                html("<p>no results</p>"),
            ),
            (
                "private-ip-disclosure",
                flow(200, "", "/p", "X-Backend: 10.1.2.3\r\n", "x"),
                flow(200, "", "/p", "X-Backend: 110.1.2.3\r\n", "version 1.10.1.2.3x"),
            ),
            (
                "aws-access-key-id",
                html("key AKIAIOSFODNN7EXAMPLE here"),
                html("key AKIA short"),
            ),
            (
                "debug-page",
                html("<title>phpinfo()</title>"),
                html("<title>Info</title>"),
            ),
            (
                "mixed-content-active",
                html(r#"<script src="http://cdn.test/a.js"></script>"#),
                html(r#"<script src="https://cdn.test/a.js"></script>"#),
            ),
            (
                "mixed-content-passive",
                html(r#"<img src='http://img.test/a.png'>"#),
                html(r#"<img src="//img.test/a.png"><a href="http://x.test/">l</a>"#),
            ),
            (
                "vulnerable-js-library",
                html(r#"<script src="/js/jquery-3.4.1.min.js"></script>"#),
                html(r#"<script src="/js/jquery-3.7.1.min.js"></script>"#),
            ),
            (
                "jwt-alg-none",
                flow(200, &auth(&tok_none), "/api", "", "x"),
                flow(200, &auth(&tok_ok), "/api", "", "x"),
            ),
            (
                "jwt-no-expiry",
                flow(200, "", "/api", "", &format!("{{\"token\":\"{tok_exp}\"}}")),
                flow(200, "", "/api", "", &format!("{{\"token\":\"{tok_ok}\"}}")),
            ),
            (
                "jwt-weak-secret",
                flow(
                    200,
                    &auth(&signed_jwt("secret", r#"{"sub":"a","exp":9999999999}"#)),
                    "/api",
                    "",
                    "x",
                ),
                flow(
                    200,
                    &auth(&signed_jwt(
                        "q8Zr2vLw0xN5mT1hYb7uKc4sPd9eJg3A",
                        r#"{"sub":"a","exp":9999999999}"#,
                    )),
                    "/api",
                    "",
                    "x",
                ),
            ),
            (
                "jwt-sensitive-claim",
                flow(200, &auth(&tok_claim), "/api", "", "x"),
                flow(200, &auth(&tok_ok), "/api", "", "x"),
            ),
            (
                "cacheable-sensitive-response",
                flow(
                    200,
                    "Authorization: Bearer a\r\n",
                    "/me",
                    "Cache-Control: public, max-age=600\r\n",
                    "x",
                ),
                flow(
                    200,
                    "Authorization: Bearer a\r\n",
                    "/me",
                    "Cache-Control: no-store\r\n",
                    "x",
                ),
            ),
            (
                "open-redirect-hint",
                flow(
                    302,
                    "",
                    "/go?next=https%3A%2F%2Fevil.test%2Fx",
                    "Location: https://evil.test/x\r\n",
                    "",
                ),
                flow(302, "", "/go?next=%2Fhome", "Location: /home\r\n", ""),
            ),
        ]
    }

    #[test]
    fn every_check_has_a_positive_and_a_negative_fixture() {
        let fx = fixtures();
        let mut want = all_ids();
        want.sort_unstable();
        let mut have: Vec<String> = fx.iter().map(|(id, _, _)| (*id).to_string()).collect();
        have.sort_unstable();
        assert_eq!(want, have, "a check without fixtures (or a fixture for no check)");
        for (id, pos, neg) in &fx {
            assert!(
                scan_flow(pos, 1).iter().any(|i| i.rule == *id),
                "{id}: positive fixture not found"
            );
            assert!(
                !scan_flow(neg, 1).iter().any(|i| i.rule == *id),
                "{id}: negative fixture found"
            );
        }
    }

    #[test]
    fn every_builtin_check_parses_and_is_passive() {
        assert_eq!(builtin().len(), 5);
        assert!(builtin().iter().all(Compiled::is_passive));
    }

    #[test]
    fn evidence_points_at_the_match() {
        let f = html(r#"<script src="http://cdn.test/a.js"></script>"#);
        let i = &scan_flow(&f, 1)[0];
        let r = f.response.as_ref().unwrap();
        let e = i.evidence[0];
        assert!(r[e.start as usize..e.end as usize].starts_with(b"<script src=\"http://cdn.test"));
        assert!(i.detail.contains("cdn.test") && !i.detail.contains("a.js"));
        // A library found by its header comment, outside a page.
        let f = flow(
            200,
            "",
            "/static/app.js",
            "Content-Type: application/javascript\r\n",
            "/*! jQuery v1.12.4 | (c) */",
        );
        let i = &scan_flow(&f, 1)[0];
        let e = i.evidence[0];
        assert_eq!(
            &f.response.as_ref().unwrap()[e.start as usize..e.end as usize],
            b"1.12.4"
        );
        assert_eq!(
            i.fingerprint,
            "vulnerable-js-library|https://shop.test:443|jquery|1.12.4"
        );
    }

    #[test]
    fn javascript_version_ranges() {
        for (src, vulnerable) in [
            ("bootstrap-4.2.1.min.js", true),
            ("bootstrap-4.3.1.min.js", false),
            ("bootstrap-3.3.7.js", true),
            ("lodash-4.17.21.min.js", false),
            ("angular.min.js", false),
            ("moment-2.29.1.js", true),
        ] {
            let f = html(&format!(r#"<script src="/{src}?v=1"></script>"#));
            assert_eq!(ids(&f) == ["vulnerable-js-library"], vulnerable, "{src}");
        }
    }

    #[test]
    fn cacheable_needs_a_reason_and_skips_static_files() {
        // A cookie on a page with no Cache-Control: tentative; a static image is left alone.
        let f = flow(200, "", "/p", "Set-Cookie: s=1\r\n", "x");
        let got = scan_flow(&f, 1);
        assert_eq!(
            got.iter()
                .filter(|i| i.rule == "cacheable-sensitive-response")
                .count(),
            1
        );
        let f = flow(
            200,
            "",
            "/i.png",
            "Set-Cookie: s=1\r\nContent-Type: image/png\r\n",
            "x",
        );
        assert!(ids(&f).is_empty());
        let f = flow(200, "", "/p", "", "x");
        assert!(ids(&f).is_empty());
    }

    #[test]
    fn open_redirect_ignores_same_host_and_unrelated_targets() {
        assert!(
            ids(&flow(
                302,
                "",
                "/go?next=https://shop.test/a",
                "Location: https://shop.test/a\r\n",
                ""
            ))
            .is_empty()
        );
        assert!(ids(&flow(302, "", "/go?x=1", "Location: https://other.test/\r\n", "")).is_empty());
        assert_eq!(
            ids(&flow(
                302,
                "",
                "/go?u=//evil.test",
                "Location: //evil.test\r\n",
                ""
            )),
            ["open-redirect-hint"]
        );
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let junk = "eyJ.eyJ.\u{0}%zz%".repeat(200);
        let f = flow(
            302,
            &format!("Authorization: {junk}\r\n"),
            &format!("/g?a=%&b=%4{junk}"),
            "Location: //\r\n",
            &junk,
        );
        let _ = scan_flow(&f, 1);
        let mut f = html("x");
        f.response = Some(b"HTTP/1.1 200 OK\r\n".to_vec());
        let _ = scan_flow(&f, 1);
    }
}
