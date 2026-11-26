//! The built-in passive rules. Each reads one recorded flow and reports what it shows; none sends anything.
//!
//! A finding's fingerprint is the rule, the origin and a rule-specific key (a cookie's name, a path), so the same
//! weakness seen in a thousand responses is one issue with a count.

use bosun_model::FlowDetail;
use bosun_store::{Confidence, Evidence, EvidencePart, NewIssue, Severity};

use crate::head::{Head, Header};

/// How much of a body the rules read.
const BODY_LIMIT: usize = 1 << 20;

struct Spec {
    rule: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: Confidence,
    remediation: &'static str,
    cwe: &'static [u32],
    owasp: &'static [&'static str],
}

const MISCONFIG: &str = "A05:2021 Security Misconfiguration";

const HSTS: Spec = Spec {
    rule: "hsts-missing",
    title: "Strict-Transport-Security header missing",
    severity: Severity::Low,
    confidence: Confidence::Certain,
    remediation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.",
    cwe: &[319],
    owasp: &[MISCONFIG],
};
const NOSNIFF: Spec = Spec {
    rule: "nosniff-missing",
    title: "X-Content-Type-Options: nosniff missing",
    severity: Severity::Info,
    confidence: Confidence::Certain,
    remediation: "Send `X-Content-Type-Options: nosniff` so browsers do not guess content types.",
    cwe: &[693],
    owasp: &[MISCONFIG],
};
const FRAMING: Spec = Spec {
    rule: "framing-unprotected",
    title: "Page can be framed by other sites (clickjacking)",
    severity: Severity::Low,
    confidence: Confidence::Firm,
    remediation: "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`).",
    cwe: &[1021],
    owasp: &[MISCONFIG],
};
const CSP_MISSING: Spec = Spec {
    rule: "csp-missing",
    title: "Content-Security-Policy header missing",
    severity: Severity::Info,
    confidence: Confidence::Certain,
    remediation: "Define a Content-Security-Policy that limits where scripts, frames and other content may load from.",
    cwe: &[693],
    owasp: &[MISCONFIG],
};
const CSP_WEAK: Spec = Spec {
    rule: "csp-weak",
    title: "Content-Security-Policy allows unsafe script sources",
    severity: Severity::Low,
    confidence: Confidence::Firm,
    remediation: "Remove `'unsafe-inline'`, `'unsafe-eval'` and bare `*` from script sources; use nonces or hashes.",
    cwe: &[693],
    owasp: &[MISCONFIG],
};
const COOKIE_SECURE: Spec = Spec {
    rule: "cookie-no-secure",
    title: "Cookie set without the Secure flag",
    severity: Severity::Low,
    confidence: Confidence::Certain,
    remediation: "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
    cwe: &[614],
    owasp: &["A02:2021 Cryptographic Failures"],
};
const COOKIE_HTTPONLY: Spec = Spec {
    rule: "cookie-no-httponly",
    title: "Cookie set without the HttpOnly flag",
    severity: Severity::Low,
    confidence: Confidence::Firm,
    remediation: "Add `HttpOnly` to cookies that scripts do not need to read, session cookies above all.",
    cwe: &[1004],
    owasp: &[MISCONFIG],
};
const COOKIE_SAMESITE: Spec = Spec {
    rule: "cookie-no-samesite",
    title: "Cookie set without a SameSite attribute",
    severity: Severity::Info,
    confidence: Confidence::Certain,
    remediation: "Add `SameSite=Lax` (or `Strict`) so the cookie is not sent on cross-site requests.",
    cwe: &[1275],
    owasp: &["A01:2021 Broken Access Control"],
};
const VERSION: Spec = Spec {
    rule: "version-disclosure",
    title: "Server software and version disclosed in a header",
    severity: Severity::Info,
    confidence: Confidence::Firm,
    remediation: "Remove the version from `Server` / `X-Powered-By` style headers, or remove the headers.",
    cwe: &[200],
    owasp: &[MISCONFIG],
};
const CORS_WILDCARD: Spec = Spec {
    rule: "cors-wildcard-credentials",
    title: "CORS allows any origin together with credentials",
    severity: Severity::Low,
    confidence: Confidence::Tentative,
    remediation: "Never combine `Access-Control-Allow-Credentials: true` with a wildcard; list the origins allowed.",
    cwe: &[942],
    owasp: &[MISCONFIG],
};
const CORS_REFLECT: Spec = Spec {
    rule: "cors-reflected-origin",
    title: "CORS trusts the request's Origin with credentials",
    severity: Severity::Medium,
    confidence: Confidence::Firm,
    remediation: "Check the Origin against a fixed list of trusted origins instead of echoing it back.",
    cwe: &[942],
    owasp: &[MISCONFIG],
};
const PRIVATE_KEY: Spec = Spec {
    rule: "private-key",
    title: "Private key in a response",
    severity: Severity::High,
    confidence: Confidence::Firm,
    remediation: "Remove the key from the response, treat it as compromised and issue a new one.",
    cwe: &[200],
    owasp: &["A02:2021 Cryptographic Failures"],
};
const DIR_LISTING: Spec = Spec {
    rule: "directory-listing",
    title: "Directory listing enabled",
    severity: Severity::Low,
    confidence: Confidence::Firm,
    remediation: "Turn off automatic directory indexes on the web server.",
    cwe: &[548],
    owasp: &[MISCONFIG],
};

/// The rule ids, for the filter in the UI and the docs.
pub const RULES: &[&str] = &[
    HSTS.rule,
    NOSNIFF.rule,
    FRAMING.rule,
    CSP_MISSING.rule,
    CSP_WEAK.rule,
    COOKIE_SECURE.rule,
    COOKIE_HTTPONLY.rule,
    COOKIE_SAMESITE.rule,
    VERSION.rule,
    CORS_WILDCARD.rule,
    CORS_REFLECT.rule,
    PRIVATE_KEY.rule,
    DIR_LISTING.rule,
];

struct Ctx<'a> {
    flow: &'a FlowDetail,
    resp: &'a [u8],
    rh: Head<'a>,
    qh: Head<'a>,
    now: i64,
    out: Vec<NewIssue>,
}

impl Ctx<'_> {
    fn origin(&self) -> String {
        let s = &self.flow.summary;
        format!(
            "{}://{}:{}",
            s.scheme.as_str(),
            s.host.to_ascii_lowercase(),
            s.port
        )
    }

    fn base_path(&self) -> &str {
        let p = &self.flow.summary.path;
        p.split(['?', '#']).next().unwrap_or(p)
    }

    fn emit(&mut self, spec: &Spec, key: &str, detail: String, evidence: Vec<Evidence>) {
        let s = &self.flow.summary;
        self.out.push(NewIssue {
            rule: spec.rule.into(),
            title: spec.title.into(),
            severity: spec.severity,
            confidence: spec.confidence,
            flow_id: s.id,
            scheme: s.scheme.as_str().into(),
            host: s.host.to_ascii_lowercase(),
            port: s.port,
            path: self.base_path().chars().take(512).collect(),
            detail,
            evidence,
            remediation: spec.remediation.into(),
            cwe: spec.cwe.to_vec(),
            owasp: spec.owasp.iter().map(|s| (*s).into()).collect(),
            fingerprint: format!("{}|{}|{key}", spec.rule, self.origin()),
            time_ms: self.now,
        });
    }

    /// The body, when it can be read as it is: not compressed, and no more than the limit.
    fn body_range(&self) -> Option<std::ops::Range<usize>> {
        if let Some(e) = self.rh.get("content-encoding")
            && !e.value.is_empty()
            && !e.value.eq_ignore_ascii_case("identity")
        {
            return None;
        }
        let b = self.resp.get(self.rh.body..)?;
        Some(self.rh.body..self.rh.body + b.len().min(BODY_LIMIT))
    }
}

fn response_range(h: &Header<'_>) -> Vec<Evidence> {
    vec![Evidence {
        part: EvidencePart::Response,
        start: h.start as u64,
        end: h.end as u64,
    }]
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_nocase(hay: &[u8], needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    if hay.len() < n.len() {
        return None;
    }
    hay.windows(n.len()).position(|w| w.eq_ignore_ascii_case(n))
}

/// `1.2`, `/2` or `v3`: something that looks like a version number.
fn has_version(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit())
        || b.windows(2).any(|w| w[0] == b'/' && w[1].is_ascii_digit())
}

fn csp_directive<'a>(csp: &'a str, name: &str) -> Option<&'a str> {
    csp.split(';').map(str::trim).find_map(|d| {
        let (n, v) = d.split_once(char::is_whitespace).unwrap_or((d, ""));
        n.eq_ignore_ascii_case(name).then_some(v)
    })
}

/// Read one flow and report what the rules find. Flows without a response give nothing.
pub fn scan_flow(flow: &FlowDetail, now_ms: i64) -> Vec<NewIssue> {
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
    let status = flow.summary.status.unwrap_or(0);
    let ok = (200..400).contains(&status) && status != 304;
    let https = flow.summary.scheme.as_str() == "https";
    let html = c.rh.get("content-type").is_some_and(|h| {
        let v = h.value.to_ascii_lowercase();
        v.contains("text/html") || v.contains("application/xhtml")
    });
    let csp =
        c.rh.get("content-security-policy")
            .map(|h| (h.value.to_string(), h.start, h.end));

    if ok && https && c.rh.get("strict-transport-security").is_none() {
        c.emit(
            &HSTS,
            "",
            "The response has no Strict-Transport-Security header.".into(),
            vec![],
        );
    }
    if ok
        && !c
            .rh
            .get("x-content-type-options")
            .is_some_and(|h| h.value.eq_ignore_ascii_case("nosniff"))
    {
        c.emit(
            &NOSNIFF,
            "",
            "The response does not send `X-Content-Type-Options: nosniff`.".into(),
            vec![],
        );
    }
    if ok && html {
        let ancestors = csp
            .as_ref()
            .is_some_and(|(v, _, _)| csp_directive(v, "frame-ancestors").is_some());
        if c.rh.get("x-frame-options").is_none() && !ancestors {
            c.emit(
                &FRAMING,
                "",
                "An HTML page with neither `X-Frame-Options` nor a CSP `frame-ancestors` directive.".into(),
                vec![],
            );
        }
        if csp.is_none() {
            c.emit(
                &CSP_MISSING,
                "",
                "An HTML page without a Content-Security-Policy header.".into(),
                vec![],
            );
        }
    }
    if let Some((v, start, end)) = &csp {
        let scripts = csp_directive(v, "script-src").or_else(|| csp_directive(v, "default-src"));
        if let Some(s) = scripts {
            let l = s.to_ascii_lowercase();
            let guarded = l.contains("'nonce-") || l.contains("'sha") || l.contains("'strict-dynamic'");
            let mut bad = Vec::new();
            if l.contains("'unsafe-inline'") && !guarded {
                bad.push("'unsafe-inline'");
            }
            if l.contains("'unsafe-eval'") {
                bad.push("'unsafe-eval'");
            }
            if l.split_whitespace().any(|t| t == "*") {
                bad.push("a bare *");
            }
            if !bad.is_empty() {
                let ev = vec![Evidence {
                    part: EvidencePart::Response,
                    start: *start as u64,
                    end: *end as u64,
                }];
                c.emit(
                    &CSP_WEAK,
                    "",
                    format!("Script sources allow {}.", bad.join(", ")),
                    ev,
                );
            }
        }
    }

    let cookies: Vec<(String, bool, bool, bool, Vec<Evidence>)> =
        c.rh.all("set-cookie")
            .filter_map(|h| {
                let mut parts = h.value.split(';');
                let name = parts.next()?.split_once('=')?.0.trim().to_string();
                let attrs: Vec<String> = parts.map(|a| a.trim().to_ascii_lowercase()).collect();
                let has = |n: &str| attrs.iter().any(|a| a == n || a.starts_with(&format!("{n}=")));
                Some((
                    name,
                    has("secure"),
                    has("httponly"),
                    has("samesite"),
                    response_range(h),
                ))
            })
            .collect();
    for (name, secure, httponly, samesite, ev) in cookies {
        let shown: String = name.chars().take(64).collect();
        if !secure {
            c.emit(
                &COOKIE_SECURE,
                &name,
                format!("Cookie `{shown}` has no Secure attribute."),
                ev.clone(),
            );
        }
        if !httponly {
            c.emit(
                &COOKIE_HTTPONLY,
                &name,
                format!("Cookie `{shown}` has no HttpOnly attribute."),
                ev.clone(),
            );
        }
        if !samesite {
            c.emit(
                &COOKIE_SAMESITE,
                &name,
                format!("Cookie `{shown}` has no SameSite attribute."),
                ev,
            );
        }
    }

    let versions: Vec<(String, String, Vec<Evidence>)> = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    ]
    .iter()
    .filter_map(|n| c.rh.get(n))
    .filter(|h| has_version(h.value))
    .map(|h| {
        (
            h.name.to_ascii_lowercase(),
            h.value.to_string(),
            response_range(h),
        )
    })
    .collect();
    for (name, value, ev) in versions {
        let shown: String = value.chars().take(120).collect();
        c.emit(&VERSION, &name, format!("`{name}: {shown}`"), ev);
    }

    if let Some(acao) = c.rh.get("access-control-allow-origin") {
        let creds =
            c.rh.get("access-control-allow-credentials")
                .is_some_and(|h| h.value.eq_ignore_ascii_case("true"));
        let ev = response_range(acao);
        let value = acao.value.to_string();
        let origin = c.qh.get("origin").map(|h| h.value.to_string());
        if creds && value == "*" {
            c.emit(
                &CORS_WILDCARD,
                "",
                "`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers refuse this \
                 combination, but it shows the policy is not thought through)."
                    .into(),
                ev,
            );
        } else if creds && value != "*" && (value == "null" || origin.as_deref() == Some(value.as_str())) {
            let shown: String = value.chars().take(120).collect();
            c.emit(
                &CORS_REFLECT,
                "",
                format!("`Access-Control-Allow-Origin: {shown}` was sent with credentials allowed, and matches the request's Origin."),
                ev,
            );
        }
    }

    if let Some(range) = c.body_range() {
        let body = &resp[range];
        let start = c.rh.body as u64;
        if let Some(i) = find(body, b"-----BEGIN ") {
            let tail = &body[i..body.len().min(i + 64)];
            if let Some(j) = find(tail, b"PRIVATE KEY-----") {
                let end = i + j + b"PRIVATE KEY-----".len();
                let ev = vec![Evidence {
                    part: EvidencePart::Response,
                    start: start + i as u64,
                    end: start + end as u64,
                }];
                let key = c.base_path().to_string();
                c.emit(
                    &PRIVATE_KEY,
                    &key,
                    "A PEM private key header appears in the response body.".into(),
                    ev,
                );
            }
        }
        if html {
            let head = &body[..body.len().min(16 * 1024)];
            if let Some(i) = find_nocase(head, "<title>index of /")
                && (find_nocase(head, "parent directory").is_some()
                    || find_nocase(head, "<h1>index of").is_some())
            {
                let ev = vec![Evidence {
                    part: EvidencePart::Response,
                    start: start + i as u64,
                    end: start + (i + "<title>index of /".len()) as u64,
                }];
                let key = c.base_path().to_string();
                c.emit(
                    &DIR_LISTING,
                    &key,
                    "The page is an automatic directory index.".into(),
                    ev,
                );
            }
        }
    }
    c.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bosun_model::{FlowSource, FlowSummary, Scheme};

    fn flow(scheme: Scheme, req_extra: &str, resp_head: &str, body: &str) -> FlowDetail {
        let resp = format!(
            "HTTP/1.1 200 OK\r\n{resp_head}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        FlowDetail {
            summary: FlowSummary {
                id: 7,
                source: FlowSource::Proxy,
                started_ms: 1,
                duration_ms: Some(1),
                scheme,
                host: "Shop.Test".into(),
                port: if scheme == Scheme::Https { 443 } else { 80 },
                method: "GET".into(),
                path: "/a/b?token=secret".into(),
                http_version: "HTTP/1.1".into(),
                status: Some(200),
                request_len: 10,
                response_len: Some(resp.len() as i64),
                mime: None,
                in_scope: true,
                edited: false,
                error: None,
                tags: vec![],
                note: None,
            },
            request: format!("GET /a/b HTTP/1.1\r\nHost: shop.test\r\n{req_extra}\r\n").into_bytes(),
            original_request: None,
            response: Some(resp.into_bytes()),
            original_response: None,
            response_truncated: false,
        }
    }

    const HARDENED: &str = "Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\n\
        Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nContent-Type: text/html\r\n";

    fn rules(f: &FlowDetail) -> Vec<&'static str> {
        let mut v: Vec<_> = scan_flow(f, 5)
            .into_iter()
            .map(|i| RULES.iter().copied().find(|r| *r == i.rule).unwrap())
            .collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn a_hardened_response_gives_nothing() {
        assert!(rules(&flow(Scheme::Https, "", HARDENED, "<p>hi</p>")).is_empty());
    }

    #[test]
    fn no_response_gives_nothing() {
        let mut f = flow(Scheme::Https, "", "", "");
        f.response = None;
        assert!(scan_flow(&f, 1).is_empty());
    }

    #[test]
    fn missing_headers() {
        let got = rules(&flow(Scheme::Https, "", "Content-Type: text/html\r\n", "x"));
        assert_eq!(
            got,
            [
                "csp-missing",
                "framing-unprotected",
                "hsts-missing",
                "nosniff-missing"
            ]
        );
        // HSTS only matters over HTTPS; plain HTTP does not owe it.
        let got = rules(&flow(Scheme::Http, "", "Content-Type: text/plain\r\n", "x"));
        assert_eq!(got, ["nosniff-missing"]);
        // Errors and redirects are not judged.
        let mut f = flow(Scheme::Https, "", "", "x");
        f.summary.status = Some(404);
        assert!(scan_flow(&f, 1).is_empty());
    }

    #[test]
    fn x_frame_options_satisfies_framing() {
        let h = format!("{HARDENED}X-Frame-Options: DENY\r\n").replace("; frame-ancestors 'none'", "");
        assert!(rules(&flow(Scheme::Https, "", &h, "x")).is_empty());
    }

    #[test]
    fn weak_csp_points_at_the_header() {
        let h = "Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/html\r\n\
                 Content-Security-Policy: script-src 'self' 'unsafe-inline' *; frame-ancestors 'none'\r\n";
        let f = flow(Scheme::Https, "", h, "x");
        let got = scan_flow(&f, 5);
        assert_eq!(got.len(), 1);
        let i = &got[0];
        assert_eq!(i.rule, "csp-weak");
        let r = f.response.as_ref().unwrap();
        let e = i.evidence[0];
        assert!(r[e.start as usize..e.end as usize].starts_with(b"Content-Security-Policy: script-src"));
        assert!(i.detail.contains("'unsafe-inline'") && i.detail.contains("bare *"));
        // A nonce makes 'unsafe-inline' inert, and a strict policy is fine.
        let h = h.replace("'unsafe-inline' *", "'unsafe-inline' 'nonce-abc'");
        assert!(rules(&flow(Scheme::Https, "", &h, "x")).is_empty());
    }

    #[test]
    fn cookie_flags() {
        let h =
            format!("{HARDENED}Set-Cookie: sid=1\r\nSet-Cookie: ok=2; Secure; HttpOnly; SameSite=Lax\r\n");
        let f = flow(Scheme::Https, "", &h, "x");
        let got = scan_flow(&f, 5);
        let mut names: Vec<_> = got.iter().map(|i| i.rule.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["cookie-no-httponly", "cookie-no-samesite", "cookie-no-secure"]
        );
        assert!(
            got.iter()
                .all(|i| i.fingerprint.ends_with("|sid") && i.detail.contains("`sid`"))
        );
        let r = f.response.as_ref().unwrap();
        let e = got[0].evidence[0];
        assert_eq!(&r[e.start as usize..e.end as usize], b"Set-Cookie: sid=1");
        // Attribute names are matched whole: `Secure` inside a value does not count.
        let h = format!("{HARDENED}Set-Cookie: sid=Secure; Path=/\r\n");
        assert_eq!(rules(&flow(Scheme::Https, "", &h, "x")).len(), 3);
    }

    #[test]
    fn version_disclosure() {
        let h = format!("{HARDENED}Server: nginx/1.18.0\r\nX-Powered-By: PHP/8.1\r\n");
        assert_eq!(
            rules(&flow(Scheme::Https, "", &h, "x")),
            ["version-disclosure", "version-disclosure"]
        );
        let h = format!("{HARDENED}Server: nginx\r\nX-Powered-By: Express\r\n");
        assert!(rules(&flow(Scheme::Https, "", &h, "x")).is_empty());
    }

    #[test]
    fn cors() {
        let h = format!(
            "{HARDENED}Access-Control-Allow-Origin: https://evil.test\r\nAccess-Control-Allow-Credentials: true\r\n"
        );
        let got = rules(&flow(Scheme::Https, "Origin: https://evil.test\r\n", &h, "x"));
        assert_eq!(got, ["cors-reflected-origin"]);
        // A fixed origin that is not the requester's is fine; so is a reflected one without credentials.
        assert!(rules(&flow(Scheme::Https, "Origin: https://other.test\r\n", &h, "x")).is_empty());
        let h2 = format!("{HARDENED}Access-Control-Allow-Origin: https://evil.test\r\n");
        assert!(rules(&flow(Scheme::Https, "Origin: https://evil.test\r\n", &h2, "x")).is_empty());
        let h3 =
            format!("{HARDENED}Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\n");
        assert_eq!(
            rules(&flow(Scheme::Https, "", &h3, "x")),
            ["cors-wildcard-credentials"]
        );
    }

    #[test]
    fn private_key_in_the_body() {
        let body = "junk\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
        let f = flow(Scheme::Https, "", HARDENED, body);
        let got = scan_flow(&f, 5);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].severity, Severity::High);
        let r = f.response.as_ref().unwrap();
        let e = got[0].evidence[0];
        assert_eq!(
            &r[e.start as usize..e.end as usize],
            b"-----BEGIN RSA PRIVATE KEY-----"
        );
        // A public certificate is not a key, and a compressed body is not read.
        assert!(rules(&flow(Scheme::Https, "", HARDENED, "-----BEGIN CERTIFICATE-----")).is_empty());
        let h = format!("{HARDENED}Content-Encoding: gzip\r\n");
        assert!(rules(&flow(Scheme::Https, "", &h, body)).is_empty());
    }

    #[test]
    fn directory_listing() {
        let body = "<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a>Parent Directory</a>";
        assert_eq!(
            rules(&flow(Scheme::Https, "", HARDENED, body)),
            ["directory-listing"]
        );
        assert!(rules(&flow(Scheme::Https, "", HARDENED, "<title>Welcome</title>")).is_empty());
    }

    #[test]
    fn fingerprints_ignore_the_query_and_case() {
        let a = scan_flow(&flow(Scheme::Https, "", "", "x"), 1);
        let mut f = flow(Scheme::Https, "", "", "x");
        f.summary.host = "SHOP.test".into();
        f.summary.path = "/other?x=1".into();
        let b = scan_flow(&f, 2);
        assert!(!a.is_empty());
        assert_eq!(
            a.iter().map(|i| &i.fingerprint).collect::<Vec<_>>(),
            b.iter().map(|i| &i.fingerprint).collect::<Vec<_>>()
        );
        assert!(a.iter().all(|i| i.path == "/a/b" && i.host == "shop.test"));
    }
}
