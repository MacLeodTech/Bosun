//! Technology fingerprints and known-vulnerable components (WP-82), from one recorded flow.
//!
//! What is read: the `Server`, `X-Powered-By`, `X-AspNet-Version` and `X-Generator` headers, cookie names that
//! belong to a framework, a `<meta name="generator">` tag and `<script src>` file names that carry a version
//! (`angular-1.8.2.min.js`). Nothing is sent, and nothing leaves the machine: versions are matched against the
//! [`AdvisoryDb`] only.
//!
//! Two kinds of issue come out. `technology-fingerprint` (Info) says what the server told us, with a version when it
//! gave one (a disclosed version is itself a small finding). `vulnerable-component` is raised once per advisory
//! that covers the detected version, with the advisory's own severity. A version in a banner is a claim, not a
//! test: a distribution may have back-ported a fix, so the confidence is Tentative and the detail says so.

use std::sync::LazyLock;

use bosun_model::FlowDetail;
use bosun_store::{Confidence, Evidence, EvidencePart, NewIssue, Severity};
use regex::bytes::Regex;

use crate::advisory::{AdvisoryDb, Version};
use crate::head::Head;
use crate::issue::{Spec, make};

/// What was found, and where in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub product: String,
    pub version: Option<String>,
    /// Where it was read: `Server header`, `cookie`, `generator tag`, `script URL`.
    pub source: &'static str,
    /// Offsets in the response of the text it came from.
    pub span: Option<(usize, usize)>,
}

/// Cookie names that give a framework away (the name is compared in lowercase).
const COOKIES: &[(&str, &str)] = &[
    ("phpsessid", "php"),
    ("jsessionid", "java-servlet"),
    ("asp.net_sessionid", "asp.net"),
    ("aspsessionid", "asp"),
    ("laravel_session", "laravel"),
    ("connect.sid", "express"),
    ("csrftoken", "django"),
    ("ci_session", "codeigniter"),
    ("cfid", "coldfusion"),
    ("wordpress_test_cookie", "wordpress"),
    ("_rails_session", "rails"),
];

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)([a-z][a-z0-9._+-]*)/(\d+(?:\.\d+){0,4})").expect("a fixed pattern"));
static META_GENERATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s+name\s*=\s*["']generator["']\s+content\s*=\s*["']([^"']{1,100})["']"#)
        .expect("a fixed pattern")
});
static SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script[^>]{0,300}?\ssrc\s*=\s*["']([^"']{1,300})["']"#).expect("a fixed pattern")
});
static LIB_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/([a-z][a-z0-9_.]*?)[-@.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js$").expect("a fixed pattern")
});
static NAME_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^([a-z][a-z0-9 ._+-]*?)\s+v?(\d+(?:\.\d+){1,4})").expect("a fixed pattern")
});

fn lower(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_ascii_lowercase()
}

/// Product names as the advisories spell them.
fn canonical(name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    match n.as_str() {
        "apache" | "apache httpd" | "httpd" => "apache".into(),
        "microsoft-iis" | "iis" => "iis".into(),
        "openresty" => "openresty".into(),
        "wordpress" => "wordpress".into(),
        _ => n,
    }
}

/// Everything the response says about its stack.
pub fn fingerprint(flow: &FlowDetail) -> Vec<Component> {
    let Some(resp) = flow.response.as_deref() else {
        return Vec::new();
    };
    let head = Head::parse(resp);
    let mut out: Vec<Component> = Vec::new();
    let mut add = |c: Component| {
        if !out
            .iter()
            .any(|o| o.product == c.product && o.version == c.version)
        {
            out.push(c);
        }
    };
    for h in &head.headers {
        let name = h.name.to_ascii_lowercase();
        match name.as_str() {
            "server" | "x-powered-by" | "x-generator" => {
                let source = if name == "server" {
                    "Server header"
                } else {
                    "response header"
                };
                let mut any = false;
                for cap in TOKEN.captures_iter(h.value.as_bytes()).take(6) {
                    let (Some(n), Some(v)) = (cap.get(1), cap.get(2)) else {
                        continue;
                    };
                    any = true;
                    add(Component {
                        product: canonical(&lower(n.as_bytes())),
                        version: Some(lower(v.as_bytes())),
                        source,
                        span: Some((h.start, h.end)),
                    });
                }
                // A product without a version: `Server: nginx`, `X-Powered-By: Express`.
                if !any {
                    let first: String = h
                        .value
                        .split([' ', '(', ';', ','])
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(40)
                        .collect();
                    if first.len() > 1
                        && first
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
                    {
                        add(Component {
                            product: canonical(&first),
                            version: None,
                            source,
                            span: Some((h.start, h.end)),
                        });
                    }
                }
            }
            "x-aspnet-version" | "x-aspnetmvc-version" => {
                let v: String = h.value.chars().take(20).collect();
                if Version::parse(&v).is_some() {
                    add(Component {
                        product: if name == "x-aspnet-version" {
                            "asp.net"
                        } else {
                            "asp.net-mvc"
                        }
                        .into(),
                        version: Some(v),
                        source: "response header",
                        span: Some((h.start, h.end)),
                    });
                }
            }
            "set-cookie" => {
                let cookie = h
                    .value
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if let Some((_, product)) = COOKIES.iter().find(|(c, _)| *c == cookie) {
                    add(Component {
                        product: (*product).into(),
                        version: None,
                        source: "cookie",
                        span: Some((h.start, h.end)),
                    });
                }
            }
            _ => {}
        }
    }
    let ct = head
        .get("content-type")
        .map_or(String::new(), |h| h.value.to_ascii_lowercase());
    let encoded = head
        .get("content-encoding")
        .is_some_and(|h| !h.value.eq_ignore_ascii_case("identity"));
    if ct.contains("html") && !encoded {
        let body = &resp[head.body.min(resp.len())..];
        let body = &body[..body.len().min(1 << 20)];
        for cap in META_GENERATOR.captures_iter(body).take(4) {
            let (Some(all), Some(c)) = (cap.get(0), cap.get(1)) else {
                continue;
            };
            let text = String::from_utf8_lossy(c.as_bytes()).into_owned();
            let span = Some((head.body + all.start(), head.body + all.end()));
            if let Some(m) = NAME_VERSION.captures(text.as_bytes()) {
                if let (Some(n), Some(v)) = (m.get(1), m.get(2)) {
                    add(Component {
                        product: canonical(&lower(n.as_bytes())),
                        version: Some(lower(v.as_bytes())),
                        source: "generator tag",
                        span,
                    });
                }
            } else {
                add(Component {
                    product: canonical(text.split_whitespace().next().unwrap_or("")),
                    version: None,
                    source: "generator tag",
                    span,
                });
            }
        }
        for cap in SCRIPT_SRC.captures_iter(body).take(64) {
            let Some(src) = cap.get(1) else { continue };
            let s = src.as_bytes();
            let path = &s[..s.iter().position(|b| matches!(b, b'?' | b'#')).unwrap_or(s.len())];
            if let Some(m) = LIB_FILE.captures(path)
                && let (Some(n), Some(v)) = (m.get(1), m.get(2))
            {
                add(Component {
                    product: canonical(&lower(n.as_bytes())),
                    version: Some(lower(v.as_bytes())),
                    source: "script URL",
                    span: Some((head.body + src.start(), head.body + src.end())),
                });
            }
        }
    }
    out
}

const TECH: &str = "technology-fingerprint";
const VULN: &str = "vulnerable-component";

/// The rule ids of this module, for filters and docs.
pub const RULES: &[&str] = &[TECH, VULN];

/// Fingerprint one flow and match what it finds against `db`.
pub fn scan_flow(flow: &FlowDetail, now_ms: i64, db: &AdvisoryDb) -> Vec<NewIssue> {
    let mut out = Vec::new();
    for c in fingerprint(flow) {
        let evidence: Vec<Evidence> = c
            .span
            .map(|(start, end)| {
                vec![Evidence {
                    part: EvidencePart::Response,
                    start: start as u64,
                    end: end as u64,
                }]
            })
            .unwrap_or_default();
        let shown = match &c.version {
            Some(v) => format!("{} {v}", c.product),
            None => c.product.clone(),
        };
        let key = format!("{}|{}", c.product, c.version.as_deref().unwrap_or(""));
        let title = if c.version.is_some() {
            format!("Software version disclosed: {shown}")
        } else {
            format!("Technology detected: {shown}")
        };
        out.push(make(
            flow,
            &Spec {
                rule: TECH,
                title: &title,
                severity: Severity::Info,
                confidence: Confidence::Firm,
                remediation: "Not a flaw by itself. Hide the version in banners where practical, and keep the component updated.",
                cwe: &[200],
                owasp: &["A05:2021 Security Misconfiguration".to_string()],
            },
            &key,
            format!("Read from the {}: {shown}.", c.source),
            evidence.clone(),
            now_ms,
        ));
        let Some(version) = c.version.as_deref().and_then(Version::parse) else {
            continue;
        };
        for a in db.matching(&c.product, &version) {
            let mut detail = format!(
                "[{}] {} ({}). Detected as {shown} from the {}. {}",
                a.severity,
                a.summary,
                std::iter::once(a.id.as_str())
                    .chain(a.aliases.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(", "),
                c.source,
                "A version in a banner is what the server says, not a test: a package may have back-ported the fix."
            );
            if let Some(r) = a.references.first() {
                detail.push_str(&format!(" See {r}."));
            }
            let mut cwe = a.cwe.clone();
            if !cwe.contains(&1104) {
                cwe.push(1104);
            }
            out.push(make(
                flow,
                &Spec {
                    rule: VULN,
                    title: &format!("Known vulnerable component: {shown} ({})", a.id),
                    severity: a.severity(),
                    confidence: Confidence::Tentative,
                    remediation: "Update the component to a release that is not affected (or confirm that the distribution has back-ported the fix).",
                    cwe: &cwe,
                    owasp: &["A06:2021 Vulnerable and Outdated Components".to_string()],
                },
                &format!("{key}|{}", a.id),
                detail,
                evidence.clone(),
                now_ms,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use bosun_model::{FlowSource, FlowSummary, Scheme};

    use super::*;

    fn flow(head: &str, body: &str) -> FlowDetail {
        let resp = format!(
            "HTTP/1.1 200 OK\r\n{head}Content-Length: {}\r\n\r\n{body}",
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
                path: "/".into(),
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
            request: b"GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n".to_vec(),
            original_request: None,
            response: Some(resp.into_bytes()),
            original_response: None,
            response_truncated: false,
        }
    }

    fn found(f: &FlowDetail) -> Vec<(String, Option<String>, &'static str)> {
        fingerprint(f)
            .into_iter()
            .map(|c| (c.product, c.version, c.source))
            .collect()
    }

    #[test]
    fn headers_cookies_tags_and_script_names_give_the_stack_away() {
        let f = flow(
            "Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k\r\nX-Powered-By: PHP/7.2.5\r\nX-AspNet-Version: 4.0.30319\r\n\
             Set-Cookie: PHPSESSID=abc; path=/\r\nSet-Cookie: theme=dark\r\nContent-Type: text/html\r\n",
            r#"<meta name="generator" content="WordPress 6.2.1"><script src="/js/angular-1.8.2.min.js?x=1"></script>"#,
        );
        let got = found(&f);
        for want in [
            ("apache", Some("2.4.49"), "Server header"),
            ("openssl", Some("1.1.1"), "Server header"),
            ("php", Some("7.2.5"), "response header"),
            ("asp.net", Some("4.0.30319"), "response header"),
            ("php", None, "cookie"),
            ("wordpress", Some("6.2.1"), "generator tag"),
            ("angular", Some("1.8.2"), "script URL"),
        ] {
            assert!(
                got.iter()
                    .any(|(p, v, s)| p == want.0 && v.as_deref() == want.1 && *s == want.2),
                "{want:?} not in {got:?}"
            );
        }
        assert!(!got.iter().any(|(p, _, _)| p == "theme"));
        // A header with no version still names the product.
        let f = flow("Server: nginx\r\nX-Powered-By: Express\r\n", "");
        assert_eq!(
            found(&f).into_iter().map(|(p, v, _)| (p, v)).collect::<Vec<_>>(),
            [("nginx".to_string(), None), ("express".to_string(), None)]
        );
    }

    #[test]
    fn a_version_inside_an_advisory_range_is_raised_once_per_advisory_with_evidence() {
        let db = AdvisoryDb::bundled();
        let f = flow("Server: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/7.3.5\r\n", "");
        let issues = scan_flow(&f, 1, db);
        let rules: Vec<(&str, &str)> = issues
            .iter()
            .map(|i| (i.rule.as_str(), i.title.as_str()))
            .collect();
        // Apache 2.4.49 is in both Apache advisories; PHP 7.3.5 is in the PHP-FPM one.
        let vulns: Vec<&str> = rules
            .iter()
            .filter(|(r, _)| *r == "vulnerable-component")
            .map(|(_, t)| *t)
            .collect();
        assert_eq!(vulns.len(), 3, "{rules:?}");
        for id in ["CVE-2021-41773", "CVE-2021-42013", "CVE-2019-11043"] {
            assert!(vulns.iter().any(|t| t.contains(id)), "{id} in {vulns:?}");
        }
        let v = issues
            .iter()
            .find(|i| i.title.contains("CVE-2021-41773"))
            .unwrap();
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.confidence, Confidence::Tentative);
        assert!(v.detail.contains("back-ported") && v.cwe.contains(&22) && v.cwe.contains(&1104));
        let e = &v.evidence[0];
        let resp = f.response.as_deref().unwrap();
        assert!(
            String::from_utf8_lossy(&resp[e.start as usize..e.end as usize])
                .starts_with("Server: Apache/2.4.49")
        );
        // Fingerprint keys do not repeat per path: one issue per host, product, version and advisory.
        assert!(
            v.fingerprint
                .starts_with("vulnerable-component|https://shop.test:443|apache|2.4.49|")
        );
    }

    #[test]
    fn fixed_versions_and_unknown_products_raise_only_the_fingerprint() {
        let db = AdvisoryDb::bundled();
        let f = flow(
            "Server: Apache/2.4.51\r\nX-Powered-By: PHP/8.2.1\r\nSet-Cookie: connect.sid=x\r\n",
            "",
        );
        let rules: Vec<String> = scan_flow(&f, 1, db).into_iter().map(|i| i.rule).collect();
        assert!(rules.iter().all(|r| r == "technology-fingerprint"), "{rules:?}");
        assert!(scan_flow(&flow("", ""), 1, db).is_empty());
        let mut no_response = flow("Server: Apache/2.4.49\r\n", "");
        no_response.response = None;
        assert!(scan_flow(&no_response, 1, db).is_empty());
    }

    #[test]
    fn a_feed_can_cover_a_script_library() {
        let db = AdvisoryDb {
            sequence: 1,
            generated: "2026-11-28".into(),
            advisories: vec![crate::advisory::Advisory {
                id: "TEST-1".into(),
                aliases: vec!["GHSA-x".into()],
                product: "angular".into(),
                summary: "A test advisory.".into(),
                severity: "medium".into(),
                ranges: vec![crate::advisory::Range {
                    introduced: None,
                    fixed: Some("1.8.3".into()),
                    last_affected: None,
                }],
                cwe: vec![79],
                references: vec!["https://example.test/a".into()],
            }],
            source: "feed",
        };
        let f = flow(
            "Content-Type: text/html\r\n",
            r#"<script src="https://cdn.test/angular-1.8.2.min.js"></script>"#,
        );
        let issues = scan_flow(&f, 1, &db);
        let v = issues.iter().find(|i| i.rule == "vulnerable-component").unwrap();
        assert_eq!(v.severity, Severity::Medium);
        assert!(v.detail.contains("TEST-1, GHSA-x") && v.detail.contains("https://example.test/a"));
    }
}
