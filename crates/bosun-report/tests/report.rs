//! Golden-file tests for each format (`BLESS=1 cargo test -p bosun-report` rewrites them), SARIF schema validation,
//! redaction and escaping.

#![allow(clippy::unwrap_used)]
use bosun_report::{
    Confidence, Evidence, Format, Issue, Options, Severity, Status, html_csp, redact, render,
};

fn fixture() -> Vec<Issue> {
    vec![
        Issue {
            id: 2,
            issue_type: "cookie-no-httponly".into(),
            title: "Session cookie without HttpOnly".into(),
            severity: Severity::Low,
            confidence: Confidence::Certain,
            status: Status::Confirmed,
            method: "GET".into(),
            url: "https://app.example/login?next=/home&token=abc123secret".into(),
            description: "The session cookie can be read by script.".into(),
            remediation: "Set the HttpOnly attribute.".into(),
            cwe: vec![1004],
            owasp: vec!["A05:2021".into()],
            evidence: vec![Evidence {
                part: "response".into(),
                excerpt: "HTTP/1.1 200 OK\nSet-Cookie: sid=deadbeefcafe; Path=/\nContent-Type: text/html"
                    .into(),
            }],
        },
        Issue {
            id: 1,
            issue_type: "missing-csp".into(),
            title: "No Content-Security-Policy".into(),
            severity: Severity::Medium,
            confidence: Confidence::Firm,
            status: Status::New,
            method: "GET".into(),
            url: "https://app.example/".into(),
            description: String::new(),
            remediation: "Send a Content-Security-Policy header.".into(),
            cwe: vec![693],
            owasp: vec![],
            evidence: vec![],
        },
        Issue {
            id: 3,
            issue_type: "server-banner".into(),
            title: "Server version disclosed".into(),
            severity: Severity::Info,
            confidence: Confidence::Tentative,
            status: Status::FalsePositive,
            method: "GET".into(),
            url: "https://app.example/status".into(),
            description: String::new(),
            remediation: String::new(),
            cwe: vec![200],
            owasp: vec![],
            evidence: vec![],
        },
    ]
}

fn hostile() -> Vec<Issue> {
    vec![Issue {
        id: 9,
        issue_type: "reflected".into(),
        title: "<script>alert(1)</script> \"quoted\" & `tick` [x](javascript:alert(1))".into(),
        severity: Severity::High,
        confidence: Confidence::Firm,
        status: Status::New,
        method: "GET".into(),
        url: "https://t.example/?q=<img src=x onerror=alert(1)>".into(),
        description: "<svg onload=alert(1)> **bold**".into(),
        remediation: "</style><script>alert(2)</script>".into(),
        cwe: vec![79],
        owasp: vec![],
        evidence: vec![Evidence {
            part: "response".into(),
            excerpt: "</pre><script>alert(3)</script>\n```\n# heading\u{1}\u{FFFF}".into(),
        }],
    }]
}

fn golden(name: &str, got: &str) {
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&path, got).unwrap();
        return;
    }
    let want =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {path}; run with BLESS=1"));
    assert_eq!(
        got, want,
        "golden {name} differs; run with BLESS=1 if the change is intended"
    );
}

#[test]
fn golden_files() {
    for f in [
        Format::Html,
        Format::Json,
        Format::Sarif,
        Format::Junit,
        Format::Markdown,
    ] {
        golden(
            &format!("report.{}", f.extension()),
            &render(&fixture(), f, Options::default()),
        );
    }
}

#[test]
fn sarif_validates_against_the_schema() {
    let schema: serde_json::Value = serde_json::from_str(include_str!("sarif-schema-2.1.0.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for issues in [fixture(), hostile(), vec![]] {
        let doc: serde_json::Value =
            serde_json::from_str(&render(&issues, Format::Sarif, Options::default())).unwrap();
        let errors: Vec<String> = validator.iter_errors(&doc).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{errors:?}");
    }
}

#[test]
fn secrets_are_redacted_by_default_and_kept_when_asked() {
    let issues = fixture();
    for f in [
        Format::Html,
        Format::Json,
        Format::Sarif,
        Format::Junit,
        Format::Markdown,
    ] {
        let out = render(&issues, f, Options::default());
        assert!(!out.contains("abc123secret"), "{f:?} leaks the URL token");
        assert!(!out.contains("deadbeefcafe"), "{f:?} leaks the cookie");
        assert!(
            out.contains("[redacted]")
                || out.contains("&#91;redacted&#93;")
                || out.contains("\\[redacted\\]")
        );
    }
    let raw = render(&issues, Format::Json, Options { redact: false });
    assert!(raw.contains("abc123secret") && raw.contains("deadbeefcafe"));
}

#[test]
fn redact_patterns() {
    assert!(!redact("Authorization: Bearer abcdefghijkl").contains("abcdefghijkl"));
    assert!(!redact("Cookie: a=b; c=d").contains("c=d"));
    assert!(!redact("curl https://user:hunter2@host/").contains("hunter2"));
    assert!(!redact("{\"password\": \"hunter2\"}").contains("hunter2"));
    assert!(!redact("id=eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSM").contains("SflKxwRJSM"));
    assert_eq!(redact("name=alice&page=2"), "name=alice&page=2");
    assert_eq!(redact(&redact("password=x")), redact("password=x"));
}

#[test]
fn html_report_carries_no_markup_from_the_target() {
    let out = render(&hostile(), Format::Html, Options::default());
    // The only script-like and tag-like text is escaped; the document has no script element, handler or link.
    for bad in [
        "<script", "<img", "<svg", "</pre><", "<a ", "<iframe", "<link", "<style><",
    ] {
        assert!(!out.contains(bad), "html contains {bad:?}");
    }
    assert!(out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    let csp = html_csp();
    assert!(out.contains("http-equiv=\"Content-Security-Policy\""));
    assert!(
        csp.contains("default-src 'none'") && !csp.contains("script-src") && !csp.contains("unsafe-inline")
    );
    assert!(csp.contains("style-src 'sha256-"));
}

#[test]
fn markdown_and_junit_neutralise_hostile_text() {
    let mut no_evidence = hostile();
    no_evidence[0].evidence.clear();
    // Outside a code fence no raw tag survives (inside one, Markdown renderers show text as it is).
    assert!(!render(&no_evidence, Format::Markdown, Options::default()).contains("<script"));
    let md = render(&hostile(), Format::Markdown, Options::default());
    assert!(!md.contains("[x](javascript"), "link syntax survives");
    // The evidence fence is longer than the backtick run inside it.
    assert!(md.contains("````\n</pre>"));
    let xml = render(&hostile(), Format::Junit, Options::default());
    assert!(!xml.contains("<script") && !xml.contains('\u{1}') && !xml.contains('\u{FFFF}'));
}

#[test]
fn format_names() {
    assert_eq!(Format::parse("MD").unwrap(), Format::Markdown);
    assert_eq!(Format::parse("junit").unwrap(), Format::Junit);
    assert!(Format::parse("pdf").is_err());
}
