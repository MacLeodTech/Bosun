//! The Rust active checks. Each one probes one insertion point and reports only what the answer proves.

use crate::{Confidence, Finding, Options, Point, Req, Severity, Shared, Strength};

pub const SQLI_ERROR: &str = "active-sqli-error";
pub const XSS_REFLECTED: &str = "active-xss-reflected";

/// Database error text that has no business in a page.
const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ora-00933",
    "ora-01756",
    "pg_query()",
    "syntax error at or near",
    "unterminated quoted string at or near",
    "sqlite3::",
    "sqlite_error",
    "sqlstate[",
];

fn sql_error(body: &str) -> Option<&'static str> {
    let low = body.to_ascii_lowercase();
    SQL_ERRORS.iter().copied().find(|e| low.contains(e))
}

pub(crate) async fn run(sh: &Shared, req: &Req, point: &Point) {
    let o: &Options = &sh.opts;
    if o.enabled(SQLI_ERROR) {
        sqli_error(sh, req, point).await;
    }
    if o.enabled(XSS_REFLECTED) {
        xss_reflected(sh, req, point).await;
    }
}

/// A quote breaks the query and a doubled quote does not: the database error is a response to the quote, not
/// static text. Without the second request the finding would only be tentative, so it is always sent.
async fn sqli_error(sh: &Shared, req: &Req, point: &Point) {
    let orig = req.value(point);
    let quotes: &[&str] = if sh.opts.strength == Strength::Low {
        &["'"]
    } else {
        &["'", "\""]
    };
    for q in quotes {
        let probe = format!("{orig}{q}");
        let Some(a) = sh.send(req, req.bytes(Some((point, &probe)))).await else {
            return;
        };
        let Some(err) = sql_error(&a.body) else { continue };
        let control = format!("{orig}{q}{q}");
        let Some(c) = sh.send(req, req.bytes(Some((point, &control)))).await else {
            return;
        };
        if sql_error(&c.body).is_some() {
            // The page says so either way.
            continue;
        }
        sh.report(Finding {
            check: SQLI_ERROR.into(),
            title: "SQL injection (error based)".into(),
            severity: Severity::High,
            confidence: Confidence::Certain,
            url: req.base_url(),
            point: req.label(point),
            payload: probe,
            detail: format!(
                "A single {q} in {} made the application answer a database error (\"{err}\", status {}), \
                 and a doubled {q} did not.",
                req.label(point),
                a.status
            ),
            remediation: "Use parameterised queries; never build SQL from request data.".into(),
            cwe: vec![89],
            flow_id: a.flow_id,
        });
        return;
    }
}

/// A marker with the characters HTML needs escaped comes back untouched in an HTML page.
async fn xss_reflected(sh: &Shared, req: &Req, point: &Point) {
    let marker = sh.marker();
    let payload = format!("{marker}'\"<>");
    let Some(a) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
        return;
    };
    let html = a.content_type.is_empty() || a.content_type.contains("html");
    if !html || !a.body.contains(&payload) {
        return;
    }
    sh.report(Finding {
        check: XSS_REFLECTED.into(),
        title: "Reflected cross-site scripting".into(),
        severity: Severity::Medium,
        confidence: Confidence::Firm,
        url: req.base_url(),
        point: req.label(point),
        payload,
        detail: format!(
            "A value sent in {} comes back in an HTML page with its quotes and angle brackets unescaped.",
            req.label(point)
        ),
        remediation:
            "Encode untrusted data for the context it is written into, and send a Content-Security-Policy."
                .into(),
        cwe: vec![79],
        flow_id: a.flow_id,
    });
}
