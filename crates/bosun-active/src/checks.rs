//! The Rust active checks. Each one probes one insertion point (or, for [`Point::Whole`], one request) and reports
//! only what the answer proves.

use std::time::Duration;

use crate::{Answer, Confidence, Finding, Options, Point, Req, Severity, Shared, Strength};

pub const SQLI_ERROR: &str = "active-sqli-error";
pub const XSS_REFLECTED: &str = "active-xss-reflected";
pub const SQLI_BOOLEAN: &str = "active-sqli-boolean";
pub const SQLI_TIME: &str = "active-sqli-time";
pub const XSS_STORED: &str = "active-xss-stored";
pub const SSTI: &str = "active-ssti";
pub const CMD_INJECTION: &str = "active-cmd-injection";
pub const PATH_TRAVERSAL: &str = "active-path-traversal";
pub const OPEN_REDIRECT: &str = "active-open-redirect";
pub const CRLF_INJECTION: &str = "active-crlf-injection";
pub const CORS: &str = "active-cors";
pub const HOST_HEADER: &str = "active-host-header";
pub use crate::extra::{DESERIALIZATION, FILE_UPLOAD, GRAPHQL, JWT, PROTOTYPE_POLLUTION, SESSION, TLS, XXE};

/// How long an injected sleep lasts. The answer must take at least this long with the sleep and not with a sleep of
/// zero, twice.
const DELAY: Duration = Duration::from_secs(2);
const DELAY_SECS: u64 = 2;

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
    if *point == Point::Whole {
        if o.enabled(CORS) {
            cors(sh, req, point).await;
        }
        if o.enabled(HOST_HEADER) {
            host_header(sh, req, point).await;
        }
        crate::extra::whole(sh, req).await;
        return;
    }
    if o.enabled(SQLI_ERROR) {
        sqli_error(sh, req, point).await;
    }
    if o.enabled(XSS_REFLECTED) {
        xss_reflected(sh, req, point).await;
    }
    if o.enabled(SQLI_BOOLEAN) {
        sqli_boolean(sh, req, point).await;
    }
    if o.enabled(SQLI_TIME) {
        sqli_time(sh, req, point).await;
    }
    if o.enabled(XSS_STORED) {
        xss_stored(sh, req, point).await;
    }
    if o.enabled(SSTI) {
        ssti(sh, req, point).await;
    }
    if o.enabled(CMD_INJECTION) {
        cmd_injection(sh, req, point).await;
    }
    if o.enabled(PATH_TRAVERSAL) {
        path_traversal(sh, req, point).await;
    }
    if o.enabled(OPEN_REDIRECT) {
        open_redirect(sh, req, point).await;
    }
    if o.enabled(CRLF_INJECTION) {
        crlf_injection(sh, req, point).await;
    }
    if o.enabled(DESERIALIZATION) {
        crate::extra::deserialization(sh, req, point).await;
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
    if !is_html(&a) || !a.body.contains(&payload) {
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

pub(crate) fn is_html(a: &Answer) -> bool {
    a.content_type.is_empty() || a.content_type.contains("html")
}

/// The fields every finding of the checks below shares.
pub(crate) struct Hit<'a> {
    pub check: &'a str,
    pub title: &'a str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub payload: String,
    pub detail: String,
    pub remediation: &'a str,
    pub cwe: u32,
}

pub(crate) fn report(sh: &Shared, req: &Req, point: &Point, flow_id: i64, h: Hit<'_>) {
    sh.report(Finding {
        check: h.check.into(),
        title: h.title.into(),
        severity: h.severity,
        confidence: h.confidence,
        url: req.base_url(),
        point: req.label(point),
        payload: h.payload,
        detail: h.detail,
        remediation: h.remediation.into(),
        cwe: vec![h.cwe],
        flow_id,
    });
}

const SQLI_FIX: &str = "Use parameterised queries; never build SQL from request data.";
const CMD_FIX: &str =
    "Do not pass request data to a shell; call the program with an argument list and validate the value.";

/// Two numbers and their product, new for every probe, so the product cannot be on the page by chance.
fn sum(sh: &Shared) -> (u64, u64, u64) {
    let n = u64::from_str_radix(sh.marker().trim_start_matches("bsn"), 16).unwrap_or(7);
    let (a, b) = (1000 + n % 9000, 1000 + (n / 9000) % 9000);
    (a, b, a * b)
}

/// A page that answers an always-true condition like the original and an always-false one differently, and keeps
/// doing so with other constants, is evaluating the condition.
async fn sqli_boolean(sh: &Shared, req: &Req, point: &Point) {
    let orig = match req.value(point) {
        v if v.is_empty() => "1".to_string(),
        v => v,
    };
    let Some(base) = sh.send(req, req.bytes(Some((point, &orig)))).await else {
        return;
    };
    // Each: the suffixes for true, false, another true and another false.
    let mut variants: Vec<[&str; 4]> = vec![
        [" AND 1=1", " AND 1=2", " AND 2=2", " AND 2=3"],
        ["' AND '1'='1", "' AND '1'='2", "' AND '2'='2", "' AND '2'='3"],
    ];
    if sh.opts.strength != Strength::Low {
        variants.push([
            "\" AND \"1\"=\"1",
            "\" AND \"1\"=\"2",
            "\" AND \"2\"=\"2",
            "\" AND \"2\"=\"3",
        ]);
    }
    for v in variants {
        let [t, f, t2, f2] = v.map(|c| format!("{orig}{c}"));
        let Some(at) = sh.send(req, req.bytes(Some((point, &t)))).await else {
            return;
        };
        if at.status != base.status || at.body != base.body {
            continue;
        }
        let Some(af) = sh.send(req, req.bytes(Some((point, &f)))).await else {
            return;
        };
        if af.status == at.status && af.body == at.body {
            continue;
        }
        let Some(at2) = sh.send(req, req.bytes(Some((point, &t2)))).await else {
            return;
        };
        let Some(af2) = sh.send(req, req.bytes(Some((point, &f2)))).await else {
            return;
        };
        if at2.body == at.body && at2.status == at.status && af2.body == af.body && af2.status == af.status {
            report(
                sh,
                req,
                point,
                af.flow_id,
                Hit {
                    check: SQLI_BOOLEAN,
                    title: "SQL injection (boolean blind)",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "In {} the conditions `{}` and `{}` gave the original page (status {}), and `{}` and \
                         `{}` gave a different one (status {}), twice with different constants.",
                        req.label(point),
                        v[0].trim(),
                        v[2].trim(),
                        at.status,
                        v[1].trim(),
                        v[3].trim(),
                        af.status,
                    ),
                    payload: f,
                    remediation: SQLI_FIX,
                    cwe: 89,
                },
            );
            return;
        }
    }
}

/// The proof by time shared by the sleep checks: `slow` takes at least [`DELAY`], `fast` does not, and `slow` takes
/// it again. Outer `None`: the scan must stop; inner `None`: not proven.
async fn timed(sh: &Shared, req: &Req, point: &Point, slow: &str, fast: &str) -> Option<Option<Answer>> {
    let a = sh.send(req, req.bytes(Some((point, slow)))).await?;
    if a.elapsed < DELAY {
        return Some(None);
    }
    let c = sh.send(req, req.bytes(Some((point, fast)))).await?;
    if c.elapsed >= DELAY * 3 / 4 {
        return Some(None);
    }
    let a2 = sh.send(req, req.bytes(Some((point, slow)))).await?;
    Some((a2.elapsed >= DELAY).then_some(a))
}

/// A page too slow on its own proves nothing by time.
async fn is_quick(sh: &Shared, req: &Req, point: &Point, orig: &str) -> bool {
    match sh.send(req, req.bytes(Some((point, orig)))).await {
        Some(b) => b.elapsed < DELAY * 3 / 4,
        None => false,
    }
}

async fn sqli_time(sh: &Shared, req: &Req, point: &Point) {
    let orig = req.value(point);
    if !is_quick(sh, req, point, &orig).await {
        return;
    }
    let n = DELAY_SECS;
    let mut variants: Vec<(String, String)> = vec![
        (
            format!("{orig}' AND SLEEP({n})-- -"),
            format!("{orig}' AND SLEEP(0)-- -"),
        ),
        (
            format!("{orig} AND SLEEP({n})-- -"),
            format!("{orig} AND SLEEP(0)-- -"),
        ),
    ];
    if sh.opts.strength != Strength::Low {
        variants.push((
            format!("{orig}';SELECT pg_sleep({n})--"),
            format!("{orig}';SELECT pg_sleep(0)--"),
        ));
        variants.push((
            format!("{orig}';WAITFOR DELAY '0:0:{n}'--"),
            format!("{orig}';WAITFOR DELAY '0:0:0'--"),
        ));
    }
    for (slow, fast) in variants {
        let Some(r) = timed(sh, req, point, &slow, &fast).await else {
            return;
        };
        if let Some(a) = r {
            report(
                sh,
                req,
                point,
                a.flow_id,
                Hit {
                    check: SQLI_TIME,
                    title: "SQL injection (time based)",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "In {} an injected sleep of {n} seconds delayed the answer ({} ms) and a sleep of zero \
                         did not; the delay came again on a second try.",
                        req.label(point),
                        a.elapsed.as_millis()
                    ),
                    payload: slow,
                    remediation: SQLI_FIX,
                    cwe: 89,
                },
            );
            return;
        }
    }
}

/// A marker saved by one request and read back by a plain `GET` of the same page (or the site root), which carries
/// no payload: it can only be there because the application stored it. Destructive: it saves data.
async fn xss_stored(sh: &Shared, req: &Req, point: &Point) {
    let marker = sh.marker();
    let payload = format!("{marker}'\"<>");
    if sh.send(req, req.bytes(Some((point, &payload)))).await.is_none() {
        return;
    }
    let mut pages = vec![req.page(None)];
    let root = req.page(Some("/"));
    if root.base_url() != pages[0].base_url() {
        pages.push(root);
    }
    for page in pages {
        let Some(a) = sh.send(&page, page.bytes(None)).await else {
            return;
        };
        if is_html(&a) && a.body.contains(&payload) {
            report(
                sh,
                req,
                point,
                a.flow_id,
                Hit {
                    check: XSS_STORED,
                    title: "Stored cross-site scripting",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "A value sent in {} was saved and came back, with its quotes and angle brackets \
                         unescaped, when {} was read again without it.",
                        req.label(point),
                        page.base_url()
                    ),
                    payload,
                    remediation: "Encode stored data for the context it is written into when it is shown, and \
                                  send a Content-Security-Policy.",
                    cwe: 79,
                },
            );
            return;
        }
    }
}

/// Template syntax with arithmetic in it: the product coming back means the engine evaluated it.
async fn ssti(sh: &Shared, req: &Req, point: &Point) {
    let (a, b, p) = sum(sh);
    let mut payloads = vec![format!("{{{{{a}*{b}}}}}"), format!("${{{a}*{b}}}")];
    if sh.opts.strength != Strength::Low {
        payloads.push(format!("<%= {a}*{b} %>"));
        payloads.push(format!("#{{{a}*{b}}}"));
    }
    let product = p.to_string();
    for payload in payloads {
        let Some(r) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
            return;
        };
        if r.body.contains(&product) {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: SSTI,
                    title: "Server-side template injection",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "`{payload}` sent in {} came back as {product}: the application evaluates template \
                         syntax in the value.",
                        req.label(point)
                    ),
                    payload,
                    remediation: "Never build templates from request data; pass it to the template as a value.",
                    cwe: 1336,
                },
            );
            return;
        }
    }
}

/// An injected command that prints a computed number, or one that sleeps.
async fn cmd_injection(sh: &Shared, req: &Req, point: &Point) {
    let orig = req.value(point);
    let (a, b, p) = sum(sh);
    let product = p.to_string();
    let mut echoes = vec![
        format!("{orig};echo $(({a}*{b}))"),
        format!("{orig}|echo $(({a}*{b}))"),
    ];
    if sh.opts.strength != Strength::Low {
        echoes.push(format!("{orig}$(echo $(({a}*{b})))"));
        echoes.push(format!("{orig}&& echo $(({a}*{b}))"));
    }
    if sh.opts.strength == Strength::High {
        echoes.push(format!("{orig}&set /a {a}*{b}"));
    }
    for payload in echoes {
        let Some(r) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
            return;
        };
        if r.body.contains(&product) {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: CMD_INJECTION,
                    title: "OS command injection",
                    severity: Severity::High,
                    confidence: Confidence::Certain,
                    detail: format!(
                        "In {} the injected command `{}` printed {product}, a number the shell had to compute.",
                        req.label(point),
                        payload.trim_start_matches(&orig)
                    ),
                    payload,
                    remediation: CMD_FIX,
                    cwe: 78,
                },
            );
            return;
        }
    }
    if !is_quick(sh, req, point, &orig).await {
        return;
    }
    let n = DELAY_SECS;
    let mut variants = vec![(format!("{orig};sleep {n}"), format!("{orig};sleep 0"))];
    if sh.opts.strength != Strength::Low {
        variants.push((format!("{orig}|sleep {n}"), format!("{orig}|sleep 0")));
        variants.push((format!("{orig}$(sleep {n})"), format!("{orig}$(sleep 0)")));
    }
    for (slow, fast) in variants {
        let Some(r) = timed(sh, req, point, &slow, &fast).await else {
            return;
        };
        if let Some(a) = r {
            report(
                sh,
                req,
                point,
                a.flow_id,
                Hit {
                    check: CMD_INJECTION,
                    title: "OS command injection (time based)",
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "In {} an injected `sleep {n}` delayed the answer ({} ms) and `sleep 0` did not; the \
                         delay came again on a second try.",
                        req.label(point),
                        a.elapsed.as_millis()
                    ),
                    payload: slow,
                    remediation: CMD_FIX,
                    cwe: 78,
                },
            );
            return;
        }
    }
}

/// The start of a system file only a traversal could have made the application read.
pub(crate) fn file_signature(body: &str) -> Option<&'static str> {
    if body.contains("root:x:0:0:") || body.contains("root:*:0:0:") {
        Some("/etc/passwd")
    } else if body.contains("; for 16-bit app support")
        || (body.contains("[fonts]") && body.contains("[extensions]"))
    {
        Some("win.ini")
    } else {
        None
    }
}

async fn path_traversal(sh: &Shared, req: &Req, point: &Point) {
    let mut payloads = vec!["../../../../../../../../etc/passwd".to_string()];
    if sh.opts.strength != Strength::Low {
        payloads.push("/etc/passwd".into());
        payloads.push("....//....//....//....//....//....//etc/passwd".into());
        payloads.push("..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd".into());
        payloads.push("..\\..\\..\\..\\..\\..\\windows\\win.ini".into());
    }
    for payload in payloads {
        let Some(r) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
            return;
        };
        let Some(file) = file_signature(&r.body) else {
            continue;
        };
        // The unchanged request must not already show it.
        let Some(base) = sh.send(req, req.bytes(None)).await else {
            return;
        };
        if file_signature(&base.body).is_some() {
            return;
        }
        report(
            sh,
            req,
            point,
            r.flow_id,
            Hit {
                check: PATH_TRAVERSAL,
                title: "Path traversal",
                severity: Severity::High,
                confidence: Confidence::Certain,
                detail: format!(
                    "`{payload}` in {} made the application return {file}.",
                    req.label(point)
                ),
                payload,
                remediation: "Map names to files with an allow list, or resolve the path and check that it stays \
                              inside the intended directory.",
                cwe: 22,
            },
        );
        return;
    }
}

/// The host a `Location` value sends the browser to, if it names one (`https://h/`, `//h/`, `/\h`, `https:h`).
pub(crate) fn redirect_host(location: &str) -> Option<String> {
    let l = location.trim();
    let rest = l
        .strip_prefix("https:")
        .or_else(|| l.strip_prefix("http:"))
        .unwrap_or(l);
    let rest = rest.trim_start_matches(['/', '\\']);
    if rest.len() == l.len() {
        // No scheme and no leading slash: a relative reference.
        return None;
    }
    if rest.len() + 1 == l.len() && !l.starts_with("https:") && !l.starts_with("http:") {
        // One slash: a path on this host.
        return None;
    }
    let host: String = rest
        .chars()
        .take_while(|c| !matches!(c, '/' | '\\' | '?' | '#' | ':' | '@'))
        .collect();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

async fn open_redirect(sh: &Shared, req: &Req, point: &Point) {
    let host = format!("{}.invalid", sh.marker());
    let mut payloads = vec![format!("https://{host}/")];
    if sh.opts.strength != Strength::Low {
        payloads.push(format!("//{host}/"));
    }
    if sh.opts.strength == Strength::High {
        payloads.push(format!("/\\{host}"));
    }
    for payload in payloads {
        let Some(r) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
            return;
        };
        let to = header(&r, "location").and_then(redirect_host);
        if (300..400).contains(&r.status) && to.as_deref() == Some(host.as_str()) {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: OPEN_REDIRECT,
                    title: "Open redirect",
                    severity: Severity::Medium,
                    confidence: Confidence::Certain,
                    detail: format!(
                        "A host sent in {} came back as the Location of a {} response.",
                        req.label(point),
                        r.status
                    ),
                    payload,
                    remediation: "Redirect only to relative paths or to hosts on an allow list.",
                    cwe: 601,
                },
            );
            return;
        }
    }
}

/// A line break in the value starts a new header in the response, with a name only this probe could have chosen.
async fn crlf_injection(sh: &Shared, req: &Req, point: &Point) {
    // A cookie or request header value would put the line break into the request itself.
    if matches!(point, Point::Cookie(_) | Point::Header(_)) {
        return;
    }
    let orig = req.value(point);
    let name = format!("x-bosun-{}", sh.marker());
    let mut payloads = vec![format!("{orig}\r\n{name}: injected")];
    if sh.opts.strength != Strength::Low {
        payloads.push(format!("{orig}\n{name}: injected"));
    }
    for payload in payloads {
        let Some(r) = sh.send(req, req.bytes(Some((point, &payload)))).await else {
            return;
        };
        if header(&r, &name).is_some() {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: CRLF_INJECTION,
                    title: "CRLF injection (header injection)",
                    severity: Severity::Medium,
                    confidence: Confidence::Certain,
                    detail: format!(
                        "A line break in {} added the response header {name}.",
                        req.label(point)
                    ),
                    payload,
                    remediation: "Reject or strip CR and LF in any value written into a response header.",
                    cwe: 113,
                },
            );
            return;
        }
    }
}

pub(crate) fn header<'a>(a: &'a Answer, name: &str) -> Option<&'a str> {
    a.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// An origin of the scanner's choosing (and `null`) allowed together with credentials: any site can read the
/// answer as the signed-in user.
async fn cors(sh: &Shared, req: &Req, point: &Point) {
    let mut origins = vec![format!("https://{}.invalid", sh.marker())];
    if sh.opts.strength != Strength::Low {
        origins.push("null".to_string());
    }
    for origin in origins {
        let Some(r) = sh.send(req, req.bytes_with(None, &[("Origin", &origin)])).await else {
            return;
        };
        let allowed =
            header(&r, "access-control-allow-origin").is_some_and(|v| v.eq_ignore_ascii_case(&origin));
        let credentials =
            header(&r, "access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if allowed && credentials {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: CORS,
                    title: "CORS misconfiguration",
                    severity: Severity::Medium,
                    confidence: Confidence::Certain,
                    detail: format!(
                        "With `Origin: {origin}` the answer carries `Access-Control-Allow-Origin: {origin}` and \
                         `Access-Control-Allow-Credentials: true`: a page on any origin can read it with the \
                         user's cookies."
                    ),
                    payload: format!("Origin: {origin}"),
                    remediation: "Allow only an explicit list of origins; never reflect the request's Origin or \
                                  allow null with credentials.",
                    cwe: 942,
                },
            );
            return;
        }
    }
}

/// A `Host` or `X-Forwarded-Host` of the scanner's choosing used to build links or redirects (password reset
/// poisoning, cache poisoning). The marker must come back as a host: after `//` in the body or in `Location`.
async fn host_header(sh: &Shared, req: &Req, point: &Point) {
    let host = format!("{}.invalid", sh.marker());
    let mut probes: Vec<(String, Vec<u8>)> = vec![(
        format!("X-Forwarded-Host: {host}"),
        req.bytes_with(None, &[("X-Forwarded-Host", &host)]),
    )];
    if sh.opts.strength != Strength::Low {
        probes.push((format!("Host: {host}"), req.bytes_with(Some(&host), &[])));
    }
    let link = format!("//{host}");
    for (payload, raw) in probes {
        let Some(r) = sh.send(req, raw).await else { return };
        let in_location = header(&r, "location").is_some_and(|l| l.contains(&host));
        if in_location || r.body.contains(&link) {
            report(
                sh,
                req,
                point,
                r.flow_id,
                Hit {
                    check: HOST_HEADER,
                    title: "Host header attack",
                    severity: Severity::Medium,
                    confidence: Confidence::Firm,
                    detail: format!(
                        "The host from `{payload}` came back in {}: the application builds links from a header \
                         the client controls.",
                        if in_location {
                            "the Location header"
                        } else {
                            "a link in the page"
                        }
                    ),
                    payload,
                    remediation: "Build absolute URLs from a configured host name, and reject unknown Host values.",
                    cwe: 644,
                },
            );
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_hosts() {
        assert_eq!(redirect_host("https://a.invalid/x").as_deref(), Some("a.invalid"));
        assert_eq!(redirect_host("//A.invalid").as_deref(), Some("a.invalid"));
        assert_eq!(redirect_host("/\\a.invalid").as_deref(), Some("a.invalid"));
        assert_eq!(redirect_host("https:a.invalid").as_deref(), Some("a.invalid"));
        assert_eq!(redirect_host("http://u@a.invalid").as_deref(), Some("u"));
        assert_eq!(redirect_host("/home"), None);
        assert_eq!(redirect_host("home?x=//a.invalid"), None);
        assert_eq!(redirect_host(""), None);
        assert_eq!(redirect_host("///"), None);
    }

    #[test]
    fn file_signatures() {
        assert!(file_signature("root:x:0:0:root:/root:/bin/sh").is_some());
        assert!(file_signature("[fonts]\n[extensions]").is_some());
        assert!(file_signature("a page about root").is_none());
    }
}
