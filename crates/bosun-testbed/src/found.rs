//! Planted content for discovery (WP-81): hidden paths, a directory that redirects, an area that answers 200 to
//! everything ("soft 404") with a few real pages, and a page with a hidden parameter.

use super::{Reply, Rq, html};

pub fn route(rq: &Rq<'_>) -> Option<Reply> {
    let (path, query) = rq.target.split_once('?').unwrap_or((rq.target, ""));
    if rq.method != "GET" {
        return None;
    }
    match path {
        "/admin" => Some(Reply::new(301, "text/html", "").header("Location: /admin/")),
        "/admin/" => Some(html("Admin console")),
        "/admin/config" => Some(html("settings: debug=false")),
        "/admin/backup.sql" => Some(Reply::new(403, "text/html", "forbidden")),
        "/.git/HEAD" => Some(Reply::new(200, "text/plain", "ref: refs/heads/main\n")),
        "/backup.zip" => Some(Reply::new(200, "application/zip", "PK\u{3}\u{4}planted")),
        // A directory that answers every name with a 200 page that says it is missing.
        "/ghost" => Some(Reply::new(301, "text/html", "").header("Location: /ghost/")),
        "/ghost/real" => Some(html("A real page with its own content.")),
        p if p.starts_with("/ghost/") => Some(html(&format!(
            "Sorry, nothing lives at {} on this site. Try the home page.",
            super::escape(p)
        ))),
        // A page that reads a parameter nothing links to.
        "/tool" => {
            let debug = query.split('&').any(|kv| kv.split('=').next() == Some("debug"));
            Some(html(if debug {
                "Tool v1.2 (debug on): config at /etc/tool.conf, 14 workers, queue depth 3, last error: none"
            } else {
                "Tool v1.2"
            }))
        }
        _ => None,
    }
}
