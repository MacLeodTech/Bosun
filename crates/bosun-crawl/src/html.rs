//! A forgiving scanner for the parts of an HTML page a spider needs: links, resources, forms and `<base>`.
//! It does not build a tree and never runs script; it only reads tags.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// `a`, `area`, `link`, a meta refresh or a frame: somewhere to go.
    Link,
    /// `script`, `img`, `iframe`, ... : something the page loads.
    Resource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub target: String,
    pub kind: LinkKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// The input type (`text`, `hidden`, `password`, ...), `textarea` or `select`.
    pub kind: String,
    /// Whether a browser would send it without the user touching it (checked boxes, hidden fields, text).
    pub submitted: bool,
}

/// A form as written: `action` is not resolved yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawForm {
    pub action: String,
    pub method: String,
    pub enctype: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default)]
pub struct Doc {
    pub title: Option<String>,
    pub base: Option<String>,
    pub links: Vec<Link>,
    pub forms: Vec<RawForm>,
}

/// Scan `html`. Never fails: whatever cannot be read is skipped.
pub fn scan(html: &str) -> Doc {
    let mut doc = Doc::default();
    let b = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let mut form: Option<RawForm> = None;
    let mut select: Option<usize> = None;
    while let Some(off) = html[i..].find('<') {
        i += off;
        let rest = &html[i..];
        if rest.starts_with("<!--") {
            i = html[i + 4..].find("-->").map_or(b.len(), |e| i + 4 + e + 3);
            continue;
        }
        let next = b.get(i + 1).copied().unwrap_or(0);
        if next == b'!' || next == b'?' {
            i = html[i..].find('>').map_or(b.len(), |e| i + e + 1);
            continue;
        }
        let closing = next == b'/';
        let name_start = i + 1 + usize::from(closing);
        let name_end = (name_start..b.len())
            .find(|&k| !b[k].is_ascii_alphanumeric())
            .unwrap_or(b.len());
        if name_end == name_start {
            i += 1;
            continue;
        }
        let name = lower[name_start..name_end].to_string();
        let (attrs, end) = if closing {
            (
                Vec::new(),
                html[name_end..].find('>').map_or(b.len(), |e| name_end + e + 1),
            )
        } else {
            attributes(html, name_end)
        };
        i = end;
        if closing {
            match name.as_str() {
                "form" => doc.forms.extend(form.take()),
                "select" => select = None,
                _ => {}
            }
            continue;
        }
        let attr = |n: &str| attrs.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        let link = |doc: &mut Doc, t: Option<&str>, kind| {
            if let Some(t) = t.map(str::trim).filter(|t| !t.is_empty()) {
                doc.links.push(Link {
                    target: t.to_string(),
                    kind,
                });
            }
        };
        match name.as_str() {
            "a" | "area" | "link" => link(&mut doc, attr("href"), LinkKind::Link),
            "iframe" | "frame" => link(&mut doc, attr("src"), LinkKind::Link),
            "script" | "img" | "embed" | "source" | "audio" | "video" | "track" => {
                link(&mut doc, attr("src"), LinkKind::Resource)
            }
            "object" => link(&mut doc, attr("data"), LinkKind::Resource),
            "base" => {
                if doc.base.is_none() {
                    doc.base = attr("href").map(str::to_string);
                }
            }
            "meta" => {
                if attr("http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
                    && let Some(c) = attr("content")
                    && let Some(p) = c.to_ascii_lowercase().find("url=")
                {
                    let u = c[p + 4..].trim().trim_matches(['\'', '"']);
                    link(&mut doc, Some(u), LinkKind::Link);
                }
            }
            "form" => {
                doc.forms.extend(form.take());
                form = Some(RawForm {
                    action: attr("action").unwrap_or("").to_string(),
                    method: attr("method").unwrap_or("get").to_ascii_uppercase(),
                    enctype: attr("enctype")
                        .unwrap_or("application/x-www-form-urlencoded")
                        .to_string(),
                    fields: Vec::new(),
                });
            }
            "input" | "textarea" | "select" | "button" => {
                if name == "input" {
                    link(
                        &mut doc,
                        attr("src").filter(|_| attr("type") == Some("image")),
                        LinkKind::Resource,
                    );
                }
                if let (Some(f), Some(n)) = (form.as_mut(), attr("name").filter(|n| !n.is_empty())) {
                    let kind = match name.as_str() {
                        "input" => attr("type").unwrap_or("text").to_ascii_lowercase(),
                        "button" => "submit".to_string(),
                        other => other.to_string(),
                    };
                    let submitted = match kind.as_str() {
                        "submit" | "button" | "image" | "reset" | "file" => false,
                        "checkbox" | "radio" => attr("checked").is_some(),
                        _ => true,
                    };
                    f.fields.push(Field {
                        name: n.to_string(),
                        value: attr("value").unwrap_or("").to_string(),
                        kind,
                        submitted,
                    });
                    if name == "select" {
                        select = Some(f.fields.len() - 1);
                    }
                }
            }
            "option" => {
                if let (Some(f), Some(k)) = (form.as_mut(), select)
                    && f.fields[k].value.is_empty()
                    && let Some(v) = attr("value")
                {
                    f.fields[k].value = v.to_string();
                }
            }
            "title" if doc.title.is_none() => {
                let stop = lower[i..].find('<').map_or(b.len(), |e| i + e);
                doc.title = Some(entities(html[i..stop].trim()));
            }
            _ => {}
        }
        // Raw-text elements: their content is not markup.
        if matches!(name.as_str(), "script" | "style" | "textarea") {
            let close = format!("</{name}");
            i = lower[i..].find(&close).map_or(b.len(), |e| i + e);
        }
    }
    doc.forms.extend(form.take());
    doc
}

/// Attributes of the tag whose name ends at `from`, and the index after its `>`.
fn attributes(html: &str, from: usize) -> (Vec<(String, String)>, usize) {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = from;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return (out, b.len());
        }
        if b[i] == b'>' {
            return (out, i + 1);
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let name = html[start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i] as char;
                let s = i + 1;
                let e = html[s..].find(q).map_or(b.len(), |e| s + e);
                value = entities(&html[s..e]);
                i = (e + 1).min(b.len());
            } else {
                let s = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = entities(&html[s..i]);
            }
        }
        if !name.is_empty() {
            out.push((name, value));
        } else if i == start {
            i += 1;
        }
    }
}

/// Decode the character references that turn up in URLs and values.
pub fn entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let decoded = rest.find(';').filter(|&e| e <= 10).and_then(|e| {
            let ent = &rest[1..e];
            let c = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent.strip_prefix('#').and_then(|n| {
                    let code = match n.strip_prefix(['x', 'X']) {
                        Some(h) => u32::from_str_radix(h, 16).ok()?,
                        None => n.parse().ok()?,
                    };
                    char::from_u32(code)
                }),
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, n)) => {
                out.push(c);
                rest = &rest[n..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The `<loc>` values of a sitemap, and whether it is an index of other sitemaps.
pub fn sitemap_locs(xml: &str) -> (Vec<String>, bool) {
    let lower = xml.to_ascii_lowercase();
    let index = lower.contains("<sitemapindex");
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(s) = lower[i..].find("<loc>") {
        let s = i + s + 5;
        let Some(e) = lower[s..].find("</loc>") else { break };
        let v = xml[s..s + e].trim();
        let v = v
            .strip_prefix("<![CDATA[")
            .and_then(|v| v.strip_suffix("]]>"))
            .unwrap_or(v);
        out.push(entities(v.trim()));
        i = s + e + 6;
    }
    (out, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_links_resources_base_and_title() {
        let d = scan(
            "<html><head><title>Hi &amp; bye</title><base href=\"/x/\"><link rel=stylesheet href=s.css>\
             <meta http-equiv=\"Refresh\" content=\"0; url='/r'\"><script src=a.js>var u='<a href=no>';</script></head>\
             <!-- <a href=\"hidden\"> --><body><a href=\"/one\">1</a><A HREF='two?a=1&amp;b=2'>2</A><img src=i.png>\
             <iframe src=/f></iframe></body></html>",
        );
        let t = |k| {
            d.links
                .iter()
                .filter(|l| l.kind == k)
                .map(|l| l.target.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(d.title.as_deref(), Some("Hi & bye"));
        assert_eq!(d.base.as_deref(), Some("/x/"));
        assert_eq!(t(LinkKind::Link), ["s.css", "/r", "/one", "two?a=1&b=2", "/f"]);
        assert_eq!(t(LinkKind::Resource), ["a.js", "i.png"]);
    }

    #[test]
    fn reads_forms() {
        let d = scan(
            "<form action=/s method=post><input name=q value=x><input type=hidden name=h value=1>\
             <input type=checkbox name=c><input type=checkbox name=d checked><textarea name=t>ignored</textarea>\
             <select name=s><option value=a><option value=b></select><input type=submit name=go value=Go></form>\
             <form><input name=z></form>",
        );
        assert_eq!(d.forms.len(), 2);
        let f = &d.forms[0];
        assert_eq!((f.action.as_str(), f.method.as_str()), ("/s", "POST"));
        let sent: Vec<_> = f
            .fields
            .iter()
            .filter(|f| f.submitted)
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(sent, [("q", "x"), ("h", "1"), ("d", ""), ("t", ""), ("s", "a")]);
        assert_eq!(d.forms[1].method, "GET");
    }

    #[test]
    fn survives_garbage() {
        for s in [
            "<",
            "<a",
            "<a href",
            "<a href=\"x",
            "<!--",
            "<form><input name",
            "<<<>>>",
            "&#xzz; &",
        ] {
            let _ = scan(s);
        }
    }

    #[test]
    fn sitemaps() {
        let (v, idx) = sitemap_locs(
            "<urlset><url><loc> http://h/a?x=1&amp;y=2 </loc></url><url><loc>http://h/b</loc></url></urlset>",
        );
        assert_eq!(v, ["http://h/a?x=1&y=2", "http://h/b"]);
        assert!(!idx);
        assert!(sitemap_locs("<sitemapindex><sitemap><loc>http://h/s.xml</loc></sitemap></sitemapindex>").1);
    }
}
