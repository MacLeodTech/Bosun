//! Burp "save items" XML: each `<item>` holds the URL and the raw request (base64 or plain text). The recorded response (`<response>`) is kept. The parser never resolves entities: a DOCTYPE that declares any is refused, and so is any entity
//! reference other than the five predefined ones and numeric character references.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::{ImportError, MAX_BODY, Out};

const MAX_DEPTH: usize = 16;
/// One field's text, bytes (a request is at most its body limit plus headers).
const MAX_FIELD: usize = 2 * MAX_BODY;

#[derive(Default)]
struct Entry {
    url: String,
    request: Vec<u8>,
    request_b64: bool,
    response: Vec<u8>,
    response_b64: bool,
}

pub fn parse(input: &[u8], out: &mut Out) -> Result<(), ImportError> {
    let text = std::str::from_utf8(input).map_err(|_| ImportError::Syntax("not UTF-8 text".into()))?;
    let mut rd = Reader::from_str(text);
    let bad = |e: &dyn std::fmt::Display| ImportError::Syntax(format!("invalid XML: {e}"));
    let mut path: Vec<String> = Vec::new();
    let mut cur = Entry::default();
    let mut saw_item = false;
    loop {
        match rd.read_event().map_err(|e| bad(&e))? {
            Event::Eof => break,
            Event::DocType(d) => {
                let t = d.into_inner();
                if t.as_bytes().windows(6).any(|w| w.eq_ignore_ascii_case(b"ENTITY")) {
                    return Err(ImportError::Unsupported("XML entity declarations are refused".into()));
                }
            }
            Event::Start(e) => {
                if path.len() >= MAX_DEPTH {
                    return Err(ImportError::Unsupported("XML nested too deeply".into()));
                }
                let name = e.local_name().as_ref().to_string();
                if name == "item" {
                    cur = Entry::default();
                    saw_item = true;
                } else if name == "request" || name == "response" {
                    let b64 = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == "base64" && a.value.as_ref() == "true");
                    if name == "request" {
                        cur.request_b64 = b64;
                    } else {
                        cur.response_b64 = b64;
                    }
                }
                path.push(name);
            }
            Event::End(e) => {
                if e.local_name().as_ref() == "item" {
                    finish(&cur, out);
                    if out.full() {
                        out.dropped += 1; // more items may follow; the count is a lower bound
                        break;
                    }
                }
                path.pop();
            }
            Event::Text(t) => {
                add(&path, &mut cur, t.into_inner().as_bytes())?;
            }
            Event::CData(c) => add(&path, &mut cur, c.into_inner().as_bytes())?,
            Event::GeneralRef(r) => {
                let name = r.clone().into_inner();
                let ch = match name.as_ref() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => match r.resolve_char_ref().map_err(|e| bad(&e))? {
                        Some(c) => c,
                        None => return Err(ImportError::Unsupported(format!("XML entity &{name}; is refused"))),
                    },
                };
                let mut b = [0u8; 4];
                add(&path, &mut cur, ch.encode_utf8(&mut b).as_bytes())?;
            }
            _ => {}
        }
    }
    if !saw_item {
        return Err(ImportError::Unsupported("not a Burp items export (no <item>)".into()));
    }
    Ok(())
}

fn add(path: &[String], cur: &mut Entry, data: &[u8]) -> Result<(), ImportError> {
    let (Some(last), Some(parent)) = (path.last(), path.len().checked_sub(2).and_then(|i| path.get(i))) else {
        return Ok(());
    };
    if parent != "item" {
        return Ok(());
    }
    match last.as_str() {
        "url" => {
            if cur.url.len() + data.len() > 8192 {
                return Err(ImportError::Unsupported("a URL is too long".into()));
            }
            cur.url.push_str(&String::from_utf8_lossy(data));
        }
        "request" => {
            if cur.request.len() + data.len() > MAX_FIELD {
                return Err(ImportError::Unsupported("a request is too large".into()));
            }
            cur.request.extend_from_slice(data);
        }
        "response" => {
            if cur.response.len() + data.len() > MAX_FIELD {
                return Err(ImportError::Unsupported("a response is too large".into()));
            }
            cur.response.extend_from_slice(data);
        }
        _ => {}
    }
    Ok(())
}

fn finish(e: &Entry, out: &mut Out) {
    let url = e.url.trim();
    let raw = if e.request_b64 {
        let compact: Vec<u8> = e.request.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        match B64.decode(compact) {
            Ok(r) => r,
            Err(_) => return out.note(format!("{url}: the request is not valid base64")),
        }
    } else {
        e.request.clone()
    };
    let response = if e.response_b64 {
        let compact: Vec<u8> = e.response.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        B64.decode(compact).ok()
    } else {
        Some(e.response.clone())
    }
    .filter(|r| r.starts_with(b"HTTP/"));
    let (head, body) = split(&raw);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let method = lines
        .next()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("GET")
        .to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    out.push_with_response(&format!("{method} {url}"), &method, url, headers, body.to_vec(), response);
}

/// The head and the body of a raw request.
fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    for (sep, n) in [(&b"\r\n\r\n"[..], 4), (&b"\n\n"[..], 2)] {
        if let Some(i) = raw.windows(n).position(|w| w == sep) {
            return (&raw[..i], &raw[i + n..]);
        }
    }
    (raw, &[])
}
