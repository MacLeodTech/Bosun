//! A header scanner that keeps byte offsets, so findings can point at the exact line in the stored message.
//! (`bosun_model::raw` normalises line endings, which moves offsets.)

const MAX_HEADERS: usize = 256;

#[derive(Debug)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
    /// Offsets of the whole line in the message, without its line ending.
    pub start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub struct Head<'a> {
    pub headers: Vec<Header<'a>>,
    /// Where the body starts (the message length when there is no blank line).
    pub body: usize,
}

impl<'a> Head<'a> {
    pub fn parse(raw: &'a [u8]) -> Self {
        let mut headers = Vec::new();
        let mut pos = 0;
        let mut first = true;
        let mut body = raw.len();
        while pos < raw.len() {
            let nl = raw[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(raw.len(), |i| pos + i);
            let mut end = nl;
            if end > pos && raw[end - 1] == b'\r' {
                end -= 1;
            }
            let next = (nl + 1).min(raw.len());
            if !first && end == pos {
                body = next;
                break;
            }
            if !first
                && !matches!(raw[pos], b' ' | b'\t')
                && headers.len() < MAX_HEADERS
                && let Ok(line) = std::str::from_utf8(&raw[pos..end])
                && let Some((n, v)) = line.split_once(':')
            {
                headers.push(Header {
                    name: n.trim(),
                    value: v.trim(),
                    start: pos,
                    end,
                });
            }
            first = false;
            pos = next;
        }
        Self { headers, body }
    }

    pub fn get(&self, name: &str) -> Option<&Header<'a>> {
        self.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name))
    }

    pub fn all<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Header<'a>> {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_point_at_header_lines() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\nX: y\r\n\r\nbody";
        let h = Head::parse(raw);
        let s = h.get("server").unwrap();
        assert_eq!(&raw[s.start..s.end], b"Server: nginx/1.2");
        assert_eq!(s.value, "nginx/1.2");
        assert_eq!(&raw[h.body..], b"body");
    }

    #[test]
    fn bare_newlines_and_missing_blank_line() {
        let h = Head::parse(b"GET / HTTP/1.1\nA: b\n\nrest");
        assert_eq!(h.get("a").unwrap().value, "b");
        assert_eq!(h.body, 21);
        let h = Head::parse(b"GET / HTTP/1.1\r\nA: b\r\n");
        assert_eq!(h.body, 22);
    }
}
