//! The history query language (WP-75): one line of text such as
//! `host:example.com method:GET,POST status:4xx -ext:png,css (login or "sign in") header:x-api-key size:>10k`.
//!
//! The grammar is documented in `docs/query-language.md`. In short, terms are joined by an implicit `and`;
//! `or` and parentheses group; `-` or `not` in front of a term or group negates it; anything that is not
//! `key:value` is free text.
//!
//! [`parse`] is total: any string gives a result, and a malformed term becomes an error message and is left
//! out, never a panic. [`compile`] turns the tree into an SQL condition with bound parameters only: no part of
//! the query is ever pasted into the SQL text.

use std::fmt::Write as _;

use bosun_model::FlowSource;
use serde::{Deserialize, Serialize};

/// Longest query accepted; the rest is ignored (and reported).
pub const MAX_QUERY: usize = 2000;
/// Most terms in one query.
pub const MAX_TERMS: usize = 64;
/// Deepest nesting of parentheses.
pub const MAX_DEPTH: usize = 8;

/// An inclusive range; either end may be open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Range {
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// A point in time: some time before now, or a calendar date (UTC midnight), both in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum When {
    /// This long before now.
    Ago(i64),
    /// Unix time in milliseconds.
    At(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Has {
    Note,
    Error,
    Edited,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Term {
    /// Free text: request line, headers and text bodies (needs three or more characters; shorter text is
    /// looked for in the host and path).
    Text(String),
    /// Host contains any of these (lower case).
    Host(Vec<String>),
    /// Method is one of these (upper case).
    Method(Vec<String>),
    /// Status is in any of these ranges.
    Status(Vec<Range>),
    /// In scope, or not.
    Scope(bool),
    /// Path ends in one of these extensions (lower case, letters and digits).
    Ext(Vec<String>),
    Source(FlowSource),
    /// A header, optionally with a value: `Name:` or `Name: value` appears in the request or the response.
    Header {
        name: String,
        value: Option<String>,
    },
    Tag(String),
    Mime(String),
    Path(String),
    Note(String),
    Port(u16),
    Https(bool),
    /// Response size in bytes.
    Size(Range),
    /// Started at or after this time (`since:`), or at or before it (`until:`).
    Since(When),
    Until(When),
    Has(Has),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Term(Term),
}

/// A recognised term, for showing as a chip: where it is in the query and what it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TermSpan {
    /// `host`, `method`, `status`, `text`, ...
    pub key: String,
    /// The term as written, including a leading `-`.
    pub label: String,
    /// Byte offsets into the query.
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueryError {
    pub message: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// `None` for an empty query (or one with nothing valid in it).
    pub expr: Option<Expr>,
    pub terms: Vec<TermSpan>,
    pub errors: Vec<QueryError>,
}

// ---- tokens ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Open,
    Close,
    /// A word with its quotes removed. `bare` is true when nothing in it was quoted.
    Word {
        text: String,
        bare: bool,
    },
}

#[derive(Debug, Clone)]
struct Spanned {
    tok: Tok,
    start: usize,
    end: usize,
}

fn tokenize(q: &str) -> Vec<Spanned> {
    let mut out = Vec::new();
    let mut it = q.char_indices().peekable();
    while let Some(&(start, c)) = it.peek() {
        if c.is_whitespace() {
            it.next();
        } else if c == '(' {
            it.next();
            out.push(Spanned {
                tok: Tok::Open,
                start,
                end: start + 1,
            });
        } else if c == ')' {
            it.next();
            out.push(Spanned {
                tok: Tok::Close,
                start,
                end: start + 1,
            });
        } else {
            let mut text = String::new();
            let mut quoted = false;
            let mut bare = true;
            let mut end = start;
            while let Some(&(i, c)) = it.peek() {
                if !quoted && (c.is_whitespace() || c == ')' || (c == '(' && text == "-")) {
                    break;
                }
                it.next();
                end = i + c.len_utf8();
                if c == '"' {
                    quoted = !quoted;
                    bare = false;
                } else if c != '\0' {
                    // NUL is dropped: SQLite would cut a bound string there, and a half phrase is a syntax error.
                    text.push(c);
                }
            }
            out.push(Spanned {
                tok: Tok::Word { text, bare },
                start,
                end,
            });
        }
    }
    out
}

// ---- parser ---------------------------------------------------------------------------------------------

struct P<'a> {
    q: &'a str,
    toks: Vec<Spanned>,
    i: usize,
    terms: Vec<TermSpan>,
    errors: Vec<QueryError>,
    count: usize,
}

impl P<'_> {
    fn err(&mut self, message: impl Into<String>, start: usize, end: usize) {
        if self.errors.len() < 20 {
            self.errors.push(QueryError {
                message: message.into(),
                start,
                end,
            });
        }
    }

    fn peek(&self) -> Option<&Spanned> {
        self.toks.get(self.i)
    }

    fn keyword(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Spanned { tok: Tok::Word { text, bare: true }, .. }) if text.eq_ignore_ascii_case(w))
    }

    fn or(&mut self, depth: usize) -> Option<Expr> {
        let mut parts = Vec::new();
        parts.extend(self.and(depth));
        while self.keyword("or") {
            let s = self.toks[self.i].clone();
            self.i += 1;
            match self.and(depth) {
                Some(e) => parts.push(e),
                None => self.err("or: nothing to combine on one side", s.start, s.end),
            }
        }
        match parts.len() {
            0 => None,
            1 => parts.pop(),
            _ => Some(Expr::Or(parts)),
        }
    }

    fn and(&mut self, depth: usize) -> Option<Expr> {
        let mut parts = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(Spanned { tok: Tok::Close, .. }) => break,
                _ if self.keyword("or") => break,
                _ if self.keyword("and") => {
                    self.i += 1;
                }
                _ => parts.extend(self.unary(depth)),
            }
            if self.errors.len() >= 20 {
                self.i = self.toks.len();
            }
        }
        match parts.len() {
            0 => None,
            1 => parts.pop(),
            _ => Some(Expr::And(parts)),
        }
    }

    fn unary(&mut self, depth: usize) -> Option<Expr> {
        let first = self.toks[self.i].clone();
        // `not` or `-` in front of a term or group.
        let mut neg = false;
        let mut start = first.start;
        if self.keyword("not") {
            neg = true;
            self.i += 1;
            match self.peek() {
                Some(t) if t.tok != Tok::Close => start = first.start,
                _ => {
                    self.err("not: needs a term after it", first.start, first.end);
                    return None;
                }
            }
        }
        let t = self.toks[self.i].clone();
        match &t.tok {
            Tok::Open => self.group(depth, neg, start),
            Tok::Close => None,
            Tok::Word { text, bare } => {
                // `-(`: the minus is its own word.
                if *bare
                    && text == "-"
                    && matches!(self.toks.get(self.i + 1), Some(n) if n.tok == Tok::Open && n.start == t.end)
                {
                    self.i += 1;
                    return self.group(depth, !neg, start);
                }
                self.i += 1;
                let e = self.term(text, *bare, t.start, t.end)?;
                Some(if neg { Expr::Not(Box::new(e)) } else { e })
            }
        }
    }

    fn group(&mut self, depth: usize, neg: bool, start: usize) -> Option<Expr> {
        let open = self.toks[self.i].clone();
        self.i += 1;
        if depth + 1 > MAX_DEPTH {
            self.err(
                format!("too many nested groups (at most {MAX_DEPTH})"),
                open.start,
                open.end,
            );
            // Skip to the matching close so the rest still parses.
            let mut n = 1;
            while let Some(t) = self.toks.get(self.i) {
                self.i += 1;
                match t.tok {
                    Tok::Open => n += 1,
                    Tok::Close => {
                        n -= 1;
                        if n == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            return None;
        }
        let inner = self.or(depth + 1);
        match self.peek() {
            Some(Spanned {
                tok: Tok::Close, end, ..
            }) => {
                let end = *end;
                self.i += 1;
                let _ = (start, end);
            }
            _ => self.err("this ( is never closed", open.start, open.end),
        }
        inner.map(|e| if neg { Expr::Not(Box::new(e)) } else { e })
    }

    /// One word: `key:value` or free text. Records a chip when it is valid.
    fn term(&mut self, text: &str, bare: bool, start: usize, end: usize) -> Option<Expr> {
        let label = self.q[start..end].to_string();
        let split = if bare {
            text.split_once(':')
                .filter(|(k, _)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphabetic()))
        } else {
            None
        };
        // A leading `-` on the word itself (`-ext:png`, `-login`).
        let (word_neg, text, split) = match (bare, text.strip_prefix('-')) {
            (true, Some(rest)) if !rest.is_empty() => (
                true,
                rest,
                rest.split_once(':')
                    .filter(|(k, _)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphabetic())),
            ),
            _ => (false, text, split),
        };
        if self.count >= MAX_TERMS {
            self.err(format!("too many terms (at most {MAX_TERMS})"), start, end);
            return None;
        }
        let parsed = match split {
            Some((k, v)) => match key_of(k) {
                Some(key) => self.keyed(key, v, &label, start, end),
                None => Some(("text", Term::Text(text.to_string()))),
            },
            None => Some(("text", Term::Text(text.to_string()))),
        };
        let (key, term) = parsed?;
        if let Term::Text(t) = &term
            && t.is_empty()
        {
            return None;
        }
        self.count += 1;
        self.terms.push(TermSpan {
            key: key.into(),
            label,
            start,
            end,
        });
        let e = Expr::Term(term);
        // `-ext:png` and `-login`: the word's own minus. (`neg` from `not`/`-(` is applied by the caller.)
        Some(if word_neg { Expr::Not(Box::new(e)) } else { e })
    }

    fn keyed(
        &mut self,
        key: &'static str,
        v: &str,
        label: &str,
        start: usize,
        end: usize,
    ) -> Option<(&'static str, Term)> {
        let bad = |this: &mut Self, what: &str| {
            this.err(format!("{what} (in \"{label}\")"), start, end);
            None
        };
        if v.is_empty() {
            return bad(self, &format!("{key}: needs a value"));
        }
        let list = |v: &str| {
            v.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let term = match key {
            "host" => {
                let hosts: Vec<_> = list(v)
                    .into_iter()
                    .map(|h| strip_scheme(&h).to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect();
                if hosts.is_empty() {
                    return bad(self, "host: needs a host name");
                }
                Term::Host(hosts)
            }
            "method" => {
                let ms = list(v);
                if ms.is_empty() || !ms.iter().all(|m| m.bytes().all(|b| b.is_ascii_alphabetic())) {
                    return bad(self, "method: expects names such as GET,POST");
                }
                Term::Method(ms.into_iter().map(|m| m.to_ascii_uppercase()).collect())
            }
            "status" => {
                let rs: Option<Vec<Range>> = list(v).iter().map(|s| parse_status(s)).collect();
                match rs {
                    Some(rs) if !rs.is_empty() => Term::Status(rs),
                    _ => {
                        return bad(
                            self,
                            "status: expects 404, 400-499, 4xx or >=400 (comma-separated for \"or\")",
                        );
                    }
                }
            }
            "scope" => match v.to_ascii_lowercase().as_str() {
                "in" => Term::Scope(true),
                "out" => Term::Scope(false),
                _ => return bad(self, "scope: expects in or out"),
            },
            "ext" => {
                let es: Vec<_> = list(v)
                    .into_iter()
                    .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                    .collect();
                if es.is_empty()
                    || !es
                        .iter()
                        .all(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_alphanumeric()))
                {
                    return bad(self, "ext: expects names such as png,css");
                }
                Term::Ext(es)
            }
            "source" => match FlowSource::parse(&v.to_ascii_lowercase()) {
                Some(s) => Term::Source(s),
                None => {
                    return bad(
                        self,
                        "source: expects proxy, repeater, intruder, scanner, import, ...",
                    );
                }
            },
            "header" => {
                let (name, value) = match v.split_once('=') {
                    Some((n, val)) => (n, Some(val)),
                    None => (v, None),
                };
                let name = name.trim();
                if name.len() < 2
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return bad(
                        self,
                        "header: expects a header name (two or more letters), optionally header:name=value",
                    );
                }
                let value = value.map(str::trim).filter(|x| !x.is_empty());
                Term::Header {
                    name: name.to_ascii_lowercase(),
                    value: value.map(str::to_string),
                }
            }
            "tag" => Term::Tag(v.to_string()),
            "mime" => Term::Mime(v.to_ascii_lowercase()),
            "path" => Term::Path(v.to_string()),
            "note" => Term::Note(v.to_string()),
            "port" => match v.parse::<u16>() {
                Ok(p) => Term::Port(p),
                Err(_) => return bad(self, "port: expects a number up to 65535"),
            },
            "scheme" => match v.to_ascii_lowercase().as_str() {
                "https" => Term::Https(true),
                "http" => Term::Https(false),
                _ => return bad(self, "scheme: expects http or https"),
            },
            "size" => match parse_size_range(v) {
                Some(r) => Term::Size(r),
                None => return bad(self, "size: expects >10k, <=2m, 500 or 1k-1m"),
            },
            "since" | "until" => match parse_when(v) {
                Some(w) if key == "since" => Term::Since(w),
                Some(w) => Term::Until(w),
                None => {
                    return bad(
                        self,
                        &format!("{key}: expects 10m, 2h, 7d or a date such as 2026-11-25"),
                    );
                }
            },
            "has" => match v.to_ascii_lowercase().as_str() {
                "note" => Term::Has(Has::Note),
                "error" => Term::Has(Has::Error),
                "edited" => Term::Has(Has::Edited),
                "response" => Term::Has(Has::Response),
                _ => return bad(self, "has: expects note, error, edited or response"),
            },
            _ => return None,
        };
        Some((key, term))
    }
}

fn key_of(k: &str) -> Option<&'static str> {
    Some(match k.to_ascii_lowercase().as_str() {
        "host" | "h" => "host",
        "method" | "m" => "method",
        "status" | "s" => "status",
        "scope" => "scope",
        "ext" => "ext",
        "source" => "source",
        "header" => "header",
        "tag" => "tag",
        "mime" => "mime",
        "path" => "path",
        "note" => "note",
        "port" => "port",
        "scheme" => "scheme",
        "size" => "size",
        "since" => "since",
        "until" => "until",
        "has" => "has",
        _ => return None,
    })
}

fn strip_scheme(h: &str) -> &str {
    match h.find("://") {
        Some(i) if h[..i].bytes().all(|b| b.is_ascii_alphabetic()) => &h[i + 3..],
        _ => h,
    }
}

fn parse_status(v: &str) -> Option<Range> {
    let b = v.as_bytes();
    if b.len() == 3 && (b'1'..=b'5').contains(&b[0]) && b[1..].eq_ignore_ascii_case(b"xx") {
        let n = i64::from(b[0] - b'0') * 100;
        return Some(Range {
            min: Some(n),
            max: Some(n + 99),
        });
    }
    parse_range(v, |s| {
        (s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    })
}

/// `n`, `a-b`, `>n`, `>=n`, `<n`, `<=n`, with `num` reading one number.
fn parse_range(v: &str, num: impl Fn(&str) -> Option<i64>) -> Option<Range> {
    for (op, f) in [(">=", 0), ("<=", 1), (">", 2), ("<", 3)] {
        if let Some(rest) = v.strip_prefix(op) {
            let n = num(rest)?;
            return Some(match f {
                0 => Range {
                    min: Some(n),
                    max: None,
                },
                1 => Range {
                    min: None,
                    max: Some(n),
                },
                2 => Range {
                    min: Some(n.checked_add(1)?),
                    max: None,
                },
                _ => Range {
                    min: None,
                    max: Some(n.checked_sub(1)?),
                },
            });
        }
    }
    if let Some((a, b)) = v.split_once('-') {
        let (a, b) = (num(a)?, num(b)?);
        return (a <= b).then_some(Range {
            min: Some(a),
            max: Some(b),
        });
    }
    let n = num(v)?;
    Some(Range {
        min: Some(n),
        max: Some(n),
    })
}

fn parse_size_range(v: &str) -> Option<Range> {
    parse_range(v, |s| {
        let s = s.to_ascii_lowercase();
        let (digits, mult) = match s.as_bytes().last()? {
            b'k' => (&s[..s.len() - 1], 1024_i64),
            b'm' => (&s[..s.len() - 1], 1024 * 1024),
            b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
            _ => (&s[..], 1),
        };
        if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse::<i64>().ok()?.checked_mul(mult)
    })
}

fn parse_when(v: &str) -> Option<When> {
    let b = v.as_bytes();
    // `10m`, `2h`, `7d`, `30s`.
    if let Some(&unit) = b.last()
        && b.len() >= 2
        && b[..b.len() - 1].iter().all(u8::is_ascii_digit)
        && b.len() <= 9
    {
        let n: i64 = v[..v.len() - 1].parse().ok()?;
        let ms = match unit {
            b's' => 1000,
            b'm' => 60_000,
            b'h' => 3_600_000,
            b'd' => 86_400_000,
            _ => return None,
        };
        return Some(When::Ago(n * ms));
    }
    // `2026-11-25`: UTC midnight.
    let mut p = v.split('-');
    let (y, m, d) = (p.next()?, p.next()?, p.next()?);
    if p.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's civil-from-days, inverted).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(When::At(days * 86_400_000))
}

/// Parse a query. Total: never fails, never panics.
pub fn parse(query: &str) -> Parsed {
    let mut cut = query.len().min(MAX_QUERY);
    while !query.is_char_boundary(cut) {
        cut -= 1;
    }
    let q = &query[..cut];
    let mut p = P {
        q,
        toks: tokenize(q),
        i: 0,
        terms: Vec::new(),
        errors: Vec::new(),
        count: 0,
    };
    if cut < query.len() {
        p.err(
            format!("the query is too long (at most {MAX_QUERY} characters); the rest is ignored"),
            cut,
            cut,
        );
    }
    let mut parts = Vec::new();
    while p.i < p.toks.len() {
        parts.extend(p.or(0));
        if let Some(t) = p.peek().cloned() {
            // A stray `)`.
            p.err("this ) has no matching (", t.start, t.end);
            p.i += 1;
        }
    }
    let expr = match parts.len() {
        0 => None,
        1 => parts.pop(),
        _ => Some(Expr::And(parts)),
    };
    Parsed {
        expr,
        terms: p.terms,
        errors: p.errors,
    }
}

// ---- SQL ------------------------------------------------------------------------------------------------

/// A bound parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Text(String),
    Int(i64),
}

/// The SQL condition (over the `flows` table) and its parameters. `now_ms` resolves relative times.
pub fn compile(e: &Expr, now_ms: i64) -> (String, Vec<Param>) {
    let mut sql = String::new();
    let mut args = Vec::new();
    expr(e, now_ms, &mut sql, &mut args);
    (sql, args)
}

fn like(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('%');
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn phrase(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn expr(e: &Expr, now: i64, sql: &mut String, args: &mut Vec<Param>) {
    match e {
        Expr::And(v) | Expr::Or(v) => {
            let op = if matches!(e, Expr::And(_)) {
                " AND "
            } else {
                " OR "
            };
            sql.push('(');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    sql.push_str(op);
                }
                expr(x, now, sql, args);
            }
            sql.push(')');
        }
        Expr::Not(x) => {
            sql.push_str("NOT ");
            expr(x, now, sql, args);
        }
        Expr::Term(t) => {
            // COALESCE so that NOT (status >= 400) keeps the flows that have no status at all.
            sql.push_str("COALESCE(");
            term(t, now, sql, args);
            sql.push_str(", 0)");
        }
    }
}

fn range(col: &str, r: &Range, sql: &mut String, args: &mut Vec<Param>) {
    match (r.min, r.max) {
        (Some(a), Some(b)) if a == b => {
            let _ = write!(sql, "{col} = ?");
            args.push(Param::Int(a));
        }
        (Some(a), Some(b)) => {
            let _ = write!(sql, "{col} BETWEEN ? AND ?");
            args.extend([Param::Int(a), Param::Int(b)]);
        }
        (Some(a), None) => {
            let _ = write!(sql, "{col} >= ?");
            args.push(Param::Int(a));
        }
        (None, Some(b)) => {
            let _ = write!(sql, "{col} <= ?");
            args.push(Param::Int(b));
        }
        (None, None) => sql.push('1'),
    }
}

fn any_of<T>(items: &[T], sql: &mut String, mut one: impl FnMut(&T, &mut String)) {
    sql.push('(');
    for (i, x) in items.iter().enumerate() {
        if i > 0 {
            sql.push_str(" OR ");
        }
        one(x, sql);
    }
    sql.push(')');
}

fn when_ms(w: When, now: i64) -> i64 {
    match w {
        When::Ago(d) => now.saturating_sub(d),
        When::At(t) => t,
    }
}

fn term(t: &Term, now: i64, sql: &mut String, args: &mut Vec<Param>) {
    match t {
        Term::Text(s) => {
            // The trigram index needs three characters; shorter text is looked for in the host and path.
            if s.chars().count() >= 3 {
                sql.push_str("id IN (SELECT rowid FROM flow_text WHERE flow_text MATCH ?)");
                args.push(Param::Text(phrase(s)));
            } else {
                sql.push_str("(host || path) LIKE ? ESCAPE '\\'");
                args.push(Param::Text(like(s)));
            }
        }
        Term::Host(hs) => any_of(hs, sql, |h, sql| {
            sql.push_str("host LIKE ? ESCAPE '\\'");
            args.push(Param::Text(like(h)));
        }),
        Term::Method(ms) => {
            let _ = write!(sql, "method IN ({})", vec!["?"; ms.len()].join(","));
            args.extend(ms.iter().cloned().map(Param::Text));
        }
        Term::Status(rs) => any_of(rs, sql, |r, sql| range("status", r, sql, args)),
        Term::Scope(b) => sql.push_str(if *b { "in_scope = 1" } else { "in_scope = 0" }),
        Term::Ext(es) => any_of(es, sql, |e, sql| {
            sql.push_str("lower(base_path) LIKE ? ESCAPE '\\'");
            args.push(Param::Text(format!("%.{e}")));
        }),
        Term::Source(s) => {
            sql.push_str("source = ?");
            args.push(Param::Text(s.as_str().into()));
        }
        Term::Header { name, value } => {
            sql.push_str("id IN (SELECT rowid FROM flow_text WHERE flow_text MATCH ?)");
            args.push(Param::Text(match value {
                Some(v) => phrase(&format!("{name}: {v}")),
                None => phrase(&format!("{name}:")),
            }));
        }
        Term::Tag(tag) => {
            sql.push_str("EXISTS (SELECT 1 FROM json_each(flows.tags) WHERE lower(value) = lower(?))");
            args.push(Param::Text(tag.clone()));
        }
        Term::Mime(m) => {
            sql.push_str("lower(mime) LIKE ? ESCAPE '\\'");
            args.push(Param::Text(like(m)));
        }
        Term::Path(p) => {
            sql.push_str("path LIKE ? ESCAPE '\\'");
            args.push(Param::Text(like(p)));
        }
        Term::Note(n) => {
            sql.push_str("note LIKE ? ESCAPE '\\'");
            args.push(Param::Text(like(n)));
        }
        Term::Port(p) => {
            sql.push_str("port = ?");
            args.push(Param::Int(i64::from(*p)));
        }
        Term::Https(b) => {
            sql.push_str("scheme = ?");
            args.push(Param::Text(if *b { "https" } else { "http" }.into()));
        }
        Term::Size(r) => range("response_len", r, sql, args),
        Term::Since(w) => {
            sql.push_str("started_ms >= ?");
            args.push(Param::Int(when_ms(*w, now)));
        }
        Term::Until(w) => {
            sql.push_str("started_ms <= ?");
            args.push(Param::Int(when_ms(*w, now)));
        }
        Term::Has(h) => sql.push_str(match h {
            Has::Note => "(note IS NOT NULL AND note != '')",
            Has::Error => "error IS NOT NULL",
            Has::Edited => "edited = 1",
            Has::Response => "status IS NOT NULL",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(q: &str) -> Vec<String> {
        parse(q).terms.into_iter().map(|t| t.key).collect()
    }

    #[test]
    fn the_existing_filter_line_still_parses() {
        let p = parse(r#"host:example.com method:get,post status:4xx scope:in -ext:png,css "sign in""#);
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert_eq!(
            keys(r#"host:example.com method:get,post status:4xx scope:in -ext:png,css "sign in""#),
            ["host", "method", "status", "scope", "ext", "text"]
        );
        let Some(Expr::And(v)) = p.expr else {
            panic!("expected an and")
        };
        assert_eq!(v[1], Expr::Term(Term::Method(vec!["GET".into(), "POST".into()])));
        assert_eq!(
            v[2],
            Expr::Term(Term::Status(vec![Range {
                min: Some(400),
                max: Some(499)
            }]))
        );
        assert_eq!(
            v[4],
            Expr::Not(Box::new(Expr::Term(Term::Ext(vec!["png".into(), "css".into()]))))
        );
        assert_eq!(v[5], Expr::Term(Term::Text("sign in".into())));
    }

    #[test]
    fn or_not_and_groups() {
        let p = parse("a1b or (c2d -e3f)");
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert!(matches!(&p.expr, Some(Expr::Or(v)) if v.len() == 2 && matches!(&v[1], Expr::And(_))));
        let p = parse("a1b not g4h");
        assert!(matches!(&p.expr, Some(Expr::And(v)) if matches!(&v[1], Expr::Not(_))));
        // `a or b c` is `a or (b and c)`: and binds tighter.
        assert!(matches!(&parse("a1 or b2 c3").expr, Some(Expr::Or(v)) if matches!(&v[1], Expr::And(_))));
        // and binds tighter than or; `-(` negates a group.
        let p = parse("x1 -(y2 or z3)");
        assert!(matches!(p.expr, Some(Expr::And(ref v)) if matches!(v[1], Expr::Not(_))));
    }

    #[test]
    fn status_forms() {
        for (v, r) in [
            ("404", (Some(404), Some(404))),
            ("4xx", (Some(400), Some(499))),
            ("400-499", (Some(400), Some(499))),
            (">=400", (Some(400), None)),
            (">399", (Some(400), None)),
            ("<500", (None, Some(499))),
            ("<=500", (None, Some(500))),
        ] {
            assert_eq!(parse_status(v), Some(Range { min: r.0, max: r.1 }), "{v}");
        }
        for v in ["", "40", "6xx", "499-400", ">", "abc", "4040"] {
            assert_eq!(parse_status(v), None, "{v}");
        }
    }

    #[test]
    fn sizes_and_times() {
        assert_eq!(
            parse_size_range(">10k"),
            Some(Range {
                min: Some(10_241),
                max: None
            })
        );
        assert_eq!(
            parse_size_range("1k-1m"),
            Some(Range {
                min: Some(1024),
                max: Some(1 << 20)
            })
        );
        assert_eq!(parse_size_range("99999999999999999999"), None);
        assert_eq!(parse_when("10m"), Some(When::Ago(600_000)));
        assert_eq!(parse_when("1970-01-02"), Some(When::At(86_400_000)));
        assert_eq!(parse_when("2026-11-25"), Some(When::At(1_795_564_800_000)));
        assert_eq!(parse_when("2026-13-01"), None);
        assert_eq!(parse_when("m"), None);
    }

    #[test]
    fn mistakes_become_messages_and_the_rest_still_applies() {
        let p = parse("status:banana host:a.com (oops");
        assert_eq!(p.errors.len(), 2, "{:?}", p.errors);
        assert!(matches!(
            p.expr,
            Some(Expr::Term(Term::Host(_))) | Some(Expr::And(_))
        ));
        let p = parse(") foo");
        assert_eq!(p.errors.len(), 1);
        assert_eq!(parse("or").errors.len(), 1);
        assert_eq!(parse("not").errors.len(), 1);
        // An unknown key is just text: a URL can be searched for.
        assert_eq!(keys("http://x.test/a"), ["text"]);
    }

    #[test]
    fn limits() {
        let deep = format!("{}a1b{}", "(".repeat(100), ")".repeat(100));
        assert!(!parse(&deep).errors.is_empty());
        let many = "abc ".repeat(200);
        assert!(
            parse(&many)
                .errors
                .iter()
                .any(|e| e.message.contains("too many terms"))
        );
        let long = "x".repeat(MAX_QUERY + 10);
        assert!(parse(&long).errors.iter().any(|e| e.message.contains("too long")));
        // A multi-byte character at the cut is not split.
        let q = format!("{}é", "a".repeat(MAX_QUERY - 1));
        let _ = parse(&q);
    }

    #[test]
    fn user_text_is_only_ever_a_bound_parameter() {
        let hostile = r#"host:"a'; DROP TABLE flows; --" "x' OR '1'='1" header:x-a=b"c"#;
        let p = parse(hostile);
        let (sql, args) = compile(p.expr.as_ref().unwrap(), 0);
        assert!(!sql.contains("DROP") && !sql.contains('\''), "{sql}");
        assert_eq!(sql.matches('?').count(), args.len(), "{sql}");
    }

    #[test]
    fn a_nul_character_cannot_cut_a_bound_phrase() {
        // Found by the fuzzer: SQLite stops a bound string at NUL, leaving an unterminated FTS phrase.
        let p = parse("\u{fffd}\0\x03 host:a\0b \"x\0yz\"");
        let (sql, args) = compile(p.expr.as_ref().unwrap(), 0);
        assert_eq!(sql.matches('?').count(), args.len());
        assert!(
            args.iter()
                .all(|a| !matches!(a, Param::Text(t) if t.contains('\0'))),
            "{args:?}"
        );
    }

    #[test]
    fn like_and_phrase_escape() {
        assert_eq!(like("a%b_c\\d"), "%a\\%b\\_c\\\\d%");
        assert_eq!(phrase("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn spans_point_at_the_terms() {
        let q = r#"host:a.com -ext:png "two words""#;
        let p = parse(q);
        for t in &p.terms {
            assert_eq!(&q[t.start..t.end], t.label);
        }
        assert_eq!(p.terms.len(), 3);
    }

    use proptest::prelude::*;

    proptest! {
        /// Any string parses, the spans are valid, and whatever was recognised compiles with a matching
        /// number of parameters.
        #[test]
        fn any_string_parses_and_compiles(q in "\\PC{0,300}") {
            let p = parse(&q);
            for t in &p.terms {
                prop_assert!(t.start <= t.end && t.end <= q.len());
                prop_assert!(q.is_char_boundary(t.start) && q.is_char_boundary(t.end));
            }
            if let Some(e) = &p.expr {
                let (sql, args) = compile(e, 1_000);
                prop_assert_eq!(sql.matches('?').count(), args.len());
            }
        }

        #[test]
        fn query_shaped_strings_parse_and_compile(q in "[a-z:()\" ,<>=0-9.x-]{0,200}") {
            let p = parse(&q);
            if let Some(e) = &p.expr {
                let (sql, args) = compile(e, 1_000);
                prop_assert_eq!(sql.matches('?').count(), args.len());
            }
        }
    }
}
