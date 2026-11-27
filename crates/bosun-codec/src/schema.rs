//! A `.proto` schema, so a decoded message shows field names, types and enum names instead of numbers.
//!
//! This reads the part of the language that describes messages: `package`, `message` (nested, with `oneof` and
//! `map<,>`), `enum` and `service`/`rpc`. Everything else (`syntax`, `import`, `option`, `reserved`, `extend`) is
//! skipped. It is not a compiler: types that cannot be found (an `import` it was not given, say) decode as if there
//! were no schema for that field. The source is bounded, and so are nesting and the number of messages.

use std::collections::{HashMap, HashSet};

use crate::CodecError;

/// The largest schema source taken.
pub const MAX_SOURCE: usize = 256 << 10;
/// Messages plus enums.
const MAX_ITEMS: usize = 4096;
const MAX_FIELDS: usize = 100_000;
const MAX_DEPTH: usize = 24;
const MAX_FIELD_NUMBER: i64 = (1 << 29) - 1;

fn bad() -> CodecError {
    CodecError::Invalid("proto schema")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scalar {
    Double,
    Float,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    String,
    Bytes,
}

impl Scalar {
    fn parse(s: &str) -> Option<Scalar> {
        Some(match s {
            "double" => Scalar::Double,
            "float" => Scalar::Float,
            "int32" => Scalar::Int32,
            "int64" => Scalar::Int64,
            "uint32" => Scalar::Uint32,
            "uint64" => Scalar::Uint64,
            "sint32" => Scalar::Sint32,
            "sint64" => Scalar::Sint64,
            "fixed32" => Scalar::Fixed32,
            "fixed64" => Scalar::Fixed64,
            "sfixed32" => Scalar::Sfixed32,
            "sfixed64" => Scalar::Sfixed64,
            "bool" => Scalar::Bool,
            "string" => Scalar::String,
            "bytes" => Scalar::Bytes,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ty {
    Scalar(Scalar),
    /// The full name of a message.
    Message(String),
    /// The full name of an enum.
    Enum(String),
    /// A type the schema does not define.
    Opaque,
}

#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub name: String,
    pub num: u32,
    pub ty: Ty,
}

#[derive(Debug, Default)]
pub(crate) struct Msg {
    fields: Vec<Field>,
    by_num: HashMap<u32, usize>,
    by_name: HashMap<String, usize>,
}

impl Msg {
    fn new(fields: Vec<Field>) -> Msg {
        let mut m = Msg::default();
        for f in fields {
            let i = m.fields.len();
            // The first of a repeated name or number wins.
            m.by_num.entry(f.num).or_insert(i);
            m.by_name.entry(f.name.clone()).or_insert(i);
            m.fields.push(f);
        }
        m
    }
    pub fn by_num(&self, n: u64) -> Option<&Field> {
        u32::try_from(n).ok().and_then(|n| self.by_num.get(&n)).map(|&i| &self.fields[i])
    }
    pub fn by_name(&self, n: &str) -> Option<&Field> {
        self.by_name.get(n).map(|&i| &self.fields[i])
    }
}

#[derive(Debug, Default)]
pub(crate) struct Enum {
    values: Vec<(String, i32)>,
}

impl Enum {
    pub fn name_of(&self, v: i32) -> Option<&str> {
        self.values.iter().find(|(_, n)| *n == v).map(|(s, _)| s.as_str())
    }
    pub fn value_of(&self, name: &str) -> Option<i32> {
        self.values.iter().find(|(s, _)| s == name).map(|(_, n)| *n)
    }
}

#[derive(Debug)]
struct Rpc {
    /// `/package.Service/Method`, as it is sent in a gRPC request's path.
    path: String,
    request: String,
    response: String,
}

/// A parsed schema.
#[derive(Debug, Default)]
pub struct Schema {
    messages: HashMap<String, Msg>,
    enums: HashMap<String, Enum>,
    rpcs: Vec<Rpc>,
}

/// A message of a schema: what decoding and encoding use to name fields.
#[derive(Debug, Clone, Copy)]
pub struct Typed<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) msg: &'a Msg,
}

impl<'a> Typed<'a> {
    /// The message a field of this one holds.
    pub(crate) fn sub(&self, full: &str) -> Option<Typed<'a>> {
        self.schema.messages.get(full).map(|msg| Typed { schema: self.schema, msg })
    }
    pub(crate) fn enumeration(&self, full: &str) -> Option<&'a Enum> {
        self.schema.enums.get(full)
    }
}

impl Schema {
    /// Read a schema from `.proto` source.
    pub fn parse(src: &str) -> Result<Schema, CodecError> {
        if src.len() > MAX_SOURCE {
            return Err(CodecError::TooLarge(MAX_SOURCE));
        }
        let mut p = Parser {
            t: lex(src),
            i: 0,
            pkg: String::new(),
            msgs: Vec::new(),
            enums: Vec::new(),
            rpcs: Vec::new(),
            fields: 0,
        };
        p.file()?;
        Ok(p.finish())
    }

    /// The full names of the messages, sorted.
    pub fn message_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.messages.keys().cloned().collect();
        v.sort();
        v
    }

    /// A message by name: the full name (`pkg.Msg`, with or without a leading dot) or a short one that is unique.
    pub fn typed(&self, name: &str) -> Option<Typed<'_>> {
        let name = name.trim().trim_start_matches('.');
        if name.is_empty() {
            return None;
        }
        let msg = self.messages.get(name).or_else(|| {
            let suffix = format!(".{name}");
            let mut hits = self.messages.iter().filter(|(k, _)| k.ends_with(&suffix));
            match (hits.next(), hits.next()) {
                (Some((_, m)), None) => Some(m),
                _ => None,
            }
        })?;
        Some(Typed { schema: self, msg })
    }

    /// The request and response messages of a call, from its gRPC path (`/pkg.Service/Method`).
    pub fn rpc(&self, path: &str) -> Option<(Typed<'_>, Typed<'_>)> {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let r = self.rpcs.iter().find(|r| r.path == path)?;
        Some((self.typed(&r.request)?, self.typed(&r.response)?))
    }

    /// The paths of the calls the schema defines, sorted.
    pub fn rpc_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.rpcs.iter().map(|r| r.path.clone()).collect();
        v.sort();
        v
    }
}

// ---- reading the source ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Id(String),
    Num(String),
    Str,
    Sym(u8),
}

fn lex(src: &str) -> Vec<Tok> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let id_char = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'.';
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            i += 2;
        } else if c == b'"' || c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != c {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
            out.push(Tok::Str);
        } else if c.is_ascii_alphabetic() || c == b'_' || (c == b'.' && b.get(i + 1).is_some_and(|d| d.is_ascii_alphabetic())) {
            let s = i;
            i += 1;
            while i < b.len() && id_char(b[i]) {
                i += 1;
            }
            out.push(Tok::Id(src.get(s..i).unwrap_or("").to_owned()));
        } else if c.is_ascii_digit() || (matches!(c, b'-' | b'+') && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let s = i;
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'.' | b'_' | b'+' | b'-')) {
                i += 1;
            }
            out.push(Tok::Num(src.get(s..i).unwrap_or("").to_owned()));
        } else {
            out.push(Tok::Sym(c));
            i += 1;
        }
    }
    out
}

fn parse_int(s: &str) -> Option<i64> {
    let (neg, t) = match s.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok()?,
        None => t.parse::<i64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

fn join(scope: &str, name: &str) -> String {
    if scope.is_empty() { name.to_owned() } else { format!("{scope}.{name}") }
}

struct RawField {
    name: String,
    num: u32,
    ty: String,
}

struct RawMsg {
    full: String,
    fields: Vec<RawField>,
}

struct Parser {
    t: Vec<Tok>,
    i: usize,
    pkg: String,
    msgs: Vec<RawMsg>,
    enums: Vec<(String, Enum)>,
    /// (service full name, method, request type, response type)
    rpcs: Vec<(String, String, String, String)>,
    fields: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).cloned();
        self.i += 1;
        t
    }
    fn sym(&mut self, c: u8) -> bool {
        if self.peek() == Some(&Tok::Sym(c)) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn need(&mut self, c: u8) -> Result<(), CodecError> {
        if self.sym(c) { Ok(()) } else { Err(bad()) }
    }
    fn id(&mut self) -> Result<String, CodecError> {
        match self.bump() {
            Some(Tok::Id(s)) => Ok(s),
            _ => Err(bad()),
        }
    }
    /// A name that stands alone (a field, an enum value): no dots, so it reads back from the text form.
    fn name(&mut self) -> Result<String, CodecError> {
        let s = self.id()?;
        if s.contains('.') { Err(bad()) } else { Ok(s) }
    }
    fn int(&mut self) -> Result<i64, CodecError> {
        match self.bump() {
            Some(Tok::Num(s)) => parse_int(&s).ok_or_else(bad),
            _ => Err(bad()),
        }
    }
    /// Skip to the `;` that ends the statement, over any brackets and braces.
    fn skip_stmt(&mut self) -> Result<(), CodecError> {
        let mut depth = 0usize;
        loop {
            match self.bump() {
                None => return Err(bad()),
                Some(Tok::Sym(b'{' | b'[' | b'(')) => depth += 1,
                Some(Tok::Sym(b'}' | b']' | b')')) => depth = depth.checked_sub(1).ok_or_else(bad)?,
                Some(Tok::Sym(b';')) if depth == 0 => return Ok(()),
                _ => {}
            }
        }
    }
    /// Skip a block whose `{` is already read.
    fn skip_block(&mut self) -> Result<(), CodecError> {
        let mut depth = 1usize;
        while depth > 0 {
            match self.bump() {
                None => return Err(bad()),
                Some(Tok::Sym(b'{')) => depth += 1,
                Some(Tok::Sym(b'}')) => depth -= 1,
                _ => {}
            }
        }
        Ok(())
    }

    fn file(&mut self) -> Result<(), CodecError> {
        while let Some(t) = self.bump() {
            match t {
                Tok::Sym(b';') => {}
                Tok::Id(k) => match k.as_str() {
                    "syntax" | "edition" | "import" | "option" => self.skip_stmt()?,
                    "package" => {
                        self.pkg = self.id()?;
                        self.skip_stmt()?;
                    }
                    "message" => {
                        let pkg = self.pkg.clone();
                        self.message(&pkg, 0)?;
                    }
                    "enum" => {
                        let pkg = self.pkg.clone();
                        self.enumeration(&pkg)?;
                    }
                    "service" => self.service()?,
                    "extend" => {
                        self.id()?;
                        self.need(b'{')?;
                        self.skip_block()?;
                    }
                    _ => return Err(bad()),
                },
                _ => return Err(bad()),
            }
        }
        Ok(())
    }

    fn new_msg(&mut self, full: String) -> Result<usize, CodecError> {
        if self.msgs.len() + self.enums.len() >= MAX_ITEMS {
            return Err(bad());
        }
        self.msgs.push(RawMsg { full, fields: Vec::new() });
        Ok(self.msgs.len() - 1)
    }

    fn add_field(&mut self, msg: usize, name: String, num: i64, ty: String) -> Result<(), CodecError> {
        self.fields += 1;
        if self.fields > MAX_FIELDS || !(1..=MAX_FIELD_NUMBER).contains(&num) {
            return Err(bad());
        }
        let num = u32::try_from(num).map_err(|_| bad())?;
        self.msgs[msg].fields.push(RawField { name, num, ty });
        Ok(())
    }

    /// `type name = N [options];`, with the type read already.
    fn field(&mut self, msg: usize, ty: String) -> Result<(), CodecError> {
        if ty == "group" {
            return Err(bad());
        }
        let name = self.name()?;
        self.need(b'=')?;
        let n = self.int()?;
        self.skip_stmt()?;
        self.add_field(msg, name, n, ty)
    }

    fn message(&mut self, scope: &str, depth: usize) -> Result<(), CodecError> {
        if depth > MAX_DEPTH {
            return Err(bad());
        }
        let name = self.id()?;
        let full = join(scope, &name);
        self.need(b'{')?;
        let me = self.new_msg(full.clone())?;
        loop {
            match self.bump() {
                Some(Tok::Sym(b'}')) => return Ok(()),
                Some(Tok::Sym(b';')) => {}
                Some(Tok::Id(k)) => match k.as_str() {
                    "message" => self.message(&full, depth + 1)?,
                    "enum" => self.enumeration(&full)?,
                    "option" | "reserved" | "extensions" => self.skip_stmt()?,
                    "extend" => {
                        self.id()?;
                        self.need(b'{')?;
                        self.skip_block()?;
                    }
                    "oneof" => {
                        self.id()?;
                        self.need(b'{')?;
                        loop {
                            match self.peek() {
                                Some(Tok::Sym(b'}')) => {
                                    self.i += 1;
                                    break;
                                }
                                Some(Tok::Sym(b';')) => self.i += 1,
                                Some(Tok::Id(s)) if s == "option" => {
                                    self.i += 1;
                                    self.skip_stmt()?;
                                }
                                _ => {
                                    let ty = self.id()?;
                                    self.field(me, ty)?;
                                }
                            }
                        }
                    }
                    "map" if self.peek() == Some(&Tok::Sym(b'<')) => {
                        self.i += 1;
                        let key = self.id()?;
                        self.need(b',')?;
                        let val = self.id()?;
                        self.need(b'>')?;
                        let fname = self.name()?;
                        self.need(b'=')?;
                        let n = self.int()?;
                        self.skip_stmt()?;
                        // A map is a repeated message with a key (1) and a value (2).
                        let mut cap = fname.clone();
                        if let Some(c) = cap.get_mut(..1) {
                            c.make_ascii_uppercase();
                        }
                        let entry = join(&full, &format!("{cap}Entry"));
                        let e = self.new_msg(entry.clone())?;
                        self.add_field(e, "key".into(), 1, key)?;
                        // The value's type is looked up from the map's own message, so it climbs to the parent.
                        self.add_field(e, "value".into(), 2, val)?;
                        self.add_field(me, fname, n, format!(".{entry}"))?;
                    }
                    "repeated" | "optional" | "required" => {
                        let ty = self.id()?;
                        self.field(me, ty)?;
                    }
                    _ => self.field(me, k)?,
                },
                _ => return Err(bad()),
            }
        }
    }

    fn enumeration(&mut self, scope: &str) -> Result<(), CodecError> {
        let name = self.id()?;
        let full = join(scope, &name);
        self.need(b'{')?;
        if self.msgs.len() + self.enums.len() >= MAX_ITEMS {
            return Err(bad());
        }
        let mut e = Enum::default();
        loop {
            match self.bump() {
                Some(Tok::Sym(b'}')) => break,
                Some(Tok::Sym(b';')) => {}
                Some(Tok::Id(k)) if matches!(k.as_str(), "option" | "reserved") => self.skip_stmt()?,
                Some(Tok::Id(v)) => {
                    if v.contains('.') {
                        return Err(bad());
                    }
                    self.need(b'=')?;
                    let n = i32::try_from(self.int()?).map_err(|_| bad())?;
                    self.skip_stmt()?;
                    if e.values.len() >= MAX_FIELDS {
                        return Err(bad());
                    }
                    e.values.push((v, n));
                }
                _ => return Err(bad()),
            }
        }
        self.enums.push((full, e));
        Ok(())
    }

    fn service(&mut self) -> Result<(), CodecError> {
        let name = self.id()?;
        let full = join(&self.pkg, &name);
        self.need(b'{')?;
        loop {
            match self.bump() {
                Some(Tok::Sym(b'}')) => return Ok(()),
                Some(Tok::Sym(b';')) => {}
                Some(Tok::Id(k)) if k == "option" => self.skip_stmt()?,
                Some(Tok::Id(k)) if k == "rpc" => {
                    let method = self.id()?;
                    let req = self.rpc_type()?;
                    if self.id()? != "returns" {
                        return Err(bad());
                    }
                    let resp = self.rpc_type()?;
                    if self.sym(b'{') {
                        self.skip_block()?;
                    } else {
                        self.need(b';')?;
                    }
                    if self.rpcs.len() >= MAX_FIELDS {
                        return Err(bad());
                    }
                    self.rpcs.push((full.clone(), method, req, resp));
                }
                _ => return Err(bad()),
            }
        }
    }

    /// `( [stream] Type )`
    fn rpc_type(&mut self) -> Result<String, CodecError> {
        self.need(b'(')?;
        if matches!(self.peek(), Some(Tok::Id(s)) if s == "stream") && matches!(self.t.get(self.i + 1), Some(Tok::Id(_))) {
            self.i += 1;
        }
        let t = self.id()?;
        self.need(b')')?;
        Ok(t)
    }

    fn finish(self) -> Schema {
        let msg_names: HashSet<&str> = self.msgs.iter().map(|m| m.full.as_str()).collect();
        let enum_names: HashSet<&str> = self.enums.iter().map(|(n, _)| n.as_str()).collect();
        let resolve = |scope: &str, name: &str| -> Ty {
            if let Some(s) = Scalar::parse(name) {
                return Ty::Scalar(s);
            }
            let kind = |full: &str| {
                if msg_names.contains(full) {
                    Some(Ty::Message(full.to_owned()))
                } else if enum_names.contains(full) {
                    Some(Ty::Enum(full.to_owned()))
                } else {
                    None
                }
            };
            if let Some(abs) = name.strip_prefix('.') {
                return kind(abs).unwrap_or(Ty::Opaque);
            }
            let mut scope = scope;
            loop {
                if let Some(t) = kind(&join(scope, name)) {
                    return t;
                }
                match scope.rfind('.') {
                    Some(i) => scope = &scope[..i],
                    None if !scope.is_empty() => scope = "",
                    None => return Ty::Opaque,
                }
            }
        };
        let mut messages = HashMap::new();
        for m in &self.msgs {
            let fields = m
                .fields
                .iter()
                .map(|f| Field { name: f.name.clone(), num: f.num, ty: resolve(&m.full, &f.ty) })
                .collect();
            messages.insert(m.full.clone(), Msg::new(fields));
        }
        let rpcs = self
            .rpcs
            .iter()
            .filter_map(|(svc, method, req, resp)| {
                let (Ty::Message(request), Ty::Message(response)) = (resolve(&self.pkg, req), resolve(&self.pkg, resp)) else {
                    return None;
                };
                Some(Rpc { path: format!("/{svc}/{method}"), request, response })
            })
            .collect();
        Schema { messages, enums: self.enums.into_iter().collect(), rpcs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = r#"
        syntax = "proto3";
        package shop.v1;
        import "google/protobuf/timestamp.proto";
        option java_package = "x";

        // A customer.
        message Customer {
          enum Tier { BRONZE = 0; SILVER = 1; GOLD = 2; }
          reserved 9, 10 to 12;
          int32 id = 1;
          string name = 2;
          Tier tier = 3;
          repeated int64 scores = 4 [packed = true];
          Address home = 5;
          map<string, int32> labels = 6;
          oneof contact { string email = 7; string phone = 8; }
          google.protobuf.Timestamp since = 13;
          message Address { string city = 1; sint32 floor = 2; }
        }
        message Address { string street = 1; }
        service Shop {
          rpc Get (GetRequest) returns (Customer);
          rpc Watch (stream GetRequest) returns (stream Customer) { option deprecated = true; }
        }
        message GetRequest { int32 id = 1; }
    "#;

    #[test]
    fn reads_messages_enums_maps_and_services() {
        let s = Schema::parse(SAMPLE).unwrap();
        let names = s.message_names();
        assert!(names.contains(&"shop.v1.Customer.Address".to_owned()), "{names:?}");
        assert!(names.contains(&"shop.v1.Customer.LabelsEntry".to_owned()), "{names:?}");
        let c = s.typed("Customer").unwrap();
        assert_eq!(c.msg.by_name("name").unwrap().num, 2);
        assert_eq!(c.msg.by_num(3).unwrap().ty, Ty::Enum("shop.v1.Customer.Tier".into()));
        // The nested Address wins inside Customer; the top-level one is still reachable by full name.
        assert_eq!(c.msg.by_name("home").unwrap().ty, Ty::Message("shop.v1.Customer.Address".into()));
        assert_eq!(c.msg.by_name("since").unwrap().ty, Ty::Opaque);
        assert_eq!(c.msg.by_name("phone").unwrap().num, 8);
        assert!(s.typed("shop.v1.Address").is_some());
        assert!(s.typed("Address").is_none(), "two messages end in Address");
        let (req, resp) = s.rpc("/shop.v1.Shop/Get").unwrap();
        assert!(req.msg.by_name("id").is_some() && resp.msg.by_name("tier").is_some());
        assert_eq!(s.rpc_paths(), ["/shop.v1.Shop/Get", "/shop.v1.Shop/Watch"]);
        assert!(s.rpc("/shop.v1.Shop/Nope").is_none());
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        for src in ["message {", "message A { int32 x = 0; }", "message A { int32 x }", "garbage", "message A { group G = 1 {} }"] {
            assert!(Schema::parse(src).is_err(), "{src}");
        }
        assert!(Schema::parse(&"message A {".repeat(100)).is_err());
        assert!(Schema::parse(&" ".repeat(MAX_SOURCE + 1)).is_err());
        assert!(Schema::parse("message A { int32 a.b = 1; }").is_err(), "a dotted field name cannot be read back");
        assert!(Schema::parse("").unwrap().message_names().is_empty());
    }

    proptest::proptest! {
        #[test]
        fn parsing_never_panics(s in ".{0,300}") {
            let _ = Schema::parse(&s);
        }
    }
}
