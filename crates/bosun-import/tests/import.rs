//! Fixture files of each format import; hostile ones are refused cleanly.

use bosun_import::{Format, ImportError, Options, parse};

fn base(u: &str) -> Options {
    Options {
        base_url: Some(u.into()),
    }
}

fn run(f: Format, s: &str) -> Result<bosun_import::Imported, ImportError> {
    parse(f, s.as_bytes(), &Options::default())
}

const OPENAPI_YAML: &str = r#"
openapi: 3.0.3
info: {title: t, version: "1"}
servers:
  - url: https://{env}.example.test/v1
    variables: {env: {default: api}}
paths:
  /pets/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer}}
    get:
      operationId: getPet
      parameters:
        - {name: verbose, in: query, required: true, schema: {type: boolean}}
        - {name: X-Trace, in: header, required: true, schema: {type: string}}
    delete: {}
  /pets:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Pet'}
components:
  schemas:
    Pet:
      type: object
      properties:
        name: {type: string}
        tag: {$ref: '#/components/schemas/Pet'}
        age: {type: integer}
"#;

#[test]
fn openapi_yaml_v3() {
    let r = run(Format::Openapi, OPENAPI_YAML).unwrap();
    assert_eq!(r.items.len(), 3);
    let get = r.items.iter().find(|i| i.name == "getPet").unwrap();
    assert_eq!(get.url, "https://api.example.test/v1/pets/1?verbose=true");
    assert!(get.headers.contains(&("X-Trace".into(), "test".into())));
    let post = r.items.iter().find(|i| i.method == "POST").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["name"], "test");
    assert_eq!(body["age"], 1);
    let raw = String::from_utf8(post.raw().unwrap()).unwrap();
    assert!(raw.starts_with("POST /v1/pets HTTP/1.1\r\nHost: api.example.test\r\n"));
    assert!(raw.contains(&format!("Content-Length: {}", post.body.len())));
}

#[test]
fn openapi_swagger2_json_with_base_override() {
    let doc = r#"{"swagger":"2.0","host":"old.test","basePath":"/api","schemes":["http"],
      "paths":{"/u":{"post":{"parameters":[{"in":"body","name":"b","schema":{"type":"object","properties":{"n":{"type":"integer"}}}}]}}}}"#;
    let r = run(Format::Openapi, doc).unwrap();
    assert_eq!(r.items[0].url, "http://old.test/api/u");
    let r = parse(Format::Openapi, doc.as_bytes(), &base("https://new.test")).unwrap();
    assert_eq!(r.items[0].url, "https://new.test/u");
    assert_eq!(r.items[0].body, br#"{"n":1}"#);
}

#[test]
fn openapi_needs_a_base_url_when_the_document_has_none() {
    let doc = r#"{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}"#;
    assert!(matches!(run(Format::Openapi, doc), Err(ImportError::NoBaseUrl)));
    assert!(parse(Format::Openapi, doc.as_bytes(), &base("http://x.test")).is_ok());
}

#[test]
fn yaml_alias_bomb_is_refused() {
    let mut y = String::from("openapi: 3.0.0\nx-a: &a [x, x, x, x, x, x, x, x, x]\n");
    for i in 0..9 {
        let prev = if i == 0 { "a".to_string() } else { format!("l{}", i - 1) };
        y.push_str(&format!("x-l{i}: &l{i} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"));
    }
    assert!(matches!(run(Format::Openapi, &y), Err(ImportError::Unsupported(_))));
}

#[test]
fn json_nesting_bomb_is_refused() {
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    for f in [Format::Openapi, Format::Postman, Format::Har, Format::Graphql] {
        assert!(run(f, &deep).is_err(), "{f:?}");
    }
}

#[test]
fn oversized_input_is_refused() {
    let big = vec![b'a'; bosun_import::MAX_INPUT + 1];
    assert!(matches!(
        parse(Format::Urls, &big, &Options::default()),
        Err(ImportError::TooLarge)
    ));
}

#[test]
fn har_requests() {
    let har = r#"{"log":{"entries":[
      {"request":{"method":"POST","url":"https://t.test/login?a=1","headers":[
        {"name":":authority","value":"t.test"},{"name":"Cookie","value":"s=1"},
        {"name":"X-Bad","value":"a\r\nInjected: 1"},{"name":"Content-Length","value":"999"}],
        "postData":{"mimeType":"application/x-www-form-urlencoded","text":"u=a&p=b"}},
       "response":{"status":200}},
      {"request":{"method":"GET","url":"file:///etc/passwd","headers":[]}}]}}"#;
    let r = run(Format::Har, har).unwrap();
    assert_eq!(r.items.len(), 1);
    assert!(r.notes.iter().any(|n| n.contains("only http and https")));
    let i = &r.items[0];
    assert_eq!(i.headers.len(), 2); // Cookie and the derived Content-Type
    let raw = String::from_utf8(i.raw().unwrap()).unwrap();
    assert!(!raw.contains("Injected"));
    assert!(raw.contains("Content-Length: 7\r\n"));
    assert!(raw.ends_with("\r\n\r\nu=a&p=b"));
}

#[test]
fn postman_folders_and_variables() {
    let c = r#"{"variable":[{"key":"host","value":"https://api.test"}],"item":[
      {"name":"f","item":[
        {"name":"a","request":{"method":"POST","header":[{"key":"X","value":"1"},{"key":"Y","value":"2","disabled":true}],
          "url":{"raw":"{{host}}/a"},"body":{"mode":"raw","raw":"{\"k\":1}","options":{"raw":{"language":"json"}}}}},
        {"name":"b","request":"https://plain.test/b"},
        {"name":"c","request":{"method":"GET","url":"{{missing}}/c"}}]}]}"#;
    let r = run(Format::Postman, c).unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(r.items[0].url, "https://api.test/a");
    assert!(r.items[0].headers.contains(&("Content-Type".into(), "application/json".into())));
    assert!(!r.items[0].headers.iter().any(|(k, _)| k == "Y"));
    assert_eq!(r.notes.len(), 1);
    // The base URL stands in for an undefined leading variable.
    let r = parse(Format::Postman, c.as_bytes(), &base("http://b.test/")).unwrap();
    assert!(r.items.iter().any(|i| i.url == "http://b.test/c"));
}

#[test]
fn url_list() {
    let r = run(Format::Urls, "# c\nhttps://a.test/x\n\nftp://a.test/\nnot a url\nhttp://b.test:8080/?q=1\n").unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(r.items[1].target().unwrap().port, 8080);
    assert_eq!(r.notes.len(), 2);
    assert!(matches!(run(Format::Urls, "\n# nothing\n"), Err(ImportError::Empty)));
}

#[test]
fn burp_xml_base64_and_plain() {
    use base64::Engine as _;
    let raw = "POST /p HTTP/1.1\r\nHost: t.test\r\nContent-Type: text/plain\r\n\r\nhello";
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let xml = format!(
        r#"<?xml version="1.0"?><!DOCTYPE items [<!ELEMENT items ANY>]><items burpVersion="2024">
        <item><url><![CDATA[https://t.test/p]]></url><request base64="true"><![CDATA[{b64}]]></request>
          <response base64="true"><![CDATA[SFRUUC8xLjEgMjAw]]></response></item>
        <item><url>https://t.test/q?a=1&amp;b=2</url><request base64="false">GET /q?a=1&amp;b=2 HTTP/1.1&#13;
Host: t.test

</request></item></items>"#
    );
    let r = run(Format::Burp, &xml).unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(r.items[0].method, "POST");
    assert_eq!(r.items[0].body, b"hello");
    assert_eq!(r.items[1].url, "https://t.test/q?a=1&b=2");
}

#[test]
fn burp_xml_entity_attacks_are_refused() {
    let lol = r#"<?xml version="1.0"?><!DOCTYPE items [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]>
        <items><item><url>&b;</url><request>x</request></item></items>"#;
    assert!(matches!(run(Format::Burp, lol), Err(ImportError::Unsupported(_))));
    let ext = r#"<!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]><items><item><url>&x;</url></item></items>"#;
    assert!(run(Format::Burp, ext).is_err());
    // An undeclared entity with no DOCTYPE is refused too.
    assert!(run(Format::Burp, "<items><item><url>&x;</url></item></items>").is_err());
    let deep = "<a>".repeat(1000);
    assert!(run(Format::Burp, &deep).is_err());
}

#[test]
fn graphql_introspection() {
    let schema = r#"{"data":{"__schema":{
      "queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
      "types":[
       {"kind":"OBJECT","name":"Query","fields":[
         {"name":"user","args":[{"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID"}}}],
          "type":{"kind":"OBJECT","name":"User","ofType":null}},
         {"name":"bad name","args":[],"type":{"kind":"SCALAR","name":"String"}}]},
       {"kind":"OBJECT","name":"Mutation","fields":[
         {"name":"setRole","args":[{"name":"role","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"ENUM","name":"Role"}}}],
          "type":{"kind":"SCALAR","name":"Boolean","ofType":null}}]},
       {"kind":"OBJECT","name":"User","fields":[
         {"name":"id","args":[],"type":{"kind":"SCALAR","name":"ID"}},
         {"name":"friends","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"User"}}}]},
       {"kind":"ENUM","name":"Role","enumValues":[{"name":"ADMIN"}]}]}}}"#;
    assert!(matches!(run(Format::Graphql, schema), Err(ImportError::NoBaseUrl)));
    let r = parse(Format::Graphql, schema.as_bytes(), &base("https://t.test/graphql")).unwrap();
    assert_eq!(r.items.len(), 2);
    let q: serde_json::Value = serde_json::from_slice(&r.items[0].body).unwrap();
    assert_eq!(q["query"], "query User($id: ID!) { user(id: $id) { id friends { id } } }");
    assert_eq!(q["variables"]["id"], "1");
    let m: serde_json::Value = serde_json::from_slice(&r.items[1].body).unwrap();
    assert_eq!(m["variables"]["role"], "ADMIN");
    assert_eq!(r.items[1].method, "POST");
}

#[test]
fn wrong_format_is_refused_not_panicked() {
    for f in Format::ALL {
        for junk in ["", "{}", "[]", "null", "<a/>", "\u{0}\u{1}", "{\"log\":1}", "openapi: 3\n"] {
            let _ = run(f, junk);
        }
    }
    assert!(run(Format::Har, "{}").is_err());
}

#[test]
fn item_limit() {
    let many: String = (0..bosun_import::MAX_ITEMS + 5).map(|i| format!("http://h.test/{i}\n")).collect();
    let r = run(Format::Urls, &many).unwrap();
    assert_eq!(r.items.len(), bosun_import::MAX_ITEMS);
    assert_eq!(r.dropped, 5);
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// No input, in any format, panics; whatever is imported is a safe, absolute http(s) request.
        #[test]
        fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000), f in 0usize..6) {
            if let Ok(r) = parse(Format::ALL[f], &data, &Options::default()) {
                for i in r.items {
                    prop_assert!(i.url.starts_with("http://") || i.url.starts_with("https://"));
                    for (k, v) in &i.headers {
                        prop_assert!(!k.contains([':', '\r', '\n']) && !v.contains(['\r', '\n']));
                    }
                    prop_assert!(i.raw().is_some());
                }
            }
        }
    }
}
