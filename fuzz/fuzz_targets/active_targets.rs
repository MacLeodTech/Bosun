//! A scan target (URL, query, form or JSON body, cookies, headers) comes from the user or from a crawled page:
//! parsing it, listing its insertion points and rebuilding the request with a value in each must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (url, rest) = text.split_once('\n').unwrap_or((&text, ""));
    let (cookie, body) = rest.split_once('\n').unwrap_or((rest, ""));
    for content_type in [None, Some("application/json"), Some("text/plain")] {
        let t = bosun_active::Target {
            method: None,
            url: url.to_string(),
            headers: vec![("Cookie".into(), cookie.to_string())],
            body: Some(body.to_string()),
            content_type: content_type.map(String::from),
        };
        let Ok(req) = bosun_active::Req::from_target(&t, &[]) else { continue };
        for p in req.points(bosun_active::Strength::High) {
            let _ = req.label(&p);
            let v = req.value(&p);
            let _ = req.bytes(Some((&p, &format!("{v}'\"<>;\r\n"))));
        }
        let _ = req.bytes(None);
    }
});
