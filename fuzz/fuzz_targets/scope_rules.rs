//! Scope rules typed by the user (or loaded from a project file): compiling and matching must not panic or hang.
//! The input is split on NUL into host, path pattern and a target to test.
#![no_main]
use bosun_model::Scheme;
use bosun_scope::{RuleSpec, Scope, ScopeSpec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\0');
    let host = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let target_host = parts.next().unwrap_or("");
    let target_path = parts.next().unwrap_or("");
    let rule = RuleSpec {
        host,
        path: Some(path),
        ..Default::default()
    };
    if let Ok(scope) = Scope::compile(ScopeSpec {
        include: vec![rule.clone()],
        exclude: vec![rule],
    }) {
        // The same rule included and excluded can never match.
        assert!(!scope.contains(Scheme::Https, target_host, 443, target_path));
    }
});
