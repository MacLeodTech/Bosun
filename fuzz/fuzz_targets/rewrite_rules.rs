//! Match-and-replace rules (regexes written by the user, applied to hostile traffic): compiling and applying
//! must not panic. The input is split on NUL into pattern, replacement and a message.
#![no_main]
use bosun_proxy::{RuleSet, RuleSpec, RuleTarget};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |b| *b == 0);
    let pattern = String::from_utf8_lossy(parts.next().unwrap_or(b"")).into_owned();
    let replace = String::from_utf8_lossy(parts.next().unwrap_or(b"")).into_owned();
    let message = parts.next().unwrap_or(b"");
    for target in [
        RuleTarget::RequestHeader,
        RuleTarget::RequestBody,
        RuleTarget::ResponseHeader,
        RuleTarget::ResponseBody,
    ] {
        for regex in [false, true] {
            let spec = RuleSpec {
                enabled: true,
                target,
                pattern: pattern.clone(),
                replace: replace.clone(),
                regex,
                comment: String::new(),
            };
            if let Ok(set) = RuleSet::compile(vec![spec]) {
                let _ = set.apply_request(message);
                let _ = set.apply_response(message, true);
            }
        }
    }
});
