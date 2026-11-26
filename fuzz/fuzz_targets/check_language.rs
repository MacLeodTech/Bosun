//! The check language and the Nuclei importer read documents that may come from anyone, and the matchers run on
//! whatever a target sends: none of it may panic, hang or blow up on YAML aliases.
#![no_main]
use bosun_checks::lang::{Message, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the input into a document and a message to match it against.
    let (head, tail) = data.split_at(data.first().map_or(0, |b| (*b as usize).min(data.len())));
    let text = String::from_utf8_lossy(head);
    let msg = Message { request: tail, response: tail, status: 200, interaction: None };
    if let Ok(c) = parse(&text) {
        let _ = c.eval_passive(&msg);
        for i in 0..c.check.requests.len() {
            let _ = c.eval_request(i, &msg);
        }
        let _ = c.uses_oast();
    }
    if let Ok(c) = bosun_checks::nuclei::import(&text) {
        for i in 0..c.check.requests.len() {
            let _ = c.eval_request(i, &msg);
        }
    }
    for c in bosun_checks::passive::builtin() {
        let _ = c.eval_passive(&msg);
    }
});
