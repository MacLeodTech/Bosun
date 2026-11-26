//! The Intruder's inputs: a request with position markers, and a payload set (JSON) with its processing rules.
//! Neither may panic or run away: a template that parses renders back to the request without its markers, and
//! every payload and request a plan hands out is bounded.
#![no_main]
use bosun_intruder::{AttackType, MAX_PAYLOAD, MAX_TEMPLATE, PayloadSet, Plan, Template};
use libfuzzer_sys::fuzz_target;

const MARK: &[u8] = "§".as_bytes();

fn without_marks(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(MARK) {
            i += MARK.len();
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (raw, spec) = data.split_at(split);
    let template = Template::parse(raw);
    if let Ok(t) = &template {
        assert_eq!(t.base(), without_marks(raw));
    }
    let Ok(set) = serde_json::from_slice::<PayloadSet>(spec) else { return };
    let Ok(compiled) = set.compile() else { return };
    for i in 0..compiled.len().min(16) {
        if let Some(p) = compiled.get(i) {
            assert!(p.len() <= MAX_PAYLOAD);
        }
    }
    let Ok(t) = template else { return };
    for kind in [AttackType::Sniper, AttackType::BatteringRam] {
        if let Ok(plan) = Plan::new(t.clone(), kind, std::slice::from_ref(&set)) {
            for i in 0..plan.total().min(16) {
                if let Some(job) = plan.job(i) {
                    assert!(job.request.len() <= MAX_TEMPLATE + t.positions() * MAX_PAYLOAD);
                }
            }
        }
    }
});
