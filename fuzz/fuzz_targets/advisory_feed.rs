//! An advisory feed is a file from outside (signed, but the signature is checked first and the content is still
//! parsed): reading, checking, versions and matching must never panic, whatever the bytes.
#![no_main]
use bosun_checks::advisory::{AdvisoryDb, Feed, Version};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(feed) = serde_json::from_slice::<Feed>(data) {
        if feed.check().is_ok() {
            let db = AdvisoryDb::from_feed(feed);
            for v in ["0", "1.2.3", "99999999.1", "2.4.49-1ubuntu"] {
                if let Some(v) = Version::parse(v) {
                    for a in &db.advisories {
                        let _ = a.affects(&v);
                    }
                }
            }
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Version::parse(s);
    }
});
