//! Raw HTTP messages as a user (or a hostile project file) could write them: parsing must not panic, and a
//! message that parses must serialise and parse again to the same message.
#![no_main]
use bosun_model::{RawRequest, RawResponse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = RawRequest::parse(data) {
        assert_eq!(RawRequest::parse(&req.to_bytes()).as_ref(), Ok(&req));
    }
    if let Ok(resp) = RawResponse::parse(data) {
        assert_eq!(RawResponse::parse(&resp.to_bytes()).as_ref(), Ok(&resp));
    }
});
