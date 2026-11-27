//! Protobuf, gRPC frames and GraphQL bodies from a hostile peer, and the text forms read back: no panic, no
//! output over the limit, and text that decoded always encodes again. The first byte picks the limit.
#![no_main]
use bosun_codec::{graphql, proto};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [lim, rest @ ..] = data else { return };
    let limit = usize::from(*lim) * 64;
    if let Ok(t) = proto::decode_text(rest, limit) {
        assert!(proto::encode_text(t.as_bytes(), usize::MAX / 2).is_ok());
    }
    if let Ok(t) = proto::grpc_decode(rest, limit) {
        assert!(proto::grpc_encode(t.as_bytes(), usize::MAX / 2).is_ok());
    }
    if let Ok(o) = proto::encode_text(rest, limit) {
        assert!(o.len() <= limit);
    }
    if let Ok(o) = proto::grpc_encode(rest, limit) {
        assert!(o.len() <= limit + 5);
    }
    let _ = graphql::decode_text(rest, limit);
    let _ = graphql::has_operation(rest, "x");
});
