//! Protobuf, gRPC frames, GraphQL bodies and `.proto` schemas from a hostile peer, and the text forms read back: no
//! panic, no output over the limit, and text that decoded always encodes again, with a schema or without. The first
//! byte picks the limit; the rest is split in two, one half a schema source and the other half the data.
#![no_main]
use bosun_codec::{Schema, graphql, proto};
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

    // A schema from the first half; its first message types the second half.
    let (src, body) = rest.split_at(rest.len() / 2);
    if let Ok(schema) = Schema::parse(&String::from_utf8_lossy(src)) {
        let _ = schema.rpc("/a.B/c");
        let Some(name) = schema.message_names().into_iter().next() else { return };
        let typed = schema.typed(&name);
        if let Ok(t) = proto::decode_text_with(body, limit, typed) {
            assert!(proto::encode_text_with(t.as_bytes(), usize::MAX / 2, typed).is_ok());
        }
        if let Ok(t) = proto::grpc_decode_with(body, limit, typed) {
            assert!(proto::grpc_encode_with(t.as_bytes(), usize::MAX / 2, typed).is_ok());
        }
        // Text written by hand against the schema: any error is fine, a panic is not.
        let _ = proto::encode_text_with(body, limit, typed);
    }
});
