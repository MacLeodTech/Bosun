//! WebSocket frames from a hostile peer, fed in arbitrary pieces. The first byte picks the record limit, the
//! second the chunk size.
#![no_main]
use bosun_proxy::ws::FrameParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [limit, chunk, rest @ ..] = data else { return };
    let limit = usize::from(*limit) + 1;
    let mut parser = FrameParser::new(limit);
    for piece in rest.chunks(usize::from(*chunk) + 1) {
        for frame in parser.feed(piece) {
            assert!(frame.payload.len() <= limit);
        }
    }
});
