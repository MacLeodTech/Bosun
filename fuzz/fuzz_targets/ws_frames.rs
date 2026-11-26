//! WebSocket frames from a hostile peer, fed in arbitrary pieces, then through the `permessage-deflate`
//! inflater, plus the extension header. The first byte picks the record limit, the second the chunk size.
#![no_main]
use bosun_proxy::ws::{DeflateParams, FrameParser, Inflater};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [limit, chunk, rest @ ..] = data else { return };
    let limit = usize::from(*limit) + 1;
    let mut parser = FrameParser::new(limit);
    let mut inflater = Inflater::new(limit % 2 == 0, limit);
    for piece in rest.chunks(usize::from(*chunk) + 1) {
        for frame in parser.feed(piece) {
            assert!(frame.payload.len() <= limit);
            let _ = inflater.process(frame);
        }
    }
    if let Ok(s) = std::str::from_utf8(rest) {
        let _ = DeflateParams::from_header(s);
    }
});
