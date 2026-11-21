//! Content-Encoding decoding for display and search, with a hard cap on output size so a decompression bomb in
//! a target's response cannot exhaust memory.

use std::io::Read;

/// Default cap on decoded output (32 MiB).
pub const DEFAULT_DECODE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// Not encoded (or `identity`).
    Plain,
    Ok {
        data: Vec<u8>,
        truncated: bool,
    },
    Unsupported(String),
    Failed(String),
}

/// Decode `body` according to a Content-Encoding header value (possibly a list such as `gzip, br`).
pub fn decode(content_encoding: Option<&str>, body: &[u8], limit: usize) -> Decoded {
    let Some(ce) = content_encoding.map(str::trim).filter(|s| !s.is_empty()) else {
        return Decoded::Plain;
    };
    let codings: Vec<String> = ce.split(',').map(|c| c.trim().to_ascii_lowercase()).collect();
    if codings.iter().all(|c| c == "identity") {
        return Decoded::Plain;
    }
    let mut data = body.to_vec();
    let mut truncated = false;
    // Codings are listed in the order they were applied, so undo them in reverse.
    for c in codings.iter().rev() {
        let result = match c.as_str() {
            "identity" => continue,
            "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(&data[..]), limit),
            "deflate" => {
                // Servers send either zlib-wrapped or raw deflate under this name.
                read_capped(flate2::read::ZlibDecoder::new(&data[..]), limit)
                    .or_else(|_| read_capped(flate2::read::DeflateDecoder::new(&data[..]), limit))
            }
            "br" => read_capped(brotli::Decompressor::new(&data[..], 8192), limit),
            "zstd" => match zstd::stream::read::Decoder::new(&data[..]) {
                Ok(d) => read_capped(d, limit),
                Err(e) => Err(e),
            },
            other => return Decoded::Unsupported(other.to_string()),
        };
        match result {
            Ok((d, t)) => {
                data = d;
                truncated |= t;
            }
            Err(e) => return Decoded::Failed(format!("{c}: {e}")),
        }
    }
    Decoded::Ok { data, truncated }
}

fn read_capped(r: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let n = r.take(limit as u64 + 1).read_to_end(&mut out)?;
    if n > limit {
        out.truncate(limit);
        Ok((out, true))
    } else {
        Ok((out, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn decodes_gzip_and_caps_bombs() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![b'a'; 1_000_000]).unwrap();
        let gz = e.finish().unwrap();
        match decode(Some("gzip"), &gz, 1000) {
            Decoded::Ok { data, truncated } => {
                assert_eq!(data.len(), 1000);
                assert!(truncated);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(decode(None, b"x", 10), Decoded::Plain);
        assert!(matches!(
            decode(Some("gzip"), b"not gzip", 10),
            Decoded::Failed(_)
        ));
        assert!(matches!(
            decode(Some("compress"), b"x", 10),
            Decoded::Unsupported(_)
        ));
    }

    #[test]
    fn decodes_brotli_and_zstd() {
        let mut br = Vec::new();
        brotli::CompressorWriter::new(&mut br, 4096, 5, 22)
            .write_all(b"hello")
            .unwrap();
        assert_eq!(
            decode(Some("br"), &br, 100),
            Decoded::Ok {
                data: b"hello".to_vec(),
                truncated: false
            }
        );
        let z = zstd::encode_all(&b"hello"[..], 3).unwrap();
        assert_eq!(
            decode(Some("zstd"), &z, 100),
            Decoded::Ok {
                data: b"hello".to_vec(),
                truncated: false
            }
        );
    }
}
