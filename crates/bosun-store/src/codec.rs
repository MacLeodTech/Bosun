//! Content-Encoding decoding for display and search, with a hard cap on output size so a decompression bomb in
//! a target's response cannot exhaust memory.

use std::io::{BufRead, Read};

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

/// Why a stream cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Unsupported(String),
}

/// Undo a Content-Encoding as the bytes are read, so a large body is never held whole. The result is not capped:
/// wrap it in `take`. `Ok(None)` means the body is not encoded.
pub fn stream_decoder<'a, R: Read + 'a>(
    content_encoding: Option<&str>,
    body: R,
) -> Result<Option<Box<dyn Read + 'a>>, StreamError> {
    let Some(ce) = content_encoding.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let codings: Vec<String> = ce.split(',').map(|c| c.trim().to_ascii_lowercase()).collect();
    if codings.iter().all(|c| c == "identity") {
        return Ok(None);
    }
    let mut r: Box<dyn Read + 'a> = Box::new(body);
    for c in codings.iter().rev() {
        r = match c.as_str() {
            "identity" => r,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(r)),
            "deflate" => {
                // Servers send either zlib-wrapped or raw deflate under this name; the zlib header says which.
                let mut buf = std::io::BufReader::new(r);
                let head = buf
                    .fill_buf()
                    .map(|b| b.get(..2).map(|h| [h[0], h[1]]))
                    .unwrap_or(None);
                let zlib = head.is_some_and(|[cmf, flg]| {
                    cmf & 0x0f == 8 && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
                });
                if zlib {
                    Box::new(flate2::bufread::ZlibDecoder::new(buf))
                } else {
                    Box::new(flate2::bufread::DeflateDecoder::new(buf))
                }
            }
            "br" => Box::new(brotli::Decompressor::new(r, 8192)),
            "zstd" => match zstd::stream::read::Decoder::new(r) {
                Ok(d) => Box::new(d),
                Err(e) => return Err(StreamError::Unsupported(format!("zstd: {e}"))),
            },
            other => return Err(StreamError::Unsupported(other.to_string())),
        };
    }
    Ok(Some(r))
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
    fn streaming_matches_the_buffered_decoder() {
        let text: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&text).unwrap();
            e.finish().unwrap()
        };
        let zl = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&text).unwrap();
            e.finish().unwrap()
        };
        let raw_deflate = {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&text).unwrap();
            e.finish().unwrap()
        };
        let mut br = Vec::new();
        brotli::CompressorWriter::new(&mut br, 4096, 5, 22)
            .write_all(&text)
            .unwrap();
        let zs = zstd::encode_all(&text[..], 3).unwrap();
        // gzip applied after br, as `Content-Encoding: br, gzip` says.
        let both = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&br).unwrap();
            e.finish().unwrap()
        };
        for (ce, data) in [
            ("gzip", &gz),
            ("deflate", &zl),
            ("deflate", &raw_deflate),
            ("br", &br),
            ("zstd", &zs),
            ("br, gzip", &both),
        ] {
            let mut out = Vec::new();
            stream_decoder(Some(ce), &data[..])
                .unwrap()
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, text, "{ce}");
        }
        assert!(stream_decoder(None, &b""[..]).unwrap().is_none());
        assert!(stream_decoder(Some("identity"), &b""[..]).unwrap().is_none());
        assert!(stream_decoder(Some("compress"), &b""[..]).is_err());
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
