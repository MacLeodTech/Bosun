//! `bosun decode`: the Decoder's chain on stdin or a file, with no engine running.

#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn decode(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bosun"))
        .arg("decode")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The child may exit before reading everything (an unknown operation): a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

#[test]
fn a_chain_runs_in_order_and_writes_the_bytes() {
    let o = decode(&["base64_decode", "sha1"], b"aGVsbG8=");
    assert!(o.status.success());
    assert_eq!(o.stdout, b"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");

    // Compress and decompress through the pipe: the bytes come back unchanged, binary included.
    let gz = decode(&["gzip_encode"], &[0, 1, 2, 255, 254]);
    assert!(gz.status.success());
    let back = decode(&["gzip_decode"], &gz.stdout);
    assert_eq!(back.stdout, [0, 1, 2, 255, 254]);
    assert_eq!(
        decode(&["md5"], b"abc").stdout,
        b"900150983cd24fb0d6963f7d28e17f72"
    );
}

#[test]
fn smart_decoding_names_the_layers_it_peeled() {
    let o = decode(&["--smart"], b"aGVsbG8=");
    assert_eq!(o.stdout, b"hello");
    assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), "base64_decode");
}

#[test]
fn failures_say_which_step_and_leave_stdout_empty() {
    let o = decode(&["base64_encode", "gzip_decode"], b"not gzip");
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(String::from_utf8_lossy(&o.stderr).contains("step 2 (gzip_decode)"));

    let bad = decode(&["rot13"], b"x");
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown operation `rot13`"));

    let too_big = decode(&["--limit", "4", "hex_encode"], b"abc");
    assert_eq!(too_big.status.code(), Some(2));
    let both = decode(&["--smart", "hex_encode"], b"abc");
    assert!(!both.status.success());
}

#[test]
fn list_names_every_operation() {
    let o = decode(&["--list"], b"");
    let text = String::from_utf8(o.stdout).unwrap();
    for name in [
        "url_decode",
        "gzip_encode",
        "brotli_encode",
        "zstd_encode",
        "md5",
        "sha1",
        "sha512",
    ] {
        assert!(text.lines().any(|l| l == name), "{name} is missing:\n{text}");
    }
    assert_eq!(text.lines().count(), 26);
}
