//! `bosun advisory keygen|sign`: a signature made here is accepted by the engine's own verification, and a feed the
//! engine would refuse is not signed.

#![allow(clippy::unwrap_used)]

use std::process::Command;

fn bosun(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bosun"))
        .arg("advisory")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn a_feed_signed_by_the_cli_verifies_in_the_engine_and_junk_is_not_signed() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("feed.key");
    let feed = dir.path().join("feed.json");
    let out = bosun(&["keygen", key.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let public = String::from_utf8(out.stdout).unwrap().trim().to_string();
    // The private key is never written over an existing file.
    assert!(!bosun(&["keygen", key.to_str().unwrap()]).status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let text = r#"{"schema":1,"sequence":4,"generated":"2026-11-28","advisories":[{"id":"T-1","product":"acme","summary":"s","severity":"low","ranges":[{"fixed":"2"}]}]}"#;
    std::fs::write(&feed, text).unwrap();
    let out = bosun(&["sign", key.to_str().unwrap(), feed.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let sig = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let (f, _) = bosun_checks::advisory::verify(text.as_bytes(), &sig, &[public]).unwrap();
    assert_eq!(f.sequence, 4);

    std::fs::write(&feed, text.replace("\"low\"", "\"scary\"")).unwrap();
    let out = bosun(&["sign", key.to_str().unwrap(), feed.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("severity"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
