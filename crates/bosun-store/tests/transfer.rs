//! Moving project files around: online backup, and importing a file from someone else.

#![allow(clippy::unwrap_used)]

use bosun_model::{FlowSource, Scheme};
use bosun_store::{NewFlow, Project, StoreError, import_foreign};

fn flow(p: &Project, path: &str, body: &[u8]) -> i64 {
    let id = p.next_flow_id();
    let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(body);
    p.write_batch(
        &[NewFlow {
            id,
            source: FlowSource::Proxy,
            started_ms: 1,
            duration_ms: Some(1),
            ttfb_ms: None,
            scheme: Scheme::Https,
            host: "a.test".into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            http_version: "HTTP/1.1".into(),
            status: Some(200),
            in_scope: true,
            edited: false,
            error: None,
            request: b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
            original_request: None,
            response: Some(resp),
            original_response: None,
            response_truncated: false,
        }],
        &[],
    )
    .unwrap();
    id
}

#[test]
fn a_backup_taken_while_the_project_is_in_use_opens_with_everything_in_it() {
    let dir = tempfile::tempdir().unwrap();
    let live = Project::open(&dir.path().join("a.bosun")).unwrap();
    live.set_setting("scope", &serde_json::json!({"include": []}))
        .unwrap();
    let ids: Vec<_> = (0..20)
        .map(|i| flow(&live, &format!("/{i}"), format!("body {i}").as_bytes()))
        .collect();
    let copy = dir.path().join("copy.bosun");
    live.backup_to(&copy).unwrap();
    // The live project goes on being written to; the copy is a snapshot.
    flow(&live, "/after", b"later");
    // A backup never overwrites an existing file.
    assert!(live.backup_to(&copy).is_err());
    drop(live);

    let b = Project::open(&copy).unwrap();
    assert_eq!(b.flow_count().unwrap(), 20);
    assert!(b.setting::<serde_json::Value>("scope").unwrap().is_some());
    let got = b.flow_meta(ids[7]).unwrap().unwrap();
    assert_eq!(got.summary.path, "/7");
}

#[test]
fn an_import_is_rebuilt_into_a_new_file_and_opens() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.bosun");
    let p = Project::open(&src).unwrap();
    flow(&p, "/x", b"hello");
    drop(p);

    let dest = dir.path().join("dest.bosun");
    import_foreign(&src, &dest).unwrap();
    let q = Project::open(&dest).unwrap();
    assert_eq!(q.flow_count().unwrap(), 1);
    // The next flow does not collide with what came in.
    assert!(q.next_flow_id() > 1);
}

#[test]
fn files_that_are_not_ours_are_refused_before_anything_is_copied() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("dest.bosun");

    for (name, bytes) in [
        ("empty.bosun", &b""[..]),
        ("text.bosun", b"this is not a database at all, just text\n"),
    ] {
        let f = dir.path().join(name);
        std::fs::write(&f, bytes).unwrap();
        assert!(
            matches!(import_foreign(&f, &dest).unwrap_err(), StoreError::Untrusted(_)),
            "{name}"
        );
        assert!(!dest.exists(), "{name}: nothing was written");
    }

    // A real SQLite file with someone else's tables.
    let foreign = dir.path().join("foreign.bosun");
    rusqlite::Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE t (a); PRAGMA user_version = 1;")
        .unwrap();
    assert!(matches!(
        import_foreign(&foreign, &dest).unwrap_err(),
        StoreError::Untrusted(_)
    ));
    assert!(!dest.exists());

    // One of ours with a trigger added.
    let evil = dir.path().join("evil.bosun");
    drop(Project::open(&evil).unwrap());
    rusqlite::Connection::open(&evil)
        .unwrap()
        .execute_batch("CREATE TRIGGER t AFTER INSERT ON settings BEGIN DELETE FROM settings; END;")
        .unwrap();
    match import_foreign(&evil, &dest).unwrap_err() {
        StoreError::Untrusted(m) => assert!(m.contains("trigger"), "{m}"),
        e => panic!("{e:?}"),
    }
    assert!(!dest.exists());

    // One from a newer Bosun.
    let newer = dir.path().join("newer.bosun");
    drop(Project::open(&newer).unwrap());
    rusqlite::Connection::open(&newer)
        .unwrap()
        .pragma_update(None, "user_version", 9999)
        .unwrap();
    assert!(matches!(
        import_foreign(&newer, &dest).unwrap_err(),
        StoreError::NewerSchema(9999)
    ));

    // A damaged one: half of a real project file.
    let good = dir.path().join("good.bosun");
    let p = Project::open(&good).unwrap();
    for i in 0..30 {
        flow(&p, &format!("/{i}"), &vec![b'x'; 5000]);
    }
    drop(p);
    let bytes = std::fs::read(&good).unwrap();
    assert!(bytes.len() > 8192);
    let cut = dir.path().join("cut.bosun");
    std::fs::write(&cut, &bytes[..bytes.len() / 2]).unwrap();
    assert!(import_foreign(&cut, &dest).is_err());
}
