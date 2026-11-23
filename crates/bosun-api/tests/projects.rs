//! Projects at run time: create, switch, export, import, rename, delete.

#![allow(clippy::unwrap_used)] // helpers outside #[test] fns

mod common;
use common::*;

use bosun_client::*;

fn url(s: &Stack) -> String {
    format!("http://127.0.0.1:{}", s.api.port())
}

async fn admin(s: &Stack) -> Client {
    let c = Client::new(url(s)).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    c
}

fn names(l: &ProjectList) -> Vec<&str> {
    l.projects.iter().map(|p| p.name.as_str()).collect()
}

fn scope_for(host: &str) -> ScopeSpec {
    serde_json::from_value(serde_json::json!({ "include": [{ "host": host }], "exclude": [] })).unwrap()
}

fn files(s: &Stack) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(s.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn switching_swaps_history_scope_and_tells_clients() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let l = c.list_projects().await.unwrap();
    assert!(l.current.temporary && l.projects.is_empty());

    c.create_project("alpha", false).await.unwrap();
    c.create_project("beta", false).await.unwrap();
    assert_eq!(
        c.create_project("ALPHA", false).await.unwrap_err().status(),
        Some(409)
    );

    let mut ev = c.events(None).await.unwrap();
    assert!(matches!(
        ev.next().await.unwrap().unwrap().event,
        Event::Hello { .. }
    ));
    let pos = ev.position().unwrap().clone();

    // Work in alpha: a scope and a recorded flow.
    let cur = c.open_project("alpha").await.unwrap();
    assert_eq!(cur.name.as_deref(), Some("alpha"));
    let e = loop {
        let e = ev.next().await.unwrap().unwrap();
        if !matches!(e.event, Event::InterceptState { .. }) {
            break e;
        }
    };
    assert!(
        matches!(&e.event, Event::ProjectSwitched { name: Some(n), temporary: false } if n == "alpha"),
        "{e:?}"
    );
    c.put_scope(&scope_for("alpha.example")).await.unwrap();
    recorded(&s, "/a", "", b"hello", None);
    assert_eq!(c.flows(&Default::default()).await.unwrap().len(), 1);
    assert_eq!(
        c.open_project("alpha").await.unwrap_err().status(),
        Some(409),
        "already open"
    );

    // Beta starts empty and open scope; alpha's data is not visible.
    c.open_project("beta").await.unwrap();
    assert!(c.flows(&Default::default()).await.unwrap().is_empty());
    assert!(c.scope().await.unwrap().include.is_empty());
    assert!(!c.intercept().await.unwrap().requests);

    // And comes back as it was.
    c.open_project("alpha").await.unwrap();
    assert_eq!(c.flows(&Default::default()).await.unwrap().len(), 1);
    assert_eq!(c.scope().await.unwrap().include[0].host, "alpha.example");

    let l = c.list_projects().await.unwrap();
    assert_eq!(names(&l), ["alpha", "beta"]);
    assert_eq!(l.recent, ["alpha", "beta"]);
    assert_eq!(l.current.name.as_deref(), Some("alpha"));

    // A position from before the switches means nothing now.
    drop(ev);
    let mut ev = c.events(Some(&pos)).await.unwrap();
    assert!(matches!(
        ev.next().await.unwrap().unwrap().event,
        Event::Hello { .. }
    ));
    assert!(matches!(ev.next().await.unwrap().unwrap().event, Event::Reload));

    // Closing opens a temporary project.
    let cur = c.close_project().await.unwrap();
    assert!(cur.temporary);
    assert!(c.flows(&Default::default()).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_project_that_cannot_be_opened_leaves_the_open_one_alone() {
    let s = stack(true).await;
    let c = admin(&s).await;
    c.create_project("good", true).await.unwrap();
    recorded(&s, "/keep", "", b"x", None);

    // Damaged file.
    std::fs::write(s.dir.path().join("bad.bosun"), b"this is not a database at all").unwrap();
    assert_eq!(c.open_project("bad").await.unwrap_err().status(), Some(422));
    // Locked by another opener.
    c.create_project("busy", false).await.unwrap();
    let held = bosun_store::Project::open(&s.dir.path().join("busy.bosun")).unwrap();
    assert_eq!(c.open_project("busy").await.unwrap_err().status(), Some(409));
    drop(held);
    // No such project.
    assert_eq!(c.open_project("nothing").await.unwrap_err().status(), Some(404));

    let l = c.list_projects().await.unwrap();
    assert_eq!(l.current.name.as_deref(), Some("good"));
    assert_eq!(c.flows(&Default::default()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn export_and_import_round_trip_and_hostile_files_are_refused() {
    let s = stack(true).await;
    let c = admin(&s).await;
    c.create_project("src", true).await.unwrap();
    c.put_scope(&scope_for("src.example")).await.unwrap();
    recorded(&s, "/one", "", b"first", None);
    recorded(&s, "/two", "", b"second", None);

    // The open project exports as a consistent copy.
    let bytes = c.export_project("src").await.unwrap();
    assert!(bytes.starts_with(b"SQLite format 3\0"));
    let info = c.import_project("copy", bytes.clone(), true).await.unwrap();
    assert_eq!(info.name, "copy");
    assert!(info.current);
    assert_eq!(c.flows(&Default::default()).await.unwrap().len(), 2);
    assert_eq!(c.scope().await.unwrap().include[0].host, "src.example");
    assert_eq!(
        c.import_project("copy", bytes.clone(), false)
            .await
            .unwrap_err()
            .status(),
        Some(409)
    );

    // Refused: junk, empty, wrong names. Nothing is left behind.
    let before = files(&s);
    for junk in [b"junk".to_vec(), vec![0u8; 4096], b"SQLite format 3\0".to_vec()] {
        let e = c.import_project("hostile", junk, false).await.unwrap_err();
        assert!(matches!(e.status(), Some(400 | 422)), "{e}");
    }
    assert_eq!(
        c.import_project("empty", Vec::new(), false)
            .await
            .unwrap_err()
            .status(),
        Some(400)
    );
    for bad in ["../escape", "a/b", "CON", ".hidden", "", "import", "x\u{0}y"] {
        let e = c.import_project(bad, bytes.clone(), false).await.unwrap_err();
        assert!(matches!(e.status(), Some(400 | 404)), "{bad:?}: {e}");
    }
    assert_eq!(files(&s), before, "failed imports leave no files");
    assert!(!s.dir.path().parent().unwrap().join("escape.bosun").exists());

    // A database that is valid SQLite but is not a project (wrong tables, a trigger that would run).
    let evil = {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("evil.db");
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE notes(a); CREATE TRIGGER t AFTER INSERT ON notes BEGIN SELECT load_extension('x'); END;",
        )
        .unwrap();
        drop(conn);
        std::fs::read(&p).unwrap()
    };
    let e = c.import_project("evil", evil, false).await.unwrap_err();
    assert_eq!(e.status(), Some(422), "{e}");
    assert_eq!(files(&s), before);

    let log = c.audit(None, Some(100)).await.unwrap();
    let actions: Vec<&str> = log.iter().map(|a| a.action.as_str()).collect();
    for a in [
        "project.create",
        "project.open",
        "project.export",
        "project.import",
        "project.import.refused",
    ] {
        assert!(actions.contains(&a), "{a} missing from {actions:?}");
    }
}

#[tokio::test]
async fn rename_delete_and_backup_follow_the_rules() {
    let s = stack(true).await;
    let c = admin(&s).await;
    c.create_project("one", true).await.unwrap();
    c.create_project("two", false).await.unwrap();

    assert_eq!(
        c.rename_project("one", "uno").await.unwrap_err().status(),
        Some(409),
        "open"
    );
    assert_eq!(
        c.delete_project("one").await.unwrap_err().status(),
        Some(409),
        "open"
    );
    assert_eq!(
        c.rename_project("two", "one").await.unwrap_err().status(),
        Some(409),
        "taken"
    );
    assert_eq!(
        c.rename_project("two", "../x").await.unwrap_err().status(),
        Some(400)
    );
    assert_eq!(
        c.rename_project("ghost", "x").await.unwrap_err().status(),
        Some(404)
    );
    assert_eq!(c.rename_project("two", "dos").await.unwrap().name, "dos");

    let b = c.backup_project("one").await.unwrap();
    assert!(
        std::path::Path::new(&b.path).starts_with(s.dir.path().join("backups")),
        "{}",
        b.path
    );
    assert!(b.size_bytes > 0);
    // A backup is a project that opens.
    assert!(bosun_store::Project::open(std::path::Path::new(&b.path)).is_ok());

    c.delete_project("dos").await.unwrap();
    assert_eq!(c.delete_project("dos").await.unwrap_err().status(), Some(404));
    let l = c.list_projects().await.unwrap();
    assert_eq!(names(&l), ["one"]);
    assert!(!l.recent.contains(&"dos".to_string()));
    assert!(files(&s).iter().all(|f| !f.starts_with("dos")), "{:?}", files(&s));
}

#[tokio::test]
async fn only_admins_manage_projects() {
    let s = stack(true).await;
    let c = admin(&s).await;
    c.create_project("p", false).await.unwrap();
    c.create_user("tess", "a tester password!", Role::Tester)
        .await
        .unwrap();
    c.create_user("vic", "a viewer password!", Role::Viewer)
        .await
        .unwrap();
    for (user, pw) in [("tess", "a tester password!"), ("vic", "a viewer password!")] {
        let u = Client::new(url(&s)).unwrap();
        u.login(user, pw).await.unwrap();
        assert_eq!(
            u.list_projects().await.unwrap().projects.len(),
            1,
            "everyone can list"
        );
        assert!(u.create_project("x", false).await.unwrap_err().is_forbidden());
        assert!(u.open_project("p").await.unwrap_err().is_forbidden());
        assert!(u.close_project().await.unwrap_err().is_forbidden());
        assert!(u.export_project("p").await.unwrap_err().is_forbidden());
        assert!(u.backup_project("p").await.unwrap_err().is_forbidden());
        assert!(u.rename_project("p", "q").await.unwrap_err().is_forbidden());
        assert!(u.delete_project("p").await.unwrap_err().is_forbidden());
        assert!(
            u.import_project("z", b"x".to_vec(), false)
                .await
                .unwrap_err()
                .is_forbidden()
        );
    }
    let anon = Client::new(url(&s)).unwrap();
    assert!(anon.list_projects().await.unwrap_err().is_unauthorized());
}
