//! The local admin commands (`project`, `token`, `audit`, `user role|delete|sessions`, completions, man pages and
//! `serve --no-ui`) run as the real binary against a temporary data directory.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

struct Bosun<'a>(&'a Path);

impl Bosun<'_> {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bosun"));
        c.args(["--data-dir", self.0.to_str().unwrap()]).args(args);
        c
    }
    /// Run with `input` on stdin (not a terminal).
    fn run_in(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }
    fn run(&self, args: &[&str]) -> Output {
        self.run_in(args, "")
    }
    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert!(
            o.status.success(),
            "{args:?}: {}{}",
            text(&o.stdout),
            text(&o.stderr)
        );
        text(&o.stdout)
    }
    fn json(&self, args: &[&str]) -> serde_json::Value {
        serde_json::from_str(&self.ok(args)).unwrap()
    }
    fn add_user(&self, name: &str, role: &str) {
        let o = self.run_in(
            &["user", "add", name, "--role", role],
            "correct horse battery staple\n",
        );
        assert!(o.status.success(), "{}", text(&o.stderr));
    }
    fn audit_actions(&self) -> Vec<String> {
        self.json(&["audit", "--json", "-n", "500"])
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap().to_string())
            .collect()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

#[test]
fn project_lifecycle_with_audit() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    assert_eq!(b.json(&["project", "list", "--json"]), serde_json::json!([]));

    b.ok(&["project", "create", "alpha"]);
    b.ok(&["project", "create", "beta"]);
    let dup = b.run(&["project", "create", "ALPHA"]);
    assert_eq!(code(&dup), 1);
    assert!(text(&dup.stderr).contains("already exists"));
    let bad = b.run(&["project", "create", "../evil"]);
    assert_eq!(code(&bad), 1);

    let list = b.json(&["project", "list", "--json"]);
    let names: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert_eq!(list[0]["locked"], false);
    assert!(list[0]["size_bytes"].as_u64().unwrap() > 0);
    assert!(b.ok(&["project", "list"]).contains("alpha"));

    b.ok(&["project", "rename", "alpha", "gamma"]);
    assert_eq!(code(&b.run(&["project", "rename", "alpha", "x"])), 4);
    let clash = b.run(&["project", "rename", "gamma", "beta"]);
    assert_eq!(code(&clash), 1);

    // Backup: default place, and a chosen file; a file that exists is not overwritten.
    let bk = b.json(&["project", "backup", "gamma", "--json"]);
    let path = bk["path"].as_str().unwrap();
    assert!(path.contains("backups") && Path::new(path).is_file());
    let out = d.path().join("copy.bosun");
    b.ok(&["project", "export", "gamma", "--out", out.to_str().unwrap()]);
    assert!(out.is_file());
    assert_eq!(
        code(&b.run(&["project", "export", "gamma", "--out", out.to_str().unwrap()])),
        1
    );
    assert_eq!(code(&b.run(&["project", "export", "nope", "--out", "/x/y"])), 4);

    // Import the export under a new name (round trip), by default name and by --name.
    b.ok(&["project", "import", out.to_str().unwrap(), "--name", "imported"]);
    b.ok(&["project", "import", out.to_str().unwrap()]);
    let n = b.json(&["project", "list", "--json"]).as_array().unwrap().len();
    assert_eq!(n, 4);
    assert_eq!(
        code(&b.run(&["project", "import", out.to_str().unwrap(), "--name", "imported"])),
        1
    );
    // No stray temporary files in the projects folder.
    for e in std::fs::read_dir(d.path().join("projects")).unwrap() {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.starts_with('.'), "left behind: {name}");
    }

    // Delete needs confirmation when there is no terminal.
    let refused = b.run(&["project", "delete", "beta"]);
    assert_eq!(code(&refused), 5);
    assert!(text(&refused.stderr).contains("--yes"));
    assert!(d.path().join("projects/beta.bosun").exists());
    b.ok(&["project", "delete", "beta", "--yes"]);
    assert!(!d.path().join("projects/beta.bosun").exists());
    assert_eq!(code(&b.run(&["project", "delete", "beta", "--yes"])), 4);

    let actions = b.audit_actions();
    for a in [
        "project.create",
        "project.rename",
        "project.backup",
        "project.export",
        "project.import",
        "project.delete",
    ] {
        assert!(actions.iter().any(|x| x == a), "no audit entry {a}: {actions:?}");
    }
    let creates = b.json(&["audit", "--json", "--action", "project.c"]);
    assert_eq!(creates.as_array().unwrap().len(), 2);
    assert!(creates[0]["detail"].as_str().unwrap().ends_with("via CLI"));
}

#[test]
fn hostile_import_is_refused_and_audited() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    let junk = d.path().join("junk.bosun");
    std::fs::write(&junk, b"this is not a database at all, not even close").unwrap();
    let o = b.run(&["project", "import", junk.to_str().unwrap()]);
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("not a usable Bosun project"),
        "{}",
        text(&o.stderr)
    );
    assert!(!d.path().join("projects/junk.bosun").exists());
    assert!(b.audit_actions().contains(&"project.import.refused".to_string()));
    assert_eq!(code(&b.run(&["project", "import", "/no/such/file.bosun"])), 1);
}

/// A running engine holds its project; the commands that need the file say so and exit 3.
#[test]
fn refused_while_a_running_engine_has_the_project() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    b.ok(&["project", "create", "spare"]);
    let mut engine = b
        .cmd(&["serve", "--embedded"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(engine.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("api_url"));

    let list = b.json(&["project", "list", "--json"]);
    let locked: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["locked"].as_bool().unwrap()))
        .collect();
    assert_eq!(locked, [("default", true), ("spare", false)]);

    for args in [
        &["project", "rename", "default", "x"][..],
        &["project", "delete", "default", "--yes"],
        &["project", "backup", "default"],
        &[
            "project",
            "export",
            "default",
            "--out",
            "/tmp/never-written.bosun",
        ],
    ] {
        let o = b.run(args);
        assert_eq!(code(&o), 3, "{args:?}: {}", text(&o.stderr));
        assert!(
            text(&o.stderr).contains("another Bosun process"),
            "{}",
            text(&o.stderr)
        );
    }
    assert!(d.path().join("projects/default.bosun").exists());
    // The other project, and the accounts, are still manageable.
    b.ok(&["project", "rename", "spare", "spare2"]);
    b.add_user("alice", "admin");

    drop(engine.stdin.take());
    engine.wait().unwrap();
    b.ok(&["project", "backup", "default"]);
}

#[test]
fn users_roles_sessions_and_tokens() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    b.add_user("alice", "admin");
    b.add_user("bob", "tester");

    let users = b.json(&["user", "list", "--json"]);
    assert_eq!(users.as_array().unwrap().len(), 2);
    assert!(b.ok(&["user", "list"]).contains("bob"));

    // Roles: change, the last admin is protected, unknown users and roles are errors.
    b.ok(&["user", "role", "bob", "viewer"]);
    assert_eq!(b.json(&["user", "list", "--json"])[1]["role"], "viewer");
    let last = b.run(&["user", "role", "alice", "tester"]);
    assert_eq!(code(&last), 1);
    assert!(text(&last.stderr).contains("last admin"));
    assert_eq!(code(&b.run(&["user", "role", "nobody", "admin"])), 4);
    assert_eq!(code(&b.run(&["user", "role", "bob", "root"])), 2);

    // Sessions: none yet.
    assert_eq!(
        b.json(&["user", "sessions", "bob", "--json"]),
        serde_json::json!([])
    );
    let r = b.json(&["user", "sessions", "bob", "--revoke", "--json"]);
    assert_eq!(r["revoked"], 0);
    assert_eq!(code(&b.run(&["user", "sessions", "nobody"])), 4);

    // Tokens.
    let tok = b.json(&[
        "token",
        "create",
        "bob",
        "--name",
        "ci",
        "--scope",
        "read",
        "--expires-days",
        "30",
        "--json",
    ]);
    let secret = tok["token"].as_str().unwrap();
    assert!(secret.starts_with("bosun_"));
    assert_eq!(tok["info"]["scope"], "read");
    assert!(tok["info"]["expires_ms"].is_number());
    let plain = b.ok(&["token", "create", "alice", "--name", "full"]);
    assert!(plain.trim().starts_with("bosun_") && plain.trim().lines().count() == 1);
    assert_eq!(code(&b.run(&["token", "create", "ghost", "--name", "x"])), 4);
    assert_eq!(
        code(&b.run(&["token", "create", "bob", "--name", "x", "--expires-days", "0"])),
        1
    );

    let all = b.json(&["token", "list", "--json"]);
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(all[0]["username"], "alice");
    assert!(
        !b.ok(&["token", "list", "bob", "--json"]).contains(secret),
        "tokens are not stored"
    );
    assert_eq!(
        b.json(&["token", "list", "alice", "--json"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(b.ok(&["token", "list"]).contains("ci"));

    let id = tok["info"]["id"].as_i64().unwrap().to_string();
    b.ok(&["token", "revoke", &id]);
    assert_eq!(code(&b.run(&["token", "revoke", &id])), 4);
    assert_eq!(b.json(&["token", "list", "--json"]).as_array().unwrap().len(), 1);

    // Deleting a user needs confirmation, and takes their tokens along.
    assert_eq!(code(&b.run(&["user", "delete", "alice"])), 5);
    let o = b.run(&["user", "delete", "alice", "--yes"]);
    assert_eq!(code(&o), 1, "the last admin stays");
    b.ok(&["user", "delete", "bob", "--yes"]);
    assert_eq!(code(&b.run(&["user", "delete", "bob", "--yes"])), 4);

    let actions = b.audit_actions();
    for a in [
        "user.role",
        "token.create",
        "token.revoke",
        "user.delete",
        "session.revoke_all",
    ] {
        assert!(actions.iter().any(|x| x == a), "no audit entry {a}: {actions:?}");
    }
}

#[test]
fn audit_filters_and_paging() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    for n in ["a", "b", "c"] {
        b.ok(&["project", "create", n]);
    }
    b.add_user("alice", "admin");
    let all = b.json(&["audit", "--json"]);
    assert_eq!(all.as_array().unwrap().len(), 4);
    assert_eq!(all[0]["action"], "user.create", "newest first");
    let two = b.json(&["audit", "--json", "-n", "2"]);
    assert_eq!(two.as_array().unwrap().len(), 2);
    let before = two[1]["id"].as_i64().unwrap().to_string();
    let rest = b.json(&["audit", "--json", "--before", &before]);
    assert_eq!(rest.as_array().unwrap().len(), 2);
    assert_eq!(
        b.json(&["audit", "--json", "--user", "-"])
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        b.json(&["audit", "--json", "--user", "alice"])
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(b.ok(&["audit"]).contains("project.create"));
}

#[test]
fn completions_and_man_pages() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    let sh = b.ok(&["completions", "bash"]);
    assert!(sh.contains("bosun") && sh.contains("project"));
    assert_eq!(code(&b.run(&["completions", "klingon"])), 2);

    let out = d.path().join("man");
    b.ok(&["man", "--out", out.to_str().unwrap()]);
    let top = std::fs::read_to_string(out.join("bosun.1")).unwrap();
    assert!(top.contains("bosun"));
    assert!(out.join("bosun-project-list.1").is_file());
    assert!(out.join("bosun-token-create.1").is_file());
}

#[test]
fn serve_no_ui_records_without_the_ui() {
    let d = tempfile::tempdir().unwrap();
    let b = Bosun(d.path());
    let mut engine = b
        .cmd(&["serve", "--no-ui", "--proxy", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(engine.stderr.take().unwrap());
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        if err.read_line(&mut line).unwrap() == 0 {
            break;
        }
        seen.push_str(&line);
        if line.contains("proxy ") {
            break;
        }
    }
    assert!(seen.contains("no web UI"), "{seen}");
    assert!(!seen.contains("setup code"));
    // The project is held, and no account database was needed.
    assert_eq!(code(&b.run(&["project", "backup", "default"])), 3);
    engine.kill().unwrap();
    engine.wait().unwrap();
    assert_eq!(
        code(&b.run(&["serve", "--no-ui", "--embedded"])),
        2,
        "the two modes conflict"
    );
}
