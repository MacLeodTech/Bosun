#![allow(clippy::unwrap_used)]
//! The matrix against the testbed's logged-in area: it finds the planted IDOR and the missing role check, and
//! stays quiet on the safe twins.

use bosun_auth::{FindingKind, Identity, Options, Probe, Verdict, run};
use bosun_http::{Engine, Exchange, SendOptions, response_header};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};

fn engine() -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "127.0.0.1".into(),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

async fn login(e: &Engine, t: &Target, user: &str, pass: &str) -> Identity {
    let body = format!("user={user}&pass={pass}");
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let ex: Exchange = e.send(t, req.as_bytes(), &SendOptions::default()).await.unwrap();
    let cookie = response_header(&ex.response, "set-cookie").unwrap();
    let sid = cookie.split(';').next().unwrap().to_string();
    Identity {
        name: user.into(),
        headers: vec![("Cookie".into(), sid)],
    }
}

fn get(t: &Target, label: &str, owner: &str, path: &str, allowed: &[&str]) -> Probe {
    Probe {
        label: label.into(),
        owner: owner.into(),
        allowed: allowed.iter().map(|s| (*s).to_string()).collect(),
        target: t.clone(),
        request: format!("GET {path} HTTP/1.1\r\nHost: x\r\nCookie: sid=stale\r\n\r\n").into_bytes(),
    }
}

#[tokio::test]
async fn the_matrix_finds_the_planted_idor_and_missing_role_check() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let t = Target::new(Scheme::Http, "127.0.0.1", tb.addr.port());
    let e = engine();
    let ids = vec![
        login(&e, &t, "alice", "alicepw").await,
        login(&e, &t, "bob", "bobpw").await,
        login(&e, &t, "admin", "adminpw").await,
    ];
    let probes = vec![
        get(&t, "order 1 (idor)", "alice", "/app/orders/1", &["admin"]),
        get(&t, "order 1 (safe)", "alice", "/app/orders-safe/1", &["admin"]),
        get(
            &t,
            "admin users (no role check)",
            "admin",
            "/app/admin/users",
            &[],
        ),
        get(&t, "admin users (safe)", "admin", "/app/admin-safe/users", &[]),
        get(&t, "login required", "alice", "/app", &["bob", "admin"]),
    ];
    let rows = run(&e, &ids, &probes, &Options::default()).await.unwrap();
    let findings: Vec<_> = rows.iter().flat_map(|r| r.findings()).collect();
    let on = |label: &str| findings.iter().filter(|f| f.label == label).collect::<Vec<_>>();

    // The IDOR: bob reads alice's order. Admin is allowed; anonymous is bounced to the login page.
    let idor = on("order 1 (idor)");
    assert_eq!(idor.len(), 1, "{findings:?}");
    assert_eq!(
        (idor[0].identity.as_str(), idor[0].kind),
        ("bob", FindingKind::BrokenAccessControl)
    );
    // The vertical bypass: alice and bob reach the admin page.
    let mut who: Vec<_> = on("admin users (no role check)")
        .iter()
        .map(|f| f.identity.clone())
        .collect();
    who.sort();
    assert_eq!(who, ["alice", "bob"]);
    // The safe twins and the plain login-gated page are quiet.
    assert!(on("order 1 (safe)").is_empty());
    assert!(on("admin users (safe)").is_empty());
    assert!(on("login required").is_empty());
    // Anonymous is denied (redirected) everywhere.
    for r in &rows {
        let anon = r.cells.iter().find(|c| c.identity == "anonymous").unwrap();
        assert_eq!(anon.verdict, Verdict::Denied, "{}", r.label);
    }
}
