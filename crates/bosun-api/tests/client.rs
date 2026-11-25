//! The Rust client against a real engine: every operation of the API is called through `bosun-client`, so the
//! typed shapes in that crate are checked against what the server really sends.

#![allow(clippy::unwrap_used)] // helpers outside #[test] fns

mod common;
use common::*;

use std::time::Duration;

use bosun_client::*;

fn url(s: &Stack) -> String {
    format!("http://127.0.0.1:{}", s.api.port())
}

/// A client signed in as the first admin with a password (cookie session).
async fn admin(s: &Stack) -> Client {
    let c = Client::new(url(s)).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    c
}

#[tokio::test]
async fn sessions_tokens_and_accounts() {
    let s = stack(true).await;
    let c = Client::new(url(&s)).unwrap();
    let st = c.status().await.unwrap();
    assert!(st.setup_required);
    assert!(c.flows(&Default::default()).await.unwrap_err().is_unauthorized());
    assert!(c.sso_config().await.unwrap().sso.is_none());

    // Wrong code, then the right one.
    assert_eq!(
        c.setup("guess", "admin", "a long enough password")
            .await
            .unwrap_err()
            .status(),
        Some(403)
    );
    let me = c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    assert_eq!((me.user.username.as_str(), me.user.role), ("admin", Role::Admin));
    assert!(me.csrf.is_some());
    assert!(!c.status().await.unwrap().setup_required);
    assert_eq!(c.me().await.unwrap().user.id, me.user.id);

    // Tokens: the secret is shown once and works as a bearer.
    let t = c.create_token("ci", Some(30), None).await.unwrap();
    assert!(t.token.starts_with("bosun_"), "{}", t.token);
    assert_eq!(t.info.scope, TokenScope::Full);
    assert_eq!(c.tokens().await.unwrap().len(), 1);
    let bearer = Client::builder(url(&s)).token(&t.token).build().unwrap();
    assert_eq!(bearer.me().await.unwrap().user.username, "admin");
    assert!(bearer.me().await.unwrap().csrf.is_none());
    let ro = c.create_token("ro", None, Some(TokenScope::Read)).await.unwrap();
    let ro = Client::builder(url(&s)).token(&ro.token).build().unwrap();
    assert!(ro.flows(&Default::default()).await.is_ok());
    assert!(
        ro.put_scope(&ScopeSpec::default())
            .await
            .unwrap_err()
            .is_forbidden()
    );
    let bad = Client::builder(url(&s)).token("bosun_nope").build().unwrap();
    assert!(bad.me().await.unwrap_err().is_unauthorized());

    // Accounts.
    let bob = c
        .create_user("bob", "another long password", Role::Viewer)
        .await
        .unwrap();
    assert_eq!(bob.role, Role::Viewer);
    assert_eq!(c.users().await.unwrap().len(), 2);
    let bobc = Client::new(url(&s)).unwrap();
    bobc.login("bob", "another long password").await.unwrap();
    assert!(
        bobc.users().await.unwrap_err().is_forbidden(),
        "viewers cannot list users"
    );
    assert!(
        bobc.put_scope(&ScopeSpec::default())
            .await
            .unwrap_err()
            .is_forbidden()
    );
    assert!(bobc.audit(None, None).await.unwrap_err().is_forbidden());
    assert_eq!(c.user_sessions(bob.id).await.unwrap().len(), 1);
    c.set_user_role(bob.id, Role::Tester).await.unwrap();
    assert!(
        bobc.me().await.unwrap_err().is_unauthorized(),
        "a role change ends the user's sessions"
    );
    bobc.login("bob", "another long password").await.unwrap();
    assert!(
        bobc.put_scope(&ScopeSpec::default()).await.is_ok(),
        "the new role applies"
    );
    let bt = bobc.create_token("mine", None, None).await.unwrap();
    assert_eq!(c.user_tokens(bob.id).await.unwrap().len(), 1);
    c.revoke_user_token(bob.id, bt.info.id).await.unwrap();
    assert!(c.user_tokens(bob.id).await.unwrap().is_empty());
    assert_eq!(c.revoke_user_sessions(bob.id).await.unwrap(), 1);
    assert!(bobc.me().await.unwrap_err().is_unauthorized());
    bobc.login("bob", "another long password").await.unwrap();
    let sid = c.user_sessions(bob.id).await.unwrap().remove(0).id;
    c.revoke_user_session(bob.id, &sid).await.unwrap();
    assert!(bobc.me().await.unwrap_err().is_unauthorized());
    bobc.login("bob", "another long password").await.unwrap();
    bobc.change_password("another long password", "a third long password", None)
        .await
        .unwrap();
    assert!(
        bobc.me().await.unwrap_err().is_unauthorized(),
        "a password change ends sessions"
    );
    c.delete_user(bob.id).await.unwrap();
    assert!(c.delete_user(bob.id).await.unwrap_err().is_not_found());

    // Tokens can be revoked by their owner; the audit log shows what happened.
    c.delete_token(t.info.id).await.unwrap();
    assert!(bearer.me().await.unwrap_err().is_unauthorized());
    let audit = c.audit(None, Some(100)).await.unwrap();
    for a in ["user.create", "user.role", "user.delete"] {
        assert!(
            audit.iter().any(|e| e.action == a),
            "{a} not in {:?}",
            audit.iter().map(|e| &e.action).collect::<Vec<_>>()
        );
    }
    assert!(c.audit(None, Some(2)).await.unwrap().len() <= 2);

    c.logout().await.unwrap();
    assert!(c.me().await.unwrap_err().is_unauthorized());
}

#[tokio::test]
async fn history_bodies_annotations_and_sitemap() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let a = recorded(&s, "/a.css", "Content-Type: text/css\r\n", b"body{}", None);
    let b = recorded(
        &s,
        "/b",
        "Content-Type: text/plain\r\n",
        b"hello world",
        Some(b"HTTP/1.1 200 OK\r\n\r\norig".to_vec()),
    );

    let all = c.flows(&FlowQuery::default()).await.unwrap();
    assert_eq!(
        all.iter().map(|f| f.id).collect::<Vec<_>>(),
        vec![b, a],
        "newest first"
    );
    let only = c
        .flows(&FlowQuery {
            hide_ext: Some("css".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(only.len(), 1);
    assert_eq!(
        c.flows(&FlowQuery {
            limit: Some(1),
            before: Some(b),
            ..Default::default()
        })
        .await
        .unwrap()[0]
            .id,
        a
    );
    assert_eq!(
        c.flows(&FlowQuery {
            methods: Some("POST".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .len(),
        0
    );

    let m = c.flow(b).await.unwrap();
    assert_eq!(m.summary.path, "/b");
    assert_eq!(m.response.as_ref().unwrap().body_len, 11);
    assert!(m.original_response.is_some() && m.original_request.is_none());
    assert!(m.request.head.starts_with(b"GET / HTTP/1.1"));
    assert!(c.flow(9999).await.unwrap_err().is_not_found());

    assert_eq!(
        &c.flow_body(b, Part::Response, false).await.unwrap()[..],
        b"hello world"
    );
    assert_eq!(
        &c.flow_body(b, Part::OriginalResponse, false).await.unwrap()[..],
        b"orig"
    );
    assert_eq!(
        &c.flow_body_range(b, Part::Response, 6, None).await.unwrap()[..],
        b"world"
    );
    assert_eq!(
        &c.flow_body_range(b, Part::Response, 0, Some(4)).await.unwrap()[..],
        b"hello"
    );
    assert!(c.flow_body(b, Part::Request, true).await.unwrap_err().status() == Some(400));

    c.annotate_flow(b, Some(&["interesting".to_string()]), Some("check the cookie"))
        .await
        .unwrap();
    let m = c.flow(b).await.unwrap();
    assert_eq!(m.summary.tags, vec!["interesting"]);
    assert_eq!(m.summary.note.as_deref(), Some("check the cookie"));

    let sm = c.site_map(None).await.unwrap();
    assert!(sm.iter().any(|e| e.host == "a.test" && e.path == "/b"));
    assert!(c.site_map(Some("nothing.test")).await.unwrap().is_empty());
    assert!(c.ws_messages(b, None, None).await.unwrap().is_empty());

    assert_eq!(c.delete_flows(&[a]).await.unwrap(), 1);
    assert_eq!(c.flows(&Default::default()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn scope_rules_proxy_and_ca() {
    let s = stack(true).await;
    let c = admin(&s).await;

    let spec = ScopeSpec {
        include: vec![
            ScopeRule::host("*.example.com"),
            ScopeRule {
                scheme: Some(Scheme::Https),
                ..ScopeRule::host("api.test")
            },
        ],
        exclude: vec![ScopeRule {
            path: Some("^/logout".into()),
            ..ScopeRule::host("*.example.com")
        }],
    };
    assert_eq!(c.put_scope(&spec).await.unwrap(), spec);
    assert_eq!(c.scope().await.unwrap(), spec);
    let bad = ScopeSpec {
        include: vec![ScopeRule {
            path: Some("(".into()),
            ..ScopeRule::host("x")
        }],
        exclude: vec![],
    };
    assert_eq!(c.put_scope(&bad).await.unwrap_err().status(), Some(400));

    let rule = MatchRule {
        enabled: true,
        target: RuleTarget::RequestHeader,
        pattern: "User-Agent: .*".into(),
        replace: "User-Agent: bosun".into(),
        regex: true,
        comment: "disguise".into(),
    };
    assert_eq!(
        c.put_rules(std::slice::from_ref(&rule)).await.unwrap(),
        vec![rule.clone()]
    );
    assert_eq!(c.rules().await.unwrap(), vec![rule]);
    assert!(
        c.put_rules(&[MatchRule {
            pattern: "(".into(),
            regex: true,
            ..c.rules().await.unwrap().remove(0)
        }])
        .await
        .is_err()
    );

    let want = InterceptSettings {
        requests: true,
        responses: true,
        in_scope_only: false,
        timeout_secs: Some(30),
    };
    assert_eq!(c.put_intercept(&want).await.unwrap(), want);
    assert_eq!(c.intercept().await.unwrap(), want);
    assert!(c.intercept_queue().await.unwrap().is_empty());
    assert_eq!(c.intercept_forward_all().await.unwrap(), 0);
    assert!(c.intercept_item(1).await.unwrap_err().is_not_found());

    let info = c.proxy_info().await.unwrap();
    assert_eq!(info.listen, s.proxy.to_string());
    assert!(!info.tools_stopped);
    assert!(info.stats.memory_budget > 0);
    assert!(c.set_stopped(true).await.unwrap());
    assert!(c.proxy_info().await.unwrap().tools_stopped);
    assert!(!c.set_stopped(false).await.unwrap());

    let ca = c.ca_info().await.unwrap();
    assert_eq!(c.ca_pem().await.unwrap(), ca.pem);
    assert!(
        ca.pem.contains("BEGIN CERTIFICATE")
            && !ca.fingerprint_sha256.is_empty()
            && !ca.spki_sha256.is_empty()
    );
    // The test engine has no browser launcher.
    assert!(c.launch_browser().await.unwrap_err().is_forbidden());

    let audit = c.audit(None, None).await.unwrap();
    for a in ["scope.update", "rules.update", "intercept.settings"] {
        assert!(audit.iter().any(|e| e.action == a), "{a} missing");
    }
}

/// A traffic round trip: a request through the proxy is held, edited, forwarded and recorded, and the client sees
/// each step on the event stream.
#[tokio::test]
async fn a_held_request_can_be_edited_and_forwarded_and_shows_up_in_history() {
    let s = stack(true).await;
    let c = admin(&s).await;

    // A tiny upstream that echoes the request line.
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut sock, _) = up.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{first}",
                            first.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    c.put_scope(&ScopeSpec {
        include: vec![ScopeRule {
            allow_private: true,
            ..ScopeRule::host("127.0.0.1")
        }],
        exclude: vec![],
    })
    .await
    .unwrap();
    c.put_intercept(&InterceptSettings {
        requests: true,
        responses: false,
        in_scope_only: true,
        timeout_secs: None,
    })
    .await
    .unwrap();

    let mut events = c.events(None).await.unwrap();
    assert!(matches!(
        events.next().await.unwrap().unwrap().event,
        Event::Hello { .. }
    ));
    let _ = c
        .put_intercept(&InterceptSettings {
            requests: true,
            responses: false,
            in_scope_only: true,
            timeout_secs: None,
        })
        .await;

    let proxied = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", s.proxy)).unwrap())
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let call = tokio::spawn(async move {
        proxied
            .get(format!("http://127.0.0.1:{up_port}/original"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });

    // Wait for it to be held.
    let item = loop {
        if let Some(q) = c.intercept_queue().await.unwrap().first() {
            break c.intercept_item(q.id).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(item.summary.phase, Phase::Request);
    assert_eq!(item.summary.method, "GET");
    let text = String::from_utf8_lossy(&item.raw).replace("/original", "/edited");
    c.intercept_decide(
        item.summary.id,
        &Decision::Forward {
            raw: Some(text.into_bytes()),
        },
    )
    .await
    .unwrap();
    assert_eq!(call.await.unwrap(), "GET /edited HTTP/1.1");

    // The stream told us about it, in order, with sequence numbers.
    let mut seen = Vec::new();
    let mut flow_id = None;
    while flow_id.is_none() {
        let e = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("events")
            .unwrap()
            .unwrap();
        if let Event::Flow { flow } = &e.event {
            flow_id = Some(flow.id);
        }
        seen.push(e);
    }
    assert!(
        seen.iter()
            .any(|e| matches!(e.event, Event::InterceptQueued { .. }))
    );
    assert!(
        seen.iter()
            .any(|e| matches!(e.event, Event::InterceptResolved { .. }))
    );
    let seqs: Vec<u64> = seen.iter().filter_map(|e| e.seq).collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");

    let f = c.flow(flow_id.unwrap()).await.unwrap();
    assert!(f.summary.edited);
    assert_eq!(f.summary.path, "/edited");
    assert!(f.original_request.is_some());

    // A second held request can be dropped.
    let proxied = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", s.proxy)).unwrap())
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let call = tokio::spawn(async move {
        proxied
            .get(format!("http://127.0.0.1:{up_port}/dropped"))
            .send()
            .await
            .map(|r| r.status().as_u16())
    });
    let held = loop {
        if let Some(q) = c.intercept_queue().await.unwrap().first() {
            break q.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    c.intercept_decide(held, &Decision::Drop).await.unwrap();
    let r = call.await.unwrap();
    assert!(
        r.is_err() || r.is_ok_and(|s| s >= 400),
        "a dropped request gets no 200"
    );
}

#[tokio::test]
async fn the_event_stream_resumes_where_the_client_left_off() {
    use bosun_proxy::ProxyEvent;
    let s = stack(true).await;
    let c = admin(&s).await;
    let mut ev = c.events(None).await.unwrap();
    let first = ev.next().await.unwrap().unwrap();
    assert!(matches!(first.event, Event::Hello { seq: 0, .. }));
    s.events.send(ProxyEvent::InterceptResolved { id: 1 });
    let e = ev.next().await.unwrap().unwrap();
    assert_eq!(
        (e.seq, matches!(e.event, Event::InterceptResolved { id: 1 })),
        (Some(1), true)
    );
    let pos = ev.position().unwrap().clone();
    assert_eq!(pos.seq, 1);
    drop(ev);

    for id in 2..=3 {
        s.events.send(ProxyEvent::InterceptResolved { id });
    }
    let mut ev = c.events(Some(&pos)).await.unwrap();
    assert!(matches!(
        ev.next().await.unwrap().unwrap().event,
        Event::Hello { .. }
    ));
    for want in 2..=3u64 {
        let e = ev.next().await.unwrap().unwrap();
        assert!(
            matches!(e.event, Event::InterceptResolved { id } if id == want),
            "{e:?}"
        );
        assert_eq!(e.seq, Some(want));
    }

    // reconnect() carries on from the stream's own position.
    ev.reconnect().await.unwrap();
    s.events.send(ProxyEvent::InterceptResolved { id: 4 });
    let mut got = Vec::new();
    while got.len() < 2 {
        got.push(ev.next().await.unwrap().unwrap());
    }
    assert!(matches!(got[0].event, Event::Hello { .. }));
    assert_eq!(got[1].seq, Some(4), "no repeats of 2 and 3");

    // A position from another engine run is told to reload.
    let stale = Position {
        epoch: "0000000000000000".into(),
        seq: 3,
    };
    let mut ev = c.events(Some(&stale)).await.unwrap();
    assert!(matches!(
        ev.next().await.unwrap().unwrap().event,
        Event::Hello { .. }
    ));
    assert!(matches!(ev.next().await.unwrap().unwrap().event, Event::Reload));

    // Without a session the stream is refused with the engine's status.
    let anon = Client::new(url(&s)).unwrap();
    assert_eq!(anon.events(None).await.unwrap_err().status(), Some(401));
}

/// Every operation in the description has a method on the client: a new endpoint fails here until it is added.
#[test]
fn the_client_covers_every_documented_operation() {
    let client_src = include_str!("../../bosun-client/src/client.rs");
    let covered: &[(&str, &str, &str)] = &[
        ("get", "/status", "status"),
        ("post", "/setup", "setup"),
        ("post", "/auth/login", "login"),
        ("post", "/auth/logout", "logout"),
        ("get", "/auth/me", "me"),
        ("post", "/auth/ticket", "login_ticket"),
        ("get", "/auth/sso", "sso_config"),
        ("post", "/auth/password", "change_password"),
        ("get", "/flows", "flows"),
        ("delete", "/flows", "delete_flows"),
        ("get", "/flows/{id}", "flow"),
        ("patch", "/flows/{id}", "annotate_flow"),
        ("get", "/flows/{id}/ws", "ws_messages"),
        ("get", "/flows/{id}/{part}/body", "flow_body"),
        ("get", "/sitemap", "site_map"),
        ("get", "/scope", "scope"),
        ("put", "/scope", "put_scope"),
        ("get", "/rules", "rules"),
        ("put", "/rules", "put_rules"),
        ("get", "/intercept", "intercept"),
        ("put", "/intercept", "put_intercept"),
        ("get", "/intercept/queue", "intercept_queue"),
        ("get", "/intercept/queue/{id}", "intercept_item"),
        ("post", "/intercept/queue/{id}", "intercept_decide"),
        ("post", "/intercept/forward-all", "intercept_forward_all"),
        ("get", "/proxy", "proxy_info"),
        ("put", "/tools/stop", "set_stopped"),
        ("post", "/decoder/apply", "decoder_apply"),
        ("post", "/decoder/smart", "decoder_smart"),
        ("post", "/comparer/diff", "comparer_diff"),
        ("post", "/repeater/send", "repeater_send"),
        ("get", "/repeater/settings", "repeater_settings"),
        ("put", "/repeater/settings", "put_repeater_settings"),
        ("post", "/repeater/ws", "repeater_ws"),
        ("get", "/repeater/tabs", "repeater_tabs"),
        ("put", "/repeater/tabs", "put_repeater_tabs"),
        ("get", "/ca", "ca_info"),
        ("get", "/ca/cert.pem", "ca_pem"),
        ("post", "/browser/launch", "launch_browser"),
        ("get", "/tokens", "tokens"),
        ("post", "/tokens", "create_token"),
        ("delete", "/tokens/{id}", "delete_token"),
        ("get", "/users", "users"),
        ("post", "/users", "create_user"),
        ("delete", "/users/{id}", "delete_user"),
        ("put", "/users/{id}/role", "set_user_role"),
        ("get", "/users/{id}/sessions", "user_sessions"),
        ("delete", "/users/{id}/sessions", "revoke_user_sessions"),
        ("delete", "/users/{id}/sessions/{sid}", "revoke_user_session"),
        ("get", "/users/{id}/tokens", "user_tokens"),
        ("delete", "/users/{id}/tokens/{tid}", "revoke_user_token"),
        ("get", "/projects", "list_projects"),
        ("post", "/projects", "create_project"),
        ("post", "/projects/close", "close_project"),
        ("post", "/projects/import", "import_project"),
        ("delete", "/projects/{name}", "delete_project"),
        ("post", "/projects/{name}/open", "open_project"),
        ("post", "/projects/{name}/rename", "rename_project"),
        ("get", "/projects/{name}/export", "export_project"),
        ("post", "/projects/{name}/backup", "backup_project"),
        ("get", "/audit", "audit"),
        ("get", "/events", "events"),
    ];
    let documented: std::collections::BTreeSet<_> = bosun_api::openapi::OPERATIONS
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    let listed: std::collections::BTreeSet<_> = covered
        .iter()
        .map(|(m, p, _)| (m.to_string(), p.to_string()))
        .collect();
    assert_eq!(
        documented, listed,
        "an operation was added or removed: give the client a method and list it here"
    );
    for (_, path, name) in covered {
        assert!(
            client_src.contains(&format!("pub async fn {name}(")),
            "the client has no `{name}` for {path}"
        );
    }
}

#[tokio::test]
async fn a_login_ticket_signs_in_once_and_sets_up_a_local_admin() {
    let s = stack(true).await;
    let c = Client::new(url(&s)).unwrap();
    assert!(
        c.login_ticket("bosun_ticket_nothing")
            .await
            .unwrap_err()
            .is_unauthorized(),
        "none issued"
    );
    assert!(c.status().await.unwrap().setup_required);

    let ticket = s.state.issue_login_ticket();
    assert!(
        c.login_ticket("bosun_ticket_wrong")
            .await
            .unwrap_err()
            .is_unauthorized()
    );
    let me = c.login_ticket(&ticket).await.unwrap();
    assert_eq!(
        (me.user.username.as_str(), me.user.role),
        ("desktop", Role::Admin)
    );
    assert!(c.me().await.is_ok(), "the session works");
    assert!(c.users().await.is_ok(), "as an admin");
    assert!(
        !c.status().await.unwrap().setup_required,
        "no first-run setup is left to do"
    );
    assert_eq!(
        Client::new(url(&s))
            .unwrap()
            .setup(&s.code, "x", "a long enough password")
            .await
            .unwrap_err()
            .status(),
        Some(409)
    );

    // Single use: the same ticket from anyone else is refused.
    let other = Client::new(url(&s)).unwrap();
    assert!(other.login_ticket(&ticket).await.unwrap_err().is_unauthorized());

    // With an admin already there, a ticket signs in as the oldest admin rather than making another account.
    let t2 = s.state.issue_login_ticket();
    let again = Client::new(url(&s)).unwrap().login_ticket(&t2).await.unwrap();
    assert_eq!(again.user.id, me.user.id);
    assert_eq!(c.users().await.unwrap().len(), 1);

    let audit = c.audit(None, None).await.unwrap();
    let actions: Vec<_> = audit.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions.iter().filter(|a| **a == "login.ticket").count(),
        2,
        "{actions:?}"
    );
    assert!(
        actions.contains(&"login.ticket.failed") && actions.contains(&"setup"),
        "{actions:?}"
    );
}
