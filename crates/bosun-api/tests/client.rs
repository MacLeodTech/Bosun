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
async fn history_queries_run_on_the_server_and_mistakes_are_explained() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let a = recorded(&s, "/a.css", "Content-Type: text/css\r\n", b"body{}", None);
    let b = recorded(&s, "/login", "Content-Type: text/plain\r\n", b"hello world", None);
    let ask = |q: &str| {
        let c = c.clone();
        let q = q.to_string();
        async move {
            c.flows(&FlowQuery {
                q: Some(q),
                ..Default::default()
            })
            .await
            .map(|v| v.into_iter().map(|f| f.id).collect::<Vec<_>>())
        }
    };
    assert_eq!(ask("host:a.test -ext:css").await.unwrap(), vec![b]);
    assert_eq!(ask("hello or body").await.unwrap(), vec![b, a]);
    assert_eq!(ask("not hello").await.unwrap(), vec![a]);
    assert_eq!(ask("size:>1k").await.unwrap(), Vec::<i64>::new());
    // The query adds to the plain filters.
    let both = c
        .flows(&FlowQuery {
            q: Some("host:a.test".into()),
            hide_ext: Some("css".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(both.len(), 1);
    // A mistake is a 400 that says what is wrong; the check endpoint lists them all without running anything.
    let err = ask("status:banana").await.unwrap_err().to_string();
    assert!(err.contains("status:"), "{err}");
    let chk = c
        .check_flow_query(r#"host:a.test status:banana "two words" (open"#)
        .await
        .unwrap();
    assert_eq!(
        chk.terms.iter().map(|t| t.key.as_str()).collect::<Vec<_>>(),
        ["host", "text", "text"]
    );
    assert_eq!(chk.errors.len(), 2);
    assert!(chk.errors[0].start < chk.errors[0].end);
    // Viewers may ask; anonymous callers may not.
    assert!(
        Client::new(url(&s))
            .unwrap()
            .check_flow_query("x")
            .await
            .unwrap_err()
            .is_unauthorized()
    );
}

#[tokio::test]
async fn history_can_be_sorted_and_paged_by_any_column() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let a = recorded(&s, "/b-second", "Content-Type: text/plain\r\n", b"1", None);
    let b = recorded(&s, "/a-first", "Content-Type: text/html\r\n", b"22222", None);
    let d = recorded(&s, "/c-third", "Content-Type: text/css\r\n", b"333", None);
    let list = |sort: &str, asc: bool, offset: Option<u32>, limit: Option<u32>| {
        let c = c.clone();
        let sort = sort.to_string();
        async move {
            c.flows(&FlowQuery {
                sort: Some(sort),
                asc,
                offset,
                limit,
                ..Default::default()
            })
            .await
            .map(|v| v.into_iter().map(|f| f.id).collect::<Vec<_>>())
        }
    };
    assert_eq!(list("id", false, None, None).await.unwrap(), [d, b, a]);
    assert_eq!(list("path", true, None, None).await.unwrap(), [b, a, d]);
    assert_eq!(list("path", false, None, None).await.unwrap(), [d, a, b]);
    assert_eq!(list("size", false, None, None).await.unwrap(), [b, d, a]);
    assert_eq!(list("mime", true, None, None).await.unwrap(), [d, b, a]);
    // Paging a sorted list: the pages join up with nothing missing or repeated.
    let first = list("path", true, None, Some(2)).await.unwrap();
    let rest = list("path", true, Some(2), Some(2)).await.unwrap();
    assert_eq!([first, rest].concat(), [b, a, d]);
    // An unknown column is a mistake, not a guess.
    let err = list("id; drop table flows", true, None, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("sort:"), "{err}");
    assert_eq!(list("id", false, None, None).await.unwrap().len(), 3);
}

#[tokio::test]
async fn tags_change_in_bulk_for_testers_only() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let a = recorded(&s, "/a", "Content-Type: text/plain\r\n", b"1", None);
    let b = recorded(&s, "/b", "Content-Type: text/plain\r\n", b"2", None);
    assert_eq!(c.change_tags(&[a, b], &["review"], &[]).await.unwrap(), 2);
    let tagged = |q: &str| {
        let c = c.clone();
        let q = q.to_string();
        async move {
            c.flows(&FlowQuery {
                q: Some(q),
                ..Default::default()
            })
            .await
            .unwrap()
            .len()
        }
    };
    assert_eq!(tagged("tag:review").await, 2);
    assert_eq!(c.change_tags(&[a], &[], &["REVIEW"]).await.unwrap(), 1);
    assert_eq!(tagged("tag:review").await, 1);
    for bad in [&[][..], &[a][..]] {
        let tags: &[&str] = if bad.is_empty() { &["x"] } else { &[""] };
        assert!(c.change_tags(bad, tags, &[]).await.is_err());
    }
    assert!(
        Client::new(url(&s))
            .unwrap()
            .change_tags(&[a], &["x"], &[])
            .await
            .unwrap_err()
            .is_unauthorized()
    );
}

#[tokio::test]
async fn the_organizer_keeps_requests_for_follow_up() {
    use bosun_client::OrganizerStatus;
    let s = stack(true).await;
    let c = admin(&s).await;
    let a = recorded(&s, "/a", "Content-Type: text/plain\r\n", b"1", None);
    let b = recorded(&s, "/b", "Content-Type: text/plain\r\n", b"2", None);
    assert!(c.organizer().await.unwrap().is_empty());
    assert_eq!(c.add_to_organizer(&[a, b, a]).await.unwrap(), 2);
    assert_eq!(c.add_to_organizer(&[a]).await.unwrap(), 0);
    let list = c.organizer().await.unwrap();
    assert_eq!(list.iter().map(|i| i.flow_id).collect::<Vec<_>>(), [b, a]);
    let id = list[0].id;
    c.update_organizer_item(id, Some(OrganizerStatus::Done), Some("reported"))
        .await
        .unwrap();
    let item = &c.organizer().await.unwrap()[0];
    assert_eq!(
        (item.status, item.note.as_str()),
        (OrganizerStatus::Done, "reported")
    );
    assert!(
        c.update_organizer_item(9999, Some(OrganizerStatus::Done), None)
            .await
            .is_err()
    );
    assert!(
        c.update_organizer_item(id, None, Some(&"x".repeat(10_001)))
            .await
            .is_err()
    );
    // Nothing to add, or far too much, is refused; deleting the flow takes its item along.
    assert!(c.add_to_organizer(&[]).await.is_err());
    assert_eq!(c.delete_flows(&[b]).await.unwrap(), 1);
    assert_eq!(c.organizer().await.unwrap().len(), 1);
    c.delete_organizer_item(c.organizer().await.unwrap()[0].id)
        .await
        .unwrap();
    assert!(c.organizer().await.unwrap().is_empty());
    assert!(
        Client::new(url(&s))
            .unwrap()
            .add_to_organizer(&[a])
            .await
            .unwrap_err()
            .is_unauthorized()
    );
}

#[tokio::test]
async fn saved_filters_are_kept_per_project_and_must_be_valid() {
    use bosun_client::SavedFilter;
    let s = stack(true).await;
    let c = admin(&s).await;
    assert!(c.saved_filters().await.unwrap().is_empty());
    let f = |n: &str, q: &str| SavedFilter {
        name: n.into(),
        query: q.into(),
    };
    let list = vec![f("  api  ", "host:api.test or tag:x"), f("errors", "status:5xx")];
    let back = c.put_saved_filters(&list).await.unwrap();
    assert_eq!(back[0].name, "api", "names are trimmed");
    assert_eq!(c.saved_filters().await.unwrap(), back);
    // A filter that would not run is refused, and so are duplicates, empty names and too many.
    for bad in [
        vec![f("x", "status:banana")],
        vec![f("x", "a"), f("x", "b")],
        vec![f("  ", "a")],
        vec![f("bad\nname", "a")],
        (0..51).map(|i| f(&format!("n{i}"), "a")).collect(),
    ] {
        assert!(c.put_saved_filters(&bad).await.is_err());
    }
    assert_eq!(
        c.saved_filters().await.unwrap(),
        back,
        "a refused write changes nothing"
    );
}

#[tokio::test]
async fn engagement_helpers_report_a_response_and_build_a_csrf_page() {
    use bosun_client::{FindingKind, ParamWhere};
    let s = stack(true).await;
    let c = admin(&s).await;
    let req = b"POST /transfer?src=1 HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nto=bob&amount=5&note=%22%3E%3Cb%3E";
    let page = b"<html><!-- admin at /old --><script src=\"/app.js\"></script><a href=\"/next\">x</a></html>";
    let id = common::recorded_exchange(
        &s,
        "POST",
        "/transfer?src=1",
        req,
        "Content-Type: text/html\r\n",
        page,
        None,
    );

    let r = c.flow_engage(id).await.unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == FindingKind::Comment && f.value == "admin at /old")
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == FindingKind::ScriptSrc && f.value == "/app.js")
    );
    let got: Vec<_> = r.params.iter().map(|p| (p.name.as_str(), p.location)).collect();
    assert_eq!(
        got,
        [
            ("src", ParamWhere::Query),
            ("to", ParamWhere::Form),
            ("amount", ParamWhere::Form),
            ("note", ParamWhere::Form)
        ]
    );

    let html = c.flow_csrf_poc(id, true).await.unwrap();
    assert!(
        html.contains("action=\"https://a.test/transfer?src=1\" method=\"post\""),
        "{html}"
    );
    assert!(html.contains("name=\"to\" value=\"bob\"") && html.contains("HTMLFormElement.prototype.submit"));
    assert!(
        html.contains("value=\"&quot;&gt;&lt;b&gt;\""),
        "values are escaped: {html}"
    );
    assert!(!c.flow_csrf_poc(id, false).await.unwrap().contains("<script>"));

    // A GET page cannot be a PUT, and a missing flow is a 404; neither route is open to the signed-out.
    let put = common::recorded_exchange(
        &s,
        "PUT",
        "/x",
        b"PUT /x HTTP/1.1\r\nHost: a.test\r\n\r\n",
        "",
        b"",
        None,
    );
    assert!(c.flow_csrf_poc(put, false).await.is_err());
    assert!(c.flow_engage(9999).await.is_err());
    // Signed out, neither route answers.
    let anon = reqwest::Client::new();
    for what in ["csrf-poc", "engage"] {
        let r = anon
            .get(format!("{}/api/v1/flows/{id}/{what}", url(&s)))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "{what}");
    }
}

#[tokio::test]
async fn target_analysis_lists_endpoints_and_parameters_of_a_host() {
    use bosun_client::ParamWhere;
    let s = stack(true).await;
    let c = admin(&s).await;
    for (i, q) in ["?page=1&sort=asc", "?page=2", "?page=3&sort=desc"]
        .iter()
        .enumerate()
    {
        let path = format!("/items/{}{q}", 10 + i);
        let req = format!("GET {path} HTTP/1.1\r\nHost: a.test\r\n\r\n");
        common::recorded_exchange(&s, "GET", &path, req.as_bytes(), "", b"", None);
    }
    let login = b"POST /login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b";
    common::recorded_exchange(&s, "POST", "/login", login, "", b"", None);
    let json = b"POST /api/n HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"id\":7,\"user\":{\"role\":\"x\"}}";
    common::recorded_exchange(&s, "POST", "/api/n", json, "", b"", None);

    let r = c.host_analysis("A.test", None).await.unwrap();
    assert_eq!(
        (r.host.as_str(), r.requests, r.capped, r.truncated),
        ("a.test", 5, false, false)
    );
    let items = &r.endpoints[0];
    assert_eq!(
        (items.method.as_str(), items.path.as_str(), items.count),
        ("GET", "/items/{n}", 3)
    );
    assert_eq!(items.params, ["page", "sort"]);
    assert_eq!(items.statuses.len(), 1);
    let page = r.params.iter().find(|p| p.name == "page").unwrap();
    assert_eq!(
        (page.location, page.count, page.endpoints, page.values.len()),
        (ParamWhere::Query, 3, 1, 3)
    );
    assert!(
        r.params
            .iter()
            .any(|p| p.name == "pass" && p.location == ParamWhere::Form)
    );
    assert!(
        r.params
            .iter()
            .any(|p| p.name == "user.role" && p.location == ParamWhere::Json)
    );

    // The port narrows it; another host, or a limit, changes what is read.
    assert_eq!(c.host_analysis("a.test", Some(443)).await.unwrap().requests, 5);
    assert_eq!(c.host_analysis("a.test", Some(8080)).await.unwrap().requests, 0);
    assert_eq!(c.host_analysis("b.test", None).await.unwrap().requests, 0);
    assert!(c.host_analysis("  ", None).await.is_err());
    let anon = reqwest::Client::new();
    let r = anon
        .get(format!("{}/api/v1/analysis?host=a.test", url(&s)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
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
    let f = bosun_client::ResponseFilter {
        statuses: vec!["5xx".into()],
        mime_contains: vec!["json".into()],
        ..Default::default()
    };
    assert_eq!(c.put_response_filter(&f).await.unwrap(), f);
    assert_eq!(c.response_filter().await.unwrap(), f);
    let bad = bosun_client::ResponseFilter {
        statuses: vec!["fifty".into()],
        ..Default::default()
    };
    assert!(c.put_response_filter(&bad).await.is_err());
    assert_eq!(c.response_filter().await.unwrap(), f);
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
    assert!(ca.days_left > 365 && !ca.expiring && ca.not_after > 0 && ca.permitted_domains.is_empty());
    // The test engine has no browser launcher.
    assert!(c.launch_browser().await.unwrap_err().is_forbidden());

    let audit = c.audit(None, None).await.unwrap();
    for a in [
        "scope.update",
        "rules.update",
        "intercept.settings",
        "intercept.response_filter",
    ] {
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
        ("get", "/flows/query", "check_flow_query"),
        ("get", "/saved-filters", "saved_filters"),
        ("put", "/saved-filters", "put_saved_filters"),
        ("delete", "/flows", "delete_flows"),
        ("post", "/flows/tags", "change_tags"),
        ("get", "/organizer", "organizer"),
        ("post", "/organizer", "add_to_organizer"),
        ("patch", "/organizer/{id}", "update_organizer_item"),
        ("delete", "/organizer/{id}", "delete_organizer_item"),
        ("get", "/checks", "checks"),
        ("post", "/checks", "add_check"),
        ("post", "/checks/validate", "validate_check"),
        ("put", "/checks/{id}", "replace_check"),
        ("patch", "/checks/{id}", "set_check_enabled"),
        ("delete", "/checks/{id}", "delete_check"),
        ("get", "/issues", "issues"),
        ("post", "/issues/rescan", "rescan_issues"),
        ("get", "/issues/report", "issues_report"),
        ("get", "/issues/{id}/tracker", "issue_tracker"),
        ("get", "/issues/{id}", "issue"),
        ("patch", "/issues/{id}", "change_issue"),
        ("post", "/intruder/plan", "intruder_plan"),
        ("get", "/intruder/attacks", "intruder_attacks"),
        ("post", "/intruder/attacks", "intruder_start"),
        ("get", "/intruder/attacks/{id}", "intruder_attack"),
        ("delete", "/intruder/attacks/{id}", "intruder_delete"),
        ("get", "/intruder/attacks/{id}/results", "intruder_results"),
        ("post", "/intruder/attacks/{id}/stop", "intruder_stop"),
        ("post", "/crawl/crawls", "crawl_start"),
        ("get", "/crawl/crawls", "crawl_list"),
        ("get", "/crawl/crawls/{id}", "crawl_get"),
        ("post", "/crawl/crawls/{id}/stop", "crawl_stop"),
        ("get", "/flows/{id}", "flow"),
        ("patch", "/flows/{id}", "annotate_flow"),
        ("get", "/flows/{id}/ws", "ws_messages"),
        ("get", "/flows/{id}/engage", "flow_engage"),
        ("get", "/flows/{id}/csrf-poc", "flow_csrf_poc"),
        ("get", "/analysis", "host_analysis"),
        ("get", "/flows/{id}/{part}/body", "flow_body"),
        ("get", "/sitemap", "site_map"),
        ("get", "/scope", "scope"),
        ("put", "/scope", "put_scope"),
        ("get", "/rules", "rules"),
        ("put", "/rules", "put_rules"),
        ("get", "/intercept", "intercept"),
        ("put", "/intercept", "put_intercept"),
        ("get", "/intercept/response-filter", "response_filter"),
        ("put", "/intercept/response-filter", "put_response_filter"),
        ("get", "/intercept/queue", "intercept_queue"),
        ("get", "/intercept/queue/{id}", "intercept_item"),
        ("post", "/intercept/queue/{id}", "intercept_decide"),
        ("post", "/intercept/forward-all", "intercept_forward_all"),
        ("get", "/proxy", "proxy_info"),
        ("get", "/proxy/listeners", "list_listeners"),
        ("post", "/proxy/listeners", "add_listener"),
        ("put", "/proxy/listeners/{id}", "update_listener"),
        ("delete", "/proxy/listeners/{id}", "remove_listener"),
        ("get", "/proxy/config", "proxy_config"),
        ("put", "/proxy/config", "put_proxy_config"),
        ("put", "/tools/stop", "set_stopped"),
        ("post", "/decoder/apply", "decoder_apply"),
        ("post", "/decoder/smart", "decoder_smart"),
        ("post", "/comparer/diff", "comparer_diff"),
        ("post", "/import", "import_requests"),
        ("post", "/repeater/send", "repeater_send"),
        ("get", "/repeater/settings", "repeater_settings"),
        ("put", "/repeater/settings", "put_repeater_settings"),
        ("post", "/repeater/ws", "repeater_ws"),
        ("get", "/repeater/tabs", "repeater_tabs"),
        ("put", "/repeater/tabs", "put_repeater_tabs"),
        ("post", "/sequencer/analyze", "sequencer_analyze"),
        ("post", "/sequencer/capture", "sequencer_capture"),
        ("get", "/sequencer/capture/{id}", "sequencer_capture_status"),
        ("post", "/sequencer/capture/{id}/stop", "sequencer_capture_stop"),
        ("get", "/ca", "ca_info"),
        ("get", "/ca/cert.pem", "ca_pem"),
        ("post", "/browser/launch", "launch_browser"),
        ("get", "/tokens", "tokens"),
        ("post", "/tokens", "create_token"),
        ("delete", "/tokens/{id}", "delete_token"),
        ("post", "/auth/login/totp", "login_totp"),
        ("get", "/auth/totp", "totp_status"),
        ("post", "/auth/totp/enroll", "totp_enroll"),
        ("post", "/auth/totp/confirm", "totp_confirm"),
        ("post", "/auth/totp/disable", "totp_disable"),
        ("post", "/auth/totp/recovery-codes", "totp_recovery_codes"),
        ("put", "/auth/totp/required", "totp_set_required"),
        ("delete", "/users/{id}/totp", "reset_user_totp"),
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

/// Listeners are added, changed and removed while the engine runs, each with its own options, and the live
/// settings change without a restart. Every change is audited and only an admin may make it.
#[tokio::test]
async fn proxy_listeners_and_live_settings_change_without_a_restart() {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let s = stack(true).await;
    let c = admin(&s).await;

    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = up.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            });
        }
    });
    let target = format!("http://127.0.0.1:{up_port}/x");
    let via = |addr: &str, auth: Option<&str>| {
        let mut p = reqwest::Proxy::http(format!("http://{addr}")).unwrap();
        if let Some(a) = auth {
            p = p.basic_auth("tester", a);
        }
        reqwest::Client::builder()
            .proxy(p)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    };
    let raw_get = |addr: String| async move {
        let mut raw = tokio::net::TcpStream::connect(&addr).await.unwrap();
        raw.write_all(
            format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        raw.read_to_string(&mut out).await.unwrap();
        out
    };

    // The configured listener is there, and cannot be removed.
    let l = c.list_listeners().await.unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0]["primary"], true);
    assert_eq!(l[0]["addr"], s.proxy.to_string());
    assert!(
        c.remove_listener(l[0]["id"].as_u64().unwrap() as u32)
            .await
            .is_err()
    );

    // Add one: it works at once.
    let added = c.add_listener(&json!({"addr": "127.0.0.1:0"})).await.unwrap();
    let (id, addr) = (
        added["id"].as_u64().unwrap() as u32,
        added["addr"].as_str().unwrap().to_string(),
    );
    assert_eq!(c.list_listeners().await.unwrap().len(), 2);
    let r = via(&addr, None).get(&target).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "ok");

    // An open proxy is refused; so are bad bodies and a repeated address.
    let open = c.add_listener(&json!({"addr": "0.0.0.0:0"})).await.unwrap_err();
    assert_eq!(open.status(), Some(400));
    assert!(
        c.add_listener(&json!({"addr": "127.0.0.1:0", "nope": 1}))
            .await
            .is_err()
    );
    assert!(c.add_listener(&json!({"addr": addr})).await.is_err());

    // Credentials, live. The password is never returned.
    let pw = "a long proxy password";
    let upd = c
        .update_listener(
            id,
            &json!({"addr": addr, "auth": {"username": "tester", "password": pw}}),
        )
        .await
        .unwrap();
    assert_eq!(upd["auth_required"], true);
    assert!(!upd.to_string().contains(pw));
    let status = |r: reqwest::Response| r.status().as_u16();
    assert_eq!(status(via(&addr, None).get(&target).send().await.unwrap()), 407);
    assert_eq!(
        status(via(&addr, Some(pw)).get(&target).send().await.unwrap()),
        200
    );
    // The configured listener is unaffected.
    let main = s.proxy.to_string();
    assert_eq!(status(via(&main, None).get(&target).send().await.unwrap()), 200);
    // An empty password on edit keeps the current one.
    c.update_listener(
        id,
        &json!({"addr": addr, "invisible": true, "auth": {"username": "tester", "password": ""}}),
    )
    .await
    .unwrap();
    assert_eq!(
        status(via(&addr, Some(pw)).get(&target).send().await.unwrap()),
        200
    );

    // Invisible mode: an origin-form request with a Host header.
    c.update_listener(id, &json!({"addr": addr, "invisible": true}))
        .await
        .unwrap();
    let out = raw_get(addr.clone()).await;
    assert!(out.starts_with("HTTP/1.1 200") && out.ends_with("ok"), "{out}");
    c.update_listener(id, &json!({"addr": addr, "invisible": false}))
        .await
        .unwrap();
    let out = raw_get(addr.clone()).await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");

    // A client allowlist that excludes the caller.
    c.update_listener(id, &json!({"addr": addr, "allow_clients": ["10.0.0.0/8"]}))
        .await
        .unwrap();
    assert!(via(&addr, None).get(&target).send().await.is_err());

    // A per-listener connection cap is stored, shown, and zero is refused.
    c.update_listener(id, &json!({"addr": addr, "max_connections": 5}))
        .await
        .unwrap();
    let shown = c.list_listeners().await.unwrap();
    assert!(shown.iter().any(|l| l["max_connections"] == 5), "{shown:?}");
    assert!(
        c.update_listener(id, &json!({"addr": addr, "max_connections": 0}))
            .await
            .is_err()
    );

    // Remove: the port stops answering.
    c.remove_listener(id).await.unwrap();
    assert_eq!(c.list_listeners().await.unwrap().len(), 1);
    assert!(c.remove_listener(id).await.unwrap_err().is_not_found());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(tokio::net::TcpStream::connect(&addr).await.is_err());

    // Live settings.
    let cfg = c.proxy_config().await.unwrap();
    let names: Vec<&str> = cfg["restart_required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(names.contains(&"upstream") && names.contains(&"listen"));
    let mut live = cfg["live"].clone();
    live["max_request_body"] = json!(10);
    let put = c.put_proxy_config(&live).await.unwrap();
    assert_eq!(put["live"]["max_request_body"], 10);
    let big = via(&main, None)
        .post(&target)
        .body("x".repeat(100))
        .send()
        .await
        .unwrap();
    assert_eq!(status(big), 413);
    live["max_request_body"] = json!(1_000_000);
    c.put_proxy_config(&live).await.unwrap();
    let ok = via(&main, None)
        .post(&target)
        .body("x".repeat(100))
        .send()
        .await
        .unwrap();
    assert_eq!(status(ok), 200);
    let mut bad = live.clone();
    bad["upstream"] = json!(null);
    assert_eq!(c.put_proxy_config(&bad).await.unwrap_err().status(), Some(409));
    let mut zero = live.clone();
    zero["max_connections"] = json!(0);
    assert_eq!(c.put_proxy_config(&zero).await.unwrap_err().status(), Some(400));

    // Only an admin changes them.
    c.create_user("bob", "another long password", Role::Tester)
        .await
        .unwrap();
    let bobc = Client::new(url(&s)).unwrap();
    bobc.login("bob", "another long password").await.unwrap();
    assert!(bobc.list_listeners().await.is_ok());
    assert!(bobc.proxy_config().await.is_ok());
    assert!(
        bobc.add_listener(&json!({"addr": "127.0.0.1:0"}))
            .await
            .unwrap_err()
            .is_forbidden()
    );
    assert!(bobc.put_proxy_config(&live).await.unwrap_err().is_forbidden());
    assert!(bobc.remove_listener(1).await.unwrap_err().is_forbidden());

    let audit = c.audit(None, None).await.unwrap();
    for a in [
        "proxy.listener.add",
        "proxy.listener.update",
        "proxy.listener.remove",
        "proxy.config.update",
    ] {
        assert!(audit.iter().any(|e| e.action == a), "{a} missing");
    }
    assert!(
        !audit.iter().any(|e| e.detail.contains(pw)),
        "the password is in the audit log"
    );
}
