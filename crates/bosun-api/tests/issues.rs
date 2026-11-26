//! The passive scanner's issues through the Rust client against a real engine.

#![allow(clippy::unwrap_used)] // helpers outside #[test] fns

mod common;
use common::*;

use std::time::Duration;

use bosun_client::*;

fn url(s: &Stack) -> String {
    format!("http://127.0.0.1:{}", s.api.port())
}

async fn admin(s: &Stack) -> Client {
    let c = Client::new(url(s)).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    c
}

async fn settled(c: &Client) -> IssueList {
    for _ in 0..400 {
        let l = c.issues(&IssueQuery::default()).await.unwrap();
        if l.pending == 0 {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the scanner did not catch up");
}

#[tokio::test]
async fn the_scanner_reports_issues_that_can_be_triaged_and_rescanned() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let _scanner = bosun_scan::Scanner::start(&s.state.project());
    let key = b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
    let flow = recorded(
        &s,
        "/key",
        "Content-Type: text/plain\r\nSet-Cookie: sid=1\r\n",
        key,
        None,
    );
    recorded(
        &s,
        "/other",
        "Content-Type: text/plain\r\nSet-Cookie: sid=2\r\n",
        b"x",
        None,
    );
    let list = settled(&c).await;
    assert!(list.rules.iter().any(|r| r == "private-key"));
    let by_rule = |r: &str| list.issues.iter().find(|i| i.rule == r).unwrap();
    let cookie = by_rule("cookie-no-httponly");
    assert_eq!(cookie.count, 2, "two sightings of one cookie are one issue");
    let key_issue = by_rule("private-key");
    assert_eq!(
        (key_issue.severity, key_issue.flow_id),
        (Severity::High, Some(flow))
    );
    assert_eq!(key_issue.status, IssueStatus::New);
    assert_eq!(key_issue.evidence.len(), 1);
    assert_eq!(key_issue.evidence[0].part, EvidencePart::Response);

    let only = |q: IssueQuery| {
        let c = c.clone();
        async move { c.issues(&q).await.unwrap().issues }
    };
    let high = only(IssueQuery {
        severity: Some(Severity::High),
        ..Default::default()
    })
    .await;
    assert_eq!(high.len(), 1);
    let text = only(IssueQuery {
        q: Some("private key".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(text.len(), 1);
    let on_flow = only(IssueQuery {
        flow_id: Some(flow),
        ..Default::default()
    })
    .await;
    assert_eq!(
        on_flow.len(),
        list.issues.iter().filter(|i| i.flow_id == Some(flow)).count()
    );

    c.change_issue(key_issue.id, IssueStatus::FalsePositive)
        .await
        .unwrap();
    assert_eq!(
        c.issue(key_issue.id).await.unwrap().status,
        IssueStatus::FalsePositive
    );
    let fp = only(IssueQuery {
        status: Some(IssueStatus::FalsePositive),
        ..Default::default()
    })
    .await;
    assert_eq!(fp.len(), 1);
    assert!(c.change_issue(99_999, IssueStatus::Confirmed).await.is_err());
    assert!(c.issue(99_999).await.unwrap_err().is_not_found());
    assert!(
        c.audit(None, Some(50))
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "issue.status")
    );

    // A rescan counts again from scratch and keeps the triage.
    c.rescan_issues().await.unwrap();
    settled(&c).await;
    assert_eq!(c.issue(cookie.id).await.unwrap().count, 2);
    assert_eq!(
        c.issue(key_issue.id).await.unwrap().status,
        IssueStatus::FalsePositive
    );
    assert!(
        c.audit(None, Some(50))
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "issues.rescan")
    );

    // Not signed in: nothing.
    let anon = Client::new(url(&s)).unwrap();
    assert!(
        anon.issues(&IssueQuery::default())
            .await
            .unwrap_err()
            .is_unauthorized()
    );
    assert!(anon.rescan_issues().await.unwrap_err().is_unauthorized());
}

#[tokio::test]
async fn the_report_is_an_inert_attachment_with_secrets_redacted() {
    let s = stack(true).await;
    let c = admin(&s).await;
    let _scanner = bosun_scan::Scanner::start(&s.state.project());
    recorded(
        &s,
        "/p?token=hunter2secret",
        "Content-Type: text/plain\r\nSet-Cookie: sid=cookievalue99\r\n",
        b"<script>alert(1)</script>",
        None,
    );
    settled(&c).await;
    let q = IssueQuery::default();
    for f in ["html", "json", "sarif", "junit", "markdown"] {
        let b = String::from_utf8(c.issues_report(&q, f, true).await.unwrap().to_vec()).unwrap();
        assert!(
            b.contains("cookie-no-httponly") || f == "markdown" || f == "html",
            "{f}"
        );
        assert!(
            !b.contains("hunter2secret") && !b.contains("cookievalue99"),
            "{f} leaks"
        );
        assert!(!b.contains("<script>"), "{f} carries raw target markup");
    }
    // Headers: an attachment that nothing in it can turn into script.
    let raw = reqwest::Client::new()
        .get(format!("{}/api/v1/issues/report", url(&s)))
        .bearer_auth(c.create_token("t", None, None).await.unwrap().token)
        .send()
        .await
        .unwrap();
    let h = raw.headers().clone();
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(c.issues_report(&q, "pdf", true).await.is_err());

    // Keeping secrets is a tester action and is audited.
    let kept = c.issues_report(&q, "json", false).await.unwrap();
    assert!(
        String::from_utf8_lossy(&kept).contains("cookievalue99")
            || String::from_utf8_lossy(&kept).contains("hunter2secret")
    );
    assert!(
        c.audit(None, Some(50))
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "issues.report")
    );
    let anon = Client::new(url(&s)).unwrap();
    assert!(
        anon.issues_report(&q, "html", true)
            .await
            .unwrap_err()
            .is_unauthorized()
    );
}
