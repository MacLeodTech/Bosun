//! Custom passive checks through the Rust client against a real engine.

#![allow(clippy::unwrap_used)] // helpers outside #[test] fns

mod common;
use common::*;

use std::time::Duration;

use bosun_client::*;

const CHECK: &str = r#"
version: 1
id: custom-teapot
info:
  name: Teapot marker in a response
  severity: low
  description: The response mentions the teapot.
passive:
  matchers:
    - type: word
      part: body
      words: ["short and stout"]
"#;

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
async fn a_custom_check_is_validated_stored_switched_and_fires_on_recorded_traffic() {
    let s = stack(true).await;
    let c = Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();

    // Validation reports the loader's message and stores nothing.
    let bad = c.validate_check("version: 1\nid: x\n").await.unwrap();
    assert!(!bad.valid && bad.error.is_some());
    assert!(c.validate_check(CHECK).await.unwrap().valid);
    assert!(c.checks().await.unwrap().is_empty());
    let huge = format!("{CHECK}\n# {}", "x".repeat(300 * 1024));
    assert!(c.add_check(&huge).await.is_err());
    assert!(c.add_check("not: a check").await.is_err());
    let builtin = CHECK.replace("custom-teapot", "private-key");
    assert!(
        !c.validate_check(&builtin).await.unwrap().valid,
        "a built-in rule's id is taken"
    );
    let active = CHECK.replace("passive:", "requests:\n  - path: [\"/\"]\nnotes_ignored:");
    assert!(c.add_check(&active).await.is_err());

    let added = c.add_check(CHECK).await.unwrap();
    assert_eq!((added.check_id.as_str(), added.enabled), ("custom-teapot", true));
    assert_eq!(added.severity, "low");
    assert!(c.add_check(CHECK).await.is_err(), "the id is taken");

    recorded(
        &s,
        "/pot",
        "Content-Type: text/plain\r\n",
        b"I'm a little teapot, short and stout",
        None,
    );
    let hit = |l: &IssueList| l.issues.iter().filter(|i| i.rule == "custom-teapot").count();
    assert_eq!(hit(&settled(&c).await), 1);

    // Switched off: a rescan no longer finds it. Switched on: it does again.
    c.set_check_enabled(added.id, false).await.unwrap();
    c.rescan_issues().await.unwrap();
    let after = settled(&c).await;
    assert!(
        after
            .issues
            .iter()
            .filter(|i| i.rule == "custom-teapot")
            .all(|i| i.count == 0)
    );
    c.set_check_enabled(added.id, true).await.unwrap();
    c.rescan_issues().await.unwrap();
    assert!(
        settled(&c)
            .await
            .issues
            .iter()
            .any(|i| i.rule == "custom-teapot" && i.count == 1)
    );

    let edited = c
        .replace_check(added.id, &CHECK.replace("Teapot marker", "Teapot sign"))
        .await
        .unwrap();
    assert_eq!(edited.name, "Teapot sign in a response");
    assert!(c.replace_check(9999, CHECK).await.is_err());

    c.delete_check(added.id).await.unwrap();
    assert!(c.checks().await.unwrap().is_empty());
    assert!(c.delete_check(added.id).await.is_err());

    let log = c.audit(None, Some(200)).await.unwrap();
    for action in ["check.add", "check.update", "check.enable", "check.delete"] {
        assert!(log.iter().any(|e| e.action == action), "{action} was not audited");
    }
}
