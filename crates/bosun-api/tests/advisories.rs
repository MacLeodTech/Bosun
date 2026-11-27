//! The advisory feed: only a feed signed by a trusted key, with a rising sequence, is loaded; recorded traffic is
//! then matched against it.

#![allow(clippy::unwrap_used)]

mod common;
use common::*;

use std::time::Duration;

use base64::Engine as _;
use bosun_client::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn feed(seq: u64, product: &str, fixed: &str) -> String {
    format!(
        r#"{{"schema":1,"sequence":{seq},"generated":"2026-11-28","advisories":[{{"id":"TEST-{seq}","product":"{product}","summary":"A test advisory.","severity":"medium","ranges":[{{"fixed":"{fixed}"}}]}}]}}"#
    )
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
async fn a_signed_feed_is_verified_ordered_audited_and_applied_to_recorded_traffic() {
    let s = stack(true).await;
    let c = Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    let _scanner = bosun_scan::Scanner::start(&s.state.project());

    let rng = SystemRandom::new();
    let kp = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let other = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let sign = |k: &Ed25519KeyPair, text: &str| b64(k.sign(text.as_bytes()).as_ref());

    // The built-in database is in force until a feed is loaded, and a feed needs a trusted key.
    let st = c.advisories_status().await.unwrap();
    assert_eq!(
        (st["source"].as_str(), st["sequence"].as_u64()),
        (Some("bundled"), Some(0))
    );
    let f1 = feed(1, "acme", "2.0");
    let err = c
        .advisories_load_feed(&f1, &sign(&kp, &f1), true)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Api { status: 422, .. }), "{err:?}");
    assert!(c.advisories_trust(&["AAAA".into()]).await.is_err());
    c.advisories_trust(&[b64(kp.public_key().as_ref())])
        .await
        .unwrap();

    // Signed by someone else, or changed after signing: refused.
    let err = c
        .advisories_load_feed(&f1, &sign(&other, &f1), true)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Api { status: 422, .. }), "{err:?}");
    let err = c
        .advisories_load_feed(&f1.replace("medium", "high"), &sign(&kp, &f1), true)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Api { status: 422, .. }), "{err:?}");

    // Traffic recorded before the feed is loaded is matched after it (the load queues a rescan).
    recorded(
        &s,
        "/",
        "Server: acme/1.5\r\nContent-Type: text/plain\r\n",
        b"x",
        None,
    );
    let before = settled(&c).await;
    assert!(!before.issues.iter().any(|i| i.rule == "vulnerable-component"));
    assert!(
        before
            .issues
            .iter()
            .any(|i| i.rule == "technology-fingerprint" && i.title.contains("acme 1.5"))
    );

    let st = c.advisories_load_feed(&f1, &sign(&kp, &f1), true).await.unwrap();
    assert_eq!(
        (
            st["source"].as_str(),
            st["sequence"].as_u64(),
            st["advisories"].as_u64()
        ),
        (Some("feed"), Some(1), Some(1))
    );
    let after = settled(&c).await;
    let v = after
        .issues
        .iter()
        .find(|i| i.rule == "vulnerable-component")
        .unwrap();
    assert!(
        v.title.contains("acme 1.5") && v.title.contains("TEST-1"),
        "{}",
        v.title
    );

    // The same sequence, or an older one, is refused even though it is validly signed.
    let err = c
        .advisories_load_feed(&f1, &sign(&kp, &f1), true)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Api { status: 409, .. }), "{err:?}");
    // A newer one replaces it: version 1.5 is no longer in range.
    let f2 = feed(2, "acme", "1.0");
    c.advisories_load_feed(&f2, &sign(&kp, &f2), true).await.unwrap();
    assert_eq!(c.advisories_status().await.unwrap()["sequence"], 2);

    // Changing the trusted keys stops the stored feed from being used; reset goes back to the built-in one.
    c.advisories_trust(&[]).await.unwrap();
    assert_eq!(c.advisories_status().await.unwrap()["source"], "bundled");
    c.advisories_trust(&[b64(kp.public_key().as_ref())])
        .await
        .unwrap();
    assert_eq!(c.advisories_status().await.unwrap()["source"], "feed");
    c.advisories_reset().await.unwrap();
    assert_eq!(c.advisories_status().await.unwrap()["source"], "bundled");

    let audit = format!("{:?}", c.audit(None, Some(200)).await.unwrap());
    for a in [
        "advisories.trust",
        "advisories.update",
        "advisories.update_refused",
        "advisories.reset",
    ] {
        assert!(audit.contains(a), "{a} missing");
    }
}

#[tokio::test]
async fn the_built_in_advisories_match_without_any_feed_and_changes_need_admin() {
    let s = stack(true).await;
    let c = Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    c.setup(&s.code, "admin", "a long enough password").await.unwrap();
    let _scanner = bosun_scan::Scanner::start(&s.state.project());
    recorded(
        &s,
        "/",
        "Server: Apache/2.4.49 (Unix)\r\nContent-Type: text/plain\r\n",
        b"x",
        None,
    );
    let l = settled(&c).await;
    let ids: Vec<&str> = l
        .issues
        .iter()
        .filter(|i| i.rule == "vulnerable-component")
        .map(|i| i.title.as_str())
        .collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(ids.iter().all(|t| t.contains("apache 2.4.49")));
    // Nobody who is not signed in can read or change it.
    let anon = Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    assert!(matches!(
        anon.advisories_status().await.unwrap_err(),
        Error::Api { status: 401, .. }
    ));
}
