//! The TOTP second factor through the real API and the Rust client: enrolment, sign-in in two steps, replay,
//! recovery codes, throttling, the admin's reset and the "required" policy.

#![allow(clippy::unwrap_used)] // helpers outside #[test] fns

mod common;
use common::*;

use bosun_api::totp::{STEP_SECS, base32_decode, code_at};
use bosun_client::*;
use serde_json::{Value, json};

const PASSWORD: &str = "a long enough password";

fn url(s: &Stack) -> String {
    format!("http://127.0.0.1:{}", s.api.port())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn admin(s: &Stack) -> Client {
    let c = Client::new(url(s)).unwrap();
    c.setup(&s.code, "admin", PASSWORD).await.unwrap();
    c
}

/// Enrol the signed-in account and confirm it; returns the secret and the recovery codes.
async fn enrol(c: &Client) -> (Vec<u8>, Vec<String>) {
    let e = c.totp_enroll().await.unwrap();
    let secret = base32_decode(&e.secret).unwrap();
    assert_eq!(secret.len(), 20);
    let codes = c.totp_confirm(&code_at(&secret, now())).await.unwrap();
    (secret, codes.recovery_codes)
}

async fn pending_of(s: &Stack, user: &str) -> (Client, String) {
    let c = Client::new(url(s)).unwrap();
    match c.login(user, PASSWORD).await.unwrap_err() {
        Error::SecondFactor { pending } => (c, pending),
        e => panic!("expected a request for the second factor, got {e}"),
    }
}

#[tokio::test]
async fn enrolment_is_not_enforced_until_a_code_confirms_it() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let st = a.totp_status().await.unwrap();
    assert!(!st.enabled && !st.enrolling && !st.required);

    let e = a.totp_enroll().await.unwrap();
    assert!(
        e.otpauth_uri.starts_with("otpauth://totp/Bosun:admin?secret="),
        "{}",
        e.otpauth_uri
    );
    assert!(e.otpauth_uri.contains(&e.secret));
    assert!(e.otpauth_uri.contains("algorithm=SHA1&digits=6&period=30"));
    let st = a.totp_status().await.unwrap();
    assert!(!st.enabled && st.enrolling);

    // A password sign-in still works without a code: nothing is enforced yet.
    let other = Client::new(url(&s)).unwrap();
    other.login("admin", PASSWORD).await.unwrap();

    // A wrong code does not turn it on.
    assert_eq!(a.totp_confirm("000000").await.unwrap_err().status(), Some(400));
    assert!(!a.totp_status().await.unwrap().enabled);

    // The secret is sealed at rest: the stored blob is neither the secret nor its base32 text.
    let secret = base32_decode(&e.secret).unwrap();
    let row = s.app.totp_row(1).unwrap().unwrap();
    assert!(!row.confirmed);
    assert!(
        !row.sealed_secret
            .windows(secret.len())
            .any(|w| w == secret.as_slice())
    );
    assert!(
        !row.sealed_secret
            .windows(e.secret.len())
            .any(|w| w == e.secret.as_bytes())
    );

    let codes = a
        .totp_confirm(&code_at(&secret, now()))
        .await
        .unwrap()
        .recovery_codes;
    assert_eq!(codes.len(), 10);
    let st = a.totp_status().await.unwrap();
    assert!(st.enabled && !st.enrolling && st.recovery_codes_left == 10);
    // Enrolling again while it is on is refused, and does not replace the secret.
    assert_eq!(a.totp_enroll().await.unwrap_err().status(), Some(409));

    let audit: Vec<String> = a
        .audit(None, Some(50))
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(
        audit.contains(&"totp.enroll".to_string()) && audit.contains(&"totp.enable".to_string()),
        "{audit:?}"
    );
}

#[tokio::test]
async fn sign_in_needs_the_code_and_no_session_exists_before_it() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let (secret, _) = enrol(&a).await;

    // The password step answers with a pending token, no cookie, and no access.
    let raw = reqwest::Client::new();
    let r = raw
        .post(format!("{}/api/v1/auth/login", url(&s)))
        .json(&json!({ "username": "admin", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers().get("set-cookie").is_none(),
        "no session before the code"
    );
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["second_factor"], "totp");
    assert!(v.get("user").is_none() && v.get("csrf").is_none());

    let (c, pending) = pending_of(&s, "admin").await;
    assert!(c.me().await.unwrap_err().is_unauthorized());
    assert!(c.flows(&Default::default()).await.unwrap_err().is_unauthorized());

    // A wrong code, a malformed one and a bad token are all refused.
    assert_eq!(
        c.login_totp(&pending, "123456").await.unwrap_err().status(),
        Some(401)
    );
    assert_eq!(
        c.login_totp(&pending, "abc").await.unwrap_err().status(),
        Some(401)
    );
    assert_eq!(
        c.login_totp("bosun_pending_nope", "123456")
            .await
            .unwrap_err()
            .status(),
        Some(401)
    );
    assert!(c.me().await.unwrap_err().is_unauthorized());

    // (The current step was used up by the confirmation, so the next step's code is the one that works.)
    let code = code_at(&secret, now() + STEP_SECS);
    let me = c.login_totp(&pending, &code).await.unwrap();
    assert_eq!(me.user.username, "admin");
    c.flows(&Default::default()).await.unwrap();
    // The pending token is spent.
    assert_eq!(
        c.login_totp(&pending, &code).await.unwrap_err().status(),
        Some(401)
    );

    let audit: Vec<String> = c
        .audit(None, Some(50))
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    for want in ["login.password", "login.totp.failed", "login"] {
        assert!(audit.contains(&want.to_string()), "{want} in {audit:?}");
    }
}

#[tokio::test]
async fn a_code_works_once_and_the_window_is_one_step() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let (secret, _) = enrol(&a).await;
    let t = now();

    // Confirmation used this step's code already: it cannot sign in.
    let (c, pending) = pending_of(&s, "admin").await;
    let cur = code_at(&secret, t);
    assert_eq!(
        c.login_totp(&pending, &cur).await.unwrap_err().status(),
        Some(401),
        "the code that confirmed enrolment is used up"
    );

    // The next step's code is inside the window and works once ...
    let (c2, p2) = pending_of(&s, "admin").await;
    let next = code_at(&secret, t + STEP_SECS);
    c2.login_totp(&p2, &next).await.unwrap();
    // ... and a second time (a replay) is refused, as is the older step after it.
    let (c3, p3) = pending_of(&s, "admin").await;
    assert_eq!(
        c3.login_totp(&p3, &next).await.unwrap_err().status(),
        Some(401),
        "replay"
    );
    let (c4, p4) = pending_of(&s, "admin").await;
    let prev = code_at(&secret, t.saturating_sub(STEP_SECS));
    assert_eq!(
        c4.login_totp(&p4, &prev).await.unwrap_err().status(),
        Some(401),
        "older than the last used step"
    );
    // Two steps ahead is outside the window.
    let (c5, p5) = pending_of(&s, "admin").await;
    let far = code_at(&secret, t + 3 * STEP_SECS);
    assert_eq!(
        c5.login_totp(&p5, &far).await.unwrap_err().status(),
        Some(401),
        "outside the window"
    );
}

#[tokio::test]
async fn recovery_codes_work_once_and_can_be_replaced() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let (secret, codes) = enrol(&a).await;
    assert_eq!(codes.len(), 10);
    // Stored hashed: the codes are not in the database.
    assert!(codes.iter().all(|c| c.len() == 19));

    let (c, p) = pending_of(&s, "admin").await;
    c.login_totp(&p, &codes[0]).await.unwrap();
    assert_eq!(a.totp_status().await.unwrap().recovery_codes_left, 9);
    let (c, p) = pending_of(&s, "admin").await;
    assert_eq!(
        c.login_totp(&p, &codes[0]).await.unwrap_err().status(),
        Some(401),
        "used once"
    );
    // Lower case and no dashes still match another code.
    let (c, p) = pending_of(&s, "admin").await;
    c.login_totp(&p, &codes[1].to_lowercase().replace('-', ""))
        .await
        .unwrap();

    // New codes need a valid code, and replace the old set.
    assert_eq!(
        a.totp_recovery_codes("000000").await.unwrap_err().status(),
        Some(403)
    );
    let fresh = a
        .totp_recovery_codes(&code_at(&secret, now() + STEP_SECS))
        .await
        .unwrap()
        .recovery_codes;
    assert_eq!(fresh.len(), 10);
    assert_eq!(a.totp_status().await.unwrap().recovery_codes_left, 10);
    let (c, p) = pending_of(&s, "admin").await;
    assert_eq!(
        c.login_totp(&p, &codes[2]).await.unwrap_err().status(),
        Some(401),
        "old set is gone"
    );
    let (c, p) = pending_of(&s, "admin").await;
    c.login_totp(&p, &fresh[0]).await.unwrap();
}

#[tokio::test]
async fn disabling_needs_a_valid_code() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let (secret, _) = enrol(&a).await;
    assert_eq!(a.totp_disable("000000").await.unwrap_err().status(), Some(403));
    assert!(a.totp_status().await.unwrap().enabled);
    a.totp_disable(&code_at(&secret, now() + STEP_SECS))
        .await
        .unwrap();
    assert!(!a.totp_status().await.unwrap().enabled);
    // Signing in no longer asks for a code, and the factor can be set up afresh.
    Client::new(url(&s))
        .unwrap()
        .login("admin", PASSWORD)
        .await
        .unwrap();
    enrol(&a).await;
    let audit: Vec<String> = a
        .audit(None, Some(50))
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(audit.contains(&"totp.disable".to_string()), "{audit:?}");
}

#[tokio::test]
async fn wrong_codes_are_throttled_like_wrong_passwords() {
    let s = stack(true).await;
    let a = admin(&s).await;
    enrol(&a).await;
    let (c, p) = pending_of(&s, "admin").await;
    let mut seen = vec![];
    for _ in 0..4 {
        let e = c.login_totp(&p, "000000").await.unwrap_err();
        seen.push(e.status().unwrap());
    }
    // The first attempts are free; after that the next one is held back, and the answer says to wait.
    assert_eq!(&seen[..3], &[401, 401, 401], "{seen:?}");
    assert_eq!(seen[3], 429, "{seen:?}");

    // The refusal carries Retry-After.
    let raw = reqwest::Client::new();
    let r = raw
        .post(format!("{}/api/v1/auth/login/totp", url(&s)))
        .json(&json!({ "pending": p, "code": "000000" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    assert!(r.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn an_admin_resets_a_users_factor_and_it_is_audited() {
    let s = stack(true).await;
    let a = admin(&s).await;
    let u = a.create_user("ann", PASSWORD, Role::Tester).await.unwrap();
    let ann = Client::new(url(&s)).unwrap();
    ann.login("ann", PASSWORD).await.unwrap();
    enrol(&ann).await;
    let _ = pending_of(&s, "ann").await;

    // Only an admin may; a user cannot reset their own through the admin route.
    assert_eq!(ann.reset_user_totp(u.id).await.unwrap_err().status(), Some(403));
    let anon = Client::new(url(&s)).unwrap();
    assert!(anon.reset_user_totp(u.id).await.unwrap_err().is_unauthorized());

    a.reset_user_totp(u.id).await.unwrap();
    // Ann's session ended, and her next sign-in asks for no code.
    assert!(ann.me().await.unwrap_err().is_unauthorized());
    Client::new(url(&s))
        .unwrap()
        .login("ann", PASSWORD)
        .await
        .unwrap();
    // Nothing left to reset.
    assert_eq!(a.reset_user_totp(u.id).await.unwrap_err().status(), Some(404));

    let entry = a
        .audit(None, Some(50))
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.action == "user.totp.reset")
        .expect("an audit entry");
    assert_eq!(entry.username.as_deref(), Some("admin"));
    assert!(entry.detail.contains(&u.id.to_string()));
}

#[tokio::test]
async fn the_cli_style_reset_in_the_store_removes_the_factor() {
    let s = stack(true).await;
    let a = admin(&s).await;
    enrol(&a).await;
    assert!(s.app.totp_enabled(1).unwrap());
    assert!(s.app.totp_remove(1).unwrap());
    assert!(!s.app.totp_enabled(1).unwrap());
    assert_eq!(s.app.totp_recovery_left(1).unwrap(), 0);
    assert!(!s.app.totp_remove(1).unwrap());
}

#[tokio::test]
async fn an_admin_can_require_a_second_factor_of_everyone() {
    let s = stack(true).await;
    let a = admin(&s).await;
    a.create_user("ann", PASSWORD, Role::Tester).await.unwrap();
    let ann = Client::new(url(&s)).unwrap();
    ann.login("ann", PASSWORD).await.unwrap();
    // Tester and viewer may not change the policy.
    assert_eq!(ann.totp_set_required(true).await.unwrap_err().status(), Some(403));

    let st = a.totp_set_required(true).await.unwrap();
    assert!(st.required && st.setup_required, "the admin has no factor yet");

    // Until a factor is set up, a session reaches only what sets it up.
    let err = ann.flows(&Default::default()).await.unwrap_err();
    assert_eq!(err.status(), Some(403), "{err}");
    assert!(err.to_string().contains("second factor"));
    assert!(ann.totp_status().await.unwrap().setup_required);
    ann.me().await.unwrap();
    let (secret, _) = enrol(&ann).await;
    ann.flows(&Default::default()).await.unwrap();
    assert!(!ann.totp_status().await.unwrap().setup_required);

    // The admin is held to the same rule and enrols to carry on.
    assert_eq!(a.users().await.unwrap_err().status(), Some(403));
    enrol(&a).await;
    a.users().await.unwrap();

    // The requirement survives a restart (it is stored), and an admin can lift it.
    assert_eq!(s.app.meta("totp_required").unwrap().as_deref(), Some("1"));
    let st = a.totp_set_required(false).await.unwrap();
    assert!(!st.required);
    assert_eq!(s.app.meta("totp_required").unwrap().as_deref(), Some("0"));
    let _ = secret;
    let audit: Vec<String> = a
        .audit(None, Some(50))
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(
        audit.iter().filter(|x| *x == "totp.policy").count() == 2,
        "{audit:?}"
    );
}
