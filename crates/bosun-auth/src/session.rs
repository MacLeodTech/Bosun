//! Session handling: sign in with a login macro, keep the session's headers, and sign in again when it expires.
//!
//! The macro is a recorded login request (with its credentials already filled in from the vault by the caller) and
//! a rule for what to keep from the answer: every cookie it sets, or a token from its body or a header. The
//! session's headers then replace the `Cookie` and `Authorization` headers of whatever the caller sends. When an
//! answer looks like an expired session ([`Expiry`]), the caller asks for a refresh and tries once more.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{FlowSource, Target};
use regex::Regex;

/// Sign-ins one session will do before it gives up (a wrong password must not loop).
pub const MAX_SIGN_INS: u32 = 25;

/// What to keep from the login answer.
#[derive(Debug, Clone)]
pub enum Capture {
    /// Every `Set-Cookie` of the answer, sent back as one `Cookie` header.
    Cookies,
    /// The first capture group of `pattern` on the body, sent as `header: {prefix}{value}`.
    Body {
        pattern: Regex,
        header: String,
        prefix: String,
    },
    /// The value of a response header, sent as `header: {prefix}{value}`.
    Header {
        from: String,
        header: String,
        prefix: String,
    },
}

/// When an answer means the session has ended.
#[derive(Debug, Clone)]
pub struct Expiry {
    pub statuses: Vec<u16>,
    /// A redirect whose `Location` contains this (the login page).
    pub redirect_contains: Option<String>,
    /// A body that contains this.
    pub body_contains: Option<String>,
}

impl Default for Expiry {
    fn default() -> Self {
        Self {
            statuses: vec![401],
            redirect_contains: Some("login".into()),
            body_contains: None,
        }
    }
}

impl Expiry {
    /// `headers` are lowercased names and text values.
    pub fn expired(&self, status: u16, headers: &[(String, String)], body: &str) -> bool {
        if self.statuses.contains(&status) {
            return true;
        }
        if (300..400).contains(&status)
            && let Some(frag) = &self.redirect_contains
            && headers
                .iter()
                .any(|(k, v)| k == "location" && v.to_ascii_lowercase().contains(&frag.to_ascii_lowercase()))
        {
            return true;
        }
        self.body_contains
            .as_ref()
            .is_some_and(|b| body.contains(b.as_str()))
    }
}

#[derive(Debug, Clone)]
pub struct LoginMacro {
    pub target: Target,
    pub request: Vec<u8>,
    pub capture: Capture,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("the login request was refused: {0}")]
    Refused(String),
    #[error("the login request failed: {0}")]
    Send(String),
    #[error("the login did not give a session (status {0:?}); check the credentials and the capture rule")]
    NoSession(Option<u16>),
    #[error("{0}")]
    Failed(String),
    #[error("gave up after {0} sign-ins")]
    TooMany(u32),
}

#[derive(Default)]
struct State {
    headers: Vec<(String, String)>,
    signed_in: bool,
    /// The first sign-in failure. Nothing signs in again after it: a wrong password must not be tried over and
    /// over (it could lock the account).
    failed: Option<String>,
}

/// A live session. Share it behind an `Arc`.
pub struct Session {
    engine: Engine,
    login: LoginMacro,
    pub expiry: Expiry,
    state: tokio::sync::Mutex<State>,
    generation: AtomicU64,
    sign_ins: AtomicU32,
}

impl Session {
    pub fn new(engine: Engine, login: LoginMacro, expiry: Expiry) -> Self {
        Self {
            engine,
            login,
            expiry,
            state: tokio::sync::Mutex::default(),
            generation: AtomicU64::new(0),
            sign_ins: AtomicU32::new(0),
        }
    }

    /// How many times this session has signed in.
    pub fn sign_ins(&self) -> u32 {
        self.sign_ins.load(Ordering::SeqCst)
    }

    /// The session's headers and their generation, signing in first if there is no session yet.
    pub async fn headers(&self) -> Result<(Vec<(String, String)>, u64), SessionError> {
        let mut st = self.state.lock().await;
        if !st.signed_in {
            self.sign_in(&mut st).await?;
        }
        Ok((st.headers.clone(), self.generation.load(Ordering::SeqCst)))
    }

    /// Sign in again, unless another caller already has since `stale` (the generation the failing request used).
    pub async fn refresh(&self, stale: u64) -> Result<(), SessionError> {
        let mut st = self.state.lock().await;
        if self.generation.load(Ordering::SeqCst) != stale && st.signed_in {
            return Ok(());
        }
        self.sign_in(&mut st).await
    }

    async fn sign_in(&self, st: &mut State) -> Result<(), SessionError> {
        if let Some(why) = &st.failed {
            return Err(SessionError::Failed(why.clone()));
        }
        let r = self.try_sign_in(st).await;
        if let Err(e) = &r {
            st.signed_in = false;
            st.failed = Some(e.to_string());
        }
        r
    }

    async fn try_sign_in(&self, st: &mut State) -> Result<(), SessionError> {
        if self.sign_ins.fetch_add(1, Ordering::SeqCst) >= MAX_SIGN_INS {
            self.sign_ins.fetch_sub(1, Ordering::SeqCst);
            return Err(SessionError::TooMany(MAX_SIGN_INS));
        }
        let opts = SendOptions {
            source: FlowSource::Scanner,
            update_content_length: true,
            ..SendOptions::default()
        };
        let ex = self
            .engine
            .send(&self.login.target, &self.login.request, &opts)
            .await
            .map_err(|e| match e {
                SendError::Refused(e) => SessionError::Refused(e.to_string()),
                e => SessionError::Send(e.to_string()),
            })?;
        let headers = capture(&self.login.capture, &ex.response);
        if headers.is_empty() {
            st.signed_in = false;
            return Err(SessionError::NoSession(ex.status));
        }
        st.headers = headers;
        st.signed_in = true;
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn split(raw: &[u8]) -> (Vec<(String, String)>, String) {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match end {
        Some(p) => (&raw[..p], &raw[p + 4..]),
        None => (raw, &[][..]),
    };
    let headers = String::from_utf8_lossy(head)
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (headers, String::from_utf8_lossy(body).into_owned())
}

fn capture(rule: &Capture, response: &[u8]) -> Vec<(String, String)> {
    let (headers, body) = split(response);
    match rule {
        Capture::Cookies => {
            let jar: Vec<String> = headers
                .iter()
                .filter(|(k, _)| k == "set-cookie")
                .filter_map(|(_, v)| v.split(';').next())
                .filter(|c| c.contains('=') && !c.ends_with('=')) // an emptied cookie clears it
                .map(str::to_string)
                .collect();
            if jar.is_empty() {
                vec![]
            } else {
                vec![("Cookie".into(), jar.join("; "))]
            }
        }
        Capture::Body {
            pattern,
            header,
            prefix,
        } => pattern
            .captures(&body)
            .and_then(|c| c.get(1))
            .map(|m| vec![(header.clone(), format!("{prefix}{}", m.as_str()))])
            .unwrap_or_default(),
        Capture::Header { from, header, prefix } => headers
            .iter()
            .find(|(k, _)| *k == from.to_ascii_lowercase())
            .map(|(_, v)| vec![(header.clone(), format!("{prefix}{v}"))])
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(k: &str, v: &str) -> (String, String) {
        (k.into(), v.into())
    }

    #[test]
    fn expiry_matches_status_login_redirect_and_body() {
        let e = Expiry::default();
        assert!(e.expired(401, &[], ""));
        assert!(e.expired(302, &[h("location", "/Login?next=/app")], ""));
        assert!(!e.expired(302, &[h("location", "/app/next")], ""));
        assert!(!e.expired(200, &[], "welcome"));
        let e = Expiry {
            body_contains: Some("session expired".into()),
            ..Expiry::default()
        };
        assert!(e.expired(200, &[], "error: session expired"));
    }

    #[test]
    fn capture_keeps_cookies_a_body_token_or_a_header() {
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/; HttpOnly\r\nSet-Cookie: gone=; Max-Age=0\r\nSet-Cookie: t=1\r\nX-Token: hdr\r\n\r\n{\"token\":\"tok123\"}";
        assert_eq!(capture(&Capture::Cookies, resp), [h("Cookie", "sid=abc; t=1")]);
        let body = Capture::Body {
            pattern: Regex::new(r#""token":"([^"]+)""#).unwrap(),
            header: "Authorization".into(),
            prefix: "Bearer ".into(),
        };
        assert_eq!(capture(&body, resp), [h("Authorization", "Bearer tok123")]);
        let hdr = Capture::Header {
            from: "X-Token".into(),
            header: "X-Auth".into(),
            prefix: String::new(),
        };
        assert_eq!(capture(&hdr, resp), [h("X-Auth", "hdr")]);
        assert!(capture(&Capture::Cookies, b"HTTP/1.1 401 No\r\n\r\n").is_empty());
    }
}
