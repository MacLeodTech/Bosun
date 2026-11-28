use std::fmt;

/// What can go wrong calling the engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The engine answered with an error status. `message` is its `{"error": …}` text when it sent one.
    #[error("{status}: {message}")]
    Api { status: u16, message: String },
    /// The request did not complete (connection refused, timeout, TLS failure).
    #[error("could not reach the engine: {0}")]
    Transport(#[from] reqwest::Error),
    /// The password was right but the account has a second factor: finish with `Client::login_totp`, passing
    /// this token and a code from the authenticator app (or a recovery code).
    #[error("this account needs a second-factor code")]
    SecondFactor { pending: String },
    /// The answer was not the shape this client expects (a version mismatch).
    #[error("unexpected answer from the engine: {0}")]
    Decode(String),
    /// The event stream failed.
    #[error("event stream: {0}")]
    Events(String),
    /// The client was configured badly (for example an unreadable CA certificate).
    #[error("bad client setup: {0}")]
    Setup(String),
}

impl Error {
    /// The HTTP status of an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn is_unauthorized(&self) -> bool {
        self.status() == Some(401)
    }

    pub fn is_forbidden(&self) -> bool {
        self.status() == Some(403)
    }

    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    pub(crate) fn decode(e: impl fmt::Display) -> Self {
        Self::Decode(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
