//! A typed client for the Bosun engine's API, for the CLI, the TUI and the tests.
//!
//! ```no_run
//! # async fn demo() -> bosun_client::Result<()> {
//! let client = bosun_client::Client::builder("http://127.0.0.1:8090").token("bosun_…").build()?;
//! for flow in client.flows(&Default::default()).await? {
//!     println!("{} {}{}", flow.method, flow.host, flow.path);
//! }
//! # Ok(()) }
//! ```
//!
//! Every operation in `docs/openapi.json` has a method here (the tests check that). Two ways to sign in:
//! an API token ([`ClientBuilder::token`]), or a username and password ([`Client::login`]) which keeps the session
//! cookie and sends the CSRF token for you.

mod checks;
pub use checks::{ClientCert, VaultEntry};
mod client;
mod error;
mod events;
mod issues;
pub mod types;

pub use client::{Client, ClientBuilder};
pub use error::{Error, Result};
pub use events::{EventStream, Position, Sequenced};
pub use issues::*;
pub use types::*;
