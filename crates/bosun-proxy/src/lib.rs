//! The Bosun intercepting proxy.
//!
//! An HTTP proxy that terminates TLS with per-host certificates from the install's CA, records every flow to
//! the project, and can hold requests and responses for editing. HTTP/1.1 and HTTP/2 on both sides (each hop
//! negotiates its own version), WebSockets, upstream HTTP/SOCKS5 proxies and TLS pass-through for hosts that
//! must not be intercepted.

pub mod body;
pub mod config;
pub mod events;
pub mod intercept;
pub mod recorder;
pub mod rules;
pub mod server;
pub mod upstream;
pub mod ws;

pub use config::{ProxyAuth, ProxyConfig, UpstreamProxy};
pub use events::{EventSender, ProxyEvent};
pub use intercept::{
    Decision, InterceptController, InterceptItem, InterceptSettings, InterceptSummary, Phase,
};
pub use rules::{RuleSet, RuleSpec, RuleTarget};
pub use server::{MAGIC_HOST, Proxy, ProxyError};
pub use upstream::LoopGuard;
