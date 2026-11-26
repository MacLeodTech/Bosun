//! The Bosun intercepting proxy.
//!
//! An HTTP proxy that terminates TLS with per-host certificates from the install's CA, records every flow to
//! the project, and can hold requests and responses for editing. HTTP/1.1 and HTTP/2 on both sides (each hop
//! negotiates its own version), WebSockets, upstream HTTP/SOCKS5 proxies and TLS pass-through for hosts that
//! must not be intercepted.

pub mod body;
pub mod budget;
pub mod config;
pub mod events;
pub mod intercept;
mod limits;
pub mod recorder;
pub mod rules;
pub mod server;
pub mod upstream;
pub mod ws;

pub use config::{
    ListenerSpec, LiveSettings, ProxyAuth, ProxyConfig, RESTART_ONLY, UpstreamProxy, read_secret_file,
};
pub use events::{EventBus, EventReceiver, EventSender, ProxyEvent, Resume, Sequenced};
pub use intercept::{
    Decision, InterceptController, InterceptItem, InterceptSettings, InterceptSummary, Phase, ResponseFilter,
};
pub use limits::ConnLimit;
pub use rules::{RuleSet, RuleSpec, RuleTarget};
pub use server::{ListenerInfo, MAGIC_HOST, Proxy, ProxyError, ProxyStats};
pub use upstream::LoopGuard;
