//! Scope rules and the outbound-traffic gate.
//!
//! Scope answers "is this request part of the engagement?". The proxy uses it to label (and optionally hide or
//! not intercept) traffic. Every *active* tool (repeater, intruder, scanner, crawler, plugins) must go through
//! [`Gate::check`] before sending anything, and out-of-scope targets are refused unless the user turns that
//! protection off for a specific tool. Testing a host you are not allowed to test is the most damaging mistake a
//! DAST user can make, so the default is to refuse.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use bosun_model::{FlowSource, Scheme};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid host pattern {0:?}: {1}")]
    BadHost(String, String),
    #[error("invalid path regex {0:?}: {1}")]
    BadPath(String, String),
    #[error("{0} is out of scope")]
    OutOfScope(String),
    #[error("all outbound tool traffic is stopped (kill switch)")]
    Stopped,
}

/// One include or exclude rule, as the user writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuleSpec {
    /// `http`, `https`, or empty for both.
    #[serde(default)]
    pub scheme: Option<Scheme>,
    /// Host glob, case-insensitive. `example.com` matches that host only; `*.example.com` matches one level of
    /// sub-domain (`*` never crosses a dot), so add a rule per level you want. IP addresses work as literals.
    pub host: String,
    /// Port, or empty for any.
    #[serde(default)]
    pub port: Option<u16>,
    /// Regex matched against the path (without the query), or empty for any path.
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScopeSpec {
    #[serde(default)]
    pub include: Vec<RuleSpec>,
    #[serde(default)]
    pub exclude: Vec<RuleSpec>,
}

#[derive(Debug)]
struct Rule {
    scheme: Option<Scheme>,
    host: Regex,
    port: Option<u16>,
    path: Option<Regex>,
}

impl Rule {
    fn compile(spec: &RuleSpec) -> Result<Self, ScopeError> {
        let host_pat = spec.host.trim().to_ascii_lowercase();
        if host_pat.is_empty() {
            return Err(ScopeError::BadHost(spec.host.clone(), "empty".into()));
        }
        if !host_pat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.*:[]".contains(&b))
        {
            return Err(ScopeError::BadHost(
                spec.host.clone(),
                "only letters, digits, '-', '_', '.', ':' and '*' are allowed".into(),
            ));
        }
        // `*` matches within one label only, so `*.example.com` never matches `a.b.example.com`.
        let host_pat = host_pat.trim_start_matches('[').trim_end_matches(']');
        let re = format!("^{}$", regex::escape(host_pat).replace(r"\*", "[^.]*"));
        let host = Regex::new(&re).map_err(|e| ScopeError::BadHost(spec.host.clone(), e.to_string()))?;
        let path = match spec.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => Some(Regex::new(p).map_err(|e| ScopeError::BadPath(p.to_string(), e.to_string()))?),
            None => None,
        };
        Ok(Self {
            scheme: spec.scheme,
            host,
            port: spec.port,
            path,
        })
    }

    fn matches(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        self.scheme.is_none_or(|s| s == scheme)
            && self.port.is_none_or(|p| p == port)
            && self.host.is_match(host)
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
    }
}

/// Compiled scope. An empty include list means "nothing is in scope" (not "everything"): the user has to say
/// what they are testing.
#[derive(Debug, Default)]
pub struct Scope {
    spec: ScopeSpec,
    include: Vec<Rule>,
    exclude: Vec<Rule>,
}

impl Scope {
    pub fn compile(spec: ScopeSpec) -> Result<Self, ScopeError> {
        let include = spec.include.iter().map(Rule::compile).collect::<Result<_, _>>()?;
        let exclude = spec.exclude.iter().map(Rule::compile).collect::<Result<_, _>>()?;
        Ok(Self {
            spec,
            include,
            exclude,
        })
    }

    pub fn spec(&self) -> &ScopeSpec {
        &self.spec
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
    }

    /// `path` may include a query string; it is cut off before matching.
    pub fn contains(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let path = path.split(['?', '#']).next().unwrap_or("");
        let path = if path.is_empty() { "/" } else { path };
        self.include.iter().any(|r| r.matches(scheme, &host, port, path))
            && !self.exclude.iter().any(|r| r.matches(scheme, &host, port, path))
    }
}

/// Per-tool policy for out-of-scope targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutOfScopePolicy {
    /// Refuse to send (the default for every active tool).
    #[default]
    Refuse,
    /// Send anyway. Only for manual tools, and only when the user explicitly chose it.
    Allow,
}

/// The single choke point for outbound tool traffic. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct Gate {
    inner: Arc<GateInner>,
}

#[derive(Debug, Default)]
struct GateInner {
    scope: RwLock<Arc<Scope>>,
    stopped: AtomicBool,
    repeater_policy: RwLock<OutOfScopePolicy>,
}

impl Gate {
    pub fn new(scope: Scope) -> Self {
        let g = Self::default();
        g.set_scope(scope);
        g
    }

    pub fn scope(&self) -> Arc<Scope> {
        self.inner.scope.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_scope(&self, scope: Scope) {
        *self.inner.scope.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(scope);
    }

    /// Stop (or resume) all outbound tool traffic. Proxied browser traffic is not affected: the user is
    /// driving that by hand.
    pub fn set_stopped(&self, stopped: bool) {
        self.inner.stopped.store(stopped, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }

    pub fn set_repeater_policy(&self, p: OutOfScopePolicy) {
        *self
            .inner
            .repeater_policy
            .write()
            .unwrap_or_else(|e| e.into_inner()) = p;
    }

    /// May `source` send a request to this target now?
    pub fn check(
        &self,
        source: FlowSource,
        scheme: Scheme,
        host: &str,
        port: u16,
        path: &str,
    ) -> Result<(), ScopeError> {
        if source == FlowSource::Proxy {
            return Ok(());
        }
        if self.is_stopped() {
            return Err(ScopeError::Stopped);
        }
        if self.scope().contains(scheme, host, port, path) {
            return Ok(());
        }
        let policy = match source {
            FlowSource::Repeater => *self
                .inner
                .repeater_policy
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            // Automated tools never leave scope.
            _ => OutOfScopePolicy::Refuse,
        };
        match policy {
            OutOfScopePolicy::Allow => Ok(()),
            OutOfScopePolicy::Refuse => Err(ScopeError::OutOfScope(format!(
                "{}://{}:{}{}",
                scheme.as_str(),
                host,
                port,
                path
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str) -> RuleSpec {
        RuleSpec {
            host: host.into(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_scope_contains_nothing() {
        let s = Scope::compile(ScopeSpec::default()).unwrap();
        assert!(!s.contains(Scheme::Https, "example.com", 443, "/"));
    }

    #[test]
    fn host_globs_ports_paths_and_excludes() {
        let s = Scope::compile(ScopeSpec {
            include: vec![
                rule("example.com"),
                rule("*.example.com"),
                RuleSpec {
                    scheme: Some(Scheme::Https),
                    port: Some(8443),
                    ..rule("api.test")
                },
            ],
            exclude: vec![RuleSpec {
                path: Some("^/logout".into()),
                ..rule("*example.com")
            }],
        })
        .unwrap();
        assert!(s.contains(Scheme::Https, "EXAMPLE.com.", 443, "/a?x=1"));
        assert!(s.contains(Scheme::Http, "a.example.com", 80, "/"));
        assert!(
            !s.contains(Scheme::Http, "a.b.example.com", 80, "/"),
            "* does not cross dots"
        );
        assert!(!s.contains(Scheme::Http, "notexample.com", 80, "/"));
        assert!(!s.contains(Scheme::Https, "example.com", 443, "/logout?all"));
        assert!(s.contains(Scheme::Https, "api.test", 8443, "/"));
        assert!(!s.contains(Scheme::Http, "api.test", 8443, "/"));
        assert!(!s.contains(Scheme::Https, "api.test", 443, "/"));
    }

    #[test]
    fn gate_refuses_out_of_scope_for_tools_and_honours_kill_switch() {
        let g = Gate::new(
            Scope::compile(ScopeSpec {
                include: vec![rule("in.test")],
                exclude: vec![],
            })
            .unwrap(),
        );
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "in.test", 80, "/")
                .is_ok()
        );
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "out.test", 80, "/")
                .is_err()
        );
        assert!(
            g.check(FlowSource::Proxy, Scheme::Http, "out.test", 80, "/")
                .is_ok()
        );
        assert!(
            g.check(FlowSource::Repeater, Scheme::Http, "out.test", 80, "/")
                .is_err()
        );
        g.set_repeater_policy(OutOfScopePolicy::Allow);
        assert!(
            g.check(FlowSource::Repeater, Scheme::Http, "out.test", 80, "/")
                .is_ok()
        );
        assert!(
            g.check(FlowSource::Intruder, Scheme::Http, "out.test", 80, "/")
                .is_err()
        );
        g.set_stopped(true);
        assert!(matches!(
            g.check(FlowSource::Scanner, Scheme::Http, "in.test", 80, "/"),
            Err(ScopeError::Stopped)
        ));
    }

    #[test]
    fn bad_patterns_are_errors() {
        assert!(
            Scope::compile(ScopeSpec {
                include: vec![rule("")],
                exclude: vec![]
            })
            .is_err()
        );
        assert!(
            Scope::compile(ScopeSpec {
                include: vec![RuleSpec {
                    path: Some("(".into()),
                    ..rule("a")
                }],
                exclude: vec![]
            })
            .is_err()
        );
    }
}
