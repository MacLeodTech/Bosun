//! The advisory database for known-vulnerable components (WP-82), and the signed feed that updates it.
//!
//! An advisory names a product (lowercase, as [`crate::components`] spells it) and the version ranges that are
//! affected, in the style of OSV (`introduced` included, `fixed` excluded, `last_affected` included). The database
//! is offline: nothing here asks a third party about a version.
//!
//! A feed is a JSON file plus a detached Ed25519 signature over its exact bytes. [`verify`] accepts it only when one
//! of the trusted public keys verifies the signature, then checks the content (sizes, characters, schema) before
//! anything is used. `sequence` must rise with every feed, so an old, validly signed feed cannot be put back
//! (the caller compares it with the one it holds). A small database is built in (see `advisories/bundled.json`);
//! it is trusted because it ships with the program.

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bosun_store::Severity;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// The most advisories in one feed, and the most bytes.
pub const MAX_ADVISORIES: usize = 50_000;
pub const MAX_FEED_BYTES: usize = 16 << 20;
/// Public keys that may be trusted at once.
pub const MAX_KEYS: usize = 5;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    #[error("no trusted key is set, so no feed can be verified")]
    NoKeys,
    #[error("a trusted key is not a base64 Ed25519 public key (32 bytes)")]
    BadKey,
    #[error("the signature is not base64 of 64 bytes")]
    BadSignature,
    #[error("the signature does not match the feed under any trusted key")]
    Unverified,
    #[error("the feed is too large")]
    TooLarge,
    #[error("the feed is not valid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// First affected version (omitted: from the start).
    #[serde(default)]
    pub introduced: Option<String>,
    /// First version that is not affected.
    #[serde(default)]
    pub fixed: Option<String>,
    /// Last affected version, when no fix is known or the fix is not a release.
    #[serde(default)]
    pub last_affected: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Lowercase product name, as the fingerprints spell it (`nginx`, `apache`, `php`, `jquery`).
    pub product: String,
    pub summary: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub cwe: Vec<u32>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl Advisory {
    pub fn severity(&self) -> Severity {
        match self.severity.as_str() {
            // Issues have no `critical`; the advisory's own word stays in the issue text.
            "critical" | "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Whether `version` is in an affected range.
    pub fn affects(&self, version: &Version) -> bool {
        self.ranges.iter().any(|r| {
            let parse = |s: &Option<String>| s.as_deref().and_then(Version::parse);
            let from_ok = parse(&r.introduced).is_none_or(|v| *version >= v);
            let to_ok = match (parse(&r.fixed), parse(&r.last_affected)) {
                (Some(f), _) => *version < f,
                (None, Some(l)) => *version <= l,
                (None, None) => true,
            };
            from_ok && to_ok
        })
    }
}

/// A dotted numeric version (`1.18.0`). Anything after the numbers (`-1ubuntu`, `p1`, a letter) is ignored, so
/// `1.0.2k` reads as `1.0.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(Vec<u64>);

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        let mut parts = Vec::new();
        for p in s.split('.').take(6) {
            let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() || digits.len() > 9 {
                break;
            }
            parts.push(digits.parse().ok()?);
            if digits.len() != p.len() {
                break;
            }
        }
        // `2.4` and `2.4.0` are the same version.
        while parts.len() > 1 && parts.last() == Some(&0) {
            parts.pop();
        }
        (!parts.is_empty()).then_some(Self(parts))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let (a, b) = (self.0.get(i).unwrap_or(&0), other.0.get(i).unwrap_or(&0));
            match a.cmp(b) {
                std::cmp::Ordering::Equal => {}
                o => return o,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feed {
    pub schema: u32,
    /// Rises with every feed.
    pub sequence: u64,
    /// When it was made, `YYYY-MM-DD`.
    pub generated: String,
    pub advisories: Vec<Advisory>,
}

fn invalid<T>(m: impl Into<String>) -> Result<T, FeedError> {
    Err(FeedError::Invalid(m.into()))
}

impl Feed {
    /// Check the content of a feed (the signature is [`verify`]'s business).
    pub fn check(&self) -> Result<(), FeedError> {
        if self.schema != 1 {
            return invalid("the schema is not 1");
        }
        if self.advisories.len() > MAX_ADVISORIES {
            return invalid("too many advisories");
        }
        if self.generated.len() != 10 || !self.generated.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return invalid("`generated` is YYYY-MM-DD");
        }
        let plain = |s: &str, max: usize| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control);
        for a in &self.advisories {
            let product_ok = a.product.len() <= 64
                && !a.product.is_empty()
                && a.product.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_' | b'+')
                });
            if !plain(&a.id, 64) || !product_ok || !plain(&a.summary, 2000) {
                return invalid(format!(
                    "advisory `{}` has a bad id, product or summary",
                    a.id.chars().take(40).collect::<String>()
                ));
            }
            if !matches!(
                a.severity.as_str(),
                "critical" | "high" | "medium" | "low" | "info"
            ) {
                return invalid(format!("advisory `{}` has an unknown severity", a.id));
            }
            if a.ranges.is_empty()
                || a.ranges.len() > 50
                || a.aliases.len() > 20
                || a.cwe.len() > 20
                || a.references.len() > 20
            {
                return invalid(format!(
                    "advisory `{}` has too many or no ranges, aliases, CWEs or references",
                    a.id
                ));
            }
            if a.aliases.iter().any(|s| !plain(s, 64)) {
                return invalid(format!("advisory `{}` has a bad alias", a.id));
            }
            // A link is shown to people, so only web links, and no script or data URLs.
            if a.references.iter().any(|r| {
                !(r.starts_with("https://") || r.starts_with("http://")) || !plain(r, 500) || r.contains(' ')
            }) {
                return invalid(format!(
                    "advisory `{}` has a reference that is not an http(s) link",
                    a.id
                ));
            }
            for r in &a.ranges {
                for v in [&r.introduced, &r.fixed, &r.last_affected].into_iter().flatten() {
                    if Version::parse(v).is_none() {
                        return invalid(format!(
                            "advisory `{}` has a version that is not numeric: `{}`",
                            a.id,
                            v.chars().take(40).collect::<String>()
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Verify `feed` (the exact bytes) against the detached `signature` (base64) under any of `keys` (base64 Ed25519
/// public keys), then read and check it. Returns the feed and the index of the key that verified it.
pub fn verify(feed: &[u8], signature: &str, keys: &[String]) -> Result<(Feed, usize), FeedError> {
    if keys.is_empty() {
        return Err(FeedError::NoKeys);
    }
    if feed.len() > MAX_FEED_BYTES {
        return Err(FeedError::TooLarge);
    }
    let sig = STANDARD
        .decode(signature.trim())
        .ok()
        .filter(|s| s.len() == 64)
        .ok_or(FeedError::BadSignature)?;
    let mut verified = None;
    for (i, k) in keys.iter().enumerate() {
        let raw = STANDARD
            .decode(k.trim())
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(FeedError::BadKey)?;
        if verified.is_none() && UnparsedPublicKey::new(&ED25519, &raw).verify(feed, &sig).is_ok() {
            verified = Some(i);
        }
    }
    let key = verified.ok_or(FeedError::Unverified)?;
    let parsed: Feed = serde_json::from_slice(feed).map_err(|e| FeedError::Invalid(e.to_string()))?;
    parsed.check()?;
    Ok((parsed, key))
}

/// What the scanner matches against: the advisories, and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryDb {
    pub sequence: u64,
    pub generated: String,
    pub advisories: Vec<Advisory>,
    /// `bundled` or `feed`.
    pub source: &'static str,
}

static BUNDLED: LazyLock<AdvisoryDb> = LazyLock::new(|| {
    let feed: Feed = serde_json::from_str(include_str!("advisories/bundled.json")).unwrap_or(Feed {
        schema: 1,
        sequence: 0,
        generated: "1970-01-01".into(),
        advisories: Vec::new(),
    });
    AdvisoryDb {
        sequence: feed.sequence,
        generated: feed.generated,
        advisories: feed.advisories,
        source: "bundled",
    }
});

impl AdvisoryDb {
    /// The small database that ships with the program.
    pub fn bundled() -> &'static AdvisoryDb {
        &BUNDLED
    }

    pub fn from_feed(feed: Feed) -> Self {
        Self {
            sequence: feed.sequence,
            generated: feed.generated,
            advisories: feed.advisories,
            source: "feed",
        }
    }

    pub fn matching<'a>(
        &'a self,
        product: &'a str,
        version: &'a Version,
    ) -> impl Iterator<Item = &'a Advisory> {
        self.advisories
            .iter()
            .filter(move |a| a.product == product && a.affects(version))
    }
}

/// Settings keys in the project: the verified feed as received, and the public keys that may sign one.
pub const SETTING_FEED: &str = "advisory_feed";
pub const SETTING_KEYS: &str = "advisory_trust";

/// A feed as it was accepted: the exact bytes and the signature, so it is verified again whenever it is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub feed: String,
    pub signature: String,
    pub loaded_ms: i64,
}

/// The keys a feed may be signed with.
pub fn trusted_keys(p: &bosun_store::Project) -> Vec<String> {
    p.setting::<Vec<String>>(SETTING_KEYS)
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub fn stored(p: &bosun_store::Project) -> Option<Stored> {
    p.setting::<Stored>(SETTING_FEED).ok().flatten()
}

/// The database in force: the stored feed if it still verifies under the trusted keys, otherwise the built-in one.
/// A feed that no longer verifies (the keys changed, or the file was edited by hand) is not used.
pub fn load(p: &bosun_store::Project) -> AdvisoryDb {
    let Some(s) = stored(p) else {
        return AdvisoryDb::bundled().clone();
    };
    match verify(s.feed.as_bytes(), &s.signature, &trusted_keys(p)) {
        Ok((feed, _)) => AdvisoryDb::from_feed(feed),
        Err(e) => {
            tracing::warn!(error = %e, "the stored advisory feed does not verify; using the built-in advisories");
            AdvisoryDb::bundled().clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn keypair() -> (Ed25519KeyPair, String) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = STANDARD.encode(kp.public_key().as_ref());
        (kp, public)
    }

    fn feed_json(seq: u64) -> String {
        format!(
            r#"{{"schema":1,"sequence":{seq},"generated":"2026-11-28","advisories":[{{"id":"X-1","product":"nginx","summary":"s","severity":"high","ranges":[{{"fixed":"1.9.0"}}]}}]}}"#
        )
    }

    #[test]
    fn versions_compare_by_number_and_ignore_suffixes() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("1.18.0") < v("1.20.1"));
        assert!(v("1.9") < v("1.10"));
        assert_eq!(v("2.4"), v("2.4.0"));
        assert_eq!(v("5.6.40-1ubuntu2"), v("5.6.40"));
        assert_eq!(v("1.0.2k"), v("1.0.2"));
        assert!(Version::parse("abc").is_none() && Version::parse("").is_none());
    }

    #[test]
    fn ranges_include_the_start_and_exclude_the_fix() {
        let a = &AdvisoryDb::bundled().advisories[0];
        assert_eq!(a.id, "CVE-2021-41773");
        let v = |s| Version::parse(s).unwrap();
        assert!(a.affects(&v("2.4.49")));
        assert!(!a.affects(&v("2.4.48")) && !a.affects(&v("2.4.50")));
        let last = Advisory {
            ranges: vec![Range {
                introduced: None,
                fixed: None,
                last_affected: Some("3.0".into()),
            }],
            ..a.clone()
        };
        assert!(last.affects(&v("3.0.0")) && last.affects(&v("0.1")) && !last.affects(&v("3.0.1")));
    }

    #[test]
    fn a_feed_verifies_only_with_a_trusted_key_and_untouched_bytes() {
        let (kp, public) = keypair();
        let (_, other) = keypair();
        let body = feed_json(3);
        let sig = STANDARD.encode(kp.sign(body.as_bytes()).as_ref());
        let (feed, key) = verify(body.as_bytes(), &sig, &[other.clone(), public.clone()]).unwrap();
        assert_eq!((feed.sequence, key, feed.advisories.len()), (3, 1, 1));
        // The wrong key, no key, a changed byte, a bad signature.
        assert_eq!(
            verify(body.as_bytes(), &sig, &[other]).unwrap_err(),
            FeedError::Unverified
        );
        assert_eq!(verify(body.as_bytes(), &sig, &[]).unwrap_err(), FeedError::NoKeys);
        let tampered = body.replace("high", "info");
        assert_eq!(
            verify(tampered.as_bytes(), &sig, std::slice::from_ref(&public)).unwrap_err(),
            FeedError::Unverified
        );
        assert_eq!(
            verify(body.as_bytes(), "AAAA", std::slice::from_ref(&public)).unwrap_err(),
            FeedError::BadSignature
        );
        assert_eq!(
            verify(body.as_bytes(), &sig, &["AAAA".into()]).unwrap_err(),
            FeedError::BadKey
        );
    }

    #[test]
    fn a_signed_feed_with_bad_content_is_still_refused() {
        let (kp, public) = keypair();
        for bad in [
            feed_json(1).replace(r#""schema":1"#, r#""schema":2"#),
            feed_json(1).replace("nginx", "NGINX"),
            feed_json(1).replace(r#""high""#, r#""scary""#),
            feed_json(1).replace(r#""fixed":"1.9.0""#, r#""fixed":"soon""#),
            feed_json(1).replace(
                r#""severity""#,
                r#""references":["javascript:alert(1)"],"severity""#,
            ),
            feed_json(1).replace(r#""ranges":[{"fixed":"1.9.0"}]"#, r#""ranges":[]"#),
        ] {
            let sig = STANDARD.encode(kp.sign(bad.as_bytes()).as_ref());
            assert!(
                matches!(
                    verify(bad.as_bytes(), &sig, std::slice::from_ref(&public)),
                    Err(FeedError::Invalid(_))
                ),
                "{bad}"
            );
        }
    }
}
