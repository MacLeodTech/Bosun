//! `bosun advisory keygen|sign`: make the Ed25519 key pair and the detached signature for an advisory feed (WP-82).
//! The engine only verifies; whoever publishes feeds signs them with this (or any Ed25519 tool). Nothing here needs a
//! project or a running engine.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Make a key pair. The private key (PKCS#8) is written to `out` (never over a file that exists, readable by the
/// owner only); the public key is returned, base64, ready for `PUT /advisories/trust`.
pub fn keygen(out: &Path) -> Result<String> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("no random numbers"))?;
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("cannot create {} (it must not exist)", out.display()))?;
    f.write_all(STANDARD.encode(pkcs8.as_ref()).as_bytes())?;
    Ok(STANDARD.encode(kp.public_key().as_ref()))
}

/// Sign the feed file's exact bytes. The feed is checked first, so a feed the engine would refuse is not signed.
pub fn sign(key: &Path, feed: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(key).with_context(|| format!("cannot read {}", key.display()))?;
    let pkcs8 = STANDARD
        .decode(raw.trim())
        .context("the key file is not a key made by `bosun advisory keygen`")?;
    let kp = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| anyhow::anyhow!("the key file is not an Ed25519 key"))?;
    let bytes = std::fs::read(feed).with_context(|| format!("cannot read {}", feed.display()))?;
    if bytes.len() > bosun_checks::advisory::MAX_FEED_BYTES {
        bail!("the feed is too large");
    }
    let parsed: bosun_checks::advisory::Feed =
        serde_json::from_slice(&bytes).context("the feed is not valid JSON of the feed format")?;
    parsed.check().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(STANDARD.encode(kp.sign(&bytes).as_ref()))
}
