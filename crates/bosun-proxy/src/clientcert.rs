//! Client certificates for targets that require mutual TLS, matched by host.
//!
//! The registry is shared by the proxy's upstream connector and the tools' engine, so both present the same
//! certificate to the same host. The private key is held here only as a signing key; the store keeps it sealed
//! and the API never returns it. Certificate and key files are untrusted input: [`parse_identity`] is fuzzed.

use std::sync::{Arc, RwLock};

use rustls::ClientConfig;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::sign::CertifiedKey;

/// The largest certificate file accepted.
pub const MAX_INPUT: usize = 64 * 1024;
const MAX_CHAIN: usize = 8;

/// A certificate chain (leaf first) and its private key.
pub struct Identity {
    pub chain: Vec<Vec<u8>>,
    /// Kind tag (1 PKCS#1, 2 SEC1, 8 PKCS#8) followed by the DER; this is what gets sealed.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("certs", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// Parse PEM (certificates and a private key in any order) or PKCS#12 (`password` may be empty).
pub fn parse_identity(data: &[u8], password: &str) -> Result<Identity, String> {
    if data.len() > MAX_INPUT {
        return Err("the file is too large".into());
    }
    let id = if data.windows(11).any(|w| w == b"-----BEGIN ") {
        parse_pem(data)?
    } else {
        parse_p12(data, password)?
    };
    if id.chain.is_empty() {
        return Err("no certificate found".into());
    }
    if id.chain.len() > MAX_CHAIN {
        return Err("the certificate chain is too long".into());
    }
    certified(&id)?;
    Ok(id)
}

fn parse_pem(data: &[u8]) -> Result<Identity, String> {
    let chain = CertificateDer::pem_slice_iter(data)
        .map(|c| c.map(|c| c.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(data).map_err(|_| "no private key found".to_string())?;
    Ok(Identity {
        chain,
        key: tag_key(&key),
    })
}

fn parse_p12(data: &[u8], password: &str) -> Result<Identity, String> {
    use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Strict)
        .map_err(|e| format!("not a readable PKCS#12 file (wrong password?): {e}"))?;
    let (_, pk) = ks
        .private_key_chain()
        .ok_or("the PKCS#12 file holds no private key")?;
    let mut key = vec![8];
    key.extend_from_slice(pk.key().as_der());
    Ok(Identity {
        chain: pk.certs().iter().map(|c| c.as_der().to_vec()).collect(),
        key,
    })
}

fn tag_key(k: &PrivateKeyDer<'_>) -> Vec<u8> {
    let (t, d) = match k {
        PrivateKeyDer::Pkcs1(d) => (1, d.secret_pkcs1_der()),
        PrivateKeyDer::Sec1(d) => (2, d.secret_sec1_der()),
        PrivateKeyDer::Pkcs8(d) => (8, d.secret_pkcs8_der()),
        _ => (0, &[][..]),
    };
    let mut v = vec![t];
    v.extend_from_slice(d);
    v
}

fn untag_key(k: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    let (t, d) = k.split_first().ok_or("empty key")?;
    Ok(match t {
        1 => PrivatePkcs1KeyDer::from(d.to_vec()).into(),
        2 => PrivateSec1KeyDer::from(d.to_vec()).into(),
        8 => PrivatePkcs8KeyDer::from(d.to_vec()).into(),
        _ => return Err("unknown key kind".into()),
    })
}

fn certified(id: &Identity) -> Result<Arc<CertifiedKey>, String> {
    let key = untag_key(&id.key)?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported private key: {e}"))?;
    let ck = CertifiedKey::new(
        id.chain.iter().map(|c| CertificateDer::from(c.clone())).collect(),
        signer,
    );
    ck.keys_match()
        .map_err(|e| format!("the private key does not match the certificate: {e}"))?;
    Ok(Arc::new(ck))
}

/// Subject and expiry (ms since the epoch) of the leaf certificate.
pub fn describe(id: &Identity) -> Result<(String, i64), String> {
    let leaf = id.chain.first().ok_or("no certificate")?;
    let (_, c) = x509_parser::parse_x509_certificate(leaf).map_err(|e| format!("certificate: {e}"))?;
    Ok((c.subject().to_string(), c.validity().not_after.timestamp() * 1000))
}

/// A host pattern: an exact name, or `*.example.com` for any name under it. Lower-cased.
pub fn normalize_pattern(p: &str) -> Result<String, String> {
    let p = p.trim().to_ascii_lowercase();
    let body = p.strip_prefix("*.").unwrap_or(&p);
    let ok = !body.is_empty()
        && p.len() <= 253
        && body.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':')
        });
    if ok {
        Ok(p)
    } else {
        Err("the host must be a name like `api.example.com` or `*.example.com`".into())
    }
}

fn matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => pattern == host,
    }
}

#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesClientCert for One {
    fn resolve(&self, _: &[&[u8]], _: &[rustls::SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

type Entries = Vec<(String, Arc<CertifiedKey>)>;

/// The certificates in force, shared between clones.
#[derive(Clone, Default)]
pub struct ClientCerts {
    entries: Arc<RwLock<Entries>>,
}

impl std::fmt::Debug for ClientCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCerts").finish_non_exhaustive()
    }
}

impl ClientCerts {
    /// Replace the set. Entries that no longer parse are skipped (logged), never fatal.
    pub fn replace(&self, items: Vec<(String, Identity)>) {
        let mut v: Vec<_> = items
            .into_iter()
            .filter_map(|(p, id)| match certified(&id) {
                Ok(c) => Some((p, c)),
                Err(e) => {
                    tracing::warn!(host = %p, error = %e, "a stored client certificate is unusable");
                    None
                }
            })
            .collect();
        // Exact names first, then the longest wildcard.
        v.sort_by_key(|(p, _)| (p.starts_with("*."), std::cmp::Reverse(p.len())));
        *self.entries.write().unwrap_or_else(|e| e.into_inner()) = v;
    }

    fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(p, _)| matches(p, &host))
            .map(|(_, c)| c.clone())
    }

    /// `cfg` as is, or a copy that presents the certificate configured for `host`.
    pub fn apply(&self, host: &str, cfg: Arc<ClientConfig>) -> Arc<ClientConfig> {
        match self.lookup(host) {
            None => cfg,
            Some(ck) => {
                let mut c = (*cfg).clone();
                c.client_auth_cert_resolver = Arc::new(One(ck));
                Arc::new(c)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(normalize_pattern(" API.Example.com ").unwrap(), "api.example.com");
        assert!(normalize_pattern("*.example.com").is_ok());
        assert!(normalize_pattern("a b").is_err());
        assert!(normalize_pattern("").is_err());
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "a.b.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "badexample.com"));
        assert!(matches("x.test", "x.test"));
    }

    #[test]
    fn pem_and_pkcs12_both_load() {
        use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
        let ck = rcgen::generate_simple_self_signed(vec!["c.test".to_string()]).unwrap();
        let (cert_der, key_der) = (ck.cert.der().to_vec(), ck.signing_key.serialize_der());
        let pem = format!("{}{}", ck.cert.pem(), ck.signing_key.serialize_pem());
        let id = parse_identity(pem.as_bytes(), "").unwrap();
        assert_eq!(id.chain.len(), 1);
        assert!(describe(&id).unwrap().0.contains("rcgen self signed cert"));

        let mut ks = KeyStore::new();
        let chain = PrivateKeyChain::new(
            vec![1u8],
            PrivateKey::from_der(&key_der).unwrap(),
            [Certificate::from_der(&cert_der).unwrap()],
        );
        ks.add_entry("a", KeyStoreEntry::PrivateKeyChain(chain));
        let p12 = ks.writer("pw").write().unwrap();
        assert_eq!(parse_identity(&p12, "pw").unwrap().chain, [cert_der]);
        assert!(parse_identity(&p12, "wrong").is_err());
    }

    #[test]
    fn garbage_is_refused() {
        assert!(parse_identity(b"nonsense", "").is_err());
        assert!(
            parse_identity(
                b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                ""
            )
            .is_err()
        );
    }
}
