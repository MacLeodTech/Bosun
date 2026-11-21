//! The per-install certificate authority used to intercept TLS.
//!
//! Every install generates its own CA on first run; nothing is shared between installs, so trusting one
//! install's CA never lets anyone else intercept your traffic. The private key is sealed with the install's
//! data key (see [`sealed`]) and only the certificate is ever written in the clear.
//!
//! Leaf certificates are made on demand for each host, signed by the CA, valid for a short time, and cached in
//! memory. All leaves of one running process share one key pair (generated at start-up, never written to disk),
//! which keeps issuing cheap.

pub mod sealed;

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

pub use sealed::{DataKey, SealError};

const CA_CERT_FILE: &str = "ca.crt.pem";
const CA_KEY_FILE: &str = "ca.key.sealed";
const SEAL_PURPOSE: &str = "bosun-ca-key-v1";
const CA_VALIDITY_DAYS: i64 = 3 * 365;
const LEAF_VALIDITY_DAYS: i64 = 30;
const LEAF_CACHE: usize = 1024;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error("I/O error on {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("invalid host name for a certificate: {0:?}")]
    BadHost(String),
    #[error("the CA files are incomplete: {0} exists but {1} does not")]
    Incomplete(String, String),
}

/// The CA and its leaf cache.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    leaf_key: KeyPair,
    cache: Mutex<lru::LruCache<(String, bool), Arc<ServerConfig>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert_path: PathBuf,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("cert_path", &self.cert_path)
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Load the CA from `dir`, or create a new one there.
    pub fn load_or_create(dir: &Path, key: &DataKey) -> Result<Self, CaError> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let io = |p: &Path| {
            let path = p.display().to_string();
            move |source| CaError::Io { path, source }
        };
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                let pem = std::fs::read_to_string(&cert_path).map_err(io(&cert_path))?;
                let sealed = std::fs::read(&key_path).map_err(io(&key_path))?;
                sealed::check_private(&key_path)?;
                let pkcs8 = key.open(SEAL_PURPOSE, &sealed)?;
                let ca_key = KeyPair::try_from(pkcs8.as_slice())?;
                Self::from_parts(&pem, ca_key, cert_path)
            }
            (false, false) => {
                std::fs::create_dir_all(dir).map_err(io(dir))?;
                let (pem, ca_key) = generate_ca()?;
                let sealed = key.seal(SEAL_PURPOSE, &ca_key.serialize_der())?;
                sealed::write_private(&key_path, &sealed).map_err(io(&key_path))?;
                std::fs::write(&cert_path, &pem).map_err(io(&cert_path))?;
                tracing::info!(path = %cert_path.display(), "created a new CA for this install");
                Self::from_parts(&pem, ca_key, cert_path)
            }
            (true, false) => Err(CaError::Incomplete(
                cert_path.display().to_string(),
                key_path.display().to_string(),
            )),
            (false, true) => Err(CaError::Incomplete(
                key_path.display().to_string(),
                cert_path.display().to_string(),
            )),
        }
    }

    /// Generate a throwaway CA held only in memory (tests, and `--ephemeral-ca`).
    pub fn ephemeral() -> Result<Self, CaError> {
        let (pem, ca_key) = generate_ca()?;
        Self::from_parts(&pem, ca_key, PathBuf::new())
    }

    fn from_parts(pem: &str, ca_key: KeyPair, cert_path: PathBuf) -> Result<Self, CaError> {
        let ca_der = CertificateDer::from(pem_to_der(pem).ok_or(rcgen::Error::CouldNotParseCertificate)?);
        let issuer = Issuer::from_ca_cert_der(&ca_der, ca_key)?;
        Ok(Self {
            issuer,
            ca_der,
            ca_pem: pem.to_string(),
            leaf_key: KeyPair::generate()?,
            cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(LEAF_CACHE).unwrap_or(NonZeroUsize::MIN),
            )),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            cert_path,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        self.ca_der.as_ref()
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// SHA-256 fingerprint of the CA certificate, hex with colons (what browsers show).
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.ca_der.as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Base64 SHA-256 of the CA's SubjectPublicKeyInfo, for Chromium's
    /// `--ignore-certificate-errors-spki-list`. Lets the launched browser accept our certificates without the
    /// CA being installed anywhere.
    pub fn spki_hash(&self) -> String {
        use rcgen::PublicKeyData;
        let spki = self.issuer.key().subject_public_key_info();
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki))
    }

    /// A rustls server config presenting a leaf certificate for `host`. `h2` controls whether HTTP/2 is offered
    /// over ALPN.
    pub fn server_config(&self, host: &str, h2: bool) -> Result<Arc<ServerConfig>, CaError> {
        let host = normalise_host(host)?;
        let key = (host.clone(), h2);
        if let Some(cfg) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return Ok(cfg.clone());
        }
        let leaf = self.issue_leaf(&host)?;
        let chain = vec![leaf, self.ca_der.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, private)?;
        cfg.alpn_protocols = if h2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let cfg = Arc::new(cfg);
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, cfg.clone());
        Ok(cfg)
    }

    fn issue_leaf(&self, host: &str) -> Result<CertificateDer<'static>, CaError> {
        let mut params = CertificateParams::default();
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.to_string().try_into()?),
        };
        params.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn.push(DnType::OrganizationName, "Bosun");
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
        params.serial_number = Some(random_serial());
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        Ok(cert.der().clone())
    }
}

/// Lower-case the host, strip IPv6 brackets and a trailing dot, and refuse anything that could not be a host.
fn normalise_host(host: &str) -> Result<String, CaError> {
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.parse::<IpAddr>().is_ok() {
        return Ok(h);
    }
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if ok {
        Ok(h)
    } else {
        Err(CaError::BadHost(host.to_string()))
    }
}

fn generate_ca() -> Result<(String, KeyPair), CaError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut id = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut id);
    let id = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("Bosun local CA {id}"));
    dn.push(
        DnType::OrganizationName,
        "Bosun (testing CA, unique to this install)",
    );
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
    params.serial_number = Some(random_serial());
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key))
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
    b[0] &= 0x7f; // keep it positive
    SerialNumber::from_slice(&b)
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_reloads_and_keeps_identity() {
        let dir = tempfile::tempdir().unwrap();
        let key = DataKey::generate();
        let a = CertificateAuthority::load_or_create(dir.path(), &key).unwrap();
        let b = CertificateAuthority::load_or_create(dir.path(), &key).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.spki_hash(), b.spki_hash());
        // The key on disk is sealed: no PEM private key, and the wrong data key cannot open it.
        let sealed = std::fs::read(dir.path().join(CA_KEY_FILE)).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("PRIVATE KEY"));
        assert!(CertificateAuthority::load_or_create(dir.path(), &DataKey::generate()).is_err());
    }

    #[test]
    fn issues_leaves_for_names_and_ips_and_caches_them() {
        let ca = CertificateAuthority::ephemeral().unwrap();
        let a = ca.server_config("Example.com.", true).unwrap();
        let b = ca.server_config("example.com", true).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols[0], b"h2");
        ca.server_config("127.0.0.1", false).unwrap();
        ca.server_config("[::1]", false).unwrap();
    }

    #[test]
    fn refuses_bad_hosts() {
        let ca = CertificateAuthority::ephemeral().unwrap();
        for h in ["", "a..b", "evil host", "x/y", &"a".repeat(64), "*.example.com"] {
            assert!(ca.server_config(h, false).is_err(), "{h:?} should be refused");
        }
    }
}
