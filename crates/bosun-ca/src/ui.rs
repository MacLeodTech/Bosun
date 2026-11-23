//! The certificate the web UI is served with over HTTPS.
//!
//! It is deliberately *not* the interception CA's: a UI served with a CA-issued certificate pushes people to trust
//! that CA in their everyday browser, and whoever holds that CA's key could then impersonate any site to them.
//! Two sources instead:
//!
//! * certificate and key files the operator provides (for example from Let's Encrypt or an internal CA), reloaded
//!   when they change or on request (SIGHUP);
//! * a self-signed certificate made for the UI only. It is not a CA (`basicConstraints: CA:FALSE`, no
//!   `keyCertSign`), so trusting it lets nobody impersonate anything but this UI. Its key is sealed with the data
//!   key like the CA's.
//!
//! The recommended setup is still a TLS-terminating reverse proxy in front (see `docs/ui-tls.md`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration as StdDuration, Instant, SystemTime};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::sealed::{self, DataKey};
use crate::{CaError, random_serial};

const CERT_FILE: &str = "ui.crt.pem";
const KEY_FILE: &str = "ui.key.sealed";
/// What the certificate was made for, so a change of host names makes a new one.
const META_FILE: &str = "ui.meta";
const SEAL_PURPOSE: &str = "bosun-ui-key-v1";
const VALIDITY_DAYS: i64 = 365;
/// Make a fresh certificate when fewer than this many days remain.
const RENEW_DAYS: i64 = 30;
/// How often to look at configured files for changes.
const POLL: StdDuration = StdDuration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp(Vec<Option<SystemTime>>);

fn stamp(paths: &[&Path]) -> Stamp {
    Stamp(
        paths
            .iter()
            .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .collect(),
    )
}

struct Files {
    cert: PathBuf,
    key: PathBuf,
    seen: Stamp,
    checked: Instant,
}

/// The UI's TLS configuration, shared by every connection and refreshed when its source changes.
pub struct UiTls {
    current: RwLock<(Arc<ServerConfig>, String)>,
    files: Option<Mutex<Files>>,
}

impl std::fmt::Debug for UiTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiTls").finish_non_exhaustive()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn build(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(Arc<ServerConfig>, String), CaError> {
    let fingerprint = chain
        .first()
        .map(|c| fingerprint_of(c.as_ref()))
        .unwrap_or_default();
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((Arc::new(cfg), fingerprint))
}

fn fingerprint_of(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn io_err(p: &Path) -> impl FnOnce(std::io::Error) -> CaError {
    let path = p.display().to_string();
    move |source| CaError::Io { path, source }
}

fn pem_err(p: &Path, e: impl std::fmt::Display) -> CaError {
    CaError::Io {
        path: p.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
    }
}

fn load_files(cert: &Path, key: &Path) -> Result<(Arc<ServerConfig>, String), CaError> {
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|e| pem_err(cert, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_err(cert, e))?;
    if chain.is_empty() {
        return Err(pem_err(cert, "no certificate found"));
    }
    let private = PrivateKeyDer::from_pem_file(key).map_err(|e| pem_err(key, e))?;
    build(chain, private)
}

impl UiTls {
    /// Serve the certificate in `cert` (a PEM chain, leaf first) with the key in `key`. Both are re-read when
    /// either changes; a file that fails to load keeps the previous certificate in service.
    pub fn from_files(cert: &Path, key: &Path) -> Result<Self, CaError> {
        let current = load_files(cert, key)?;
        Ok(Self {
            current: RwLock::new(current),
            files: Some(Mutex::new(Files {
                cert: cert.to_path_buf(),
                key: key.to_path_buf(),
                seen: stamp(&[cert, key]),
                checked: Instant::now(),
            })),
        })
    }

    /// A self-signed, non-CA certificate for `hosts` (names and IP addresses), kept in `dir` with its key sealed.
    /// Reused until the hosts change or it is within 30 days of expiry.
    pub fn self_signed(dir: &Path, key: &DataKey, hosts: &[String]) -> Result<Self, CaError> {
        let (cert_path, key_path, meta_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE), dir.join(META_FILE));
        let mut hosts: Vec<String> = hosts.iter().map(|h| h.trim().to_ascii_lowercase()).collect();
        hosts.sort();
        hosts.dedup();
        let wanted = |expires: i64| format!("{}\n{expires}\n", hosts.join(","));
        let now = OffsetDateTime::now_utc();

        let existing = (|| {
            let pem = std::fs::read_to_string(&cert_path).ok()?;
            let sealed = std::fs::read(&key_path).ok()?;
            sealed::check_private(&key_path).ok()?;
            let meta = std::fs::read_to_string(&meta_path).ok()?;
            let (h, exp) = meta.trim_end().split_once('\n')?;
            let exp: i64 = exp.parse().ok()?;
            if h != hosts.join(",") || exp - now.unix_timestamp() < RENEW_DAYS * 86_400 {
                return None;
            }
            let pkcs8 = key.open(SEAL_PURPOSE, &sealed).ok()?;
            let der = CertificateDer::from_pem_slice(pem.as_bytes()).ok()?;
            Some((vec![der], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8))))
        })();
        let current = match existing {
            Some((chain, k)) => build(chain, k)?,
            None => {
                std::fs::create_dir_all(dir).map_err(io_err(dir))?;
                let (pem, der, pair) = generate(&hosts, now)?;
                sealed::write_private(&key_path, &key.seal(SEAL_PURPOSE, &pair.serialize_der())?)
                    .map_err(io_err(&key_path))?;
                std::fs::write(&cert_path, &pem).map_err(io_err(&cert_path))?;
                let expires = (now + Duration::days(VALIDITY_DAYS)).unix_timestamp();
                std::fs::write(&meta_path, wanted(expires)).map_err(io_err(&meta_path))?;
                tracing::info!(path = %cert_path.display(), "made a self-signed certificate for the UI");
                build(
                    vec![der],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der())),
                )?
            }
        };
        Ok(Self {
            current: RwLock::new(current),
            files: None,
        })
    }

    /// The configuration to hand to the next connection. With configured files this notices a change at most
    /// every ten seconds.
    pub fn config(&self) -> Arc<ServerConfig> {
        if let Some(files) = &self.files {
            let due = {
                let mut f = files.lock().unwrap_or_else(|e| e.into_inner());
                if f.checked.elapsed() >= POLL {
                    f.checked = Instant::now();
                    let now = stamp(&[&f.cert, &f.key]);
                    if now != f.seen {
                        f.seen = now;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if due {
                self.reload();
            }
        }
        self.current.read().unwrap_or_else(|e| e.into_inner()).0.clone()
    }

    /// Re-read configured files now (SIGHUP). A failure is logged and the old certificate stays.
    pub fn reload(&self) {
        let Some(files) = &self.files else { return };
        let (cert, key) = {
            let f = files.lock().unwrap_or_else(|e| e.into_inner());
            (f.cert.clone(), f.key.clone())
        };
        match load_files(&cert, &key) {
            Ok(c) => {
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = c;
                tracing::info!(cert = %cert.display(), "reloaded the UI certificate");
            }
            Err(e) => tracing::warn!(error = %e, "could not reload the UI certificate; keeping the old one"),
        }
    }

    /// SHA-256 fingerprint of the certificate being served.
    pub fn fingerprint(&self) -> String {
        self.current.read().unwrap_or_else(|e| e.into_inner()).1.clone()
    }
}

fn generate(
    hosts: &[String],
    now: OffsetDateTime,
) -> Result<(String, CertificateDer<'static>, KeyPair), CaError> {
    let pair = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut sans = Vec::new();
    for h in hosts {
        let h = h.trim_start_matches('[').trim_end_matches(']');
        sans.push(match h.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(h.to_string().try_into()?),
        });
    }
    params.subject_alt_names = sans;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Bosun web UI");
    dn.push(DnType::OrganizationName, "Bosun (UI certificate, not a CA)");
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    params.serial_number = Some(random_serial());
    let cert = params.self_signed(&pair)?;
    Ok((cert.pem(), cert.der().clone(), pair))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertificateAuthority;

    fn names() -> Vec<String> {
        vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()]
    }

    #[test]
    fn the_self_signed_certificate_is_not_the_ca_and_not_a_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::ephemeral().unwrap();
        let ui = UiTls::self_signed(dir.path(), &DataKey::generate(), &names()).unwrap();
        assert_ne!(ui.fingerprint(), ca.fingerprint());
        let pem = std::fs::read_to_string(dir.path().join(CERT_FILE)).unwrap();
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        assert!(
            !parsed.is_ca(),
            "the UI certificate must not be able to sign anything"
        );
        assert_ne!(parsed.issuer().to_string(), ca_subject(&ca));
        assert_eq!(parsed.issuer(), parsed.subject(), "self-signed");
        // Its key is sealed on disk.
        let sealed = std::fs::read(dir.path().join(KEY_FILE)).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("PRIVATE KEY"));
    }

    fn ca_subject(ca: &CertificateAuthority) -> String {
        let (_, c) = x509_parser::parse_x509_certificate(ca.cert_der()).unwrap();
        c.subject().to_string()
    }

    #[test]
    fn it_is_reused_until_the_host_names_change() {
        let dir = tempfile::tempdir().unwrap();
        let key = DataKey::generate();
        let a = UiTls::self_signed(dir.path(), &key, &names()).unwrap();
        let b = UiTls::self_signed(dir.path(), &key, &names()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        let mut more = names();
        more.push("bosun.example.test".into());
        let c = UiTls::self_signed(dir.path(), &key, &more).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
        // The wrong data key cannot be used to open it: it is regenerated rather than trusted.
        let d = UiTls::self_signed(dir.path(), &DataKey::generate(), &more).unwrap();
        assert_ne!(c.fingerprint(), d.fingerprint());
    }

    #[test]
    fn configured_files_are_served_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let write = |host: &str| {
            let pair = KeyPair::generate().unwrap();
            let params = CertificateParams::new(vec![host.to_string()]).unwrap();
            let cert = params.self_signed(&pair).unwrap();
            std::fs::write(dir.path().join("c.pem"), cert.pem()).unwrap();
            std::fs::write(dir.path().join("k.pem"), pair.serialize_pem()).unwrap();
            fingerprint_of(cert.der())
        };
        let first = write("one.test");
        let ui = UiTls::from_files(&dir.path().join("c.pem"), &dir.path().join("k.pem")).unwrap();
        assert_eq!(ui.fingerprint(), first);
        let second = write("two.test");
        ui.reload();
        assert_eq!(ui.fingerprint(), second);
        // A broken replacement leaves the working certificate in service.
        std::fs::write(dir.path().join("c.pem"), "garbage").unwrap();
        ui.reload();
        assert_eq!(ui.fingerprint(), second);
        assert!(UiTls::from_files(&dir.path().join("c.pem"), &dir.path().join("k.pem")).is_err());
    }
}
