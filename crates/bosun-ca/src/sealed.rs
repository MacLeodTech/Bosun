//! Sealing secrets at rest with the install's data key.
//!
//! The data key is 32 random bytes. It comes from, in order: the `BOSUN_DATA_KEY` environment variable (base64,
//! for containers that pass secrets as env), a key file given explicitly (for mounted secret files), or
//! `<data dir>/data.key`, created with mode 0600 on first run. Sealed blobs use ChaCha20-Poly1305 with a random
//! 96-bit nonce (fine for the small number of secrets sealed under one key) and a purpose label as associated
//! data, so a blob sealed for one purpose cannot be opened as another.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use thiserror::Error;

const MAGIC: &[u8; 5] = b"BSNS1";
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("I/O error on {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("the data key is invalid: {0}")]
    BadKey(&'static str),
    #[error("sealed data is corrupt or was sealed with a different data key")]
    Open,
    #[error("sealing failed")]
    Seal,
    #[error("{path} is readable by other users (mode {mode:o}); run `chmod 600 {path}`")]
    Permissions { path: String, mode: u32 },
}

/// The install's symmetric data key. Never logged, never serialised.
pub struct DataKey {
    key: [u8; 32],
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        // Best effort: overwrite the key before the memory is freed.
        self.key.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&self.key);
    }
}

impl DataKey {
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_base64(s: &str) -> Result<Self, SealError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| SealError::BadKey("not valid base64"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SealError::BadKey("must be 32 bytes"))?;
        Ok(Self { key })
    }

    /// Generate a fresh random key.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Load the key from `path`, creating it (mode 0600) when it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self, SealError> {
        let io = |source| SealError::Io {
            path: path.display().to_string(),
            source,
        };
        match fs::read_to_string(path) {
            Ok(s) => {
                check_private(path)?;
                Self::from_base64(&s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate();
                let encoded = base64::engine::general_purpose::STANDARD.encode(key.key);
                write_private(path, encoded.as_bytes()).map_err(io)?;
                Ok(key)
            }
            Err(e) => Err(io(e)),
        }
    }

    /// Resolve the key the way the binary does: env var, explicit file, or the default file in the data dir.
    pub fn resolve(explicit_file: Option<&Path>, default_file: &Path) -> Result<Self, SealError> {
        if let Ok(v) = std::env::var("BOSUN_DATA_KEY") {
            return Self::from_base64(&v);
        }
        match explicit_file {
            Some(p) => {
                let s = fs::read_to_string(p).map_err(|source| SealError::Io {
                    path: p.display().to_string(),
                    source,
                })?;
                Self::from_base64(&s)
            }
            None => Self::load_or_create(default_file),
        }
    }

    pub fn seal(&self, purpose: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let cipher = ChaCha20Poly1305::new(&Key::from(self.key));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| SealError::Seal)?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < MAGIC.len() + NONCE_LEN + 16 || &sealed[..MAGIC.len()] != MAGIC {
            return Err(SealError::Open);
        }
        let (nonce, ct) = sealed[MAGIC.len()..].split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce).map_err(|_| SealError::Open)?;
        let cipher = ChaCha20Poly1305::new(&Key::from(self.key));
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| SealError::Open)
    }
}

/// Write a file that only the owner can read, replacing it atomically.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Refuse a secret file that group or others can read.
///
/// On Windows there is no mode to check and this accepts every file. Access there is decided by ACLs, and the
/// data directory lives under the user's profile (`%LOCALAPPDATA%`), which other standard users cannot read; a
/// file created inside inherits that. Rewriting ACLs without `unsafe` code is not possible with the standard
/// library, so Bosun relies on the profile's protection and `docs/threat-model.md` says so. Keep the data
/// directory inside your profile (or another location only you can read) on Windows.
pub fn check_private(path: &Path) -> Result<(), SealError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|source| SealError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SealError::Permissions {
                path: path.display().to_string(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob sealed by an earlier build (and independently with Python's `cryptography`) must still open after
    /// a dependency upgrade, or every installed CA key would become unreadable.
    #[test]
    fn data_sealed_by_an_earlier_version_still_opens() {
        let blob = hex_decode(
            "42534e5331a0a1a2a3a4a5a6a7a8a9aaab67c5172823c6a3c3d3789666dc8e9888e95718ef75fae2fbd8468e3b82074f34c6",
        );
        let key = DataKey::from_bytes(core::array::from_fn(|i| i as u8));
        assert_eq!(key.open("ca-key", &blob).unwrap(), b"known answer test");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn seal_open_round_trip_and_purpose_binding() {
        let k = DataKey::generate();
        let sealed = k.seal("ca-key", b"secret").unwrap();
        assert_eq!(k.open("ca-key", &sealed).unwrap(), b"secret");
        assert!(k.open("vault", &sealed).is_err(), "purpose label must be bound");
        assert!(
            DataKey::generate().open("ca-key", &sealed).is_err(),
            "other key must fail"
        );
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(k.open("ca-key", &tampered).is_err());
    }

    #[test]
    fn key_file_is_created_private_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data.key");
        let a = DataKey::load_or_create(&p).unwrap();
        let b = DataKey::load_or_create(&p).unwrap();
        assert_eq!(a.key, b.key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                DataKey::load_or_create(&p),
                Err(SealError::Permissions { .. })
            ));
        }
    }
}
