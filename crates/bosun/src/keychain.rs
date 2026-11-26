//! Where the data key lives: a file in the data directory, or the operating system's keychain (Windows
//! Credential Manager, macOS Keychain, Secret Service on Linux). The desktop apps default to the keychain;
//! servers keep the file, `BOSUN_DATA_KEY` or `BOSUN_DATA_KEY_FILE`.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use bosun_ca::DataKey;
use serde::{Deserialize, Serialize};

use crate::{Config, Paths};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    File,
    Keychain,
}

impl KeySource {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "file" => Some(Self::File),
            "keychain" => Some(Self::Keychain),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Keychain => "keychain",
        }
    }
}

/// One secret slot in a keychain. Values are the base64 data key.
pub trait SecretStore {
    fn get(&self) -> Result<Option<String>>;
    fn set(&self, value: &str) -> Result<()>;
    fn delete(&self) -> Result<()>;
    fn describe(&self) -> String;
}

/// The real OS keychain. One entry per data directory, so two installs do not share a key.
pub struct OsKeychain {
    account: String,
}

impl OsKeychain {
    pub fn for_paths(paths: &Paths) -> Self {
        Self {
            account: format!("data-key:{}", paths.data.display()),
        }
    }
    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new("Bosun", &self.account).map_err(|e| anyhow!("the OS keychain is not usable: {e}"))
    }
}

impl SecretStore for OsKeychain {
    fn get(&self) -> Result<Option<String>> {
        match self.entry()?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => bail!("cannot read the data key from the OS keychain: {e}"),
        }
    }
    fn set(&self, value: &str) -> Result<()> {
        self.entry()?
            .set_password(value)
            .map_err(|e| anyhow!("cannot store the data key in the OS keychain: {e}"))
    }
    fn delete(&self) -> Result<()> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => bail!("cannot remove the data key from the OS keychain: {e}"),
        }
    }
    fn describe(&self) -> String {
        "the OS keychain".into()
    }
}

/// An in-memory store, for tests.
#[derive(Default)]
pub struct MemoryKeychain(Mutex<Option<String>>);

impl SecretStore for MemoryKeychain {
    fn get(&self) -> Result<Option<String>> {
        Ok(self.0.lock().map_err(|_| anyhow!("poisoned"))?.clone())
    }
    fn set(&self, value: &str) -> Result<()> {
        *self.0.lock().map_err(|_| anyhow!("poisoned"))? = Some(value.to_string());
        Ok(())
    }
    fn delete(&self) -> Result<()> {
        *self.0.lock().map_err(|_| anyhow!("poisoned"))? = None;
        Ok(())
    }
    fn describe(&self) -> String {
        "the in-memory keychain".into()
    }
}

/// Where the key comes from for this run: `BOSUN_DATA_KEY` and an explicit key file win; then the configured
/// source (`data_key_store`, `BOSUN_DATA_KEY_STORE`); then, for the desktop apps, the keychain unless a
/// `data.key` already exists; otherwise the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Env,
    ExplicitFile,
    File,
    Keychain,
}

pub fn resolve_source(cfg: &Config, paths: &Paths) -> Resolved {
    if std::env::var_os("BOSUN_DATA_KEY").is_some() {
        return Resolved::Env;
    }
    if cfg.data_key_file.is_some() {
        return Resolved::ExplicitFile;
    }
    match cfg.data_key_store {
        Some(KeySource::File) => Resolved::File,
        Some(KeySource::Keychain) => Resolved::Keychain,
        None if cfg.keychain_default && !paths.key().exists() => Resolved::Keychain,
        None => Resolved::File,
    }
}

pub fn load_key_with(cfg: &Config, paths: &Paths, store: &dyn SecretStore) -> Result<DataKey> {
    match resolve_source(cfg, paths) {
        Resolved::Keychain => load_from_store(paths, store),
        _ => DataKey::resolve(cfg.data_key_file.as_deref(), &paths.key()).map_err(Into::into),
    }
}

fn load_from_store(paths: &Paths, store: &dyn SecretStore) -> Result<DataKey> {
    if let Some(v) = store.get()? {
        return DataKey::from_base64(&v).context("the data key in the keychain is invalid");
    }
    // A new key is only made for a brand-new install; otherwise it would orphan what the old key sealed.
    if paths.key().exists() {
        bail!(
            "the keychain has no data key for this install, but {} exists; run `bosun key migrate --to keychain` \
             or set data_key_store = \"file\"",
            paths.key().display()
        );
    }
    if paths.ca().join("ca.key.sealed").exists() {
        bail!(
            "the keychain has no data key for this install, but the CA is already sealed with one; restore the \
             keychain entry (or the key file and `bosun key migrate --to keychain`)"
        );
    }
    let key = DataKey::generate();
    store.set(&encode(&key))?;
    Ok(key)
}

fn encode(key: &DataKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.export())
}

/// Move the key between the file and the keychain. The key bytes do not change, so everything sealed with it
/// (CA key, TOTP secrets, vault entries) stays readable; the CA key is opened with the key from its new
/// location before the old copy is removed.
pub fn migrate(cfg: &Config, paths: &Paths, to: KeySource, store: &dyn SecretStore) -> Result<String> {
    if matches!(resolve_source(cfg, paths), Resolved::Env | Resolved::ExplicitFile) {
        bail!("the key comes from BOSUN_DATA_KEY or BOSUN_DATA_KEY_FILE; nothing to migrate");
    }
    let key_file = paths.key();
    match to {
        KeySource::Keychain => {
            if !key_file.exists() {
                if store.get()?.is_some() {
                    return Ok(format!("the data key is already in {}", store.describe()));
                }
                bail!("there is no {} to move", key_file.display());
            }
            let key = DataKey::load_or_create(&key_file)?;
            store.set(&encode(&key))?;
            verify(paths, &stored(store)?, &key)?;
            remove_private(&key_file)?;
            Ok(format!(
                "moved the data key into {}; removed {}",
                store.describe(),
                key_file.display()
            ))
        }
        KeySource::File => {
            let Some(v) = store.get()? else {
                if key_file.exists() {
                    return Ok(format!("the data key is already in {}", key_file.display()));
                }
                bail!("the keychain has no data key for this install: nothing to move");
            };
            if key_file.exists() {
                bail!("{} already exists; remove it first", key_file.display());
            }
            let key = DataKey::from_base64(&v)?;
            std::fs::create_dir_all(&paths.data)?;
            DataKey::write_file(&key_file, &key)?;
            verify(paths, &DataKey::load_or_create(&key_file)?, &key)?;
            store.delete()?;
            Ok(format!(
                "moved the data key into {}; removed it from {}",
                key_file.display(),
                store.describe()
            ))
        }
    }
}

fn stored(store: &dyn SecretStore) -> Result<DataKey> {
    let v = store.get()?.context("the keychain did not keep the data key")?;
    DataKey::from_base64(&v).map_err(Into::into)
}

/// The copy at the destination must equal the original and open the sealed CA key, if there is one.
fn verify(paths: &Paths, copy: &DataKey, original: &DataKey) -> Result<()> {
    if copy.export() != original.export() {
        bail!("the key read back from its new location differs; nothing was removed");
    }
    if paths.ca().join("ca.key.sealed").exists() {
        bosun_ca::CertificateAuthority::load_or_create(&paths.ca(), copy)
            .context("the CA key does not open with the moved key; nothing was removed")?;
    }
    Ok(())
}

fn remove_private(p: &Path) -> Result<()> {
    // Overwrite first so the key does not linger in the file's blocks (best effort).
    if let Ok(meta) = std::fs::metadata(p) {
        let _ = std::fs::write(p, vec![0u8; meta.len() as usize]);
    }
    std::fs::remove_file(p).with_context(|| format!("cannot remove {}", p.display()))
}

/// Where the key lives, for `doctor`.
pub fn describe(cfg: &Config, paths: &Paths) -> String {
    match resolve_source(cfg, paths) {
        Resolved::Env => "BOSUN_DATA_KEY".into(),
        Resolved::ExplicitFile => cfg
            .data_key_file
            .as_ref()
            .map(|f| f.display().to_string())
            .unwrap_or_default(),
        Resolved::File => paths.key().display().to_string(),
        Resolved::Keychain => "the OS keychain".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Paths, Config) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::new(d.path().to_path_buf());
        (d, paths, Config::default())
    }

    #[test]
    fn missing_entry_for_existing_install_is_a_clear_error() {
        let (_d, paths, mut cfg) = setup();
        cfg.data_key_store = Some(KeySource::Keychain);
        std::fs::write(paths.key(), "x").unwrap();
        let e = load_key_with(&cfg, &paths, &MemoryKeychain::default()).unwrap_err();
        assert!(e.to_string().contains("keychain has no data key"), "{e}");
    }

    #[test]
    fn fresh_install_creates_then_reuses() {
        let (_d, paths, mut cfg) = setup();
        cfg.data_key_store = Some(KeySource::Keychain);
        let s = MemoryKeychain::default();
        let a = load_key_with(&cfg, &paths, &s).unwrap();
        let b = load_key_with(&cfg, &paths, &s).unwrap();
        assert_eq!(a.export(), b.export());
        assert!(!paths.key().exists());
    }

    #[test]
    fn desktop_default_keeps_an_existing_file() {
        let (_d, paths, mut cfg) = setup();
        cfg.keychain_default = true;
        assert_eq!(resolve_source(&cfg, &paths), Resolved::Keychain);
        DataKey::load_or_create(&paths.key()).unwrap();
        assert_eq!(resolve_source(&cfg, &paths), Resolved::File);
    }

    #[test]
    fn migration_round_trips() {
        let (_d, paths, mut cfg) = setup();
        let s = MemoryKeychain::default();
        let key = DataKey::load_or_create(&paths.key()).unwrap();
        std::fs::create_dir_all(paths.ca()).unwrap();
        let ca = bosun_ca::CertificateAuthority::load_or_create(&paths.ca(), &key).unwrap();
        let fp = ca.fingerprint();
        migrate(&cfg, &paths, KeySource::Keychain, &s).unwrap();
        assert!(!paths.key().exists());
        cfg.data_key_store = Some(KeySource::Keychain);
        let k2 = load_key_with(&cfg, &paths, &s).unwrap();
        let ca2 = bosun_ca::CertificateAuthority::load_or_create(&paths.ca(), &k2).unwrap();
        assert_eq!(ca2.fingerprint(), fp);
        cfg.data_key_store = None;
        migrate(&cfg, &paths, KeySource::File, &s).unwrap();
        assert!(paths.key().exists());
        assert!(s.get().unwrap().is_none());
        let k3 = load_key_with(&cfg, &paths, &s).unwrap();
        assert_eq!(k3.export(), key.export());
    }

    #[test]
    fn migrate_refuses_when_the_key_is_external() {
        let (_d, paths, mut cfg) = setup();
        cfg.data_key_file = Some(paths.data.join("k"));
        assert!(migrate(&cfg, &paths, KeySource::Keychain, &MemoryKeychain::default()).is_err());
    }
}
