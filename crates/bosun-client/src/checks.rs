//! Custom passive checks.

use serde::Deserialize;

/// A stored custom check.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomCheck {
    pub id: i64,
    /// The `id` in the YAML: the rule name on the issues it finds.
    pub check_id: String,
    pub name: String,
    pub severity: String,
    pub enabled: bool,
    pub yaml: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CustomCheckList {
    pub checks: Vec<CustomCheck>,
}

/// A client certificate as listed: never the key.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCert {
    pub id: i64,
    pub host: String,
    pub subject: String,
    pub not_after_ms: i64,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ClientCertList {
    pub certs: Vec<ClientCert>,
}

/// A vault entry as listed: never the secret.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultEntry {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub hint: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VaultList {
    pub entries: Vec<VaultEntry>,
}

/// The outcome of `Client::validate_check`.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckValidation {
    pub valid: bool,
    pub error: Option<String>,
    pub check_id: Option<String>,
    pub name: Option<String>,
}
