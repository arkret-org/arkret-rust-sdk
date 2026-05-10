//! Off-target stub for [`LinuxSecretServiceKeyStore`].
//!
//! Used when either the target is not Linux or the `keystore-linux` feature
//! is disabled. Constructors return [`KeyStoreError::Unsupported`]; trait
//! methods do the same so naive callers don't panic.

use crate::Result;
use crate::keystore::{KeyStore, KeyStoreError};

/// Linux Secret Service-backed [`KeyStore`] (off-target stub).
#[derive(Debug)]
pub struct LinuxSecretServiceKeyStore {
    _private: (),
}

impl LinuxSecretServiceKeyStore {
    /// Construct a keystore for the given application id. Off-target this
    /// always returns [`KeyStoreError::Unsupported`].
    pub fn new(_application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        Err(KeyStoreError::unsupported(
            "LinuxSecretServiceKeyStore requires target_os = \"linux\" + feature \"keystore-linux\"",
        ))
    }
}

impl KeyStore for LinuxSecretServiceKeyStore {
    fn load(&self, _id: &str) -> Result<Vec<u8>> {
        Err(KeyStoreError::unsupported("LinuxSecretServiceKeyStore (stub)").into())
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        Err(KeyStoreError::unsupported("LinuxSecretServiceKeyStore (stub)").into())
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(KeyStoreError::unsupported("LinuxSecretServiceKeyStore (stub)").into())
    }

    fn delete(&self, _id: &str) -> Result<()> {
        Err(KeyStoreError::unsupported("LinuxSecretServiceKeyStore (stub)").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_target_constructor_returns_unsupported() {
        let err = LinuxSecretServiceKeyStore::new("test.app").unwrap_err();
        assert!(matches!(err, KeyStoreError::Unsupported { .. }));
        assert!(format!("{err}").contains("keystore-linux"));
    }
}
