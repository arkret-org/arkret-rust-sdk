//! Off-target stub for [`WindowsCredentialKeyStore`].
//!
//! Used when either the target is not Windows or the `keystore-windows`
//! feature is disabled. Constructors return [`KeyStoreError::Unsupported`];
//! trait methods do the same so naive callers don't panic.

use crate::contract::{KeyBytes, Result};
use crate::{KeyStore, KeyStoreError};

/// Windows Credential Manager-backed [`KeyStore`] (off-target stub).
#[derive(Debug)]
pub struct WindowsCredentialKeyStore {
    _private: (),
}

impl WindowsCredentialKeyStore {
    /// Construct a keystore for the given application id. Off-target this
    /// always returns [`KeyStoreError::Unsupported`].
    pub fn new(_application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        Err(KeyStoreError::unsupported(
            "WindowsCredentialKeyStore requires target_os = \"windows\" + feature \
             \"keystore-windows\"",
        ))
    }
}

impl KeyStore for WindowsCredentialKeyStore {
    fn load(&self, _id: &str) -> Result<KeyBytes> {
        Err(KeyStoreError::unsupported(
            "WindowsCredentialKeyStore (stub)",
        ))
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        Err(KeyStoreError::unsupported(
            "WindowsCredentialKeyStore (stub)",
        ))
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(KeyStoreError::unsupported(
            "WindowsCredentialKeyStore (stub)",
        ))
    }

    fn delete(&self, _id: &str) -> Result<()> {
        Err(KeyStoreError::unsupported(
            "WindowsCredentialKeyStore (stub)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_target_constructor_returns_unsupported() {
        let err = WindowsCredentialKeyStore::new("test.app").unwrap_err();
        assert!(matches!(err, KeyStoreError::Unsupported { .. }));
        assert!(format!("{err}").contains("keystore-windows"));
    }
}
