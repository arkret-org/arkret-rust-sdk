//! Off-target stub for [`MacOsKeychainKeyStore`].
//!
//! Used when either the target is not macOS or the `keystore-macos` feature
//! is disabled. Constructors return [`KeyStoreError::Unsupported`]; trait
//! methods do the same so naive callers don't panic.

use cokret_core::Result;

use crate::{KeyStore, KeyStoreError};

/// macOS Keychain-backed [`KeyStore`] (off-target stub).
#[derive(Debug)]
pub struct MacOsKeychainKeyStore {
    _private: (),
}

impl MacOsKeychainKeyStore {
    /// Construct a keystore for the given application id. Off-target this
    /// always returns [`KeyStoreError::Unsupported`].
    pub fn new(_application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        Err(KeyStoreError::unsupported(
            "MacOsKeychainKeyStore requires target_os = \"macos\" + feature \"keystore-macos\"",
        ))
    }
}

impl KeyStore for MacOsKeychainKeyStore {
    fn load(&self, _id: &str) -> Result<Vec<u8>> {
        Err(KeyStoreError::unsupported("MacOsKeychainKeyStore (stub)").into())
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        Err(KeyStoreError::unsupported("MacOsKeychainKeyStore (stub)").into())
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(KeyStoreError::unsupported("MacOsKeychainKeyStore (stub)").into())
    }

    fn delete(&self, _id: &str) -> Result<()> {
        Err(KeyStoreError::unsupported("MacOsKeychainKeyStore (stub)").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_target_constructor_returns_unsupported() {
        let err = MacOsKeychainKeyStore::new("test.app").unwrap_err();
        assert!(matches!(err, KeyStoreError::Unsupported { .. }));
        assert!(format!("{err}").contains("keystore-macos"));
    }
}
