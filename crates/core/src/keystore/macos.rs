//! macOS Keychain Services backend for [`KeyStore`].
//!
//! Wires generic-password keychain items via the `security-framework`
//! crate. Each Cokret-using app supplies an `application_id` at
//! construction time; items are stored under the service name
//! `"cokret.<application_id>"` so independent apps don't trample each
//! other on a shared host.
//!
//! Implementation notes:
//! - Items are written as **generic passwords** (`SecGenericPasswordItem`)
//!   keyed on `(service, account)` where `service` is the namespaced
//!   service-name and `account` is the caller-supplied key id.
//! - `list()` enumerates all generic-password items whose service field
//!   equals our service name.
//! - `delete()` is idempotent — a "not found" error from the underlying
//!   `delete_generic_password` is swallowed.

use security_framework::base::Error as SfError;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::Result;
use crate::keystore::{KeyStore, KeyStoreError, service_name, validate_id};

/// macOS Keychain-backed [`KeyStore`].
///
/// Construct with [`MacOsKeychainKeyStore::new`] supplying the host
/// application id (a stable reverse-DNS string, e.g.
/// `"chat.acroidea.yougen"`). All keychain items written through this
/// keystore live under service `"cokret.<application_id>"`.
pub struct MacOsKeychainKeyStore {
    service: String,
}

impl MacOsKeychainKeyStore {
    /// Construct the keystore for the given application id.
    ///
    /// On macOS with the `keystore-macos` feature enabled this just
    /// records the namespaced service-name; the underlying Keychain
    /// session is acquired lazily on each call.
    pub fn new(application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id("application_id must be non-empty"));
        }
        Ok(Self { service: service_name(application_id) })
    }

    /// Service-name prefix used by this keystore (testing hook).
    #[doc(hidden)]
    pub fn service_name(&self) -> &str {
        &self.service
    }

    fn map_sf<T>(res: std::result::Result<T, SfError>) -> std::result::Result<T, KeyStoreError> {
        res.map_err(|err| KeyStoreError::backend(format!("keychain: {err}")))
    }
}

impl KeyStore for MacOsKeychainKeyStore {
    fn load(&self, id: &str) -> Result<Vec<u8>> {
        validate_id(id)?;
        match get_generic_password(&self.service, id) {
            Ok(bytes) => Ok(bytes),
            Err(err) if is_not_found(&err) => Err(KeyStoreError::not_found(id).into()),
            Err(err) => Err(KeyStoreError::backend(format!("keychain: {err}")).into()),
        }
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        Self::map_sf(set_generic_password(&self.service, id, key))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        // Use SecItemCopyMatching via security-framework's item module.
        // We request `load_attributes(true)` so each result is a `Dict`
        // containing the `acct` (account / our key id) attribute.
        use security_framework::item::{ItemClass, ItemSearchOptions};

        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::generic_password());
        search.service(&self.service);
        // `i64::MAX` would overflow the underlying CFNumber; use a high
        // but bounded ceiling. Real keystores never approach this.
        search.limit(i64::from(i32::MAX));
        search.load_attributes(true);

        let results = match search.search() {
            Ok(results) => results,
            Err(err) if is_not_found(&err) => return Ok(Vec::new()),
            Err(err) => {
                return Err(KeyStoreError::backend(format!("keychain enum: {err}")).into());
            }
        };

        let mut ids = Vec::new();
        for result in results {
            // `simplify_dict()` returns the loaded attribute dict as a
            // `HashMap<String, String>`. The "acct" attribute holds our
            // caller-supplied key id.
            if let Some(attrs) = result.simplify_dict()
                && let Some(account) = attrs.get("acct")
            {
                ids.push(account.clone());
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        match delete_generic_password(&self.service, id) {
            Ok(()) => Ok(()),
            Err(err) if is_not_found(&err) => Ok(()), // idempotent
            Err(err) => Err(KeyStoreError::backend(format!("keychain delete: {err}")).into()),
        }
    }
}

/// Map Keychain Services' "errSecItemNotFound" to our `NotFound` shape.
fn is_not_found(err: &SfError) -> bool {
    // errSecItemNotFound = -25300
    err.code() == -25300
}

#[cfg(test)]
mod tests {
    //! These tests are skipped automatically off-macOS via the parent
    //! module's `cfg(target_os = "macos", feature = "keystore-macos")`
    //! gate. On a macOS CI runner they exercise live Keychain Services
    //! calls; on a fresh user account that's harmless because each test
    //! cleans up its own items.

    use super::*;

    fn unique_app_id() -> String {
        format!("cokret.test.{}", uuid_like())
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        format!("{nanos:x}")
    }

    #[test]
    fn round_trip_store_load_delete() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:alice:k1";
        store.store(id, b"keychain-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap(), b"keychain-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(format!("{err}").contains("key not found"));
    }

    #[test]
    fn store_overwrites_existing_id() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        assert!(store.store("", b"x").is_err());
        assert!(store.load("").is_err());
        assert!(store.delete("").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = MacOsKeychainKeyStore::new(&app_a).unwrap();
        let store_b = MacOsKeychainKeyStore::new(&app_b).unwrap();
        store_a.store("k-a-1", b"a1").unwrap();
        store_a.store("k-a-2", b"a2").unwrap();
        store_b.store("k-b-1", b"b1").unwrap();

        let listed_a = store_a.list().unwrap();
        assert!(listed_a.contains(&"k-a-1".to_owned()));
        assert!(listed_a.contains(&"k-a-2".to_owned()));
        assert!(!listed_a.contains(&"k-b-1".to_owned()));

        store_a.delete("k-a-1").unwrap();
        store_a.delete("k-a-2").unwrap();
        store_b.delete("k-b-1").unwrap();
    }
}
