//! Linux Secret Service (`org.freedesktop.secrets`) backend for [`KeyStore`].
//!
//! Uses the `secret-service` crate's blocking API to talk to the running
//! D-Bus Secret Service implementation (GNOME Keyring / KWallet /
//! `keepassxc-secret-service`). Items live in the user's default
//! collection (`/org/freedesktop/secrets/aliases/default`) and are tagged
//! with two attributes:
//!
//! - `service = "cokret.<application_id>"` — namespaces items so multiple
//!   Cokret-using apps on the same desktop don't collide.
//! - `account = <key_id>` — the caller-supplied opaque key id.
//!
//! Collisions on `(service, account)` are resolved by overwriting the
//! existing item (the Secret Service `replace` flag).

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;

use cokret_core::Result;
use cokret_core::keystore::{service_name, validate_id};

use crate::{KeyStore, KeyStoreError};

/// Linux Secret Service-backed [`KeyStore`].
pub struct LinuxSecretServiceKeyStore {
    service: String,
    /// Optional collection alias override; `None` means "default
    /// collection". Most desktop sessions only have one.
    collection_alias: Option<String>,
}

impl LinuxSecretServiceKeyStore {
    /// Construct a keystore for the given application id, using the
    /// default collection.
    pub fn new(application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id("application_id must be non-empty"));
        }
        // Probe the bus once so a missing Secret Service surfaces at
        // construction time rather than per call.
        Self::connect()?;
        Ok(Self { service: service_name(application_id), collection_alias: None })
    }

    /// Construct with an explicit collection alias (`"login"`,
    /// `"session"`, or any custom alias the desktop has set up).
    pub fn with_collection(
        application_id: &str,
        collection_alias: impl Into<String>,
    ) -> std::result::Result<Self, KeyStoreError> {
        let mut store = Self::new(application_id)?;
        store.collection_alias = Some(collection_alias.into());
        Ok(store)
    }

    fn connect() -> std::result::Result<SecretService<'static>, KeyStoreError> {
        SecretService::connect(EncryptionType::Dh)
            .map_err(|err| KeyStoreError::backend(format!("secret-service: {err}")))
    }

    fn collection_path(&self) -> &str {
        self.collection_alias.as_deref().unwrap_or("default")
    }

    fn attrs<'a>(&'a self, id: &'a str) -> std::collections::HashMap<&'a str, &'a str> {
        let mut a = std::collections::HashMap::new();
        a.insert("service", self.service.as_str());
        a.insert("account", id);
        a
    }
}

impl KeyStore for LinuxSecretServiceKeyStore {
    fn load(&self, id: &str) -> Result<Vec<u8>> {
        validate_id(id)?;
        let ss = Self::connect()?;
        let collection = ss
            .get_collection_by_alias(self.collection_path())
            .map_err(|err| KeyStoreError::backend(format!("get collection: {err}")))?;
        if collection.is_locked().unwrap_or(false) {
            collection
                .unlock()
                .map_err(|err| KeyStoreError::backend(format!("unlock collection: {err}")))?;
        }
        let attrs = self.attrs(id);
        let items = ss
            .search_items(attrs)
            .map_err(|err| KeyStoreError::backend(format!("search items: {err}")))?;
        let item = items
            .unlocked
            .into_iter()
            .chain(items.locked)
            .next()
            .ok_or_else(|| KeyStoreError::not_found(id))?;
        if item.is_locked().unwrap_or(false) {
            item.unlock().map_err(|err| KeyStoreError::backend(format!("unlock item: {err}")))?;
        }
        let secret = item
            .get_secret()
            .map_err(|err| KeyStoreError::backend(format!("get secret: {err}")))?;
        Ok(secret)
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        let ss = Self::connect()?;
        let collection = ss
            .get_collection_by_alias(self.collection_path())
            .map_err(|err| KeyStoreError::backend(format!("get collection: {err}")))?;
        if collection.is_locked().unwrap_or(false) {
            collection
                .unlock()
                .map_err(|err| KeyStoreError::backend(format!("unlock collection: {err}")))?;
        }
        let label = format!("{}/{}", self.service, id);
        let attrs = self.attrs(id);
        collection
            .create_item(&label, attrs, key, true /* replace */, "text/plain")
            .map_err(|err| KeyStoreError::backend(format!("create item: {err}")))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        let ss = Self::connect()?;
        // Search by `service = "cokret.<app>"` only; account is the key
        // id we're enumerating.
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("service", self.service.as_str());
        let items = ss
            .search_items(attrs)
            .map_err(|err| KeyStoreError::backend(format!("search items: {err}")))?;
        let mut ids = Vec::new();
        for item in items.unlocked.iter().chain(items.locked.iter()) {
            if let Ok(item_attrs) = item.get_attributes()
                && let Some(id) = item_attrs.get("account")
            {
                ids.push(id.clone());
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let ss = Self::connect()?;
        let attrs = self.attrs(id);
        let items = ss
            .search_items(attrs)
            .map_err(|err| KeyStoreError::backend(format!("search items: {err}")))?;
        for item in items.unlocked.into_iter().chain(items.locked) {
            item.delete().map_err(|err| KeyStoreError::backend(format!("delete item: {err}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Skipped automatically off-Linux. On Linux CI without a running
    //! D-Bus Secret Service these tests fail at construction with
    //! `KeyStoreError::Backend`; gate `COKRET_TEST_LINUX_KEYSTORE=1`
    //! before running.

    use super::*;

    fn enabled() -> bool {
        std::env::var("COKRET_TEST_LINUX_KEYSTORE").as_deref() == Ok("1")
    }

    fn unique_app_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        format!("test.{nanos:x}")
    }

    #[test]
    fn round_trip_store_load_delete() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:alice:k1";
        store.store(id, b"linux-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap(), b"linux-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(format!("{err}").contains("key not found"));
    }

    #[test]
    fn store_overwrites_existing_id() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        assert!(store.store("", b"x").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        if !enabled() {
            return;
        }
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = LinuxSecretServiceKeyStore::new(&app_a).unwrap();
        let store_b = LinuxSecretServiceKeyStore::new(&app_b).unwrap();
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
