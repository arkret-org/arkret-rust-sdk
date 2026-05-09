//! Pluggable key storage abstraction for SDK signers and HSM integrations.
//!
//! Round 22 (2026-05-09): expose a small [`KeyStore`] trait so downstream
//! crates (yougen real-key signing, soland anchorer-cell key custody,
//! coauth recovery flow) can swap between an in-process [`InMemoryKeyStore`]
//! and platform-native secret storage (macOS Keychain, Linux Secret
//! Service, Windows Credential Locker) without changing the public signing
//! surface.
//!
//! The trait stays small — `load` / `store` / `list` / `delete` only — so
//! it can wrap any of the platform backends behind a `// TODO(c10g-hsm)`
//! hook. Real platform implementations are stubbed out with
//! `unimplemented!()` here until the HSM workstream lands.
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"contrix:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use crate::{Error, Result};

/// Pluggable key storage interface.
///
/// Implementations MUST be concurrency-safe (typically `Send + Sync`) so
/// they can be shared across signer instances and threadpool workers.
///
/// # Errors
///
/// Implementations return [`Error::Protocol`] on backend failure. Missing
/// keys SHOULD surface as [`Error::Protocol`] with a "not found" message
/// (a dedicated `NotFound` variant lives in the SDK error module but is
/// not required for trait conformance).
pub trait KeyStore: Send + Sync {
    /// Load the raw key bytes for `id`.
    ///
    /// Returns the bytes verbatim; the caller is responsible for any
    /// envelope decoding (PKCS#8, raw seed, etc.).
    fn load(&self, id: &str) -> Result<Vec<u8>>;

    /// Persist `key` under `id`. Existing entries with the same id MUST be
    /// overwritten.
    fn store(&self, id: &str, key: &[u8]) -> Result<()>;

    /// List all key ids known to this store, sorted ascending.
    fn list(&self) -> Result<Vec<String>>;

    /// Delete the entry under `id`. Idempotent: deleting a missing id is
    /// not an error.
    fn delete(&self, id: &str) -> Result<()>;
}

/// In-process [`KeyStore`] backed by a `BTreeMap`. Suitable for tests and
/// for short-lived ephemeral signers. Not encrypted at rest.
#[derive(Default)]
pub struct InMemoryKeyStore {
    inner: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut BTreeMap<String, Vec<u8>>) -> T,
    {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(f(&mut guard))
    }
}

impl KeyStore for InMemoryKeyStore {
    fn load(&self, id: &str) -> Result<Vec<u8>> {
        let bytes = self.with_lock(|map| map.get(id).cloned())?;
        bytes.ok_or_else(|| Error::Protocol(format!("key not found: {id}")))
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        if id.is_empty() {
            return Err(Error::Protocol("KeyStore id must be non-empty".to_owned()));
        }
        self.with_lock(|map| {
            map.insert(id.to_owned(), key.to_vec());
        })
    }

    fn list(&self) -> Result<Vec<String>> {
        self.with_lock(|map| map.keys().cloned().collect())
    }

    fn delete(&self, id: &str) -> Result<()> {
        self.with_lock(|map| {
            map.remove(id);
        })
    }
}

// ---------------------------------------------------------------------------
// Platform-native stubs.
//
// These structs are intentionally unimplemented; their purpose is to give
// downstream HSM work (yougen / soland / coauth) a stable type to import
// and feature-gate against, without forcing every consumer to depend on a
// platform-native crate today.
//
// TODO(c10g-hsm): wire each to its native backend:
//   - macOS:   `security-framework` keychain item APIs.
//   - Linux:   `secret-service` D-Bus client.
//   - Windows: `windows-rs` `Windows.Security.Credentials.Vault`.
// ---------------------------------------------------------------------------

/// macOS Keychain-backed [`KeyStore`].
///
/// TODO(c10g-hsm): wire to `security-framework` keychain item APIs.
#[derive(Default)]
pub struct MacOsKeychainKeyStore {
    /// Optional service-name prefix so multiple Contrix apps can share a
    /// host without colliding on Keychain item names.
    pub service: Option<String>,
}

impl MacOsKeychainKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_service(service: impl Into<String>) -> Self {
        Self { service: Some(service.into()) }
    }
}

impl KeyStore for MacOsKeychainKeyStore {
    fn load(&self, _id: &str) -> Result<Vec<u8>> {
        // TODO(c10g-hsm): read from macOS Keychain via `security-framework`.
        unimplemented!("MacOsKeychainKeyStore::load — pending HSM workstream (c10g-hsm)")
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        // TODO(c10g-hsm): write to macOS Keychain via `security-framework`.
        unimplemented!("MacOsKeychainKeyStore::store — pending HSM workstream (c10g-hsm)")
    }

    fn list(&self) -> Result<Vec<String>> {
        // TODO(c10g-hsm): enumerate keychain items by service prefix.
        unimplemented!("MacOsKeychainKeyStore::list — pending HSM workstream (c10g-hsm)")
    }

    fn delete(&self, _id: &str) -> Result<()> {
        // TODO(c10g-hsm): delete keychain item via `security-framework`.
        unimplemented!("MacOsKeychainKeyStore::delete — pending HSM workstream (c10g-hsm)")
    }
}

/// Linux Secret Service ([`org.freedesktop.secrets`]) [`KeyStore`].
///
/// TODO(c10g-hsm): wire to the `secret-service` crate D-Bus client.
#[derive(Default)]
pub struct LinuxSecretServiceKeyStore {
    /// Collection name (`"login"` / `"session"`); `None` defaults to the
    /// session keyring.
    pub collection: Option<String>,
}

impl LinuxSecretServiceKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_collection(collection: impl Into<String>) -> Self {
        Self { collection: Some(collection.into()) }
    }
}

impl KeyStore for LinuxSecretServiceKeyStore {
    fn load(&self, _id: &str) -> Result<Vec<u8>> {
        // TODO(c10g-hsm): SecretService.lookup() over D-Bus.
        unimplemented!("LinuxSecretServiceKeyStore::load — pending HSM workstream (c10g-hsm)")
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        // TODO(c10g-hsm): SecretService.create_item() over D-Bus.
        unimplemented!("LinuxSecretServiceKeyStore::store — pending HSM workstream (c10g-hsm)")
    }

    fn list(&self) -> Result<Vec<String>> {
        // TODO(c10g-hsm): SecretService.search_items() filtered by Contrix attribute.
        unimplemented!("LinuxSecretServiceKeyStore::list — pending HSM workstream (c10g-hsm)")
    }

    fn delete(&self, _id: &str) -> Result<()> {
        // TODO(c10g-hsm): SecretService.delete_item() over D-Bus.
        unimplemented!("LinuxSecretServiceKeyStore::delete — pending HSM workstream (c10g-hsm)")
    }
}

/// Windows Credential Locker (`Windows.Security.Credentials.Vault`) [`KeyStore`].
///
/// TODO(c10g-hsm): wire to `windows-rs` Vault APIs.
#[derive(Default)]
pub struct WindowsCredentialKeyStore {
    /// Resource string used as the Credential Locker resource attribute.
    pub resource: Option<String>,
}

impl WindowsCredentialKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_resource(resource: impl Into<String>) -> Self {
        Self { resource: Some(resource.into()) }
    }
}

impl KeyStore for WindowsCredentialKeyStore {
    fn load(&self, _id: &str) -> Result<Vec<u8>> {
        // TODO(c10g-hsm): Vault.Retrieve() via windows-rs.
        unimplemented!("WindowsCredentialKeyStore::load — pending HSM workstream (c10g-hsm)")
    }

    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        // TODO(c10g-hsm): Vault.Add() via windows-rs.
        unimplemented!("WindowsCredentialKeyStore::store — pending HSM workstream (c10g-hsm)")
    }

    fn list(&self) -> Result<Vec<String>> {
        // TODO(c10g-hsm): Vault.RetrieveAll() filtered by resource.
        unimplemented!("WindowsCredentialKeyStore::list — pending HSM workstream (c10g-hsm)")
    }

    fn delete(&self, _id: &str) -> Result<()> {
        // TODO(c10g-hsm): Vault.Remove() via windows-rs.
        unimplemented!("WindowsCredentialKeyStore::delete — pending HSM workstream (c10g-hsm)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_key_store_round_trips_store_load_delete() {
        let store = InMemoryKeyStore::new();
        store.store("contrix:signer:alice:key-1", b"secret-bytes-1").unwrap();
        store.store("contrix:signer:bob:key-1", b"secret-bytes-2").unwrap();

        let loaded = store.load("contrix:signer:alice:key-1").unwrap();
        assert_eq!(loaded, b"secret-bytes-1");

        let mut listed = store.list().unwrap();
        listed.sort();
        assert_eq!(listed, vec![
            "contrix:signer:alice:key-1".to_owned(),
            "contrix:signer:bob:key-1".to_owned(),
        ]);

        store.delete("contrix:signer:alice:key-1").unwrap();
        let err = store.load("contrix:signer:alice:key-1").unwrap_err();
        assert!(format!("{err}").contains("key not found"));
    }

    #[test]
    fn in_memory_key_store_overwrites_existing_id() {
        let store = InMemoryKeyStore::new();
        store.store("k", b"first").unwrap();
        store.store("k", b"second").unwrap();
        assert_eq!(store.load("k").unwrap(), b"second");
    }

    #[test]
    fn in_memory_key_store_rejects_empty_id() {
        let store = InMemoryKeyStore::new();
        let err = store.store("", b"x").unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn in_memory_key_store_delete_idempotent_for_missing_id() {
        let store = InMemoryKeyStore::new();
        // Never errors even though the id was never stored.
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn platform_stubs_construct_with_optional_metadata() {
        let m = MacOsKeychainKeyStore::with_service("contrix.app");
        assert_eq!(m.service.as_deref(), Some("contrix.app"));

        let l = LinuxSecretServiceKeyStore::with_collection("login");
        assert_eq!(l.collection.as_deref(), Some("login"));

        let w = WindowsCredentialKeyStore::with_resource("contrix");
        assert_eq!(w.resource.as_deref(), Some("contrix"));
    }

    #[test]
    #[should_panic(expected = "pending HSM workstream")]
    fn macos_keychain_load_unimplemented() {
        let _ = MacOsKeychainKeyStore::new().load("any");
    }

    #[test]
    #[should_panic(expected = "pending HSM workstream")]
    fn linux_secret_service_store_unimplemented() {
        let _ = LinuxSecretServiceKeyStore::new().store("k", b"v");
    }

    #[test]
    #[should_panic(expected = "pending HSM workstream")]
    fn windows_credential_list_unimplemented() {
        let _ = WindowsCredentialKeyStore::new().list();
    }
}
