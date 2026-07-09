//! Pluggable key storage abstraction for SDK signers and HSM integrations.
//!
//! The trait stays small — `load` / `store` / `list` / `delete` only — so it
//! can wrap any backend (in-process map, OS keyring, HSM) behind a single
//! signing surface. This module holds only the **pure contract** — the
//! [`KeyStore`] trait, the typed [`KeyStoreError`], and the zeroizing
//! [`InMemoryKeyStore`]. OS-native backends (macOS Keychain, Linux Secret
//! Service, Windows Credential Manager) and the
//! `platform_default_keystore_with_kind` constructor live in the separate
//! `arkret-keystore` crate so this crate stays free of platform IO and
//! native OS dependencies.
//!
//! ## Service-name namespacing
//!
//! Platform backends namespace credentials under `"arkret.<application_id>"`
//! so multiple Arkret-using apps on the same host (inkson, sodmin, soland
//! notary, …) don't trample each other's keychain items. The
//! `application_id` is supplied at construction time and SHOULD be a stable
//! reverse-DNS-like identifier for the host application
//! (e.g. `"chat.acroidea.inkson"`). [`service_name`] builds that prefix and
//! is re-used by the `arkret-keystore` backends.
//!
//! ## Key ids
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"arkret:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Key material loaded from a [`KeyStore`].
///
/// The backing allocation is zeroized when dropped so callers do not
/// accidentally leave plaintext signing seeds in process memory longer
/// than their lexical lifetime.
pub type KeyBytes = Zeroizing<Vec<u8>>;

/// Pluggable key storage interface.
///
/// Implementations MUST be concurrency-safe (`Send + Sync`) so they can be
/// shared across signer instances and threadpool workers.
///
/// # Errors
///
/// Implementations return [`Error::KeyStore`] on backend failure. Missing
/// keys SHOULD surface as [`KeyStoreError::NotFound`] so callers can
/// distinguish cache misses without parsing display text.
pub trait KeyStore: Send + Sync {
    /// Load the raw key bytes for `id`.
    ///
    /// Returns the bytes verbatim; the caller is responsible for any
    /// envelope decoding (PKCS#8, raw seed, etc.).
    fn load(&self, id: &str) -> Result<KeyBytes>;

    /// Persist `key` under `id`. Existing entries with the same id MUST be
    /// overwritten.
    fn store(&self, id: &str, key: &[u8]) -> Result<()>;

    /// List all key ids known to this store, sorted ascending.
    fn list(&self) -> Result<Vec<String>>;

    /// Delete the entry under `id`. Idempotent: deleting a missing id is
    /// not an error.
    fn delete(&self, id: &str) -> Result<()>;
}

/// Strongly-typed key-store error. Convertible to the workspace
/// [`Error::KeyStore`] for trait conformance.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// The active target / feature combination does not provide this
    /// backend (e.g. constructing `MacOsKeychainKeyStore` on Linux, or
    /// without the `keystore-macos` feature enabled).
    #[error("key-store backend unsupported on this target: {reason}")]
    Unsupported { reason: String },

    /// The requested key id does not exist in the backend.
    #[error("key not found: {id}")]
    NotFound { id: String },

    /// Caller supplied an empty / malformed id.
    #[error("invalid key id: {reason}")]
    InvalidId { reason: String },

    /// Backend-specific failure (D-Bus, Keychain Services, Win32 last
    /// error, ...). The message is intentionally opaque so backend
    /// implementations don't leak structured details across platforms.
    #[error("key-store backend failure: {0}")]
    Backend(String),
}

impl KeyStoreError {
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }

    pub fn not_found(id: impl Into<String>) -> Self {
        Self::NotFound { id: id.into() }
    }

    pub fn invalid_id(reason: impl Into<String>) -> Self {
        Self::InvalidId {
            reason: reason.into(),
        }
    }

    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

impl From<KeyStoreError> for Error {
    fn from(err: KeyStoreError) -> Self {
        Error::KeyStore(err)
    }
}

/// Validate that an id is non-empty. Backends call this before touching the
/// platform API so all impls share the same "empty id" contract.
pub fn validate_id(id: &str) -> std::result::Result<(), KeyStoreError> {
    if id.is_empty() {
        return Err(KeyStoreError::invalid_id("id must be non-empty"));
    }
    Ok(())
}

/// Build the per-backend service / target name. All platform backends use
/// `arkret.<application_id>` as the service-prefix so independent Arkret
/// apps on the same host don't collide.
pub fn service_name(application_id: &str) -> String {
    format!("arkret.{application_id}")
}

/// In-process [`KeyStore`] backed by a `BTreeMap`. Suitable for tests and
/// for short-lived ephemeral signers. Not encrypted at rest.
#[derive(Default)]
pub struct InMemoryKeyStore {
    inner: Mutex<BTreeMap<String, KeyBytes>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut BTreeMap<String, KeyBytes>) -> T,
    {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(f(&mut guard))
    }
}

impl KeyStore for InMemoryKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        validate_id(id)?;
        let bytes = self.with_lock(|map| map.get(id).cloned())?;
        bytes.ok_or_else(|| KeyStoreError::not_found(id).into())
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        self.with_lock(|map| {
            map.insert(id.to_owned(), KeyBytes::new(key.to_vec()));
        })
    }

    fn list(&self) -> Result<Vec<String>> {
        self.with_lock(|map| map.keys().cloned().collect())
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.with_lock(|map| {
            map.remove(id);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_key_store_round_trips_store_load_delete() {
        let store = InMemoryKeyStore::new();
        store
            .store("arkret:signer:alice:key-1", b"secret-bytes-1")
            .unwrap();
        store
            .store("arkret:signer:bob:key-1", b"secret-bytes-2")
            .unwrap();

        let loaded = store.load("arkret:signer:alice:key-1").unwrap();
        assert_eq!(loaded.as_slice(), b"secret-bytes-1");

        let mut listed = store.list().unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                "arkret:signer:alice:key-1".to_owned(),
                "arkret:signer:bob:key-1".to_owned(),
            ]
        );

        store.delete("arkret:signer:alice:key-1").unwrap();
        let err = store.load("arkret:signer:alice:key-1").unwrap_err();
        assert!(err.is_key_store_not_found());
    }

    #[test]
    fn in_memory_key_store_overwrites_existing_id() {
        let store = InMemoryKeyStore::new();
        store.store("k", b"first").unwrap();
        store.store("k", b"second").unwrap();
        assert_eq!(store.load("k").unwrap().as_slice(), b"second");
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
    fn key_store_error_unsupported_renders_reason() {
        let err = KeyStoreError::unsupported("no-D-Bus session bus");
        let rendered = format!("{err}");
        assert!(rendered.contains("unsupported"));
        assert!(rendered.contains("no-D-Bus session bus"));
    }

    #[test]
    fn key_store_error_round_trips_into_workspace_error() {
        let proto: Error = KeyStoreError::not_found("missing-id").into();
        assert!(proto.is_key_store_not_found());
        assert!(matches!(
            proto.as_key_store_error(),
            Some(KeyStoreError::NotFound { id }) if id == "missing-id"
        ));
    }

    #[test]
    fn service_name_namespaces_per_application_id() {
        assert_eq!(service_name("inkson"), "arkret.inkson");
        assert_eq!(service_name("soland.notary"), "arkret.soland.notary");
    }
}
