//! Pluggable key storage abstraction for SDK signers and HSM integrations.
//!
//! The trait stays small — `load` / `store` / `list` / `delete` only — so it
//! can wrap any backend (in-process map, OS keyring, HSM) behind a single
//! signing surface. Real platform implementations are gated behind feature
//! flags + `target_os` cfgs so consumers only pay for the backend they
//! actually use.
//!
//! ## Backends
//!
//! | Backend | Feature | `target_os` |
//! |---|---|---|
//! | [`InMemoryKeyStore`] | always available | any |
//! | [`MacOsKeychainKeyStore`] | `keystore-macos` | `macos` |
//! | [`LinuxSecretServiceKeyStore`] | `keystore-linux` | `linux` |
//! | [`WindowsCredentialKeyStore`] | `keystore-windows` | `windows` |
//!
//! Off-target compilation: each platform type still **compiles** on every
//! target so downstream code can reference it unconditionally; constructors
//! return [`KeyStoreError::Unsupported`] when the active target / feature
//! combination cannot reach the underlying API.
//!
//! ## Service-name namespacing
//!
//! Backends namespace credentials under `"contrix.<application_id>"` so
//! multiple Contrix-using apps on the same host (yougen, sodmin, soland
//! anchorer, …) don't trample each other's keychain items. The
//! `application_id` is supplied at construction time and SHOULD be a stable
//! reverse-DNS-like identifier for the host application
//! (e.g. `"chat.acroidea.yougen"`).
//!
//! ## Key ids
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"contrix:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use thiserror::Error;

use crate::{Error, Result};

#[cfg(all(target_os = "macos", feature = "keystore-macos"))]
mod macos;
#[cfg(all(target_os = "macos", feature = "keystore-macos"))]
pub use macos::MacOsKeychainKeyStore;

#[cfg(all(target_os = "linux", feature = "keystore-linux"))]
mod linux;
#[cfg(all(target_os = "linux", feature = "keystore-linux"))]
pub use linux::LinuxSecretServiceKeyStore;

#[cfg(all(target_os = "windows", feature = "keystore-windows"))]
mod windows;
#[cfg(all(target_os = "windows", feature = "keystore-windows"))]
pub use windows::WindowsCredentialKeyStore;

// ---------------------------------------------------------------------------
// Off-target stubs.
//
// These keep the type visible everywhere so downstream code can reference
// the platform key-store types from cross-target builds (docs, FFI, tests
// that compile on every CI runner). Constructors return
// `KeyStoreError::Unsupported`; trait methods do the same so calls into a
// stub don't panic.
// ---------------------------------------------------------------------------

#[cfg(not(all(target_os = "macos", feature = "keystore-macos")))]
mod macos_stub;
#[cfg(not(all(target_os = "macos", feature = "keystore-macos")))]
pub use macos_stub::MacOsKeychainKeyStore;

#[cfg(not(all(target_os = "linux", feature = "keystore-linux")))]
mod linux_stub;
#[cfg(not(all(target_os = "linux", feature = "keystore-linux")))]
pub use linux_stub::LinuxSecretServiceKeyStore;

#[cfg(not(all(target_os = "windows", feature = "keystore-windows")))]
mod windows_stub;
#[cfg(not(all(target_os = "windows", feature = "keystore-windows")))]
pub use windows_stub::WindowsCredentialKeyStore;

/// Pluggable key storage interface.
///
/// Implementations MUST be concurrency-safe (`Send + Sync`) so they can be
/// shared across signer instances and threadpool workers.
///
/// # Errors
///
/// Implementations return [`Error::Protocol`] on backend failure. Missing
/// keys SHOULD surface as [`Error::Protocol`] with a "key not found"
/// message; callers MAY downcast via [`KeyStoreError`] for stronger typing.
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

/// Strongly-typed key-store error. Convertible to the workspace
/// [`Error::Protocol`] for trait conformance.
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
        Self::Unsupported { reason: reason.into() }
    }

    pub fn not_found(id: impl Into<String>) -> Self {
        Self::NotFound { id: id.into() }
    }

    pub fn invalid_id(reason: impl Into<String>) -> Self {
        Self::InvalidId { reason: reason.into() }
    }

    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

impl From<KeyStoreError> for Error {
    fn from(err: KeyStoreError) -> Self {
        Error::Protocol(err.to_string())
    }
}

/// Validate that an id is non-empty. Backends call this before touching the
/// platform API so all impls share the same "empty id" contract.
pub(crate) fn validate_id(id: &str) -> std::result::Result<(), KeyStoreError> {
    if id.is_empty() {
        return Err(KeyStoreError::invalid_id("id must be non-empty"));
    }
    Ok(())
}

/// Build the per-backend service / target name. All platform backends use
/// `contrix.<application_id>` as the service-prefix so independent Contrix
/// apps on the same host don't collide.
#[cfg(any(
    test,
    all(target_os = "macos", feature = "keystore-macos"),
    all(target_os = "linux", feature = "keystore-linux"),
    all(target_os = "windows", feature = "keystore-windows"),
))]
pub(crate) fn service_name(application_id: &str) -> String {
    format!("contrix.{application_id}")
}

/// Construct the platform-default [`KeyStore`] for the given application
/// id, falling back to [`InMemoryKeyStore`] when no native backend is
/// available (target/feature mismatch, or D-Bus session not reachable on
/// Linux).
///
/// Resolution order on each target:
/// - macOS + `keystore-macos` → [`MacOsKeychainKeyStore`]
/// - Linux + `keystore-linux` → [`LinuxSecretServiceKeyStore`]
/// - Windows + `keystore-windows` → [`WindowsCredentialKeyStore`]
/// - otherwise → [`InMemoryKeyStore`]
///
/// The fallback is intentional: ephemeral / test environments and
/// platforms without a native key store still get a working trait
/// object. Callers that REQUIRE durable storage should construct the
/// platform type directly and surface the [`KeyStoreError::Unsupported`]
/// to the user.
pub fn platform_default_keystore(application_id: &str) -> Box<dyn KeyStore> {
    #[cfg(all(target_os = "macos", feature = "keystore-macos"))]
    {
        if let Ok(store) = MacOsKeychainKeyStore::new(application_id) {
            return Box::new(store);
        }
    }
    #[cfg(all(target_os = "linux", feature = "keystore-linux"))]
    {
        if let Ok(store) = LinuxSecretServiceKeyStore::new(application_id) {
            return Box::new(store);
        }
    }
    #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
    {
        if let Ok(store) = WindowsCredentialKeyStore::new(application_id) {
            return Box::new(store);
        }
    }
    let _ = application_id;
    Box::new(InMemoryKeyStore::new())
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
        validate_id(id)?;
        let bytes = self.with_lock(|map| map.get(id).cloned())?;
        bytes.ok_or_else(|| KeyStoreError::not_found(id).into())
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        self.with_lock(|map| {
            map.insert(id.to_owned(), key.to_vec());
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
        store.store("contrix:signer:alice:key-1", b"secret-bytes-1").unwrap();
        store.store("contrix:signer:bob:key-1", b"secret-bytes-2").unwrap();

        let loaded = store.load("contrix:signer:alice:key-1").unwrap();
        assert_eq!(loaded, b"secret-bytes-1");

        let mut listed = store.list().unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec!["contrix:signer:alice:key-1".to_owned(), "contrix:signer:bob:key-1".to_owned(),]
        );

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
    fn key_store_error_unsupported_renders_reason() {
        let err = KeyStoreError::unsupported("no-D-Bus session bus");
        let rendered = format!("{err}");
        assert!(rendered.contains("unsupported"));
        assert!(rendered.contains("no-D-Bus session bus"));
    }

    #[test]
    fn key_store_error_round_trips_into_workspace_error() {
        let proto: Error = KeyStoreError::not_found("missing-id").into();
        let rendered = format!("{proto}");
        assert!(rendered.contains("key not found"));
        assert!(rendered.contains("missing-id"));
    }

    #[test]
    fn service_name_namespaces_per_application_id() {
        assert_eq!(service_name("yougen"), "contrix.yougen");
        assert_eq!(service_name("soland.anchorer"), "contrix.soland.anchorer");
    }

    #[test]
    fn platform_default_keystore_returns_a_working_keystore() {
        // On targets/features without a native backend this falls back to
        // InMemoryKeyStore. On targets WITH a native backend, the native
        // backend is constructed; either way we can round-trip a key.
        let store = platform_default_keystore("contrix.test.platform_default");
        // We can't reuse a fixed id across runs because some backends
        // persist; use a per-process unique id instead.
        let id = format!(
            "contrix:test:platform-default:{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        store.store(&id, b"platform-default-secret").unwrap();
        assert_eq!(store.load(&id).unwrap(), b"platform-default-secret");
        store.delete(&id).unwrap();
    }
}
