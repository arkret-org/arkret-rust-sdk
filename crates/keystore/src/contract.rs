//! Pluggable key storage abstraction for SDK signers and HSM integrations.
//!
//! The trait stays small — `load` / `store` / `list` / `delete` only — so it
//! can wrap any durable backend (OS keyring, encrypted file, HSM) behind a single
//! signing surface. This module holds the **pure contract** — the
//! [`KeyStore`] trait, the typed [`KeyStoreError`], and zeroizing key bytes.
//! OS-native and encrypted-file implementations live in sibling modules.
//!
//! ## Service-name namespacing
//!
//! Platform backends namespace credentials under `"arkret.<application_id>"`
//! so multiple Arkret-using apps on the same host (inkson, sodmin, soland
//! authority, …) don't trample each other's keychain items. The
//! `application_id` is supplied at construction time and SHOULD be a stable
//! reverse-DNS-like identifier for the host application
//! (e.g. `"chat.acroidea.inkson"`). [`service_name`] builds that prefix and
//! is re-used by the platform backends.
//!
//! ## Key ids
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"arkret:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

use std::fmt;
use std::ops::Deref;

use thiserror::Error;
use zeroize::Zeroizing;

/// Result alias for [`KeyStore`] operations.
pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Key material loaded from a [`KeyStore`].
///
/// The backing allocation is zeroized when dropped so callers do not
/// accidentally leave plaintext signing seeds in process memory longer
/// than their lexical lifetime.
#[derive(Clone)]
pub struct KeyBytes(Zeroizing<Vec<u8>>);

impl KeyBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

impl AsRef<[u8]> for KeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for KeyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl fmt::Debug for KeyBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyBytes([REDACTED])")
    }
}

/// Pluggable key storage interface.
///
/// Implementations MUST be concurrency-safe (`Send + Sync`) so they can be
/// shared across signer instances and threadpool workers.
///
/// # Errors
///
/// Implementations return [`KeyStoreError`] on backend failure. Missing
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

/// Strongly-typed key-store boundary error.
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

    /// True when this error is a typed key-store miss.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}

/// Validate that an id is non-empty. Backends call this before touching the
/// platform API so all impls share the same "empty id" contract.
pub fn validate_id(id: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bytes_debug_output_is_redacted() {
        let bytes = KeyBytes::new(b"must-not-appear".to_vec());
        assert_eq!(format!("{bytes:?}"), "KeyBytes([REDACTED])");
    }

    #[test]
    fn key_store_error_unsupported_renders_reason() {
        let err = KeyStoreError::unsupported("no-D-Bus session bus");
        let rendered = format!("{err}");
        assert!(rendered.contains("unsupported"));
        assert!(rendered.contains("no-D-Bus session bus"));
    }

    #[test]
    fn service_name_namespaces_per_application_id() {
        assert_eq!(service_name("inkson"), "arkret.inkson");
        assert_eq!(service_name("soland.authority"), "arkret.soland.authority");
    }
}
