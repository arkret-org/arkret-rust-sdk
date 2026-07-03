//! Platform-native [`KeyStore`] backends for the Cokret v1 SDK.
//!
//! The pure storage contract — the [`KeyStore`] trait, [`KeyStoreError`] and
//! the dependency-free [`InMemoryKeyStore`] — lives in `cokret-core`. This
//! crate adds the OS-native backends that carry platform IO and native OS
//! dependencies, kept out of `cokret-core` so the core wire/model crate
//! stays light and free of platform crates.
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
//! ## Persistence and concurrency semantics (per backend)
//!
//! The backends are NOT semantically identical; callers storing durable
//! material (device signing keys) must account for these differences:
//!
//! | Backend | Persistence | At-rest protection | Cross-process concurrency |
//! |---|---|---|---|
//! | [`InMemoryKeyStore`] | none — lost on process exit | none (process memory) | none (per-process map) |
//! | [`MacOsKeychainKeyStore`] | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | Keychain serializes item ops; no SDK-level CAS |
//! | [`LinuxSecretServiceKeyStore`] | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | D-Bus daemon serializes ops; no SDK-level CAS |
//! | [`WindowsCredentialKeyStore`] | survives logout and reboot (`CRED_PERSIST_LOCAL_MACHINE`) | DPAPI, scoped to the user profile | Win32 credential API serializes ops; no SDK-level CAS |
//!
//! Concurrency: every backend is last-writer-wins for `store` on the same
//! id — there is no compare-and-swap and no cross-process lock. If two
//! processes race a `store` for one id, one write silently wins; serialize
//! key rotation at the application layer.
//!
//! ## Service-name namespacing
//!
//! Backends namespace credentials under `"cokret.<application_id>"` so
//! multiple Cokret-using apps on the same host (yougen, sodmin, soland
//! notary, …) don't trample each other's keychain items. The
//! `application_id` is supplied at construction time and SHOULD be a stable
//! reverse-DNS-like identifier for the host application
//! (e.g. `"chat.acroidea.yougen"`).
//!
//! ## Key ids
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"cokret:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

// The pure storage contract is re-exported from `cokret-core` so consumers
// of `cokret-keystore` get the trait + in-memory backend + error type from a
// single import surface alongside the platform backends below.
pub use cokret_core::keystore::{InMemoryKeyStore, KeyBytes, KeyStore, KeyStoreError};

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
/// object. Callers that REQUIRE durable storage should either use
/// [`platform_default_keystore_with_kind`] and reject
/// [`BackendKind::InMemory`], or construct the platform type directly and
/// surface the [`KeyStoreError::Unsupported`] to the user.
///
/// SDK-SEC-04: when this convenience function falls back to the in-memory
/// backend it emits a `tracing::warn!` so a silent downgrade to non-durable,
/// OS-unprotected key storage is at least observable in logs. A log line is
/// not a contract, though — which is why this entry point is deprecated in
/// favour of the variant whose downgrade is visible in the type system.
#[deprecated(
    note = "use platform_default_keystore_with_kind and reject BackendKind::InMemory when \
            persistence is required — this variant silently downgrades to a non-durable, \
            OS-unprotected in-memory store"
)]
pub fn platform_default_keystore(application_id: &str) -> Box<dyn KeyStore> {
    let (store, kind) = platform_default_keystore_with_kind(application_id);
    if kind == BackendKind::InMemory {
        tracing::warn!(
            target: "cokret_keystore",
            application_id,
            "platform_default_keystore fell back to the in-memory KeyStore: keys are \
             NOT persisted and have NO OS-level access protection. Use \
             platform_default_keystore_with_kind to detect and reject this downgrade, \
             or construct the platform backend directly."
        );
    }
    store
}

/// Identifies which concrete [`KeyStore`] backend
/// [`platform_default_keystore_with_kind`] resolved to, so callers can detect
/// (and refuse) a downgrade to the non-durable in-memory backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Keychain ([`MacOsKeychainKeyStore`]).
    MacOsKeychain,
    /// Linux Secret Service / D-Bus ([`LinuxSecretServiceKeyStore`]).
    LinuxSecretService,
    /// Windows Credential Manager ([`WindowsCredentialKeyStore`]).
    WindowsCredential,
    /// Non-durable, OS-unprotected in-memory fallback ([`InMemoryKeyStore`]).
    InMemory,
}

/// Like [`platform_default_keystore`] but also returns the [`BackendKind`] that
/// was resolved, so durable-storage-requiring callers can reject a fallback to
/// [`BackendKind::InMemory`] instead of silently downgrading (SDK-SEC-04).
pub fn platform_default_keystore_with_kind(
    application_id: &str,
) -> (Box<dyn KeyStore>, BackendKind) {
    #[cfg(all(target_os = "macos", feature = "keystore-macos"))]
    {
        if let Ok(store) = MacOsKeychainKeyStore::new(application_id) {
            return (Box::new(store), BackendKind::MacOsKeychain);
        }
    }
    #[cfg(all(target_os = "linux", feature = "keystore-linux"))]
    {
        if let Ok(store) = LinuxSecretServiceKeyStore::new(application_id) {
            return (Box::new(store), BackendKind::LinuxSecretService);
        }
    }
    #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
    {
        if let Ok(store) = WindowsCredentialKeyStore::new(application_id) {
            return (Box::new(store), BackendKind::WindowsCredential);
        }
    }
    let _ = application_id;
    (Box::new(InMemoryKeyStore::new()), BackendKind::InMemory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_default_keystore_returns_a_working_keystore() {
        // On targets/features without a native backend this falls back to
        // InMemoryKeyStore. On targets WITH a native backend, the native
        // backend is constructed; either way we can round-trip a key. The
        // resolved kind is surfaced so callers can reject the downgrade.
        let (store, kind) = platform_default_keystore_with_kind("cokret.test.platform_default");
        if cfg!(all(target_os = "windows", feature = "keystore-windows")) {
            assert_eq!(kind, BackendKind::WindowsCredential);
        }
        // We can't reuse a fixed id across runs because some backends
        // persist; use a per-process unique id instead.
        let id = format!(
            "cokret:test:platform-default:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        store.store(&id, b"platform-default-secret").unwrap();
        assert_eq!(
            store.load(&id).unwrap().as_slice(),
            b"platform-default-secret"
        );
        store.delete(&id).unwrap();
    }
}
