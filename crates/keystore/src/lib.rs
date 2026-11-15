//! [`KeyStore`] contract and durable backends for the Arkret v1 SDK.
//!
//! The pure storage contract — [`KeyStore`], [`KeyStoreError`], and zeroizing
//! key bytes — lives in [`contract`]. Sibling modules provide durable
//! encrypted-file and OS-native backends.
//!
//! ## Backends
//!
//! | Backend | Feature | `target_os` |
//! |---|---|---|
//! | [`EncryptedFileKeyStore`] | `keystore-encrypted-file` | native targets |
//! | [`MacOsKeychainKeyStore`] | `keystore-macos` | `macos` |
//! | [`LinuxSecretServiceKeyStore`] | `keystore-linux` | `linux` |
//! | [`WindowsProtectedKeyStore`] | `keystore-windows` | `windows` |
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
//! | [`EncryptedFileKeyStore`] | survives reboot with caller-custodied master key | XChaCha20-Poly1305 authenticated encryption | stable lock file + atomic same-directory replacement |
//! | [`MacOsKeychainKeyStore`] | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | per-user stable OS lock serializes Keychain mutations |
//! | [`LinuxSecretServiceKeyStore`] | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | namespaced D-Bus lease serializes SDK mutations |
//! | [`WindowsProtectedKeyStore`] | survives logout and reboot (current-user DPAPI) | XChaCha20-Poly1305 vault; 32-byte master key protected by user-profile DPAPI | stable lock files + atomic same-directory replacement |
//!
//! `store` remains last-writer-wins. `create_if_absent` returns the committed
//! first value without replacing existing bytes, including invalid application
//! payloads. `compare_exchange` compares the complete committed bytes and replaces
//! only a matching value; absence and a present empty value are distinct. Successful
//! returns follow durable commit, and a mismatch leaves storage unchanged.
//! File and Windows stores serialize every mutation with their stable vault lock.
//! macOS uses a private per-user stable OS file lock shared by all SDK writers in
//! one Keychain service; the system account home is resolved independently of HOME and
//! TMPDIR, outside temporary-file cleanup. Linux holds a namespaced D-Bus lease on the actual
//! Secret Service connection. Process exit releases the OS lock or lease. Direct external writers
//! must not mutate the macOS or Linux namespace concurrently; ambiguous Secret
//! Service items fail closed. Custom import-only backends default to typed
//! `Unsupported` for first creation and compare exchange, without emulating them
//! using a separate load and store.

//! ## Service-name namespacing
//!
//! Backends namespace credentials under `"arkret.<application_id>"` so
//! multiple Arkret-using apps on the same host (inkson, codmin, coland
//! authority, …) don't trample each other's keychain items. The
//! `application_id` is supplied at construction time and SHOULD be a stable
//! reverse-DNS-like identifier for the host application
//! (e.g. `"chat.acroidea.inkson"`).
//!
//! ## Key ids
//!
//! Keys are addressed by an opaque `id: &str`; the SDK does not interpret
//! the id beyond passing it through to the backend. Conventional ids look
//! like `"arkret:signer:<did>:<kid>"` so independent backends can share a
//! namespace without collisions.

pub mod contract;

pub use contract::{KeyBytes, KeyStore, KeyStoreError, service_name, validate_id};

#[cfg(feature = "keystore-encrypted-file")]
mod encrypted_file;
#[cfg(feature = "keystore-encrypted-file")]
pub use encrypted_file::EncryptedFileKeyStore;

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
pub use windows::WindowsProtectedKeyStore;

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
pub use windows_stub::WindowsProtectedKeyStore;

/// Resolve a durable platform-native key store or fail closed when the target,
/// feature set, or host service cannot provide one.
pub fn durable_platform_keystore(application_id: &str) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    #[cfg(all(target_os = "macos", feature = "keystore-macos"))]
    {
        if let Ok(store) = MacOsKeychainKeyStore::new(application_id) {
            return Ok(Box::new(store));
        }
    }
    #[cfg(all(target_os = "linux", feature = "keystore-linux"))]
    {
        if let Ok(store) = LinuxSecretServiceKeyStore::new(application_id) {
            return Ok(Box::new(store));
        }
    }
    #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
    {
        if let Ok(store) = WindowsProtectedKeyStore::new(application_id) {
            return Ok(Box::new(store));
        }
    }
    let _ = application_id;
    Err(KeyStoreError::unsupported(
        "no durable platform key-store backend is available",
    ))
}
