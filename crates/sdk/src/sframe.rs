//! SFrame media frame-key and recording-key derivation.
//!
//! The implementation now lives in [`arkret_crypto::sframe`]; this module
//! re-exports it so the historical `arkret::sframe::*` / `arkret_sdk::sframe::*`
//! paths stay stable. The `MlsExporterSource` impl for
//! [`crate::mls::ArkretMlsGroup`] lives in the `arkret-mls` crate.

pub use arkret_crypto::sframe::*;

/// Public result name for downstream [`MlsExporterSource`] implementations.
/// The trait is owned by `arkret-crypto`, so this alias keeps its owner error
/// explicit at downstream implementation boundaries.
pub type MlsExporterResult<T> = arkret_crypto::Result<T>;
pub use arkret_crypto::Error as MlsExporterError;
