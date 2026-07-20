//! SFrame media frame-key and recording-key derivation.
//!
//! The implementation now lives in [`arkret_crypto::sframe`]; this module
//! re-exports it so the historical `arkret::sframe::*` / `arkret_sdk::sframe::*`
//! paths stay stable. The `MlsExporterSource` impl for
//! [`crate::mls::ArkretMlsGroup`] lives in the `arkret-mls` crate.

pub use arkret_crypto::sframe::*;

/// Public result name for downstream [`MlsExporterSource`] implementations.
/// The trait is owned by `arkret-crypto`, so its error must not be confused
/// with the SDK facade's broader `arkret_sdk::Error`.
pub type MlsExporterResult<T> = arkret_crypto::Result<T>;
pub use arkret_crypto::Error as MlsExporterError;
