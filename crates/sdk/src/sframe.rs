//! SFrame media frame-key and recording-key derivation.
//!
//! The implementation now lives in [`arkret_crypto::sframe`]; this module
//! re-exports it so the historical `arkret::sframe::*` / `arkret_sdk::sframe::*`
//! paths stay stable. The `MlsExporterSource` impl for
//! [`crate::mls::ArkretMlsGroup`] lives in the `arkret-mls` crate.

pub use arkret_crypto::sframe::*;
