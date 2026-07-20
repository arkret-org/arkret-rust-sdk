//! Shim: key management and recovery schema artifact counterparts —
//! including the `KeyPackageOperations` aggregate — migrated to
//! `arkret-models-crypto` (`artifacts_keys`). Re-exported here to preserve
//! the `arkret_core::` path.

pub use arkret_models_crypto::artifacts_keys::*;
