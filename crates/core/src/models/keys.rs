//! Key DTO shim.
//!
//! The key claim and distribution DTOs migrated to
//! `arkret-models-crypto`; the device-message transport DTOs migrated to
//! `arkret-models-collaboration` (`sync_frames::account_sync`, surfaced
//! through the artifact re-exports).

pub use arkret_models_crypto::keys::*;
