//! Key management and recovery schema artifact counterparts.
//!
//! The pure wire shapes migrated to `arkret-models-crypto` (re-exported
//! below); [`KeyPackageOperations`] stays here because it wraps the
//! keypackage HTTP operation bodies owned by `crate::http`.

pub use arkret_models_crypto::artifacts_keys::*;

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyPackageOperations {
    KeyPackagesUploadRequestBody(crate::KeyPackagesUploadRequestBody),
    KeyPackagesUploadOutcome(crate::KeyPackagesUploadOutcome),
    KeyPackagesClaimRequestBody(crate::KeyPackagesClaimRequestBody),
    KeyPackagesClaimOutcome(crate::KeyPackagesClaimOutcome),
    KeyPackagesConsumeRequestBody(crate::KeyPackagesConsumeRequestBody),
    KeyPackagesConsumeOutcome(crate::KeyPackagesConsumeOutcome),
    KeyPackagesRevokeRequestBody(crate::KeyPackagesRevokeRequestBody),
    KeyPackagesRevokeOutcome(crate::KeyPackagesRevokeOutcome),
}
