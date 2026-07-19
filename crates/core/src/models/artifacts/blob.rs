//! Blob schema artifact counterparts retained by `arkret-core`.
//!
//! The `Blob` object, upload receipt, and encrypted-attachment key
//! descriptions migrated to `arkret-models-collaboration` /
//! `arkret-models-crypto` (re-exported below). [`BlobOperations`] stays
//! because it aggregates the core HTTP request body DTOs.

pub use arkret_models_collaboration::objects::blob::*;

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlobOperations {
    BlobUploadRequestBody(crate::BlobUploadRequestBody),
    BlobUploadOutcome(BlobUploadOutcome),
}
