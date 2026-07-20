//! Blob schema artifact counterparts.
//!
//! The `Blob` object, upload receipt, encrypted-attachment key
//! descriptions, and the [`BlobOperations`] aggregate all live in
//! `arkret-models-collaboration` (`objects::blob`) / `arkret-models-crypto`;
//! re-exported here for path stability.

pub use arkret_models_collaboration::objects::blob::*;
