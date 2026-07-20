//! Contact and directory `$defs` shapes migrated to `arkret-models-discovery`
//! (`directory_artifacts`), re-exported here for path stability.
//!
//! The cross-domain contact/directory operation aggregator enums
//! (ContactOperations, DirectoryOperations) and the `PaginationRequest` struct
//! that previously lived here had no runtime consumer and were removed. Schema
//! coverage is preserved by `arkret-schema`, which mirrors the spec JSON
//! artifacts directly.

pub use arkret_models_discovery::directory_artifacts::*;
