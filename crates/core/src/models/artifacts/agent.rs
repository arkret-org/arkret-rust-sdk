//! Agent lifecycle schema artifact counterparts.
//!
//! The public-key / grant-snapshot / device-metadata / key-authorization /
//! seal-signature leaf shapes migrated to `arkret-models-collaboration`
//! (`governance::agent_artifacts`); the `AgentOperations` aggregation enum and
//! `KeyState` migrated alongside the agent lifecycle models
//! (`agent_operations`). Re-exported here for `arkret_core::` path stability.

pub use arkret_models_collaboration::governance::agent_artifacts::*;
