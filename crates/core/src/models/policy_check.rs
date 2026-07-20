//! Policy-check request/response bindings migrated to
//! `arkret-models-collaboration` (`governance::policy_check`). Re-exported
//! so the `arkret_core::{PolicyCheckOutcome, compute_audit_policy_version_digest, ...}`
//! paths stay stable.

pub use arkret_models_collaboration::governance::policy_check::*;
