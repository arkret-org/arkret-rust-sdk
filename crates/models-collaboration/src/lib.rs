//! Arkret v1 collaboration domain models.
//!
//! Trunk crate of the model family: governance, collaboration objects,
//! event payloads, and sync/federation frames, organized as semantic
//! module directories. Phase 1A seeds the governance module with the
//! receive-policy, audit, and plaintext-classification wire shapes; the
//! remaining domains migrate from `arkret-core` in phase 1B.

pub mod governance;

pub use governance::audit::{AccessKind, AuditPolicyAccessPayload};
