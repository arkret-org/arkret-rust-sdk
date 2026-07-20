//! Arkret v1 collaboration domain models.
//!
//! Trunk crate of the model family: governance, collaboration objects,
//! event payloads, and sync/federation frames, organized as semantic
//! module directories. Phase 1A seeded the governance module with the
//! receive-policy, audit, and plaintext-classification wire shapes;
//! phase 1B-c2 lands the governance domain (realm governance, circle,
//! invite addressing, moderation, grant constraints, delivery bindings)
//! plus the first event-payload faces migrated from `arkret-core`.

pub mod account_lifecycle;
pub mod agent_operations;
pub mod applet_service;
pub mod event_query;
pub mod event_sync;
pub mod events_payloads;
pub mod federation;
pub mod governance;
pub mod governance_payloads;
pub mod http_bodies;
pub mod http_params;
mod internal_prelude;
pub mod object_lifecycle;
pub mod object_patch;
pub mod objects;
pub mod resolved_state;
pub mod runtime_identity;
pub mod seal_transparency;
pub mod session_grant_bodies;
pub mod sync_frames;

pub use governance::audit::{AccessKind, AuditPolicyAccessPayload};
pub use resolved_state::ResolvedStateEvent;

/// Canonical object reference string (typed id / DID / content digest).
pub type ObjectRef = String;
