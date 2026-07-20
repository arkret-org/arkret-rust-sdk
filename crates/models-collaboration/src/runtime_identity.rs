//! Runtime identifier wire wrappers for agents and applets.
//!
//! Migrated from `arkret-core` (`models/runtime_identity.rs`); a shim
//! there re-exports `AgentId` to preserve the `arkret_core::` path.
//!
//! `AppletIdentifier` lives in `arkret-models-integration`.

use arkret_wire::Did;

// ── AgentId typed wrapper (DID required) ─────────────────────────────
/// Round 4 (commit 7fae9ba) — typed `agent_id`. The pre-round-4 wire
/// permitted plain strings; round 4 enforces the DID shape only.
pub type AgentId = Did;
