//! Runtime identifier wire wrappers for agents and applets.
//!
//! The `arkret` umbrella re-exports the owner-defined `AgentId` at its root.
//!
//! `AppletIdentifier` lives in `arkret-identifiers` as a cross-domain wire scalar.

use arkret_wire::DidFullId;

// ── AgentId typed wrapper (DID required) ─────────────────────────────
/// Round 4 (commit 7fae9ba) — typed `agent_id`. The pre-round-4 wire
/// permitted plain strings; round 4 enforces the DID shape only.
pub type AgentId = DidFullId;
