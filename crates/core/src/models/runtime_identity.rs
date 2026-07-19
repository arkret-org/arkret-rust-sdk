//! Runtime identifier wire wrappers for agents and applets.
//!
//! `AppletIdentifier` migrated to `arkret-models-integration`
//! (`applet_models`, re-exported via the sibling `applet` module).

use super::*;

// ── AgentId typed wrapper (DID required) ─────────────────────────────
/// Round 4 (commit 7fae9ba) — typed `agent_id`. The pre-round-4 wire
/// permitted plain strings; round 4 enforces the DID shape only.
pub type AgentId = Did;
