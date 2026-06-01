//! Runtime identifier wire wrappers for agents and applets.

use super::*;

// ── AgentId / AppletId typed wrappers (DID required) ─────────────────

/// Round 4 (commit 7fae9ba) — typed `agent_id`. The pre-round-4 wire

/// permitted plain strings; round 4 enforces the DID shape only.

pub type AgentId = Did;

/// Round 4 — typed `applet_id`. Accepts either a DID

/// (`did:webvh:applet.example`) or a strictly-validated

/// `cx:applet:<uuidv7>`.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]

pub enum AppletIdentifier {
    Did(Did),

    Cx(AppletId),
}

impl AppletIdentifier {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Did(d) => d.as_str(),

            Self::Cx(a) => a.as_str(),
        }
    }
}
