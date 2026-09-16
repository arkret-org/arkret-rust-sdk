//! Sidecar Event payloads.

use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{EventId, Result, SidecarId, WireError};
use serde::{Deserialize, Serialize};

use crate::sidecar_operations::SidecarContextRef;

/// Counterpart for `event-payload.schema.json#/$defs/sidecar_create_payload`.
///
/// The payload is empty: `sidecar_id` is derived from the Event id, and
/// `realm_id`, `controller_account_id`, `state` and the timestamps are
/// reducer-derived from the accepted envelope. The Sidecar scope activates
/// standard RFC 9420 through its own accepted `ak.mls.genesis`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarCreatePayload {}

/// Counterpart for
/// `event-payload.schema.json#/$defs/sidecar_context_attach_payload`.
///
/// Controller-signed versioned attachment of a source Realm context to an
/// existing native Sidecar. It creates no Strand and no Relation protocol
/// object. `version` 1 opens the chain and carries no predecessor; every later
/// version names the attach Event it supersedes.
// Field declaration order is byte-for-byte the properties order of
// event-payload.schema.json#/$defs/sidecar_context_attach_payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarContextAttachPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
}

impl SidecarContextAttachPayload {
    /// The schema's version/predecessor conditional: the opening version has
    /// no predecessor, and every later version must name one.
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(WireError::Protocol(
                "Sidecar context attach version starts at 1".to_owned(),
            ));
        }
        if (self.version == 1) != self.predecessor_event_ref.is_none() {
            return Err(WireError::Protocol(
                "Sidecar context attach carries a predecessor for exactly every version after the first"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/agent_sidecar_exchange_control_payload`.
///
/// Outer payload of `ak.agent.sidecar.exchange.control`. `sidecar_id` and
/// `source_context_ref` route the Event inside a native Sidecar scope; the
/// plaintext inside `encrypted_payload` is
/// [`crate::agent_sidecar::AgentSidecarExchangeControl`], which only the
/// Sidecar controller can open.
// Field declaration order is byte-for-byte the properties order of
// event-payload.schema.json#/$defs/agent_sidecar_exchange_control_payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSidecarExchangeControlPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub encrypted_payload: EncryptedEnvelope,
}
