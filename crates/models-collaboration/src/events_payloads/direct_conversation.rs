//! Direct Conversation Event payloads.

use arkret_wire::{Error, EventId, Hash, MlsGroupId, NonEmptyString, Result, StrandId};
use serde::{Deserialize, Serialize};

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationMlsGenerationPhase {
    ProvisionalHistorySend,
    ExactPair,
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/direct_conversation_mls_generation_activate_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationMlsGenerationActivatePayload {
    pub pair_key: Hash,
    pub mls_generation: u64,
    pub phase: DirectConversationMlsGenerationPhase,
    pub mls_group_id: MlsGroupId,
    pub genesis_event_ref: EventId,
    pub selected_group_state_ref: NonEmptyString,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_active_value_digest: Option<Hash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectConversationMlsGenerationActivatePayloadWire {
    pair_key: Hash,
    mls_generation: u64,
    phase: DirectConversationMlsGenerationPhase,
    mls_group_id: MlsGroupId,
    genesis_event_ref: EventId,
    selected_group_state_ref: NonEmptyString,
    main_strand_id: StrandId,
    predecessor_active_value_digest: Option<Hash>,
}

impl DirectConversationMlsGenerationActivatePayload {
    pub fn validate(&self) -> Result<()> {
        if !self.pair_key.as_str().starts_with("sha256:") {
            return schema_violation("direct-conversation pair_key must use sha256");
        }
        match (
            self.mls_generation,
            self.phase,
            self.predecessor_active_value_digest.as_ref(),
        ) {
            (0, DirectConversationMlsGenerationPhase::ProvisionalHistorySend, None) => Ok(()),
            (1.., DirectConversationMlsGenerationPhase::ExactPair, Some(digest))
                if digest.as_str().starts_with("sha256:") =>
            {
                Ok(())
            }
            _ => schema_violation(
                "MLS generation 0 requires provisional_history_send without predecessor; later generations require exact_pair with a sha256 predecessor digest",
            ),
        }
    }
}

impl<'de> Deserialize<'de> for DirectConversationMlsGenerationActivatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DirectConversationMlsGenerationActivatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            pair_key: wire.pair_key,
            mls_generation: wire.mls_generation,
            phase: wire.phase,
            mls_group_id: wire.mls_group_id,
            genesis_event_ref: wire.genesis_event_ref,
            selected_group_state_ref: wire.selected_group_state_ref,
            main_strand_id: wire.main_strand_id,
            predecessor_active_value_digest: wire.predecessor_active_value_digest,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}
