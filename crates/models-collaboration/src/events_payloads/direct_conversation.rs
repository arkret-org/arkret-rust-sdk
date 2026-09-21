//! Participant endorsement of an accepted Direct Conversation founding unit.

use std::collections::BTreeSet;

use arkret_wire::{ActorId, EventId, Hash, RealmId, Result, StrandId, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::objects::direct_conversation::DirectConversationAuthorizationBasis;

/// `event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
/// `binding_digest` is receiver-derived and deliberately absent from the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBoundPayload {
    pub pair_key: Hash,
    pub unordered_participant_ids: Vec<ActorId>,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_basis: DirectConversationAuthorizationBasis,
    pub initial_exact_pair_group_state_ref: EventId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

impl DirectConversationBoundPayload {
    pub fn validate_shape(&self) -> Result<()> {
        if self.unordered_participant_ids.len() != 2
            || self
                .unordered_participant_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != 2
        {
            return Err(WireError::Protocol(
                "Direct Conversation binding requires exactly two distinct participants".into(),
            ));
        }
        self.authorization_basis.validate_shape()
    }
}
