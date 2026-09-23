//! Participant endorsement of an accepted Direct Conversation founding unit.

use std::collections::BTreeSet;

use arkret_wire::{ActorId, EventId, Hash, RealmId, Result, StrandId, WireError, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::objects::direct_conversation::{
    DirectConversationAuthorizationBasis, DirectConversationAuthorizationKind,
};

const BINDING_DIGEST_DOMAIN: &[u8] = b"ak.direct-conversation.binding-digest.v1\n";

#[derive(Serialize)]
struct BindingObject<'a> {
    pair_key: &'a Hash,
    participants_unordered: Vec<ActorId>,
    realm_id: &'a RealmId,
    main_strand_id: &'a StrandId,
    founding_unit_digest: &'a Hash,
    authorization_basis: NormalizedAuthorizationBasis,
    initial_exact_pair_group_state_ref: &'a EventId,
}

#[derive(Serialize)]
struct NormalizedAuthorizationBasis {
    kind: DirectConversationAuthorizationKind,
    event_refs: Vec<EventId>,
}

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

    /// RFC 8785 JCS bytes of the receiver-derived, closed §8.3 binding object.
    /// The signed wire's `created_at` is deliberately excluded.
    pub fn binding_object_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut participants = self
            .unordered_participant_ids
            .iter()
            .map(|actor| Ok((canonical::canonical_json_bytes(actor)?, actor.clone())))
            .collect::<Result<Vec<_>>>()?;
        participants.sort_by(|left, right| left.0.cmp(&right.0));

        let mut event_refs = self.authorization_basis.event_refs.clone();
        event_refs.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        let object = BindingObject {
            pair_key: &self.pair_key,
            participants_unordered: participants.into_iter().map(|(_, actor)| actor).collect(),
            realm_id: &self.realm_id,
            main_strand_id: &self.main_strand_id,
            founding_unit_digest: &self.founding_unit_digest,
            authorization_basis: NormalizedAuthorizationBasis {
                kind: self.authorization_basis.kind,
                event_refs,
            },
            initial_exact_pair_group_state_ref: &self.initial_exact_pair_group_state_ref,
        };
        Ok(canonical::canonical_json_bytes(&object)?)
    }

    /// Domain-separated SHA-256 over the exact §8.3 binding object, not a wire field.
    pub fn binding_digest(&self) -> Result<Hash> {
        let canonical = self.binding_object_canonical_bytes()?;
        let mut transcript = Vec::with_capacity(BINDING_DIGEST_DOMAIN.len() + canonical.len());
        transcript.extend_from_slice(BINDING_DIGEST_DOMAIN);
        transcript.extend_from_slice(&canonical);
        Ok(Hash::new(canonical::sha256_digest(transcript))?)
    }
}
