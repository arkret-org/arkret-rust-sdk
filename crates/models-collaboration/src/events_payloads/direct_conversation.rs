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

impl DirectConversationBindingCurrentValue {
    /// The one semantic `binding_digest` every endorsement carries. A value
    /// whose endorsements disagree, or that has none, is not a binding.
    pub fn binding_digest(&self) -> Result<Hash> {
        let mut digests = self
            .endorsements
            .iter()
            .map(|entry| entry.value.binding_digest())
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter();
        match (digests.next(), digests.next()) {
            (Some(digest), None) => Ok(digest),
            _ => Err(WireError::Protocol(
                "a direct_conversation_binding value endorses exactly one binding digest".into(),
            )),
        }
    }

    /// Add one accepted endorsement, keeping the dot set canonically sorted.
    /// An endorsement of another binding digest is refused, never added.
    pub fn with_endorsement(
        mut self,
        entry: DirectConversationBindingEndorsementEntry,
    ) -> Result<Self> {
        if entry.value.binding_digest()? != self.binding_digest()? {
            return Err(WireError::Protocol(
                "an endorsement of another binding digest never joins the binding".into(),
            ));
        }
        if self
            .endorsements
            .iter()
            .any(|existing| existing.tag_id == entry.tag_id)
        {
            return Err(WireError::Protocol(
                "an endorsement dot is already in the binding".into(),
            ));
        }
        self.endorsements.push(entry);
        self.endorsements
            .sort_by(|left, right| left.tag_id.cmp(&right.tag_id));
        Ok(self)
    }

    /// Whether `event_id` is the Event of one accepted endorsement.
    pub fn endorsed_by(&self, event_id: &EventId) -> bool {
        self.endorsements
            .iter()
            .any(|entry| entry.tag_id.event_id() == event_id)
    }
}

include!("generated/direct_conversation_contracts.rs");
