use std::collections::BTreeMap;

use arkret_wire::serde_helpers::{deserialize_canonical_timestamp, serialize_canonical_timestamp};
use arkret_wire::{
    Did, Error, EventId, Hash, InviteId, RealmId, Result, StrandId, XExtensionMap, canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ObjectRef;
use crate::governance::delivery_binding::{DeliveryStatus, MemberDeliveryBinding};
use crate::governance::invite_addressing::InviteDeliveryTarget;

/// Evaluate a third-party invite claim against the only canonical admission
/// time available before acceptance: the signed claim Event's `created_at`.
///
/// Receiver-local wall clocks are deliberately absent. A claim at the exact
/// expiry boundary is expired (`invite.expires_at <= claim.created_at`), and a
/// rejected claim must not be used to mutate the invite cell.
pub fn invite_claim_within_canonical_expiry(
    claim_created_at: chrono::DateTime<chrono::Utc>,
    invite_expires_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    claim_created_at < invite_expires_at
}

/// Canonical membership state for `ak.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_state`).
///
/// Distinct from `MembershipState` (the `arkret` umbrella roster projection enum, which
/// only models the live `join`/`invite`/`knock` states): the FSM transition
/// payload additionally carries the terminal `leave`/`ban` states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipPayloadState {
    Join,
    Invite,
    Knock,
    Leave,
    Ban,
}

/// Strong type for `ak.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_payload`).
///
/// `additionalProperties:false`: the removed `handle` / `from` keys that older
/// inkson call sites tried to emit are intentionally NOT representable here —
/// `handle` has no spec-legal home in this payload (the member identity is
/// carried by `actor_id`; handle evidence lives in signed `HandleClaim`
/// objects on the roster, not the durable membership event), and the FSM
/// `from` precondition is expressed via the operation `preconditions`/effect
/// `transition`, not the payload body.
///
/// Conditional required fields (schema `allOf`): when `membership == join`,
/// `realm_id` + `actor_id` + `delivery_status` are required; and additionally
/// when `delivery_status == routable`, `delivery_binding` is required. These
/// are enforced by [`MembershipPayload::to_value`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    pub membership: MembershipPayloadState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<DeliveryStatus>,
    /// `member_delivery_binding` carried opaquely as a `Value`.
    ///
    /// NOTE: we intentionally do NOT type this as the SDK
    /// [`MemberDeliveryBinding`] struct: that struct models the `*_ref`
    /// fields (e.g. `service_acceptance_ref`) as the rich `EventRef`
    /// `{id, role, …}` object, whereas the spec
    /// `member_delivery_binding.service_acceptance_ref` is a bare
    /// `event_ref` string (`^ak:event:…$`). Routing a spec-correct binding
    /// through that struct fails to deserialize. The binding wire shape is
    /// validated by soland's `validate_payload` against the canonical schema;
    /// see the "real wire divergence" note in the migration spec. Producers
    /// build the binding `Value` directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding: Option<MemberDeliveryBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_service_ids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `oneOf(event_ref | invite_id)` — both are opaque strings on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_ref: Option<MembershipInviteRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MembershipInviteRef {
    Event(EventId),
    Invite(InviteId),
}

impl MembershipPayload {
    /// Build a non-`join` transition payload (`invite`/`knock`/`leave`/`ban`).
    pub fn transition(
        membership: MembershipPayloadState,
        actor_id: Did,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership,
            strand_id: None,
            realm_id: None,
            actor_id: Some(actor_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    /// Build a `join` transition payload with the schema-required
    /// `realm_id` + `actor_id` + `delivery_status` fields.
    pub fn join(
        realm_id: RealmId,
        actor_id: Did,
        delivery_status: DeliveryStatus,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(realm_id),
            actor_id: Some(actor_id),
            delivery_status: Some(delivery_status),
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    pub fn with_delivery_binding(mut self, binding: MemberDeliveryBinding) -> Self {
        self.delivery_binding = Some(binding);
        self
    }

    pub fn with_invite_ref(mut self, invite_ref: MembershipInviteRef) -> Self {
        self.invite_ref = Some(invite_ref);
        self
    }

    /// Validate the schema-level conditional required fields, then serialize.
    pub fn to_value(&self) -> Result<Value> {
        if self.membership == MembershipPayloadState::Join {
            if self.realm_id.is_none() || self.actor_id.is_none() || self.delivery_status.is_none()
            {
                return Err(Error::Protocol(
                    "membership_payload{join} requires realm_id, actor_id, delivery_status"
                        .to_owned(),
                ));
            }
            if self.delivery_status == Some(DeliveryStatus::Routable)
                && self.delivery_binding.is_none()
            {
                return Err(Error::Protocol(
                    "membership_payload{join,routable} requires delivery_binding".to_owned(),
                ));
            }
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("membership payload serialize: {err}")))
    }
}

/// Directed-create form of `invite_payload`
/// (`event-payload.schema.json#/$defs/invite_payload`, anyOf branch that
/// requires `invitee + invite_delivery_target + introduction_evidence_digest
/// + expires_at`). Carried by `ak.invite.create`.
///
/// The schema allows `x_*` extension properties (patternProperties
/// `^x_[a-z][a-z0-9_]{0,63}$`) but is otherwise `additionalProperties:false`;
/// the typed `x_*` extensions (e.g. `x_role`) are carried in [`Self::extensions`]
/// and re-prefixed on serialize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteCreatePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    pub invitee: Did,
    pub invite_delivery_target: InviteDeliveryTarget,
    pub introduction_evidence_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `x_*` extension properties.
    #[serde(flatten, default)]
    pub extensions: XExtensionMap,
}

impl InviteCreatePayload {
    pub fn new(
        invite_id: InviteId,
        invitee: Did,
        invite_delivery_target: InviteDeliveryTarget,
        introduction_evidence_digest: Hash,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            invite_id: Some(invite_id),
            invitee,
            invite_delivery_target,
            introduction_evidence_digest,
            expires_at,
            reason: None,
            extensions: XExtensionMap::default(),
        }
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Result<Self> {
        let key = key.into();
        let wire_key = if key.starts_with("x_") {
            key
        } else {
            format!("x_{key}")
        };
        self.extensions
            .insert(wire_key, value)
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        Ok(self)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.invite_delivery_target.validate()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite create payload serialize: {err}")))
    }
}

/// Enforce the `invite_payload` closed-key set (typed fields + `x_*`
/// extensions) before deserializing an inbound payload. Callers that also
/// require schema-catalog validation run the `arkret-schema` payload gate at
/// their ingress boundary before decoding this model.
pub fn validate_invite_create_wire_keys(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(Error::Protocol(
            "invite create payload must be an object".to_owned(),
        ));
    };
    for key in object.keys() {
        if matches!(
            key.as_str(),
            "invite_id"
                | "invitee"
                | "invite_delivery_target"
                | "introduction_evidence_digest"
                | "expires_at"
                | "reason"
        ) || valid_invite_create_extension_key(key)
        {
            continue;
        }
        return Err(Error::Protocol(format!(
            "invite create payload unknown field `{key}`"
        )));
    }
    Ok(())
}

fn valid_invite_create_extension_key(key: &str) -> bool {
    let Some(suffix) = key.strip_prefix("x_") else {
        return false;
    };
    if suffix.is_empty() || suffix.len() > 64 {
        return false;
    }
    let mut chars = suffix.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

/// Reference-by-id form of `invite_payload` (anyOf branch requiring
/// `invite_id`). Carried by `ak.invite.accept` / `ak.invite.cancel` /
/// `ak.invite.revoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRefPayload {
    pub invite_id: InviteId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InviteRefPayload {
    pub fn new(invite_id: InviteId) -> Self {
        Self {
            invite_id,
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite ref payload serialize: {err}")))
    }
}

pub const INVITE_CLAIM_AUDIENCE: &str = "arkret.invite.claim";
pub const INVITE_BINDING_PROOF_TRANSCRIPT_DOMAIN: &str = "ak.invite.claim.binding_proof.v1\n";
pub const INVITE_SUBJECT_PROOF_ALG: &str = "EdDSA";
pub const INVITE_SUBJECT_PROOF_TRANSCRIPT_DOMAIN: &str = "ak.invite.claim.subject_proof.v1\n";

/// Verification-service proof carried by `ak.invite.claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteClaimBindingProof {
    pub verification_service_id: Did,
    pub verification_method: String,
    pub subject_id: Did,
    pub realm_id: RealmId,
    pub audience: String,
    pub claim_nonce: String,
    pub expires_at: String,
    pub signature: String,
}

impl InviteClaimBindingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verification_service_id: Did,
        subject_id: Did,
        realm_id: RealmId,
        claim_nonce: impl Into<String>,
        expires_at: impl Into<String>,
        verification_method: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            verification_service_id,
            subject_id,
            realm_id,
            audience: INVITE_CLAIM_AUDIENCE.to_owned(),
            claim_nonce: claim_nonce.into(),
            expires_at: expires_at.into(),
            verification_method: verification_method.into(),
            signature: signature.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.audience != INVITE_CLAIM_AUDIENCE {
            return Err(Error::Protocol(
                "invite binding proof audience must be arkret.invite.claim".to_owned(),
            ));
        }
        if self.claim_nonce.len() < 16 || self.claim_nonce.len() > 128 {
            return Err(Error::Protocol(
                "invite binding proof claim_nonce length must be 16..=128".to_owned(),
            ));
        }
        canonical::validate_timestamp_canonical(&self.expires_at)?;
        if self.verification_method.trim().is_empty() {
            return Err(Error::Protocol(
                "invite binding proof verification_method must not be empty".to_owned(),
            ));
        }
        if self.signature.trim().is_empty() {
            return Err(Error::Protocol(
                "invite binding proof signature must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn unsigned(&self) -> InviteClaimUnsignedBindingProof {
        InviteClaimUnsignedBindingProof {
            verification_service_id: self.verification_service_id.clone(),
            subject_id: self.subject_id.clone(),
            realm_id: self.realm_id.clone(),
            audience: self.audience.clone(),
            claim_nonce: self.claim_nonce.clone(),
            expires_at: self.expires_at.clone(),
            verification_method: self.verification_method.clone(),
        }
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(canonical::canonical_sha256(self)?)?)
    }
}

/// `binding_proof` with only the `signature` member removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteClaimUnsignedBindingProof {
    pub verification_service_id: Did,
    pub subject_id: Did,
    pub realm_id: RealmId,
    pub audience: String,
    pub claim_nonce: String,
    pub expires_at: String,
    pub verification_method: String,
}

/// Canonical `ak.invite.claim.binding_proof.v1` transcript body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteClaimBindingProofBody {
    pub audience: String,
    pub binding_proof: InviteClaimUnsignedBindingProof,
    pub claim_nonce: String,
    pub invite_digest: Hash,
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub subject_id: Did,
    pub token_commitment: Hash,
    pub verification_service_id: Did,
}

impl InviteClaimBindingProofBody {
    pub fn new(
        binding_proof: &InviteClaimBindingProof,
        invite_id: InviteId,
        token_commitment: Hash,
        invite_digest: Hash,
    ) -> Result<Self> {
        binding_proof.validate()?;
        if !token_commitment.as_str().starts_with("sha256:") {
            return Err(Error::Protocol(
                "invite binding proof token_commitment must be sha256".to_owned(),
            ));
        }
        if !invite_digest.as_str().starts_with("sha256:") {
            return Err(Error::Protocol(
                "invite binding proof invite_digest must be sha256".to_owned(),
            ));
        }
        Ok(Self {
            audience: INVITE_CLAIM_AUDIENCE.to_owned(),
            binding_proof: binding_proof.unsigned(),
            claim_nonce: binding_proof.claim_nonce.clone(),
            invite_digest,
            invite_id,
            realm_id: binding_proof.realm_id.clone(),
            subject_id: binding_proof.subject_id.clone(),
            token_commitment,
            verification_service_id: binding_proof.verification_service_id.clone(),
        })
    }

    pub fn from_wire_parts(
        binding_proof: &InviteClaimBindingProof,
        invite_id: impl Into<String>,
        token_commitment: impl Into<String>,
        invite_digest: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            binding_proof,
            InviteId::new(invite_id.into())?,
            Hash::new(token_commitment.into())?,
            Hash::new(invite_digest.into())?,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = INVITE_BINDING_PROOF_TRANSCRIPT_DOMAIN.as_bytes().to_vec();
        bytes.extend(canonical::canonical_json_bytes(self)?);
        Ok(bytes)
    }

    pub fn transcript_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

pub fn invite_binding_proof_transcript_bytes(
    binding_proof: &InviteClaimBindingProof,
    invite_id: &str,
    token_commitment: &str,
    invite_digest: &str,
) -> Result<Vec<u8>> {
    InviteClaimBindingProofBody::from_wire_parts(
        binding_proof,
        invite_id,
        token_commitment,
        invite_digest,
    )?
    .canonical_bytes()
}

pub fn invite_binding_proof_transcript_digest(
    binding_proof: &InviteClaimBindingProof,
    invite_id: &str,
    token_commitment: &str,
    invite_digest: &str,
) -> Result<Hash> {
    InviteClaimBindingProofBody::from_wire_parts(
        binding_proof,
        invite_id,
        token_commitment,
        invite_digest,
    )?
    .transcript_digest()
}

/// Subject DID proof carried by `ak.invite.claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteSubjectProof {
    pub verification_method: String,
    pub alg: String,
    pub transcript_digest: Hash,
    pub signature: String,
}

impl InviteSubjectProof {
    pub fn new(
        verification_method: impl Into<String>,
        transcript_digest: Hash,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            verification_method: verification_method.into(),
            alg: INVITE_SUBJECT_PROOF_ALG.to_owned(),
            transcript_digest,
            signature: signature.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.verification_method.trim().is_empty() {
            return Err(Error::Protocol(
                "invite subject proof verification_method must not be empty".to_owned(),
            ));
        }
        if self.alg != INVITE_SUBJECT_PROOF_ALG {
            return Err(Error::Protocol(
                "invite subject proof alg must be EdDSA".to_owned(),
            ));
        }
        if !self.transcript_digest.as_str().starts_with("sha256:") {
            return Err(Error::Protocol(
                "invite subject proof transcript_digest must be sha256".to_owned(),
            ));
        }
        if self.signature.trim().is_empty() {
            return Err(Error::Protocol(
                "invite subject proof signature must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Canonical `ak.invite.claim.subject_proof.v1` transcript body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteSubjectProofBody {
    pub subject_id: Did,
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub token_commitment: Hash,
    pub claim_nonce: String,
    pub audience: String,
    pub verification_service_id: Did,
    pub binding_proof_digest: Hash,
}

impl InviteSubjectProofBody {
    pub fn new(
        subject_id: Did,
        invite_id: InviteId,
        realm_id: RealmId,
        token_commitment: Hash,
        claim_nonce: impl Into<String>,
        verification_service_id: Did,
        binding_proof_digest: Hash,
    ) -> Self {
        Self {
            subject_id,
            invite_id,
            realm_id,
            token_commitment,
            claim_nonce: claim_nonce.into(),
            audience: INVITE_CLAIM_AUDIENCE.to_owned(),
            verification_service_id,
            binding_proof_digest,
        }
    }

    pub fn from_wire_parts(
        subject_id: impl Into<String>,
        invite_id: impl Into<String>,
        realm_id: impl Into<String>,
        token_commitment: impl Into<String>,
        claim_nonce: impl Into<String>,
        verification_service_id: impl Into<String>,
        binding_proof_digest: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self::new(
            Did::new(subject_id.into())?,
            InviteId::new(invite_id.into())?,
            RealmId::new(realm_id.into())?,
            Hash::new(token_commitment.into())?,
            claim_nonce,
            Did::new(verification_service_id.into())?,
            Hash::new(binding_proof_digest.into())?,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.token_commitment.as_str().starts_with("sha256:") {
            return Err(Error::Protocol(
                "invite subject proof token_commitment must be sha256".to_owned(),
            ));
        }
        if self.claim_nonce.len() < 16 || self.claim_nonce.len() > 128 {
            return Err(Error::Protocol(
                "invite subject proof claim_nonce length must be 16..=128".to_owned(),
            ));
        }
        if self.audience != INVITE_CLAIM_AUDIENCE {
            return Err(Error::Protocol(
                "invite subject proof audience must be arkret.invite.claim".to_owned(),
            ));
        }
        if !self.binding_proof_digest.as_str().starts_with("sha256:") {
            return Err(Error::Protocol(
                "invite subject proof binding_proof_digest must be sha256".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = INVITE_SUBJECT_PROOF_TRANSCRIPT_DOMAIN.as_bytes().to_vec();
        bytes.extend(canonical::canonical_json_bytes(self)?);
        Ok(bytes)
    }

    pub fn transcript_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

pub fn invite_subject_proof_transcript_bytes(
    subject_id: &str,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_service_id: &str,
    binding_proof_digest: &str,
) -> Result<Vec<u8>> {
    InviteSubjectProofBody::from_wire_parts(
        subject_id,
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        verification_service_id,
        binding_proof_digest,
    )?
    .canonical_bytes()
}

pub fn invite_subject_proof_transcript_digest(
    subject_id: &str,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_service_id: &str,
    binding_proof_digest: &str,
) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        invite_subject_proof_transcript_bytes(
            subject_id,
            invite_id,
            realm_id,
            token_commitment,
            claim_nonce,
            verification_service_id,
            binding_proof_digest,
        )?,
    ))?)
}

/// Flat-form payload for `ak.relation.create`
/// (`#/$defs/relation_create_payload`).
///
/// The spec `anyOf` allows either an embedded `{relation: <object_snapshot>}`
/// or the flat `{relation_id, kind, from_ref, to_ref}` form; this strong type models the
/// flat form (the only shape inkson constructs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationCreatePayload {
    /// The whole relation object.
    ///
    /// `ak.relation.create`'s registered projection is `set value =
    /// payload.relation`, and `event-and-patch.md` §2.4.2 lets a projection
    /// move an existing root path wholesale but never assemble one — so the
    /// object is what the cell holds, and a flat
    /// `{relation_id, kind, from_ref, to_ref}` form would reduce to nothing.
    pub relation: RelationSnapshot,
    /// Optional lexical ordering rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
}

/// The relation object a `ak.relation.create` payload carries.
///
/// `object_snapshot` derives the object kind from the typed-id prefix on `id`,
/// so there is deliberately no `type` member — the schema bans that name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSnapshot {
    pub id: String,
    /// Registered `relation_kind` (e.g. `ak.relation.parent_of`).
    pub kind: String,
    /// Source endpoint `object_ref` (canonical typed id / did / digest).
    pub from_ref: ObjectRef,
    /// Target endpoint `object_ref`.
    pub to_ref: ObjectRef,
}

impl RelationCreatePayload {
    pub fn new(
        relation_id: impl Into<String>,
        kind: impl Into<String>,
        from_ref: impl Into<ObjectRef>,
        to_ref: impl Into<ObjectRef>,
    ) -> Self {
        Self {
            relation: RelationSnapshot {
                id: relation_id.into(),
                kind: kind.into(),
                from_ref: from_ref.into(),
                to_ref: to_ref.into(),
            },
            rank: None,
        }
    }

    pub fn with_rank(mut self, rank: impl Into<String>) -> Self {
        self.rank = Some(rank.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("relation create payload serialize: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_expiry_uses_signed_event_time_and_excludes_the_boundary() {
        let expiry = chrono::DateTime::parse_from_rfc3339("2026-07-26T00:05:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(invite_claim_within_canonical_expiry(
            expiry - chrono::Duration::milliseconds(1),
            expiry
        ));
        assert!(!invite_claim_within_canonical_expiry(expiry, expiry));
        assert!(!invite_claim_within_canonical_expiry(
            expiry + chrono::Duration::milliseconds(1),
            expiry
        ));
    }

    const SUBJECT: &str = "did:web:bob.example";
    const INVITE: &str = "ak:invite:0196419b-0000-7000-8000-000000000101";
    const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000001";
    const TOKEN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SERVICE: &str = "did:web:verify.example";
    const BINDING: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn binding_proof() -> InviteClaimBindingProof {
        InviteClaimBindingProof::new(
            Did::new(SERVICE).unwrap(),
            Did::new(SUBJECT).unwrap(),
            RealmId::new(REALM).unwrap(),
            "nonce-claim-proof-1",
            "2099-01-01T00:00:00.000Z",
            "did:web:verify.example#key-1",
            "c2ln",
        )
    }

    #[test]
    fn invite_binding_proof_transcript_is_typed_and_domain_separated() {
        let bytes = invite_binding_proof_transcript_bytes(&binding_proof(), INVITE, TOKEN, BINDING)
            .unwrap();
        let actual = String::from_utf8(bytes).unwrap();

        assert!(actual.starts_with(INVITE_BINDING_PROOF_TRANSCRIPT_DOMAIN));
        assert!(actual.contains("\"binding_proof\""));
        assert!(actual.contains("\"invite_digest\":\"sha256:bbbb"));
        assert!(!actual.contains("\"signature\""));
    }

    #[test]
    fn invite_binding_proof_rejects_sig_alias_and_unknown_fields() {
        let mut value = serde_json::to_value(binding_proof()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("signature");
        object.insert("sig".to_owned(), Value::String("c2ln".to_owned()));

        assert!(serde_json::from_value::<InviteClaimBindingProof>(value).is_err());
    }

    #[test]
    fn invite_binding_proof_digest_matches_transcript_bytes() {
        let proof = binding_proof();
        let bytes = invite_binding_proof_transcript_bytes(&proof, INVITE, TOKEN, BINDING).unwrap();
        let digest =
            invite_binding_proof_transcript_digest(&proof, INVITE, TOKEN, BINDING).unwrap();

        assert_eq!(digest.as_str(), canonical::sha256_digest(&bytes));
    }

    #[test]
    fn invite_subject_proof_transcript_bytes_are_domain_separated() {
        let bytes = invite_subject_proof_transcript_bytes(
            SUBJECT,
            INVITE,
            REALM,
            TOKEN,
            "nonce-claim-proof-1",
            SERVICE,
            BINDING,
        )
        .unwrap();
        let actual = String::from_utf8(bytes).unwrap();

        assert_eq!(
            actual,
            concat!(
                "ak.invite.claim.subject_proof.v1\n",
                "{\"audience\":\"arkret.invite.claim\",",
                "\"binding_proof_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                "\"claim_nonce\":\"nonce-claim-proof-1\",",
                "\"invite_id\":\"ak:invite:0196419b-0000-7000-8000-000000000101\",",
                "\"realm_id\":\"ak:realm:0196419b-0000-7000-8000-000000000001\",",
                "\"subject_id\":\"did:web:bob.example\",",
                "\"token_commitment\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "\"verification_service_id\":\"did:web:verify.example\"}"
            )
        );
    }

    #[test]
    fn invite_subject_proof_digest_matches_transcript_bytes() {
        let bytes = invite_subject_proof_transcript_bytes(
            SUBJECT,
            INVITE,
            REALM,
            TOKEN,
            "nonce-claim-proof-1",
            SERVICE,
            BINDING,
        )
        .unwrap();
        let digest = invite_subject_proof_transcript_digest(
            SUBJECT,
            INVITE,
            REALM,
            TOKEN,
            "nonce-claim-proof-1",
            SERVICE,
            BINDING,
        )
        .unwrap();

        assert_eq!(digest.as_str(), canonical::sha256_digest(&bytes));
    }

    #[test]
    fn invite_subject_proof_rejects_non_sha256_digest() {
        let body = InviteSubjectProofBody::from_wire_parts(
            SUBJECT,
            INVITE,
            REALM,
            TOKEN,
            "nonce-claim-proof-1",
            SERVICE,
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(body.canonical_bytes().is_err());
    }

    #[test]
    fn invite_subject_proof_rejects_short_nonce() {
        let body = InviteSubjectProofBody::from_wire_parts(
            SUBJECT, INVITE, REALM, TOKEN, "short", SERVICE, BINDING,
        )
        .unwrap();

        assert!(body.canonical_bytes().is_err());
    }
}
