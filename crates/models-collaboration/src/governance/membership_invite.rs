use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, ActorId, DidCoreId, DidUrl, EventId, Hash, InviteId, NonEmptyString, PayloadProof,
    RealmId, Result, StrandId, WireError, XExtensionMap, canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::agent_membership_cascade::{
    AgentControllerMembershipBinding, MembershipLifecycleCause,
};
use crate::governance::third_party_invite::ThirdPartyInvite;

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
/// only models the live `join`/`knock` states): the FSM transition
/// payload additionally carries the terminal `leave`/`ban` states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipPayloadState {
    Join,
    Knock,
    Leave,
    Ban,
}

/// The two join-policy gate kinds that take an applicant-supplied proof.
///
/// `parent_membership`, `principal_admission` and `cooldown` are replayed by
/// the reducer from accepted state, so a proof item naming one of them has no
/// meaning and cannot be constructed (`join-policy.md` §4 rule 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinGateProofKind {
    ChallengeResponse,
    ClaimRequired,
}

/// Closed applicant proof for one automatic join gate
/// (`event-payload.schema.json#/$defs/join_gate_proof`).
///
/// The binding tuple — gate, Realm, applicant, policy revision, creation time —
/// rides as wire members and is covered by `proofs`, so a proof replayed across
/// Realms, applicants or policy revisions fails by field comparison before any
/// signature is checked. Freshness is judged against the enclosing Event's
/// signed `created_at`, never a receiver clock.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinGateProof {
    pub gate_id: String,
    pub kind: JoinGateProofKind,
    pub realm_id: RealmId,
    pub applicant_actor_id: ActorId,
    /// `sha256` over the canonical JSON of the accepted `join_policy`
    /// component the reducer evaluates this join against.
    pub policy_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `challenge_response` only; MUST be one of the gate's `challenge_kinds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_kind: Option<JoinPolicyChallengeKind>,
    /// `challenge_response` only; the provider treats it as single-use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    /// `claim_required` only; MUST be listed in the gate's `trusted_issuer_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<DidCoreId>,
    /// `claim_required` only; MUST cover the gate's `required_claims`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<NonEmptyString>>,
    pub proofs: Vec<PayloadProof>,
}

impl JoinGateProof {
    /// `payload_digest` for this proof: `sha256` over its canonical JSON with
    /// `proofs` removed (`proof-context-registry.json`, context
    /// `ak.join_gate_proof.v1`).
    ///
    /// Derived from the typed body rather than from received JSON, so a
    /// verifier cannot be handed a digest over some other object.
    pub fn payload_digest(&self) -> Result<Hash> {
        let body = canonical::unsigned_value(self, &["proofs"])?;
        Hash::new(canonical::canonical_sha256(&body)?).map_err(Into::into)
    }

    /// The canonical binding object one detached proof signs.
    ///
    /// Members are exactly the registered `binding_fields` for this context and
    /// in that order, so a signature made under another object family's context
    /// cannot verify against this one.
    pub fn proof_binding_object(&self, detached: &PayloadProof) -> Result<Value> {
        let payload_digest = self.payload_digest()?;
        let mut binding = serde_json::Map::new();
        binding.insert(
            "context".to_owned(),
            Value::String(arkret_wire::ProofContextId::JOIN_GATE_PROOF_V1.to_owned()),
        );
        binding.insert(
            "payload_digest".to_owned(),
            serde_json::to_value(&payload_digest)?,
        );
        binding.insert("gate_id".to_owned(), Value::String(self.gate_id.clone()));
        binding.insert("realm_id".to_owned(), serde_json::to_value(&self.realm_id)?);
        binding.insert(
            "applicant_actor_id".to_owned(),
            serde_json::to_value(&self.applicant_actor_id)?,
        );
        binding.insert(
            "policy_digest".to_owned(),
            serde_json::to_value(&self.policy_digest)?,
        );
        binding.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&detached.verification_method)?,
        );
        binding.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(detached.created_at)),
        );
        Ok(Value::Object(binding))
    }
}

/// Challenge families a `challenge_response` gate may accept
/// (`join-policy.md` §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyChallengeKind {
    Captcha,
    Pow,
    AttestedHuman,
    IdpOidc,
}

/// Strong type for `ak.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_payload`).
///
/// `additionalProperties:false`: the removed `handle` / `from` keys that older
/// inkson call sites tried to emit are intentionally NOT representable here —
/// `handle` has no spec-legal home in this payload (the member identity is
/// carried by `member_id`; handle evidence lives in signed `HandleClaim`
/// objects on the roster, not the durable membership event), and the FSM
/// `from` expectation is checked by the governance Station against its committed
/// `transition`, not the payload body.
///
/// Member identity is one closed `ActorId`; delivery is projected from it and
/// is not membership state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/membership_payload`.
pub struct MembershipPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub member_id: ActorId,
    pub membership: MembershipPayloadState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<JoinGateProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Closed audit-only lifecycle cause. It classifies the transition and
    /// never supplies authority (`zh/models/actor.md` section on explicit
    /// cascade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_cause: Option<MembershipLifecycleCause>,
    /// Exact controller authority pair and membership generation an Agent
    /// membership is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_controller_binding: Option<AgentControllerMembershipBinding>,
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
    /// Build a membership transition payload.
    pub fn transition(
        membership: MembershipPayloadState,
        member_id: ActorId,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership,
            strand_id: None,
            realm_id: None,
            member_id,
            gate_proofs: Vec::new(),
            reason: Some(reason.into()),
            membership_cause: None,
            agent_controller_binding: None,
            invite_ref: None,
        }
    }

    /// Build a `join` transition payload with the schema-required
    /// `realm_id` + complete `member_id` fields.
    pub fn join(realm_id: RealmId, member_id: ActorId, reason: impl Into<String>) -> Self {
        Self {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(realm_id),
            member_id,
            gate_proofs: Vec::new(),
            reason: Some(reason.into()),
            membership_cause: None,
            agent_controller_binding: None,
            invite_ref: None,
        }
    }

    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    /// Validate the schema-level conditional required fields, then serialize.
    pub fn to_value(&self) -> Result<Value> {
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.chars().count() > 256)
        {
            return Err(WireError::Protocol(
                "membership payload reason exceeds 256 characters".to_owned(),
            ));
        }
        if self.membership_cause.is_some() {
            let binding = self.agent_controller_binding.as_ref().ok_or_else(|| {
                WireError::Protocol(
                    "membership lifecycle cause requires the Agent controller binding".to_owned(),
                )
            })?;
            if self.membership != MembershipPayloadState::Leave
                || binding.controller_terminal_event_ref.is_none()
            {
                return Err(WireError::Protocol(
                    "controller-membership-ended cleanup must be a leave bound to the terminal controller Event"
                        .to_owned(),
                ));
            }
            binding.validate()?;
        }
        if self.membership == MembershipPayloadState::Join
            && let Some(binding) = self.agent_controller_binding.as_ref()
        {
            if binding.controller_terminal_event_ref.is_some() {
                return Err(WireError::Protocol(
                    "an Agent join binding must not carry a terminal controller Event".to_owned(),
                ));
            }
            binding.validate()?;
        }
        self.member_id.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("membership payload serialize: {err}")))
    }
}

/// Directed-create form of `invite_create_payload`. The Invite id is derived
/// from the create Event and therefore cannot be represented in this payload.
///
/// The schema allows `x_*` extension properties (patternProperties
/// `^x_[a-z][a-z0-9_]{0,63}$`) but is otherwise `additionalProperties:false`;
/// the typed `x_*` extensions (e.g. `x_role`) are carried in [`Self::extensions`]
/// and re-prefixed on serialize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteCreatePayload {
    pub invitee_account_id: AccountId,
    pub introduction_evidence_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// `x_*` extension properties.
    #[serde(flatten, default)]
    pub extensions: XExtensionMap,
}

impl InviteCreatePayload {
    pub fn new(
        invitee_account_id: AccountId,
        introduction_evidence_digest: Hash,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            invitee_account_id,
            introduction_evidence_digest,
            expires_at,
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
            .map_err(|error| WireError::Protocol(error.to_owned()))?;
        Ok(self)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.invitee_account_id.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("invite create payload serialize: {err}")))
    }
}

/// Enforce the `invite_create_payload` closed-key set (typed fields + `x_*`
/// extensions) before deserializing an inbound payload. Callers that also
/// require schema-catalog validation run the `arkret-schema` payload gate at
/// their ingress boundary before decoding this model.
pub fn validate_invite_create_wire_keys(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(WireError::Protocol(
            "invite create payload must be an object".to_owned(),
        ));
    };
    for key in object.keys() {
        if matches!(
            key.as_str(),
            "invitee_account_id" | "introduction_evidence_digest" | "expires_at"
        ) || valid_invite_create_extension_key(key)
        {
            continue;
        }
        return Err(WireError::Protocol(format!(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteCancelTargetState {
    Rejected,
    Revoked,
}

/// Directed-invite cancel/reject payload. It deliberately carries the stored
/// invitee so the Invite lifecycle and member-state transitions are atomic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteCancelPayload {
    pub invite_id: InviteId,
    pub invitee_account_id: AccountId,
    pub target_state: InviteCancelTargetState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InviteCancelPayload {
    pub fn new(
        invite_id: InviteId,
        invitee_account_id: AccountId,
        target_state: InviteCancelTargetState,
    ) -> Self {
        Self {
            invite_id,
            invitee_account_id,
            target_state,
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("invite cancel payload serialize: {err}")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteRevokeTargetState {
    Revoked,
    Expired,
    /// The delivery service could not reach the private invite delivery target.
    ///
    /// It is the only non-terminal target state and the only one that keeps the
    /// invite inside the live set, so it derives no
    /// `ak.component.invite.live_target.v1` release write
    /// (`zh/models/governance-objects.md` section 5.3).
    SendFailed,
    RevokedByCapabilityLoss,
    RevokedByInviterLeft,
    InvalidatedByRateLimit,
}

impl InviteRevokeTargetState {
    /// Whether this transition releases the invitee's Realm live-target slot.
    ///
    /// `send_failed` keeps the invite live, so it MUST NOT release; every other
    /// registered target state is terminal and MUST.
    pub const fn releases_live_target(self) -> bool {
        !matches!(self, Self::SendFailed)
    }
}

/// High-risk/direct-or-third-party revocation payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRevokePayload {
    pub invite_id: InviteId,
    /// Present exactly when the target Invite stores one and `target_state` is
    /// not `send_failed`: it is the only signed source the
    /// `ak.component.invite.live_target.v1` subject can be derived from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee_account_id: Option<AccountId>,
    pub target_state: InviteRevokeTargetState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InviteRevokePayload {
    /// Enforce the schema's `if/then`: `send_failed` MUST NOT carry
    /// `invitee_account_id`.
    ///
    /// A `send_failed` Move that carried one would derive a slot release write
    /// while the invite is still live, which is exactly the leak the live set
    /// definition forbids (`zh/models/governance-objects.md` section 5.3).
    pub fn validate(&self) -> Result<()> {
        if self.target_state == InviteRevokeTargetState::SendFailed
            && self.invitee_account_id.is_some()
        {
            return Err(WireError::Protocol(
                "invite revoke payload must omit invitee_account_id when target_state is send_failed"
                    .to_owned(),
            ));
        }
        if let Some(invitee_account_id) = &self.invitee_account_id {
            invitee_account_id.validate()?;
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("invite revoke payload serialize: {err}")))
    }
}

/// `ak.invite.accept` payload. The accepting subject is the Event actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteAcceptPayload {
    pub invite_id: InviteId,
    /// Present exactly when the target Invite stores one, that is for a
    /// directed invite and never for a third-party invite.
    ///
    /// It exists only so the `ak.component.invite.live_target.v1` subject can be
    /// derived from the signed Event: the projection grammar cannot convert the
    /// envelope ActorId into an AccountId. It is not a "accept on behalf of"
    /// entry point — see [`Self::validate_actor`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee_account_id: Option<AccountId>,
    #[serde(flatten, default)]
    pub extensions: XExtensionMap,
}

impl InviteAcceptPayload {
    pub fn new(invite_id: InviteId) -> Self {
        Self {
            invite_id,
            invitee_account_id: None,
            extensions: XExtensionMap::default(),
        }
    }

    /// Directed form: carry the stored invitee so the slot release write is
    /// derivable from this Event alone.
    pub fn directed(invite_id: InviteId, invitee_account_id: AccountId) -> Self {
        Self {
            invite_id,
            invitee_account_id: Some(invitee_account_id),
            extensions: XExtensionMap::default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(invitee_account_id) = &self.invitee_account_id {
            invitee_account_id.validate()?;
        }
        Ok(())
    }

    /// `zh/models/governance-objects.md` section 5.3: `invitee_account_id` MUST
    /// equal the envelope actor's account component. Only the invitee accepts
    /// their own invite; the field never widens who may accept.
    pub fn validate_actor(&self, actor_id: &ActorId) -> Result<()> {
        self.validate()?;
        let Some(invitee_account_id) = &self.invitee_account_id else {
            return Ok(());
        };
        if actor_id.as_account_id() != Some(invitee_account_id) {
            return Err(WireError::Protocol(
                "invite accept payload invitee_account_id must equal the envelope actor account"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("invite accept payload serialize: {err}")))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteThirdPartyCreatePayload {
    pub third_party_invite: ThirdPartyInvite,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(flatten, default)]
    pub extensions: XExtensionMap,
}

impl InviteThirdPartyCreatePayload {
    pub fn validate(&self) -> Result<()> {
        self.third_party_invite.validate_minimal()
    }
}

pub const INVITE_CLAIM_AUDIENCE: &str = "arkret.invite.claim";
pub const INVITE_BINDING_PROOF_TRANSCRIPT_DOMAIN: &str = "ak.invite.claim.binding_proof.v1\n";
pub const INVITE_SUBJECT_PROOF_ALG: &str = "Ed25519";
pub const INVITE_SUBJECT_PROOF_TRANSCRIPT_DOMAIN: &str = "ak.invite.claim.subject_proof.v1\n";

/// Verification-service proof carried by `ak.invite.claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteClaimBindingProof {
    pub verification_id: DidCoreId,
    pub verification_method: DidUrl,
    pub subject_account_id: AccountId,
    pub realm_id: RealmId,
    pub audience: String,
    pub claim_nonce: String,
    pub expires_at: String,
    pub signature: String,
}

impl InviteClaimBindingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verification_id: DidCoreId,
        subject_account_id: AccountId,
        realm_id: RealmId,
        claim_nonce: impl Into<String>,
        expires_at: impl Into<String>,
        verification_method: DidUrl,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            verification_id,
            subject_account_id,
            realm_id,
            audience: INVITE_CLAIM_AUDIENCE.to_owned(),
            claim_nonce: claim_nonce.into(),
            expires_at: expires_at.into(),
            verification_method,
            signature: signature.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.audience != INVITE_CLAIM_AUDIENCE {
            return Err(WireError::Protocol(
                "invite binding proof audience must be arkret.invite.claim".to_owned(),
            ));
        }
        if self.claim_nonce.len() < 16 || self.claim_nonce.len() > 128 {
            return Err(WireError::Protocol(
                "invite binding proof claim_nonce length must be 16..=128".to_owned(),
            ));
        }
        canonical::validate_timestamp_canonical(&self.expires_at)?;
        // `verification_method` is a `DidUrl`: emptiness — and "is it a DID
        // URL at all" — is enforced by the type at deserialization, so the
        // hand-written guard that used to live here is gone
        // (did-usage-and-verification.md §6).
        if self.signature.trim().is_empty() {
            return Err(WireError::Protocol(
                "invite binding proof signature must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn unsigned(&self) -> InviteClaimUnsignedBindingProof {
        InviteClaimUnsignedBindingProof {
            verification_id: self.verification_id.clone(),
            subject_account_id: self.subject_account_id.clone(),
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
    pub verification_id: DidCoreId,
    pub subject_account_id: AccountId,
    pub realm_id: RealmId,
    pub audience: String,
    pub claim_nonce: String,
    pub expires_at: String,
    pub verification_method: DidUrl,
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
    pub subject_account_id: AccountId,
    pub token_commitment: Hash,
    pub verification_id: DidCoreId,
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
            return Err(WireError::Protocol(
                "invite binding proof token_commitment must be sha256".to_owned(),
            ));
        }
        if !invite_digest.as_str().starts_with("sha256:") {
            return Err(WireError::Protocol(
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
            subject_account_id: binding_proof.subject_account_id.clone(),
            token_commitment,
            verification_id: binding_proof.verification_id.clone(),
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

/// Subject DID proof carried by `ak.invite.claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteSubjectProof {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub transcript_digest: Hash,
    pub signature: String,
}

impl InviteSubjectProof {
    pub fn new(
        verification_method: DidUrl,
        transcript_digest: Hash,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            verification_method,
            signature_algorithm: INVITE_SUBJECT_PROOF_ALG.to_owned(),
            transcript_digest,
            signature: signature.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.verification_method.trim().is_empty() {
            return Err(WireError::Protocol(
                "invite subject proof verification_method must not be empty".to_owned(),
            ));
        }
        if !matches!(self.signature_algorithm.as_str(), "Ed25519" | "ML-DSA-65") {
            return Err(WireError::Protocol(
                "invite subject proof alg must be Ed25519 or ML-DSA-65".to_owned(),
            ));
        }
        if !self.transcript_digest.as_str().starts_with("sha256:") {
            return Err(WireError::Protocol(
                "invite subject proof transcript_digest must be sha256".to_owned(),
            ));
        }
        if self.signature.trim().is_empty() {
            return Err(WireError::Protocol(
                "invite subject proof signature must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Complete `ak.invite.claim` payload. Claim evidence is kept distinct from
/// every create/cancel/revoke payload shape.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteClaimPayload {
    pub invite_id: InviteId,
    pub subject_account_id: AccountId,
    pub token_commitment: Hash,
    pub claim_nonce: String,
    pub binding_proof: InviteClaimBindingProof,
    pub subject_proof: InviteSubjectProof,
    #[serde(flatten, default)]
    pub extensions: XExtensionMap,
}

impl InviteClaimPayload {
    pub fn validate(&self) -> Result<()> {
        self.binding_proof.validate()?;
        self.subject_proof.validate()?;
        if self.claim_nonce.len() < 16
            || self.claim_nonce.len() > 128
            || self.subject_account_id != self.binding_proof.subject_account_id
            || self.claim_nonce != self.binding_proof.claim_nonce
            || !self.token_commitment.as_str().starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "invite claim payload does not match its binding evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Canonical `ak.invite.claim.subject_proof.v1` transcript body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteSubjectProofBody {
    pub subject_account_id: AccountId,
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub token_commitment: Hash,
    pub claim_nonce: String,
    pub audience: String,
    pub verification_id: DidCoreId,
    pub binding_proof_digest: Hash,
}

impl InviteSubjectProofBody {
    pub fn new(
        subject_account_id: AccountId,
        invite_id: InviteId,
        realm_id: RealmId,
        token_commitment: Hash,
        claim_nonce: impl Into<String>,
        verification_id: DidCoreId,
        binding_proof_digest: Hash,
    ) -> Self {
        Self {
            subject_account_id,
            invite_id,
            realm_id,
            token_commitment,
            claim_nonce: claim_nonce.into(),
            audience: INVITE_CLAIM_AUDIENCE.to_owned(),
            verification_id,
            binding_proof_digest,
        }
    }

    pub fn from_wire_parts(
        subject_account_id: AccountId,
        invite_id: impl Into<String>,
        realm_id: impl Into<String>,
        token_commitment: impl Into<String>,
        claim_nonce: impl Into<String>,
        verification_id: impl Into<String>,
        binding_proof_digest: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self::new(
            subject_account_id,
            InviteId::new(invite_id.into())?,
            RealmId::new(realm_id.into())?,
            Hash::new(token_commitment.into())?,
            claim_nonce,
            DidCoreId::new(verification_id.into())?,
            Hash::new(binding_proof_digest.into())?,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.token_commitment.as_str().starts_with("sha256:") {
            return Err(WireError::Protocol(
                "invite subject proof token_commitment must be sha256".to_owned(),
            ));
        }
        if self.claim_nonce.len() < 16 || self.claim_nonce.len() > 128 {
            return Err(WireError::Protocol(
                "invite subject proof claim_nonce length must be 16..=128".to_owned(),
            ));
        }
        if self.audience != INVITE_CLAIM_AUDIENCE {
            return Err(WireError::Protocol(
                "invite subject proof audience must be arkret.invite.claim".to_owned(),
            ));
        }
        if !self.binding_proof_digest.as_str().starts_with("sha256:") {
            return Err(WireError::Protocol(
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
    subject_account_id: &AccountId,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_id: &str,
    binding_proof_digest: &str,
) -> Result<Vec<u8>> {
    InviteSubjectProofBody::from_wire_parts(
        subject_account_id.clone(),
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        verification_id,
        binding_proof_digest,
    )?
    .canonical_bytes()
}

pub fn invite_subject_proof_transcript_digest(
    subject_account_id: &AccountId,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_id: &str,
    binding_proof_digest: &str,
) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        invite_subject_proof_transcript_bytes(
            subject_account_id,
            invite_id,
            realm_id,
            token_commitment,
            claim_nonce,
            verification_id,
            binding_proof_digest,
        )?,
    ))?)
}
