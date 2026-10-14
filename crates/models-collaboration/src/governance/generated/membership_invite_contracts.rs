// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=448abceebd5661cb1d2db37d9a28dbe85815f08cf0119282307229865080a78b
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Input: schemas/agent-operations.schema.json
// sha256=61dfc936d4795906bf2eaa2ab39f5a0ad8833d024e53eddfdd2a3500fee90e8e
//
// Input: schemas/agent-membership-cascade.schema.json
// sha256=c0bb436f9758322f34eeafa870f05761aee9a4c5d7bf3f5783d81c12639d0b5c
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

/// Counterpart: `typed-current-result.schema.json#/$defs/invite_directed_invitee_value`.
/// Closed value of the `invite_directed_invitee` typed current result
/// (`typed-current-result.schema.json#/$defs/invite_directed_invitee_value`).
///
/// It is the create-locked reverse index of the `invite_live_target` slot:
/// written once by a directed `ak.invite.create` from that Event's own payload
/// and never by `ak.invite.third_party`, so a third-party Invite's stored
/// invitee is absent rather than null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDirectedInviteeValue {
    pub invitee_account_id: AccountId,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/invite_live_target_value/oneOf/0`.
/// The occupied branch of the `invite_live_target` slot value
/// (`typed-current-result.schema.json#/$defs/invite_live_target_value/oneOf/0`).
///
/// The occupant is the verbatim `ak:event:` id of the `ak.invite.create` that
/// holds the slot, never its `ak:invite:` retype. The empty branch of the same
/// value is JSON `null`, carried as `Option<InviteLiveTargetOccupant>`: it is
/// the reusable state a registered release write returns the slot to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteLiveTargetOccupant {
    pub create_event_id: EventId,
}

/// Counterpart: `event-payload.schema.json#/$defs/join_gate_proof`.
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
    pub policy_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub challenge_kind: Option<JoinPolicyChallengeKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub challenge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub issuer_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub claims: Option<Vec<NonEmptyString>>,
    pub proofs: Vec<PayloadProof>,
}

/// Counterpart: `event-payload.schema.json#/$defs/membership_payload`.
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
pub struct MembershipPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub realm_id: Option<RealmId>,
    pub member_id: ActorId,
    pub membership: MembershipPayloadState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<JoinGateProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub membership_cause: Option<MembershipLifecycleCause>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub agent_controller_binding: Option<AgentControllerMembershipBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub invite_ref: Option<MembershipInviteRef>,
}
