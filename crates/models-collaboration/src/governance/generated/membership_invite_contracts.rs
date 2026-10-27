// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//
// Input: schemas/event-payload.schema.json
// sha256=6e557b3350ecfe34a8c4836bb00abf61dce039fa6a5fbbc58b07ec74dbaaba7f
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/agent-operations.schema.json
// sha256=57acbc5881e4ce66c0742968ae383fe5bda77fe0461abc395560e10fcdca637a
//
// Input: schemas/agent-membership-cascade.schema.json
// sha256=0aeb76477ec3d0ff335ea072a019a0b7d4371ff5890add72cf986fe5167e8de3
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c8b4ad76a778828f23891614ed9c259161da8c53eb669c8825b9bb8a5da8ff2

/// Counterpart: `current-state.schema.json#/$defs/invite_directed_invitee_value`.
/// Closed value of the `invite_directed_invitee` current state
/// (`current-state.schema.json#/$defs/invite_directed_invitee_value`).
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

/// Counterpart: `current-state.schema.json#/$defs/invite_live_target_value/oneOf/0`.
/// The occupied branch of the `invite_live_target` slot value
/// (`current-state.schema.json#/$defs/invite_live_target_value/oneOf/0`).
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
/// The binding tuple â€” gate, Realm, applicant, policy revision, creation time â€”
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
/// inkson call sites tried to emit are intentionally NOT representable here â€”
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
