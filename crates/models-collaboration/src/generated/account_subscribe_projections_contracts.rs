// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-subscribe-frame.schema.json
// sha256=ba4f9b067a14c0f6a204ce7687fb39e115823811a98c15438e533e2094139809
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

/// Counterpart: `account-subscribe-frame.schema.json#/$defs/member_roster`.
/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/member_roster`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRoster {
    pub entries: Vec<MemberRosterEntry>,
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<Cursor>,
}

/// Counterpart: `account-subscribe-frame.schema.json#/$defs/member_roster_entry`.
/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`.
///
/// The schema's `dependentRequired` block is the entry's whole privacy rule:
/// inline identity Events, handle-claim digests, inline handle claims and the
/// truncation flag are all linkable to one member, so each one may appear only
/// when `subject_account_id` is already disclosed. [`Self::validate`] enforces
/// that, so an entry that reaches a caller has never leaked a subject through
/// a side channel the projection itself declined to disclose.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRosterEntry {
    pub actor_id: ActorId,
    pub membership: MemberRosterMembership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub subject_account_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub member_display_state_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub identity_events: Option<Vec<Event>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub handle_claim_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub handle_claims: Option<Vec<HandleClaim>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub handle_claims_limited: Option<bool>,
}

/// Counterpart:
/// `account-subscribe-frame.schema.json#/$defs/agent_runtime_approval_notification_data`.
/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/agent_runtime_approval_notification_data`.
///
/// This is the `upsert` payload of the Agent runtime approval branch of one
/// `notification_delta`, selected by an `ak:notification:<uuidv7>` delta id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationData {
    pub approval_request_id: AgentRuntimeApprovalRequestId,
    pub agent_id: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}
