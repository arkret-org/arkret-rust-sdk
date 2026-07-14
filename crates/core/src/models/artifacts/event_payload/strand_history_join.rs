//! Strand-create/stage, history-sharing policy, join-policy, and key-backup payloads.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{
    HistoryKeyShareDefault, HistoryKeySource, HistorySharingPostRemovalRecoveryPolicy,
    HistorySharingPreJoinPolicy, HistorySharingRange, HistorySharingReceiverClass,
    HistorySharingScopeKind,
};
use crate::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreatePayload {
    pub object: Strand,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `strand_move_payload` now has a strong type:
// `models::operation_payloads::StrandMovePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; flat
// board/target Space ids + rank with an optional `expected_position`
// CAS guard, `additionalProperties:false`).

// `strand_reorder_payload` now has a strong type:
// `models::operation_payloads::StrandReorderPayload` (single List-Space
// re-rank; `additionalProperties:false`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandStageSetPayload {
    pub strand_id: StrandId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
}

// `strand_watch_set_payload` now has a strong type:
// `models::operation_payloads::StrandWatchSetPayload` (carries the
// `StrandWatchLevel` enum / nullable `level` clear path and the
// `level_public`/`expected_value` CAS fields; `additionalProperties:false`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/generic_standard_payload`.
pub type GenericStandardPayload = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/hierarchy_link_status`.
pub type HierarchyLinkStatus = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayloadValueAudit {
    pub share_audit_event_required: bool,
    pub access_audit_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayloadValue {
    pub version: u64,
    pub default_key_share: HistoryKeyShareDefault,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_join_history: Option<HistorySharingPreJoinPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_removal_recovery: Option<HistorySharingPostRemovalRecoveryPolicy>,
    pub allowed_key_sources: Vec<HistoryKeySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_receiver_states: Option<Vec<HistorySharingReceiverClass>>,
    pub audit: HistorySharingPolicyPayloadValueAudit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_rules: Option<Vec<HistorySharingRestrictedRule>>,
}

impl HistorySharingPolicyPayloadValue {
    pub fn receiver_state_allowed(&self, receiver_class: HistorySharingReceiverClass) -> bool {
        self.allowed_receiver_states
            .as_ref()
            .map(|states| states.contains(&receiver_class))
            .unwrap_or(receiver_class == HistorySharingReceiverClass::ActiveMember)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayload {
    pub value: HistorySharingPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_restricted_rule`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingRestrictedRuleHistoryScope {
    pub kind: HistorySharingScopeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<CircleId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingRestrictedRule {
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_scope: Option<HistorySharingRestrictedRuleHistoryScope>,
    pub receiver_classes: Vec<HistorySharingReceiverClass>,
    pub allowed_history_visibility_values: Vec<HistoryVisibilityValue>,
    pub range: HistorySharingRange,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epoch_span: Option<u64>,
    pub key_sources: Vec<HistoryKeySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_required: Option<bool>,
}

// `history_visibility_payload` now has a strong type:
// `models::operation_payloads::HistoryVisibilityPayload` (`{value,
// restricted_policy_digest?, reason?}`, deny_unknown_fields, with the
// `value==restricted ⇒ restricted_policy_digest` conditional enforced by
// `to_value`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_visibility_value`.
pub type HistoryVisibilityValue = HistoryVisibility;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/inheritance_policy_status`.
pub type InheritancePolicyStatus = String;

// `invite_payload` anyOf branches now have strong types in
// `models::operation_payloads`: `InviteCreatePayload` (directed-create) and
// `InviteRefPayload` (invite_id ref, for accept/cancel). The full union is
// not modeled as one type (the remaining anyOf branches — `invite`,
// `third_party_id`, claim-proof — are not constructed by the client wire).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/join_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayloadGatesItem {
    pub gate_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resolve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_did_methods: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_principal_dids: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_principal_dids: Option<Vec<Did>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayload {
    pub gates: Vec<JoinPolicyPayloadGatesItem>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_quorum: Option<JoinReviewerQuorum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ttl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_after_reject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_applications_per_actor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicant_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<BTreeMap<String, Value>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinReviewerQuorumPreset {
    Any,
    Majority,
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinReviewerQuorumMembers {
    pub threshold: NonZeroU64,
    pub reviewers: Vec<Did>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JoinReviewerQuorum {
    Preset(JoinReviewerQuorumPreset),
    Members(JoinReviewerQuorumMembers),
}

/// A join-policy gate proof submitted with a `membership=join` Move on the
/// auto-resolve path (`governance/join-policy.md` §5) or inside a
/// `member.application` (§7.2). Exactly one of `claim_presentation` /
/// `challenge_proof` is populated per gate, keyed by `gate_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateProof {
    pub gate_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_presentation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_proof: Option<Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// A single applicant answer to an `application_form` question
/// (`governance/join-policy.md` §7.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberApplicationAnswer {
    pub question_id: String,
    pub value: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Candidate `member.application` record (`governance/join-policy.md` §7.2).
/// This is a profile-private workflow concept — NOT a standalone `ak.*`
/// Event.kind. Carried on the active `ak.member.state{knock}` event under an
/// `application` sub-object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberApplicationPayload {
    pub realm_id: RealmId,
    pub applicant_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knock_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<MemberApplicationAnswer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<GateProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_receipt_digest: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Candidate `member.application.review` record (`governance/join-policy.md`
/// §7.3). Profile-private, carried on a `ak.member.state` event under an
/// `application_review` sub-object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberApplicationReviewPayload {
    pub realm_id: RealmId,
    pub application_ref: String,
    /// `accept` / `reject` / `request_changes`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_receipt_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_capability_proof: Option<Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/key_backup_active_series_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
    pub ssk_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: Did,
    pub backup_class: BackupClass,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub frontier_ref: Value,
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupActiveSeriesAuthData,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

pub type KeyBackupActiveSeriesPayload = KeyBackupActiveSeries;
