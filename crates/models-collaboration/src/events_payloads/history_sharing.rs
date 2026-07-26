//! History-sharing policy event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_visibility_value`.
pub type HistoryVisibilityValue = HistoryVisibility;

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
