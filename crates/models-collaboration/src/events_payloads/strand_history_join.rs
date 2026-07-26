//! Strand-create/stage, history-sharing policy, join-policy, and key-backup payloads.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::internal_prelude::*;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyQuestionAnswerKind {
    Text,
    SingleChoice,
    MultiChoice,
    Boolean,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyQuestionChoice {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyQuestion {
    pub question_id: String,
    pub prompt_canonical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_locales: Option<BTreeMap<String, String>>,
    pub answer_kind: JoinPolicyQuestionAnswerKind,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_chars: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<JoinPolicyQuestionChoice>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reject_if_choice_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_in_directory: Option<bool>,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub questions: Option<Vec<JoinPolicyQuestion>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyDirectoryChallengeKind {
    Captcha,
    Pow,
    AttestedHuman,
    IdpOidc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyDirectoryHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_review_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_review_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_kinds_displayed: Option<Vec<JoinPolicyDirectoryChallengeKind>>,
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
    pub directory_hint: Option<JoinPolicyDirectoryHint>,
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

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/key_backup_active_series_payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
    pub trust_binding: KeyBackupActiveSeriesTrustBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesFrontierRef {
    pub frontier_digest: Hash,
    pub seal_ref: Option<SealId>,
    pub generation: KeyBackupActiveSeriesFrontierGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBackupActiveSeriesTrustBinding {
    SskGeneration(NonZeroU64),
    DeviceAuthorizeEventId(EventId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBackupActiveSeriesFrontierGeneration {
    SskGeneration(NonZeroU64),
    DeviceGenerationRef(NonEmptyString),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBackupActiveSeriesAuthDataWire {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
    signature: Base64UrlString,
    signed_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<EventId>,
}

impl Serialize for KeyBackupActiveSeriesAuthData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, device_authorize_event_id) = match &self.trust_binding {
            KeyBackupActiveSeriesTrustBinding::SskGeneration(generation) => {
                (Some(*generation), None)
            }
            KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id) => {
                (None, Some(event_id.clone()))
            }
        };
        KeyBackupActiveSeriesAuthDataWire {
            verification_method: self.verification_method.clone(),
            signature_algorithm: self.signature_algorithm,
            signature: self.signature.clone(),
            signed_fields: self.signed_fields.clone(),
            ssk_generation,
            device_authorize_event_id,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeriesAuthData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyBackupActiveSeriesAuthDataWire::deserialize(deserializer)?;
        let trust_binding = match (wire.ssk_generation, wire.device_authorize_event_id) {
            (Some(generation), None) => {
                KeyBackupActiveSeriesTrustBinding::SskGeneration(generation)
            }
            (None, Some(event_id)) => {
                KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id)
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "active-series auth_data must contain exactly one trust binding",
                ));
            }
        };
        Ok(Self {
            verification_method: wire.verification_method,
            signature_algorithm: wire.signature_algorithm,
            signature: wire.signature,
            signed_fields: wire.signed_fields,
            trust_binding,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBackupActiveSeriesFrontierRefWire {
    frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_generation_ref: Option<NonEmptyString>,
}

impl Serialize for KeyBackupActiveSeriesFrontierRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, device_generation_ref) = match &self.generation {
            KeyBackupActiveSeriesFrontierGeneration::SskGeneration(generation) => {
                (Some(*generation), None)
            }
            KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation) => {
                (None, Some(generation.clone()))
            }
        };
        KeyBackupActiveSeriesFrontierRefWire {
            frontier_digest: self.frontier_digest.clone(),
            seal_ref: self.seal_ref.clone(),
            ssk_generation,
            device_generation_ref,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeriesFrontierRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyBackupActiveSeriesFrontierRefWire::deserialize(deserializer)?;
        let generation = match (wire.ssk_generation, wire.device_generation_ref) {
            (Some(generation), None) => {
                KeyBackupActiveSeriesFrontierGeneration::SskGeneration(generation)
            }
            (None, Some(generation)) => {
                KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation)
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "active-series frontier_ref must contain exactly one generation binding",
                ));
            }
        };
        Ok(Self {
            frontier_digest: wire.frontier_digest,
            seal_ref: wire.seal_ref,
            generation,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: Did,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub frontier_ref: KeyBackupActiveSeriesFrontierRef,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupActiveSeriesAuthData,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesHead {
    pub actor_id: Did,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub record_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyBackupActiveSeriesTransitionError {
    #[error("key_backup_active_series_schema_mismatch")]
    SchemaMismatch,
    #[error("key_backup_active_series_signed_fields_duplicate")]
    SignedFieldsDuplicate,
    #[error("key_backup_active_series_signed_fields_incomplete")]
    SignedFieldsIncomplete,
    #[error("key_backup_active_series_active_in_previous")]
    ActiveInPrevious,
    #[error("key_backup_active_series_previous_series_duplicate")]
    PreviousSeriesDuplicate,
    #[error("key_backup_active_series_generation_binding_mismatch")]
    GenerationBindingMismatch,
    #[error("key_backup_active_series_actor_or_class_mismatch")]
    ActorOrClassMismatch,
    #[error("key_backup_active_series_pointer_version_rollback")]
    PointerVersionRollback,
    #[error("key_backup_active_series_pointer_version_gap")]
    PointerVersionGap,
    #[error("key_backup_active_series_pointer_version_fork")]
    PointerVersionFork,
}

pub fn validate_key_backup_active_series_transition(
    current: Option<&KeyBackupActiveSeriesHead>,
    record: &KeyBackupActiveSeries,
) -> std::result::Result<KeyBackupActiveSeriesHead, KeyBackupActiveSeriesTransitionError> {
    const REQUIRED_SIGNED_FIELDS: &[&str] = &[
        "schema",
        "actor_id",
        "backup_kind",
        "active_series_id",
        "series_pointer_version",
        "previous_series_ids",
        "frontier_ref",
        "issued_at",
    ];
    if record.schema != "ak.schema.key_backup_active_series.v1"
        || record
            .extra
            .keys()
            .any(|key| !valid_active_series_extension_key(key))
    {
        return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
    }
    let signed_fields = record
        .auth_data
        .signed_fields
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if signed_fields.len() != record.auth_data.signed_fields.len() {
        return Err(KeyBackupActiveSeriesTransitionError::SignedFieldsDuplicate);
    }
    if REQUIRED_SIGNED_FIELDS.iter().any(|required| {
        !signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == *required)
    }) {
        return Err(KeyBackupActiveSeriesTransitionError::SignedFieldsIncomplete);
    }
    if record
        .previous_series_ids
        .iter()
        .any(|series_id| series_id == &record.active_series_id)
    {
        return Err(KeyBackupActiveSeriesTransitionError::ActiveInPrevious);
    }
    let previous = record
        .previous_series_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if previous.len() != record.previous_series_ids.len() {
        return Err(KeyBackupActiveSeriesTransitionError::PreviousSeriesDuplicate);
    }
    let generation_matches = matches!(
        (&record.auth_data.trust_binding, &record.frontier_ref.generation),
        (
            KeyBackupActiveSeriesTrustBinding::SskGeneration(auth),
            KeyBackupActiveSeriesFrontierGeneration::SskGeneration(frontier)
        ) if auth == frontier
    ) || matches!(
        (
            &record.auth_data.trust_binding,
            &record.frontier_ref.generation
        ),
        (
            KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(_),
            KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(_)
        )
    );
    if !generation_matches {
        return Err(KeyBackupActiveSeriesTransitionError::GenerationBindingMismatch);
    }
    let next = key_backup_active_series_head(record)?;
    let Some(current) = current else {
        return if record.series_pointer_version == 1 {
            Ok(next)
        } else {
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap)
        };
    };
    if current.actor_id != record.actor_id || current.backup_kind != record.backup_kind {
        return Err(KeyBackupActiveSeriesTransitionError::ActorOrClassMismatch);
    }
    if record.series_pointer_version == current.series_pointer_version {
        return if current.record_digest == next.record_digest {
            Ok(current.clone())
        } else {
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionFork)
        };
    }
    let expected = current.series_pointer_version.saturating_add(1);
    if record.series_pointer_version < expected {
        return Err(KeyBackupActiveSeriesTransitionError::PointerVersionRollback);
    }
    if record.series_pointer_version > expected {
        return Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap);
    }
    Ok(next)
}

pub fn key_backup_active_series_head(
    record: &KeyBackupActiveSeries,
) -> std::result::Result<KeyBackupActiveSeriesHead, KeyBackupActiveSeriesTransitionError> {
    let record_digest = canonical::canonical_sha256(record)
        .map_err(|_| KeyBackupActiveSeriesTransitionError::SchemaMismatch)?;
    Ok(KeyBackupActiveSeriesHead {
        actor_id: record.actor_id.clone(),
        backup_kind: record.backup_kind,
        active_series_id: record.active_series_id.clone(),
        series_pointer_version: record.series_pointer_version,
        previous_series_ids: record.previous_series_ids.clone(),
        record_digest,
    })
}

fn valid_active_series_extension_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("x_") else {
        return false;
    };
    if rest.is_empty() || rest.len() > 64 {
        return false;
    }
    let mut chars = rest.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|candidate| {
            candidate.is_ascii_lowercase() || candidate.is_ascii_digit() || candidate == '_'
        })
}

pub type KeyBackupActiveSeriesPayload = KeyBackupActiveSeries;

#[cfg(test)]
mod key_backup_active_series_tests {
    use serde_json::json;

    use super::*;

    fn record(version: u64) -> KeyBackupActiveSeries {
        serde_json::from_value(json!({
            "schema": "ak.schema.key_backup_active_series.v1",
            "actor_id": "did:web:alice.example",
            "backup_kind": "mls_history",
            "active_series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_pointer_version": version,
            "previous_series_ids": [],
            "frontier_ref": {
                "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "seal_ref": "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "ssk_generation": 2
            },
            "issued_at": "2026-07-18T00:00:00.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "signed_fields": [
                    "schema", "actor_id", "backup_kind", "active_series_id",
                    "series_pointer_version", "previous_series_ids", "frontier_ref", "issued_at"
                ],
                "ssk_generation": 2
            }
        }))
        .unwrap()
    }

    #[test]
    fn a_and_b_generation_models_round_trip_exclusively() {
        let a = record(1);
        assert!(matches!(
            a.auth_data.trust_binding,
            KeyBackupActiveSeriesTrustBinding::SskGeneration(_)
        ));
        let mut b = serde_json::to_value(&a).unwrap();
        b["auth_data"]
            .as_object_mut()
            .unwrap()
            .remove("ssk_generation");
        b["auth_data"]["device_authorize_event_id"] =
            json!("ak:event:01964137-0000-7000-8000-000000000009");
        b["frontier_ref"]
            .as_object_mut()
            .unwrap()
            .remove("ssk_generation");
        b["frontier_ref"]["device_generation_ref"] = json!("3-generation");
        let b_value = b.clone();
        let b_record: KeyBackupActiveSeries = serde_json::from_value(b).unwrap();
        assert_eq!(serde_json::to_value(b_record).unwrap(), b_value);

        let mut mixed = b_value;
        mixed["auth_data"]["ssk_generation"] = json!(2);
        assert!(serde_json::from_value::<KeyBackupActiveSeries>(mixed).is_err());
    }

    #[test]
    fn pointer_versions_are_contiguous_and_fail_closed() {
        let first = record(1);
        let head = validate_key_backup_active_series_transition(None, &first).unwrap();
        let second = record(2);
        let second_head =
            validate_key_backup_active_series_transition(Some(&head), &second).unwrap();
        assert_eq!(second_head.series_pointer_version, 2);
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &record(1)),
            Ok(head.clone())
        );
        let mut fork = record(1);
        fork.issued_at = "2026-07-18T00:00:01.000Z".parse().unwrap();
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &fork),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionFork)
        );
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &record(3)),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap)
        );
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&second_head), &record(1)),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionRollback)
        );
    }
}
