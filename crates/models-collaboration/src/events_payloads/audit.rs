//! Audit access, binding, session, and release event payloads.

use std::collections::BTreeMap;

use arkret_wire::{
    AppletIdentifier, AuditBindingId, AuditReleaseId, AuditSessionId, CellRef, Did, DidUrl,
    EffectiveScope, EventId, Hash, NonEmptyJsonObject, NonEmptyString, RealmId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::event_wire::NullableTimestamp;
use super::mls::MlsEpochRange;
use crate::ObjectRef;
use crate::governance::audit::AuditAssurance;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAccessedKind {
    WatchSetOthers,
    WatchAuditRead,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
    CrossSigningReset,
    JoinApplicationReview,
    PolicyAuditRead,
    Other,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAccessedPayload {
    pub access_kind: AuditAccessedKind,
    pub writer_actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cell_id: Option<CellRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_before: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_after: Option<Hash>,
    pub purpose: NonEmptyString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub accessed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ryw_required: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReleaseMode {
    TargetedEvidenceRelease,
    SealedEpochKeyRelease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetroactiveReleasePolicy {
    Forbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEligibilityBasis {
    EncryptedAfterBindingActivation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayloadReleaseWindowPolicy {
    pub retroactive_release: AuditRetroactiveReleasePolicy,
    pub eligibility_basis: AuditEligibilityBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lookback_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epoch_span: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_target_kinds: Option<Vec<NonEmptyString>>,
}

/// Closed state set for `ak.component.audit.binding.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBindingStatus {
    Active,
    Suspended,
    Revoked,
}

impl AuditBindingStatus {
    pub fn allows_transition_to(self, target: Self) -> bool {
        self == target
            || matches!(
                (self, target),
                (Self::Active, Self::Suspended | Self::Revoked)
                    | (Self::Suspended, Self::Active | Self::Revoked)
            )
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_applet_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayload {
    pub binding_id: AuditBindingId,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub status: AuditBindingStatus,
    pub purpose_kinds: Vec<NonEmptyString>,
    pub allowed_release_modes: Vec<AuditReleaseMode>,
    pub audit_assurance_class: AuditAssurance,
    pub notice_policy: NonEmptyJsonObject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_policy: Option<BTreeMap<String, Value>>,
    pub activation_frontier_digest: Hash,
    pub first_auditable_epoch: u64,
    pub release_window_policy: AuditAppletBindingPayloadReleaseWindowPolicy,
    pub policy_version_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub accessed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleasePayloadEligibilityProof {
    pub binding_activation_frontier_digest: Hash,
    pub first_auditable_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_commit_ref: Option<EventId>,
    pub policy_snapshot_digest: Hash,
    pub target_eligibility_digest: Hash,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_release_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleasePayload {
    pub release_id: AuditReleaseId,
    pub session_id: AuditSessionId,
    pub binding_id: AuditBindingId,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub release_mode: AuditReleaseMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<EventId>,
    pub seal_digest: Hash,
    pub recipient_audit_actor_id: Did,
    pub recipient_public_key_ref: DidUrl,
    pub approver_actor_id: Did,
    pub notice_ref: EventId,
    pub purpose_kind: NonEmptyString,
    pub legal_basis_ref: NonEmptyString,
    pub policy_version_digest: Hash,
    pub eligibility_proof: AuditReleasePayloadEligibilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by_commit_ref: Option<EventId>,
    pub wrapped_material_digest: Vec<Hash>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub released_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSessionStage {
    Request,
    Authorize,
    Notice,
    Close,
}

impl AuditSessionStage {
    pub fn allows_transition_to(self, target: Self) -> bool {
        self == target
            || matches!(
                (self, target),
                (Self::Request, Self::Authorize | Self::Close)
                    | (Self::Authorize, Self::Notice | Self::Close)
                    | (Self::Notice, Self::Close)
            )
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSessionPayload {
    pub session_id: AuditSessionId,
    pub binding_id: AuditBindingId,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub session_state: AuditSessionStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletIdentifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_recipient_audit_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_recipient_public_key_ref: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closer_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_kind: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_release_mode: Option<AuditReleaseMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_release_mode: Option<AuditReleaseMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_policy: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_notice_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_refs: Option<Vec<AuditReleaseId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<Hash>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

pub type AuditSessionAuthorizePayload = AuditSessionPayload;
pub type AuditSessionClosePayload = AuditSessionPayload;
pub type AuditSessionNoticePayload = AuditSessionPayload;
pub type AuditSessionRequestPayload = AuditSessionPayload;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_control_plane_state_transitions_are_closed() {
        assert!(AuditBindingStatus::Active.allows_transition_to(AuditBindingStatus::Suspended));
        assert!(AuditBindingStatus::Suspended.allows_transition_to(AuditBindingStatus::Revoked));
        assert!(!AuditBindingStatus::Revoked.allows_transition_to(AuditBindingStatus::Active));

        assert!(AuditSessionStage::Request.allows_transition_to(AuditSessionStage::Authorize));
        assert!(AuditSessionStage::Authorize.allows_transition_to(AuditSessionStage::Notice));
        assert!(AuditSessionStage::Notice.allows_transition_to(AuditSessionStage::Close));
        assert!(!AuditSessionStage::Close.allows_transition_to(AuditSessionStage::Notice));
    }

    #[test]
    fn audit_session_authorize_fields_are_preserved() {
        let value = serde_json::json!({
            "session_id": "ak:audit_session:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d",
            "binding_id": "ak:audit_binding:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5e",
            "realm_id": "ak:realm:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5f",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5f"
            },
            "session_state": "authorize",
            "approved_recipient_audit_actor_id": "did:webvh:z6mkfixture:auditor.example",
            "approved_recipient_public_key_ref": "did:webvh:z6mkfixture:auditor.example#audit-1",
            "occurred_at": "2026-07-22T10:05:00.000Z"
        });
        let payload: AuditSessionPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);
    }
}
