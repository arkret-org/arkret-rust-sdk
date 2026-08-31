//! Audit access, binding, session, and release event payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use arkret_wire::{
    AppletId, AuditBindingId, AuditReleaseId, AuditSessionId, CellRef, DidCoreId, DidUrl, EventId,
    Hash, NonEmptyJsonObject, NonEmptyString, ObjectRef, RealmId, ScopeRef, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::mls::MlsEpochRange;
use crate::governance::audit::AuditAssurance;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAccessedKind {
    WatchSetOthers,
    WatchAuditRead,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
    PolicyAuditRead,
    Other,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAccessedPayload {
    pub access_kind: AuditAccessedKind,
    pub writer_actor_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<DidCoreId>,
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cell_id: Option<CellRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_before: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_after: Option<Hash>,
    pub purpose: NonEmptyString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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

/// Closed state set for `ak.component.audit.binding_state.v1`.
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
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// audit_applet_binding_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingCreatePayload {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

/// Lifecycle-only counterpart for
/// `event-payload.schema.json#/$defs/audit_applet_binding_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingStatePayload {
    pub binding_id: AuditBindingId,
    pub from: AuditBindingStatus,
    pub to: AuditBindingStatus,
}

impl AuditAppletBindingStatePayload {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.from == AuditBindingStatus::Revoked || !self.from.allows_transition_to(self.to) {
            return Err("audit_binding_transition_invalid");
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    pub session_id: AuditSessionId,
    pub binding_id: AuditBindingId,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub release_mode: AuditReleaseMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    pub seal_ref: SealId,
    pub approver_actor_id: DidCoreId,
    pub notice_ref: EventId,
    pub purpose_kind: NonEmptyString,
    pub legal_basis_ref: NonEmptyString,
    pub policy_version_digest: Hash,
    pub eligibility_proof: AuditReleasePayloadEligibilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by_commit_ref: Option<EventId>,
    pub wrapped_material_digest: Vec<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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

/// Counterpart for the shared
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_contract`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSessionPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<AuditSessionId>,
    pub binding_id: AuditBindingId,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub session_state: AuditSessionStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_recipient_audit_actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_recipient_public_key_ref: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closer_actor_id: Option<DidCoreId>,
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl AuditSessionPayload {
    fn validate_collections(&self) -> Result<(), &'static str> {
        if self.target_refs.as_ref().is_some_and(Vec::is_empty) {
            return Err("audit session target_refs must be non-empty when present");
        }
        if self
            .target_refs
            .as_ref()
            .is_some_and(|values| values.iter().collect::<BTreeSet<_>>().len() != values.len())
        {
            return Err("audit session target_refs must be unique");
        }
        if self
            .release_refs
            .as_ref()
            .is_some_and(|values| values.iter().collect::<BTreeSet<_>>().len() != values.len())
        {
            return Err("audit session release_refs must be unique");
        }
        Ok(())
    }
}

macro_rules! audit_session_payload {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Debug, Serialize)]
        #[serde(transparent)]
        pub struct $name(AuditSessionPayload);

        impl $name {
            pub fn new(payload: AuditSessionPayload) -> std::result::Result<Self, &'static str> {
                payload.validate_collections()?;
                $validator(&payload)?;
                Ok(Self(payload))
            }

            pub fn into_inner(self) -> AuditSessionPayload {
                self.0
            }
        }

        impl Deref for $name {
            type Target = AuditSessionPayload;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(AuditSessionPayload::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

fn validate_audit_session_request(payload: &AuditSessionPayload) -> Result<(), &'static str> {
    if payload.session_state != AuditSessionStage::Request
        || payload.session_id.is_some()
        || payload.requested_by.is_none()
        || payload.purpose_kind.is_none()
        || payload.legal_basis_ref.is_none()
        || payload.requested_release_mode.is_none()
        || payload.request_digest.is_none()
        || (payload.requested_epoch_range.is_none() && payload.target_refs.is_none())
    {
        return Err("invalid audit session request payload shape");
    }
    Ok(())
}

fn validate_audit_session_authorize(payload: &AuditSessionPayload) -> Result<(), &'static str> {
    if payload.session_state != AuditSessionStage::Authorize
        || payload.session_id.is_none()
        || payload.request_ref.is_none()
        || payload.approver_actor_id.is_none()
        || payload.approved_recipient_audit_actor_id.is_none()
        || payload.approved_recipient_public_key_ref.is_none()
        || payload.approved_release_mode.is_none()
        || payload.notice_policy.is_none()
        || payload.expires_at.is_none()
        || (payload.approved_epoch_range.is_none() && payload.target_refs.is_none())
    {
        return Err("invalid audit session authorize payload shape");
    }
    Ok(())
}

fn validate_audit_session_notice(payload: &AuditSessionPayload) -> Result<(), &'static str> {
    if payload.session_state != AuditSessionStage::Notice
        || payload.session_id.is_none()
        || payload.authorize_ref.is_none()
        || payload.service_id.is_none()
        || payload.purpose_kind.is_none()
        || payload.approved_release_mode.is_none()
        || payload.approver_actor_id.is_none()
        || payload.member_notice_digest.is_none()
        || (payload.approved_epoch_range.is_none() && payload.target_refs.is_none())
    {
        return Err("invalid audit session notice payload shape");
    }
    Ok(())
}

fn validate_audit_session_close(payload: &AuditSessionPayload) -> Result<(), &'static str> {
    if payload.session_state != AuditSessionStage::Close
        || payload.session_id.is_none()
        || payload.closer_actor_id.is_none()
        || payload.close_reason.is_none()
        || payload.release_refs.is_none()
    {
        return Err("invalid audit session close payload shape");
    }
    Ok(())
}

audit_session_payload!(AuditSessionRequestPayload, validate_audit_session_request);
audit_session_payload!(
    AuditSessionAuthorizePayload,
    validate_audit_session_authorize
);
audit_session_payload!(AuditSessionNoticePayload, validate_audit_session_notice);
audit_session_payload!(AuditSessionClosePayload, validate_audit_session_close);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_access_kind_rejects_retired_join_application_review() {
        assert_eq!(
            serde_json::from_str::<AuditAccessedKind>(r#""policy_audit_read""#).unwrap(),
            AuditAccessedKind::PolicyAuditRead,
        );
        assert!(serde_json::from_str::<AuditAccessedKind>(r#""join_application_review""#).is_err());
    }

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
            "session_id": "ak:audit_session:AfJaI7rJa8SJLrm9TWhgM_CvGCjR771X43I1tyFxcETk",
            "binding_id": "ak:audit_binding:ASOyrOY2dZ3005mHWyCAFuDmQ-2p9Rp8X7dYxWTmMRAg",
            "realm_id": "ak:realm:Af5xbAMRUJoaDWcTzj2s9sJIxCGFCD2cO1gheRFGhJSi",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:Af5xbAMRUJoaDWcTzj2s9sJIxCGFCD2cO1gheRFGhJSi"
            },
            "session_state": "authorize",
            "request_ref": "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "approver_actor_id": "ak:did_core:webvh:z6mkfixture",
            "approved_recipient_audit_actor_id": "ak:did_core:webvh:z6mkfixture",
            "approved_recipient_public_key_ref": "did:webvh:z6mkfixture:auditor.example#audit-1",
            "approved_release_mode": "targeted_evidence_release",
            "target_refs": ["ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"],
            "notice_policy": {},
            "occurred_at": "2026-07-22T10:05:00.000Z",
            "expires_at": "2026-07-22T11:05:00.000Z"
        });
        let payload: AuditSessionAuthorizePayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);
    }
}
