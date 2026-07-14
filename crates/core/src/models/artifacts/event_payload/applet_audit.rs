//! Applet-registration, audit, and seal-frontier payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/seal_frontier`.
pub type SealFrontier = Vec<Hash>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeVisibilityScope {
    RealmAdmins,
    AppletController,
    RealmMembers,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_bridge_error_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletBridgeErrorPayload {
    pub applet_id: AppletIdentifier,
    pub realm_id: RealmId,
    pub failed_transaction_ref: ObjectRef,
    pub error_class: String,
    pub error_code: NonEmptyString,
    pub retriable: bool,
    pub visibility_scope: AppletBridgeVisibilityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_registration_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRegistrationPayload {
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub controller_id: Did,
    pub base_url: String,
    pub bot_actor_id: Did,
    pub protocols: Vec<String>,
    pub namespaces: BTreeMap<String, Value>,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    pub requested_scopes: Vec<String>,
    pub registration_epoch: Hash,
    pub webhook_auth: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
    pub proof: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
}

impl AppletRegistrationPayload {
    /// Build a `ak.applet.registration` payload with the full closed field set
    /// (`event-payload.schema.json#/$defs/applet_registration_payload`). The
    /// spec marks 14 fields required plus `created_at`; the collection / flag
    /// fields default to their empty / false forms (all schema-valid) and are
    /// set through the `with_*` chain. Downstream MUST stop sending the legacy
    /// `{service_id, namespace, capabilities}` short form — it fails the strong
    /// payload validator (missing required fields + `additionalProperties:false`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: AppletIdentifier,
        service_id: Did,
        controller_id: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        registration_epoch: Hash,
        webhook_auth: BTreeMap<String, Value>,
        proof: BTreeMap<String, Value>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            applet_id,
            service_id,
            controller_id,
            base_url: base_url.into(),
            bot_actor_id,
            protocols: Vec::new(),
            namespaces: BTreeMap::new(),
            receive_events: false,
            receive_ephemeral: false,
            rate_limited: false,
            requested_scopes: Vec::new(),
            registration_epoch,
            webhook_auth,
            manifest: None,
            proof,
            created_at,
        }
    }

    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols = protocols;
        self
    }

    pub fn with_namespaces(mut self, namespaces: BTreeMap<String, Value>) -> Self {
        self.namespaces = namespaces;
        self
    }

    pub fn with_requested_scopes(mut self, requested_scopes: Vec<String>) -> Self {
        self.requested_scopes = requested_scopes;
        self
    }

    pub fn with_receive_events(mut self, receive_events: bool) -> Self {
        self.receive_events = receive_events;
        self
    }

    pub fn with_receive_ephemeral(mut self, receive_ephemeral: bool) -> Self {
        self.receive_ephemeral = receive_ephemeral;
        self
    }

    pub fn with_rate_limited(mut self, rate_limited: bool) -> Self {
        self.rate_limited = rate_limited;
        self
    }

    pub fn with_manifest(mut self, manifest: BTreeMap<String, Value>) -> Self {
        self.manifest = Some(manifest);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        // Spec: an empty proof object MUST be rejected as schema_violation.
        if self.proof.is_empty() {
            return Err(Error::Protocol(
                "applet registration proof object must not be empty".to_owned(),
            ));
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("applet registration payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAccessedPayload {
    pub access_kind: String,
    pub writer_actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cell_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_before: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_after: Option<Hash>,
    pub purpose: String,
    pub accessed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ryw_required: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_applet_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayloadReleaseWindowPolicy {
    pub retroactive_release: String,
    pub eligibility_basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lookback_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epoch_span: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_target_classes: Option<Vec<String>>,
}

/// Closed state set for `ak.component.audit.binding.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayload {
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub status: AuditBindingStatus,
    pub purpose_classes: Vec<String>,
    pub allowed_release_modes: Vec<String>,
    pub audit_assurance_class: String,
    pub notice_policy: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_policy: Option<BTreeMap<String, Value>>,
    pub activation_frontier_digest: Hash,
    pub first_auditable_epoch: u64,
    pub release_window_policy: AuditAppletBindingPayloadReleaseWindowPolicy,
    pub policy_version_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
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
    pub accessed_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_release_payload/properties/eligibility_proof`.
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleasePayload {
    pub release_id: String,
    pub session_id: String,
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub release_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<EventRef>,
    pub seal_digest: Hash,
    pub recipient_audit_actor_id: Did,
    pub recipient_public_key_ref: Did,
    pub approver_actor_id: Did,
    pub notice_ref: EventRef,
    pub purpose_class: String,
    pub legal_basis_ref: String,
    pub policy_version_digest: Hash,
    pub eligibility_proof: AuditReleasePayloadEligibilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by_commit_ref: Option<EventRef>,
    pub wrapped_material_digest: Vec<Hash>,
    pub released_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_authorize_payload`.
pub type AuditSessionAuthorizePayload = AuditSessionPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_close_payload`.
pub type AuditSessionClosePayload = AuditSessionPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_notice_payload`.
pub type AuditSessionNoticePayload = AuditSessionPayload;

/// Closed state set for `ak.component.audit.session.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub session_id: String,
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub stage: AuditSessionStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletIdentifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closer_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_release_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_release_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_policy: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_notice_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<Hash>,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_request_payload`.
pub type AuditSessionRequestPayload = AuditSessionPayload;

#[cfg(test)]
mod applet_builder_tests {
    use serde_json::json;

    use super::*;
    use crate::schema::event_payload_validator_catalog_from_embedded_spec_artifacts;

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn applet_id() -> AppletIdentifier {
        AppletIdentifier::Did(did("did:webvh:z6mkfixture:applet.example"))
    }

    #[test]
    fn applet_registration_builder_validates_against_catalog() {
        let webhook_auth: BTreeMap<String, Value> = [(
            "key_ref".to_owned(),
            json!("did:webvh:z6mkfixture:applet.example#svc"),
        )]
        .into_iter()
        .collect();
        let proof: BTreeMap<String, Value> = [("signature".to_owned(), json!("c2ln"))]
            .into_iter()
            .collect();
        let payload = AppletRegistrationPayload::new(
            applet_id(),
            did("did:webvh:z6mkfixture:svc.example"),
            did("did:webvh:z6mkfixture:controller.example"),
            "https://applet.example",
            did("did:webvh:z6mkfixture:bot.example"),
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            webhook_auth,
            proof,
            "2026-07-08T10:05:00Z".parse().unwrap(),
        )
        .with_protocols(vec!["a2a".to_owned()])
        .with_requested_scopes(vec!["ak.message.create".to_owned()])
        .with_receive_events(true);
        let value = payload.to_value().unwrap();
        assert_eq!(
            value["service_id"],
            json!("did:webvh:z6mkfixture:svc.example")
        );
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload("ak.applet.registration", &value)
            .unwrap();
    }

    #[test]
    fn applet_registration_builder_rejects_empty_proof() {
        let payload = AppletRegistrationPayload::new(
            applet_id(),
            did("did:webvh:z6mkfixture:svc.example"),
            did("did:webvh:z6mkfixture:controller.example"),
            "https://applet.example",
            did("did:webvh:z6mkfixture:bot.example"),
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            BTreeMap::new(),
            BTreeMap::new(),
            "2026-07-08T10:05:00Z".parse().unwrap(),
        );
        assert!(payload.to_value().is_err());
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
}
