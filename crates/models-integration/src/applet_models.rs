//! Applet install / edge operation body DTOs.
//!
//! The install preview / install request bodies embed the applet package
//! (`AppletPackage`, this crate's `applet::registration`), so they live here.
//! Applet transaction and revoke carriers live here with the rest of the
//! Applet-owned edge contract.

use std::collections::BTreeMap;

use arkret_models_identity::account::AccountLifecycleProof;
use arkret_models_identity::authenticated_signer_resolution_evidence::{
    AuthenticatedSignerKind, AuthenticatedSignerResolutionEvidence,
};
use arkret_wire::{
    ActorId, AppletId, AppletRevokeMode, BlobRef, CommitStreamHead, CommittedEventRef,
    CurrentRevision, Did, DidCoreId, DidUrl, Event, EventCommitSubmission, EventId, GrantId, Hash,
    PayloadSigner, ProtocolOperationId, RealmId, ReasonCode, Result, ScopeRef, SignalEnvelope,
    SignerEvidenceRef, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::GhostActorProvisionRequestBody;
use crate::applet::{AppletPackage, AppletRegistrationEpochEvidence, GhostExternalTuple};
use crate::artifacts_applet::{
    AppletEventRejection, E2eePolicy, ExternalRef, FieldDefinition, ProtocolInstance,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletPingOutcome {
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    #[serde(deserialize_with = "arkret_wire::deserialize_protocol_version")]
    pub protocol_version: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletTransactionStatus {
    Accepted,
    Partial,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletTransactionOutcome {
    pub status: AppletTransactionStatus,
    /// Exact authority commits accepted from this transaction. Each reference
    /// retains its Realm, Circle, or Sidecar stream coordinate.
    pub committed_event_refs: Vec<CommittedEventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<AppletEventRejection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Current Applet edge transaction. Durable Events are producer-authored
/// Events; the receiving governance Station decides and signs finality.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletTransactionRequestBody {
    Events(AppletEventTransactionRequestBody),
    Authoring(Box<AppletAuthoringTransactionRequestBody>),
}

impl AppletTransactionRequestBody {
    pub fn applet_id(&self) -> &AppletId {
        match self {
            Self::Events(body) => &body.applet_id,
            Self::Authoring(body) => &body.applet_id,
        }
    }

    pub fn source_id(&self) -> &DidCoreId {
        match self {
            Self::Events(body) => &body.source_id,
            Self::Authoring(body) => &body.source_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Events(body) => body.validate(),
            Self::Authoring(body) => body.authoring_context.validate(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletEventTransactionRequestBody {
    pub applet_id: AppletId,
    pub source_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<SignalEnvelope>,
}

impl AppletEventTransactionRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.events.is_empty() && self.signals.is_empty() {
            return Err(WireError::Protocol(
                "applet transaction requires at least one Event or Signal".into(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthoringTransactionRequestBody {
    pub applet_id: AppletId,
    pub source_id: DidCoreId,
    pub authoring_context: AppletManagedActorAuthoringContext,
}

/// Complete content-addressed Service signer root selected by the accepted
/// registration epoch.
///
/// The Service branch is a leaf: it carries no recursive dependency array,
/// because a Service key is resolved against its own registration epoch and
/// has nothing further to close over.
// Field declaration order is byte-for-byte the `properties` order of
// `applet-edge-operations.schema.json#/$defs/applet_service_signer_evidence`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletServiceSignerEvidence {
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
    pub authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
}

impl AppletServiceSignerEvidence {
    pub fn validate(&self) -> Result<()> {
        validate_signer_root(
            &self.authenticated_signer_evidence,
            &self.signer_resolution_evidence_ref,
            AuthenticatedSignerKind::Service,
            "Applet Service signer root",
        )
    }
}

/// Complete content-addressed Principal signer root for the accepted managed
/// Actor resolution, plus its one exact Station Service attester leaf.
///
/// Signer-resolution evidence carries no attester ref of its own, so the leaf
/// is bound positionally here and by equality of `authority_commit_id` with
/// `authenticated_signer_evidence`. Omitted, surplus or mismatched closure is
/// invalid — an attester resolved at a different commit attests a different
/// state than the one this context froze.
// Field declaration order is byte-for-byte the `properties` order of
// `applet-edge-operations.schema.json#/$defs/managed_actor_principal_signer_evidence`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedActorPrincipalSignerEvidence {
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
    pub authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
    pub attester_signer_evidence: AuthenticatedSignerResolutionEvidence,
}

impl ManagedActorPrincipalSignerEvidence {
    pub fn validate(&self) -> Result<()> {
        validate_signer_root(
            &self.authenticated_signer_evidence,
            &self.signer_resolution_evidence_ref,
            AuthenticatedSignerKind::Principal,
            "managed Actor Principal signer root",
        )?;
        self.attester_signer_evidence.validate()?;
        if self.attester_signer_evidence.signer_kind != AuthenticatedSignerKind::Service {
            return Err(WireError::Protocol(
                "managed Actor attester leaf must be the Station Service that signed the resolution"
                    .to_owned(),
            ));
        }
        if self.attester_signer_evidence.authority_commit_id
            != self.authenticated_signer_evidence.authority_commit_id
        {
            return Err(WireError::Protocol(
                "managed Actor attester leaf was resolved at a different authority commit"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_signer_root(
    evidence: &AuthenticatedSignerResolutionEvidence,
    reported_ref: &SignerEvidenceRef,
    expected_kind: AuthenticatedSignerKind,
    role: &str,
) -> Result<()> {
    evidence.validate()?;
    if evidence.signer_kind != expected_kind {
        return Err(WireError::Protocol(format!(
            "{role} carries the wrong signer_kind"
        )));
    }
    if !evidence.matches_ref(reported_ref)? {
        return Err(WireError::Protocol(format!(
            "{role} ref is not the content address of the evidence beside it"
        )));
    }
    Ok(())
}

/// Current authority context for an Applet-managed Actor.
///
/// All four members are required: an accepted authoring result is conditional
/// on both signer roots having been verified and frozen inside the one
/// recoverable atomic commit, so a context without them could never have been
/// accepted in the first place. Authorization is checked again when the
/// governance Station commits the authored Event.
// Field declaration order is byte-for-byte the `properties` order of
// `applet-edge-operations.schema.json#/$defs/applet_managed_actor_authoring_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringContext {
    pub committed_request: AppletManagedActorCommittedRequest,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub realm_stream_head: CommitStreamHead,
    pub applet_service_signer_evidence: AppletServiceSignerEvidence,
    pub managed_actor_signer_evidence: ManagedActorPrincipalSignerEvidence,
}

impl AppletManagedActorAuthoringContext {
    pub fn validate(&self) -> Result<()> {
        self.applet_service_signer_evidence.validate()?;
        self.managed_actor_signer_evidence.validate()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletManagedActorCommittedRequest {
    Install(Box<AppletInstallRequestBody>),
    Ghost(Box<GhostActorProvisionRequestBody>),
}

/// Request that atomically fences an Applet installation and submits the
/// producer-authored effects to their governance Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeRequestBody {
    pub revoke_plan_digest: Hash,
    pub effective_scope: ScopeRef,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub capability_revoke_events: Vec<EventCommitSubmission>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub membership_state_events: Vec<EventCommitSubmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof: Option<AccountLifecycleProof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletApprovalRequest {
    pub approve_actions: Vec<String>,
    pub ghost_actor_mode: AppletGhostActorMode,
    pub delegated_native_actors_allowed: bool,
    pub e2ee_join_allowed: bool,
    pub widget_allowed: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletGhostActorMode {
    Disallowed,
    ControllerApproved,
    PolicyDeclared,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletActorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghost_actor_mode: Option<AppletGhostActorMode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletScopeRejection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<String>,
    pub reason_code: ReasonCode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletInstallEffectiveStatus {
    Installed,
    PartiallyInstalled,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallOutcome {
    pub install_id: String,
    pub applet_id: AppletId,
    pub registration_event_ref: CommittedEventRef,
    pub registration_epoch: Hash,
    pub bot_actor_id: ActorId,
    pub bot_actor_provision_ref: CommittedEventRef,
    pub bot_principal_control_realm_id: RealmId,
    pub capability_grant_refs: Vec<GrantId>,
    pub e2ee_authorization_refs: Vec<CommittedEventRef>,
    pub widget_policy_ref: Option<CommittedEventRef>,
    pub effective_status: AppletInstallEffectiveStatus,
    pub rejections: Vec<AppletScopeRejection>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePreviewRequestBody {
    pub effective_scope: ScopeRef,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletCapabilityRevokeIntent {
    pub event_kind: String,
    pub grant_id: GrantId,
    /// Exact revision of the same active Grant selected by the governing
    /// Station's preview snapshot. This value is covered by the canonical
    /// revoke-plan digest and copied unchanged into the signed revoke Event.
    pub expected_revision: CurrentRevision,
    pub registration_epoch: Hash,
    pub reason_code: ReasonCode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletMembershipRemoveIntent {
    pub event_kind: String,
    pub member_id: ActorId,
    pub membership: AppletManagedMembershipRemoval,
    pub reason_code: ReasonCode,
}

#[cfg(test)]
mod membership_remove_identity_tests {
    use arkret_wire::AccountId;
    use serde_json::json;

    use super::*;

    #[test]
    fn applet_membership_removal_preserves_full_actor_schema() {
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec schema registry");
        let schema = format!(
            "{}#/$defs/applet_membership_remove_intent",
            arkret_wire::SchemaId::APPLET_INSTALL_OPERATIONS_V1
        );
        let principal = DidCoreId::new("ak:did_core:web:member.example").unwrap();
        let mut identities = std::collections::BTreeSet::new();
        for actor in [
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            )),
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
            )),
            ActorId::service(principal.clone()),
        ] {
            let wire = json!({"event_kind": "ak.member.state", "member_id": actor, "membership": "remove", "reason_code": "applet_revoked"});
            registry.validate_value(&schema, &wire).unwrap();
            let decoded: AppletMembershipRemoveIntent =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(decoded.member_id, actor);
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
            assert!(identities.insert(actor));
        }
        assert_eq!(identities.len(), 3);
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletManagedMembershipRemoval {
    Leave,
    Remove,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePlan {
    pub applet_id: AppletId,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
    pub capability_revocations: Vec<AppletCapabilityRevokeIntent>,
    pub membership_removals: Vec<AppletMembershipRemoveIntent>,
    pub widget_token_refs: Vec<String>,
    pub delegated_session_refs: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePreviewOutcome {
    pub revoke_plan_digest: Hash,
    pub revoke_plan: AppletRevokePlan,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeSagaStatus {
    Complete,
    InProgress,
    PartiallyCompleted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeEventEffectKind {
    CapabilityRevokeEvent,
    MembershipStateEvent,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeLocalEffectKind {
    WidgetTokenInvalidation,
    DelegatedSessionRevocation,
    LocalAppletFence,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeSubmittedEventStatus {
    Pending,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeCommittedEventStatus {
    Accepted,
    Duplicate,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeLocalEffectStatus {
    Pending,
    Accepted,
    Duplicate,
    Rejected,
}

/// Service-local revoke effect identity. Event and RealmCommit identifiers
/// are rejected because only Event admission can produce the corresponding
/// committed effect coordinate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppletRevokeLocalEffectRef(String);

impl AppletRevokeLocalEffectRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(rest) = value.strip_prefix("ak:") else {
            return Err(WireError::Protocol(
                "Applet revoke local effect ref must start with ak:".to_owned(),
            ));
        };
        let Some((kind, payload)) = rest.split_once(':') else {
            return Err(WireError::Protocol(
                "Applet revoke local effect ref must contain a typed payload".to_owned(),
            ));
        };
        let valid_kind = !kind.is_empty()
            && kind != "event"
            && kind != "realm_commit"
            && kind.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
            });
        let valid_payload = !payload.is_empty()
            && payload.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'~' | b':' | b'/' | b'-')
            });
        if !valid_kind || !valid_payload {
            return Err(WireError::Protocol(
                "Applet revoke local effect ref must be a non-Event typed resource".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for AppletRevokeLocalEffectRef {
    type Error = WireError;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<AppletRevokeLocalEffectRef> for String {
    fn from(value: AppletRevokeLocalEffectRef) -> Self {
        value.0
    }
}

/// Durable effect reference returned by an Applet revoke saga.
///
/// Authority-accepted Event effects carry their exact commit coordinate;
/// local resource invalidations retain their protocol-typed resource string.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletRevokeEffectRef {
    CommittedEvent(CommittedEventRef),
    TypedResource(AppletRevokeLocalEffectRef),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeSubmittedEventStep {
    pub effect_kind: AppletRevokeEventEffectKind,
    pub submitted_event_id: EventId,
    pub status: AppletRevokeSubmittedEventStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeCommittedEventStep {
    pub effect_kind: AppletRevokeEventEffectKind,
    pub committed_event_ref: CommittedEventRef,
    pub status: AppletRevokeCommittedEventStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeLocalEffectStep {
    pub effect_kind: AppletRevokeLocalEffectKind,
    pub effect_ref: AppletRevokeLocalEffectRef,
    pub status: AppletRevokeLocalEffectStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletRevokeStep {
    SubmittedEvent(AppletRevokeSubmittedEventStep),
    CommittedEvent(AppletRevokeCommittedEventStep),
    LocalEffect(AppletRevokeLocalEffectStep),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeOutcome {
    pub operation_id: ProtocolOperationId,
    pub revoke_plan_digest: Hash,
    pub status: AppletRevokeSagaStatus,
    pub steps: Vec<AppletRevokeStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_refs: Vec<AppletRevokeEffectRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<AppletScopeRejection>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletActorView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg(test)]
mod actor_view_tests {
    use arkret_wire::{AccountId, SchemaId};
    use serde_json::json;

    use super::*;

    #[test]
    fn applet_actor_view_preserves_exact_actor_identity() {
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec schema registry");
        let schema = format!(
            "{}#/$defs/applet_actor_view",
            SchemaId::APPLET_EDGE_OPERATIONS_V1
        );
        let principal = DidCoreId::new("ak:did_core:web:bot.example").unwrap();
        let mut identities = std::collections::BTreeSet::new();
        for actor in [
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            )),
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
            )),
            ActorId::service(principal.clone()),
        ] {
            let value = json!({"exists": true, "actor_id": actor});
            registry.validate_value(&schema, &value).unwrap();
            let decoded: AppletActorView = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(decoded.actor_id.as_ref(), Some(&actor));
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            assert!(identities.insert(actor));
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRealmView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletProtocolMetadata {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob_ref: Option<BlobRef>,
    pub field_definitions: BTreeMap<String, FieldDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<ProtocolInstance>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request_basis: AppletInstallAuthoringRequestBasis,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletManagedActorPurpose {
    InstallBot,
    ProvisionGhost,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthoringRequestBasis {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub target_station_id: DidCoreId,
    pub install_actor_id: ActorId,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub package_digest: Hash,
    pub effective_scope: ScopeRef,
    pub approval_request: AppletApprovalRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_policy: Option<AppletActorPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_policy: Option<E2eePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy: Option<AppletWidgetPolicy>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_event: Event,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub capability_grant_events: Vec<Event>,
}

impl AppletInstallAuthoringRequestBasis {
    pub const SCHEMA: &'static str = "ak.schema.applet_install_authoring_request_basis.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.purpose != AppletManagedActorPurpose::InstallBot
            || self.capability_grant_events.is_empty()
        {
            return Err(WireError::Protocol(
                "applet install authoring request basis is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppletInstallAuthoringRequestBasisWire {
    schema: String,
    purpose: AppletManagedActorPurpose,
    target_station_id: DidCoreId,
    install_actor_id: ActorId,
    applet_id: AppletId,
    service_id: DidCoreId,
    package_digest: Hash,
    effective_scope: ScopeRef,
    approval_request: AppletApprovalRequest,
    actor_policy: Option<AppletActorPolicy>,
    e2ee_policy: Option<E2eePolicy>,
    widget_policy: Option<AppletWidgetPolicy>,
    registration_event: Event,
    capability_grant_events: Vec<Event>,
}

impl<'de> Deserialize<'de> for AppletInstallAuthoringRequestBasis {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AppletInstallAuthoringRequestBasisWire::deserialize(deserializer)?;
        let evidence = wire
            .registration_event
            .payload
            .get("manifest")
            .and_then(serde_json::Value::as_object)
            .and_then(|manifest| manifest.get("registration_epoch_evidence"))
            .cloned()
            .ok_or_else(|| {
                serde::de::Error::missing_field(
                    "registration_event.payload.manifest.registration_epoch_evidence",
                )
            })?;
        serde_json::from_value::<AppletRegistrationEpochEvidence>(evidence)
            .map_err(serde::de::Error::custom)?;
        if wire.capability_grant_events.is_empty() {
            return Err(serde::de::Error::custom(
                "capability_grant_events must not be empty",
            ));
        }
        let basis = Self {
            schema: wire.schema,
            purpose: wire.purpose,
            target_station_id: wire.target_station_id,
            install_actor_id: wire.install_actor_id,
            applet_id: wire.applet_id,
            service_id: wire.service_id,
            package_digest: wire.package_digest,
            effective_scope: wire.effective_scope,
            approval_request: wire.approval_request,
            actor_policy: wire.actor_policy,
            e2ee_policy: wire.e2ee_policy,
            widget_policy: wire.widget_policy,
            registration_event: wire.registration_event,
            capability_grant_events: wire.capability_grant_events,
        };
        basis.validate().map_err(serde::de::Error::custom)?;
        Ok(basis)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletGhostAuthoringRequestBasis {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub target_station_id: DidCoreId,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub registration_event_ref: CommittedEventRef,
    pub authorization_ref: GrantId,
    pub registration_epoch_evidence: AppletRegistrationEpochEvidence,
    pub package_digest: Hash,
}

impl AppletGhostAuthoringRequestBasis {
    pub const SCHEMA: &'static str = "ak.schema.applet_ghost_authoring_request_basis.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA || self.purpose != AppletManagedActorPurpose::ProvisionGhost
        {
            return Err(WireError::Protocol(
                "applet Ghost authoring request basis is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletManagedActorAuthoringBasis {
    InstallBot(Box<AppletInstallAuthoringRequestBasis>),
    ProvisionGhost(Box<AppletGhostAuthoringRequestBasis>),
}

impl AppletManagedActorAuthoringBasis {
    pub fn purpose(&self) -> AppletManagedActorPurpose {
        match self {
            Self::InstallBot(_) => AppletManagedActorPurpose::InstallBot,
            Self::ProvisionGhost(_) => AppletManagedActorPurpose::ProvisionGhost,
        }
    }

    pub fn target_station_id(&self) -> &DidCoreId {
        match self {
            Self::InstallBot(basis) => &basis.target_station_id,
            Self::ProvisionGhost(basis) => &basis.target_station_id,
        }
    }

    pub fn service_id(&self) -> &DidCoreId {
        match self {
            Self::InstallBot(basis) => &basis.service_id,
            Self::ProvisionGhost(basis) => &basis.service_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InstallBot(basis) => basis.validate(),
            Self::ProvisionGhost(basis) => basis.validate(),
        }
    }

    pub fn install(&self) -> Option<&AppletInstallAuthoringRequestBasis> {
        match self {
            Self::InstallBot(basis) => Some(basis),
            Self::ProvisionGhost(_) => None,
        }
    }

    pub fn ghost(&self) -> Option<&AppletGhostAuthoringRequestBasis> {
        match self {
            Self::InstallBot(_) => None,
            Self::ProvisionGhost(basis) => Some(basis),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub audience_id: DidCoreId,
    pub jws: String,
}

/// Core id of the DID that controls `method`.
///
/// An authoring request names its governance Station by core id alone, so the
/// only thing tying the proof to that Station on the wire is the controller of
/// the verification method. A consumer recomputes it here rather than trusting
/// a second copy of the identity travelling beside it.
fn verification_method_controller(method: &DidUrl) -> Result<DidCoreId> {
    let controller = method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            WireError::Protocol(
                "Applet authoring request verification_method has no fragment".to_owned(),
            )
        })?;
    arkret_wire::project_did_to_core_id(&Did::new(controller.to_owned())?).map_err(Into::into)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringRequest {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub basis: AppletManagedActorAuthoringBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<Hash>,
    /// Current governance Station service identity for the target Realm.
    ///
    /// The Station signs the resulting RealmCommit after revalidating this
    /// request at the stream head, so the request binds the identity and
    /// nothing else: a frozen generation or signer set here would be a second,
    /// staler answer to a question the commit re-asks.
    pub governance_station_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AppletManagedActorProof,
}

impl AppletManagedActorAuthoringRequest {
    pub const SCHEMA: &'static str = "ak.schema.applet_managed_actor_authoring_request.v1";
    pub const PROOF_CONTEXT: &'static str = "ak.applet_managed_actor_authoring_request_proof.v1";

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "purpose": self.purpose,
            "basis": self.basis,
            "plan_digest": self.plan_digest,
            "governance_station_id": self.governance_station_id,
            "issued_at": arkret_canonical::format_timestamp_canonical(self.issued_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(self.expires_at),
        })
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload_value())?).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": Self::PROOF_CONTEXT,
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "audience_id": self.proof.audience_id,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(&self) -> Result<()> {
        self.basis.validate()?;
        if self.schema != Self::SCHEMA
            || self.purpose != self.basis.purpose()
            || (self.purpose == AppletManagedActorPurpose::InstallBot) != self.plan_digest.is_some()
            || self.proof.payload_digest != self.payload_digest()?
            || &self.proof.audience_id != self.basis.service_id()
            || verification_method_controller(&self.proof.verification_method)?
                != self.governance_station_id
            || self.governance_station_id != *self.basis.target_station_id()
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(5)
            || self.proof.created_at >= self.expires_at
            || self.proof.created_at != self.issued_at
            || !arkret_wire::is_compact_detached_jws(&self.proof.jws)
        {
            return Err(WireError::Protocol(
                "applet managed actor authoring request binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn sign<S: PayloadSigner + ?Sized>(
        basis: AppletInstallAuthoringRequestBasis,
        plan_digest: Hash,
        governance_station_id: DidCoreId,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        signer: &S,
    ) -> Result<Self> {
        basis.validate()?;
        if governance_station_id != basis.target_station_id
            || verification_method_controller(signer.verification_method_id())?
                != governance_station_id
            || arkret_wire::project_did_to_core_id(signer.signer_did())? != governance_station_id
        {
            return Err(WireError::Protocol(
                "governance Station does not match the install authoring signer".to_owned(),
            ));
        }
        let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = arkret_canonical::canonical::normalize_timestamp_canonical(expires_at);
        let audience = basis.service_id.clone();
        let mut request = Self {
            schema: Self::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::InstallBot,
            basis: AppletManagedActorAuthoringBasis::InstallBot(Box::new(basis)),
            plan_digest: Some(plan_digest),
            governance_station_id,
            issued_at,
            expires_at,
            proof: AppletManagedActorProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: signer.verification_method_id().clone(),
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
                created_at: issued_at,
                audience_id: audience,
                jws: String::new(),
            },
        };
        request.proof.payload_digest = request.payload_digest()?;
        request.proof.jws = signer.sign_payload(&request.proof_binding_bytes()?)?.jws;
        request.validate_bindings()?;
        Ok(request)
    }

    pub fn sign_ghost<S: PayloadSigner + ?Sized>(
        basis: AppletGhostAuthoringRequestBasis,
        governance_station_id: DidCoreId,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        signer: &S,
    ) -> Result<Self> {
        basis.validate()?;
        if governance_station_id != basis.target_station_id
            || verification_method_controller(signer.verification_method_id())?
                != governance_station_id
            || arkret_wire::project_did_to_core_id(signer.signer_did())? != governance_station_id
        {
            return Err(WireError::Protocol(
                "governance Station does not match the Ghost authoring signer".to_owned(),
            ));
        }
        let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = arkret_canonical::canonical::normalize_timestamp_canonical(expires_at);
        let audience = basis.service_id.clone();
        let mut request = Self {
            schema: Self::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::ProvisionGhost,
            basis: AppletManagedActorAuthoringBasis::ProvisionGhost(Box::new(basis)),
            plan_digest: None,
            governance_station_id,
            issued_at,
            expires_at,
            proof: AppletManagedActorProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: signer.verification_method_id().clone(),
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
                created_at: issued_at,
                audience_id: audience,
                jws: String::new(),
            },
        };
        request.proof.payload_digest = request.payload_digest()?;
        request.proof.jws = signer.sign_payload(&request.proof_binding_bytes()?)?.jws;
        request.validate_bindings()?;
        Ok(request)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewOutcome {
    pub plan: crate::AppletInstallPlan,
    pub authoring_request: AppletManagedActorAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthorRequestBody {
    pub authoring_request: AppletManagedActorAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringBundle {
    pub schema: String,
    pub authoring_request_digest: Hash,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub managed_actor_provision_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accountability_grant_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_event: Event,
    pub proof: AppletManagedActorProof,
}

impl AppletManagedActorAuthoringBundle {
    pub const SCHEMA: &'static str = "ak.schema.applet_managed_actor_authoring_bundle.v1";
    pub const PROOF_CONTEXT: &'static str = "ak.applet_managed_actor_bundle_proof.v1";

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "authoring_request_digest": self.authoring_request_digest,
            "managed_actor_provision_event": self.managed_actor_provision_event,
            "pcr_genesis_event": self.pcr_genesis_event,
            "accountability_grant_event": self.accountability_grant_event,
            "profile_event": self.profile_event,
        })
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload_value())?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": Self::PROOF_CONTEXT,
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "audience_id": self.proof.audience_id,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(
        &self,
        authoring_request: &AppletManagedActorAuthoringRequest,
    ) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.authoring_request_digest != authoring_request.canonical_digest()?
            || self.proof.payload_digest != self.payload_digest()?
            || &self.proof.audience_id != authoring_request.basis.target_station_id()
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.proof.created_at != authoring_request.issued_at
            || self.proof.created_at > authoring_request.expires_at
            || [
                &self.managed_actor_provision_event,
                &self.pcr_genesis_event,
                &self.accountability_grant_event,
                &self.profile_event,
            ]
            .into_iter()
            .any(|event| event.created_at != authoring_request.issued_at)
        {
            return Err(WireError::Protocol(
                "applet managed actor authoring bundle binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthorOutcome {
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletInstallRequestBody {
    Create(Box<AppletInstallCreateRequestBody>),
    Reuse(Box<AppletInstallReuseRequestBody>),
}

impl AppletInstallRequestBody {
    pub fn applet_package(&self) -> &AppletPackage {
        match self {
            Self::Create(request) => &request.applet_package,
            Self::Reuse(request) => &request.applet_package,
        }
    }

    pub fn authoring_request(&self) -> &AppletManagedActorAuthoringRequest {
        match self {
            Self::Create(request) => &request.authoring_request,
            Self::Reuse(request) => &request.authoring_request,
        }
    }

    pub fn managed_actor_bundle(&self) -> Option<&AppletManagedActorAuthoringBundle> {
        match self {
            Self::Create(request) => Some(&request.managed_actor_bundle),
            Self::Reuse(_) => None,
        }
    }

    pub fn reuse_existing_managed_actor(&self) -> Option<&ReuseExistingManagedActor> {
        match self {
            Self::Create(_) => None,
            Self::Reuse(request) => Some(&request.reuse_existing_managed_actor),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallCreateRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallReuseRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub reuse_existing_managed_actor: ReuseExistingManagedActor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseExistingManagedActor {
    pub actor_id: ActorId,
    pub managed_actor_provision_ref: CommittedEventRef,
    pub pcr_genesis_ref: CommittedEventRef,
    pub accountability_grant_ref: CommittedEventRef,
    pub profile_event_ref: CommittedEventRef,
    pub initial_package_bot_actor_id: ActorId,
}
