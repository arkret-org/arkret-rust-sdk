//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/realm-actor.schema.json
//! sha256=3e94b6c387b6fa1d895c5c5d5d56d86d7dbeeda40e4e513afb23c904e25f1592
//!
//! Input: schemas/current-state.schema.json
//! sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=ea613fae32e25a94687889845566828fe050317b185350eceb320391ae60c2f4

/// Counterpart: `realm-actor.schema.json#/$defs/control_scope/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorControlScopeKind {
    #[serde(rename = "realm_control")]
    RealmControl,
}

/// Counterpart: `realm-actor.schema.json#/$defs/control_scope`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlScope {
    pub kind: RealmActorControlScopeKind,
    pub realm_id: arkret_wire::RealmId,
}

/// Counterpart: `realm-actor.schema.json#/$defs/create_payload/properties/actor_role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorCreatePayloadActorRole {
    #[serde(rename = "bot")]
    Bot,
    #[serde(rename = "ghost")]
    Ghost,
}

/// Counterpart:
/// `realm-actor.schema.json#/$defs/create_payload/properties/recovery/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorCreatePayloadRecoveryKind {
    #[serde(rename = "manager_native")]
    ManagerNative,
}

/// Counterpart: `realm-actor.schema.json#/$defs/create_payload/properties/recovery`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorCreatePayloadRecovery {
    pub kind: RealmActorCreatePayloadRecoveryKind,
    pub enabled: bool,
}

/// Counterpart: `realm-actor.schema.json#/$defs/create_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorCreatePayload {
    pub schema: String,
    pub actor_id: arkret_wire::ActorId,
    pub applet_id: arkret_wire::AppletId,
    pub service_id: arkret_wire::DidCoreId,
    pub actor_role: RealmActorCreatePayloadActorRole,
    pub request_id: String,
    pub creation_scope: arkret_wire::ScopeRef,
    pub registration_ref: arkret_wire::EventId,
    pub creation_authorization_ref: arkret_wire::GrantId,
    pub initial_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
    pub control_method_kid: arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub external_ref: Option<crate::GhostExternalTuple>,
    pub control_signature: arkret_wire::DetachedObjectSignature,
    pub recovery: RealmActorCreatePayloadRecovery,
}

/// Counterpart: `realm-actor.schema.json#/$defs/creation_transcript/properties/actor_role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorCreationTranscriptActorRole {
    #[serde(rename = "bot")]
    Bot,
    #[serde(rename = "ghost")]
    Ghost,
}

/// Counterpart:
/// `realm-actor.schema.json#/$defs/creation_transcript/properties/recovery/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorCreationTranscriptRecoveryKind {
    #[serde(rename = "manager_native")]
    ManagerNative,
}

/// Counterpart: `realm-actor.schema.json#/$defs/creation_transcript/properties/recovery`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorCreationTranscriptRecovery {
    pub kind: RealmActorCreationTranscriptRecoveryKind,
    pub enabled: bool,
}

/// Counterpart: `realm-actor.schema.json#/$defs/creation_transcript`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorCreationTranscript {
    pub schema: String,
    pub actor_id: arkret_wire::ActorId,
    pub applet_id: arkret_wire::AppletId,
    pub service_id: arkret_wire::DidCoreId,
    pub actor_role: RealmActorCreationTranscriptActorRole,
    pub request_id: String,
    pub creation_scope: arkret_wire::ScopeRef,
    pub registration_ref: arkret_wire::EventId,
    pub creation_authorization_ref: arkret_wire::GrantId,
    pub initial_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
    pub control_method_kid: arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub external_ref: Option<crate::GhostExternalTuple>,
    pub recovery: RealmActorCreationTranscriptRecovery,
}

/// Counterpart: `realm-actor.schema.json#/$defs/control_update_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlUpdatePayload {
    pub expected_revision: arkret_wire::CurrentRevision,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
    pub next_control_method_kid: arkret_wire::DidUrl,
    pub next_method_signature: arkret_wire::DetachedObjectSignature,
}

/// Counterpart: `realm-actor.schema.json#/$defs/control_acceptance_transcript`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlAcceptanceTranscript {
    pub actor_id: arkret_wire::ActorId,
    pub expected_revision: arkret_wire::CurrentRevision,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
    pub next_control_method_kid: arkret_wire::DidUrl,
}

/// Counterpart: `realm-actor.schema.json#/$defs/status_set_payload/properties/gate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorStatusSetPayloadGate {
    #[serde(rename = "governance")]
    Governance,
    #[serde(rename = "owner")]
    Owner,
}

/// Counterpart: `realm-actor.schema.json#/$defs/status_set_payload/properties/state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorStatusSetPayloadState {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "paused")]
    Paused,
    #[serde(rename = "retired")]
    Retired,
}

/// Counterpart: `realm-actor.schema.json#/$defs/status_set_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorStatusSetPayload {
    pub target_actor_id: arkret_wire::ActorId,
    pub gate: RealmActorStatusSetPayloadGate,
    pub expected_revision: arkret_wire::CurrentRevision,
    pub state: RealmActorStatusSetPayloadState,
}

/// Counterpart: `realm-actor.schema.json#/$defs/devices_reset_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorDevicesResetPayload {
    pub expected_revision: arkret_wire::CurrentRevision,
    pub expected_generation: u64,
    pub new_generation: u64,
}

/// Counterpart: `realm-actor.schema.json#/$defs/manager_change_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorManagerChangePayload {
    pub expected_manager_revision: arkret_wire::CurrentRevision,
    pub expected_control_revision: arkret_wire::CurrentRevision,
    pub expected_device_generation_revision: arkret_wire::CurrentRevision,
    pub expected_generation: u64,
    pub new_generation: u64,
    pub new_service_id: arkret_wire::DidCoreId,
    pub new_registration_ref: arkret_wire::EventId,
    pub management_authorization_ref: arkret_wire::GrantId,
    pub new_service_signature: arkret_wire::DetachedObjectSignature,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
}

/// Counterpart: `realm-actor.schema.json#/$defs/manager_acceptance_transcript`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorManagerAcceptanceTranscript {
    pub actor_id: arkret_wire::ActorId,
    pub applet_id: arkret_wire::AppletId,
    pub expected_manager_revision: arkret_wire::CurrentRevision,
    pub expected_control_revision: arkret_wire::CurrentRevision,
    pub expected_device_generation_revision: arkret_wire::CurrentRevision,
    pub expected_generation: u64,
    pub new_generation: u64,
    pub new_service_id: arkret_wire::DidCoreId,
    pub new_registration_ref: arkret_wire::EventId,
    pub management_authorization_ref: arkret_wire::GrantId,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
}

/// Counterpart: `realm-actor.schema.json#/$defs/control_http_metadata`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlHttpMetadata {
    pub actor_id: arkret_wire::ActorId,
    pub control_ref: arkret_wire::CommittedEventRef,
    pub nonce: String,
}

/// Counterpart: `realm-actor.schema.json#/$defs/resource/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorResourceKind {
    #[serde(rename = "realm_actor")]
    RealmActor,
}

/// Counterpart: `realm-actor.schema.json#/$defs/resource`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorResource {
    pub kind: RealmActorResourceKind,
    pub actor_id: arkret_wire::ActorId,
}

/// Counterpart: `realm-actor.schema.json#/$defs/recovery_begin_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoveryBeginPayload {
    pub target_actor_id: arkret_wire::ActorId,
    pub request_id: String,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub expected_control_revision: arkret_wire::CurrentRevision,
    pub expected_owner_status_revision: arkret_wire::CurrentRevision,
    pub expected_governance_status_revision: arkret_wire::CurrentRevision,
    pub expected_device_generation_revision: arkret_wire::CurrentRevision,
    pub expected_generation: u64,
    pub new_generation: u64,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub replaces_recovery_ref: Option<arkret_wire::CommittedEventRef>,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: RealmActorWebvhRecoveryPlan,
    pub next_control_method_kid: arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub control_signature: arkret_wire::DetachedObjectSignature,
}

/// Counterpart:
/// `realm-actor.schema.json#/$defs/recovery_acceptance_transcript/properties/
/// payload_without_control_signature`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoveryAcceptanceTranscriptPayloadWithoutControlSignature {
    pub target_actor_id: arkret_wire::ActorId,
    pub request_id: String,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub expected_control_revision: arkret_wire::CurrentRevision,
    pub expected_owner_status_revision: arkret_wire::CurrentRevision,
    pub expected_governance_status_revision: arkret_wire::CurrentRevision,
    pub expected_device_generation_revision: arkret_wire::CurrentRevision,
    pub expected_generation: u64,
    pub new_generation: u64,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub replaces_recovery_ref: Option<arkret_wire::CommittedEventRef>,
    pub next_resolution: arkret_models_identity::ResolutionCommitment,
    pub method_history_evidence: RealmActorWebvhRecoveryPlan,
    pub next_control_method_kid: arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Counterpart: `realm-actor.schema.json#/$defs/recovery_acceptance_transcript`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoveryAcceptanceTranscript {
    pub applet_id: arkret_wire::AppletId,
    pub service_id: arkret_wire::DidCoreId,
    pub payload_without_control_signature:
        RealmActorRecoveryAcceptanceTranscriptPayloadWithoutControlSignature,
}

/// Counterpart: `realm-actor.schema.json#/$defs/control_reset_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlResetPayload {
    pub target_actor_id: arkret_wire::ActorId,
    pub recovery_begin_ref: arkret_wire::CommittedEventRef,
    pub expected_recovery_revision: arkret_wire::CurrentRevision,
    pub expected_manager_revision: arkret_wire::CurrentRevision,
    pub expected_control_revision: arkret_wire::CurrentRevision,
    pub expected_device_generation_revision: arkret_wire::CurrentRevision,
    pub published_method_history_evidence: crate::AppletManagedActorMethodHistoryEvidence,
}

/// Counterpart: `realm-actor.schema.json#/$defs/recovery_set_payload`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoverySetPayload {
    pub target_actor_id: arkret_wire::ActorId,
    pub expected_recovery_revision: arkret_wire::CurrentRevision,
    pub expected_manager_revision: arkret_wire::CurrentRevision,
    pub enabled: bool,
}

/// Counterpart: `realm-actor.schema.json#/$defs/recovery_intent`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoveryIntent {
    pub begin_ref: arkret_wire::CommittedEventRef,
    pub candidate_digest: arkret_wire::Hash,
    pub manager_revision: arkret_wire::CurrentRevision,
    pub control_revision: arkret_wire::CurrentRevision,
    pub device_generation_ref: u64,
}

/// Counterpart: `realm-actor.schema.json#/$defs/webvh_recovery_plan`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorWebvhRecoveryPlan {
    pub log_entries: Vec<serde_json::Value>,
    pub witness_records: Vec<serde_json::Value>,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_control_value`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorControlValue {
    pub resolution: arkret_models_identity::PrincipalResolutionProjection,
    pub control_method_kid: arkret_wire::DidUrl,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_manager_value`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorManagerValue {
    pub service_id: arkret_wire::DidCoreId,
    pub registration_ref: arkret_wire::EventId,
    pub binding_ref: arkret_wire::CommittedEventRef,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_recovery_value`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorRecoveryValue {
    pub kind: RealmActorCreatePayloadRecoveryKind,
    pub enabled: bool,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub pending: Option<RealmActorRecoveryIntent>,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_device_authorization_value`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorDeviceAuthorizationValue {
    pub device_public_key_did: String,
    pub hpke_key: String,
    pub algorithms: Vec<String>,
    pub device_key_algorithm: String,
    pub authorized_by: arkret_wire::DidCoreId,
    pub authorization_binding_kind:
        arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind,
    pub authorized_generation_ref: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub scopes: arkret_models_collaboration::events_payloads::AppletManagedDeviceScopes,
    pub applet_id: arkret_wire::AppletId,
    pub device_signature: arkret_models_collaboration::events_payloads::SignatureMaterial,
    pub device_authorize_event_id: arkret_wire::EventId,
}
