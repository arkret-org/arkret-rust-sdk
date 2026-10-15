//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/call-invitation-operations.schema.json
//! sha256=96619c1b09e1c7b37350464b6802f1fe91f03b12273e738179b820da2b49aa43
//!
//! Input: schemas/service-operation-dtos.schema.json
//! sha256=13ad6809e32efa463de5ce3fa44c9e3ae788db50bc7a1973f56c0e988a901020
//!
//! Input: schemas/typed-current-result.schema.json
//! sha256=fe2f5aa29f51e9d6243e74433c0ee027e4d15f04b8e01c3354a423f069b285a5
//!
//! Input: schemas/consent-operations.schema.json
//! sha256=90c045bc2fadaa4481370039731723349f25656f7d89c24668082fe0a0a5fd48
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=08dd3be10645b0c4e133fe72a1a0f80596e47ca0c707a290dcd23d1116f56607

/// Counterpart: `call-invitation-operations.schema.json#/$defs/media`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationMedia {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/invitation_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationProof {
    pub verification_method: String,
    pub jws: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionProof {
    pub verification_method: String,
    pub jws: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/voluntary_join_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallVoluntaryJoinProof {
    pub verification_method: String,
    pub jws: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_outcome/properties/status`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallInvitationSendStatus {
    #[serde(rename = "deferred")]
    Deferred,
}

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/admission_request_body/properties/
/// admission_phase`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallInvitationAdmissionPhase {
    #[serde(rename = "product_delivery")]
    ProductDelivery,
    #[serde(rename = "media_token")]
    MediaToken,
}

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/invitation_join_context/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallInvitationJoinKind {
    #[serde(rename = "invitation")]
    Invitation,
}

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/voluntary_join_context/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallVoluntaryJoinKind {
    #[serde(rename = "voluntary")]
    Voluntary,
}

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/refresh_join_context/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallRefreshJoinKind {
    #[serde(rename = "refresh")]
    Refresh,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/invitation_envelope`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationEnvelope {
    pub inviter_actor_id: arkret_wire::ActorId,
    pub holder_account_id: arkret_wire::AccountId,
    pub scope_ref: arkret_wire::ScopeRef,
    pub call_id: arkret_wire::CallId,
    pub media: CallInvitationMedia,
    pub envelope_digest: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: CallInvitationProof,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationSendRequestBody {
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationSendOutcome {
    pub status: CallInvitationSendStatus,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionRequestBody {
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
    pub admission_phase: CallInvitationAdmissionPhase,
    pub audience_actor_id: arkret_wire::ActorId,
    pub subject_actor_id: arkret_wire::ActorId,
    pub subject_device_id: arkret_wire::DeviceId,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub focus_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub desired_media: Option<CallInvitationMedia>,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionOutcome {
    pub request_digest: String,
    pub admitted: bool,
    pub authority_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: CallInvitationAdmissionProof,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/delivery_view`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationDeliveryView {
    pub invitation: CallInvitationEnvelope,
    pub request: CallInvitationAdmissionRequestBody,
    pub outcome: CallInvitationAdmissionOutcome,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/invitation_join_context`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationJoinContext {
    pub kind: CallInvitationJoinKind,
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/voluntary_join_context`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallVoluntaryJoinContext {
    pub kind: CallVoluntaryJoinKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub proof: CallVoluntaryJoinProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/CallMediaRosterIdentity`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallMediaRosterIdentity {
    pub actor_id: arkret_wire::DidCoreId,
    pub device_id: arkret_wire::DeviceId,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/CallMediaSubjectBinding`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallMediaSubjectBinding {
    pub realm_id: arkret_wire::RealmId,
    pub call_id: arkret_wire::CallId,
    pub subject_actor_id: arkret_wire::ActorId,
    pub subject_device_id: arkret_wire::DeviceId,
    pub roster_identity: CallMediaRosterIdentity,
    pub focus_id: String,
    pub participant_id: String,
    pub media: CallInvitationMedia,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub issuer_kid: arkret_wire::DidUrl,
    pub sig: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/refresh_join_context`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallRefreshJoinContext {
    pub kind: CallRefreshJoinKind,
    pub participant_id: String,
    pub subject_binding: CallMediaSubjectBinding,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CallMediaJoinContext {
    Invitation(crate::call_invitation::CallInvitationJoinContext),
    Voluntary(crate::call_invitation::CallVoluntaryJoinContext),
    Refresh(crate::call_invitation::CallRefreshJoinContext),
}

/// Counterpart:
/// `typed-current-result.schema.json#/$defs/consent_result/properties/selector/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentCurrentSelectorKind {
    #[serde(rename = "consent")]
    Consent,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_result/properties/selector`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentSelector {
    pub kind: ConsentCurrentSelectorKind,
    pub consent_id: arkret_wire::ConsentId,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_result`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentRow {
    pub selector: ConsentCurrentSelector,
    pub source_stream_ref: arkret_wire::CommitStreamRef,
    pub revision: arkret_wire::CurrentRevision,
    pub value: crate::consent_operations::ConsentValue,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadProof {
    pub verification_method: arkret_wire::DidUrl,
    pub jws: String,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadRequestBody {
    pub holder_account_id: arkret_wire::AccountId,
    pub peer: crate::events_payloads::consent::ConsentPeer,
    pub consent_scope: arkret_wire::ConsentScope,
    pub audience_actor_id: arkret_wire::ActorId,
    pub nonce: String,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_outcome`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadOutcome {
    pub request_digest: String,
    pub realm_id: arkret_wire::RealmId,
    pub governance_generation: u64,
    pub effective_stream_head: arkret_wire::CommitStreamHead,
    pub consents: Vec<ConsentCurrentRow>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: ConsentCurrentReadProof,
}
