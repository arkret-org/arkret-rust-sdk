//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/call-invitation-operations.schema.json
//! sha256=a7a5319c9fe02763036f0b3edbf20b6f6e7d7066ec53be2ed913ccb5f71ba06f
//!
//! Input: schemas/typed-current-result.schema.json
//! sha256=ad33beeae92adb2bdf6ce5528d33435ba67cc5608647a5e0d5e8728902c543a7
//!
//! Input: schemas/consent-operations.schema.json
//! sha256=90c045bc2fadaa4481370039731723349f25656f7d89c24668082fe0a0a5fd48
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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

/// Counterpart: `call-invitation-operations.schema.json#/$defs/refresh_join_context`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallRefreshJoinContext {
    pub kind: CallRefreshJoinKind,
    pub participant_id: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum CallMediaJoinContext {
    Invitation(CallInvitationJoinContext),
    Voluntary(CallVoluntaryJoinContext),
    Refresh(CallRefreshJoinContext),
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
