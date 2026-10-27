//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/call-invitation-operations.schema.json
//! sha256=88f06d26b99092fdcafd2f95d0d755ecab82ec71089520093382afc8c5a3dffd
//!
//! Input: schemas/current-state.schema.json
//! sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//!
//! Input: schemas/consent-operations.schema.json
//! sha256=a367b21ca191391ab7a62c8b1413a48f9866b7cdca5692c65e5bd58c5a330b09
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

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

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/send_response_body/properties/status`.
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

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_response_body`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationSendResponseBody {
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

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_decision`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionDecision {
    pub request_digest: String,
    pub admitted: bool,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
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
    pub decision: CallInvitationAdmissionDecision,
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
/// `current-state.schema.json#/$defs/current_consent/properties/selector/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentCurrentSelectorKind {
    #[serde(rename = "consent")]
    Consent,
}

/// Counterpart: `current-state.schema.json#/$defs/current_consent/properties/selector`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentSelector {
    pub kind: ConsentCurrentSelectorKind,
    pub peer_id: arkret_wire::ActorId,
}

/// Counterpart: `current-state.schema.json#/$defs/current_consent`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CurrentConsent {
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
    pub audience_actor_id: arkret_wire::ActorId,
    pub nonce: String,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadResponseBody {
    pub request_digest: String,
    pub realm_id: arkret_wire::RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub governance_generation: u64,
    pub effective_stream_head: arkret_wire::CommitStreamHead,
    pub current: crate::call_invitation::ConsentCurrentReadState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: ConsentCurrentReadProof,
}
