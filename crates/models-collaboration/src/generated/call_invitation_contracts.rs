// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=ff3723be2839fd0ebb89296b6e3a61a209be5e24d0bbbd37b21870dd55799a39
//
// Input: schemas/call-invitation-operations.schema.json
// sha256=dbc523824e0210ad6e6197c8be96658b017f4c80de814970c5af3ba87319f9b8
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `service-operation-dtos.schema.json#/$defs/CallMediaRosterIdentity`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMediaRosterIdentity {
    pub actor_id: arkret_wire::DidCoreId,
    pub device_id: arkret_wire::DeviceId,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/CallMediaSubjectBinding`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub verification_method: arkret_wire::DidUrl,
    pub jws: String,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/invitation_envelope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationEnvelope {
    pub inviter_actor_id: arkret_wire::ActorId,
    pub holder_account_id: arkret_wire::AccountId,
    pub scope_ref: arkret_wire::ScopeRef,
    pub call_id: arkret_wire::CallId,
    pub media: CallInvitationMedia,
    pub envelope_digest: arkret_wire::Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: CallInvitationProof,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationSendRequestBody {
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_outcome/properties/status`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallInvitationSendStatus {
    #[serde(rename = "deferred")]
    Deferred,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/send_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationSendOutcome {
    pub status: CallInvitationSendStatus,
}

/// Counterpart:
/// `call-invitation-operations.schema.json#/$defs/admission_request_body/properties/
/// admission_phase`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallInvitationAdmissionStage {
    #[serde(rename = "product_delivery")]
    ProductDelivery,
    #[serde(rename = "media_token")]
    MediaToken,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionOutcome {
    pub request_digest: arkret_wire::Hash,
    pub admitted: bool,
    pub authority_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: CallInvitationProof,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/delivery_view`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationDeliveryView {
    pub invitation: CallInvitationEnvelope,
    pub request: CallInvitationAdmissionRequestBody,
    pub outcome: CallInvitationAdmissionOutcome,
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

/// Counterpart: `call-invitation-operations.schema.json#/$defs/invitation_join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationJoinRequestBody {
    pub kind: CallInvitationJoinKind,
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/voluntary_join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallVoluntaryJoinRequestBody {
    pub kind: CallVoluntaryJoinKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub proof: CallInvitationProof,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/refresh_join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRefreshJoinRequestBody {
    pub kind: CallRefreshJoinKind,
    pub participant_id: String,
    pub subject_binding: CallMediaSubjectBinding,
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/join_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CallJoinContext {
    Invitation(CallInvitationJoinRequestBody),
    Voluntary(CallVoluntaryJoinRequestBody),
    Refresh(CallRefreshJoinRequestBody),
}

/// Counterpart: `call-invitation-operations.schema.json#/$defs/admission_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInvitationAdmissionRequestBody {
    pub invitation: CallInvitationEnvelope,
    pub envelope: arkret_wire::SignalEnvelope,
    pub admission_phase: CallInvitationAdmissionStage,
    pub audience_actor_id: arkret_wire::ActorId,
    pub subject_actor_id: arkret_wire::ActorId,
    pub subject_device_id: arkret_wire::DeviceId,
    pub nonce: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub focus_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub desired_media: Option<CallInvitationMedia>,
}
