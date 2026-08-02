//! Shared closed MIMI operation payloads.

use std::num::NonZeroU64;

use arkret_wire::{
    Base64UrlString, DeviceId, Did, Hash, MimiRoomUri, MlsGroupId, NonEmptyString, ReasonCode,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiKeyPackage {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_ref: Option<NonEmptyString>,
    pub mls_key_package: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiGroupInfo {
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub group_info: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiFailure {
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = u64)))]
    pub retry_after_ms: Option<NonZeroU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiOpaquePayload {
    pub content_type: NonEmptyString,
    pub payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Base64UrlString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiCiphertext {
    pub content_type: NonEmptyString,
    pub ciphertext_digest: Hash,
    pub payload: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUpdate {
    pub kind: NonEmptyString,
    pub payload: MimiOpaquePayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotification {
    pub kind: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_hint: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotificationRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_room_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_providers: Vec<Did>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiDeliveryStatus {
    Accepted,
    Partial,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiDelivery {
    pub status: MimiDeliveryStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivered_to: Vec<Did>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiConsentTargetKind {
    Did,
    MimiUri,
    Handle,
    ProviderUser,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiConsentTarget {
    pub kind: MimiConsentTargetKind,
    pub id: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiConsentPurpose {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiIdentifierKind {
    MimiUri,
    Did,
    Handle,
    Phone,
    Email,
    Opaque,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifier {
    pub kind: MimiIdentifierKind,
    pub identifier_commitment: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierMatch {
    pub identifier_commitment: Hash,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiOhttpContext {
    pub context_id: NonEmptyString,
    pub request_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_provider: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encapsulated_request: Option<Base64UrlString>,
}
