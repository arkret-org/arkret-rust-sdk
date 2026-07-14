//! Shared closed MIMI operation payloads.

use std::num::NonZeroU64;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiKeyPackage {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_ref: Option<NonEmptyString>,
    pub mls_key_package: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiGroupInfo {
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub group_info: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiFailure {
    pub reason_code: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<NonEmptyString>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Option<u64>)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<NonZeroU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiOpaquePayload {
    pub content_type: NonEmptyString,
    pub payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Base64UrlString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiCiphertext {
    pub content_type: NonEmptyString,
    pub ciphertext_digest: Hash,
    pub payload: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiRoomUpdate {
    pub kind: NonEmptyString,
    pub payload: MimiOpaquePayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiNotification {
    pub kind: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_hint: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiNotificationRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_room_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_providers: Vec<Did>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiDeliveryStatus {
    Accepted,
    Partial,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiDelivery {
    pub status: MimiDeliveryStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivered_to: Vec<Did>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiConsentTargetKind {
    Did,
    MimiUri,
    Handle,
    ProviderUser,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiConsentTarget {
    pub kind: MimiConsentTargetKind,
    pub id: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiConsentPurpose {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiIdentifierKind {
    MimiUri,
    Did,
    Handle,
    Phone,
    Email,
    Opaque,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiIdentifier {
    pub kind: MimiIdentifierKind,
    pub identifier_commitment: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiIdentifierMatch {
    pub identifier_commitment: Hash,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiOhttpContext {
    pub context_id: NonEmptyString,
    pub request_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_provider: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encapsulated_request: Option<Base64UrlString>,
}
