//! Interop schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/ice-config-response.schema.json`.
pub type IceConfigOutcome = MediaIceConfigOutcome;

/// Counterpart for `spec/v1/artifacts/schemas/media-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MediaOperations {
    MediaIceConfigRequestBody(MediaIceConfigRequestBody),
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MimiInterop {
    ProviderDirectory(ProviderDirectory),
    RoomBinding(RoomBinding),
    ContentMappingReceipt(ContentMappingReceipt),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/content_mapping_receipt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentMappingReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub kind: String,
    pub profile: String,
    pub mimi_room_uri: MimiUri,
    pub source_format: String,
    pub target_format: String,
    pub original_envelope_digest: Hash,
    pub mapped_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arkret_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/mimi_uri`.
pub type MimiUri = String;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/provider_directory`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderDirectoryMimi {
    pub protocol_draft: String,
    pub content_draft: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_policy_draft: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_draft: Option<String>,
    pub base_url: String,
    pub provider_id: MimiUri,
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_cipher_suites: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_policy_components: Option<Vec<String>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderDirectoryProof {
    pub verification_method: String,
    pub signature: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderDirectory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    pub service_type: String,
    pub supported_profiles: Vec<String>,
    pub mimi: ProviderDirectoryMimi,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProviderDirectoryProof>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/room_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBindingPayload {
    pub profile: String,
    pub mimi_room_uri: MimiUri,
    pub binding_scope: RoomBindingPayloadBindingScope,
    pub hub_provider: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_providers: Option<Vec<Did>>,
    pub local_provider_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub kind: String,
    pub payload: RoomBindingPayload,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MimiOperations {
    MimiKeyMaterialRequestBody(crate::MimiKeyMaterialRequestBody),
    MimiKeyMaterialOutcome(crate::MimiKeyMaterialOutcome),
    MimiRoomUpdateRequestBody(crate::MimiRoomUpdateRequestBody),
    MimiRoomUpdateOutcome(crate::MimiRoomUpdateOutcome),
    MimiNotifyRequestBody(crate::MimiNotifyRequestBody),
    MimiNotifyOutcome(crate::MimiNotifyOutcome),
    MimiSubmitMessageRequestBody(crate::MimiSubmitMessageRequestBody),
    MimiSubmitMessageOutcome(crate::MimiSubmitMessageOutcome),
    MimiGroupInfoOutcome(crate::MimiGroupInfoOutcome),
    MimiRequestConsentRequestBody(crate::MimiRequestConsentRequestBody),
    MimiRequestConsentOutcome(crate::MimiRequestConsentOutcome),
    MimiUpdateConsentRequestBody(crate::MimiUpdateConsentRequestBody),
    MimiUpdateConsentOutcome(crate::MimiUpdateConsentOutcome),
    MimiIdentifierQueryRequestBody(crate::MimiIdentifierQueryRequestBody),
    MimiIdentifierQueryOutcome(crate::MimiIdentifierQueryOutcome),
    MimiReportAbuseRequestBody(crate::MimiReportAbuseRequestBody),
    MimiReportAbuseOutcome(crate::MimiReportAbuseOutcome),
    MimiProxyDownloadRequestBody(crate::MimiProxyDownloadRequestBody),
    MimiProxyDownloadOutcome(crate::MimiProxyDownloadOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/ciphertext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    pub content_type: String,
    pub ciphertext_digest: Hash,
    pub payload: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/consent_id`.
pub type ConsentId = String;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/consent_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentTarget {
    pub kind: String,
    pub id: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/group_info`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInfo {
    pub mls_group_id: String,
    pub epoch: u64,
    pub group_info: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/identifier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    pub kind: String,
    pub identifier_commitment: Hash,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/key_package`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackage {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_ref: Option<String>,
    pub mls_key_package: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/opaque_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaquePayload {
    pub content_type: String,
    pub payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}
