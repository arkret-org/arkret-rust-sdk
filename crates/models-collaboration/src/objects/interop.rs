//! Interop schema artifact counterparts (MIMI and media faces).

use std::collections::BTreeMap;

use arkret_wire::{
    DidCoreId, Hash, MimiRoomUri, MimiUri, PayloadProof, ProofContextId, RealmId, StrandId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
/// Counterpart for
/// `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/provider_directory/properties/mimi`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProviderDirectoryMimi {
    pub protocol_draft: String,
    pub content_draft: String,
    pub room_policy_draft: String,
    pub identifier_draft: String,
    pub base_url: String,
    pub provider_id: MimiUri,
    pub endpoints: Vec<ProviderDirectoryEndpoint>,
    pub features: Vec<String>,
    pub mls_cipher_suites: Vec<String>,
    pub content_profiles: Vec<String>,
    pub room_policy_components: Vec<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// One signed feature-to-path row in a MIMI provider directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProviderDirectoryEndpoint {
    pub endpoint_id: String,
    pub relative_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(transparent)]
pub struct ProviderDirectoryProof(pub PayloadProof);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProviderDirectory {
    pub schema: String,
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub supported_profiles: Vec<String>,
    pub mimi: ProviderDirectoryMimi,
    pub proof: ProviderDirectoryProof,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

impl ProviderDirectory {
    /// Exact signed projection from `mimi-interop.md` section 3.1. Draft
    /// extensions and the proof wrapper are deliberately excluded.
    pub fn unsigned_projection(&self) -> Value {
        serde_json::json!({
            "context": ProofContextId::MIMI_PROVIDER_DIRECTORY_PROOF_V1,
            "schema": self.schema,
            "service_id": self.service_id,
            "service_kind": self.service_kind,
            "supported_profiles": self.supported_profiles,
            "mimi": {
                "protocol_draft": self.mimi.protocol_draft,
                "content_draft": self.mimi.content_draft,
                "room_policy_draft": self.mimi.room_policy_draft,
                "identifier_draft": self.mimi.identifier_draft,
                "base_url": self.mimi.base_url,
                "provider_id": self.mimi.provider_id,
                "endpoints": self.mimi.endpoints,
                "features": self.mimi.features,
                "mls_cipher_suites": self.mimi.mls_cipher_suites,
                "content_profiles": self.mimi.content_profiles,
                "room_policy_components": self.mimi.room_policy_components,
            }
        })
    }

    pub fn unsigned_projection_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&self.unsigned_projection())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/room_binding/properties/payload/
/// properties/binding_scope`.
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
    pub mimi_room_uri: MimiRoomUri,
    pub binding_scope: RoomBindingPayloadBindingScope,
    pub hub_provider_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_provider_ids: Option<Vec<DidCoreId>>,
    pub local_provider_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
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

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/ciphertext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    pub content_type: String,
    pub ciphertext_digest: Hash,
    pub payload: String,
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
