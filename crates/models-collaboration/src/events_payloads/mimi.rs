//! MIMI interop event payloads.

use arkret_wire::DidCoreId;

use crate::internal_prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiLocalProviderRole {
    Hub,
    Follower,
    Observer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiRoomBindingStatus {
    Proposed,
    Accepted,
    Revoked,
    Migrating,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayload {
    pub profile: MimiInteropProfileId,
    pub mimi_room_uri: MimiRoomUri,
    pub binding_scope: MimiRoomBindingPayloadBindingScope,
    pub hub_provider_id: DidCoreId,
    pub local_provider_role: MimiLocalProviderRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_provider_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<ContentProfileId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_root: Option<Hash>,
    pub status: MimiRoomBindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
}
