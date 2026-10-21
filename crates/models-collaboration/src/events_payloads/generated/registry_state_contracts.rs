// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=a4c646467cc0e400d6cb24a119fe6791612dcf3a3a8d77fd355f9429600679bc
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `event-payload.schema.json#/$defs/resource_discovery_state_value`.
/// `resource_discovery_state_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiscoveryStateValue {
    pub resource_kind: DiscoveryResourceKind,
    pub discoverability: Discoverability,
    pub directory_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub profile_visibility: Option<DiscoveryProfileVisibility>,
}

/// Counterpart: `event-payload.schema.json#/$defs/applet_discovery_state_payload`.
/// `ak.applet.discovery` payload (`applet_discovery_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletDiscoveryStatePayload {
    pub resource_id: AppletId,
    pub value: ResourceDiscoveryStateValue,
}

/// Counterpart: `event-payload.schema.json#/$defs/policy_action_document`.
/// `policy_action_document`: the sole v1 approval-action document family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionDocument {
    pub action: arkret_wire::PolicyActionName,
    pub approval_required: bool,
    pub approval_quorum: u64,
    pub policy_scope: String,
}

/// Counterpart: `event-payload.schema.json#/$defs/schema_define_state_payload`.
/// `ak.schema.define` payload (`schema_define_state_payload`). `value` is an
/// open JSON Schema 2020-12 document whose `$id` is the definition subject.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDefineStatePayload {
    pub value: Map<String, Value>,
}

/// Counterpart: `event-payload.schema.json#/$defs/policy_action_state_payload`.
/// `ak.policy.action` payload (`policy_action_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub action_id: Option<arkret_wire::RealmPolicyActionId>,
    pub value: PolicyActionDocument,
}
