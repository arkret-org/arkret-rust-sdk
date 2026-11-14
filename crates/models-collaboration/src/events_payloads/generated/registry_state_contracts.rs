// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=110f3442df382c602cece0f2f5e0b4f2af3a0374f493911960b3cf6216f99a95
//
// Input: schemas/string-profiles.schema.json
// sha256=7c7522a769204b050b9711b53c1b911bc660645962ed6c0243f95fae72473f78
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

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
