// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-edge-operations.schema.json
// sha256=1f0506e1a93a17af4329eb42f1dd5b8cd0ea70c86a364941b0bc06884ca18902
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/account-operations.schema.json
// sha256=5b7dba680c2083d0bebc26ad32e7d37293d150cece8f2298a40bf382e7f31405
//
// Input: schemas/applet-install-authoring.schema.json
// sha256=134ef4b7401aec43c6b0b6948548be2e7dd5752b0714400f54a6d7cb4012bf2d
//
// Input: schemas/applet-install-plan.schema.json
// sha256=e896f502c8ce0ac975fbbf4211dcd153722fcac2b8b30f5fa459c6432da53b33
//
// Bindings: tools/closed-model-bindings.json
// sha256=d200bd3e6d76abd1b6154781fb5e54f11fbbc834638cdc29554f83590127fdfa

/// Counterpart: `applet-edge-operations.schema.json#/$defs/field_definition`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/field_definition`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub description: Option<String>,
    pub value_kind: String,
}

/// Counterpart: `applet-edge-operations.schema.json#/$defs/protocol_instance`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol_instance`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolInstance {
    pub instance_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub external_ref: Option<ExternalRef>,
}

/// Counterpart: `applet-edge-operations.schema.json#/$defs/rejected_event_row`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/rejected_event_row`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletEventRejection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub event_id: Option<EventId>,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart: `applet-install-authoring.schema.json#/$defs/e2ee_policy`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-authoring.schema.json#/$defs/e2ee_policy`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mls_join_allowed: Option<bool>,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/scope_grant`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/scope_grant`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    pub actions: Vec<String>,
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub circle_ids: Option<Vec<CircleId>>,
    pub constraints: Vec<BTreeMap<String, Value>>,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/capability_constraint`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/capability_constraint`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConstraint {
    pub constraint_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub params: Option<BTreeMap<String, Value>>,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/denied_scope`.
/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/denied_scope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedScope {
    pub requested_scope: String,
    pub reason_code: ReasonCode,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/e2ee_effect`.
/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/e2ee_effect`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eeEffect {
    pub mls_join_required: bool,
    pub plaintext_access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authorization_refs: Option<Vec<CommittedEventRef>>,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/event_submission`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/event_submission`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubmission {
    pub event_kind: String,
    pub payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub semantic_refs: Option<Vec<SemanticRef>>,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/namespace_conflict`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/namespace_conflict`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceConflict {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub existing_owner: Option<String>,
    pub resolution: String,
}

/// Counterpart: `applet-install-plan.schema.json#/$defs/widget_effect`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/widget_effect`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidgetEffect {
    pub widget_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<CommittedEventRef>,
}

/// Counterpart: `applet-edge-operations.schema.json#/$defs/external_ref`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/external_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRef {
    pub protocol: String,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "uri")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub url: Option<String>,
}
