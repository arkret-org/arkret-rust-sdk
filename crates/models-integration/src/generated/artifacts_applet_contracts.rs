// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-edge-operations.schema.json
// sha256=e9168099598d2c2cb6d6b19d707060904a27480265dad407dfd9cd38ae532c1b
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/applet-install-authoring.schema.json
// sha256=a32b20ae7ed2873fd6f71b264171b14d32c21de7d066426d131c8f6fbde45c8b
//
// Input: schemas/applet-install-plan.schema.json
// sha256=a97d9cd61f5f912a5d899f4214c83002f9deff71f1dbaeeab9009a8b69519a3c
//
// Bindings: tools/closed-model-bindings.json
// sha256=14ce06e703487b8afdca6c0a5335ef346a965acc5f9443d89af8470d63109b0f

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
