// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-edge-operations.schema.json
// sha256=6525f40d905ca955f9b9f3d70ad9e92aa2f4402e289fea537e31c947acaeac84
//
// Input: schemas/string-profiles.schema.json
// sha256=7c7522a769204b050b9711b53c1b911bc660645962ed6c0243f95fae72473f78
//
// Input: schemas/account-operations.schema.json
// sha256=0ae0fec5fd63dca4b9df9293eb71936cf73a3eeeae13b2268dc99699c1ed7607
//
// Input: schemas/applet-install-authoring.schema.json
// sha256=1583623ed73fa124b97721b286c9174962d3a05c4ee3853bc1bc79bee1b33995
//
// Input: schemas/applet-install-plan.schema.json
// sha256=34b87fd503f5bf7cd3cecd25e2f9be91817fc612502419b5c5d1df85ed2ccccf
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

/// Counterpart: `applet-edge-operations.schema.json#/$defs/field_definition`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/field_definition`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub field_required: Option<bool>,
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

/// Counterpart: `applet-edge-operations.schema.json#/$defs/applet_event_rejection`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/applet_event_rejection`.
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
    pub constraints:
        Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
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

/// Counterpart: `applet-install-plan.schema.json#/$defs/planned_event`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/planned_event`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedEvent {
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
