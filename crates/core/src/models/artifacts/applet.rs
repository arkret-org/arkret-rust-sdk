//! Applet schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletEdgeOperations {
    AppletPingOutcome(AppletPingOutcome),
    AppletTransactionRequestBody(AppletTransactionRequestBody),
    AppletTransactionOutcome(AppletTransactionOutcome),
    AppletActorView(AppletActorView),
    AppletRealmView(AppletRealmView),
    AppletProtocolMetadata(AppletProtocolMetadata),
    ThirdPartyQuery(ThirdPartyQuery),
    AppletThirdPartyUserList(crate::AppletThirdPartyUserList),
    AppletThirdPartyLocationList(crate::AppletThirdPartyLocationList),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/external_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRef {
    pub protocol: Protocol,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/field_type`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldType {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol`.
pub type Protocol = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol_instance`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolInstance {
    pub instance_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/rejected_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/third_party_query`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyQuery {
    pub protocol: Protocol,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AppletInstallOperations {
    AppletInstallPreviewRequestBody(AppletInstallPreviewRequestBody),
    AppletInstallPlan(AppletInstallPlan),
    AppletInstallRequestBody(AppletInstallRequestBody),
    AppletInstallOutcome(AppletInstallOutcome),
    AppletRevokeRequestBody(AppletRevokeRequestBody),
    AppletRevokeOutcome(AppletRevokeOutcome),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/e2ee_policy`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct E2eePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_mls_join: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/scope_grant`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    pub actions: Vec<String>,
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_ids: Option<Vec<CircleId>>,
    pub constraints: Vec<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/typed_ref`.
pub type TypedRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/capability_constraint`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CapabilityConstraint {
    pub constraint_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, Value>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/denied_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeniedScope {
    pub requested_scope: String,
    pub reason_code: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/e2ee_effect`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct E2eeEffect {
    pub requires_mls_join: bool,
    pub plaintext_access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_refs: Option<Vec<EventRef>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/event_submission`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventSubmission {
    pub event_kind: String,
    pub payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/namespace_conflict`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct NamespaceConflict {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_owner: Option<String>,
    pub resolution: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/widget_effect`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct WidgetEffect {
    pub allow_widget: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<EventRef>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/applet_namespaces`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletNamespaces {
    pub actors: Vec<NamespaceEntry>,
    pub realms: Vec<NamespaceEntry>,
    pub handles: Vec<NamespaceEntry>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/delegation_policy`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationPolicy {
    pub enabled: bool,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/detached_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedProof {
    pub kind: String,
    pub verification_method: Did,
    pub alg: SignatureAlg,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Value>,
    pub jws: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/endpoint_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointEntry {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/endpoint_policy`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointPolicy {
    pub endpoints: Vec<EndpointEntry>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/ghost_policy`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostPolicy {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_template: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/limits`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transaction_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/namespace_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceEntry {
    pub exclusive: bool,
    pub pattern: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/non_empty_string_array`.
pub type NonEmptyStringArray = Vec<NonEmptyString>;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/profile_id`.
pub type ProfileId = String;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/signature_alg`.
pub type SignatureAlg = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json#/properties/token_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WidgetTokenScope {
    pub actions: Vec<String>,
    pub resources: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Widget {
    pub schema: String,
    pub widget_origin: String,
    pub csp: String,
    pub token_scope: WidgetTokenScope,
    pub requires_consent: bool,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applet {
    pub schema: String,
    pub applet_id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AppletError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
