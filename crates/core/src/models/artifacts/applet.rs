//! Applet schema artifact counterparts retained by `arkret-core`.
//!
//! The leaf artifact shapes migrated to `arkret-models-integration`
//! (`artifacts_applet`, re-exported below). Kept here: the aggregate
//! operation enums whose variants embed core-retained request bodies,
//! and the widget declaration shapes bound to the collaboration-owned
//! `WireResourceSelector`.

pub use arkret_models_integration::artifacts_applet::*;

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
/// `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json#/properties/token_scope`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WidgetTokenScope {
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Widget {
    pub schema: String,
    pub widget_origin: String,
    pub csp: String,
    pub token_scope: WidgetTokenScope,
    pub requires_consent: bool,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}
