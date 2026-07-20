//! Applet schema artifact counterparts retained by `arkret-core`.
//!
//! The leaf artifact shapes and the widget declaration shapes (`Widget`,
//! `WidgetTokenScope`) migrated to `arkret-models-integration`
//! (`artifacts_applet`, re-exported below). Kept here: the aggregate
//! operation enums whose variants embed request bodies rehomed across the
//! integration / collaboration model crates.

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
