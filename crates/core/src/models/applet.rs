//! Applet operation bodies retained by `arkret-core`.
//!
//! The install / edge outcome DTOs migrated to
//! `arkret-models-integration` (`applet_models`, re-exported below). The
//! request bodies kept here are entangled with core-only or
//! collaboration-owned types: the transaction body (`EphemeralEnvelope`),
//! the install preview / install bodies (`AppletPackage`), and the revoke
//! body (`AccountLifecycleProof`).

pub use arkret_models_integration::applet_models::*;

use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionRequestBody {
    pub source_service_id: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Vec<EphemeralEnvelope>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewRequestBody {
    pub applet_package: crate::AppletPackage,
    pub effective_scope: EffectiveScope,
    pub approval_request: AppletApprovalRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletInstallRequestBody {
    pub plan_digest: Hash,
    pub applet_package: crate::AppletPackage,
    pub effective_scope: EffectiveScope,
    pub approved_scopes: Vec<ScopeGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_policy: Option<AppletActorPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_policy: Option<E2eePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy: Option<AppletWidgetPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeRequestBody {
    pub effective_scope: EffectiveScope,
    pub reason_code: String,
    pub revoke_mode: AppletRevokeMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}
