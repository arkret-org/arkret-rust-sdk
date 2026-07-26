//! Applet install / edge operation body DTOs.
//!
//! The install preview / install request bodies embed the applet package
//! (`AppletPackage`, this crate's `applet::registration`), so they live here.
//! `AppletTransactionRequestBody` (binds `EphemeralEnvelope`) and
//! `AppletRevokeRequestBody` (binds `AccountLifecycleProof`) live in
//! `arkret-models-collaboration`.

use std::collections::BTreeMap;

pub use arkret_wire::AppletIdentifier;
use arkret_wire::{BlobRef, Did, EffectiveScope, EventId, GrantId, Hash, RealmId};
use serde::{Deserialize, Serialize};

use crate::applet::AppletPackage;
use crate::artifacts_applet::{
    E2eePolicy, ExternalRef, FieldDefinition, ProtocolInstance, RejectedItem, ScopeGrant,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletPingOutcome {
    pub ok: bool,
    pub applet_id: String,
    pub service_id: Did,
    pub protocol_version: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<RejectedItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletApprovalRequest {
    pub approve_actions: Vec<String>,
    pub ghost_actors_allowed: bool,
    pub delegated_native_actors_allowed: bool,
    pub e2ee_join_allowed: bool,
    pub widget_allowed: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBotMembership {
    Invite,
    Join,
    Disabled,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletGhostActorMode {
    Disallowed,
    ControllerApproved,
    PolicyDeclared,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletActorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_membership: Option<AppletBotMembership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghost_actor_mode: Option<AppletGhostActorMode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletRejectedItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<String>,
    pub reason_code: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletInstallEffectiveStatus {
    Installed,
    PartiallyInstalled,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletInstallOutcome {
    pub ok: bool,
    pub install_id: String,
    pub applet_id: String,
    pub registration_event_ref: Option<EventId>,
    pub registration_epoch: Hash,
    pub bot_actor_id: Did,
    pub capability_grant_refs: Vec<GrantId>,
    pub membership_event_refs: Vec<EventId>,
    pub e2ee_authorization_refs: Vec<EventId>,
    pub widget_policy_ref: Option<EventId>,
    pub effective_status: AppletInstallEffectiveStatus,
    pub rejected: Vec<AppletRejectedItem>,
}

// `AppletRevokeMode` relocated to `arkret-wire` (`applet_revoke_mode`) so the
// collaboration-owned `AppletRevokeRequestBody` can name it. Re-exported here
// for path stability.
pub use arkret_wire::AppletRevokeMode;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletRevokeOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<AppletRejectedItem>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletActorView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRealmView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletProtocolMetadata {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob_ref: Option<BlobRef>,
    pub field_definitions: BTreeMap<String, FieldDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<ProtocolInstance>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewRequestBody {
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    pub approval_request: AppletApprovalRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallRequestBody {
    pub plan_digest: Hash,
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    pub approved_scopes: Vec<ScopeGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_policy: Option<AppletActorPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_policy: Option<E2eePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy: Option<AppletWidgetPolicy>,
}
