use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletPingOutcome {
    pub ok: bool,
    pub applet_id: String,
    pub service_id: Did,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletDescription {
    pub applet_id: String,
    pub service_id: Did,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub namespaces: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionRequestBody {
    pub source_service_id: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub ephemeral: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<RejectedItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletApprovalRequest {
    pub approve_actions: Vec<String>,
    pub allow_ghost_actors: bool,
    pub allow_delegated_native_actors: bool,
    pub allow_e2ee_join: bool,
    pub allow_widget: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletBotMembership {
    Invite,
    Join,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletGhostActorMode {
    Disallowed,
    ControllerApproved,
    PolicyDeclared,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletActorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_membership: Option<AppletBotMembership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghost_actor_mode: Option<AppletGhostActorMode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_widget: Option<bool>,
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
pub struct AppletRejectedItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<String>,
    pub reason_code: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletInstallEffectiveStatus {
    Installed,
    PartiallyInstalled,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeMode {
    RevokeAll,
    RevokeRuntimeOnly,
    RevokeWidgetOnly,
    RevokeDelegatedSessions,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletRevokeOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<AppletRejectedItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletActorView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletRealmView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletProtocolMetadata {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob_ref: Option<BlobRef>,
    pub field_types: BTreeMap<String, FieldType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<ProtocolInstance>,
}
