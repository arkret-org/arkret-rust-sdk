use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum AppletInstallAppletId {
    Did(Did),
    AppletId(AppletId),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPlan {
    pub schema: String,
    pub plan_id: String,
    pub applet_id: AppletInstallAppletId,
    pub package_digest: Hash,
    pub registration_epoch: Hash,
    pub effective_scope: EffectiveScope,
    pub requested_scopes: Vec<String>,
    pub approved_scopes: Vec<ScopeGrant>,
    pub denied_scopes: Vec<DeniedScope>,
    pub events_to_submit: Vec<EventSubmission>,
    pub capability_constraints: Vec<CapabilityConstraint>,
    pub namespace_conflicts: Vec<NamespaceConflict>,
    pub e2ee_effect: E2eeEffect,
    pub widget_effect: WidgetEffect,
    pub warnings: Vec<String>,
    pub plan_digest: Hash,
}

impl AppletInstallPlan {
    pub const SCHEMA: &'static str = "ak.schema.applet_install_plan.v1";
}
