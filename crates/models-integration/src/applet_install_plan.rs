//! `ak.schema.applet_install_plan.v1` wire object.

use arkret_wire::{AppletId, Hash, PlanId, Result, SchemaId, ScopeRef, WireError, canonical};
use serde::{Deserialize, Serialize};

use crate::artifacts_applet::{
    CapabilityConstraint, DeniedScope, E2eeEffect, EventSubmission, NamespaceConflict, ScopeGrant,
    WidgetEffect,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPlan {
    pub schema: String,
    pub plan_id: PlanId,
    pub applet_id: AppletId,
    pub package_digest: Hash,
    pub registration_epoch: Hash,
    pub effective_scope: ScopeRef,
    pub requested_scopes: Vec<String>,
    pub approved_scopes: Vec<ScopeGrant>,
    pub denied_scopes: Vec<DeniedScope>,
    pub event_submissions: Vec<EventSubmission>,
    pub capability_constraints: Vec<CapabilityConstraint>,
    pub namespace_conflicts: Vec<NamespaceConflict>,
    pub e2ee_effect: E2eeEffect,
    pub widget_effect: WidgetEffect,
    pub warnings: Vec<String>,
    pub plan_digest: Hash,
}

impl AppletInstallPlan {
    pub const SCHEMA: &'static str = SchemaId::APPLET_INSTALL_PLAN_V1;
    /// Compute the canonical plan digest with `plan_digest` omitted.
    pub fn compute_plan_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            WireError::Protocol("applet install plan must serialize as an object".to_owned())
        })?;
        object.remove("plan_digest");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    /// Recompute and replace the canonical plan digest.
    pub fn seal(&mut self) -> Result<()> {
        self.plan_digest = self.compute_plan_digest()?;
        Ok(())
    }
}
