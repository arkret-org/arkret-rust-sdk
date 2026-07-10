use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AppletPackage;
use crate::{Did, RealmId, Result, canonical};

/// Single install target. `kind="realm"` is a Realm-wide grant;
/// `kind="circle"` is bounded to one Circle. A single install operation
/// MUST target exactly one scope (spec §1b / §4b).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveScope {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: crate::CircleId,
    },
}

impl EffectiveScope {
    /// The Realm both variants are sealed in.
    pub fn realm_id(&self) -> &RealmId {
        match self {
            EffectiveScope::Realm { realm_id } | EffectiveScope::Circle { realm_id, .. } => {
                realm_id
            }
        }
    }
}

/// Admin approval intent attached to an install preview (spec §1b). Not
/// a grant; the commit step intersects it with package requested scopes
/// and Realm/Circle policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ApprovalRequest {
    #[serde(default)]
    pub approve_actions: Vec<String>,
    #[serde(default)]
    pub allow_ghost_actors: bool,
    #[serde(default)]
    pub allow_delegated_native_actors: bool,
    #[serde(default)]
    pub allow_e2ee_join: bool,
    #[serde(default)]
    pub allow_widget: bool,
}

/// `POST /_arkret/self/applets/install/preview` request body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallPreviewRequestBody {
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub approval_request: ApprovalRequest,
}

/// Approved capability scope (commit input). `actions` × `realm_ids`
/// under optional `constraints`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ApprovedScope {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circle_ids: Vec<crate::CircleId>,
    #[serde(default)]
    pub constraints: Vec<crate::GrantConstraint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallDeniedScope {
    pub requested_scope: String,
    pub reason_code: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallEventSubmission {
    pub event_kind: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallCapabilityConstraint {
    pub constraint_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallNamespaceConflict {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_owner: Option<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallE2eeEffect {
    pub requires_mls_join: bool,
    pub plaintext_access: String,
    #[serde(default)]
    pub authorization_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallWidgetEffect {
    pub allow_widget: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<String>,
}

/// Read-only `InstallPlan` returned by install preview (spec §1b). The
/// recomputed `plan_digest` is the anti-tamper seal the commit step
/// re-derives and compares (`applet_install_plan_mismatch`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallPlan {
    pub schema: String,
    pub plan_id: String,
    pub applet_id: String,
    pub package_digest: crate::Hash,
    pub registration_epoch: crate::Hash,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default)]
    pub approved_scopes: Vec<ApprovedScope>,
    #[serde(default)]
    pub denied_scopes: Vec<InstallDeniedScope>,
    #[serde(default)]
    pub events_to_submit: Vec<InstallEventSubmission>,
    #[serde(default)]
    pub capability_constraints: Vec<InstallCapabilityConstraint>,
    #[serde(default)]
    pub namespace_conflicts: Vec<InstallNamespaceConflict>,
    pub e2ee_effect: InstallE2eeEffect,
    pub widget_effect: InstallWidgetEffect,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// `None` until [`seal`](Self::seal); canonical digest excludes
    /// itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<crate::Hash>,
}

impl InstallPlan {
    /// Canonical SHA256 over the plan with `plan_digest` cleared.
    pub fn compute_plan_digest(&self) -> Result<crate::Hash> {
        let mut bare = self.clone();
        bare.plan_digest = None;
        crate::Hash::new(canonical::canonical_sha256(&bare)?).map_err(Into::into)
    }

    /// Compute and stamp `plan_digest`.
    pub fn seal(&mut self) -> Result<()> {
        self.plan_digest = Some(self.compute_plan_digest()?);
        Ok(())
    }
}

/// Bot / ghost membership policy carried into the install commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorPolicy {
    pub bot_membership: String,
    pub ghost_actor_mode: String,
}

/// E2EE policy at install commit time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallE2eePolicy {
    #[serde(default)]
    pub allow_mls_join: bool,
}

/// Widget policy at install commit time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WidgetPolicy {
    #[serde(default)]
    pub allow_widget: bool,
}

/// `POST /_arkret/self/applets/install` request body. MUST carry the
/// preview `plan_digest`; the server fails closed on a mismatch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallCommitRequestBody {
    pub plan_digest: crate::Hash,
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub approved_scopes: Vec<ApprovedScope>,
    pub actor_policy: ActorPolicy,
    #[serde(default)]
    pub e2ee_policy: InstallE2eePolicy,
    #[serde(default)]
    pub widget_policy: WidgetPolicy,
}

/// Install commit response (spec §1b). Carries the fan-out event refs
/// (`ak.applet.registration`, `ak.capability.grant`, membership, E2EE
/// authorization, widget policy).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallCommitOutcome {
    pub ok: bool,
    pub install_id: String,
    pub applet_id: String,
    pub registration_event_ref: String,
    pub registration_epoch: crate::Hash,
    pub bot_actor_id: Did,
    #[serde(default)]
    pub capability_grant_refs: Vec<String>,
    #[serde(default)]
    pub membership_event_refs: Vec<String>,
    #[serde(default)]
    pub e2ee_authorization_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy_ref: Option<String>,
    pub effective_status: String,
    #[serde(default)]
    pub rejected: Vec<Value>,
}

/// `POST /_arkret/self/applets/{applet_id}/revoke` request body. Revoke
/// targets the active install bound to `applet_id` + `effective_scope` and
/// `revoke_mode` (spec §4b): all active grants, widget scoped token,
/// delegated session and (where required) bot/ghost membership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InstallRevokeRequestBody {
    pub effective_scope: EffectiveScope,
    pub reason_code: String,
    pub revoke_mode: crate::AppletRevokeMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<crate::AccountLifecycleProof>,
}
