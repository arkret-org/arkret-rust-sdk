//! SDK authorization shim.
//!
//! The capability-based authorization layer (selectors, constraints, the
//! evaluation engine, grant projection / delegation helpers, and the
//! approval-strand workflow) now lives in `arkret-policy`. This module keeps
//! the historical `arkret::authz::*` / `arkret_sdk::authz::*` paths stable and
//! hosts the two `RealmState`-coupled bridges: `arkret-policy` is forbidden
//! from depending on the reducer runtime (`arkret-state`), so the functions
//! that read a `RealmState` live here in the umbrella instead.

pub use arkret_policy::authz::*;

use crate::Result;
use crate::resolver::RealmState;

/// Extract active grant/delegate capability events from a resolved Realm
/// state.
///
/// Event content MUST be the spec grant artifact (`ak.schema.capability.v1`).
/// The reducer runtime (`arkret-state`) owns `RealmState`; this bridge
/// iterates its `resolved_state` and defers each event to
/// [`arkret_policy::authz::capability_grant_from_resolved_event`], keeping
/// `arkret-policy` free of any dependency on the state runtime.
pub fn capability_grants_from_realm_state(
    state: &RealmState,
) -> Result<Vec<arkret_core::CapabilityGrant>> {
    let mut grants = Vec::new();
    for event in state.resolved_state.values() {
        if !matches!(
            event.kind.as_str(),
            "ak.capability.grant" | "ak.capability.delegate"
        ) {
            continue;
        }
        grants.push(capability_grant_from_resolved_event(
            event,
            Some(state.realm_id.clone()),
        )?);
    }
    Ok(grants)
}

/// `RealmState`-aware entry point for the [`AuthzEngine`], preserved from
/// before the authorization layer moved to `arkret-policy`. Bring this trait
/// into scope to call `check_authorization_from_realm_state` on an engine.
pub trait AuthzEngineRealmStateExt {
    /// Check authorization against grants reduced into a `RealmState`.
    fn check_authorization_from_realm_state(
        &mut self,
        ctx: &AuthzContext,
        state: &RealmState,
    ) -> EngineDecision;
}

impl AuthzEngineRealmStateExt for AuthzEngine {
    fn check_authorization_from_realm_state(
        &mut self,
        ctx: &AuthzContext,
        state: &RealmState,
    ) -> EngineDecision {
        match capability_grants_from_realm_state(state) {
            Ok(grants) => self.check_authorization(ctx, &grants),
            Err(err) => EngineDecision::Deny {
                reason: format!("invalid capability state: {}", err),
            },
        }
    }
}
