//! Typed authority contributions for capability issuance and current use.
//!
//! References retain their original grants and subjects. An unrelated action
//! does not close the exercised action, and no copied grant becomes a quota
//! or approval source.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilityGrantStatus, CapabilitySubject, GrantConstraint,
    GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind, IssuerAuthorityRef,
    ManagedActorRole,
};
use arkret_wire::{ActorId, EvaluationClass, GrantId, WireResourceSelector};
use chrono::{DateTime, Utc};

use crate::grant_evaluation::resource_selector_covers;

/// Whether this source contributes authority to an actual action and selector.
pub fn contributes(
    parent: &CapabilityGrant,
    action: &str,
    resource: &WireResourceSelector,
) -> bool {
    parent
        .actions
        .iter()
        .any(|a| crate::action_grants_authority_for(a, action).unwrap_or(false))
        && parent
            .resources
            .iter()
            .any(|r| resource_selector_covers(r, resource))
}

fn window(grant: &CapabilityGrant, action: &str) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    constraint_window(&grant.constraints, action)
}
fn constraint_window(
    constraints: &[GrantConstraint],
    action: &str,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let temporal = || {
        constraints.iter().filter(|c| {
            c.constraint_kind == GrantConstraintKind::Temporal
                && c.effect == GrantConstraintEffect::Allow
                && (c.applies_to_actions.is_empty()
                    || c.applies_to_actions.iter().any(|a| a.as_str() == action))
        })
    };
    (
        temporal().filter_map(|c| c.not_before).max(),
        temporal().filter_map(|c| c.expires_at).min(),
    )
}
fn active(grant: &CapabilityGrant, at: DateTime<Utc>, action: &str) -> bool {
    let (from, until) = window(grant, action);
    grant.status == CapabilityGrantStatus::Active
        && from.is_none_or(|v| v <= at)
        && until.is_none_or(|v| at < v)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("grant_exceeds_issuer_authority")]
    Coverage,
    #[error("authority_regrant_denied")]
    Regrant,
    #[error("authority_expiry_widening")]
    Window,
    #[error("authority_cycle")]
    Cycle,
    #[error("authority_depth_exceeded")]
    Depth,
    #[error("grant_revoked_upstream")]
    Closed,
    #[error("revision_unavailable")]
    Unproved,
    #[error("managed child drops or widens parent constraints")]
    Constraints,
}

/// Validate every real Service source of a terminal Bot/Ghost grant. Coverage
/// is a union of action/resource contributions; temporal hygiene is computed
/// separately for each action, as required by capabilities section 10.1.
/// Status and current roots are checked by the accepting caller at its cut.
pub fn validate_managed_service_sources(
    child: &CapabilityGrantCreateBody,
    parents: &[&CapabilityGrant],
    role: ManagedActorRole,
) -> Result<(), AuthorityError> {
    let CapabilitySubject::Actor(account @ ActorId::Account { .. }) = &child.subject else {
        return Err(AuthorityError::Coverage);
    };
    if !matches!(child.issuer_id, ActorId::Service { .. })
        || parents.is_empty()
        || parents.len() != child.issuer_authority_refs.len()
    {
        return Err(AuthorityError::Coverage);
    }
    let mut ids = BTreeSet::new();
    let child_binding = binding(&child.constraints).ok_or(AuthorityError::Constraints)?;
    for parent in parents {
        if !ids.insert(&parent.id)
            || !child.issuer_authority_refs.iter().any(
                |r| matches!(r, IssuerAuthorityRef::Grant { grant_id } if grant_id == &parent.id),
            )
            || !matches!(&parent.subject, CapabilitySubject::Actor(actor) if actor == &child.issuer_id)
            || parent.realm_id != child.realm_id
            || !child
                .actions
                .iter()
                .any(|a| child.resources.iter().any(|r| contributes(parent, a, r)))
        {
            return Err(AuthorityError::Coverage);
        }
        let mut expected = binding(&parent.constraints)
            .ok_or(AuthorityError::Constraints)?
            .clone();
        if expected.executed_by.as_ref() != Some(&child.issuer_id) {
            return Err(AuthorityError::Constraints);
        }
        expected.executed_by = Some(account.clone());
        if &expected != child_binding {
            return Err(AuthorityError::Constraints);
        }
        let controls: Vec<_> = parent
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::AuthorityControl
                    && c.constraint_subkind.is_none()
            })
            .collect();
        if controls.is_empty()
            || controls.iter().any(|c| {
                !c.allowed_managed_actor_roles.contains(&role)
                    || (c.authority_regrant_allowed == Some(true)
                        && c.max_authority_depth == Some(0))
            })
        {
            return Err(AuthorityError::Regrant);
        }
        let terminal: Vec<_> = child
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::AuthorityControl
                    && c.constraint_subkind.is_none()
            })
            .collect();
        if terminal.is_empty()
            || terminal.iter().any(|c| {
                c.max_authority_depth != Some(0) || c.authority_regrant_allowed != Some(false)
            })
        {
            return Err(AuthorityError::Regrant);
        }
        for constraint in &parent.constraints {
            if !child
                .constraints
                .iter()
                .any(|candidate| retained(constraint, candidate, account))
            {
                return Err(AuthorityError::Constraints);
            }
        }
    }
    for action in &child.actions {
        let (child_from, child_until) = constraint_window(&child.constraints, action);
        for resource in &child.resources {
            if !parents.iter().any(|p| contributes(p, action, resource)) {
                return Err(AuthorityError::Coverage);
            }
        }
        let covering: Vec<_> = parents
            .iter()
            .filter(|p| child.resources.iter().any(|r| contributes(p, action, r)))
            .collect();
        let from = if covering.iter().any(|p| window(p, action).0.is_none()) {
            None
        } else {
            covering.iter().filter_map(|p| window(p, action).0).min()
        };
        let until = if covering.iter().any(|p| window(p, action).1.is_none()) {
            None
        } else {
            covering.iter().filter_map(|p| window(p, action).1).max()
        };
        if from.is_some_and(|v| child_from.is_none_or(|c| c < v))
            || until.is_some_and(|v| child_until.is_none_or(|c| c > v))
        {
            return Err(AuthorityError::Window);
        }
    }
    Ok(())
}
fn binding(constraints: &[GrantConstraint]) -> Option<&GrantConstraint> {
    let mut found = constraints
        .iter()
        .filter(|c| c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority));
    let binding = found.next()?;
    (found.next().is_none()
        && binding.constraint_kind == GrantConstraintKind::AuthorityControl
        && binding.effect == GrantConstraintEffect::Allow
        && binding.evaluation_class == Some(EvaluationClass::GrantLocal)
        && binding.applet_id.is_some()
        && binding.registration_epoch.is_some())
    .then_some(binding)
}
fn retained(parent: &GrantConstraint, child: &GrantConstraint, account: &ActorId) -> bool {
    let mut expected = parent.clone();
    match (parent.constraint_kind, parent.constraint_subkind) {
        (GrantConstraintKind::AuthorityControl, Some(GrantConstraintSubkind::AppletAuthority)) => {
            expected.executed_by = Some(account.clone())
        }
        (GrantConstraintKind::AuthorityControl, None) => {
            if !child
                .allowed_managed_actor_roles
                .iter()
                .all(|r| parent.allowed_managed_actor_roles.contains(r))
            {
                return false;
            }
            expected.max_authority_depth = Some(0);
            expected.authority_regrant_allowed = Some(false);
            expected.allowed_managed_actor_roles = child.allowed_managed_actor_roles.clone();
        }
        (GrantConstraintKind::Temporal, _) if parent.effect == GrantConstraintEffect::Allow => {
            // Window bounds are combined per action above, not per reference.
            expected.not_before = child.not_before;
            expected.expires_at = child.expires_at;
        }
        (GrantConstraintKind::Quota, Some(GrantConstraintSubkind::Rate))
            if parent.effect == GrantConstraintEffect::Allow =>
        {
            if parent
                .max_operations
                .is_some_and(|p| child.max_operations.is_none_or(|c| c > p))
                || parent
                    .burst
                    .is_some_and(|p| child.burst.is_none_or(|c| c > p))
            {
                return false;
            }
            expected.max_operations = child.max_operations;
            expected.burst = child.burst;
        }
        _ => {}
    }
    &expected == child
}

/// Return each original contributing ancestor once for one exercised action.
/// All references contributing to that action/target must remain active. A
/// source of another action remains audit provenance, not a current gate for
/// this action. Missing rows fail closed because their contribution is unknown.
/// The caller provides its verified, same-cut root-anchor predicate.
pub fn current_sources<'g>(
    grant: &'g CapabilityGrant,
    action: &str,
    target: &WireResourceSelector,
    grants: &'g BTreeMap<GrantId, CapabilityGrant>,
    at: DateTime<Utc>,
    root_current: impl Fn(&IssuerAuthorityRef) -> bool,
) -> Result<Vec<&'g CapabilityGrant>, AuthorityError> {
    let mut output = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    walk(
        grant,
        action,
        target,
        grants,
        at,
        &root_current,
        &mut visiting,
        &mut output,
        0,
    )?;
    output.remove(&grant.id);
    Ok(output.into_values().collect())
}
#[expect(
    clippy::too_many_arguments,
    reason = "Each bounded traversal input and original source remains explicit."
)]
fn walk<'g>(
    grant: &'g CapabilityGrant,
    action: &str,
    target: &WireResourceSelector,
    grants: &'g BTreeMap<GrantId, CapabilityGrant>,
    at: DateTime<Utc>,
    root_current: &impl Fn(&IssuerAuthorityRef) -> bool,
    visiting: &mut BTreeSet<GrantId>,
    output: &mut BTreeMap<GrantId, &'g CapabilityGrant>,
    depth: usize,
) -> Result<(), AuthorityError> {
    if depth >= 4 {
        return Err(AuthorityError::Depth);
    }
    if !visiting.insert(grant.id.clone()) {
        return Err(AuthorityError::Cycle);
    }
    if !active(grant, at, action) {
        return Err(AuthorityError::Closed);
    }
    if grant.issuer_authority_refs.is_empty() {
        return Err(AuthorityError::Unproved);
    }
    let mut contributed = false;
    for source in &grant.issuer_authority_refs {
        match source {
            IssuerAuthorityRef::OwnedAgent { .. } => return Err(AuthorityError::Regrant),
            IssuerAuthorityRef::RealmRoot { .. } => {
                if !root_current(source) {
                    return Err(AuthorityError::Closed);
                }
                if crate::owner_may_grant(action).unwrap_or(false) {
                    contributed = true;
                }
            }
            IssuerAuthorityRef::Grant { grant_id } => {
                let parent = grants.get(grant_id).ok_or(AuthorityError::Unproved)?;
                if !matches!(&parent.subject,CapabilitySubject::Actor(actor) if actor==&grant.issuer_id)
                    || parent.realm_id != grant.realm_id
                {
                    return Err(AuthorityError::Coverage);
                }
                if !contributes(parent, action, target) {
                    continue;
                }
                if !parent.constraints.iter().any(|c| {
                    c.constraint_kind == GrantConstraintKind::AuthorityControl
                        && c.constraint_subkind.is_none()
                }) {
                    return Err(AuthorityError::Regrant);
                }
                walk(
                    parent,
                    action,
                    target,
                    grants,
                    at,
                    root_current,
                    visiting,
                    output,
                    depth + 1,
                )?;
                contributed = true;
            }
        }
    }
    visiting.remove(&grant.id);
    if !contributed {
        return Err(AuthorityError::Coverage);
    }
    output.insert(grant.id.clone(), grant);
    Ok(())
}

/// Effective grants held by this complete Actor for one actual operation.
/// Known inactive lineages do not contribute. Unproved or invalid lineages
/// fail the entire decision, including its global refusal set.
pub fn current_subject_grants<'g>(
    actor: &ActorId,
    action: &str,
    target: &WireResourceSelector,
    grants: &'g BTreeMap<GrantId, CapabilityGrant>,
    at: DateTime<Utc>,
    root_current: impl Fn(&IssuerAuthorityRef) -> bool,
) -> Result<Vec<&'g CapabilityGrant>, AuthorityError> {
    let mut current = Vec::new();
    for grant in grants.values().filter(|grant| {
        matches!(&grant.subject,CapabilitySubject::Actor(subject) if subject==actor)
            && contributes(grant, action, target)
    }) {
        match current_sources(grant, action, target, grants, at, &root_current) {
            Ok(_) => current.push(grant),
            Err(AuthorityError::Closed) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(current)
}

/// An explicitly approved Service business source for this managed role. A
/// member-derived read does not need an invented Account child grant.
/// Structural qualification only: current lineage, constraints and the actual
/// resource target remain separate mandatory checks.
pub fn managed_service_source(
    grant: &CapabilityGrant,
    service: &ActorId,
    applet: &arkret_wire::AppletId,
    epoch: &arkret_wire::Hash,
    role: ManagedActorRole,
    action: &str,
) -> bool {
    let Some(binding) = binding(&grant.constraints) else {
        return false;
    };
    let controls = grant
        .constraints
        .iter()
        .filter(|c| {
            c.constraint_kind == GrantConstraintKind::AuthorityControl
                && c.constraint_subkind.is_none()
        })
        .collect::<Vec<_>>();
    matches!(service, ActorId::Service { .. })
        && grant
            .actions
            .iter()
            .any(|held| crate::action_grants_authority_for(held, action).unwrap_or(false))
        && matches!(&grant.subject,CapabilitySubject::Actor(subject) if subject==service)
        && binding.applet_id.as_ref() == Some(applet)
        && binding.executed_by.as_ref() == Some(service)
        && binding.registration_epoch.as_ref() == Some(epoch)
        && (binding.applies_to_actions.is_empty()
            || binding
                .applies_to_actions
                .iter()
                .any(|a| a.as_str() == action))
        && !controls.is_empty()
        && controls
            .iter()
            .all(|c| c.allowed_managed_actor_roles.contains(&role))
}
