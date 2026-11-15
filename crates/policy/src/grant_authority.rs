//! Typed authority contributions for capability issuance and current use.
//!
//! References retain their original grants and subjects. An unrelated action
//! does not close the exercised action, and no copied grant becomes a quota
//! or approval source.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilityGrantStatus, CapabilitySubject, GrantConstraint,
    GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind, IssuerAuthorityRef,
    ManagedActorRole,
};
use arkret_wire::{ActorId, EvaluationClass, GrantId, WireResourceSelector};
use chrono::{DateTime, Utc};

use crate::grant_evaluation::resource_selector_covers;

mod admission;
pub use admission::{
    DerivedGrantAuthority, GrantAdmissionContext, GrantAdmissionSource, GrantPairLifetimeLimit,
    GrantWindow, validate_grant_admission, window_union_covers,
};

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

fn candidate_active(grant: &CapabilityGrant, at: DateTime<Utc>) -> bool {
    let from = grant
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::Temporal
                && constraint.effect == GrantConstraintEffect::Allow
                && constraint.applies_to_actions.is_empty()
                && constraint.recurrence.is_none()
        })
        .filter_map(|constraint| constraint.not_before)
        .max();
    grant.status == CapabilityGrantStatus::Active
        && from.is_none_or(|from| from <= at)
        && crate::grant_evaluation::capability_grant_expires_at(grant)
            .is_none_or(|until| at < until)
}

/// Qualify a current action's numeric temporal bounds, not its permission.
///
/// The independent global lifecycle stays strict. Local action/recurrence
/// bounds retain the registered inclusive temporal tolerance; their complete
/// predicates, required facts and every other constraint still belong to the
/// business evaluator. Admission window geometry is unchanged.
pub fn current_action_window_is_open(
    grant: &CapabilityGrant,
    action: &str,
    at: DateTime<Utc>,
) -> bool {
    if !candidate_active(grant, at) {
        return false;
    }
    let descriptor = arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
        arkret_identifiers::ProtocolTimeToleranceScenario::TemporalConstraint,
    );
    let skew = chrono::TimeDelta::milliseconds(descriptor.tolerance_ms());
    let (Some(earliest), Some(latest)) = (at.checked_sub_signed(skew), at.checked_add_signed(skew))
    else {
        return false;
    };
    grant
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::Temporal
                && constraint.effect == GrantConstraintEffect::Allow
                && (!constraint.applies_to_actions.is_empty() || constraint.recurrence.is_some())
                && (constraint.applies_to_actions.is_empty()
                    || constraint
                        .applies_to_actions
                        .iter()
                        .any(|named| named == action))
        })
        .all(|constraint| {
            constraint.not_before.is_none_or(|from| from <= latest)
                && constraint.expires_at.is_none_or(|until| earliest <= until)
        })
}

#[derive(Clone, Copy)]
enum SourceWindow {
    /// Only the terminal candidate's own local allows remain unevaluated.
    TerminalCandidate,
    /// Positive authority for an actual action at the current cut.
    Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("grant_exceeds_issuer_authority")]
    Coverage,
    #[error("authority_regrant_denied")]
    Regrant,
    #[error("authority_expiry_widening")]
    Window,
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
    let CapabilitySubject::Actor(subject) = &child.subject else {
        return Err(AuthorityError::Coverage);
    };
    let Some(identity) = subject.as_realm_actor_id() else {
        return Err(AuthorityError::Coverage);
    };
    if subject.validate().is_err() || child.realm_id.as_ref() != Some(&identity.realm_id) {
        return Err(AuthorityError::Coverage);
    }
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
        expected.executed_by = Some(subject.clone());
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
                .any(|candidate| retained(constraint, candidate, subject))
            {
                return Err(AuthorityError::Constraints);
            }
        }
    }
    for action in &child.actions {
        let child_window = GrantWindow::from(constraint_window(&child.constraints, action));
        for resource in &child.resources {
            let covering: Vec<_> = parents
                .iter()
                .filter(|parent| contributes(parent, action, resource))
                .map(|parent| GrantWindow::from(window(parent, action)))
                .collect();
            if covering.is_empty() {
                return Err(AuthorityError::Coverage);
            }
            if !window_union_covers(child_window, &covering) {
                return Err(AuthorityError::Window);
            }
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
fn retained(parent: &GrantConstraint, child: &GrantConstraint, subject: &ActorId) -> bool {
    let mut expected = parent.clone();
    match (parent.constraint_kind, parent.constraint_subkind) {
        (GrantConstraintKind::AuthorityControl, Some(GrantConstraintSubkind::AppletAuthority)) => {
            expected.executed_by = Some(subject.clone())
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
                .max_operation_count
                .is_some_and(|p| child.max_operation_count.is_none_or(|c| c > p))
                || parent
                    .burst_operation_count
                    .is_some_and(|p| child.burst_operation_count.is_none_or(|c| c > p))
            {
                return false;
            }
            expected.max_operation_count = child.max_operation_count;
            expected.burst_operation_count = child.burst_operation_count;
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
    sources_with_window(
        grant,
        action,
        target,
        grants,
        at,
        root_current,
        SourceWindow::Action,
    )
}

/// Current candidates for the complete global refusal set of one operation.
///
/// This terminal grant's local allow failure only removes its positive path.
/// It cannot delete its still-current deny/quarantine/review. Every actual
/// contributing ancestor retains the original full action-window gate: an
/// expired source cannot continue to impose a delegated child's refusals.
/// All root, source-subject, resource, depth and revocation checks remain
/// mandatory. This function grants no positive
/// permission: after merging all candidate refusals, an allowed path must
/// still pass `current_sources` and its complete source constraints.
pub fn current_candidate_sources<'g>(
    grant: &'g CapabilityGrant,
    action: &str,
    target: &WireResourceSelector,
    grants: &'g BTreeMap<GrantId, CapabilityGrant>,
    at: DateTime<Utc>,
    root_current: impl Fn(&IssuerAuthorityRef) -> bool,
) -> Result<Vec<&'g CapabilityGrant>, AuthorityError> {
    sources_with_window(
        grant,
        action,
        target,
        grants,
        at,
        root_current,
        SourceWindow::TerminalCandidate,
    )
}

fn sources_with_window<'g>(
    grant: &'g CapabilityGrant,
    action: &str,
    target: &WireResourceSelector,
    grants: &'g BTreeMap<GrantId, CapabilityGrant>,
    at: DateTime<Utc>,
    root_current: impl Fn(&IssuerAuthorityRef) -> bool,
    window: SourceWindow,
) -> Result<Vec<&'g CapabilityGrant>, AuthorityError> {
    if !contributes(grant, action, target) {
        return Err(AuthorityError::Coverage);
    }
    let mut output = BTreeMap::new();
    walk(
        grant,
        action,
        target,
        grants,
        at,
        &root_current,
        window,
        &mut output,
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
    window: SourceWindow,
    output: &mut BTreeMap<GrantId, &'g CapabilityGrant>,
) -> Result<(), AuthorityError> {
    if !(1..=4).contains(&grant.authority_depth) {
        return Err(AuthorityError::Depth);
    }
    grant
        .validate_authority_shape()
        .map_err(|_| AuthorityError::Unproved)?;
    if output.contains_key(&grant.id) {
        return Ok(());
    }
    let is_active = match window {
        SourceWindow::TerminalCandidate => candidate_active(grant, at),
        SourceWindow::Action => current_action_window_is_open(grant, action, at),
    };
    if !is_active {
        return Err(AuthorityError::Closed);
    }
    if grant.issuer_authority_refs.is_empty() {
        return Err(AuthorityError::Unproved);
    }
    let mut deepest = 0;
    for source in &grant.issuer_authority_refs {
        if let IssuerAuthorityRef::Grant { grant_id } = source {
            let parent = grants.get(grant_id).ok_or(AuthorityError::Unproved)?;
            deepest = deepest.max(parent.authority_depth);
        }
    }
    if deepest.checked_add(1) != Some(grant.authority_depth) {
        return Err(AuthorityError::Depth);
    }
    let mut contributed = false;
    for source in &grant.issuer_authority_refs {
        match source {
            IssuerAuthorityRef::OwnedAgent { .. } => return Err(AuthorityError::Regrant),
            IssuerAuthorityRef::RealmRoot { .. } => {
                if root_from_source(source).as_ref() != Some(&grant.authority_root_ref) {
                    return Err(AuthorityError::Unproved);
                }
                if !root_current(source) {
                    return Err(AuthorityError::Closed);
                }
                // This immutable source was qualified at creation, including
                // any registered profile issuer-action mapping and evidence.
                // Current root continuity does not re-issue that grant.
                contributed = true;
            }
            IssuerAuthorityRef::Grant { grant_id } => {
                let parent = grants.get(grant_id).ok_or(AuthorityError::Unproved)?;
                if !matches!(&parent.subject,CapabilitySubject::Actor(actor) if actor==&grant.issuer_id)
                    || parent.realm_id != grant.realm_id
                    || parent.authority_root_ref != grant.authority_root_ref
                {
                    return Err(AuthorityError::Coverage);
                }
                if !contributes(parent, action, target) {
                    continue;
                }
                if parent.authority_depth >= grant.authority_depth {
                    return Err(AuthorityError::Depth);
                }
                if !parent.constraints.iter().any(|c| {
                    c.constraint_kind == GrantConstraintKind::AuthorityControl
                        && c.constraint_subkind.is_none()
                }) {
                    return Err(AuthorityError::Regrant);
                }
                // A child's refusal is effective only while its issuer's
                // actual action authority is current. Only the initial
                // terminal grant may defer its own local allow predicates.
                walk(
                    parent,
                    action,
                    target,
                    grants,
                    at,
                    root_current,
                    SourceWindow::Action,
                    output,
                )?;
                contributed = true;
            }
        }
    }
    if !contributed {
        return Err(AuthorityError::Coverage);
    }
    output.insert(grant.id.clone(), grant);
    Ok(())
}

fn root_from_source(source: &IssuerAuthorityRef) -> Option<AuthorityRootRef> {
    match source {
        IssuerAuthorityRef::RealmRoot {
            realm_id,
            authority_event_ref,
            authority_generation,
        } => Some(AuthorityRootRef::RealmRoot {
            realm_id: realm_id.clone(),
            authority_event_ref: authority_event_ref.clone(),
            authority_generation: *authority_generation,
        }),
        IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id,
            controller_join_event_id,
            agent_join_event_id,
        } => Some(AuthorityRootRef::OwnedAgent {
            realm_id: realm_id.clone(),
            controller_account_id: controller_account_id.clone(),
            controller_join_event_id: controller_join_event_id.clone(),
            agent_join_event_id: agent_join_event_id.clone(),
        }),
        IssuerAuthorityRef::Grant { .. } => None,
    }
}

/// Derive cache invalidation only from validated semantic dependencies.
/// The dependency lists are receiver-owned outputs of registered selectors
/// and constraint evaluators, never producer cache hints. Unknown critical
/// semantics cannot establish a reusable allow cache.
pub fn moderation_dependency(
    actions: &[String],
    subject_dependencies: &[&str],
    constraint_dependencies: &[&str],
    semantics_known: bool,
) -> Result<bool, AuthorityError> {
    if !semantics_known {
        return Err(AuthorityError::Unproved);
    }
    Ok(actions.iter().any(|action| {
        matches!(
            action.as_str(),
            "ak.moderation.decision" | "ak.moderation.decision.lift"
        )
    }) || subject_dependencies.contains(&"moderation_state")
        || constraint_dependencies.contains(&"moderation_state"))
}

/// Current refusal candidates held by this complete Actor for one operation.
/// Known globally inactive lineages do not contribute. Unproved or invalid
/// lineages fail the entire decision, including its global refusal set.
/// This list is not a set of positive paths: use `current_sources` after
/// global refusal evaluation before counting an allowed dependency.
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
        match current_candidate_sources(grant, action, target, grants, at, &root_current) {
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

#[cfg(test)]
mod current_tests;
