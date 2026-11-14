//! Pure creation-order and signed-window hygiene over native accepted facts.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    IssuerAuthorityRef, ManagedActorRole,
};
use arkret_wire::{CommitStreamRef, GrantId, RealmCommit};
use chrono::{DateTime, TimeDelta, Utc};

use super::{
    AuthorityError, active, constraint_window, contributes, current_sources, root_from_source,
};

/// Receiver-owned facts loaded under the accepting authority transaction.
/// `creation_commit` covers the immutable original grant Event, never its
/// later revoke/relinquish current revision. This is not a wire DTO or proof.
pub struct GrantAdmissionSource<'a> {
    pub current: &'a CapabilityGrant,
    pub creation_commit: &'a RealmCommit,
}

/// Known applicable shorter limits resolved from existing policy/profile
/// semantics at the native cut. `Ok(None)` means no shorter limit; unknown
/// policy facts are an error, not an unbounded source.
pub type GrantPairLifetimeLimit<'a> = &'a (
        dyn Fn(&str, &arkret_wire::WireResourceSelector) -> Result<Option<u64>, AuthorityError>
            + Sync
    );

/// The exact candidate Commit is finalized by the existing native acceptance
/// path. A failed guard rolls that transaction back. TTL configuration is
/// read at that same cut and never stored as a second first-use deadline.
pub struct GrantAdmissionContext<'a> {
    pub accepting_commit: &'a RealmCommit,
    pub current_root: &'a AuthorityRootRef,
    pub max_lifetime_ms: u64,
    pub shorter_lifetime: Option<GrantPairLifetimeLimit<'a>>,
    pub managed_role: Option<ManagedActorRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedGrantAuthority {
    pub authority_depth: u64,
    pub authority_root_ref: AuthorityRootRef,
}

/// A half-open time interval; absent endpoints are negative/positive infinity.
/// These native values are normalized existing lineage bounds, not predicates
/// authored by a producer or a new protocol language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantWindow {
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)> for GrantWindow {
    fn from((not_before, expires_at): (Option<DateTime<Utc>>, Option<DateTime<Utc>>)) -> Self {
        Self {
            not_before,
            expires_at,
        }
    }
}

impl GrantWindow {
    fn nonempty(self) -> bool {
        match (self.not_before, self.expires_at) {
            (Some(start), Some(end)) => start < end,
            _ => true,
        }
    }
}

/// Exact interval-union inclusion. Separate resource/action contributions
/// must be selected before calling this helper; a convex hull is never used.
pub fn window_union_covers(child: GrantWindow, sources: &[GrantWindow]) -> bool {
    if !child.nonempty() || sources.iter().any(|source| !source.nonempty()) {
        return false;
    }
    let mut intervals = sources.to_vec();
    intervals.sort_by_key(|interval| interval.not_before);
    let mut frontier = child.not_before;
    for source in intervals {
        if let (Some(end), Some(covered)) = (source.expires_at, frontier)
            && end <= covered
        {
            continue;
        }
        let starts_before_frontier = match (source.not_before, frontier) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(start), Some(end)) => start <= end,
        };
        if !starts_before_frontier {
            return false;
        }
        frontier = source.expires_at;
        if frontier.is_none()
            || child
                .expires_at
                .is_some_and(|end| frontier.is_some_and(|covered| covered >= end))
        {
            return true;
        }
    }
    false
}

fn simple_window(
    constraints: &[GrantConstraint],
    action: &str,
) -> Result<GrantWindow, AuthorityError> {
    // Budget/session/recurrence implication needs its original native facts.
    // Never silently reinterpret an unsupported upper bound as infinity.
    if constraints.iter().any(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::Temporal
            && constraint.effect == GrantConstraintEffect::Allow
            && (constraint.applies_to_actions.is_empty()
                || constraint
                    .applies_to_actions
                    .iter()
                    .any(|governed| governed == action))
            && (constraint.max_duration.is_some()
                || constraint.max_session_duration.is_some()
                || constraint.inactivity_timeout.is_some()
                || constraint.expires_after.is_some()
                || constraint.recurrence.is_some())
    }) {
        return Err(AuthorityError::Unproved);
    }
    let result = GrantWindow::from(constraint_window(constraints, action));
    if !result.nonempty() {
        return Err(AuthorityError::Window);
    }
    Ok(result)
}

fn require_finite(action: &str) -> Result<bool, AuthorityError> {
    arkret_schema::capability_action(action)
        .map(|descriptor| descriptor.required_constraints.contains(&"expires_at"))
        .ok_or(AuthorityError::Unproved)
}

fn issuer_rule(
    action: &str,
) -> Result<Option<&'static arkret_wire::NonEventGrantAuthorityRule>, AuthorityError> {
    let mut matches = arkret_wire::PROFILE_REQUIREMENTS
        .values()
        .flat_map(|profile| profile.non_event_grant_authority_rules.iter())
        .filter(|rule| rule.grantable_action == action);
    let rule = matches.next();
    if matches.next().is_some() {
        return Err(AuthorityError::Unproved);
    }
    Ok(rule)
}

fn ordinary_parent_controls(
    parent: &CapabilityGrant,
    child: &CapabilityGrantCreateBody,
) -> Result<(), AuthorityError> {
    let controls = parent
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                && constraint.constraint_subkind.is_none()
                && constraint.effect == GrantConstraintEffect::Allow
        })
        .collect::<Vec<_>>();
    if controls.is_empty() {
        return Err(AuthorityError::Regrant);
    }
    for parent in controls {
        if parent.max_authority_depth == Some(0) {
            return Err(AuthorityError::Regrant);
        }
        let children = child
            .constraints
            .iter()
            .filter(|constraint| {
                constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                    && constraint.constraint_subkind.is_none()
                    && constraint.effect == GrantConstraintEffect::Allow
            })
            .collect::<Vec<_>>();
        if !parent.authority_regrant_allowed.unwrap_or(false)
            && (children.is_empty()
                || children.iter().any(|control| {
                    control.max_authority_depth != Some(0)
                        || control.authority_regrant_allowed != Some(false)
                }))
        {
            return Err(AuthorityError::Regrant);
        }
        if let Some(remaining) = parent.max_authority_depth
            && (children.is_empty()
                || children.iter().any(|control| {
                    control
                        .max_authority_depth
                        .is_none_or(|depth| depth >= remaining)
                }))
        {
            return Err(AuthorityError::Depth);
        }
    }
    for constraint in parent
        .constraints
        .iter()
        .filter(|constraint| constraint.effect != GrantConstraintEffect::Allow)
    {
        if !child.constraints.contains(constraint) {
            return Err(AuthorityError::Constraints);
        }
    }
    Ok(())
}

/// Check creation order, unique root/depth and pair-specific window coverage.
/// The accepting caller independently verifies original Event/body/source
/// authenticity, complete business constraints, approvals and current policy.
/// Root/owned-source qualification is the supplied native same-cut predicate;
/// this function never turns a source reference into authorization by itself.
pub fn validate_grant_admission(
    child: &CapabilityGrantCreateBody,
    context: &GrantAdmissionContext<'_>,
    sources: &BTreeMap<GrantId, GrantAdmissionSource<'_>>,
    source_current: impl Fn(&IssuerAuthorityRef) -> bool,
) -> Result<DerivedGrantAuthority, AuthorityError> {
    let accepting = context.accepting_commit;
    let root_realm = match context.current_root {
        AuthorityRootRef::RealmRoot { realm_id, .. }
        | AuthorityRootRef::OwnedAgent { realm_id, .. } => realm_id,
    };
    if child.realm_id.as_ref() != Some(&accepting.realm_id)
        || root_realm != &accepting.realm_id
        || accepting.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: accepting.realm_id.clone(),
            })
        || child.issuer_authority_refs.is_empty()
        || child.actions.is_empty()
        || child.resources.is_empty()
        || child.issuer_id.validate().is_err()
    {
        return Err(AuthorityError::Coverage);
    }
    accepting
        .validate_content_address()
        .map_err(|_| AuthorityError::Unproved)?;
    if sources.contains_key(&GrantId::from_event_id(&accepting.event_ref)) {
        return Err(AuthorityError::Coverage);
    }
    child
        .validate_owned_agent_shape()
        .map_err(|_| AuthorityError::Regrant)?;
    let mut seen = BTreeSet::new();
    let mut deepest = 0;
    let mut parents = Vec::new();
    for reference in &child.issuer_authority_refs {
        let key = arkret_canonical::canonical_json_bytes(reference)
            .map_err(|_| AuthorityError::Unproved)?;
        if !seen.insert(key) {
            return Err(AuthorityError::Coverage);
        }
        match reference {
            IssuerAuthorityRef::Grant { grant_id } => {
                let source = sources.get(grant_id).ok_or(AuthorityError::Unproved)?;
                let parent = source.current;
                let creation = source.creation_commit;
                if parent.id != *grant_id
                    || parent.realm_id != child.realm_id
                    || !matches!(&parent.subject, super::CapabilitySubject::Actor(actor) if actor == &child.issuer_id)
                    || parent.authority_root_ref != *context.current_root
                    || creation.realm_id != accepting.realm_id
                    || creation.stream_ref != accepting.stream_ref
                    || GrantId::from_event_id(&creation.event_ref) != *grant_id
                    || creation.stream_position >= accepting.stream_position
                {
                    return Err(AuthorityError::Coverage);
                }
                creation
                    .validate_content_address()
                    .map_err(|_| AuthorityError::Unproved)?;
                if !(1..=4).contains(&parent.authority_depth)
                    || matches!(
                        parent.authority_root_ref,
                        AuthorityRootRef::OwnedAgent { .. }
                    )
                {
                    return Err(AuthorityError::Depth);
                }
                deepest = deepest.max(parent.authority_depth);
                if context.managed_role.is_none() {
                    ordinary_parent_controls(parent, child)?;
                }
                parents.push(parent);
            }
            _ => {
                if root_from_source(reference).as_ref() != Some(context.current_root)
                    || !source_current(reference)
                {
                    return Err(AuthorityError::Closed);
                }
            }
        }
    }
    let authority_depth = deepest
        .checked_add(1)
        .filter(|depth| *depth <= 4)
        .ok_or(AuthorityError::Depth)?;
    if let Some(role) = context.managed_role {
        super::validate_managed_service_sources(child, &parents, role)?;
    }
    let grants = sources
        .iter()
        .map(|(id, source)| (id.clone(), (*source.current).clone()))
        .collect::<BTreeMap<_, _>>();
    let mut used = BTreeSet::new();
    for action in &child.actions {
        let rule = issuer_rule(action)?;
        let parent_action = rule.map_or(action.as_str(), |rule| rule.issuer_action);
        let finite = require_finite(action)?;
        let declared = simple_window(&child.constraints, action)?;
        if finite && declared.expires_at.is_none() {
            return Err(AuthorityError::Window);
        }
        for resource in &child.resources {
            let mut windows = Vec::new();
            for (index, reference) in child.issuer_authority_refs.iter().enumerate() {
                let mut source = match reference {
                    IssuerAuthorityRef::Grant { grant_id } => {
                        let parent = sources[grant_id].current;
                        if !contributes(parent, parent_action, resource) {
                            continue;
                        }
                        let bounds = simple_window(&parent.constraints, parent_action)?;
                        if !active(parent, accepting.committed_at, parent_action) {
                            return Err(AuthorityError::Closed);
                        }
                        current_sources(
                            parent,
                            parent_action,
                            resource,
                            &grants,
                            accepting.committed_at,
                            &source_current,
                        )?;
                        bounds
                    }
                    IssuerAuthorityRef::RealmRoot { .. } => {
                        if rule.is_some_and(|rule| !rule.issuer_owner_authority_allowed)
                            || !crate::owner_may_grant(parent_action).unwrap_or(false)
                        {
                            continue;
                        }
                        GrantWindow {
                            not_before: None,
                            expires_at: None,
                        }
                    }
                    IssuerAuthorityRef::OwnedAgent { .. } => GrantWindow {
                        not_before: None,
                        expires_at: None,
                    },
                };
                if source.expires_at.is_none() && finite {
                    let shorter = context
                        .shorter_lifetime
                        .map(|limit| limit(action, resource))
                        .transpose()?
                        .flatten();
                    let maximum = shorter.map_or(context.max_lifetime_ms, |bound| {
                        bound.min(context.max_lifetime_ms)
                    });
                    let milliseconds =
                        i64::try_from(maximum).map_err(|_| AuthorityError::Window)?;
                    let duration =
                        TimeDelta::try_milliseconds(milliseconds).ok_or(AuthorityError::Window)?;
                    source.expires_at = Some(
                        accepting
                            .committed_at
                            .checked_add_signed(duration)
                            .ok_or(AuthorityError::Window)?,
                    );
                }
                used.insert(index);
                windows.push(source);
            }
            if windows.is_empty() {
                return Err(AuthorityError::Coverage);
            }
            if !window_union_covers(declared, &windows) {
                return Err(AuthorityError::Window);
            }
        }
    }
    if used.len() != child.issuer_authority_refs.len() {
        return Err(AuthorityError::Coverage);
    }
    Ok(DerivedGrantAuthority {
        authority_depth,
        authority_root_ref: context.current_root.clone(),
    })
}

#[cfg(test)]
mod tests;
