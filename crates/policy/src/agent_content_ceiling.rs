//! Read-only Agent ceilings shared by admission and recipient products.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_wire::{AccountId, CapabilityActionId, PolicyEffect, RealmId, ServiceOperationId};

use crate::agent_management::{AgentManagementContext, evaluate_agent_management};
use crate::grant_evaluation::AuthorizationOperation;
fn unavailable(detail: impl std::fmt::Display) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(format!("failed_precondition: {detail}"))
}

/// A key/provision scope is a hard ceiling, never a content grant. The caller
/// independently verifies the scope's accepted provenance and ordinary authority.
/// Every supplied action is an actual content action, not an aggregate fallback.
pub fn require_key_scope_content_ceiling(
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    operation: &AuthorizationOperation<'_>,
) -> arkret_wire::Result<()> {
    use crate::grant_evaluation::GrantEvaluation;
    if scope.resources.is_empty()
        || operation.actions.is_empty()
        || scope.actions.iter().any(|action| {
            arkret_schema::capability_action(action).is_none()
                && ServiceOperationId::from_wire(action).is_none()
        })
        || operation.actions.iter().any(|action| {
            arkret_schema::capability_action(action)
                .is_none_or(|descriptor| descriptor.event_mapping_kind == "aggregate_admin")
                || ServiceOperationId::from_wire(action).is_some()
                || !scope.actions.iter().any(|allowed| allowed == action)
        })
        || !concrete_content_target(operation.target)
    {
        return Err(unavailable(
            "Agent content scope action or target is unavailable",
        ));
    }
    let resources = scope
        .resources
        .iter()
        .map(key_scope_content_selector)
        .collect::<arkret_wire::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let verdict = if resources.is_empty() {
        crate::grant_evaluation::evaluate_constraint_ceiling(operation, &scope.constraints)
    } else {
        crate::grant_evaluation::evaluate_resource_constraint_ceiling(
            operation,
            &resources,
            &scope.constraints,
        )
    };
    match verdict {
        GrantEvaluation::Allowed(_) => Ok(()),
        GrantEvaluation::Denied | GrantEvaluation::Unsatisfied | GrantEvaluation::Unnamed => {
            Err(arkret_wire::WireError::Protocol(
                "capability_denied: Agent content ceiling is not satisfied".into(),
            ))
        }
        GrantEvaluation::Quarantined | GrantEvaluation::RequiresReview => Err(unavailable(
            "Agent content ceiling requires unresolved quarantine or review evidence",
        )),
    }
}

pub fn concrete_content_target(target: &arkret_wire::WireResourceSelector) -> bool {
    use arkret_wire::ResourceSelectorKind as Kind;
    if target.validate().is_err() {
        return false;
    }
    match target.kind {
        Kind::Realm | Kind::Notification | Kind::ReadCursor => target.realm_id.is_some(),
        Kind::Space => target.space_id.is_some(),
        Kind::Circle => target.circle_id.is_some(),
        Kind::Strand => target.strand_id.is_some(),
        Kind::Message => target.message_id.is_some(),
        Kind::Morph => target.morph_id.is_some(),
        Kind::Object => target
            .object_ref
            .as_deref()
            .is_some_and(arkret_wire::is_object_ref),
        Kind::Relation => target.relation_id.is_some(),
        Kind::View => target.view_id.is_some(),
        Kind::Event => target.event_id.is_some(),
        Kind::Actor => target.actor_id.is_some(),
        Kind::Schema => target
            .schema_ref
            .as_ref()
            .is_some_and(|reference| !reference.is_empty()),
        Kind::Policy => target.policy_id.is_some(),
        Kind::Invite => target.invite_id.is_some(),
        Kind::Blob => target.blob_ref.is_some(),
        Kind::All => false,
    }
}

pub fn key_scope_content_selector(
    resource: &arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResource,
) -> arkret_wire::Result<Option<arkret_wire::WireResourceSelector>> {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind as ScopeKind;
    use arkret_wire::{ResourceSelectorKind as Kind, WireResourceSelector};
    if matches!(resource.kind, ScopeKind::Operation | ScopeKind::Service) {
        if resource.realm_id.is_some()
            || resource.resource_ref.is_some()
            || resource.schema_ref.is_some()
            || (resource.kind == ScopeKind::Operation
                && (resource.service_id.is_some()
                    || resource.operation.as_deref().is_some_and(|operation| {
                        ServiceOperationId::from_wire(operation).is_none()
                    })))
            || (resource.kind == ScopeKind::Service && resource.operation.is_some())
        {
            return Err(unavailable(
                "Agent service scope carries invalid content or service fields",
            ));
        }
        return Ok(None);
    }
    if resource.operation.is_some()
        || resource.service_id.is_some()
        || (resource.kind != ScopeKind::Schema && resource.schema_ref.is_some())
        || (resource.kind == ScopeKind::Schema && resource.resource_ref.is_some())
    {
        return Err(unavailable(
            "Agent content scope carries unsupported selector fields",
        ));
    }
    let kind = match resource.kind {
        ScopeKind::Realm => Kind::Realm,
        ScopeKind::Space => Kind::Space,
        ScopeKind::Circle => Kind::Circle,
        ScopeKind::Strand => Kind::Strand,
        ScopeKind::Message => Kind::Message,
        ScopeKind::Morph => Kind::Morph,
        ScopeKind::Object => Kind::Object,
        ScopeKind::Relation => Kind::Relation,
        ScopeKind::View => Kind::View,
        ScopeKind::Event => Kind::Event,
        ScopeKind::Actor => Kind::Actor,
        ScopeKind::Schema => Kind::Schema,
        ScopeKind::Policy => Kind::Policy,
        ScopeKind::Invite => Kind::Invite,
        ScopeKind::Notification => Kind::Notification,
        ScopeKind::ReadCursor => Kind::ReadCursor,
        ScopeKind::Blob => Kind::Blob,
        ScopeKind::Operation | ScopeKind::Service => unreachable!(),
    };
    // Ceiling wildcards are legal even where an actual WireResourceSelector
    // requires a concrete Realm/Actor. Do not invent facts to validate them.
    let mut selector = WireResourceSelector {
        kind,
        realm_id: resource.realm_id.clone(),
        space_id: None,
        circle_id: None,
        object_kind: None,
        object_ref: None,
        strand_id: None,
        message_id: None,
        morph_id: None,
        morph_kind: None,
        relation_kind: None,
        relation_id: None,
        view_id: None,
        event_id: None,
        actor_id: None,
        schema_ref: resource.schema_ref.clone(),
        policy_id: None,
        invite_id: None,
        blob_ref: None,
        match_scope: None,
    };
    if selector.schema_ref.as_ref().is_some_and(String::is_empty) {
        return Err(unavailable("Agent schema ceiling reference is empty"));
    }
    if let Some(reference) = resource.resource_ref.as_deref() {
        let invalid = || unavailable("Agent content ceiling reference does not match its kind");
        match resource.kind {
            ScopeKind::Realm => {
                let realm: RealmId = reference.parse().map_err(|_| invalid())?;
                if selector
                    .realm_id
                    .as_ref()
                    .is_some_and(|bound| bound != &realm)
                {
                    return Err(invalid());
                }
                selector.realm_id = Some(realm);
            }
            ScopeKind::Space => selector.space_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Circle => {
                selector.circle_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Strand => {
                selector.strand_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Message => {
                selector.message_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Morph => selector.morph_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Object if arkret_wire::is_object_ref(reference) => {
                selector.object_ref = Some(reference.to_owned())
            }
            ScopeKind::Relation => {
                selector.relation_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::View => selector.view_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Event => selector.event_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Actor => selector.actor_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Policy => {
                selector.policy_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Invite => {
                selector.invite_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Blob => selector.blob_ref = Some(reference.parse().map_err(|_| invalid())?),
            // These two registered kinds narrow only by Realm. Never drop an
            // unrepresentable exact reference and accidentally widen its scope.
            ScopeKind::Notification
            | ScopeKind::ReadCursor
            | ScopeKind::Object
            | ScopeKind::Schema
            | ScopeKind::Operation
            | ScopeKind::Service => return Err(invalid()),
        }
    }
    Ok(Some(selector))
}

pub fn agent_management_actions<'a>(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
    policy_operation: Option<AgentPolicyOperation>,
) -> arkret_wire::Result<Vec<&'a str>> {
    if operation.actor.as_account_id() != Some(agent)
        || operation.target.realm_id.as_ref() != Some(realm)
    {
        return Err(unavailable(
            "Agent management operation identity is unavailable",
        ));
    }
    // Object selector facts are not yet resolved by this admission adapter.
    // Refuse such evidence instead of making a scoped deny fail to match.
    if policies.iter().flat_map(|p| &p.rules).any(|rule| {
        rule.resources.as_ref().is_some_and(|resources| {
            resources.iter().any(|resource| {
                matches!(
                    resource.kind,
                    PolicyResourceKind::Object | PolicyResourceKind::Service
                )
            })
        })
    }) {
        return Err(unavailable(
            "Agent management object resource evidence is unavailable",
        ));
    }
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for (kind, target, fact) in [
        (
            PolicyResourceKind::Strand,
            operation.target.strand_id.as_ref().map(ToString::to_string),
            operation.facts.strand_id.as_ref(),
        ),
        (
            PolicyResourceKind::Space,
            operation.target.space_id.as_ref().map(ToString::to_string),
            operation.facts.space_id.as_ref(),
        ),
    ] {
        if target
            .as_ref()
            .zip(fact)
            .is_some_and(|(target, fact)| target != fact)
        {
            return Err(unavailable("Agent management resource facts conflict"));
        }
        if let Some(id) = target.or_else(|| fact.cloned()) {
            let valid = match kind {
                PolicyResourceKind::Strand => id.parse::<arkret_wire::StrandId>().is_ok(),
                PolicyResourceKind::Space => id.parse::<arkret_wire::SpaceId>().is_ok(),
                _ => false,
            };
            if !valid {
                return Err(unavailable("Agent management resource identity is invalid"));
            }
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(id),
            });
        }
    }
    let mut allowed = Vec::new();
    let mut aggregates = Vec::new();
    let mut concrete_count = 0;
    let mut restricted = false;
    for &token in operation.actions {
        let descriptor = arkret_schema::capability_action(token)
            .ok_or_else(|| unavailable("Agent management action mapping is unavailable"))?;
        if descriptor.event_mapping_kind == "aggregate_admin" {
            aggregates.push(token);
            continue;
        }
        concrete_count += 1;
        if ServiceOperationId::from_wire(token).is_some() {
            return Err(unavailable(
                "Agent management content action is unavailable",
            ));
        }
        let action = CapabilityActionId::from_wire(token)
            .ok_or_else(|| unavailable("Agent management content action is unknown"))?;
        let effect = evaluate_agent_management(
            Some(policies),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation: policy_operation.unwrap_or({
                    if descriptor.target_event_kinds.is_empty() {
                        AgentPolicyOperation::Read
                    } else {
                        AgentPolicyOperation::Execute
                    }
                }),
                content_action: Some(action),
                resources: Some(&resources),
                at: operation.at,
            },
        )
        .map_err(unavailable)?;
        match effect {
            PolicyEffect::Allow => allowed.push(token),
            PolicyEffect::Deny => {}
            PolicyEffect::Quarantine | PolicyEffect::RequireReview => restricted = true,
        }
    }
    if concrete_count == 0 {
        return Err(unavailable(
            "Agent management concrete action mapping is unavailable",
        ));
    }
    if allowed.is_empty() && restricted {
        return Err(unavailable(
            "Agent management requires unresolved quarantine or review evidence",
        ));
    }
    // An existing aggregate grant remains a permission path only when none
    // of this operation's concrete paths were filtered by management. It is
    // never evaluated as a content action or used to bypass a restricted path.
    if allowed.len() == concrete_count {
        allowed.extend(aggregates);
    }
    Ok(allowed)
}
