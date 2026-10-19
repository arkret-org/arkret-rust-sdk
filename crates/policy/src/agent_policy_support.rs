//! Pure Agent Policy configuration preflight (managed-governance section 1).
//! Support facts describe an enforcing backend, never protocol legality or authority.

use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyRuleKind,
};
use arkret_wire::{PolicyEffect, PolicyKind, ScopeRef, ServiceOperationId, WireError};

/// Local implementation facts, not a wire object, negotiated profile or grant.
/// A caller may declare support only when its registered consumers implement it.
#[derive(Clone, Copy, Debug)]
pub struct AgentPolicyBackendSupport {
    /// An executable, registered Circle management review carrier.
    pub circle_review: bool,
}

/// Established configuration consumers shared by the reference Station and UI.
/// This is not a claim of complete protocol or runtime support.
pub const REFERENCE_AGENT_POLICY_SUPPORT: AgentPolicyBackendSupport = AgentPolicyBackendSupport {
    circle_review: false,
};

#[derive(Debug, thiserror::Error)]
pub enum AgentPolicySupportError {
    #[error(transparent)]
    InvalidPolicy(WireError),
    #[error("expected an Agent Policy")]
    NotAgentPolicy,
    #[error("Agent Policy has no registered governance scope")]
    GovernanceScope,
    #[error("Circle review carrier is unavailable")]
    CircleReview,
    #[error("non-Agent rule has no registered Agent matcher")]
    RuleKind,
    #[error("unknown action has no registered matcher")]
    UnknownAction,
    #[error("aggregate administrative action is not a content action")]
    AggregateAdminAction,
    #[error("service operation is not a content action")]
    ServiceAction,
    #[error("join or publish action selector matcher is unavailable")]
    JoinPublishActionSelector,
    #[error("resource belongs to another Realm")]
    CrossRealmResource,
    #[error("resource reference does not match its kind or Realm")]
    ResourceReference,
    #[error("service scope is not a content-resource selector")]
    ServiceResource,
}

/// Validate the Agent family and syntax, then exact scope and supplied support.
/// Success does not establish current evidence, permission, membership or approval;
/// the enforcing Station must call this independently inside its acceptance path.
pub fn validate_agent_policy_support(
    document: &Policy,
    scope: &ScopeRef,
    support: &AgentPolicyBackendSupport,
) -> Result<(), AgentPolicySupportError> {
    use AgentPolicySupportError as Error;
    if document.policy_kind != PolicyKind::Agent {
        return Err(Error::NotAgentPolicy);
    }
    document.validate().map_err(Error::InvalidPolicy)?;
    if !matches!(scope,
        ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. }
        if document.realm_id.as_ref() == Some(realm_id))
    {
        return Err(Error::GovernanceScope);
    }
    let circle_without_review = matches!(scope, ScopeRef::Circle { .. }) && !support.circle_review;
    if circle_without_review && document.default_effect == PolicyEffect::RequireReview {
        return Err(Error::CircleReview);
    }
    for rule in &document.rules {
        if rule.kind != PolicyRuleKind::Agent {
            return Err(Error::RuleKind);
        }
        if circle_without_review && rule.effect == PolicyEffect::RequireReview {
            return Err(Error::CircleReview);
        }
        if let Some(actions) = &rule.actions {
            for action in actions {
                if ServiceOperationId::from_wire(action).is_some() {
                    return Err(Error::ServiceAction);
                }
                let descriptor =
                    arkret_schema::capability_action(action).ok_or(Error::UnknownAction)?;
                if descriptor.event_mapping_kind == "aggregate_admin" {
                    return Err(Error::AggregateAdminAction);
                }
            }
            if rule.agent_operations.as_ref().is_some_and(|ops| {
                ops.iter().any(|op| {
                    matches!(
                        op,
                        AgentPolicyOperation::Join | AgentPolicyOperation::Publish
                    )
                })
            }) {
                return Err(Error::JoinPublishActionSelector);
            }
        }
        for resource in rule.resources.iter().flatten() {
            if resource
                .realm_id
                .as_ref()
                .is_some_and(|realm| document.realm_id.as_ref() != Some(realm))
            {
                return Err(Error::CrossRealmResource);
            }
            let invalid_reference = match resource.kind {
                PolicyResourceKind::Realm => resource.resource_ref.as_ref().is_some_and(|id| {
                    document
                        .realm_id
                        .as_ref()
                        .is_none_or(|realm| realm.as_str() != id)
                }),
                PolicyResourceKind::Strand => resource
                    .resource_ref
                    .as_ref()
                    .is_some_and(|id| id.parse::<arkret_wire::StrandId>().is_err()),
                PolicyResourceKind::Space => resource
                    .resource_ref
                    .as_ref()
                    .is_some_and(|id| id.parse::<arkret_wire::SpaceId>().is_err()),
                PolicyResourceKind::Object => resource
                    .resource_ref
                    .as_ref()
                    .is_some_and(|id| !arkret_wire::is_object_ref(id)),
                PolicyResourceKind::Service => return Err(Error::ServiceResource),
            };
            if invalid_reference {
                return Err(Error::ResourceReference);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "agent_policy_support_tests.rs"]
mod tests;
