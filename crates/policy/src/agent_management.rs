//! Deterministic Agent management restrictions (owned-agent-authority section 3).
//!
//! This pure evaluator neither authenticates current evidence nor authorizes an
//! action. Callers must supply the complete applicable current Policy set, exact
//! verified ownership, and resolved actual resource facts from one enforcing cut.
//! An allow result still requires controller, grant, membership and delivery gates.

use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, AgentPolicyTarget, Policy, PolicyResourceKind, PolicyResourceSelector,
    PolicyRuleKind,
};
use arkret_wire::{
    AccountId, CapabilityActionId, PolicyEffect, PolicyKind, RealmId, ServiceOperationId,
};
use chrono::{DateTime, Utc};

/// Local evaluation inputs, not a wire object or caller-provided authority claim.
pub struct AgentManagementContext<'a> {
    pub realm_id: &'a RealmId,
    /// Exact (controller, Agent) pair established by current ownership evidence.
    pub ownership: Option<(&'a AccountId, &'a AccountId)>,
    pub operation: AgentPolicyOperation,
    /// One actual content action, not an owner aggregate or service operation.
    /// Authorizing multiple actions requires evaluating every action separately.
    pub content_action: Option<CapabilityActionId>,
    /// Complete actual resource identities, including the exact Realm anchor.
    /// Strand/Space facts are actual scope facts, never navigation ancestors.
    pub resources: Option<&'a [PolicyResourceSelector]>,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentManagementError {
    #[error("complete current Agent management evidence is unavailable")]
    IncompleteCurrent,
    #[error("exact current Agent ownership is unavailable")]
    IncompleteOwnership,
    #[error("actual content action or resource scope is unavailable")]
    InvalidOperationContext,
    #[error("Agent Policy current is invalid or has a different Realm binding")]
    InvalidPolicy,
    #[error("Agent Policy identity occurs more than once at the current cut")]
    DuplicatePolicy,
    #[error("an Agent Policy rule needs an unsupported matcher")]
    UnsupportedRule,
}

fn severity(effect: &PolicyEffect) -> u8 {
    match effect {
        PolicyEffect::Allow => 0,
        PolicyEffect::RequireReview => 1,
        PolicyEffect::Quarantine => 2,
        PolicyEffect::Deny => 3,
    }
}

fn stricter(left: PolicyEffect, right: PolicyEffect) -> PolicyEffect {
    if severity(&right) > severity(&left) {
        right
    } else {
        left
    }
}

fn content_action(action: &str) -> bool {
    arkret_schema::capability_action(action).is_some_and(|descriptor| {
        descriptor.event_mapping_kind != "aggregate_admin"
            && ServiceOperationId::from_wire(action).is_none()
    })
}

/// `None` means unknown/stale/incomplete, not an absent Policy. `Some(&[])`
/// is valid only after the caller has proved complete current absence across
/// every applicable Realm/Circle/Strand layer. Never construct it from a cache miss.
pub fn evaluate_agent_management(
    policies: Option<&[Policy]>,
    context: &AgentManagementContext<'_>,
) -> Result<PolicyEffect, AgentManagementError> {
    let policies = policies.ok_or(AgentManagementError::IncompleteCurrent)?;
    let (controller, agent) = context
        .ownership
        .filter(|(controller, agent)| controller != agent)
        .ok_or(AgentManagementError::IncompleteOwnership)?;
    let resources = context
        .resources
        .ok_or(AgentManagementError::InvalidOperationContext)?;
    if !resources.iter().any(|resource| {
        resource.kind == PolicyResourceKind::Realm
            && resource.realm_id.as_ref() == Some(context.realm_id)
            && resource.resource_ref.as_deref() == Some(context.realm_id.as_str())
    }) || resources.iter().any(|resource| {
        resource.realm_id.as_ref() != Some(context.realm_id)
            || resource.resource_ref.as_deref().is_none_or(str::is_empty)
            || (resource.kind == PolicyResourceKind::Realm
                && resource.resource_ref.as_deref() != Some(context.realm_id.as_str()))
            || resource.kind == PolicyResourceKind::Service
    }) || context
        .content_action
        .is_some_and(|action| !content_action(action.as_str()))
        || (matches!(
            context.operation,
            AgentPolicyOperation::Execute
                | AgentPolicyOperation::Read
                | AgentPolicyOperation::Deliver
        ) && context.content_action.is_none())
    {
        return Err(AgentManagementError::InvalidOperationContext);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut result = PolicyEffect::Allow;
    for policy in policies {
        policy
            .validate()
            .map_err(|_| AgentManagementError::InvalidPolicy)?;
        if policy.policy_kind != PolicyKind::Agent
            || policy.realm_id.as_ref() != Some(context.realm_id)
        {
            return Err(AgentManagementError::InvalidPolicy);
        }
        if !ids.insert(&policy.id) {
            return Err(AgentManagementError::DuplicatePolicy);
        }
        if policy
            .not_before
            .zip(policy.expires_at)
            .is_some_and(|(start, end)| start >= end)
        {
            return Err(AgentManagementError::InvalidPolicy);
        }
        if policy.not_before.is_some_and(|start| context.at < start)
            || policy.expires_at.is_some_and(|end| context.at >= end)
        {
            continue;
        }
        let mut matched: Option<(i64, PolicyEffect)> = None;
        for rule in &policy.rules {
            if rule.kind != PolicyRuleKind::Agent
                || rule
                    .actions
                    .as_ref()
                    .is_some_and(|actions| actions.iter().any(|action| !content_action(action)))
                || rule.resources.as_ref().is_some_and(|resources| {
                    resources
                        .iter()
                        .any(|resource| resource.kind == PolicyResourceKind::Service)
                })
            {
                return Err(AgentManagementError::UnsupportedRule);
            }
            let target_matches = match rule
                .agent_target
                .as_ref()
                .ok_or(AgentManagementError::InvalidPolicy)?
            {
                AgentPolicyTarget::All {} => true,
                AgentPolicyTarget::Controller {
                    controller_account_id,
                } => controller_account_id == controller,
                AgentPolicyTarget::Agent { agent_account_id } => agent_account_id == agent,
            };
            if !target_matches
                || !rule
                    .agent_operations
                    .as_ref()
                    .ok_or(AgentManagementError::InvalidPolicy)?
                    .contains(&context.operation)
            {
                continue;
            }
            if let Some(selectors) = &rule.resources
                && !selectors.iter().any(|selector| {
                    resources.iter().any(|actual| {
                        selector.kind == actual.kind
                            && selector
                                .realm_id
                                .as_ref()
                                .is_none_or(|realm| actual.realm_id.as_ref() == Some(realm))
                            && selector
                                .resource_ref
                                .as_ref()
                                .is_none_or(|id| actual.resource_ref.as_ref() == Some(id))
                    })
                })
            {
                continue;
            }
            if let Some(actions) = &rule.actions {
                let action = context
                    .content_action
                    .ok_or(AgentManagementError::InvalidOperationContext)?;
                if !actions.iter().any(|named| named == action.as_str()) {
                    continue;
                }
            }
            matched = Some(match matched {
                Some((priority, effect)) if priority == rule.priority => {
                    (priority, stricter(effect, rule.effect.clone()))
                }
                Some(existing) if existing.0 > rule.priority => existing,
                _ => (rule.priority, rule.effect.clone()),
            });
        }
        result = stricter(
            result,
            matched.map_or(policy.default_effect.clone(), |(_, effect)| effect),
        );
    }
    Ok(result)
}

#[cfg(test)]
#[path = "agent_management_tests.rs"]
mod tests;
