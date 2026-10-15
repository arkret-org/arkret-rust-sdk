//! Deterministic Applet management restrictions (owned-applet-authority section 3).
//!
//! This pure evaluator neither authenticates current evidence nor authorizes an
//! action. Callers must supply the complete applicable current Policy set, exact
//! verified ownership, and resolved actual resource facts from one enforcing cut.
//! An allow result still requires controller, grant, membership and delivery gates.

use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, AppletPolicyTarget, ManagementReviewRequirement, Policy,
    PolicyResourceKind, PolicyResourceSelector, PolicyRuleKind,
};
use arkret_wire::{
    ActorId, AppletId, CapabilityActionId, PolicyEffect, PolicyKind, RealmId, ScopeRef,
    ServiceOperationId,
};
use chrono::{DateTime, Utc};

/// Local evaluation inputs, not a wire object or caller-provided authority claim.
pub struct AppletManagementContext<'a> {
    pub realm_id: &'a RealmId,
    /// Exact (controller, Applet) pair established by current ownership evidence.
    pub requester_actor_id: &'a ActorId,
    pub applet_id: &'a AppletId,
    pub effective_scope: &'a ScopeRef,
    pub managed_actor_id: Option<&'a ActorId>,
    pub operation: AppletPolicyOperation,
    /// One actual content action, not an owner aggregate or service operation.
    /// Authorizing multiple actions requires evaluating every action separately.
    pub content_action: Option<CapabilityActionId>,
    /// Complete actual resource identities, including the exact Realm anchor.
    /// Strand/Space facts are actual scope facts, never navigation ancestors.
    pub resources: Option<&'a [PolicyResourceSelector]>,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AppletManagementError {
    #[error("complete current Applet management evidence is unavailable")]
    IncompleteCurrent,
    #[error("exact current Applet ownership is unavailable")]
    IncompleteOwnership,
    #[error("actual content action or resource scope is unavailable")]
    InvalidOperationContext,
    #[error("Applet Policy current is invalid or has a different Realm binding")]
    InvalidPolicy,
    #[error("Applet Policy identity occurs more than once at the current cut")]
    DuplicatePolicy,
    #[error("an Applet Policy rule needs an unsupported matcher")]
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

/// The effect and every applicable highest-priority review requirement are
/// selected together. A consumer must satisfy all requirements; selecting a
/// single permissive rule cannot erase another Policy or same-priority vote.
#[derive(Clone, Debug, PartialEq)]
pub struct AppletManagementDecision {
    pub effect: PolicyEffect,
    pub review_requirements: Vec<ManagementReviewRequirement>,
}

pub fn evaluate_applet_management(
    policies: Option<&[Policy]>,
    context: &AppletManagementContext<'_>,
) -> Result<PolicyEffect, AppletManagementError> {
    select_applet_management(policies, context).map(|decision| decision.effect)
}

/// `None` means unknown/stale/incomplete, not an absent Policy. `Some(&[])`
/// is valid only after the caller has proved complete current absence across
/// every applicable Realm/Circle/Strand layer. Never construct it from a cache miss.
pub fn select_applet_management(
    policies: Option<&[Policy]>,
    context: &AppletManagementContext<'_>,
) -> Result<AppletManagementDecision, AppletManagementError> {
    let policies = policies.ok_or(AppletManagementError::IncompleteCurrent)?;
    let resources = context
        .resources
        .ok_or(AppletManagementError::InvalidOperationContext)?;
    if context.effective_scope.realm_id_opt() != Some(context.realm_id)
        || !resources.iter().any(|resource| {
            resource.kind == PolicyResourceKind::Realm
                && resource.realm_id.as_ref() == Some(context.realm_id)
                && resource.resource_ref.as_deref() == Some(context.realm_id.as_str())
        })
        || resources.iter().any(|resource| {
            resource.realm_id.as_ref() != Some(context.realm_id)
                || resource.resource_ref.as_deref().is_none_or(str::is_empty)
                || (resource.kind == PolicyResourceKind::Realm
                    && resource.resource_ref.as_deref() != Some(context.realm_id.as_str()))
                || resource.kind == PolicyResourceKind::Service
        })
        || context
            .content_action
            .is_some_and(|action| !content_action(action.as_str()))
        || (matches!(
            context.operation,
            AppletPolicyOperation::Execute
                | AppletPolicyOperation::Read
                | AppletPolicyOperation::Deliver
                | AppletPolicyOperation::Serve
                | AppletPolicyOperation::Invoke
        ) && context.content_action.is_none())
    {
        return Err(AppletManagementError::InvalidOperationContext);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut result = PolicyEffect::Allow;
    let mut review_requirements = Vec::new();
    for policy in policies {
        policy
            .validate()
            .map_err(|_| AppletManagementError::InvalidPolicy)?;
        if policy.policy_kind != PolicyKind::Applet
            || policy.realm_id.as_ref() != Some(context.realm_id)
        {
            return Err(AppletManagementError::InvalidPolicy);
        }
        if !ids.insert(&policy.id) {
            return Err(AppletManagementError::DuplicatePolicy);
        }
        if policy
            .not_before
            .zip(policy.expires_at)
            .is_some_and(|(start, end)| start >= end)
        {
            return Err(AppletManagementError::InvalidPolicy);
        }
        if policy.not_before.is_some_and(|start| context.at < start)
            || policy.expires_at.is_some_and(|end| context.at >= end)
        {
            continue;
        }
        let mut matched: Option<(i64, PolicyEffect, Vec<ManagementReviewRequirement>)> = None;
        for rule in &policy.rules {
            if rule.kind != PolicyRuleKind::Applet
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
                return Err(AppletManagementError::UnsupportedRule);
            }
            let target_matches = match rule
                .applet_target
                .as_ref()
                .ok_or(AppletManagementError::InvalidPolicy)?
            {
                AppletPolicyTarget::All {} => true,
                AppletPolicyTarget::Requester { actor_id } => {
                    actor_id == context.requester_actor_id
                }
                AppletPolicyTarget::Installation {
                    applet_id,
                    effective_scope,
                } => applet_id == context.applet_id && effective_scope == context.effective_scope,
                AppletPolicyTarget::ManagedActor { actor_id } => {
                    context.managed_actor_id == Some(actor_id)
                }
            };
            if !target_matches
                || !rule
                    .applet_operations
                    .as_ref()
                    .ok_or(AppletManagementError::InvalidPolicy)?
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
                    .ok_or(AppletManagementError::InvalidOperationContext)?;
                if !actions.iter().any(|named| named == action.as_str()) {
                    continue;
                }
            }
            let requirements = if rule.effect == PolicyEffect::RequireReview {
                vec![
                    rule.review_requirement
                        .clone()
                        .ok_or(AppletManagementError::InvalidPolicy)?,
                ]
            } else {
                Vec::new()
            };
            matched = Some(match matched {
                Some((priority, effect, mut prior)) if priority == rule.priority => {
                    prior.extend(requirements);
                    (priority, stricter(effect, rule.effect.clone()), prior)
                }
                Some(existing) if existing.0 > rule.priority => existing,
                _ => (rule.priority, rule.effect.clone(), requirements),
            });
        }
        let (effect, requirements) = if let Some((_, effect, requirements)) = matched {
            (effect, requirements)
        } else if policy.default_effect == PolicyEffect::RequireReview {
            let operation = match context.operation {
                AppletPolicyOperation::Join => Some(arkret_wire::ManagementOperation::Join),
                AppletPolicyOperation::Publish => Some(arkret_wire::ManagementOperation::Publish),
                AppletPolicyOperation::CreateBot => {
                    Some(arkret_wire::ManagementOperation::CreateBot)
                }
                AppletPolicyOperation::MapGhost => Some(arkret_wire::ManagementOperation::MapGhost),
                _ => None,
            };
            if operation.is_some_and(|operation| {
                policy
                    .default_operations
                    .as_ref()
                    .is_some_and(|operations| operations.contains(&operation))
            }) {
                (
                    PolicyEffect::RequireReview,
                    vec![
                        policy
                            .default_review_requirement
                            .clone()
                            .ok_or(AppletManagementError::InvalidPolicy)?,
                    ],
                )
            } else {
                (PolicyEffect::Deny, Vec::new())
            }
        } else {
            (policy.default_effect.clone(), Vec::new())
        };
        if effect == PolicyEffect::RequireReview {
            review_requirements.extend(requirements);
        }
        result = stricter(result, effect);
    }
    if result != PolicyEffect::RequireReview {
        review_requirements.clear();
    }
    for requirement in &review_requirements {
        requirement
            .validate()
            .map_err(|_| AppletManagementError::InvalidPolicy)?;
    }
    Ok(AppletManagementDecision {
        effect: result,
        review_requirements,
    })
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorId, AppletId, DidCoreId, EventId, ScopeRef};
    use serde_json::json;

    use super::*;
    #[test]
    fn review_selection_keeps_all_highest_priority_and_parent_requirements() {
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [43; 32],
        ));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let applet = AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap();
        let requester =
            ActorId::service(DidCoreId::new("ak:did_core:web:creator.example").unwrap());
        let approver = ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:admin.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let requirement = |age| ManagementReviewRequirement {
            approver_actor_ids: vec![approver.clone()],
            threshold: 1,
            max_age_seconds: age,
        };
        let resources = [PolicyResourceSelector {
            kind: PolicyResourceKind::Realm,
            realm_id: Some(realm.clone()),
            resource_ref: Some(realm.to_string()),
        }];
        let at = "2026-10-16T00:00:00.000Z".parse().unwrap();
        let context = AppletManagementContext {
            realm_id: &realm,
            requester_actor_id: &requester,
            applet_id: &applet,
            effective_scope: &scope,
            managed_actor_id: None,
            operation: AppletPolicyOperation::CreateBot,
            content_action: None,
            resources: Some(&resources),
            at,
        };
        let rule = |id, priority, age| {
            json!({"rule_id":id,"kind":"applet","effect":"require_review","priority":priority,
            "applet_target":{"kind":"all"},"applet_operations":["create_bot"],"review_requirement":requirement(age)})
        };
        let policy:Policy=serde_json::from_value(json!({"schema":"ak.schema.policy.v1","id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "realm_id":realm,"policy_kind":"applet","rules":[rule("low",1,120),rule("first",5,60),rule("second",5,20)],
            "default_effect":"allow","created_by":requester,"created_at":arkret_canonical::format_timestamp_canonical(at)})).unwrap();
        assert_eq!(
            select_applet_management(Some(&[policy.clone()]), &context).unwrap(),
            AppletManagementDecision {
                effect: PolicyEffect::RequireReview,
                review_requirements: vec![requirement(60), requirement(20)]
            }
        );
        let mut parent_value = serde_json::to_value(&policy).unwrap();
        parent_value["id"] = json!("ak:policy:0198ff00-0000-7000-8000-000000000002");
        parent_value["rules"] = json!([{"rule_id":"other_operation","kind":"applet","effect":"allow","priority":0,
            "applet_target":{"kind":"all"},"applet_operations":["map_ghost"]}]);
        parent_value["default_effect"] = json!("require_review");
        parent_value["default_operations"] = json!(["create_bot"]);
        parent_value["default_review_requirement"] = json!(requirement(5));
        let mut parent: Policy = serde_json::from_value(parent_value).unwrap();
        assert_eq!(
            select_applet_management(Some(&[policy.clone(), parent.clone()]), &context).unwrap(),
            AppletManagementDecision {
                effect: PolicyEffect::RequireReview,
                review_requirements: vec![requirement(60), requirement(20), requirement(5)]
            }
        );
        let mut higher_allow = policy.clone();
        higher_allow.rules[1].priority = 6;
        higher_allow.rules[1].effect = PolicyEffect::Allow;
        higher_allow.rules[1].review_requirement = None;
        assert_eq!(
            select_applet_management(Some(&[higher_allow]), &context).unwrap(),
            AppletManagementDecision {
                effect: PolicyEffect::Allow,
                review_requirements: vec![]
            }
        );
        let mut same_priority_deny = policy.clone();
        same_priority_deny.rules[1].effect = PolicyEffect::Deny;
        same_priority_deny.rules[1].review_requirement = None;
        assert_eq!(
            select_applet_management(Some(&[same_priority_deny, parent.clone()]), &context)
                .unwrap(),
            AppletManagementDecision {
                effect: PolicyEffect::Deny,
                review_requirements: vec![]
            }
        );
        parent.default_operations = Some(vec![arkret_wire::ManagementOperation::MapGhost]);
        assert_eq!(
            select_applet_management(Some(&[policy, parent]), &context).unwrap(),
            AppletManagementDecision {
                effect: PolicyEffect::Deny,
                review_requirements: vec![]
            }
        );
    }

    #[test]
    fn defaults_exceptions_and_cross_policy_denial_remain_distinct() {
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [42; 32],
        ));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let applet = AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap();
        let requester = ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
        let resources = vec![PolicyResourceSelector {
            kind: PolicyResourceKind::Realm,
            realm_id: Some(realm.clone()),
            resource_ref: Some(realm.to_string()),
        }];
        let context = AppletManagementContext {
            realm_id: &realm,
            requester_actor_id: &requester,
            applet_id: &applet,
            effective_scope: &scope,
            managed_actor_id: None,
            operation: AppletPolicyOperation::CreateBot,
            content_action: None,
            resources: Some(&resources),
            at: Utc::now(),
        };
        let policy = |id, deny| {
            serde_json::from_value::<Policy>(json!({"schema":"ak.schema.policy.v1","id":format!("ak:policy:0198ff00-0000-7000-8000-{id:012}"),"realm_id":realm,"policy_kind":"applet","rules":[{"rule_id":"creator","kind":"applet","effect":if deny {"deny"} else {"allow"},"priority":5,"applet_target":{"kind":"requester","actor_id":requester},"applet_operations":["create_bot"]}],"default_effect":"deny","created_by":requester,"created_at":arkret_canonical::format_timestamp_canonical(context.at)})).unwrap()
        };
        assert_eq!(
            evaluate_applet_management(None, &context),
            Err(AppletManagementError::IncompleteCurrent)
        );
        assert_eq!(
            evaluate_applet_management(Some(&[]), &context),
            Ok(PolicyEffect::Allow)
        );
        assert_eq!(
            evaluate_applet_management(Some(&[policy(1, false)]), &context),
            Ok(PolicyEffect::Allow)
        );
        assert_eq!(
            evaluate_applet_management(Some(&[policy(1, false), policy(2, true)]), &context),
            Ok(PolicyEffect::Deny)
        );
        let mut review = policy(1, false);
        review.default_effect = PolicyEffect::RequireReview;
        review.default_operations = Some(vec![arkret_wire::ManagementOperation::Join]);
        review.default_review_requirement = Some(
            arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![requester.clone()],
                threshold: 1,
                max_age_seconds: 300,
            },
        );
        review.rules[0].applet_operations = Some(vec![AppletPolicyOperation::MapGhost]);
        assert_eq!(
            evaluate_applet_management(Some(&[review]), &context),
            Ok(PolicyEffect::Deny)
        );
    }
}
