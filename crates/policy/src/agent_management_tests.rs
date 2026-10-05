use arkret_wire::{ActorId, DidCoreId, EventId, StrandId};
use serde_json::json;

use super::*;

fn account(name: &str, station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
        DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
    )
}

struct Fixture {
    realm: RealmId,
    controller: AccountId,
    agent: AccountId,
    resources: Vec<PolicyResourceSelector>,
    at: DateTime<Utc>,
}

impl Fixture {
    fn new() -> Self {
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]);
        let realm = RealmId::from_event_id(&event);
        let strand = StrandId::from_event_id(&event);
        Self {
            resources: vec![
                PolicyResourceSelector {
                    kind: PolicyResourceKind::Realm,
                    realm_id: Some(realm.clone()),
                    resource_ref: Some(realm.to_string()),
                },
                PolicyResourceSelector {
                    kind: PolicyResourceKind::Strand,
                    realm_id: Some(realm.clone()),
                    resource_ref: Some(strand.to_string()),
                },
            ],
            realm,
            controller: account("owner", "station"),
            agent: account("agent", "station"),
            at: "2026-10-06T00:00:00Z".parse().unwrap(),
        }
    }

    fn context(&self, operation: AgentPolicyOperation) -> AgentManagementContext<'_> {
        AgentManagementContext {
            realm_id: &self.realm,
            ownership: Some((&self.controller, &self.agent)),
            operation,
            content_action: CapabilityActionId::from_wire("ak.message.create"),
            resources: Some(&self.resources),
            at: self.at,
        }
    }

    fn policy(&self, rules: serde_json::Value, default: PolicyEffect, id: u8) -> Policy {
        serde_json::from_value(json!({
            "id":format!("ak:policy:0198ff00-0000-7000-8000-{id:012}"),"schema":"ak.schema.policy.v1",
            "realm_id":self.realm,"policy_kind":"agent","rules":rules,"default_effect":default,
            "created_by":ActorId::account(self.controller.clone()),"created_at":arkret_canonical::format_timestamp_canonical(self.at),
        })).unwrap()
    }
}

fn rule(
    target: serde_json::Value,
    operations: serde_json::Value,
    effect: &str,
    priority: i64,
) -> serde_json::Value {
    json!({"rule_id":format!("{effect}-{priority}"),"kind":"agent","effect":effect,"priority":priority,
        "agent_target":target,"agent_operations":operations})
}

fn all(effect: &str, priority: i64) -> serde_json::Value {
    rule(
        json!({"kind":"all"}),
        json!(["join", "authorize", "execute", "read", "deliver"]),
        effect,
        priority,
    )
}

#[test]
fn complete_absence_is_allow_but_unknown_is_never_absence() {
    let f = Fixture::new();
    let context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(None, &context),
        Err(AgentManagementError::IncompleteCurrent)
    );
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Ok(PolicyEffect::Allow)
    );
    let mut join = f.context(AgentPolicyOperation::Join);
    join.content_action = None;
    assert_eq!(
        evaluate_agent_management(Some(&[]), &join),
        Ok(PolicyEffect::Allow)
    );
}

#[test]
fn ownership_is_required_even_with_a_complete_empty_policy_set() {
    let f = Fixture::new();
    let mut context = f.context(AgentPolicyOperation::Join);
    context.ownership = None;
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::IncompleteOwnership)
    );
    context.ownership = Some((&f.controller, &f.controller));
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::IncompleteOwnership)
    );
}

#[test]
fn controller_targets_use_both_account_components_and_cover_future_agents() {
    let f = Fixture::new();
    let policy = f.policy(
        json!([rule(
            json!({"kind":"controller","controller_account_id":f.controller}),
            json!(["execute"]),
            "deny",
            0
        )]),
        PolicyEffect::Allow,
        1,
    );
    let mut context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Deny)
    );
    let future = account("future-agent", "station");
    context.ownership = Some((&f.controller, &future));
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Deny)
    );
    let wrong_station = account("owner", "other-station");
    context.ownership = Some((&wrong_station, &f.agent));
    assert_eq!(
        evaluate_agent_management(Some(&[policy]), &context),
        Ok(PolicyEffect::Allow)
    );
}

#[test]
fn specific_agent_does_not_match_sibling_or_same_principal_other_station() {
    let f = Fixture::new();
    let policy = f.policy(
        json!([rule(
            json!({"kind":"agent","agent_account_id":f.agent}),
            json!(["execute"]),
            "deny",
            0
        )]),
        PolicyEffect::Allow,
        1,
    );
    let context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Deny)
    );
    for sibling in [
        account("sibling", "station"),
        account("agent", "other-station"),
    ] {
        let mut context = f.context(AgentPolicyOperation::Execute);
        context.ownership = Some((&f.controller, &sibling));
        assert_eq!(
            evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
            Ok(PolicyEffect::Allow)
        );
    }
}

#[test]
fn join_and_authorize_bans_do_not_implicitly_stop_existing_operations() {
    let f = Fixture::new();
    let policies = [f.policy(
        json!([rule(
            json!({"kind":"all"}),
            json!(["join", "authorize"]),
            "deny",
            0
        )]),
        PolicyEffect::Allow,
        1,
    )];
    for operation in [
        AgentPolicyOperation::Join,
        AgentPolicyOperation::Authorize,
        AgentPolicyOperation::Execute,
        AgentPolicyOperation::Read,
        AgentPolicyOperation::Deliver,
    ] {
        let expected = if matches!(
            operation,
            AgentPolicyOperation::Join | AgentPolicyOperation::Authorize
        ) {
            PolicyEffect::Deny
        } else {
            PolicyEffect::Allow
        };
        assert_eq!(
            evaluate_agent_management(Some(&policies), &f.context(operation)),
            Ok(expected)
        );
    }
}

#[test]
fn same_priority_is_strict_and_order_independent() {
    let f = Fixture::new();
    let mut policy = f.policy(
        json!([
            all("allow", 2),
            all("require_review", 2),
            all("quarantine", 2),
            all("deny", 2)
        ]),
        PolicyEffect::Allow,
        1,
    );
    for _ in 0..4 {
        assert_eq!(
            evaluate_agent_management(
                Some(std::slice::from_ref(&policy)),
                &f.context(AgentPolicyOperation::Execute)
            ),
            Ok(PolicyEffect::Deny)
        );
        policy.rules.rotate_left(1);
    }
    policy
        .rules
        .retain(|rule| rule.effect != PolicyEffect::Deny);
    assert_eq!(
        evaluate_agent_management(Some(&[policy]), &f.context(AgentPolicyOperation::Execute)),
        Ok(PolicyEffect::Quarantine)
    );
}

#[test]
fn higher_rule_priority_wins_only_inside_one_policy() {
    let f = Fixture::new();
    let mut allow = f.policy(
        json!([all("deny", 0), all("allow", 10)]),
        PolicyEffect::Deny,
        1,
    );
    allow.priority = Some(1000);
    let deny = f.policy(json!([all("deny", -100)]), PolicyEffect::Allow, 2);
    let context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&allow)), &context),
        Ok(PolicyEffect::Allow)
    );
    assert_eq!(
        evaluate_agent_management(Some(&[allow.clone(), deny.clone()]), &context),
        Ok(PolicyEffect::Deny)
    );
    assert_eq!(
        evaluate_agent_management(Some(&[deny, allow]), &context),
        Ok(PolicyEffect::Deny)
    );
}

#[test]
fn action_and_resource_filters_are_and_not_alternative_allow_paths() {
    let f = Fixture::new();
    let mut filtered = all("deny", 0);
    filtered["actions"] = json!(["ak.message.create"]);
    filtered["resources"] = json!([f.resources[1]]);
    let policy = f.policy(json!([filtered]), PolicyEffect::Allow, 1);
    let mut context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Deny)
    );
    context.content_action = CapabilityActionId::from_wire("ak.reaction.add");
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Allow)
    );
    context.content_action = CapabilityActionId::from_wire("ak.message.create");
    context.resources = Some(&f.resources[..1]);
    assert_eq!(
        evaluate_agent_management(Some(&[policy]), &context),
        Ok(PolicyEffect::Allow)
    );
}

#[test]
fn unmatched_rules_use_default_and_expired_policy_is_not_active() {
    let f = Fixture::new();
    let mut policy = f.policy(
        json!([rule(json!({"kind":"all"}), json!(["join"]), "allow", 0)]),
        PolicyEffect::Deny,
        1,
    );
    let context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Deny)
    );
    policy.not_before = Some(f.at + chrono::TimeDelta::seconds(1));
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Allow)
    );
    policy.not_before = None;
    policy.expires_at = Some(f.at);
    assert_eq!(
        evaluate_agent_management(Some(std::slice::from_ref(&policy)), &context),
        Ok(PolicyEffect::Allow)
    );
    policy.expires_at = Some(f.at + chrono::TimeDelta::seconds(1));
    assert_eq!(
        evaluate_agent_management(Some(&[policy]), &context),
        Ok(PolicyEffect::Deny)
    );
}

#[test]
fn read_deliver_and_execute_require_actual_content_action_mapping() {
    let f = Fixture::new();
    for operation in [
        AgentPolicyOperation::Execute,
        AgentPolicyOperation::Read,
        AgentPolicyOperation::Deliver,
    ] {
        let mut context = f.context(operation);
        context.content_action = None;
        assert_eq!(
            evaluate_agent_management(Some(&[]), &context),
            Err(AgentManagementError::InvalidOperationContext)
        );
        context.content_action = CapabilityActionId::from_wire("ak.event.read");
        assert_eq!(
            evaluate_agent_management(Some(&[]), &context),
            Ok(PolicyEffect::Allow)
        );
    }
}

#[test]
fn service_operations_and_owner_aggregates_cannot_substitute_content_actions() {
    let f = Fixture::new();
    for action in [
        "ak.self.agent.command.pause.v1",
        "ak.realm.owner",
        "ak.not_registered.operation",
    ] {
        let mut named = all("allow", 0);
        named["actions"] = json!([action]);
        let policy = f.policy(json!([named]), PolicyEffect::Allow, 1);
        assert_eq!(
            evaluate_agent_management(Some(&[policy]), &f.context(AgentPolicyOperation::Execute)),
            Err(AgentManagementError::UnsupportedRule)
        );
    }
    let mut context = f.context(AgentPolicyOperation::Execute);
    context.content_action = CapabilityActionId::from_wire("ak.realm.owner");
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::InvalidOperationContext)
    );
}

#[test]
fn missing_foreign_and_service_resource_facts_fail_closed() {
    let f = Fixture::new();
    let mut context = f.context(AgentPolicyOperation::Join);
    context.resources = None;
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::InvalidOperationContext)
    );
    let mut facts = f.resources.clone();
    facts[1].realm_id = None;
    context.resources = Some(&facts);
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::InvalidOperationContext)
    );
    let mut service_facts = f.resources.clone();
    service_facts[1].kind = PolicyResourceKind::Service;
    context.resources = Some(&service_facts);
    assert_eq!(
        evaluate_agent_management(Some(&[]), &context),
        Err(AgentManagementError::InvalidOperationContext)
    );
}

#[test]
fn malformed_or_duplicate_policy_sets_cannot_be_partial_current() {
    let f = Fixture::new();
    let policy = f.policy(json!([all("allow", 0)]), PolicyEffect::Allow, 1);
    let context = f.context(AgentPolicyOperation::Execute);
    assert_eq!(
        evaluate_agent_management(Some(&[policy.clone(), policy.clone()]), &context),
        Err(AgentManagementError::DuplicatePolicy)
    );
    for (index, mut changed) in [policy.clone(), policy.clone(), policy.clone(), policy]
        .into_iter()
        .enumerate()
    {
        match index {
            0 => changed.realm_id = None,
            1 => changed.policy_kind = PolicyKind::Access,
            2 => {
                changed.not_before = Some(f.at);
                changed.expires_at = Some(f.at);
            }
            _ => {
                changed.realm_id = Some(RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [8; 32],
                )))
            }
        }
        assert_eq!(
            evaluate_agent_management(Some(&[changed]), &context),
            Err(AgentManagementError::InvalidPolicy)
        );
    }
    let mut malformed = f.policy(json!([all("allow", 0)]), PolicyEffect::Allow, 1);
    malformed.rules.clear();
    assert_eq!(
        evaluate_agent_management(Some(&[malformed]), &context),
        Err(AgentManagementError::InvalidPolicy)
    );
}

#[test]
fn unsupported_non_agent_rule_is_not_silently_ignored() {
    let f = Fixture::new();
    let policy=f.policy(json!([{"rule_id":"unimplemented","kind":"action","effect":"deny","actions":["ak.message.create"]}]),PolicyEffect::Allow,1);
    assert_eq!(
        evaluate_agent_management(Some(&[policy]), &f.context(AgentPolicyOperation::Execute)),
        Err(AgentManagementError::UnsupportedRule)
    );
}
