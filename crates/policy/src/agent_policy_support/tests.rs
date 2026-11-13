use arkret_models_collaboration::governance::operation_wire::{
    ManagementOperation, ManagementReviewRequirement, PolicyResourceSelector,
};
use arkret_wire::{AccountId, ActorId, CircleId, EventId, RealmId, SpaceId, StrandId};
use serde_json::json;

use super::*;

fn event(seed: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
}

fn policy() -> Policy {
    serde_json::from_value(json!({
        "schema":"ak.schema.policy.v1",
        "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
        "realm_id":RealmId::from_event_id(&event(11)), "policy_kind":"agent",
        "rules":[{"rule_id":"agents", "kind":"agent", "effect":"deny",
            "agent_target":{"kind":"all"}, "agent_operations":["join"]}],
        "default_effect":"allow",
        "created_by":{"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:admin.example",
            "station_id":"ak:did_core:web:station.example"}},
        "created_at":"2026-10-19T12:00:00.000Z"
    }))
    .unwrap()
}

fn requirement() -> ManagementReviewRequirement {
    ManagementReviewRequirement {
        approver_actor_ids: vec![ActorId::account(AccountId::new(
            "ak:did_core:web:admin.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))],
        threshold: 1,
        max_age_seconds: 60,
    }
}

fn kind(result: Result<(), AgentPolicySupportError>) -> &'static str {
    use AgentPolicySupportError as E;
    match result {
        Ok(()) => "ok",
        Err(E::InvalidPolicy(_)) => "syntax",
        Err(E::NotAgentPolicy) => "family",
        Err(E::GovernanceScope) => "scope",
        Err(E::CircleReview) => "circle_review",
        Err(E::RuleKind) => "rule",
        Err(E::UnknownAction) => "unknown_action",
        Err(E::AggregateAdminAction) => "aggregate_action",
        Err(E::ServiceAction) => "service_action",
        Err(E::JoinPublishActionSelector) => "join_publish_actions",
        Err(E::CrossRealmResource) => "cross_realm",
        Err(E::ResourceReference) => "resource_ref",
        Err(E::ServiceResource) => "service_resource",
    }
}

fn cases() -> Vec<(String, Policy, ScopeRef, &'static str)> {
    let base = policy();
    let realm = base.realm_id.clone().unwrap();
    let mut cases = Vec::new();
    for circle in [false, true] {
        let scope = if circle {
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: CircleId::from_event_id(&event(12)),
            }
        } else {
            ScopeRef::Realm {
                realm_id: realm.clone(),
            }
        };
        let mut add = |name: &str, p: Policy, expected| {
            cases.push((format!("{circle}/{name}"), p, scope.clone(), expected));
        };
        for operation in [
            AgentPolicyOperation::Join,
            AgentPolicyOperation::Authorize,
            AgentPolicyOperation::Execute,
            AgentPolicyOperation::Read,
            AgentPolicyOperation::Deliver,
            AgentPolicyOperation::Publish,
            AgentPolicyOperation::Serve,
        ] {
            for effect in [
                PolicyEffect::Allow,
                PolicyEffect::Deny,
                PolicyEffect::Quarantine,
            ] {
                let mut p = base.clone();
                p.rules[0].agent_operations = Some(vec![operation]);
                p.rules[0].effect = effect.clone();
                add(&format!("{operation:?}/{effect:?}"), p, "ok");
            }
        }
        for effect in [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::Quarantine,
        ] {
            let mut p = base.clone();
            p.default_effect = effect.clone();
            add(&format!("default/{effect:?}"), p, "ok");
        }
        for operation in [AgentPolicyOperation::Join, AgentPolicyOperation::Publish] {
            let mut p = base.clone();
            p.rules[0].agent_operations = Some(vec![operation]);
            p.rules[0].effect = PolicyEffect::RequireReview;
            p.rules[0].review_requirement = Some(requirement());
            add(
                &format!("review/{operation:?}"),
                p,
                if circle { "circle_review" } else { "ok" },
            );
            let mut p = base.clone();
            p.rules[0].agent_operations = Some(vec![operation]);
            p.rules[0].actions = Some(vec!["ak.message.create".into()]);
            add(&format!("actions/{operation:?}"), p, "join_publish_actions");
        }
        let mut p = base.clone();
        p.default_effect = PolicyEffect::RequireReview;
        p.default_operations = Some(vec![
            ManagementOperation::Join,
            ManagementOperation::Publish,
        ]);
        p.default_review_requirement = Some(requirement());
        add(
            "default_review",
            p,
            if circle { "circle_review" } else { "ok" },
        );
        let mut p = base.clone();
        p.rules[0].agent_operations = Some(vec![AgentPolicyOperation::Execute]);
        p.rules[0].effect = PolicyEffect::RequireReview;
        p.rules[0].review_requirement = Some(requirement());
        add("execute_review", p, "syntax");
        let mut p = base.clone();
        p.default_effect = PolicyEffect::RequireReview;
        add("default_review_missing_carrier", p, "syntax");
        for (action, expected) in [
            ("ak.message.create", "ok"),
            ("ak.unknown.action", "unknown_action"),
            ("ak.realm.admin", "aggregate_action"),
            (
                ServiceOperationId::SelfAccountDataReadListV1.as_str(),
                "service_action",
            ),
        ] {
            let mut p = base.clone();
            p.rules[0].agent_operations = Some(vec![AgentPolicyOperation::Execute]);
            p.rules[0].actions = Some(vec![action.into()]);
            add(action, p, expected);
        }
        for (resource_kind, reference) in [
            (PolicyResourceKind::Realm, realm.to_string()),
            (
                PolicyResourceKind::Strand,
                StrandId::from_event_id(&event(13)).to_string(),
            ),
            (
                PolicyResourceKind::Space,
                SpaceId::from_event_id(&event(13)).to_string(),
            ),
            (PolicyResourceKind::Object, realm.to_string()),
            (
                PolicyResourceKind::Service,
                "ak:did_core:web:station.example".into(),
            ),
        ] {
            let mut p = base.clone();
            p.rules[0].resources = Some(vec![PolicyResourceSelector {
                kind: resource_kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(reference),
            }]);
            add(
                &format!("resource/{resource_kind:?}"),
                p.clone(),
                if resource_kind == PolicyResourceKind::Service {
                    "service_resource"
                } else {
                    "ok"
                },
            );
            p.rules[0].resources.as_mut().unwrap()[0].realm_id =
                Some(RealmId::from_event_id(&event(14)));
            add(
                &format!("cross_realm/{resource_kind:?}"),
                p.clone(),
                "cross_realm",
            );
            if resource_kind != PolicyResourceKind::Service {
                p.rules[0].resources.as_mut().unwrap()[0].realm_id = Some(realm.clone());
                p.rules[0].resources.as_mut().unwrap()[0].resource_ref =
                    Some("ak:unknown:invalid".into());
                add(
                    &format!("invalid_ref/{resource_kind:?}"),
                    p.clone(),
                    "resource_ref",
                );
                p.rules[0].resources.as_mut().unwrap()[0].resource_ref = None;
                add(&format!("wildcard/{resource_kind:?}"), p, "ok");
            }
        }
        let mut p = base.clone();
        p.rules[0].kind = PolicyRuleKind::Action;
        p.rules[0].agent_target = None;
        p.rules[0].agent_operations = None;
        p.rules[0].actions = Some(vec!["ak.message.create".into()]);
        add("non_agent_rule", p, "rule");
        let mut p = base.clone();
        p.rules.clear();
        add("empty_rules", p, "syntax");
    }
    cases.push((
        "wrong_scope".into(),
        base.clone(),
        ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&event(14)),
        },
        "scope",
    ));
    cases.push((
        "genesis_scope".into(),
        base.clone(),
        ScopeRef::RealmGenesis,
        "scope",
    ));
    let mut p = base;
    p.policy_kind = PolicyKind::Access;
    cases.push((
        "wrong_family".into(),
        p,
        ScopeRef::Realm { realm_id: realm },
        "family",
    ));
    cases
}

#[test]
fn reference_backend_configuration_matrix_has_typed_rejections() {
    let cases = cases();
    assert!(cases.len() > 100);
    for (name, p, scope, expected) in &cases {
        assert_eq!(
            kind(validate_agent_policy_support(
                p,
                scope,
                &REFERENCE_AGENT_POLICY_SUPPORT
            )),
            *expected,
            "{name}"
        );
    }
    println!("{} exact configuration cases", cases.len());
}

#[test]
fn declared_backend_support_never_overrides_protocol_review_legality() {
    let support = AgentPolicyBackendSupport {
        circle_review: true,
    };
    let mut p = policy();
    let scope = ScopeRef::Circle {
        realm_id: p.realm_id.clone().unwrap(),
        circle_id: CircleId::from_event_id(&event(12)),
    };
    p.rules[0].effect = PolicyEffect::RequireReview;
    p.rules[0].review_requirement = Some(requirement());
    assert!(validate_agent_policy_support(&p, &scope, &support).is_ok());
    p.rules[0].agent_operations = Some(vec![AgentPolicyOperation::Execute]);
    assert_eq!(
        kind(validate_agent_policy_support(&p, &scope, &support)),
        "syntax"
    );
}

#[test]
fn backend_review_support_cannot_turn_service_or_admin_into_content() {
    let support = AgentPolicyBackendSupport {
        circle_review: true,
    };
    for (name, p, scope, expected) in cases().into_iter().filter(|(_, _, _, expected)| {
        matches!(
            *expected,
            "aggregate_action"
                | "service_action"
                | "service_resource"
                | "unknown_action"
                | "join_publish_actions"
        )
    }) {
        assert_eq!(
            kind(validate_agent_policy_support(&p, &scope, &support)),
            expected,
            "{name}"
        );
    }
}
