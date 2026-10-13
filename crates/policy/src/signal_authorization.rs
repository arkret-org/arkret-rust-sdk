//! Recipient product decisions over one delivery's authority-qualified material.
use arkret_models_collaboration::SignalProductAuthority;
use arkret_models_collaboration::governance::grant_constraint::CapabilityGrant;
use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
use arkret_wire::{ActorId, CapabilityActionId, ScopeRef, StrandId, WireResourceSelector};
use chrono::{DateTime, Utc};

use crate::grant_evaluation::{AuthorizationOperation, OperationFacts, evaluate_grants};

fn allows(
    operation: &AuthorizationOperation<'_>,
    historical: &[CapabilityGrant],
    current: &[CapabilityGrant],
    owner_actions: &[String],
    sent_at: DateTime<Utc>,
) -> bool {
    let original = evaluate_grants(
        &AuthorizationOperation {
            at: sent_at,
            ..*operation
        },
        historical.iter(),
    );
    let live = evaluate_grants(operation, current.iter());
    if original.is_refusal() || live.is_refusal() {
        return false;
    }
    owner_actions
        .iter()
        .any(|owned| operation.actions.contains(&owned.as_str()))
        || original
            .unreserved()
            .iter()
            .any(|grant| live.unreserved().iter().any(|active| active.id == grant.id))
}

/// Both actions are mandatory. No network call, history replay, quota write or
/// reusable authorization lease is created by this evaluation.
pub fn message_stream_allowed(
    authority: &SignalProductAuthority,
    sender: &ActorId,
    scope: &ScopeRef,
    strand: &StrandId,
    now: DateTime<Utc>,
) -> bool {
    if authority.current_realm_head.stream_ref != (arkret_wire::CommitStreamRef::Realm { realm_id: scope.realm_id().clone() })
        || arkret_wire::CommitStreamRef::from_scope(scope, None).ok().as_ref() != Some(&authority.current_scope_head.stream_ref)
        || authority.grants.iter().chain(&authority.current_grants).any(|g| !matches!(&g.subject, arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(actor) if actor == sender)) { return false; }
    let target = WireResourceSelector::strand(scope.realm_id().clone(), strand.clone());
    let facts = OperationFacts {
        strand_id: Some(strand.to_string()),
        circle_id: match scope {
            ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
            _ => None,
        },
        track: Some("discussion".into()),
        object_kind: Some("message".into()),
        ..Default::default()
    };
    for action in [
        CapabilityActionId::MESSAGE_STREAM_SEND,
        CapabilityActionId::MESSAGE_CREATE,
    ] {
        let actions = [action];
        let operation = AuthorizationOperation {
            actor: sender,
            actions: &actions,
            target: &target,
            at: now,
            facts: &facts,
        };
        let profile = authority.profile_actions.iter().any(|a| a == action);
        if !profile
            && !allows(
                &operation,
                &authority.grants,
                &authority.current_grants,
                &authority.owner_actions,
                authority.sent_at,
            )
        {
            return false;
        }
        if let Some(agent) = &authority.agent {
            let Some(account) = sender.as_account_id() else {
                return false;
            };
            if crate::agent_content_ceiling::require_key_scope_content_ceiling(
                &agent.key_scope,
                &operation,
            )
            .is_err()
            {
                return false;
            }
            let controller = ActorId::account(agent.controller_account_id.clone());
            let controller_operation = AuthorizationOperation {
                actor: &controller,
                ..operation
            };
            if !profile
                && !allows(
                    &controller_operation,
                    &agent.controller_grants,
                    &agent.current_controller_grants,
                    &agent.controller_owner_actions,
                    authority.sent_at,
                )
            {
                return false;
            }
            for (policies, at) in [
                (&agent.historical_management_policies, authority.sent_at),
                (&agent.current_management_policies, now),
            ] {
                let management_operation = AuthorizationOperation { at, ..operation };
                let Ok(actions) = crate::agent_content_ceiling::agent_management_actions(
                    policies,
                    scope.realm_id(),
                    &agent.controller_account_id,
                    account,
                    &management_operation,
                    Some(AgentPolicyOperation::Execute),
                ) else {
                    return false;
                };
                if !actions.contains(&action) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilitySubject, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    };
    use arkret_wire::{AccountId, CommitStreamHead, CommitStreamRef, RealmCommitId};

    use super::*;
    const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
    fn actor(station: &str) -> ActorId {
        ActorId::account(AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            station.parse().unwrap(),
        ))
    }
    fn at() -> DateTime<Utc> {
        "2026-10-13T15:00:00.000Z".parse().unwrap()
    }
    fn material() -> SignalProductAuthority {
        let sender = actor("ak:did_core:web:station-a.example");
        let grant: CapabilityGrant = serde_json::from_value(serde_json::json!({
            "id": arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7;32])),
            "schema":"ak.schema.capability.v1", "realm_id":REALM, "issuer_id":sender, "subject":sender,
            "actions":[CapabilityActionId::MESSAGE_STREAM_SEND, CapabilityActionId::MESSAGE_CREATE],
            "resources":[{"kind":"strand", "realm_id":REALM, "strand_id":STRAND}],
            "issuer_authority_refs":[{"kind":"realm_root", "realm_id":REALM, "authority_event_ref":arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[8;32]), "authority_generation":0}],
            "authority_root_refs":[{"kind":"realm_root", "realm_id":REALM, "authority_event_ref":arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[8;32]), "authority_generation":0}],
            "authority_depth":1, "issued_at":"2026-10-01T00:00:00.000Z", "status":"active"
        })).unwrap();
        let head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: REALM.parse().unwrap(),
            },
            commit_id: RealmCommitId::from_digest([9; 32]),
            stream_position: 9,
        };
        SignalProductAuthority {
            authority_commit_id: head.commit_id.clone(),
            parent_realm_authority_commit_id: None,
            current_realm_head: head.clone(),
            current_scope_head: head,
            sent_at: at(),
            grants: vec![grant.clone()],
            current_grants: vec![grant],
            owner_actions: vec![],
            profile_actions: vec![],
            agent: None,
        }
    }
    fn allowed(material: &SignalProductAuthority) -> bool {
        message_stream_allowed(
            material,
            &actor("ak:did_core:web:station-a.example"),
            &ScopeRef::Realm {
                realm_id: REALM.parse().unwrap(),
            },
            &STRAND.parse().unwrap(),
            at(),
        )
    }
    #[test]
    fn both_actions_exact_actor_and_target_are_required() {
        let mut evidence = material();
        assert!(allowed(&evidence));
        evidence.grants[0].actions.pop();
        assert!(!allowed(&evidence));
        let evidence = material();
        assert!(!message_stream_allowed(
            &evidence,
            &actor("ak:did_core:web:station-b.example"),
            &ScopeRef::Realm {
                realm_id: REALM.parse().unwrap()
            },
            &STRAND.parse().unwrap(),
            at()
        ));
        assert!(!message_stream_allowed(
            &evidence,
            &actor("ak:did_core:web:station-a.example"),
            &ScopeRef::Realm {
                realm_id: REALM.parse().unwrap()
            },
            &"ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy"
                .parse()
                .unwrap(),
            at()
        ));
    }
    #[test]
    fn revoked_source_cannot_be_replaced_by_a_new_grant() {
        let mut evidence = material();
        evidence.current_grants.clear();
        assert!(!allowed(&evidence));
        evidence.current_grants = material().current_grants;
        evidence.current_grants[0].id = arkret_wire::GrantId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [11; 32]),
        );
        assert!(!allowed(&evidence));
    }
    #[test]
    fn historical_and_current_refusals_precede_owner() {
        for historical in [true, false] {
            for effect in [
                GrantConstraintEffect::Deny,
                GrantConstraintEffect::Quarantine,
                GrantConstraintEffect::RequireReview,
            ] {
                let mut evidence = material();
                evidence.owner_actions = vec![
                    CapabilityActionId::MESSAGE_CREATE.into(),
                    CapabilityActionId::MESSAGE_STREAM_SEND.into(),
                ];
                let grant = if historical {
                    &mut evidence.grants[0]
                } else {
                    &mut evidence.current_grants[0]
                };
                let mut unknown =
                    GrantConstraint::new(GrantConstraintKind::ScopeLimitation, effect);
                unknown.allowed_session_ids = vec!["private-unavailable-session".into()];
                grant.constraints.push(unknown);
                assert!(!allowed(&evidence));
            }
        }
    }
    #[test]
    fn direct_profile_and_agent_key_controller_bounds_remain_independent() {
        use arkret_models_collaboration::SignalAgentProductAuthority;
        let mut evidence = material();
        let controller = AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station-a.example".parse().unwrap(),
        );
        let mut controller_grant = evidence.grants[0].clone();
        controller_grant.subject = CapabilitySubject::Actor(ActorId::account(controller.clone()));
        evidence.agent = Some(SignalAgentProductAuthority { controller_account_id:controller, controller_grants:vec![controller_grant.clone()], current_controller_grants:vec![controller_grant], controller_owner_actions:vec![], historical_management_policies:vec![], current_management_policies:vec![], key_scope:serde_json::from_value(serde_json::json!({"actions":[CapabilityActionId::MESSAGE_STREAM_SEND, CapabilityActionId::MESSAGE_CREATE],"resources":[{"kind":"realm","realm_id":REALM}]})).unwrap() });
        assert!(allowed(&evidence));
        let deny: arkret_models_collaboration::governance::operation_wire::Policy = serde_json::from_value(serde_json::json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001", "schema":"ak.schema.policy.v1", "realm_id":REALM,
            "policy_kind":"agent", "rules":[{"rule_id":"deny_execute","kind":"agent","effect":"deny","priority":0,"agent_target":{"kind":"all"},"agent_operations":["execute"]}], "default_effect":"allow", "created_by":actor("ak:did_core:web:station-a.example"), "created_at":"2026-10-01T00:00:00.000Z"
        })).unwrap();
        for historical in [true, false] {
            let policies = if historical {
                &mut evidence
                    .agent
                    .as_mut()
                    .unwrap()
                    .historical_management_policies
            } else {
                &mut evidence.agent.as_mut().unwrap().current_management_policies
            };
            policies.push(deny.clone());
            assert!(!allowed(&evidence));
            evidence
                .agent
                .as_mut()
                .unwrap()
                .historical_management_policies
                .clear();
            evidence
                .agent
                .as_mut()
                .unwrap()
                .current_management_policies
                .clear();
        }
        evidence
            .agent
            .as_mut()
            .unwrap()
            .current_controller_grants
            .clear();
        assert!(!allowed(&evidence));
        evidence.profile_actions = vec![CapabilityActionId::MESSAGE_CREATE.into()];
        assert!(!allowed(&evidence));
        evidence.agent.as_mut().unwrap().current_controller_grants =
            evidence.agent.as_ref().unwrap().controller_grants.clone();
        assert!(allowed(&evidence));
        evidence.agent.as_mut().unwrap().key_scope.actions.pop();
        assert!(!allowed(&evidence));
        evidence.agent = None;
        evidence.profile_actions.clear();
        evidence.grants.clear();
        evidence.current_grants.clear();
        evidence.owner_actions = vec![CapabilityActionId::MESSAGE_CREATE.into()];
        assert!(!allowed(&evidence));
    }
}
