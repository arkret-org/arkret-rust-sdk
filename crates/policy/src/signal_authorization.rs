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
    profile_actions: &[String],
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
        .chain(profile_actions)
        .any(|owned| operation.actions.contains(&owned.as_str()))
        || original
            .unreserved()
            .iter()
            .any(|grant| live.unreserved().iter().any(|active| active.id == grant.id))
}

fn controller_allows(
    operation: &AuthorizationOperation<'_>,
    agent: &arkret_models_collaboration::SignalAgentProductAuthority,
    profile_actions: &[String],
    sent_at: DateTime<Utc>,
) -> bool {
    let original = evaluate_grants(
        &AuthorizationOperation {
            at: sent_at,
            ..*operation
        },
        agent.controller_grants.iter(),
    );
    let current = evaluate_grants(operation, agent.current_controller_grants.iter());
    if original.is_refusal() || current.is_refusal() {
        return false;
    }
    let role = |actions: &[String]| {
        actions
            .iter()
            .chain(profile_actions)
            .any(|action| operation.actions.contains(&action.as_str()))
    };
    (role(&agent.historical_controller_owner_actions) || !original.unreserved().is_empty())
        && (role(&agent.current_controller_owner_actions) || !current.unreserved().is_empty())
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
    strand_actions_allowed(
        authority,
        sender,
        scope,
        strand,
        now,
        &[
            CapabilityActionId::MESSAGE_STREAM_SEND,
            CapabilityActionId::MESSAGE_CREATE,
        ],
        Some("message"),
    )
}

/// Complete Typing permission at the original and current cut, including
/// applicable refusal constraints and independent Agent ceilings.
pub fn typing_allowed(
    authority: &SignalProductAuthority,
    sender: &ActorId,
    scope: &ScopeRef,
    strand: &StrandId,
    now: DateTime<Utc>,
) -> bool {
    strand_actions_allowed(
        authority,
        sender,
        scope,
        strand,
        now,
        &[CapabilityActionId::TYPING_BROADCAST],
        None,
    )
}

/// Product visibility restrictions for an effective member. The caller must
/// separately prove current membership, the active track and MLS readability;
/// member-derived reads never require a fabricated explicit read grant.
pub fn typing_visible(
    authority: &SignalProductAuthority,
    recipient: &ActorId,
    scope: &ScopeRef,
    strand: &StrandId,
    now: DateTime<Utc>,
) -> bool {
    let target = WireResourceSelector::strand(scope.realm_id().clone(), strand.clone());
    let facts = OperationFacts {
        strand_id: Some(strand.to_string()),
        circle_id: match scope {
            ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
            _ => None,
        },
        track: Some("discussion".into()),
        object_kind: Some("strand".into()),
        ..Default::default()
    };
    let operation = AuthorizationOperation {
        actor: recipient,
        actions: &[CapabilityActionId::STRAND_READ],
        target: &target,
        at: now,
        facts: &facts,
    };
    product_policies_allow(
        &authority.historical_product_policies,
        &AuthorizationOperation {
            at: authority.sent_at,
            ..operation
        },
    ) && product_policies_allow(&authority.current_product_policies, &operation)
}

fn strand_actions_allowed(
    authority: &SignalProductAuthority,
    sender: &ActorId,
    scope: &ScopeRef,
    strand: &StrandId,
    now: DateTime<Utc>,
    required_actions: &[&str],
    object_kind: Option<&str>,
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
        object_kind: object_kind.map(str::to_owned),
        ..Default::default()
    };
    for &action in required_actions {
        let actions = [action];
        let operation = AuthorizationOperation {
            actor: sender,
            actions: &actions,
            target: &target,
            at: now,
            facts: &facts,
        };
        if !allows(
            &operation,
            &authority.grants,
            &authority.current_grants,
            &authority.owner_actions,
            &authority.profile_actions,
            authority.sent_at,
        ) {
            return false;
        }
        if !product_policies_allow(
            &authority.historical_product_policies,
            &AuthorizationOperation {
                at: authority.sent_at,
                ..operation
            },
        ) || !product_policies_allow(&authority.current_product_policies, &operation)
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
            if !controller_allows(
                &controller_operation,
                agent,
                &authority.profile_actions,
                authority.sent_at,
            ) {
                return false;
            }
            if !product_policies_allow(
                &authority.historical_product_policies,
                &AuthorizationOperation {
                    at: authority.sent_at,
                    ..controller_operation
                },
            ) || !product_policies_allow(
                &authority.current_product_policies,
                &controller_operation,
            ) {
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

/// Policy only restricts an independently granted action. Unknown condition,
/// server, quota or extension inputs cannot be assumed to match or not match.
/// Known action/resource mismatch excludes a rule before unknown predicates.
pub fn product_policies_allow(
    policies: &[arkret_models_collaboration::governance::operation_wire::Policy],
    operation: &AuthorizationOperation<'_>,
) -> bool {
    use arkret_models_collaboration::governance::operation_wire::{
        PolicyResourceKind, PolicyRuleKind,
    };
    use arkret_wire::{PolicyEffect, PolicyKind};
    fn rank(effect: &PolicyEffect) -> u8 {
        match effect {
            PolicyEffect::Allow => 0,
            PolicyEffect::RequireReview => 1,
            PolicyEffect::Quarantine => 2,
            PolicyEffect::Deny => 3,
        }
    }
    policies.iter().all(|policy| {
        if !matches!(
            policy.policy_kind,
            PolicyKind::Access | PolicyKind::Moderation
        ) || policy.realm_id.as_ref() != operation.target.realm_id.as_ref()
            || policy.validate().is_err()
            || policy.created_at > operation.at
        {
            return false;
        }
        if policy.not_before.is_some_and(|time| time > operation.at)
            || policy.expires_at.is_some_and(|time| time <= operation.at)
        {
            return true;
        }
        let mut matched: Option<(i64, u8)> = None;
        let mut unknown: Option<i64> = None;
        for rule in &policy.rules {
            if rule.actions.as_ref().is_some_and(|actions| {
                !actions
                    .iter()
                    .any(|action| operation.actions.contains(&action.as_str()))
            }) {
                continue;
            }
            if rule.resources.as_ref().is_some_and(|resources| {
                !resources.iter().any(|resource| {
                    resource
                        .realm_id
                        .as_ref()
                        .is_none_or(|realm| operation.target.realm_id.as_ref() == Some(realm))
                        && match resource.kind {
                            PolicyResourceKind::Realm => {
                                resource.resource_ref.as_deref().is_none_or(|id| {
                                    operation
                                        .target
                                        .realm_id
                                        .as_ref()
                                        .is_some_and(|realm| realm.as_str() == id)
                                })
                            }
                            PolicyResourceKind::Strand => {
                                resource.resource_ref.as_deref().is_none_or(|id| {
                                    operation
                                        .target
                                        .strand_id
                                        .as_ref()
                                        .is_some_and(|strand| strand.as_str() == id)
                                })
                            }
                            _ => false,
                        }
                })
            }) {
                continue;
            }
            let evaluable = matches!(rule.kind, PolicyRuleKind::Action | PolicyRuleKind::Resource)
                && rule.conditions.is_none()
                && rule.servers.is_none()
                && rule.schema_ref.is_none()
                && rule.profile_ref.is_none()
                && rule.params.is_none()
                && rule.review_requirement.is_none();
            if !evaluable {
                unknown = Some(unknown.map_or(rule.priority, |held| held.max(rule.priority)));
                continue;
            }
            matched = Some(match matched {
                Some((priority, effect)) if priority == rule.priority => {
                    (priority, effect.max(rank(&rule.effect)))
                }
                Some(held) if held.0 > rule.priority => held,
                _ => (rule.priority, rank(&rule.effect)),
            });
        }
        if unknown.is_some_and(|priority| matched.is_none_or(|held| priority >= held.0)) {
            return false;
        }
        matched.map_or_else(|| rank(&policy.default_effect), |(_, effect)| effect) == 0
    })
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
            historical_product_policies: vec![],
            current_product_policies: vec![],
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
    fn policy(
        rules: serde_json::Value,
        default: &str,
    ) -> arkret_models_collaboration::governance::operation_wire::Policy {
        serde_json::from_value(serde_json::json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001", "schema":"ak.schema.policy.v1", "realm_id":REALM,
            "policy_kind":"access", "rules":rules, "default_effect":default,
            "created_by":actor("ak:did_core:web:station-a.example"), "created_at":"2026-10-01T00:00:00.000Z"
        })).unwrap()
    }

    #[test]
    fn typing_product_policy_priority_and_parent_restrictions_do_not_grant_authority() {
        let mut evidence = material();
        evidence.grants[0].actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        evidence.current_grants = evidence.grants.clone();
        let gate = |evidence: &SignalProductAuthority| {
            typing_allowed(
                evidence,
                &actor("ak:did_core:web:station-a.example"),
                &ScopeRef::Realm {
                    realm_id: REALM.parse().unwrap(),
                },
                &STRAND.parse().unwrap(),
                at(),
            )
        };
        for effect in ["deny", "quarantine", "require_review"] {
            let deny = policy(
                serde_json::json!([{"rule_id":"restrict_typing","kind":"action","effect":effect,"actions":[CapabilityActionId::TYPING_BROADCAST]}]),
                "allow",
            );
            for historical in [true, false] {
                evidence.historical_product_policies.clear();
                evidence.current_product_policies.clear();
                if historical {
                    evidence.historical_product_policies.push(deny.clone());
                } else {
                    evidence.current_product_policies.push(deny.clone());
                }
                assert!(!gate(&evidence), "{effect} historical={historical}");
            }
        }
        evidence.historical_product_policies.clear();
        evidence.current_product_policies = vec![policy(
            serde_json::json!([
                {"rule_id":"lower_deny","kind":"action","effect":"deny","priority":1,"actions":[CapabilityActionId::TYPING_BROADCAST]},
                {"rule_id":"higher_allow","kind":"action","effect":"allow","priority":2,"actions":[CapabilityActionId::TYPING_BROADCAST]}
            ]),
            "deny",
        )];
        assert!(gate(&evidence));
        evidence.current_product_policies[0].rules[0].priority = 2;
        assert!(!gate(&evidence));
        evidence.current_product_policies[0].rules.reverse();
        assert!(!gate(&evidence));
        evidence.current_product_policies[0].rules[0].priority = 3;
        assert!(gate(&evidence));
        let allow = evidence.current_product_policies[0].clone();
        evidence.historical_product_policies = vec![policy(
            serde_json::json!([{"rule_id":"parent_deny","kind":"resource","effect":"deny","resources":[{"kind":"realm","realm_id":REALM}]}]),
            "allow",
        )];
        assert!(!gate(&evidence));
        evidence.historical_product_policies.clear();
        evidence.current_product_policies = vec![allow];
        evidence.grants.clear();
        evidence.current_grants.clear();
        assert!(!gate(&evidence));
    }

    #[test]
    fn typing_product_policy_target_time_and_unknown_predicates_fail_closed() {
        let mut evidence = material();
        evidence.profile_actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        let gate = |evidence: &SignalProductAuthority| {
            typing_allowed(
                evidence,
                &actor("ak:did_core:web:station-a.example"),
                &ScopeRef::Realm {
                    realm_id: REALM.parse().unwrap(),
                },
                &STRAND.parse().unwrap(),
                at(),
            )
        };
        let mut unknown = policy(
            serde_json::json!([{"rule_id":"unknown","kind":"action","effect":"deny","actions":[CapabilityActionId::TYPING_BROADCAST],"conditions":{"private_quota":true}}]),
            "allow",
        );
        evidence.current_product_policies = vec![unknown.clone()];
        assert!(!gate(&evidence));
        unknown.rules[0].actions = Some(vec![CapabilityActionId::MESSAGE_CREATE.into()]);
        evidence.current_product_policies = vec![unknown];
        assert!(gate(&evidence));
        let targeted = policy(
            serde_json::json!([{"rule_id":"other_target","kind":"resource","effect":"deny","resources":[{"kind":"strand","realm_id":REALM,"resource_ref":"ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy"}]}]),
            "allow",
        );
        evidence.current_product_policies = vec![targeted];
        assert!(gate(&evidence));
        evidence.current_product_policies[0].rules[0]
            .resources
            .as_mut()
            .unwrap()[0]
            .resource_ref = Some(STRAND.into());
        assert!(!gate(&evidence));
        evidence.current_product_policies[0].expires_at = Some(at());
        assert!(gate(&evidence));
        evidence.current_product_policies[0].expires_at = None;
        evidence.current_product_policies[0].not_before = Some(at() + chrono::Duration::seconds(1));
        assert!(gate(&evidence));
    }

    #[test]
    fn typing_broadcast_cannot_override_target_read_visibility_policy() {
        let mut evidence = material();
        evidence.profile_actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        evidence.current_product_policies = vec![policy(
            serde_json::json!([{"rule_id":"hide_target","kind":"action","effect":"deny","actions":[CapabilityActionId::STRAND_READ]}]),
            "allow",
        )];
        let sender = actor("ak:did_core:web:station-a.example");
        let scope = ScopeRef::Realm {
            realm_id: REALM.parse().unwrap(),
        };
        let strand = STRAND.parse().unwrap();
        assert!(typing_allowed(&evidence, &sender, &scope, &strand, at()));
        assert!(!typing_visible(&evidence, &sender, &scope, &strand, at()));
        evidence.current_product_policies.clear();
        assert!(typing_visible(&evidence, &sender, &scope, &strand, at()));
    }

    #[test]
    fn typing_requires_its_own_live_source_and_profile_never_bypasses_refusal() {
        let mut evidence = material();
        let gate = |evidence: &SignalProductAuthority| {
            typing_allowed(
                evidence,
                &actor("ak:did_core:web:station-a.example"),
                &ScopeRef::Realm {
                    realm_id: REALM.parse().unwrap(),
                },
                &STRAND.parse().unwrap(),
                at(),
            )
        };
        assert!(!gate(&evidence));
        evidence.grants[0].actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        evidence.current_grants = evidence.grants.clone();
        assert!(gate(&evidence));
        evidence.current_grants.clear();
        assert!(!gate(&evidence));
        evidence.current_grants = evidence.grants.clone();
        evidence.current_grants[0].id = arkret_wire::GrantId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [12; 32]),
        );
        assert!(!gate(&evidence));
        evidence.grants.clear();
        evidence.current_grants.clear();
        evidence.owner_actions = vec![CapabilityActionId::MESSAGE_CREATE.into()];
        assert!(!gate(&evidence));
        evidence.profile_actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        assert!(gate(&evidence));
        let mut negative = material().grants.remove(0);
        negative.actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        for effect in [
            GrantConstraintEffect::Deny,
            GrantConstraintEffect::Quarantine,
            GrantConstraintEffect::RequireReview,
        ] {
            negative.constraints = vec![GrantConstraint::new(
                GrantConstraintKind::ScopeLimitation,
                effect,
            )];
            negative.constraints[0].allowed_session_ids = vec!["unknown-private-session".into()];
            evidence.grants = vec![negative.clone()];
            assert!(!gate(&evidence));
            evidence.grants.clear();
            evidence.current_grants = vec![negative.clone()];
            assert!(!gate(&evidence));
            evidence.current_grants.clear();
        }
    }

    #[test]
    fn typing_agent_controller_management_and_key_are_independent_ceilings() {
        use arkret_models_collaboration::SignalAgentProductAuthority;
        let mut evidence = material();
        evidence.grants[0].actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        evidence.current_grants = evidence.grants.clone();
        let controller = AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station-a.example".parse().unwrap(),
        );
        let mut grant = evidence.grants[0].clone();
        grant.subject = CapabilitySubject::Actor(ActorId::account(controller.clone()));
        evidence.agent = Some(SignalAgentProductAuthority { controller_account_id:controller, controller_grants:vec![grant.clone()], current_controller_grants:vec![grant], historical_controller_owner_actions:vec![], current_controller_owner_actions:vec![], historical_management_policies:vec![], current_management_policies:vec![], key_scope:serde_json::from_value(serde_json::json!({"actions":[CapabilityActionId::TYPING_BROADCAST],"resources":[{"kind":"realm","realm_id":REALM}]})).unwrap() });
        let gate = |evidence: &SignalProductAuthority| {
            typing_allowed(
                evidence,
                &actor("ak:did_core:web:station-a.example"),
                &ScopeRef::Realm {
                    realm_id: REALM.parse().unwrap(),
                },
                &STRAND.parse().unwrap(),
                at(),
            )
        };
        assert!(gate(&evidence));
        evidence.agent.as_mut().unwrap().current_controller_grants[0].id =
            arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [13; 32],
            ));
        assert!(
            gate(&evidence),
            "an equivalent live controller source need not preserve its old parent ID"
        );
        let valid = evidence.clone();
        evidence
            .agent
            .as_mut()
            .unwrap()
            .current_controller_grants
            .clear();
        assert!(!gate(&evidence));
        evidence = valid.clone();
        evidence.agent.as_mut().unwrap().key_scope.actions =
            vec![CapabilityActionId::MESSAGE_CREATE.into()];
        assert!(!gate(&evidence));
        let deny: arkret_models_collaboration::governance::operation_wire::Policy = serde_json::from_value(serde_json::json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001", "schema":"ak.schema.policy.v1", "realm_id":REALM,
            "policy_kind":"agent", "rules":[{"rule_id":"deny_execute","kind":"agent","effect":"deny","priority":0,"agent_target":{"kind":"all"},"agent_operations":["execute"]}], "default_effect":"allow", "created_by":actor("ak:did_core:web:station-a.example"), "created_at":"2026-10-01T00:00:00.000Z"
        })).unwrap();
        evidence = valid;
        evidence
            .agent
            .as_mut()
            .unwrap()
            .historical_management_policies = vec![deny];
        assert!(!gate(&evidence));
        let agent = evidence.agent.as_mut().unwrap();
        agent.current_management_policies =
            std::mem::take(&mut agent.historical_management_policies);
        assert!(!gate(&evidence));
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
        evidence.agent = Some(SignalAgentProductAuthority { controller_account_id:controller, controller_grants:vec![controller_grant.clone()], current_controller_grants:vec![controller_grant], historical_controller_owner_actions:vec![], current_controller_owner_actions:vec![], historical_management_policies:vec![], current_management_policies:vec![], key_scope:serde_json::from_value(serde_json::json!({"actions":[CapabilityActionId::MESSAGE_STREAM_SEND, CapabilityActionId::MESSAGE_CREATE],"resources":[{"kind":"realm","realm_id":REALM}]})).unwrap() });
        assert!(allowed(&evidence));
        let valid = evidence.clone();
        evidence
            .agent
            .as_mut()
            .unwrap()
            .historical_controller_owner_actions = vec![CapabilityActionId::MESSAGE_CREATE.into()];
        evidence.agent.as_mut().unwrap().controller_grants[0].actions =
            vec![CapabilityActionId::MESSAGE_STREAM_SEND.into()];
        assert!(
            allowed(&evidence),
            "historical owner and a current grant are independent legal controller paths"
        );
        evidence
            .agent
            .as_mut()
            .unwrap()
            .historical_controller_owner_actions
            .clear();
        assert!(!allowed(&evidence));
        evidence = valid;
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
