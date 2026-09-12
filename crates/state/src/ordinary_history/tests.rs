use arkret_wire::{AuthorizationDependencyKind, CapabilityActionId, DidCoreId, Hlc};
use serde_json::json;

use super::*;

fn realm() -> RealmId {
    RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
}

fn id(label: &str) -> EventId {
    EventId::from_event_digest(
        &Hash::new(arkret_canonical::sha256_digest(label.as_bytes())).unwrap(),
    )
    .unwrap()
}

fn usage(generation: &str) -> AuthorizationUse {
    AuthorizationUse {
        authority_realm_id: realm(),
        dependency_kind: AuthorizationDependencyKind::MemberJoin,
        authorization_event_id: id("member-authorization"),
        generation_event_id: id(generation),
        scope_ref: ScopeRef::Realm { realm_id: realm() },
        actions: BTreeSet::from([CapabilityActionId::MessageCreate]),
    }
}

fn event(
    label: &str,
    generation: &str,
    previous: &[EventId],
    causal: &[EventId],
) -> HistoryEventInput {
    let mut event = arkret_wire::test_support::raw_event_at(
        "ak.message.create",
        ScopeRef::Realm { realm_id: realm() },
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        7,
        Hlc::new("0198d35d9800-0000-a13f9c2e").unwrap(),
        json!({"body": label}),
        "2026-09-12T00:00:00.000Z".parse().unwrap(),
    )
    .unwrap();
    event.prev_refs = previous.to_vec();
    event.causal_refs = causal.iter().map(|id| id.event_digest()).collect();
    event.event_id = EventId::from_event_digest(
        &Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    // These tests supply algorithm inputs; they do not exercise authentication.
    HistoryEventInput {
        event,
        authorization: HistoryAuthorizationInput::Ordinary {
            uses: vec![usage(generation)],
            execution_dependencies: BTreeSet::new(),
        },
    }
}

#[derive(Default)]
struct Source(BTreeMap<EventId, HistoryEventInput>);
impl Source {
    fn insert(&mut self, event: HistoryEventInput) -> EventId {
        let id = event.event.event_id.clone();
        self.0.insert(id.clone(), event);
        id
    }
}
impl HistoryInputSource for Source {
    fn event(&self, id: &EventId) -> Result<Option<&HistoryEventInput>, HistoryEvidenceError> {
        Ok(self.0.get(id))
    }
}

fn cut(command: &str, generation: &str, frontier: Vec<EventId>) -> AuthorizationClosure {
    let usage = usage(generation);
    let mut frontier = frontier;
    frontier.sort();
    AuthorizationClosure {
        command_event_id: id(command),
        dependency_kind: usage.dependency_kind,
        authorization_event_id: usage.authorization_event_id,
        generation_event_id: usage.generation_event_id,
        scope_ref: usage.scope_ref,
        actions: usage.actions.into_iter().collect(),
        frontier,
    }
}

fn inventory(closures: Vec<AuthorizationClosure>) -> HistoryClosureInventoryInput {
    // This fixture supplies a closure inventory input without an authentication claim.
    HistoryClosureInventoryInput::from_prefix_inputs([HistoryClosurePrefixInput {
        realm_id: realm(),
        head: SealId::new(format!(
            "ak:seal:{}",
            arkret_canonical::sha256_digest(b"head")
        ))
        .unwrap(),
        closures,
        committed_events: [
            "member-authorization",
            "parent-grant",
            "generation",
            "old-generation",
            "new-generation",
            "parent-generation",
        ]
        .into_iter()
        .map(id)
        .collect(),
    }])
    .unwrap()
}

#[test]
fn same_sequence_branches_are_distinguished_by_exact_event_identity() {
    let mut source = Source::default();
    let a = source.insert(event("a", "generation", &[], &[]));
    let b = source.insert(event("b", "generation", &[], &[]));
    assert_eq!(source.0[&a].event.actor_seq, source.0[&b].event.actor_seq);
    let inventory = inventory(vec![cut("cut", "generation", vec![a.clone()])]);
    assert_eq!(
        classify_ordinary_history(&a, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    assert!(matches!(
        classify_ordinary_history(&b, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
}

#[test]
fn causal_digest_parents_and_previous_ids_form_one_complete_closure() {
    let mut source = Source::default();
    let a = source.insert(event("a", "generation", &[], &[]));
    let b = source.insert(event("b", "generation", &[], &[]));
    let c = source.insert(event(
        "c",
        "generation",
        std::slice::from_ref(&a),
        std::slice::from_ref(&b),
    ));
    let closure =
        frontier_for_complete_history(&BTreeSet::from([a.clone(), b.clone(), c.clone()]), &source)
            .unwrap();
    assert_eq!(closure.frontier(), &[c.clone()]);
    assert_eq!(closure.event_ids(), &BTreeSet::from([a, b, c]));
}

#[test]
fn wider_later_cut_cannot_revive_an_excluded_event() {
    let mut source = Source::default();
    let a = source.insert(event("a", "generation", &[], &[]));
    let b = source.insert(event("b", "generation", std::slice::from_ref(&a), &[]));
    let inventory = inventory(vec![
        cut("first", "generation", vec![a]),
        cut("later", "generation", vec![b.clone()]),
    ]);
    assert_eq!(
        classify_ordinary_history(&b, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined {
            closing_commands: BTreeSet::from([id("first")]),
            unauthorized_events: BTreeSet::new(),
            rejected_commands: BTreeSet::new(),
        }
    );
}

#[test]
fn a_new_authorization_generation_is_not_cut_by_an_old_generation() {
    let mut source = Source::default();
    let new = source.insert(event("new", "new-generation", &[], &[]));
    let inventory = inventory(vec![cut("cut", "old-generation", vec![])]);
    assert_eq!(
        classify_ordinary_history(&new, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
}

#[test]
fn missing_cut_ancestor_is_pending_even_when_target_is_not_a_frontier_member() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    let missing = event("missing", "generation", std::slice::from_ref(&target), &[]);
    let tip = source.insert(event(
        "tip",
        "generation",
        std::slice::from_ref(&missing.event.event_id),
        &[],
    ));
    let inventory = inventory(vec![cut("cut", "generation", vec![tip])]);
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
    source.insert(missing);
    assert_eq!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
}

#[test]
fn authenticated_empty_cut_excludes_but_missing_prefix_is_pending() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    let mut inventory = inventory(vec![cut("cut", "generation", vec![])]);
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
    inventory.prefixes.clear();
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
    assert!(HistoryClosureInventoryInput::from_prefix_inputs([]).is_err());
}

#[test]
fn causal_replies_do_not_inherit_quarantine_but_execution_dependencies_do() {
    let mut source = Source::default();
    let old = source.insert(event("old", "old-generation", &[], &[]));
    let reply = source.insert(event(
        "reply",
        "new-generation",
        &[],
        std::slice::from_ref(&old),
    ));
    let inventory = inventory(vec![cut("cut", "old-generation", vec![])]);
    assert_eq!(
        classify_ordinary_history(&reply, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    let HistoryAuthorizationInput::Ordinary {
        execution_dependencies,
        ..
    } = &mut source.0.get_mut(&reply).unwrap().authorization
    else {
        unreachable!()
    };
    execution_dependencies.insert(old);
    assert!(matches!(
        classify_ordinary_history(&reply, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
}

#[test]
fn unrelated_actions_do_not_close_a_verified_use() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    let mut unrelated = cut("cut", "generation", vec![]);
    unrelated.actions = vec![CapabilityActionId::MessageRevise];
    assert_eq!(
        classify_ordinary_history(&target, &inventory(vec![unrelated]), &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
}

#[test]
fn input_structure_rejects_empty_authorization_uses() {
    let event = event("target", "generation", &[], &[]).event;
    assert!(matches!(
        HistoryEventInput::from_inputs(
            event,
            DigestSuite::Sha256,
            HistoryAuthorizationInput::Ordinary {
                uses: vec![],
                execution_dependencies: BTreeSet::new()
            }
        ),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn missing_target_ancestor_prevents_eligibility_without_any_known_cuts() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[id("missing")], &[]));
    assert!(matches!(
        classify_ordinary_history(&target, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
}

#[test]
fn full_prefix_cannot_be_replaced_by_an_empty_closure_list() {
    let head = SealId::new(format!(
        "ak:seal:{}",
        arkret_canonical::sha256_digest(b"head")
    ))
    .unwrap();
    assert!(matches!(
        HistoryClosurePrefixInput::from_complete_prefix_inputs(&[], &head),
        Err(HistoryEvidenceError::Unavailable(_))
    ));
}

#[test]
fn historical_authorization_denial_is_quarantine_not_invalid_evidence() {
    let mut source = Source::default();
    let mut denied = event("denied", "generation", &[], &[]);
    denied.authorization = HistoryAuthorizationInput::Unauthorized;
    let target = source.insert(denied);
    assert_eq!(
        classify_ordinary_history(&target, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined {
            closing_commands: BTreeSet::new(),
            unauthorized_events: BTreeSet::from([target.clone()]),
            rejected_commands: BTreeSet::new(),
        }
    );
    assert!(frontier_for_complete_history(&BTreeSet::from([target]), &source).is_err());
}

#[test]
fn all_delegation_parent_uses_must_satisfy_their_own_cuts() {
    let mut source = Source::default();
    let mut target = event("target", "generation", &[], &[]);
    let HistoryAuthorizationInput::Ordinary { uses, .. } = &mut target.authorization else {
        unreachable!()
    };
    let mut parent = usage("parent-generation");
    parent.authorization_event_id = id("parent-grant");
    uses.push(parent.clone());
    let target = source.insert(target);
    let mut parent_cut = cut("parent-close", "parent-generation", vec![]);
    parent_cut.authorization_event_id = parent.authorization_event_id;
    let inventory = inventory(vec![
        cut("member-close", "generation", vec![target.clone()]),
        parent_cut,
    ]);
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
}

#[test]
fn an_older_security_prefix_cannot_confirm_a_new_authorization_generation() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    let mut inventory = inventory(vec![]);
    inventory
        .prefixes
        .get_mut(&realm())
        .unwrap()
        .committed_events
        .remove(&id("generation"));
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
}

#[test]
fn selected_reply_retains_unauthorized_ancestor_bytes_without_inheriting_ineligibility() {
    let mut source = Source::default();
    let mut ancestor = event("ancestor", "generation", &[], &[]);
    ancestor.authorization = HistoryAuthorizationInput::Unauthorized;
    let ancestor = source.insert(ancestor);
    let reply = source.insert(event(
        "reply",
        "generation",
        &[],
        std::slice::from_ref(&ancestor),
    ));
    let closure = frontier_for_complete_history(&BTreeSet::from([reply.clone()]), &source).unwrap();
    assert_eq!(closure.frontier(), std::slice::from_ref(&reply));
    assert!(closure.event_ids().contains(&ancestor));
    assert_eq!(
        classify_ordinary_history(&reply, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
}

#[test]
fn pending_or_rejected_control_causal_evidence_does_not_create_execution_effects() {
    for outcome in [
        None,
        Some(CommandOutcome::Rejected),
        Some(CommandOutcome::Committed),
    ] {
        let mut source = Source::default();
        let mut command = event("command", "generation", &[], &[]);
        command.authorization = HistoryAuthorizationInput::ControlEvidence {
            command_outcome: outcome,
        };
        let command = source.insert(command);
        let reply = source.insert(event(
            "reply",
            "generation",
            &[],
            std::slice::from_ref(&command),
        ));
        assert!(frontier_for_complete_history(&BTreeSet::from([reply.clone()]), &source).is_ok());
        assert_eq!(
            classify_ordinary_history(&reply, &inventory(vec![]), &source).unwrap(),
            OrdinaryHistoryEligibility::Eligible
        );
        let HistoryAuthorizationInput::Ordinary {
            execution_dependencies,
            ..
        } = &mut source.0.get_mut(&reply).unwrap().authorization
        else {
            unreachable!()
        };
        execution_dependencies.insert(command.clone());
        let result = classify_ordinary_history(&reply, &inventory(vec![]), &source).unwrap();
        match outcome {
            None => assert!(matches!(result, OrdinaryHistoryEligibility::Pending { .. })),
            Some(CommandOutcome::Rejected) => assert!(
                matches!(result, OrdinaryHistoryEligibility::Quarantined { rejected_commands, .. } if rejected_commands == BTreeSet::from([command]))
            ),
            Some(CommandOutcome::Committed) => {
                assert_eq!(result, OrdinaryHistoryEligibility::Eligible)
            }
        }
    }
}

#[test]
fn unresolved_ancestor_authorization_does_not_block_a_separately_authorized_reply() {
    let mut source = Source::default();
    let mut ancestor = event("ancestor", "generation", &[], &[]);
    ancestor.authorization = HistoryAuthorizationInput::AuthorizationPending;
    let ancestor = source.insert(ancestor);
    let reply = source.insert(event(
        "reply",
        "generation",
        &[],
        std::slice::from_ref(&ancestor),
    ));
    assert!(frontier_for_complete_history(&BTreeSet::from([reply.clone()]), &source).is_ok());
    assert_eq!(
        classify_ordinary_history(&reply, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    assert!(matches!(
        classify_ordinary_history(&ancestor, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
}

#[test]
fn one_complete_excluding_cut_outweighs_another_incomplete_cut() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    for cuts in [
        vec![
            cut("missing", "generation", vec![id("unavailable")]),
            cut("exclude", "generation", vec![]),
        ],
        vec![
            cut("exclude", "generation", vec![]),
            cut("missing", "generation", vec![id("unavailable")]),
        ],
    ] {
        assert!(
            matches!(classify_ordinary_history(&target, &inventory(cuts), &source).unwrap(), OrdinaryHistoryEligibility::Quarantined { closing_commands, .. } if closing_commands == BTreeSet::from([id("exclude")]))
        );
    }
}

#[test]
fn a_complete_exclusion_outweighs_missing_execution_dependencies() {
    let mut source = Source::default();
    let mut target = event("target", "generation", &[], &[]);
    let HistoryAuthorizationInput::Ordinary {
        execution_dependencies,
        ..
    } = &mut target.authorization
    else {
        unreachable!()
    };
    execution_dependencies.insert(id("missing-execution-dependency"));
    let target = source.insert(target);
    assert!(matches!(
        classify_ordinary_history(&target, &inventory(vec![]), &source).unwrap(),
        OrdinaryHistoryEligibility::Pending { .. }
    ));
    assert!(matches!(
        classify_ordinary_history(
            &target,
            &inventory(vec![cut("exclude", "generation", vec![])]),
            &source
        )
        .unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
}

#[test]
fn proven_invalid_evidence_is_not_hidden_by_exclusion_or_missing_evidence() {
    let mut source = Source::default();
    let target = source.insert(event("target", "generation", &[], &[]));
    let wrong_key = id("wrong-key");
    source.0.insert(
        wrong_key.clone(),
        event("another-event", "generation", &[], &[]),
    );
    let mut incomplete_and_invalid = vec![id("unavailable"), wrong_key];
    incomplete_and_invalid.sort();
    let inventory = inventory(vec![
        cut("exclude", "generation", vec![]),
        cut("invalid", "generation", incomplete_and_invalid),
    ]);
    assert!(matches!(
        classify_ordinary_history(&target, &inventory, &source),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn genesis_controller_transfer_does_not_close_root_grants_or_member_baseline() {
    let mut source = Source::default();
    let mut direct = event("direct-controller", "generation", &[], &[]);
    let mut granted = event("granted", "generation", &[], &[]);
    let mut baseline = event("baseline", "generation", &[], &[]);
    let mut same_genesis = usage("member-authorization");
    same_genesis.dependency_kind = AuthorizationDependencyKind::RealmControllerAssignment;
    let HistoryAuthorizationInput::Ordinary { uses, .. } = &mut direct.authorization else {
        unreachable!()
    };
    *uses = vec![same_genesis.clone()];
    same_genesis.dependency_kind = AuthorizationDependencyKind::RealmAuthorityGeneration;
    let HistoryAuthorizationInput::Ordinary { uses, .. } = &mut granted.authorization else {
        unreachable!()
    };
    let mut grant = usage("parent-grant");
    grant.authorization_event_id = id("parent-grant");
    grant.dependency_kind = AuthorizationDependencyKind::CapabilityGrant;
    *uses = vec![same_genesis.clone(), grant];
    let HistoryAuthorizationInput::Ordinary { uses, .. } = &mut baseline.authorization else {
        unreachable!()
    };
    same_genesis.dependency_kind = AuthorizationDependencyKind::MemberJoin;
    *uses = vec![same_genesis];
    let direct = source.insert(direct);
    let granted = source.insert(granted);
    let baseline = source.insert(baseline);
    let mut transfer = cut("transfer", "member-authorization", vec![]);
    transfer.dependency_kind = AuthorizationDependencyKind::RealmControllerAssignment;
    let transfer_inventory = inventory(vec![transfer.clone()]);
    assert!(matches!(
        classify_ordinary_history(&direct, &transfer_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
    assert_eq!(
        classify_ordinary_history(&granted, &transfer_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    assert_eq!(
        classify_ordinary_history(&baseline, &transfer_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    let mut reset = transfer;
    reset.command_event_id = id("reset");
    reset.dependency_kind = AuthorizationDependencyKind::RealmAuthorityGeneration;
    let reset_inventory = inventory(vec![reset]);
    assert!(matches!(
        classify_ordinary_history(&granted, &reset_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
    assert_eq!(
        classify_ordinary_history(&baseline, &reset_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
}

#[test]
fn reopened_lifecycle_gate_keeps_the_other_gate_identity_without_false_revocation() {
    let mut source = Source::default();
    let mut restored = event("restored-unfrozen", "new-generation", &[], &[]);
    let HistoryAuthorizationInput::Ordinary { uses, .. } = &mut restored.authorization else {
        unreachable!()
    };
    uses[0].dependency_kind = AuthorizationDependencyKind::RealmUnarchived;
    let mut never_frozen = usage("old-generation");
    never_frozen.dependency_kind = AuthorizationDependencyKind::RealmUnfrozen;
    uses.push(never_frozen);
    let restored = source.insert(restored);
    let mut archive = cut("archive", "old-generation", vec![]);
    archive.dependency_kind = AuthorizationDependencyKind::RealmUnarchived;
    let archive_inventory = inventory(vec![archive.clone()]);
    assert_eq!(
        classify_ordinary_history(&restored, &archive_inventory, &source).unwrap(),
        OrdinaryHistoryEligibility::Eligible
    );
    let mut freeze = archive;
    freeze.command_event_id = id("freeze");
    freeze.dependency_kind = AuthorizationDependencyKind::RealmUnfrozen;
    assert!(matches!(
        classify_ordinary_history(&restored, &inventory(vec![freeze]), &source).unwrap(),
        OrdinaryHistoryEligibility::Quarantined { .. }
    ));
}

#[test]
fn coordinate_validation_rejects_unknown_kinds_and_incompatible_action_or_scope() {
    let member = cut("cut", "generation", vec![]);
    member.validate_structural().unwrap();
    let mut value = serde_json::to_value(&member).unwrap();
    value["dependency_kind"] = json!("lifecycle");
    assert!(serde_json::from_value::<AuthorizationClosure>(value).is_err());
    let mut value = serde_json::to_value(&member).unwrap();
    value["actions"] = json!(["ak.message.edit"]);
    assert!(serde_json::from_value::<AuthorizationClosure>(value).is_err());
    let mut invalid = member.clone();
    invalid.dependency_kind = AuthorizationDependencyKind::ConsentGrant;
    assert!(invalid.validate_structural().is_err());
    invalid.dependency_kind = AuthorizationDependencyKind::CircleActive;
    assert!(invalid.validate_structural().is_err());
    invalid.dependency_kind = AuthorizationDependencyKind::DeviceAuthorization;
    invalid.scope_ref = ScopeRef::RealmGenesis;
    assert!(invalid.validate_structural().is_err());
    let mut invalid_use = usage("generation");
    invalid_use.dependency_kind = AuthorizationDependencyKind::CircleActive;
    assert!(
        HistoryEventInput::from_inputs(
            event("target", "generation", &[], &[]).event,
            DigestSuite::Sha256,
            HistoryAuthorizationInput::Ordinary {
                uses: vec![invalid_use],
                execution_dependencies: BTreeSet::new()
            }
        )
        .is_err()
    );
}
