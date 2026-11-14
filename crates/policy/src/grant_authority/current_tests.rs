//! Actual current-candidate and positive-source boundaries, without I/O.
use arkret_canonical::DigestSuite;
use arkret_wire::{AccountId, CapabilityActionId, EventId, RealmId};
use chrono::TimeDelta;

use super::*;
use crate::grant_evaluation::{
    AuthorizationOperation, GrantEvaluation, OperationFacts, evaluate_grants,
};

const ACTION: &str = CapabilityActionId::CALL_RECORD;

fn at(minute: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc)
        + TimeDelta::minutes(minute)
}

fn actor(name: &str) -> ActorId {
    ActorId::account(AccountId::new(
        format!("ak:did_core:web:{name}.example").parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}

fn realm() -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [240; 32]))
}

fn root_source() -> IssuerAuthorityRef {
    IssuerAuthorityRef::RealmRoot {
        realm_id: realm(),
        authority_event_ref: EventId::from_digest(DigestSuite::Sha256, [241; 32]),
        authority_generation: 0,
    }
}

fn root_current(source: &IssuerAuthorityRef) -> bool {
    source == &root_source()
}

fn temporal(
    effect: GrantConstraintEffect,
    action: Option<&str>,
    from: Option<i64>,
    until: Option<i64>,
) -> GrantConstraint {
    let mut constraint = GrantConstraint::new(GrantConstraintKind::Temporal, effect);
    constraint.applies_to_actions = action.into_iter().map(str::to_owned).collect();
    constraint.not_before = from.map(at);
    constraint.expires_at = until.map(at);
    constraint
}

fn grant(seed: u8, subject: ActorId, constraints: Vec<GrantConstraint>) -> CapabilityGrant {
    let root = AuthorityRootRef::RealmRoot {
        realm_id: realm(),
        authority_event_ref: EventId::from_digest(DigestSuite::Sha256, [241; 32]),
        authority_generation: 0,
    };
    serde_json::from_value(serde_json::json!({
        "id": GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256,[seed;32])),
        "schema":"ak.schema.capability.v1", "realm_id":realm(),
        "issuer_id":actor("owner"), "subject":subject,
        "actions":[ACTION,CapabilityActionId::CALL_JOIN],
        "resources":[WireResourceSelector::realm(realm())], "constraints":constraints,
        "issuer_authority_refs":[root_source()], "authority_depth":1,
        "authority_root_ref":root, "issued_at":"2026-11-01T00:00:00.000Z",
        "status":"active"
    }))
    .unwrap()
}

fn global_window() -> GrantConstraint {
    temporal(GrantConstraintEffect::Allow, None, None, Some(120))
}

fn evaluate<'g>(
    subject: &ActorId,
    candidates: impl IntoIterator<Item = &'g CapabilityGrant>,
    time: DateTime<Utc>,
) -> GrantEvaluation<'g> {
    evaluate_grants(
        &AuthorizationOperation {
            actor: subject,
            actions: &[ACTION],
            target: &WireResourceSelector::realm(realm()),
            at: time,
            facts: &OperationFacts::default(),
        },
        candidates,
    )
}

#[test]
fn a_terminal_allow_window_cannot_erase_its_current_refusals() {
    let subject = actor("holder");
    let target = WireResourceSelector::realm(realm());
    for (effect, expected) in [
        (GrantConstraintEffect::Deny, 0),
        (GrantConstraintEffect::Quarantine, 1),
        (GrantConstraintEffect::RequireReview, 2),
    ] {
        for (from, until) in [(Some(60), None), (None, Some(20))] {
            let refusal = grant(
                242,
                subject.clone(),
                vec![
                    global_window(),
                    temporal(effect, Some(ACTION), Some(0), None),
                    temporal(GrantConstraintEffect::Allow, Some(ACTION), from, until),
                ],
            );
            let positive = grant(243, subject.clone(), vec![global_window()]);
            let rows = BTreeMap::from([
                (refusal.id.clone(), refusal.clone()),
                (positive.id.clone(), positive.clone()),
            ]);
            assert!(matches!(
                current_sources(&refusal, ACTION, &target, &rows, at(30), root_current),
                Err(AuthorityError::Closed)
            ));
            assert!(
                current_candidate_sources(&refusal, ACTION, &target, &rows, at(30), root_current)
                    .is_ok()
            );
            let candidates =
                current_subject_grants(&subject, ACTION, &target, &rows, at(30), root_current)
                    .unwrap();
            assert_eq!(candidates.len(), 2);
            match (expected, evaluate(&subject, candidates, at(30))) {
                (0, GrantEvaluation::Denied)
                | (1, GrantEvaluation::Quarantined)
                | (2, GrantEvaluation::RequiresReview) => {}
                (_, other) => panic!("a terminal allow cannot erase {effect:?}: {other:?}"),
            }
            assert!(
                current_sources(&positive, ACTION, &target, &rows, at(30), root_current).is_ok()
            );
        }
    }
}

#[test]
fn retained_candidates_are_not_positive_paths_and_real_global_expiry_still_closes_them() {
    let subject = actor("holder");
    let target = WireResourceSelector::realm(realm());
    let mut future = grant(
        242,
        subject.clone(),
        vec![
            global_window(),
            temporal(GrantConstraintEffect::Allow, Some(ACTION), Some(60), None),
        ],
    );
    let positive = grant(243, subject.clone(), vec![global_window()]);
    let rows = BTreeMap::from([
        (future.id.clone(), future.clone()),
        (positive.id.clone(), positive.clone()),
    ]);
    let candidates =
        current_subject_grants(&subject, ACTION, &target, &rows, at(30), root_current).unwrap();
    let GrantEvaluation::Allowed(paths) = evaluate(&subject, candidates, at(30)) else {
        panic!("another independently satisfied source remains usable")
    };
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].grant.id, positive.id);
    assert!(matches!(
        evaluate(&subject, [&future], at(30)),
        GrantEvaluation::Unsatisfied
    ));
    future.constraints[0].not_before = Some(at(60));
    assert!(matches!(
        current_candidate_sources(&future, ACTION, &target, &rows, at(30), root_current),
        Err(AuthorityError::Closed)
    ));
    future.constraints[0].not_before = None;
    assert!(matches!(
        current_candidate_sources(&future, ACTION, &target, &rows, at(120), root_current),
        Err(AuthorityError::Closed)
    ));
}

fn delegated_pair() -> (CapabilityGrant, CapabilityGrant) {
    let issuer = actor("delegate");
    let mut parent = grant(
        244,
        issuer.clone(),
        vec![
            global_window(),
            temporal(GrantConstraintEffect::Allow, Some(ACTION), None, Some(20)),
            temporal(GrantConstraintEffect::Deny, Some(ACTION), Some(0), None),
            GrantConstraint::authority_control(1, true),
        ],
    );
    parent.actions = vec![ACTION.into()];
    let mut child = grant(
        245,
        actor("holder"),
        vec![
            global_window(),
            temporal(GrantConstraintEffect::Allow, Some(ACTION), None, Some(20)),
            parent.constraints[2].clone(),
            GrantConstraint::authority_control(0, false),
        ],
    );
    child.issuer_id = issuer;
    child.authority_depth = 2;
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent.id.clone(),
    }];
    (parent, child)
}

#[test]
fn every_contributing_ancestor_keeps_its_actual_action_window() {
    let (mut parent, child) = delegated_pair();
    let target = WireResourceSelector::realm(realm());
    for (from, until) in [(None, Some(20)), (Some(60), None)] {
        parent.constraints[1].not_before = from.map(at);
        parent.constraints[1].expires_at = until.map(at);
        let rows = BTreeMap::from([
            (parent.id.clone(), parent.clone()),
            (child.id.clone(), child.clone()),
        ]);
        assert!(matches!(
            current_candidate_sources(&child, ACTION, &target, &rows, at(30), root_current),
            Err(AuthorityError::Closed)
        ));
        assert!(matches!(
            current_sources(&child, ACTION, &target, &rows, at(30), root_current),
            Err(AuthorityError::Closed)
        ));
        // Parent's own refusal is still current for its own subject, but it
        // no longer supplies action authority to a delegated child's refusal.
        assert!(
            current_candidate_sources(&parent, ACTION, &target, &rows, at(30), root_current)
                .is_ok()
        );
        let CapabilitySubject::Actor(issuer) = &parent.subject else {
            unreachable!()
        };
        let own =
            current_subject_grants(issuer, ACTION, &target, &rows, at(30), root_current).unwrap();
        assert!(matches!(
            evaluate(issuer, own, at(30)),
            GrantEvaluation::Denied
        ));
        let CapabilitySubject::Actor(holder) = &child.subject else {
            unreachable!()
        };
        assert!(
            current_subject_grants(holder, ACTION, &target, &rows, at(30), root_current)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn candidate_lineage_never_downgrades_unknown_or_invalid_sources_to_absence() {
    let (mut parent, child) = delegated_pair();
    parent.constraints[1].expires_at = Some(at(90));
    let target = WireResourceSelector::realm(realm());
    let mut rows = BTreeMap::from([
        (parent.id.clone(), parent.clone()),
        (child.id.clone(), child.clone()),
    ]);
    assert!(
        current_candidate_sources(&child, ACTION, &target, &rows, at(30), root_current).is_ok()
    );
    assert!(matches!(
        current_candidate_sources(&child, ACTION, &target, &rows, at(30), |_| false),
        Err(AuthorityError::Closed)
    ));
    rows.get_mut(&parent.id).unwrap().status = CapabilityGrantStatus::Revoked;
    assert!(matches!(
        current_candidate_sources(&child, ACTION, &target, &rows, at(30), root_current),
        Err(AuthorityError::Closed)
    ));
    rows.insert(parent.id.clone(), parent.clone());
    rows.get_mut(&parent.id).unwrap().constraints[0].expires_at = Some(at(20));
    assert!(matches!(
        current_candidate_sources(&child, ACTION, &target, &rows, at(30), root_current),
        Err(AuthorityError::Closed)
    ));
    rows.insert(parent.id.clone(), parent.clone());
    rows.get_mut(&parent.id).unwrap().authority_depth = 2;
    assert!(matches!(
        current_candidate_sources(&child, ACTION, &target, &rows, at(30), root_current),
        Err(AuthorityError::Depth)
    ));
    rows.remove(&parent.id);
    let positive = grant(243, actor("holder"), vec![global_window()]);
    rows.insert(positive.id.clone(), positive);
    let CapabilitySubject::Actor(holder) = &child.subject else {
        unreachable!()
    };
    assert_eq!(
        current_subject_grants(holder, ACTION, &target, &rows, at(30), root_current).unwrap_err(),
        AuthorityError::Unproved
    );
}
