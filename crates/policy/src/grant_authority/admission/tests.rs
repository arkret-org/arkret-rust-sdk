use arkret_canonical::{DigestSuite, canonical_json_bytes, sha256_bytes};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrantStatus, CapabilitySubject,
};
use arkret_wire::{ActorId, EventId, RealmCommitId, RealmId, WireResourceSelector};
use serde_json::json;

use super::*;

// The sidecar profile is not generic Realm-owner grant authority. Exercise
// finite root approval with an actually owner-grantable registered action.
const FINITE_ROOT_ACTION: &str = "ak.message.mention.broadcast";

fn at(hour: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc)
        + TimeDelta::hours(hour)
}
fn realm() -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [1; 32]))
}
fn actor() -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:owner.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}
fn root() -> AuthorityRootRef {
    AuthorityRootRef::RealmRoot {
        realm_id: realm(),
        authority_event_ref: EventId::from_digest(DigestSuite::Sha256, [2; 32]),
        authority_generation: 0,
    }
}
fn root_source() -> IssuerAuthorityRef {
    serde_json::from_value(serde_json::to_value(root()).unwrap()).unwrap()
}
fn resource(seed: u8) -> WireResourceSelector {
    serde_json::from_value(json!({"kind":"strand","realm_id":realm(),
        "strand_id":arkret_wire::StrandId::from_event_id(&EventId::from_digest(DigestSuite::Sha256,[seed;32]))})).unwrap()
}
fn control(depth: u64) -> GrantConstraint {
    GrantConstraint::authority_control(depth, true)
}
fn bounds(from: Option<i64>, until: Option<i64>) -> GrantConstraint {
    let mut constraint =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    constraint.not_before = from.map(at);
    constraint.expires_at = until.map(at);
    constraint
}
fn constraints(action: &str, depth: u64, until: Option<i64>) -> Vec<GrantConstraint> {
    let mut constraints = vec![control(depth), bounds(None, until)];
    if action == FINITE_ROOT_ACTION {
        constraints.push(
            serde_json::from_value(json!({
                "constraint_kind":"quota", "constraint_subkind":"rate", "effect":"allow",
                "max_operation_count":100, "period":"PT1H", "constraint_scope":"per_actor"
            }))
            .unwrap(),
        );
    }
    constraints
}
fn parent(
    seed: u8,
    action: &str,
    target: WireResourceSelector,
    until: Option<i64>,
) -> CapabilityGrant {
    serde_json::from_value(json!({
        "id":GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256,[seed;32])),
        "schema":"ak.schema.capability.v1", "realm_id":realm(), "issuer_id":actor(),"subject":actor(),
        "actions":[action],"resources":[target],"constraints":constraints(action,3,until),
        "issuer_authority_refs":[root_source()],"authority_depth":1,"authority_root_ref":root(),
        "issued_at":"2000-01-01T00:00:00.000Z","status":"active"
    })).unwrap()
}
fn child(
    parents: &[&CapabilityGrant],
    action: &str,
    targets: Vec<WireResourceSelector>,
    until: Option<i64>,
) -> CapabilityGrantCreateBody {
    CapabilityGrantCreateBody {
        schema: "ak.schema.capability.v1".into(),
        realm_id: Some(realm()),
        issuer_id: actor(),
        subject: CapabilitySubject::Actor(actor()),
        actions: vec![action.into()],
        resources: targets,
        constraints: constraints(action, 2, until),
        issuer_authority_refs: if parents.is_empty() {
            vec![root_source()]
        } else {
            parents
                .iter()
                .map(|parent| IssuerAuthorityRef::Grant {
                    grant_id: parent.id.clone(),
                })
                .collect()
        },
        issued_at: at(-100),
    }
}
fn commit(seed: u8, position: u64, time: DateTime<Utc>) -> RealmCommit {
    // This fixture models already qualified native facts. Signature verification
    // is deliberately not claimed by this pure policy test.
    let event = EventId::from_digest(DigestSuite::Sha256, [seed; 32]);
    let time = arkret_canonical::format_timestamp_canonical(time);
    let mut value = json!({"realm_id":realm(),"stream_ref":{"kind":"realm","realm_id":realm()},
        "stream_position":position,"previous_commit_ref":RealmCommitId::from_digest([3;32]),
        "event_ref":event,"governance_generation":"0","authority_ref":event,"committed_at":time});
    value["commit_id"] = json!(RealmCommitId::from_digest(sha256_bytes(
        canonical_json_bytes(&value).unwrap()
    )));
    value["signature"] = json!({"context":"ak.realm_commit_signature.v1","signature_algorithm":"Ed25519",
        "verification_method":"did:web:station.example#authority","signed_digest":format!("sha256:{}","0".repeat(64)),
        "created_at":time,"signature":"A".repeat(86)});
    serde_json::from_value(value).unwrap()
}
fn validate(
    body: &CapabilityGrantCreateBody,
    parents: &[(&CapabilityGrant, &RealmCommit)],
    accepting: &RealmCommit,
    ttl: u64,
) -> Result<DerivedGrantAuthority, AuthorityError> {
    let sources = parents
        .iter()
        .map(|(current, creation_commit)| {
            (
                current.id.clone(),
                GrantAdmissionSource {
                    current,
                    creation_commit,
                },
            )
        })
        .collect();
    validate_grant_admission(
        body,
        &GrantAdmissionContext {
            accepting_commit: accepting,
            current_root: &root(),
            max_lifetime_ms: ttl,
            shorter_lifetime: None,
            managed_role: None,
        },
        &sources,
        |_| true,
    )
}

#[test]
fn union_does_not_bridge_a_gap_and_matches_a_pointwise_oracle() {
    let interval = |a, b| GrantWindow {
        not_before: Some(at(a)),
        expires_at: Some(at(b)),
    };
    assert!(!window_union_covers(
        interval(0, 4),
        &[interval(0, 1), interval(2, 4)]
    ));
    assert!(window_union_covers(
        interval(0, 4),
        &[interval(-3, -1), interval(0, 2), interval(2, 4)]
    ));
    for a in 0..4 {
        for b in a + 1..5 {
            for c in 0..4 {
                for d in c + 1..5 {
                    let sources = [interval(a, b), interval(c, d)];
                    let expected = (0..8).all(|half| {
                        let x = at(0) + TimeDelta::minutes(half * 30);
                        sources.iter().any(|source| {
                            source.not_before.unwrap() <= x && x < source.expires_at.unwrap()
                        })
                    });
                    assert_eq!(window_union_covers(interval(0, 4), &sources), expected);
                }
            }
        }
    }
}

#[test]
fn native_creation_order_and_single_root_are_required() {
    let p = parent(4, "ak.message.create", resource(8), None);
    let body = child(&[&p], "ak.message.create", vec![resource(8)], None);
    let accepting = commit(9, 10, at(20));
    assert_eq!(
        validate(&body, &[(&p, &commit(4, 1, at(0)))], &accepting, 3_600_000)
            .unwrap()
            .authority_depth,
        2
    );
    for position in [10, 11] {
        assert!(
            validate(
                &body,
                &[(&p, &commit(4, position, at(0)))],
                &accepting,
                3_600_000
            )
            .is_err()
        );
    }
    assert!(validate(&body, &[(&p, &commit(5, 1, at(0)))], &accepting, 3_600_000).is_err());
    let mut wrong = p.clone();
    wrong.authority_root_ref = AuthorityRootRef::RealmRoot {
        realm_id: realm(),
        authority_event_ref: EventId::from_digest(DigestSuite::Sha256, [99; 32]),
        authority_generation: 0,
    };
    assert!(
        validate(
            &body,
            &[(&wrong, &commit(4, 1, at(0)))],
            &accepting,
            3_600_000
        )
        .is_err()
    );
}

#[test]
fn required_finite_root_uses_this_accepting_commit_and_new_approval_can_start_later() {
    let accepting = commit(9, 10, at(20));
    let mut body = child(&[], FINITE_ROOT_ACTION, vec![resource(8)], Some(21));
    assert!(crate::owner_may_grant(FINITE_ROOT_ACTION).unwrap());
    assert!(require_finite(FINITE_ROOT_ACTION).unwrap());
    assert!(
        crate::grant_evaluation::capability_grant_action_requirements_declared(
            FINITE_ROOT_ACTION,
            &body.resources,
            &body.constraints,
        )
    );
    assert!(validate(&body, &[], &accepting, 3_600_000).is_ok());
    body.constraints[1].not_before = Some(at(20) + TimeDelta::minutes(30));
    assert!(validate(&body, &[], &accepting, 3_600_000).is_ok());
    body.issued_at = at(100);
    assert!(validate(&body, &[], &accepting, 3_600_000).is_ok());
    body.constraints[1].expires_at = Some(at(22));
    assert_eq!(
        validate(&body, &[], &accepting, 3_600_000),
        Err(AuthorityError::Window)
    );
    assert!(validate(&body, &[], &commit(10, 11, at(21)), 3_600_000).is_ok());
    body.constraints[1].expires_at = None;
    assert_eq!(
        validate(&body, &[], &accepting, 3_600_000),
        Err(AuthorityError::Window)
    );
}

#[test]
fn profile_only_sidecar_action_is_not_generic_realm_root_authority() {
    let accepting = commit(9, 10, at(20));
    let body = child(&[], "ak.agent.sidecar.publish", vec![resource(8)], Some(21));
    assert!(!crate::owner_may_grant("ak.agent.sidecar.publish").unwrap());
    assert_eq!(
        validate(&body, &[], &accepting, 3_600_000),
        Err(AuthorityError::Coverage)
    );
}

#[test]
fn finite_parent_never_refreshes_and_ordinary_unbounded_action_has_no_new_ttl() {
    let accepting = commit(9, 10, at(20));
    let p = parent(4, FINITE_ROOT_ACTION, resource(8), Some(25));
    let mut body = child(&[&p], FINITE_ROOT_ACTION, vec![resource(8)], Some(25));
    assert!(validate(&body, &[(&p, &commit(4, 1, at(0)))], &accepting, 3_600_000).is_ok());
    body.constraints[1].expires_at = Some(at(26));
    assert_eq!(
        validate(&body, &[(&p, &commit(4, 1, at(0)))], &accepting, 3_600_000),
        Err(AuthorityError::Window)
    );
    let ordinary = child(&[], "ak.message.create", vec![resource(8)], None);
    assert!(validate(&ordinary, &[], &accepting, 0).is_ok());
}

#[test]
fn shorter_native_limits_are_pair_specific_and_do_not_reclip_finite_parents() {
    let accepting = commit(9, 10, at(20));
    let a = resource(8);
    let b = resource(7);
    let limits = |_: &str, target: &WireResourceSelector| {
        Ok(Some(if *target == a { 3_600_000 } else { 10_800_000 }))
    };
    let context = GrantAdmissionContext {
        accepting_commit: &accepting,
        current_root: &root(),
        max_lifetime_ms: 86_400_000,
        shorter_lifetime: Some(&limits),
        managed_role: None,
    };
    let body = child(&[], FINITE_ROOT_ACTION, vec![a.clone()], Some(22));
    assert_eq!(
        validate_grant_admission(&body, &context, &BTreeMap::new(), |_| true),
        Err(AuthorityError::Window)
    );
    let body = child(&[], FINITE_ROOT_ACTION, vec![b], Some(22));
    assert!(validate_grant_admission(&body, &context, &BTreeMap::new(), |_| true).is_ok());
    let p = parent(4, FINITE_ROOT_ACTION, a.clone(), Some(25));
    let creation = commit(4, 1, at(0));
    let sources = BTreeMap::from([(
        p.id.clone(),
        GrantAdmissionSource {
            current: &p,
            creation_commit: &creation,
        },
    )]);
    let body = child(&[&p], FINITE_ROOT_ACTION, vec![a.clone()], Some(25));
    assert!(validate_grant_admission(&body, &context, &sources, |_| true).is_ok());
    let unknown = |_: &str, _: &WireResourceSelector| Err(AuthorityError::Unproved);
    let context = GrantAdmissionContext {
        shorter_lifetime: Some(&unknown),
        ..context
    };
    let body = child(&[], FINITE_ROOT_ACTION, vec![resource(8)], Some(21));
    assert_eq!(
        validate_grant_admission(&body, &context, &BTreeMap::new(), |_| true),
        Err(AuthorityError::Unproved)
    );
}

#[test]
fn mixed_parents_keep_their_own_bounds_without_a_global_minimum() {
    let accepting = commit(9, 10, at(20));
    let a = parent(4, FINITE_ROOT_ACTION, resource(8), Some(25));
    // The unbounded contribution must itself be longevity-safe. A direct
    // grant of FINITE_ROOT_ACTION without expiry would be invalid before
    // this admission helper is reached; the owner aggregate can contribute
    // that action without inventing an invalid parent fixture.
    let b = parent(5, "ak.realm.owner", resource(8), None);
    let body = child(&[&a, &b], FINITE_ROOT_ACTION, vec![resource(8)], Some(25));
    assert!(
        validate(
            &body,
            &[(&a, &commit(4, 1, at(0))), (&b, &commit(5, 2, at(1)))],
            &accepting,
            3_600_000
        )
        .is_ok()
    );
}

#[test]
fn a_long_window_for_another_resource_or_action_cannot_cover_the_pair() {
    let accepting = commit(9, 10, at(20));
    let a = parent(4, "ak.message.create", resource(8), Some(21));
    let b = parent(5, "ak.message.create", resource(7), Some(25));
    let mut body = child(
        &[&a, &b],
        "ak.message.create",
        vec![resource(8), resource(7)],
        Some(25),
    );
    assert_eq!(
        validate(
            &body,
            &[(&a, &commit(4, 1, at(0))), (&b, &commit(5, 2, at(1)))],
            &accepting,
            3_600_000
        ),
        Err(AuthorityError::Window)
    );
    body.actions = vec!["ak.event.read".into()];
    assert_eq!(
        validate(
            &body,
            &[(&a, &commit(4, 1, at(0))), (&b, &commit(5, 2, at(1)))],
            &accepting,
            3_600_000
        ),
        Err(AuthorityError::Coverage)
    );
}

#[test]
fn closed_sources_unknown_budget_and_time_overflow_fail_closed() {
    let accepting = commit(9, 10, at(20));
    let mut p = parent(4, "ak.message.create", resource(8), None);
    let body = child(&[&p], "ak.message.create", vec![resource(8)], None);
    p.status = CapabilityGrantStatus::Revoked;
    assert_eq!(
        validate(&body, &[(&p, &commit(4, 1, at(0)))], &accepting, 3_600_000),
        Err(AuthorityError::Closed)
    );
    p.status = CapabilityGrantStatus::Active;
    p.constraints[1].max_duration = Some("PT1H".into());
    assert_eq!(
        validate(&body, &[(&p, &commit(4, 1, at(0)))], &accepting, 3_600_000),
        Err(AuthorityError::Unproved)
    );
    let root_child = child(&[], FINITE_ROOT_ACTION, vec![resource(8)], Some(21));
    assert_eq!(
        validate(&root_child, &[], &accepting, u64::MAX),
        Err(AuthorityError::Window)
    );
}

#[test]
fn deleting_cycle_detection_keeps_real_depth_and_current_root_gates() {
    let p = parent(4, "ak.message.create", resource(8), None);
    let body = child(&[&p], "ak.message.create", vec![resource(8)], None);
    let creation = commit(4, 1, at(0));
    let accepting = commit(9, 10, at(20));
    let mut too_deep = p.clone();
    too_deep.authority_depth = 4;
    assert_eq!(
        validate(&body, &[(&too_deep, &creation)], &accepting, 3_600_000),
        Err(AuthorityError::Depth)
    );
    let sources = BTreeMap::from([(
        p.id.clone(),
        GrantAdmissionSource {
            current: &p,
            creation_commit: &creation,
        },
    )]);
    assert_eq!(
        validate_grant_admission(
            &body,
            &GrantAdmissionContext {
                accepting_commit: &accepting,
                current_root: &root(),
                max_lifetime_ms: 3_600_000,
                shorter_lifetime: None,
                managed_role: None
            },
            &sources,
            |_| false
        ),
        Err(AuthorityError::Closed)
    );
}

#[test]
fn cache_dependency_is_receiver_derived_and_unknown_semantics_cannot_cache_allow() {
    let actions = vec!["ak.message.create".into()];
    assert_eq!(
        super::super::moderation_dependency(&actions, &[], &[], true),
        Ok(false)
    );
    assert_eq!(
        super::super::moderation_dependency(&actions, &["moderation_state"], &[], true),
        Ok(true)
    );
    assert_eq!(
        super::super::moderation_dependency(&actions, &[], &["moderation_state"], true),
        Ok(true)
    );
    assert_eq!(
        super::super::moderation_dependency(
            &["ak.moderation.decision.lift".into()],
            &[],
            &[],
            true
        ),
        Ok(true)
    );
    assert_eq!(
        super::super::moderation_dependency(&actions, &[], &[], false),
        Err(AuthorityError::Unproved)
    );
}

#[test]
fn accepted_profile_source_keeps_current_without_reissuing_its_approval() {
    let action = "ak.applet.bot.provision";
    let rule = issuer_rule(action).unwrap().unwrap();
    assert!(rule.issuer_owner_authority_allowed);
    assert_eq!(rule.issuer_action, "ak.realm.admin");
    assert!(!crate::owner_may_grant(action).unwrap());
    assert!(crate::owner_may_grant(rule.issuer_action).unwrap());
    // Native acceptance already established the registered Applet binding;
    // this pure test only exercises retained current facts at a later cut.
    let p = parent(4, action, resource(8), None);
    let grants = BTreeMap::from([(p.id.clone(), p.clone())]);
    assert!(current_sources(&p, action, &resource(8), &grants, at(20), |_| true).is_ok());
    assert_eq!(
        current_sources(&p, action, &resource(8), &grants, at(20), |_| false).unwrap_err(),
        AuthorityError::Closed
    );
    assert_eq!(
        current_sources(&p, action, &resource(7), &grants, at(20), |_| true).unwrap_err(),
        AuthorityError::Coverage
    );
    assert_eq!(
        current_sources(
            &p,
            "ak.message.create",
            &resource(8),
            &grants,
            at(20),
            |_| true
        )
        .unwrap_err(),
        AuthorityError::Coverage
    );
    let mut closed = p.clone();
    closed.status = CapabilityGrantStatus::Revoked;
    assert_eq!(
        current_sources(&closed, action, &resource(8), &grants, at(20), |_| true).unwrap_err(),
        AuthorityError::Closed
    );
}
