use super::*;

const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const OTHER_REALM: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

fn actor() -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}

fn at() -> DateTime<Utc> {
    "2026-10-12T12:00:00.000Z".parse().unwrap()
}

fn target(realm: &str) -> WireResourceSelector {
    WireResourceSelector::strand(realm.parse().unwrap(), STRAND.parse().unwrap())
}

fn operation<'a>(
    actor: &'a ActorId,
    target: &'a WireResourceSelector,
    facts: &'a OperationFacts,
) -> AuthorizationOperation<'a> {
    AuthorizationOperation {
        actor,
        actions: &[CapabilityActionId::MESSAGE_CREATE],
        target,
        at: at(),
        facts,
    }
}

fn accepts(verdict: &GrantEvaluation<'_>) -> bool {
    matches!(verdict, GrantEvaluation::Allowed(candidates) if candidates.is_empty())
}

#[test]
fn explicit_resource_ceiling_rejects_other_realm_and_empty_set() {
    let actor = actor();
    let target = target(REALM);
    let facts = OperationFacts::default();
    let op = operation(&actor, &target, &facts);
    let correct = WireResourceSelector::realm(REALM.parse().unwrap());
    let wrong = WireResourceSelector::realm(OTHER_REALM.parse().unwrap());
    assert!(accepts(&evaluate_resource_constraint_ceiling(
        &op,
        &[correct],
        &[]
    )));
    assert!(!accepts(&evaluate_resource_constraint_ceiling(
        &op,
        &[wrong],
        &[]
    )));
    assert!(!accepts(&evaluate_resource_constraint_ceiling(
        &op,
        &[],
        &[]
    )));
}

#[test]
fn all_allow_constraints_intersect_actual_track_and_target() {
    let actor = actor();
    let target = target(REALM);
    let mut facts = OperationFacts {
        track: Some("discussion".into()),
        ..Default::default()
    };
    let mut track = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    track.allowed_tracks = vec!["discussion".into()];
    let mut strand = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    strand.allowed_strand_ids = vec![STRAND.into()];
    assert!(accepts(&evaluate_constraint_ceiling(
        &operation(&actor, &target, &facts),
        &[track.clone(), strand.clone()]
    )));
    facts.track = Some("synthesis".into());
    assert!(!accepts(&evaluate_constraint_ceiling(
        &operation(&actor, &target, &facts),
        &[track, strand]
    )));
}

#[test]
fn temporal_ceiling_uses_actual_evaluation_time() {
    let actor = actor();
    let target = target(REALM);
    let facts = OperationFacts::default();
    let op = operation(&actor, &target, &facts);
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(at() + TimeDelta::hours(1));
    assert!(accepts(&evaluate_constraint_ceiling(
        &op,
        &[temporal.clone()]
    )));
    let mut own_window =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    own_window.constraint_subkind = Some(GrantConstraintSubkind::EditWindow);
    own_window.applies_to_actions = vec![CapabilityActionId::MESSAGE_REVISE_OWN.into()];
    own_window.message_edit_window = Some("PT1M".into());
    assert!(accepts(&evaluate_constraint_ceiling(
        &op,
        &[own_window.clone()]
    )));
    let all_actions = AuthorizationOperation {
        actions: &[
            CapabilityActionId::MESSAGE_CREATE,
            CapabilityActionId::MESSAGE_REVISE_OWN,
        ],
        ..op
    };
    assert!(
        matches!(
            evaluate_constraint_ceiling(&all_actions, &[own_window]),
            GrantEvaluation::Unsatisfied
        ),
        "an unrelated neutral action cannot replace a required unknown own-window fact"
    );
    temporal.expires_at = Some(at() - TimeDelta::hours(1));
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[temporal]),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn global_refusals_keep_deny_quarantine_review_priority() {
    let actor = actor();
    let target = target(REALM);
    let facts = OperationFacts {
        track: Some("discussion".into()),
        ..Default::default()
    };
    let op = operation(&actor, &target, &facts);
    let mut deny = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Deny,
    );
    deny.denied_tracks = vec!["discussion".into()];
    let quarantine = GrantConstraint::new(
        GrantConstraintKind::Temporal,
        GrantConstraintEffect::Quarantine,
    );
    let review = GrantConstraint::new(
        GrantConstraintKind::Temporal,
        GrantConstraintEffect::RequireReview,
    );
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[review.clone(), quarantine.clone(), deny]),
        GrantEvaluation::Denied
    ));
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[review.clone(), quarantine]),
        GrantEvaluation::Quarantined
    ));
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[review]),
        GrantEvaluation::RequiresReview
    ));
}

#[test]
fn unknown_identity_or_track_facts_cannot_discharge_constraints() {
    let actor = actor();
    let target = target(REALM);
    let facts = OperationFacts::default();
    let op = operation(&actor, &target, &facts);
    let mut track = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    track.allowed_tracks = vec!["discussion".into()];
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[track]),
        GrantEvaluation::Unsatisfied
    ));
    let mut identity = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    identity.constraint_subkind = Some(GrantConstraintSubkind::AppletAuthority);
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[identity]),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn external_quota_never_gets_a_synthetic_grant_reservation() {
    let actor = actor();
    let target = target(REALM);
    let facts = OperationFacts::default();
    let op = operation(&actor, &target, &facts);
    let mut quota = GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
    quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
    quota.constraint_scope = Some(GrantConstraintScope::PerActor);
    quota.max_operations = Some(3);
    quota.period = Some("PT1H".into());
    assert!(matches!(
        evaluate_constraint_ceiling(&op, &[quota]),
        GrantEvaluation::Unsatisfied
    ));
    let missing = AuthorizationOperation { actions: &[], ..op };
    assert!(matches!(
        evaluate_constraint_ceiling(&missing, &[]),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn agent_event_projection_ceiling_uses_exact_accepted_collection_facts() {
    use crate::agent_content_ceiling::require_key_scope_content_ceiling;
    let actor = actor();
    let mut event = WireResourceSelector::realm(REALM.parse().unwrap());
    event.kind = ResourceSelectorKind::Event;
    event.event_id = Some(
        arkret_wire::EventId::new("ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv").unwrap(),
    );
    let mut facts = OperationFacts {
        strand_id: Some(STRAND.into()),
        track: Some("discussion".into()),
        ..Default::default()
    };
    let scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_value(serde_json::json!({
            "actions":["ak.event.read","ak.message.create"],
            "resources":[{"kind":"strand","realm_id":REALM,"resource_ref":STRAND}]
        }))
        .unwrap();
    fn read<'a>(
        actor: &'a ActorId,
        event: &'a WireResourceSelector,
        facts: &'a OperationFacts,
    ) -> AuthorizationOperation<'a> {
        AuthorizationOperation {
            actor,
            actions: &[CapabilityActionId::EVENT_READ],
            target: event,
            at: at(),
            facts,
        }
    }
    assert!(require_key_scope_content_ceiling(&scope, &read(&actor, &event, &facts)).is_ok());
    assert!(
        !resource_selector_covers(&target(REALM), &event),
        "generic grant selector matching must remain exact"
    );
    facts.strand_id = None;
    assert!(require_key_scope_content_ceiling(&scope, &read(&actor, &event, &facts)).is_err());
    facts.strand_id = Some("ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy".into());
    assert!(require_key_scope_content_ceiling(&scope, &read(&actor, &event, &facts)).is_err());
    facts.strand_id = Some(STRAND.into());
    let mut wrong = scope.clone();
    wrong.resources[0].realm_id = Some(OTHER_REALM.parse().unwrap());
    assert!(require_key_scope_content_ceiling(&wrong, &read(&actor, &event, &facts)).is_err());
    let write = AuthorizationOperation {
        actions: &[CapabilityActionId::MESSAGE_CREATE],
        ..read(&actor, &event, &facts)
    };
    assert!(require_key_scope_content_ceiling(&scope, &write).is_err());
    let mut bounded = scope.clone();
    bounded.constraints = serde_json::from_value(serde_json::json!([{"constraint_kind":"scope_limitation","effect":"allow","allowed_tracks":["discussion"]}])).unwrap();
    assert!(require_key_scope_content_ceiling(&bounded, &read(&actor, &event, &facts)).is_ok());
    facts.track = None;
    assert!(require_key_scope_content_ceiling(&bounded, &read(&actor, &event, &facts)).is_err());
    facts.track = Some("discussion".into());
    bounded.constraints = serde_json::from_value(serde_json::json!([{"constraint_kind":"scope_limitation","effect":"deny","denied_tracks":["discussion"]}])).unwrap();
    assert!(require_key_scope_content_ceiling(&bounded, &read(&actor, &event, &facts)).is_err());
    let circle = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M";
    let circle_scope = serde_json::from_value(serde_json::json!({"actions":["ak.event.read"],"resources":[{"kind":"circle","realm_id":REALM,"resource_ref":circle}]})).unwrap();
    facts.circle_id = Some(circle.into());
    assert!(
        require_key_scope_content_ceiling(&circle_scope, &read(&actor, &event, &facts)).is_ok()
    );
    facts.circle_id = None;
    assert!(
        require_key_scope_content_ceiling(&circle_scope, &read(&actor, &event, &facts)).is_err()
    );
}
