use super::*;
use crate::{Event, EventId, EventRequirements, Hlc, SpaceState};
use serde_json::json;
use std::collections::BTreeMap;

fn grant_for(action: &str, resource: ResourceSelector) -> CapabilityGrant {
    CapabilityGrant {
        id: "grant-1".to_owned(),
        space_id: None,
        issuer: Did::new("did:web:authority.example.com").unwrap(),
        subject: Did::new("did:web:alice.example.com").unwrap(),
        actions: vec![action.to_owned()],
        resources: vec![resource],
        constraints: vec![],
        delegable: false,
        parent_grant_id: None,
        valid_from: None,
        valid_until: None,
        revoked_by: None,
        revoked_at: None,
        #[cfg(feature = "full-surface")]
        attached_authority: None,
    }
}

fn utc(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value).unwrap().with_timezone(&Utc)
}

fn ctx_at(value: &str, action: &str, resource: Resource) -> AuthzContext {
    let mut ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        action.to_owned(),
        resource,
    );
    ctx.now = utc(value);
    ctx
}

fn morph_resource(space_id: &str, morph_type: &str, morph_id: &str) -> Resource {
    Resource::Morph {
        space_id: space_id.to_owned(),
        morph_type: morph_type.to_owned(),
        morph_id: morph_id.to_owned(),
    }
}

fn message_resource(space_id: &str, message_id: &str) -> Resource {
    Resource::Message { space_id: space_id.to_owned(), message_id: message_id.to_owned() }
}

fn message_selector(space_id: &str) -> ResourceSelector {
    ResourceSelector::Message { space_id: space_id.to_owned(), message_id: None }
}

fn capability_event(
    event_id: &str,
    kind: &str,
    actor_seq: u64,
    hlc: &str,
    content: Value,
) -> Event {
    Event {
        event_id: EventId::new(event_id).unwrap(),
        kind: kind.to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        actor_id: Did::new("did:web:authority.example.com").unwrap(),
        actor_seq,
        created_at: utc("2026-04-29T00:00:00Z"),
        hlc: Hlc::new(hlc).unwrap(),
        prev_refs: vec![],
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        anchor_ref: None,
        requirements: EventRequirements::default(),
        redacts: None,
        content,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

#[test]
fn resource_selector_parse_space() {
    let selector =
        ResourceSelector::parse("space:cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    assert_eq!(
        selector,
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()
        }
    );
}

#[test]
fn resource_selector_parse_object() {
    let selector =
        ResourceSelector::parse("object:cx:space:01904100-0000-7000-8000-b721a5c84b0d:task")
            .unwrap();
    assert_eq!(
        selector,
        ResourceSelector::Object {
            space_id: "cx:space:01904100-0000-7000-8000-b721a5c84b0d".to_owned(),
            object_type: Some("task".to_owned()),
            object_ref: None,
        }
    );
}

#[test]
fn flow_selector_matches_flow_resource() {
    let selector = ResourceSelector::parse(
        "flow:cx:space:01904100-0000-7000-8000-9b64700c6ee8:cx:flow:01904100-0000-7000-8000-5a9f22e193a1",
    )
    .unwrap();
    assert_eq!(
        selector,
        ResourceSelector::Flow {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            flow_id: Some("cx:flow:01904100-0000-7000-8000-5a9f22e193a1".to_owned()),
        }
    );
    assert!(selector.matches(&Resource::Flow {
        space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
        flow_id: "cx:flow:01904100-0000-7000-8000-5a9f22e193a1".to_owned(),
    }));
    assert!(!selector.matches(&Resource::Flow {
        space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
        flow_id: "cx:flow:01904100-0000-7000-8000-9c74a047a052".to_owned(),
    }));
}

#[test]
fn resource_selector_parse_space_scoped_resources_with_colon_ids() {
    assert_eq!(
        ResourceSelector::parse("policy:cx:space:01904100-0000-7000-8000-9b64700c6ee8:policy-main")
            .unwrap(),
        ResourceSelector::Policy {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            policy_id: Some("policy-main".to_owned()),
        }
    );
    assert_eq!(
        ResourceSelector::parse(
            "relation:cx:space:01904100-0000-7000-8000-9b64700c6ee8:assigned_to"
        )
        .unwrap(),
        ResourceSelector::Relation {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            relation_kind: "assigned_to".to_owned(),
        }
    );
}

#[test]
fn resource_selector_wildcard_matches_all() {
    let selector = ResourceSelector::Wildcard;
    assert!(selector.matches(&Resource::Space { space_id: "test".to_owned() }));
    assert!(selector.matches(&morph_resource("test", "task", "cx:morph:test")));
}

#[test]
fn space_selector_matches_space() {
    let selector = ResourceSelector::Space {
        space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
    };
    assert!(selector.matches(&Resource::Space {
        space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned()
    }));
    assert!(!selector.matches(&Resource::Space {
        space_id: "cx:space:01904100-0000-7000-8000-2a9d538f2fcf".to_owned()
    }));
}

#[test]
fn object_selector_matches_morph() {
    let selector = ResourceSelector::Object {
        space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        object_type: Some("task".to_owned()),
        object_ref: None,
    };
    assert!(selector.matches(&morph_resource(
        "cx:space:01904100-0000-7000-8000-1a412919cd4b",
        "task",
        "cx:morph:01904100-0000-7000-8000-20ec63a5423d",
    )));
    assert!(!selector.matches(&morph_resource(
        "cx:space:01904100-0000-7000-8000-1a412919cd4b",
        "note",
        "cx:morph:01904100-0000-7000-8000-20ec63a5423d",
    )));
}

#[test]
fn type_restriction_respects_flow_scope_limitation() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "read".to_owned(),
        Resource::Flow {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            flow_id: "cx:flow:01904100-0000-7000-8000-f571eead1fc4".to_owned(),
        },
    );
    let mut grant = grant_for(
        "read",
        ResourceSelector::Flow {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            flow_id: None,
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::TypeRestriction {
        object_type_allow: None,
        object_type_deny: None,
        morph_type_allow: None,
        morph_type_deny: None,
        facet_allow: vec![],
        facet_deny: vec![],
        scope_limitation: Some(ScopeLimitation::Flow),
    })];

    assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn type_restriction_requires_entity_facets_from_context() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "write".to_owned(),
        morph_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "task",
            "cx:morph:01904100-0000-7000-8000-20ec63a5423d",
        ),
    )
    .with_facets([Facet::Stateful, Facet::Rankable]);
    let mut grant = grant_for(
        "write",
        ResourceSelector::Object {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            object_type: Some("task".to_owned()),
            object_ref: None,
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::TypeRestriction {
        object_type_allow: Some(vec!["morph".to_owned()]),
        object_type_deny: None,
        morph_type_allow: Some(vec!["task".to_owned()]),
        morph_type_deny: None,
        facet_allow: vec![Facet::Stateful, Facet::Rankable],
        facet_deny: vec![],
        scope_limitation: None,
    })];

    assert!(engine.check_authorization(&ctx, &[grant.clone()]).is_allowed());

    let missing_facet_ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "write".to_owned(),
        morph_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "task",
            "cx:morph:01904100-0000-7000-8000-20ec63a5423d",
        ),
    )
    .with_facets([Facet::Stateful]);
    assert!(!engine.check_authorization(&missing_facet_ctx, &[grant]).is_allowed());
}

#[test]
fn authz_engine_deny_without_grant() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "read".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let decision = engine.check_authorization(&ctx, &[]);
    assert!(!decision.is_allowed());
}

#[test]
fn authz_engine_allow_with_matching_grant() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "read".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );

    let decision = engine.check_authorization(&ctx, &[grant]);
    assert!(decision.is_allowed());
}

#[test]
fn authz_engine_deny_wrong_action() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "write".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );

    let decision = engine.check_authorization(&ctx, &[grant]);
    assert!(!decision.is_allowed());
}

#[test]
fn authz_engine_evaluates_grants_from_space_state() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let grant = capability_event(
        "cx:event:01904100-0000-7000-8000-db6fcaf186ba",
        "cx.capability.grant",
        1,
        "01970e589d21-00000004-a13f9c2e",
        json!({
            "capability_id": "cap-message-send",
            "subject": "did:web:alice.example.com",
            "actions": ["cx.message.create"],
            "resources": ["message:cx:space:01904100-0000-7000-8000-9b64700c6ee8"]
        }),
    );
    state.apply_events(&[grant]).unwrap();

    let ctx = ctx_at(
        "2026-04-29T01:00:00Z",
        "cx.message.create",
        message_resource(
            "cx:space:01904100-0000-7000-8000-9b64700c6ee8",
            "cx:message:01904100-0000-7000-8000-424c57fe6d8e",
        ),
    );

    let mut engine = AuthzEngine::new();
    assert!(engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
}

#[test]
fn authz_engine_denies_after_revoke_wins_in_space_state() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let grant = capability_event(
        "cx:event:01904100-0000-7000-8000-4fe0190ae99f",
        "cx.capability.grant",
        1,
        "01970e589d21-00000004-a13f9c2e",
        json!({
            "capability_id": "cap-message-send",
            "subject": "did:web:alice.example.com",
            "actions": ["cx.message.create"],
            "resources": ["message:cx:space:01904100-0000-7000-8000-9b64700c6ee8"]
        }),
    );
    let revoke = capability_event(
        "cx:event:01904100-0000-7000-8000-a85aaf6d56fc",
        "cx.capability.revoke",
        2,
        "01970e589d22-00000004-a13f9c2e",
        json!({ "target_capability_id": "cap-message-send" }),
    );
    state.apply_events(&[grant, revoke]).unwrap();

    let ctx = ctx_at(
        "2026-04-29T01:00:00Z",
        "cx.message.create",
        message_resource(
            "cx:space:01904100-0000-7000-8000-9b64700c6ee8",
            "cx:message:01904100-0000-7000-8000-424c57fe6d8e",
        ),
    );

    let mut engine = AuthzEngine::new();
    assert!(!engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
}

#[test]
fn authz_engine_denies_after_delegate_revoke_wins_in_space_state() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let delegate = capability_event(
        "cx:event:01904100-0000-7000-8000-cadd1669a70a",
        "cx.capability.delegate",
        1,
        "01970e589d21-00000004-a13f9c2e",
        json!({
            "capability_id": "cap-message-delegate",
            "parent_grant_id": "cap-root",
            "subject": "did:web:alice.example.com",
            "actions": ["cx.message.create"],
            "resources": ["message:cx:space:01904100-0000-7000-8000-9b64700c6ee8"]
        }),
    );
    state.apply_events(std::slice::from_ref(&delegate)).unwrap();

    let ctx = ctx_at(
        "2026-04-29T01:00:00Z",
        "cx.message.create",
        message_resource(
            "cx:space:01904100-0000-7000-8000-9b64700c6ee8",
            "cx:message:01904100-0000-7000-8000-424c57fe6d8e",
        ),
    );

    let mut engine = AuthzEngine::new();
    assert!(engine.check_authorization_from_space_state(&ctx, &state).is_allowed());

    let revoke = capability_event(
        "cx:event:01904100-0000-7000-8000-738d5fbe3070",
        "cx.capability.revoke",
        2,
        "01970e589d22-00000004-a13f9c2e",
        json!({ "target_capability_id": "cap-message-delegate" }),
    );
    state.apply_events(&[revoke]).unwrap();

    assert!(!engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
}

#[test]
fn authz_engine_denies_wrong_subject() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:bob.example.com").unwrap(),
        "read".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );

    let decision = engine.check_authorization(&ctx, &[grant]);
    assert!(!decision.is_allowed());
}

#[test]
fn policy_server_no_action_never_grants_without_capability() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "read".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let allow_policy = PolicyCheckResBody::no_action();
    assert!(!engine.check_authorization_with_policy(&ctx, &[], &allow_policy).is_allowed());

    let grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    assert!(engine.check_authorization_with_policy(&ctx, &[grant], &allow_policy).is_allowed());
}

#[test]
fn policy_server_denies_quarantines_and_reports_moderation_outcomes() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "post".to_owned(),
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-c89a39a907e5",
        ),
    );
    let grant =
        grant_for("post", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    let policy = PolicyCheckResBody {
        operation: "cx.policy.check".to_owned(),
        effect: PolicyServerEffect::Quarantine,
        reason: "possible abuse".to_owned(),
        policy_id: Some("policy-abuse".to_owned()),
        moderation_report_id: Some("report-1".to_owned()),
    };

    let decision = engine.check_authorization_with_policy(&ctx, &[grant], &policy);
    assert!(matches!(decision, AuthzDecision::Quarantine { .. }));
    let report =
        moderation_report_for_policy_outcome(&ctx, &policy, utc("2026-04-29T00:00:00Z")).unwrap();
    assert_eq!(report.report_id, "report-1");
    assert_eq!(report.effect, PolicyServerEffect::Quarantine);
}

#[test]
fn capability_frontier_rejects_cycles_widening_and_unknown_critical_constraints() {
    let authority = Did::new("did:web:authority.example.com").unwrap();
    let alice = Did::new("did:web:alice.example.com").unwrap();
    let bob = Did::new("did:web:bob.example.com").unwrap();
    let mut root = grant_for(
        "cx.message.create",
        ResourceSelector::Message {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            message_id: None,
        },
    );
    root.id = "root".to_owned();
    root.issuer = authority;
    root.subject = alice.clone();
    root.delegable = true;
    let child = CapabilityGrant {
        id: "child".to_owned(),
        space_id: None,
        issuer: alice,
        subject: bob,
        actions: vec!["cx.message.create".to_owned()],
        resources: vec![ResourceSelector::Message {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            message_id: Some("message-1".to_owned()),
        }],
        constraints: Vec::new(),
        delegable: false,
        parent_grant_id: Some("root".to_owned()),
        valid_from: None,
        valid_until: None,
        revoked_by: None,
        revoked_at: None,
        #[cfg(feature = "full-surface")]
        attached_authority: None,
    };
    let validation = validate_capability_frontier(&[root.clone(), child.clone()]).unwrap();
    assert_eq!(validation.max_delegation_depth, 1);

    let mut widened = child;
    widened.actions = vec!["message.delete".to_owned()];
    assert!(validate_capability_frontier(&[root, widened]).is_err());

    let wire = json!({
        "constraints": [
            {"type": "future_constraint", "critical": true}
        ]
    });
    assert!(reject_unknown_critical_constraints(&wire, &["temporal"]).is_err());
}

#[test]
fn authz_engine_temporal_constraint_expires() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "read".to_owned(),
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        recurrence: None,
    })];

    let decision = engine.check_authorization(&ctx, &[grant]);
    assert!(!decision.is_allowed());
}

#[test]
fn authz_engine_temporal_recurrence_allows_weekday_window_in_timezone() {
    let mut engine = AuthzEngine::new();
    let ctx = ctx_at(
        "2026-04-29T02:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: None,
        recurrence: Some(Recurrence {
            frequency: Some("weekly".to_owned()),
            days: Some(vec!["wed".to_owned()]),
            window_start: Some("09:00".to_owned()),
            window_end: Some("17:00".to_owned()),
            timezone: Some("Asia/Shanghai".to_owned()),
        }),
    })];

    assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn authz_engine_temporal_recurrence_denies_outside_window() {
    let mut engine = AuthzEngine::new();
    let ctx = ctx_at(
        "2026-04-29T11:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: None,
        recurrence: Some(Recurrence {
            frequency: Some("daily".to_owned()),
            days: None,
            window_start: Some("09:00".to_owned()),
            window_end: Some("17:00".to_owned()),
            timezone: Some("Asia/Shanghai".to_owned()),
        }),
    })];

    assert!(!engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn authz_engine_temporal_recurrence_allows_cross_midnight_window() {
    let mut engine = AuthzEngine::new();
    let ctx = ctx_at(
        "2026-04-29T15:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: None,
        recurrence: Some(Recurrence {
            frequency: Some("daily".to_owned()),
            days: None,
            window_start: Some("22:00".to_owned()),
            window_end: Some("06:00".to_owned()),
            timezone: Some("+08:00".to_owned()),
        }),
    })];

    assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn authz_engine_temporal_recurrence_handles_dst_boundary() {
    let mut engine = AuthzEngine::new();
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: None,
        recurrence: Some(Recurrence {
            frequency: Some("weekly".to_owned()),
            days: Some(vec!["sun".to_owned()]),
            window_start: Some("01:00".to_owned()),
            window_end: Some("04:00".to_owned()),
            timezone: Some("America/New_York".to_owned()),
        }),
    })];

    let before_jump = ctx_at(
        "2026-03-08T06:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let after_jump = ctx_at(
        "2026-03-08T07:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    assert!(engine.check_authorization(&before_jump, &[grant.clone()]).is_allowed());
    assert!(engine.check_authorization(&after_jump, &[grant]).is_allowed());
}

#[test]
fn authz_cache_expires_at_temporal_boundaries() {
    let mut engine = AuthzEngine::new();
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
        not_before: None,
        expires_at: Some(utc("2026-04-29T03:00:00Z")),
        recurrence: None,
    })];

    let before_expiry = ctx_at(
        "2026-04-29T02:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let after_expiry = ctx_at(
        "2026-04-29T03:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    assert!(engine.check_authorization(&before_expiry, &[grant.clone()]).is_allowed());
    assert!(!engine.check_authorization(&after_expiry, &[grant]).is_allowed());
}

#[test]
fn authz_cache_rechecks_future_not_before_grants() {
    let mut engine = AuthzEngine::new();
    let mut grant = grant_for(
        "read",
        ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        },
    );
    grant.valid_from = Some(utc("2026-04-29T03:00:00Z"));

    let before_valid = ctx_at(
        "2026-04-29T02:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );
    let after_valid = ctx_at(
        "2026-04-29T03:30:00Z",
        "read",
        Resource::Space { space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned() },
    );

    assert!(!engine.check_authorization(&before_valid, &[grant.clone()]).is_allowed());
    assert!(engine.check_authorization(&after_valid, &[grant]).is_allowed());
}

#[test]
fn authz_engine_field_access_deny() {
    let mut engine = AuthzEngine::new();
    let mut ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "update".to_owned(),
        morph_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "task",
            "cx:morph:01904100-0000-7000-8000-20ec63a5423d",
        ),
    );
    ctx.write_fields = vec!["id".to_owned(), "title".to_owned()];

    let mut grant = grant_for(
        "update",
        ResourceSelector::Object {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            object_type: Some("task".to_owned()),
            object_ref: None,
        },
    );
    grant.constraints = vec![ConstraintEntry::new(Constraint::FieldAccess {
        effect: ConstraintEffect::Deny,
        scope: FieldScope::Write,
        fields: vec!["id".to_owned(), "created_by".to_owned()],
    })];

    let decision = engine.check_authorization(&ctx, &[grant]);
    assert!(!decision.is_allowed());
}

#[test]
fn authz_engine_enforces_runtime_constraints() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "send".to_owned(),
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-20ec63a5423d",
        ),
    )
    .with_delegation_depth(2)
    .with_rate_limit_count(3)
    .with_accountability_logged(true)
    .with_encryption_level("mls_rfc9420")
    .with_verified_claim(VerifiedClaim {
        claim_id: None,
        subject: Did::new("did:web:alice.example.com").unwrap(),
        claim_type: "employee".to_owned(),
        issuer: Did::new("did:web:issuer.example.com").unwrap(),
        organization: Some(Did::new("did:web:org.example.com").unwrap()),
        status: Some("active".to_owned()),
        roles: vec!["writer".to_owned()],
        issued_at: None,
        expires_at: None,
        revoked_at: None,
        refreshed_at: None,
    });
    let mut grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    grant.constraints = vec![
        ConstraintEntry::new(Constraint::DelegationControl {
            max_delegation_depth: Some(2),
            prohibit_subdelegation: false,
        }),
        ConstraintEntry::new(Constraint::RateLimiting {
            max_operations: 4,
            period: ConstraintDuration { value: 1, unit: "m".to_owned() },
            scope: RateLimitScope::PerSpace,
        }),
        ConstraintEntry::new(Constraint::ClaimBased {
            requires_claims: vec![ClaimRequirement {
                claim_type: "employee".to_owned(),
                issuer: None,
                organization: Some(Did::new("did:web:org.example.com").unwrap()),
                status: Some("active".to_owned()),
                roles: Some(vec!["writer".to_owned()]),
            }],
            trusted_issuers: vec![Did::new("did:web:issuer.example.com").unwrap()],
            claim_refresh_required: false,
            claim_max_age: None,
        }),
        ConstraintEntry::new(Constraint::Accountability {
            accountability_required: true,
            responsible_actor: Some(Did::new("did:web:alice.example.com").unwrap()),
        }),
        ConstraintEntry::new(Constraint::EncryptionRequirement {
            encryption_required: true,
            min_encryption_level: Some("mls_rfc9420".to_owned()),
        }),
    ];

    assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn authz_claim_constraints_fail_closed_on_subject_time_and_revocation() {
    let mut engine = AuthzEngine::new();
    let base_claim = VerifiedClaim {
        claim_id: Some("claim-1".to_owned()),
        subject: Did::new("did:web:alice.example.com").unwrap(),
        claim_type: "employee".to_owned(),
        issuer: Did::new("did:web:issuer.example.com").unwrap(),
        organization: None,
        status: Some("active".to_owned()),
        roles: vec![],
        issued_at: Some(utc("2026-04-28T00:00:00Z")),
        expires_at: Some(utc("2026-04-30T00:00:00Z")),
        revoked_at: None,
        refreshed_at: None,
    };
    let ctx = ctx_at(
        "2026-04-29T00:00:00Z",
        "send",
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-20ec63a5423d",
        ),
    )
    .with_verified_claim(base_claim.clone());
    let mut grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    grant.constraints = vec![ConstraintEntry::new(Constraint::ClaimBased {
        requires_claims: vec![ClaimRequirement {
            claim_type: "employee".to_owned(),
            issuer: None,
            organization: None,
            status: Some("active".to_owned()),
            roles: None,
        }],
        trusted_issuers: vec![Did::new("did:web:issuer.example.com").unwrap()],
        claim_refresh_required: false,
        claim_max_age: Some(ConstraintDuration { value: 2, unit: "d".to_owned() }),
    })];

    assert!(engine.check_authorization(&ctx, &[grant.clone()]).is_allowed());
    let revoked_ctx = ctx.clone().with_revoked_claim_id("claim-1");
    assert!(!engine.check_authorization(&revoked_ctx, &[grant.clone()]).is_allowed());

    let mut wrong_subject = base_claim;
    wrong_subject.subject = Did::new("did:web:bob.example.com").unwrap();
    let wrong_subject_ctx = ctx_at(
        "2026-04-29T00:00:00Z",
        "send",
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-20ec63a5423d",
        ),
    )
    .with_verified_claim(wrong_subject);
    assert!(!engine.check_authorization(&wrong_subject_ctx, &[grant]).is_allowed());
}

#[test]
fn authz_engine_denies_missing_encryption() {
    let mut engine = AuthzEngine::new();
    let ctx = AuthzContext::new(
        Did::new("did:web:alice.example.com").unwrap(),
        "send".to_owned(),
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-20ec63a5423d",
        ),
    );
    let mut grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    grant.constraints = vec![ConstraintEntry::new(Constraint::EncryptionRequirement {
        encryption_required: true,
        min_encryption_level: Some("mls_rfc9420".to_owned()),
    })];

    assert!(!engine.check_authorization(&ctx, &[grant]).is_allowed());
}

#[test]
fn approval_flow_manager_submits_records_and_resolves_proposals() {
    let mut manager = ApprovalFlowManager::new();
    let proposer = Did::new("did:web:alice.example.com").unwrap();
    let approver1 = Did::new("did:web:bob.example.com").unwrap();
    let approver2 = Did::new("did:web:carol.example.com").unwrap();

    let mut grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    grant.constraints = vec![ConstraintEntry::new(Constraint::ApprovalWorkflow {
        approval_required: true,
        approval_actor_refs: Some(vec![approver1.clone(), approver2.clone()]),
        timeout: None,
        approval_mode: Some(ApprovalMode::All),
        approval_relation: None,
        guardian_approval_required: false,
        controller_approval_required: false,
    })];

    let proposal = manager.submit_proposal(
        grant.clone(),
        proposer,
        vec![approver1.clone(), approver2.clone()],
        ApprovalMode::All,
        None,
    );
    assert_eq!(proposal.status, ProposalStatus::Pending);

    // First approval is not enough for ApprovalMode::All.
    let updated = manager.record_approval(&proposal.proposal_id, approver1, true, None).unwrap();
    assert_eq!(updated.status, ProposalStatus::Pending);
    assert!(!manager.is_grant_approved(&grant.id));

    // Second approval completes the proposal.
    let updated = manager.record_approval(&proposal.proposal_id, approver2, true, None).unwrap();
    assert_eq!(updated.status, ProposalStatus::Approved);
    assert!(manager.is_grant_approved(&grant.id));
}

#[test]
fn approval_flow_rejects_unauthorized_approvers_and_duplicate_responses() {
    let mut manager = ApprovalFlowManager::new();
    let proposer = Did::new("did:web:alice.example.com").unwrap();
    let approver = Did::new("did:web:bob.example.com").unwrap();
    let outsider = Did::new("did:web:eve.example.com").unwrap();

    let grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));

    let proposal =
        manager.submit_proposal(grant, proposer, vec![approver.clone()], ApprovalMode::Any, None);

    // Outsider cannot approve.
    assert!(manager.record_approval(&proposal.proposal_id, outsider, true, None).is_err());

    // Approver can approve once.
    assert!(manager.record_approval(&proposal.proposal_id, approver.clone(), true, None).is_ok());

    // Duplicate response is rejected.
    assert!(manager.record_approval(&proposal.proposal_id, approver, true, None).is_err());
}

#[test]
fn authz_engine_filters_unapproved_grants_with_approval_flow() {
    let mut engine = AuthzEngine::new();
    let mut approvals = ApprovalFlowManager::new();
    let proposer = Did::new("did:web:alice.example.com").unwrap();
    let approver = Did::new("did:web:bob.example.com").unwrap();

    let ctx = ctx_at(
        "2026-04-29T12:00:00Z",
        "send",
        message_resource(
            "cx:space:01904100-0000-7000-8000-1a412919cd4b",
            "cx:message:01904100-0000-7000-8000-20ec63a5423d",
        ),
    );

    let mut grant =
        grant_for("send", message_selector("cx:space:01904100-0000-7000-8000-1a412919cd4b"));
    grant.constraints = vec![ConstraintEntry::new(Constraint::ApprovalWorkflow {
        approval_required: true,
        approval_actor_refs: Some(vec![approver.clone()]),
        timeout: None,
        approval_mode: Some(ApprovalMode::Any),
        approval_relation: None,
        guardian_approval_required: false,
        controller_approval_required: false,
    })];

    // Without approval, the grant is filtered out.
    let decision = engine.check_authorization_with_approvals(&ctx, &[grant.clone()], &approvals);
    assert!(!decision.is_allowed());

    // Submit and approve the proposal.
    let proposal = approvals.submit_proposal(
        grant.clone(),
        proposer,
        vec![approver.clone()],
        ApprovalMode::Any,
        None,
    );
    approvals.record_approval(&proposal.proposal_id, approver, true, None).unwrap();

    // With approval, the grant is included.
    let decision = engine.check_authorization_with_approvals(&ctx, &[grant], &approvals);
    assert!(decision.is_allowed());
}
