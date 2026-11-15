use arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValueHistory;
use arkret_models_collaboration::governance::grant_constraint::{
    GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
};
use arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement;
use arkret_models_collaboration::governance::realm_lifecycle::MemberCountHysteresis;
use arkret_models_collaboration::objects::queries::{FieldFilter, Filter};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountFilter;
use arkret_wire::{AccountId, ActorId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn rejects_previous_name<T: DeserializeOwned + Serialize>(
    value: Value,
    current: &str,
    previous: &str,
) {
    let parsed: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    let mut previous_only = value.clone();
    let member = previous_only
        .as_object_mut()
        .unwrap()
        .remove(current)
        .unwrap();
    previous_only[previous] = member.clone();
    assert!(serde_json::from_value::<T>(previous_only).is_err());
    let mut mixed = value;
    mixed[previous] = member;
    assert!(serde_json::from_value::<T>(mixed).is_err());
}

#[test]
fn count_and_permission_names_are_not_compatibility_aliases() {
    rejects_previous_name::<AccountFilter>(
        json!({"max_window_event_count": 25}),
        "max_window_event_count",
        "window_limit",
    );
    rejects_previous_name::<PreviewPolicyPayloadValueHistory>(
        json!({"range":"event_stubs","content":"redacted","member_events_allowed":false}),
        "member_events_allowed",
        "include_member_events",
    );
    rejects_previous_name::<MemberCountHysteresis>(
        json!({"absolute_count":2}),
        "absolute_count",
        "absolute",
    );
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:alice.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    rejects_previous_name::<ManagementReviewRequirement>(
        json!({"approver_actor_ids":[actor],"min_approver_count":1,"max_age_seconds":300}),
        "min_approver_count",
        "threshold",
    );
}

#[test]
fn query_operator_rejects_previous_short_name() {
    rejects_previous_name::<FieldFilter>(
        json!({"field":"title","operator":"eq","value":"Ready"}),
        "operator",
        "op",
    );
}

#[test]
fn recursive_boolean_filters_are_closed_and_preserve_null_predicates() {
    let predicate = json!({"field":"metadata.status","operator":"eq","value":null});
    for value in [
        predicate.clone(),
        json!({"and":[predicate]}),
        json!({"or":[{"not":predicate}]}),
        json!({"not":{"and":[predicate,{"field":"kind","operator":"exists"}]}}),
    ] {
        let filter: Filter = serde_json::from_value(value.clone()).unwrap();
        filter.validate().unwrap();
        assert_eq!(serde_json::to_value(filter).unwrap(), value);
    }

    let previous = json!({"field":"kind","op":"eq","value":"task"});
    let dual = json!({"field":"kind","operator":"eq","op":"eq","value":"task"});
    for value in [
        previous.clone(),
        dual.clone(),
        json!({"and":[predicate],"op":"eq"}),
        json!({"and":[predicate],"operator":"eq"}),
        json!({"and":[predicate],"or":[predicate]}),
        json!({"and":[previous]}),
        json!({"or":[{"not":dual}]}),
        json!({"and":[]}),
        json!({"or":[]}),
        json!({"not":{"and":[]}}),
        json!({"and":[predicate],"or":null}),
        json!({"field":"metadata..status","operator":"exists"}),
    ] {
        assert!(
            serde_json::from_value::<Filter>(value.clone()).is_err(),
            "accepted {value}"
        );
    }
    assert!(Filter::And { and: vec![] }.validate().is_err());
    assert!(Filter::Or { or: vec![] }.validate().is_err());
}

#[test]
fn quota_capacity_uses_operation_units() {
    let constraint = GrantConstraint {
        burst_operation_count: Some(3),
        ..GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow)
    };
    rejects_previous_name::<GrantConstraint>(
        serde_json::to_value(constraint).unwrap(),
        "burst_operation_count",
        "burst",
    );
}
