use arkret_wire::{ActorId, DidCoreId, EventId, RealmId, ScopeRef, test_support};
use chrono::TimeZone;
use serde_json::json;

use super::*;

const POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";
const OTHER_POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000002";

fn holder() -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkholder").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    )
}

fn recovery_policy_payload_value() -> serde_json::Value {
    json!({
        "policy_id": POLICY,
        "value": {
            "schema": "ak.schema.recovery_policy.v1",
            "policy_id": POLICY,
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkholder",
                "station_id": "ak:did_core:web:station.example"
            },
            "version": 1,
            "supersedes_id": null,
            "trust_domain": "ak:trust_domain:station.example",
            "issued_at": "2026-09-16T00:00:00.000Z",
            "signature_proof": {
                "verification_method": "did:web:station.example#key-1",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl"
            },
            "methods": []
        }
    })
}

fn submission_value(kind: &str, payload: serde_json::Value) -> serde_json::Value {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x31; 32],
    ));
    let event = test_support::raw_event_for_actor_at(
        kind,
        ScopeRef::Realm { realm_id },
        ActorId::account(holder()),
        payload,
        Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
    )
    .unwrap();
    json!({ "event": serde_json::to_value(&event).unwrap() })
}

#[test]
fn a_recovery_policy_set_submission_round_trips() {
    let value = submission_value("ak.policy.set", recovery_policy_payload_value());
    let request: RecoveryPolicyPublishRequestBody = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(request.event().kind, EventKind::PolicySet);
    assert_eq!(request.account_id().unwrap(), holder());
    assert_eq!(request.payload().unwrap().value.policy_id.as_str(), POLICY);
    assert_eq!(serde_json::to_value(&request).unwrap(), value);
}

#[test]
fn only_ak_policy_set_may_publish_a_recovery_policy() {
    let value = submission_value("ak.realm.policy_bundle", recovery_policy_payload_value());
    assert!(serde_json::from_value::<RecoveryPolicyPublishRequestBody>(value).is_err());
}

#[test]
fn a_governance_policy_document_is_not_a_recovery_publication() {
    let governance = json!({
        "policy_id": POLICY,
        "value": {
            "schema": "ak.schema.policy.v1",
            "id": POLICY,
            "policy_kind": "access",
            "rules": [],
            "default_effect": "deny",
            "created_by": { "kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkholder",
                "station_id": "ak:did_core:web:station.example"
            }},
            "created_at": "2026-09-16T00:00:00.000Z"
        }
    });
    let value = submission_value("ak.policy.set", governance);
    assert!(serde_json::from_value::<RecoveryPolicyPublishRequestBody>(value).is_err());
}

#[test]
fn the_payload_subject_must_equal_the_document_policy_id() {
    let mut mismatched = recovery_policy_payload_value();
    mismatched
        .as_object_mut()
        .unwrap()
        .insert("policy_id".to_owned(), json!(OTHER_POLICY));
    let value = submission_value("ak.policy.set", mismatched);
    assert!(serde_json::from_value::<RecoveryPolicyPublishRequestBody>(value).is_err());
}

#[test]
fn a_publication_carries_exactly_one_event_and_no_sidecar() {
    let mut value = submission_value("ak.policy.set", recovery_policy_payload_value());
    value
        .as_object_mut()
        .unwrap()
        .insert("commit".to_owned(), json!({}));
    assert!(serde_json::from_value::<RecoveryPolicyPublishRequestBody>(value).is_err());
}

#[test]
fn an_empty_method_set_publishes_an_explicit_revocation() {
    let value = submission_value("ak.policy.set", recovery_policy_payload_value());
    let request: RecoveryPolicyPublishRequestBody = serde_json::from_value(value).unwrap();
    assert!(request.payload().unwrap().value.revokes_recovery());
}
