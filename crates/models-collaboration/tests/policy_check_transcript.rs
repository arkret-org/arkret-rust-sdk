use arkret_identifiers::{DidCoreId, Hash, RealmId};
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody, PolicyCheckSignature,
    PolicyCheckSource, policy_decision_transcript_bytes,
};
use arkret_wire::{AuthzDecision, FreshnessState, ReasonCode};
use chrono::{TimeZone as _, Utc};

fn empty_sha256() -> Hash {
    Hash::new("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned())
        .unwrap()
}

fn request() -> PolicyCheckRequestBody {
    PolicyCheckRequestBody {
        request_id: "req-1".to_owned(),
        realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap(),
        request_canonical_digest: empty_sha256(),
        action: "ak.message.create".to_owned(),
        actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        device_id: None,
        source: PolicyCheckSource {
            service_id: DidCoreId::new("ak:did_core:web:soland.example").unwrap(),
            service_kind: "principal_server".to_owned(),
            source_ip_digest: None,
            signed_transport: true,
        },
        event_preview: None,
        auth_context: None,
    }
}

fn outcome() -> PolicyCheckOutcome {
    let digest = empty_sha256();
    PolicyCheckOutcome {
        request_id: "req-1".to_owned(),
        bound_to: PolicyCheckBoundTo {
            realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                .unwrap(),
            actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            action: "ak.message.create".to_owned(),
            request_canonical_digest: digest.clone(),
            policy_server_id: DidCoreId::new("ak:did_core:web:coauth.example").unwrap(),
        },
        decision: AuthzDecision::Allow,
        reason_code: ReasonCode::Ok,
        freshness_state: FreshnessState::Fresh,
        expires_at: Utc.with_ymd_and_hms(2026, 5, 21, 0, 1, 0).unwrap(),
        auth_state_digest: digest.clone(),
        policy_frontier_digest: digest.clone(),
        membership_frontier_digest: digest,
        next_retry_at: None,
        obligations: Vec::new(),
        signature: PolicyCheckSignature {
            kid: String::new(),
            sig: String::new(),
        },
    }
}

#[test]
fn policy_check_transcript_matches_domain_registry_kat() {
    let canonical = policy_decision_transcript_bytes(&outcome()).unwrap();
    let expected = concat!(
        "{\"auth_state_digest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
        "\"bound_to\":{\"action\":\"ak.message.create\",\"actor_id\":\"ak:did_core:web:alice.example\",",
        "\"policy_server_id\":\"ak:did_core:web:coauth.example\",",
        "\"realm_id\":\"ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO\",",
        "\"request_canonical_digest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"},",
        "\"decision\":\"allow\",\"domain\":\"ak.policy.check.transcript.v1\",",
        "\"expires_at\":\"2026-05-21T00:01:00.000Z\",\"freshness_state\":\"fresh\",",
        "\"membership_frontier_digest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
        "\"policy_frontier_digest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
        "\"reason_code\":\"ok\",\"request_id\":\"req-1\"}"
    );

    assert_eq!(std::str::from_utf8(&canonical).unwrap(), expected);
    let transcript: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(transcript["domain"], "ak.policy.check.transcript.v1");
    assert!(transcript.get("kind").is_none());
}

#[test]
fn policy_check_request_rejects_unknown_top_level_and_source_fields() {
    let mut top_level = serde_json::to_value(request()).unwrap();
    top_level["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyCheckRequestBody>(top_level).is_err());

    let mut nested = serde_json::to_value(request()).unwrap();
    nested["source"]["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyCheckRequestBody>(nested).is_err());
}

#[test]
fn policy_check_outcome_rejects_unknown_top_level_and_nested_fields() {
    let mut top_level = serde_json::to_value(outcome()).unwrap();
    top_level["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyCheckOutcome>(top_level).is_err());

    let mut bound_to = serde_json::to_value(outcome()).unwrap();
    bound_to["bound_to"]["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyCheckOutcome>(bound_to).is_err());

    let mut signature = serde_json::to_value(outcome()).unwrap();
    signature["signature"]["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyCheckOutcome>(signature).is_err());
}
