use arkret_models_crypto::{HistoryGrant, HistoryRequest};
use arkret_schema_conformance::spec_json_artifact;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

fn grant_wire() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json").unwrap()["hpke_grant"]["grant"]
        .clone()
}

fn request_wire(grant: &Value) -> Value {
    json!({
        "recipient": grant["recipient"],
        "recipient_hpke_key_base64url": grant["recipient_hpke_key_base64url"],
        "history_cut": grant["history_cut"],
        "expires_at": grant["expires_at"],
    })
}

#[test]
fn grant_matches_every_accepted_request_binding_and_rejects_legacy_top_level_authority() {
    let wire = grant_wire();
    let grant: HistoryGrant = serde_json::from_value(wire.clone()).unwrap();
    let request_json = request_wire(&wire);
    let request: HistoryRequest = serde_json::from_value(request_json.clone()).unwrap();
    grant
        .validate_for_request(&grant.recipient_key_event_ref, &request)
        .unwrap();
    let other = request.recipient.authorization_event_ref.clone();
    assert_ne!(other, grant.recipient_key_event_ref);
    assert!(grant.validate_for_request(&other, &request).is_err());

    for pointer in [
        "/recipient/authorization_event_ref",
        "/recipient/signature_key_base64url",
        "/recipient/endpoint/device_id",
        "/recipient/actor_id/account_id/principal_id",
        "/recipient_hpke_key_base64url",
        "/history_cut/stream_position",
        "/expires_at",
    ] {
        let mut changed = request_json.clone();
        *changed.pointer_mut(pointer).unwrap() = match pointer {
            "/recipient/authorization_event_ref" => json!(grant.recipient_key_event_ref),
            "/recipient/endpoint/device_id" => {
                json!("ak:device:019a0000-0000-7000-8000-000000000099")
            }
            "/recipient/actor_id/account_id/principal_id" => json!("ak:did_core:webvh:z6mkother"),
            "/history_cut/stream_position" => json!(1),
            "/expires_at" => json!("2026-11-08T00:14:59.000Z"),
            _ => json!(arkret_canonical::base64url_encode([7; 32])),
        };
        let changed: HistoryRequest = serde_json::from_value(changed).unwrap();
        changed.validate().unwrap();
        assert!(
            grant
                .validate_for_request(&grant.recipient_key_event_ref, &changed)
                .is_err(),
            "{pointer}"
        );
    }
    let mut legacy_request = request_json;
    legacy_request["authorization_event_ref"] = json!(other);
    assert!(serde_json::from_value::<HistoryRequest>(legacy_request).is_err());
    let mut legacy_grant = wire;
    legacy_grant["authorization_event_ref"] = json!(other);
    assert!(serde_json::from_value::<HistoryGrant>(legacy_grant).is_err());
}

#[test]
fn request_window_is_exact_and_does_not_treat_old_history_cut_as_authorization_time() {
    let mut request: HistoryRequest = serde_json::from_value(request_wire(&grant_wire())).unwrap();
    let created: DateTime<Utc> = "2026-11-08T00:00:00.000Z".parse().unwrap();
    request.validate_at(created, created).unwrap();
    request
        .validate_at(created, request.expires_at - Duration::milliseconds(1))
        .unwrap();
    assert!(request.validate_at(created, request.expires_at).is_err());
    assert!(
        request
            .validate_at(created, created - Duration::milliseconds(1))
            .is_err()
    );
    assert!(
        request
            .validate_at(created - Duration::milliseconds(1), created)
            .is_err()
    );
    request.expires_at = created;
    assert!(request.validate_at(created, created).is_err());
    request.expires_at = created - Duration::milliseconds(1);
    assert!(request.validate_at(created, created).is_err());
}
