//! Exact-peer replacement preserves the complete permission set.
use arkret_models_collaboration::call_invitation::{
    ConsentCurrentReadOutcome, ConsentCurrentReadRequestBody,
};
use arkret_models_collaboration::consent_operations::ConsentValue;
use arkret_models_collaboration::events_payloads::consent::{
    ConsentExpectedCurrent, ConsentReplacePayload,
};
use arkret_wire::ConsentScope;
use serde_json::json;

#[test]
fn empty_is_a_real_value_and_never_written_is_an_explicit_precondition() {
    let empty: ConsentValue = serde_json::from_value(json!({"permissions":[]})).unwrap();
    empty.validate().unwrap();
    assert_eq!(
        serde_json::to_value(empty).unwrap(),
        json!({"permissions":[]})
    );
    let pre: ConsentExpectedCurrent =
        serde_json::from_value(json!({"state":"never_written"})).unwrap();
    assert_eq!(
        serde_json::to_value(pre).unwrap(),
        json!({"state":"never_written"})
    );
    for invalid in [
        json!({"state":"present"}),
        json!({"state":"never_written","revision":null}),
        json!({"state":"missing"}),
    ] {
        assert!(serde_json::from_value::<ConsentExpectedCurrent>(invalid).is_err());
    }
}

#[test]
fn permissions_preserve_optional_presence_and_refuse_sorting_or_widening() {
    let value = json!({"permissions":[
        {"consent_scope":"invite","reason":"retained","constraints":[]},
        {"consent_scope":"voice_call","not_before":"2026-01-01T00:00:00.000Z","expires_at":"2026-02-01T00:00:00.000Z","evidence_ref":"receipt","constraints":[{"future_rule":{"limit":1}}]}
    ]});
    let typed: ConsentValue = serde_json::from_value(value.clone()).unwrap();
    typed.validate().unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), value);
    let now = "2026-10-21T00:00:00Z".parse().unwrap();
    let (request, current) = permission_read(&typed, now);
    current.validate_for_request(&request, 0, now).unwrap();
    assert!(current.permits(&request, ConsentScope::Invite, now));
    assert!(!current.permits(&request, ConsentScope::VoiceCall, now));
    let mut reversed = typed.clone();
    reversed.permissions.reverse();
    assert!(reversed.validate().is_err());
    let mut duplicate = typed.clone();
    duplicate.permissions.push(typed.permissions[1].clone());
    assert!(duplicate.validate().is_err());
    for invalid in [
        json!({"permissions":[{"consent_scope":"any"}]}),
        json!({"permissions":[{"consent_scope":"invite","reason":null}]}),
        json!({"permissions":[],"consent_id":"retired"}),
    ] {
        assert!(serde_json::from_value::<ConsentValue>(invalid).is_err());
    }
}

#[test]
fn native_event_requires_peer_precondition_and_full_set() {
    let value = json!({"peer":{"kind":"actor","actor_id":{"kind":"service","service_id":"ak:did_core:web:peer.example"}},"expected_current":{"state":"never_written"},"permissions":[]});
    let typed: ConsentReplacePayload = serde_json::from_value(value.clone()).unwrap();
    typed.validate().unwrap();
    assert_eq!(serde_json::to_value(typed).unwrap(), value);
    for field in ["peer", "expected_current", "permissions"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ConsentReplacePayload>(missing).is_err());
    }
}

// This fixture exercises the public local permission-set evaluator. It is
// deliberately not a signed/accepted authority witness; live trust is covered
// by http-client own_station_results::consent_current's real-JWS tests.
fn permission_read(
    value: &ConsentValue,
    now: chrono::DateTime<chrono::Utc>,
) -> (ConsentCurrentReadRequestBody, ConsentCurrentReadOutcome) {
    let request: ConsentCurrentReadRequestBody = serde_json::from_value(json!({
        "holder_account_id":{"principal_id":"ak:did_core:web:holder.example","station_id":"ak:did_core:web:station.example"},
        "peer":{"kind":"actor","actor_id":{"kind":"service","service_id":"ak:did_core:web:peer.example"}},
        "audience_actor_id":{"kind":"service","service_id":"ak:did_core:web:station.example"},
        "nonce":arkret_canonical::base64url_encode([27;24])
    })).unwrap();
    let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    let commit = arkret_wire::RealmCommitId::from_digest([28; 32]);
    let arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor { actor_id } =
        &request.peer;
    let outcome=serde_json::from_value(json!({
        "request_digest":request.digest().unwrap(),"realm_id":realm,"governance_generation":0,
        "effective_stream_head":{"stream_ref":{"kind":"realm","realm_id":realm},"stream_position":7,"commit_id":commit},
        "current":{"state":"present","result":{"selector":{"kind":"consent","peer_id":actor_id},
            "source_stream_ref":{"kind":"realm","realm_id":realm},"revision":{"commit_id":commit,"stream_position":7},"value":value}},
        "evaluated_at":now.to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
        "expires_at":(now+chrono::Duration::seconds(30)).to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
        "proof":{"verification_method":"did:web:station.example#authority","jws":"local-evaluator-fixture-unverified"}
    })).unwrap();
    (request, outcome)
}

#[test]
fn full_native_replacement_roundtrips_unrelated_expired_permissions_and_optional_members() {
    let previous:ConsentValue=serde_json::from_value(json!({"permissions":[
        {"consent_scope":"invite","constraints":[],"reason":""},
        {"consent_scope":"voice_call","expires_at":"2020-01-01T00:00:00.000Z","constraints":[{"unknown_rule":true}]}
    ]})).unwrap();
    let value = json!({"peer":{"kind":"actor","actor_id":{"kind":"service","service_id":"ak:did_core:web:peer.example"}},
        "expected_current":{"state":"present","revision":{"commit_id":arkret_wire::RealmCommitId::from_digest([29;32]),"stream_position":6}},
        "permissions":[previous.permissions[0],previous.permissions[1],{"consent_scope":"presence"}]});
    let target: ConsentReplacePayload = serde_json::from_value(value.clone()).unwrap();
    target.validate().unwrap();
    assert_eq!(serde_json::to_value(&target).unwrap(), value);
    assert_eq!(target.permissions[..2], previous.permissions);
    // Native replacement may change the full set. Correlation-purpose limits
    // belong to the real MIMI admission helper, whose PG/HTTP tests reject a
    // voice revoke that also changes presence. DTO shape cannot enforce them.
    let mut native_edit = target.clone();
    native_edit.permissions[0].reason = None;
    native_edit.permissions.remove(1);
    native_edit.validate().unwrap();
    let encoded = serde_json::to_value(&native_edit).unwrap();
    assert_eq!(
        serde_json::from_value::<ConsentReplacePayload>(encoded.clone()).unwrap(),
        native_edit
    );
    assert!(encoded["permissions"][0].get("reason").is_none());
    assert_eq!(encoded["permissions"][0]["constraints"], json!([]));
}

#[test]
fn future_expired_empty_and_reversed_windows_are_preserved_and_never_authorize() {
    let now = "2026-10-21T00:00:00Z".parse().unwrap();
    for (start, end) in [
        ("2026-10-22T00:00:00.000Z", "2026-10-23T00:00:00.000Z"),
        ("2026-10-01T00:00:00.000Z", "2026-10-20T00:00:00.000Z"),
        ("2026-10-21T00:00:00.000Z", "2026-10-21T00:00:00.000Z"),
        ("2026-10-22T00:00:00.000Z", "2026-10-20T00:00:00.000Z"),
    ] {
        let wire = json!({"permissions":[{"consent_scope":"voice_call","not_before":start,"expires_at":end}]});
        let value: ConsentValue = serde_json::from_value(wire.clone()).unwrap();
        value.validate().unwrap();
        assert_eq!(serde_json::to_value(&value).unwrap(), wire);
        let (request, current) = permission_read(&value, now);
        current.validate_for_request(&request, 0, now).unwrap();
        assert!(!current.permits(&request, ConsentScope::VoiceCall, now));
    }
    let wire = json!({"permissions":[{"consent_scope":"voice_call","constraints":[{"future_rule":{"limit":1}}]}]});
    let value: ConsentValue = serde_json::from_value(wire.clone()).unwrap();
    value.validate().unwrap();
    assert_eq!(serde_json::to_value(&value).unwrap(), wire);
    let (request, current) = permission_read(&value, now);
    assert!(!current.permits(&request, ConsentScope::VoiceCall, now));
}
