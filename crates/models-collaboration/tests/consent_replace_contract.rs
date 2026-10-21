//! Exact-peer replacement preserves the complete permission set.
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
    assert!(typed.permits(ConsentScope::Invite, now));
    assert!(!typed.permits(ConsentScope::VoiceCall, now));
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

#[test]
fn facade_scope_diff_preserves_every_other_scope_and_optional_member() {
    let previous:ConsentValue=serde_json::from_value(json!({"permissions":[{"consent_scope":"invite","constraints":[],"reason":""},{"consent_scope":"voice_call","expires_at":"2020-01-01T00:00:00.000Z","constraints":[{"unknown_rule":true}]}]})).unwrap();
    let mut target:ConsentReplacePayload=serde_json::from_value(json!({"peer":{"kind":"actor","actor_id":{"kind":"service","service_id":"ak:did_core:web:peer.example"}},"expected_current":{"state":"never_written"},"permissions":previous.permissions})).unwrap();
    target
        .permissions
        .push(serde_json::from_value(json!({"consent_scope":"presence"})).unwrap());
    target
        .validate_scope_diff(&previous.permissions, ConsentScope::Presence, true)
        .unwrap();
    let mut lost_presence = target.clone();
    lost_presence.permissions[0].reason = None;
    assert!(
        lost_presence
            .validate_scope_diff(&previous.permissions, ConsentScope::Presence, true)
            .is_err()
    );
    let mut lost_expired = target.clone();
    lost_expired.permissions.remove(1);
    assert!(
        lost_expired
            .validate_scope_diff(&previous.permissions, ConsentScope::Presence, true)
            .is_err()
    );
    assert!(
        target
            .validate_scope_diff(&previous.permissions, ConsentScope::VideoCall, false)
            .is_err()
    );
}
