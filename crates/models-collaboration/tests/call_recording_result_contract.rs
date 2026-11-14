//! Recording results keep one artifact while retaining independent context gates.

use std::fs;

use arkret_models_collaboration::events_payloads::call::{
    CallRecordingArtifact, CallRecordingArtifactCurrentValue, CallRecordingMetadata,
    CallStatePayload, CallTranscriptArtifactCurrentValue,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{CallId, EventId, GrantId, RealmId};
use serde_json::{Value, json};

fn event_id(byte: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
}

fn realm_id(byte: u8) -> RealmId {
    RealmId::from_event_id(&event_id(byte))
}

fn call_id(byte: u8) -> CallId {
    CallId::from_event_id(&event_id(byte))
}

fn grant_id(byte: u8) -> GrantId {
    GrantId::from_event_id(&event_id(byte))
}

fn artifact() -> Value {
    let realm = realm_id(1);
    let call = call_id(2);
    let start = event_id(3);
    json!({
        "schema":"ak.schema.call_recording_artifact.v1",
        "realm_id":realm, "call_id":call, "recording_id":"recording-1",
        "recording_start_event_id":start,
        "blob_ref":format!("ak:blob:sha256:{}", "0".repeat(64)),
        "size_bytes":1, "duration_ms":1, "media_type":"audio/ogg",
        "encryption":{
            "encryption_algorithm":"mls_exporter_aead_xchacha20poly1305",
            "exporter_label":"ak.rtc-recording-key/v1",
            "context":{"realm_id":realm,"call_id":call,"focus_id":"focus-1",
                "recording_id":"recording-1","media_service_id":"ak:did_core:web:media.example",
                "recording_start_event_id":start}
        },
        "retention":{"retention_expires_at":"2026-12-14T00:00:00.000Z","consent_confirmed":true},
        "produced_by":"ak:did_core:web:media.example",
        "recording_initiator_capability_ref":grant_id(4),
        "created_at":"2026-11-14T00:00:00.000Z"
    })
}

fn ready() -> Value {
    json!({"call_id":call_id(2),"recording_transition":{
        "recording_id":"recording-1","from":"stopped","to":"ready",
        "expected_commit_id":event_id(6).as_str().replace("ak:event:","ak:realm_commit:"),
        "capture_metadata":{"artifact":artifact()}
    }})
}

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:recording-result",
            schema,
            "#/$defs/call_state_payload",
        )
        .unwrap();
    registry
        .validate_value("test:recording-result", value)
        .is_ok()
}

fn sdk_accepts(value: Value) -> bool {
    serde_json::from_value::<CallStatePayload>(value)
        .is_ok_and(|payload| payload.validate().is_ok())
}

#[test]
fn ready_roundtrips_the_single_complete_artifact() {
    let value = ready();
    assert!(schema_accepts(&value));
    let payload: CallStatePayload = serde_json::from_value(value.clone()).unwrap();
    payload.validate().unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), value);
    let typed: CallRecordingArtifact = serde_json::from_value(artifact()).unwrap();
    assert_eq!(
        serde_json::to_value(CallRecordingMetadata::ready(typed)).unwrap(),
        value["recording_transition"]["capture_metadata"]
    );
}

#[test]
fn equal_outer_mirrors_nulls_and_second_digest_are_rejected() {
    for (name, mirror) in [
        (
            "content_digest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("duration_ms", json!(1)),
        ("media_type", json!("audio/ogg")),
        (
            "retention_policy_id",
            json!("ak:policy:0198ff00-0000-7000-8000-000000000001"),
        ),
        ("retention", artifact()["retention"].clone()),
        (
            "recording_start_event_id",
            artifact()["recording_start_event_id"].clone(),
        ),
        ("recording_stop_event_id", json!(event_id(5))),
        ("failure_reason_code", json!("x_capture_failed")),
        ("failure_message", json!("capture failed")),
        ("unknown", json!(true)),
    ] {
        for mirror in [mirror, Value::Null] {
            let mut value = ready();
            value["recording_transition"]["capture_metadata"][name] = mirror;
            assert!(!schema_accepts(&value), "{name}: {value}");
            assert!(!sdk_accepts(value), "{name}");
        }
    }
    let mut duplicate_digest = ready();
    duplicate_digest["recording_transition"]["capture_metadata"]["artifact"]["content_digest"] =
        json!(format!("sha256:{}", "0".repeat(64)));
    assert!(!schema_accepts(&duplicate_digest));
    assert!(!sdk_accepts(duplicate_digest));
    for field in ["artifact", "capture_metadata"] {
        let mut value = ready();
        if field == "artifact" {
            value["recording_transition"]["capture_metadata"][field] = Value::Null;
        } else {
            value["recording_transition"][field] = Value::Null;
        }
        assert!(!schema_accepts(&value));
        assert!(!sdk_accepts(value));
    }
}

#[test]
fn nonready_outcomes_keep_their_own_metadata_and_confirmed_stop_reference() {
    let mut value = ready();
    value["recording_transition"]["to"] = json!("failed");
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value.clone()));
    value["recording_transition"]["capture_metadata"] = json!({
        "recording_stop_event_id":event_id(5),
        "failure_reason_code":"x_capture_failed","failure_message":"capture failed",
        "duration_ms":1,"retention":artifact()["retention"]
    });
    assert!(schema_accepts(&value));
    assert!(sdk_accepts(value.clone()));
    value["recording_transition"]["capture_metadata"]
        .as_object_mut()
        .unwrap()
        .remove("recording_stop_event_id");
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value));
    let mut stopped = ready();
    stopped["recording_transition"]["from"] = json!("recording");
    stopped["recording_transition"]["to"] = json!("stopped");
    assert!(!schema_accepts(&stopped));
    assert!(!sdk_accepts(stopped.clone()));
    stopped["recording_transition"]
        .as_object_mut()
        .unwrap()
        .remove("expected_commit_id");
    stopped["recording_transition"]["capture_metadata"] = json!({"duration_ms":1});
    assert!(schema_accepts(&stopped));
    assert!(sdk_accepts(stopped));
}

#[test]
fn artifact_simplification_preserves_parent_context_and_retention_validation() {
    for pointer in [
        "/call_id",
        "/recording_id",
        "/encryption/context/realm_id",
        "/encryption/context/call_id",
        "/encryption/context/recording_id",
        "/encryption/context/recording_start_event_id",
        "/encryption/context/media_service_id",
        "/encryption/exporter_label",
        "/retention",
    ] {
        let mut value = ready();
        let replacement = match pointer {
            "/call_id" | "/encryption/context/call_id" => json!(call_id(9)),
            "/recording_id" | "/encryption/context/recording_id" => json!("another-recording"),
            "/encryption/context/realm_id" => json!(realm_id(9)),
            "/encryption/context/recording_start_event_id" => json!(event_id(9)),
            "/encryption/context/media_service_id" => json!("ak:did_core:web:other.example"),
            "/encryption/exporter_label" => json!("ak.other/v1"),
            "/retention" => json!({}),
            _ => unreachable!(),
        };
        *value["recording_transition"]["capture_metadata"]["artifact"]
            .pointer_mut(pointer)
            .unwrap() = replacement;
        assert!(!sdk_accepts(value), "{pointer}");
    }
}

#[test]
fn result_guard_is_required_scalar_and_stop_guard_is_forbidden() {
    let mut value = ready();
    let guard = value["recording_transition"]["expected_commit_id"].clone();
    for replacement in [Value::Null, json!({"commit_id":guard,"stream_position":1})] {
        value["recording_transition"]["expected_commit_id"] = replacement;
        assert!(!schema_accepts(&value));
        assert!(!sdk_accepts(value.clone()));
    }
    value["recording_transition"]
        .as_object_mut()
        .unwrap()
        .remove("expected_commit_id");
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value));
    let value = json!({"call_id":call_id(2),"recording_transition":{
        "recording_id":"recording-1","from":"recording","to":"stopped",
        "expected_commit_id":guard}});
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value));
}

#[test]
fn current_status_is_real_information_and_never_a_second_revision() {
    let value = json!({"status":"ready","details":{"artifact":artifact()}});
    let current: CallRecordingArtifactCurrentValue = serde_json::from_value(value.clone()).unwrap();
    current
        .validate(&call_id(2), &"recording-1".parse().unwrap())
        .unwrap();
    assert_eq!(serde_json::to_value(current).unwrap(), value);
    for name in ["expected_commit_id", "revision"] {
        let mut changed = value.clone();
        changed[name] = ready()["recording_transition"]["expected_commit_id"].clone();
        assert!(serde_json::from_value::<CallRecordingArtifactCurrentValue>(changed).is_err());
    }
    for status in ["pending", "failed"] {
        let mut changed = value.clone();
        changed["status"] = json!(status);
        let current: CallRecordingArtifactCurrentValue = serde_json::from_value(changed).unwrap();
        assert!(
            current
                .validate(&call_id(2), &"recording-1".parse().unwrap())
                .is_err()
        );
    }
}

#[test]
fn transcript_uses_its_exact_stop_and_cannot_consume_a_recording_artifact() {
    let mut value = json!({"call_id":call_id(2),"transcript_transition":{
        "recording_id":"transcript-1","from":"stopped","to":"ready",
        "expected_commit_id":ready()["recording_transition"]["expected_commit_id"],
        "capture_metadata":{"transcript_start_event_id":event_id(7),
            "transcript_stop_event_id":event_id(8),"retention":artifact()["retention"]}}});
    assert!(schema_accepts(&value));
    assert!(sdk_accepts(value.clone()));
    for field in [
        "transcript_start_event_id",
        "transcript_stop_event_id",
        "retention",
    ] {
        let mut changed = value.clone();
        changed["transcript_transition"]["capture_metadata"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(!schema_accepts(&changed));
        assert!(!sdk_accepts(changed));
    }
    value["transcript_transition"]["capture_metadata"]["artifact"] = artifact();
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value));
    assert!(
        serde_json::from_value::<CallTranscriptArtifactCurrentValue>(
            json!({"status":"ready","details":{"artifact":artifact()}})
        )
        .is_err()
    );
}

#[test]
fn stopped_transcript_distinguishes_absence_from_explicit_null() {
    let mut value = json!({"call_id":call_id(2),"transcript_transition":{
        "recording_id":"transcript-1","from":"transcribing","to":"stopped"}});
    assert!(schema_accepts(&value));
    assert!(sdk_accepts(value.clone()));
    value["transcript_transition"]["capture_metadata"] = Value::Null;
    assert!(!schema_accepts(&value));
    assert!(!sdk_accepts(value));
}

#[test]
fn all_recording_algorithms_preserve_the_canonical_wire_spelling() {
    for algorithm in [
        "mls_exporter_aead_xchacha20poly1305",
        "mls_exporter_aead_aes_256_gcm",
        "mls_exporter_aead_xchacha20poly1305_stream",
        "mls_exporter_aead_aes_256_gcm_stream",
    ] {
        let mut value = ready();
        value["recording_transition"]["capture_metadata"]["artifact"]["encryption"]["encryption_algorithm"] =
            json!(algorithm);
        assert!(schema_accepts(&value));
        let payload: CallStatePayload = serde_json::from_value(value.clone()).unwrap();
        payload.validate().unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);
    }
    for invalid in [
        "mls_exporter_aead_aes256_gcm",
        "mls_exporter_aead_aes256_gcm_stream",
    ] {
        let mut value = ready();
        value["recording_transition"]["capture_metadata"]["artifact"]["encryption"]["encryption_algorithm"] =
            json!(invalid);
        assert!(!schema_accepts(&value));
        assert!(!sdk_accepts(value));
    }
}
