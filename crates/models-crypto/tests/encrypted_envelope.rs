use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
    MAX_EVENT_CONTENT_INTEGER,
};
use arkret_schema_conformance::{schema_registry_from_spec_artifacts, spec_json_artifact};
use arkret_wire::{EncryptedPayloadScheme, EventId, RealmId, ScopeRef, event_kind_str};
use serde_json::{Value, json};

fn event() -> EventId {
    EventId::new("ak:event:AX9nZ3uX9PVPLzEzy8k3kAa76IhSmQF4MQHNkxYwnI8z").unwrap()
}

fn envelope(epoch: u64, reaction: bool) -> EncryptedEnvelope {
    EncryptedEnvelope {
        version: "1.0".to_owned(),
        content_type: "application/vnd.arkret.message+json".to_owned(),
        encryption_context: EncryptedEnvelopeEncryptionContext::StandardMls {
            epoch,
            group_state_ref: event(),
            routing_context: reaction.then(|| EncryptedEnvelopeRoutingContext {
                target_ref: event(),
                routing_tag: "A".repeat(43),
            }),
        },
        ciphertext: "AQID".to_owned(),
    }
}

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema = spec_json_artifact("schemas/encrypted-envelope.schema.json").unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:encrypted-envelope".to_owned(), schema, "#")
        .unwrap();
    registry
        .validate_value("test:encrypted-envelope", value)
        .is_ok()
}

#[test]
fn encrypted_envelope_round_trip_matches_closed_schema_and_authenticated_header() {
    for epoch in [0, 4, MAX_EVENT_CONTENT_INTEGER] {
        for reaction in [false, true] {
            let original = envelope(epoch, reaction);
            let wire = serde_json::to_value(&original).unwrap();
            assert!(schema_accepts(&wire));
            let decoded: EncryptedEnvelope = serde_json::from_value(wire).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(
                decoded.payload_digest().unwrap(),
                original.payload_digest().unwrap()
            );
            let scope = ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AW-eYHZqTc5zBim-zkto9i7ELc_x5Idz3ZVEWb2fBGBj")
                    .unwrap(),
            };
            let header = |value: &EncryptedEnvelope| {
                value
                    .reconstruct_pre_encryption_header(
                        EncryptedPayloadScheme::MlsRfc9420,
                        scope.clone(),
                        if reaction {
                            event_kind_str::REACTION_ADD
                        } else {
                            event_kind_str::MESSAGE_CREATE
                        },
                        "ak:device:01a0676d-bc3a-70b2-909e-d8914c3d1828",
                        reaction.then_some(42),
                    )
                    .unwrap()
                    .canonical_bytes()
                    .unwrap()
            };
            assert_eq!(header(&original), header(&decoded));
        }
    }
}

#[test]
fn encrypted_envelope_rejects_retired_counter_and_unknown_context_fields() {
    for counter in [
        json!(null),
        json!(0),
        json!(7),
        json!(MAX_EVENT_CONTENT_INTEGER),
        json!(-1),
        json!("0"),
        json!(0.5),
        json!(u64::MAX),
    ] {
        let mut wire = serde_json::to_value(envelope(4, false)).unwrap();
        wire["encryption_context"]["counter"] = counter;
        assert!(!schema_accepts(&wire));
        assert!(serde_json::from_value::<EncryptedEnvelope>(wire).is_err());
    }
    for reaction in [false, true] {
        for field in ["unknown", "scheme", "algorithm", "mls_group_id"] {
            let mut wire = serde_json::to_value(envelope(4, reaction)).unwrap();
            wire["encryption_context"][field] = json!(true);
            assert!(!schema_accepts(&wire));
            assert!(serde_json::from_value::<EncryptedEnvelope>(wire).is_err());
        }
    }
    assert!(
        serde_json::from_value::<EncryptedPayloadScheme>(json!("mls_exporter_aead_v1")).is_err()
    );
}

#[test]
fn encrypted_envelope_rejects_null_or_open_routing_and_invalid_epoch() {
    for invalid in [
        json!(null),
        json!(-1),
        json!("0"),
        json!(0.5),
        json!(MAX_EVENT_CONTENT_INTEGER + 1),
    ] {
        let mut wire = serde_json::to_value(envelope(4, false)).unwrap();
        wire["encryption_context"]["epoch"] = invalid;
        assert!(!schema_accepts(&wire));
        assert!(serde_json::from_value::<EncryptedEnvelope>(wire).is_err());
    }
    let mut null_routing = serde_json::to_value(envelope(4, false)).unwrap();
    null_routing["encryption_context"]["routing_context"] = Value::Null;
    assert!(!schema_accepts(&null_routing));
    assert!(serde_json::from_value::<EncryptedEnvelope>(null_routing).is_err());
    let mut unknown_routing = serde_json::to_value(envelope(4, true)).unwrap();
    unknown_routing["encryption_context"]["routing_context"]["counter"] = json!(0);
    assert!(!schema_accepts(&unknown_routing));
    assert!(serde_json::from_value::<EncryptedEnvelope>(unknown_routing).is_err());
    assert!(serde_json::to_value(envelope(MAX_EVENT_CONTENT_INTEGER + 1, false)).is_err());
    assert!(
        envelope(MAX_EVENT_CONTENT_INTEGER + 1, false)
            .validate()
            .is_err()
    );
}
