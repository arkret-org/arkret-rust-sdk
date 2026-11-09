mod support;
use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
};
use arkret_schema_conformance::{schema_registry_from_spec_artifacts, spec_json_artifact};
use arkret_wire::{EncryptedPayloadScheme, EventId, RealmId, ScopeRef, event_kind_str};
use serde_json::{Value, json};

fn event() -> EventId {
    EventId::new("ak:event:AX9nZ3uX9PVPLzEzy8k3kAa76IhSmQF4MQHNkxYwnI8z").unwrap()
}

#[test]
fn original_material_preserves_complete_outer_event_and_rejects_coordinate_substitution() {
    use arkret_models_crypto::{ContentContext, EventContentMaterial};
    use arkret_wire::{AccountId, ActorId, DidCoreId, Event, SemanticRef};

    let fixture = support::fixture();
    let context: ContentContext =
        serde_json::from_value(fixture["kat"]["content_context"].clone()).unwrap();
    let envelope: EncryptedEnvelope =
        serde_json::from_value(fixture["kat"]["envelope"].clone()).unwrap();
    let mut wire = fixture["kat"]["outer_event"].clone();
    wire["event_id"] = json!(event());
    wire["payload"] = json!({});
    let mut original: Event = serde_json::from_value(wire).unwrap();
    let reconstruct = |original: &Event, context: ContentContext| {
        EventContentMaterial::from_original(
            original,
            &envelope,
            context.root_context,
            context.producer,
        )
    };
    let initial = reconstruct(&original, context.clone()).unwrap();
    assert_eq!(initial.outer_event, fixture["kat"]["outer_event"]);
    original.executed_by = Some(original.actor_id.clone());
    original.actor_id = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    original.semantic_refs = vec![SemanticRef::new(event().to_string(), "after")];
    original.external_ref = Some(std::collections::BTreeMap::from([(
        "source".to_owned(),
        json!("original import"),
    )]));
    let delegated = reconstruct(&original, context.clone()).unwrap();
    assert_ne!(delegated.outer_event, initial.outer_event);
    assert_eq!(
        delegated.outer_event,
        EventContentMaterial::outer_event_for(&original).unwrap()
    );
    assert_eq!(
        delegated.outer_event["executed_by"],
        json!(context.producer.actor_id)
    );
    assert!(delegated.outer_event.get("semantic_refs").is_some());
    assert!(delegated.outer_event.get("external_ref").is_some());
    for change in 0..4 {
        let mut invalid = context.clone();
        match change {
            0 => invalid.root_context.epoch += 1,
            1 => invalid.root_context.group_state_ref = event(),
            2 => {
                invalid.root_context.effective_scope = ScopeRef::Realm {
                    realm_id: RealmId::from_event_id(&event()),
                }
            }
            _ => invalid.producer.actor_id = original.actor_id.clone(),
        }
        assert!(
            reconstruct(&original, invalid).is_err(),
            "substitution {change}"
        );
    }
}

fn envelope(epoch: u64, reaction: bool) -> EncryptedEnvelope {
    let wire = support::fixture()["kat"]["envelope"]["encryption_context"].clone();
    EncryptedEnvelope {
        version: "1.0".to_owned(),
        encryption_scheme: EncryptedPayloadScheme::EpochContentAead,
        content_type: "application/vnd.arkret.message+json".to_owned(),
        encryption_context: EncryptedEnvelopeEncryptionContext::EpochContent {
            epoch,
            group_state_ref: event(),
            content_key_salt: wire["content_key_salt"].as_str().unwrap().to_owned(),
            root_ref: serde_json::from_value(wire["root_ref"].clone()).unwrap(),
            key_commitment: serde_json::from_value(wire["key_commitment"].clone()).unwrap(),
            protection: serde_json::from_value(wire["protection"].clone()).unwrap(),
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
    for epoch in [0, 4, 9_007_199_254_740_992, u64::MAX] {
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
                        EncryptedPayloadScheme::EpochContentAead,
                        scope.clone(),
                        if reaction {
                            event_kind_str::REACTION_ADD
                        } else {
                            event_kind_str::MESSAGE_CREATE
                        },
                        support::sender_domain(),
                        reaction.then_some(42),
                        support::material(
                            value,
                            &scope,
                            if reaction {
                                event_kind_str::REACTION_ADD
                            } else {
                                event_kind_str::MESSAGE_CREATE
                            },
                        ),
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
fn encrypted_content_requires_a_nonempty_backup_dependency_before_seal_or_open() {
    let mut wire = serde_json::to_value(envelope(4, false)).unwrap();
    wire["encryption_context"]["protection"]["backup_refs"] = json!([]);
    assert!(!schema_accepts(&wire));
    let decoded: EncryptedEnvelope = serde_json::from_value(wire).unwrap();
    assert!(decoded.validate().is_err());
    let scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:AW-eYHZqTc5zBim-zkto9i7ELc_x5Idz3ZVEWb2fBGBj").unwrap(),
    };
    assert!(
        decoded
            .reconstruct_pre_encryption_header(
                EncryptedPayloadScheme::EpochContentAead,
                scope.clone(),
                event_kind_str::MESSAGE_CREATE,
                support::sender_domain(),
                None,
                support::material(&decoded, &scope, event_kind_str::MESSAGE_CREATE),
            )
            .is_err()
    );
}

#[test]
fn encrypted_envelope_rejects_retired_counter_and_unknown_context_fields() {
    for counter in [
        json!(null),
        json!(0),
        json!(7),
        json!(u64::MAX),
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
        json!(0),
        json!("00"),
        json!(0.5),
        json!("18446744073709551616"),
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
    assert!(serde_json::to_value(envelope(u64::MAX, false)).is_ok());
    assert!(envelope(u64::MAX, false).validate().is_ok());
}
