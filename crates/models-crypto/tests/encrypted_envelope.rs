use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext,
};
use arkret_wire::{EncryptedPayloadScheme, EventId, RealmId, ScopeRef, event_kind_str};
use serde_json::json;

fn envelope(counter: Option<u64>) -> EncryptedEnvelope {
    let event =
        EventId::new("ak:event:AX9nZ3uX9PVPLzEzy8k3kAa76IhSmQF4MQHNkxYwnI8z".to_owned()).unwrap();
    EncryptedEnvelope {
        version: "1.0".to_owned(),
        content_type: "application/vnd.arkret.message+json".to_owned(),
        encryption_context: match counter {
            Some(counter) => EncryptedEnvelopeEncryptionContext::exporter(4, event, counter),
            None => EncryptedEnvelopeEncryptionContext::standard(4, event),
        },
        ciphertext: "AQID".to_owned(),
    }
}

#[test]
fn wire_round_trip_preserves_scheme_counter_digest_and_authenticated_header() {
    for counter in [None, Some(0), Some(7), Some(9_007_199_254_740_991)] {
        let original = envelope(counter);
        let decoded: EncryptedEnvelope =
            serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encryption_context.counter(), counter);
        assert_eq!(
            decoded.payload_digest().unwrap(),
            original.payload_digest().unwrap()
        );
        let scope = ScopeRef::Realm {
            realm_id: RealmId::new(
                "ak:realm:AW-eYHZqTc5zBim-zkto9i7ELc_x5Idz3ZVEWb2fBGBj".to_owned(),
            )
            .unwrap(),
        };
        let scheme = if counter.is_some() {
            EncryptedPayloadScheme::MlsExporterAeadV1
        } else {
            EncryptedPayloadScheme::MlsRfc9420
        };
        let header = |value: &EncryptedEnvelope| {
            value
                .reconstruct_pre_encryption_header(
                    scheme.clone(),
                    scope.clone(),
                    event_kind_str::MESSAGE_CREATE,
                    "ak:device:01a0676d-bc3a-70b2-909e-d8914c3d1828",
                    None,
                )
                .unwrap()
                .canonical_bytes()
                .unwrap()
        };
        assert_eq!(header(&original), header(&decoded));
    }
}

#[test]
fn malformed_exporter_counter_cannot_be_dropped_into_standard_mls() {
    for counter in [
        json!(null),
        json!(-1),
        json!("0"),
        json!(0.5),
        json!(9_007_199_254_740_992_u64),
        json!(u64::MAX),
    ] {
        let mut value = serde_json::to_value(envelope(Some(0))).unwrap();
        value["encryption_context"]["counter"] = counter;
        assert!(serde_json::from_value::<EncryptedEnvelope>(value).is_err());
    }
    assert!(serde_json::to_vec(&envelope(Some(u64::MAX))).is_err());
    assert!(envelope(Some(u64::MAX)).validate().is_err());
    for counter in [None, Some(0)] {
        let mut value = serde_json::to_value(envelope(counter)).unwrap();
        value["encryption_context"]["unknown"] = json!(true);
        assert!(serde_json::from_value::<EncryptedEnvelope>(value).is_err());
    }
}
