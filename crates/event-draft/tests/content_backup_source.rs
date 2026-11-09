//! Frozen source bytes and slot binding, not native issuer or storage qualification.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{ContentBackupSourceAttestation, ContentEndpoint};
use arkret_wire::{DidCoreId, Event};
use serde_json::{Value, json};

fn cases() -> Vec<Value> {
    arkret_schema_conformance::spec_json_artifact("fixtures/content-backup-source-fixture.json")
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn frozen_human_and_agent_sources_match_full_event_and_signing_bytes() {
    for case in cases() {
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        let source: ContentBackupSourceAttestation =
            serde_json::from_value(case["attestation"].clone()).unwrap();
        let producer: ContentEndpoint = serde_json::from_value(case["producer"].clone()).unwrap();
        let destination = DidCoreId::new("ak:did_core:web:governor.example").unwrap();
        assert_eq!(serde_json::to_value(&source).unwrap(), case["attestation"]);
        let expected = case["signing_hex"].as_str().unwrap();
        let actual = source.signing_payload_bytes().unwrap();
        let encoded: String = actual.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(encoded, expected);
        assert_eq!(
            event.event_content_protections_digest().unwrap(),
            source.protections_digest
        );
        event
            .validate_content_backup_source_binding(&source, &producer, &destination)
            .unwrap();
        source
            .validate_at("2026-11-08T00:00:02.000Z".parse().unwrap())
            .unwrap();
        assert!(source.validate_at(source.expires_at).is_err());
    }
}

#[test]
fn changed_original_proof_payload_endpoint_or_destination_cannot_rebind() {
    for case in cases() {
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        let source: ContentBackupSourceAttestation =
            serde_json::from_value(case["attestation"].clone()).unwrap();
        let producer: ContentEndpoint = serde_json::from_value(case["producer"].clone()).unwrap();
        let destination = DidCoreId::new("ak:did_core:web:governor.example").unwrap();
        let foreign = DidCoreId::new("ak:did_core:web:another.example").unwrap();
        assert!(
            event
                .validate_content_backup_source_binding(&source, &producer, &foreign)
                .is_err()
        );
        let mut endpoint = producer.clone();
        endpoint.authorization_event_ref =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [19; 32]);
        assert!(
            event
                .validate_content_backup_source_binding(&source, &endpoint, &destination)
                .is_err()
        );
        let mut changed = event.clone();
        changed.producer_proof.as_mut().unwrap().jws.push('A');
        assert!(
            changed
                .validate_content_backup_source_binding(&source, &producer, &destination)
                .is_err()
        );
        let mut changed = event.clone();
        changed.payload.get_mut("encrypted_metadata").unwrap()["ciphertext"] = json!("changed");
        assert!(
            changed
                .validate_content_backup_source_binding(&source, &producer, &destination)
                .is_err()
        );
        let mut incomplete = source.clone();
        incomplete.protections_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(
            event
                .validate_content_backup_source_binding(&incomplete, &producer, &destination)
                .is_err()
        );
    }
}

#[test]
fn source_is_closed_required_and_observation_window_is_bounded() {
    let original = &cases()[0]["attestation"];
    for field in original.as_object().unwrap().keys() {
        for missing in [true, false] {
            let mut value = original.clone();
            if missing {
                value.as_object_mut().unwrap().remove(field);
            } else {
                value[field] = Value::Null;
            }
            assert!(
                serde_json::from_value::<ContentBackupSourceAttestation>(value).is_err(),
                "{field}"
            );
        }
    }
    let mut value = original.clone();
    value["durable"] = json!(true);
    assert!(serde_json::from_value::<ContentBackupSourceAttestation>(value).is_err());
    let mut source: ContentBackupSourceAttestation =
        serde_json::from_value(original.clone()).unwrap();
    source.expires_at = source.attested_at + chrono::Duration::seconds(301);
    assert!(source.validate().is_err());
}

#[test]
fn cross_station_check_cannot_skip_source_or_replace_local_root_checks() {
    let case = &cases()[0];
    let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
    let producer: ContentEndpoint = serde_json::from_value(case["producer"].clone()).unwrap();
    let destination = DidCoreId::new("ak:did_core:web:governor.example").unwrap();
    let now = "2026-11-08T00:00:02.000Z".parse().unwrap();
    assert!(
        arkret_event_draft::validate_cross_station_content_backup_sources(
            &[&event],
            None,
            std::slice::from_ref(&producer),
            &destination,
            now,
        )
        .is_err()
    );
    assert!(
        arkret_event_draft::validate_cross_station_content_backup_sources(
            &[&event],
            Some(&[]),
            std::slice::from_ref(&producer),
            &destination,
            now,
        )
        .is_err()
    );
    assert!(
        arkret_event_draft::validate_cross_station_content_backup_sources(
            &[&event],
            None,
            &[],
            &destination,
            now,
        )
        .is_err()
    );
    let local = &producer.actor_id.as_account_id().unwrap().station_id;
    assert!(
        arkret_event_draft::validate_cross_station_content_backup_sources(
            &[&event],
            None,
            std::slice::from_ref(&producer),
            local,
            now,
        )
        .is_err()
    );
}

#[test]
fn source_completeness_requires_an_actual_original() {
    let destination = DidCoreId::new("ak:did_core:web:governor.example").unwrap();
    assert!(
        arkret_event_draft::validate_cross_station_content_backup_sources(
            &[],
            None,
            &[],
            &destination,
            "2026-11-08T00:00:02.000Z".parse().unwrap(),
        )
        .is_err()
    );
}
