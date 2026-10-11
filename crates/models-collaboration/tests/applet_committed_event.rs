//! Closed Applet delivery codec and byte-local evidence bindings. The formal
//! cryptographic transcript explicitly excludes actual admission and native
//! Service/DID-chain verification; this test does not establish either.

use arkret_models_collaboration::applet_installation_authority::AppletCommittedEvent;
use arkret_models_identity::{
    AccountDeviceSignerEvidence, AuthenticatedServiceResolution, DidDocument,
    ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    normalized_did_document_digest,
};
use arkret_wire::{ActorId, DeviceId, Did, DidCoreId};
use serde_json::{Value, json};

fn original_device_pair() -> AppletCommittedEvent {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/signer-key-historical-coordinate-fixture.json"))
            .unwrap(),
    )
    .unwrap();
    let transcript = &fixture["foreign_human_historical_signer_delivery"]["crypto_transcript"];
    let source: arkret_models_crypto::ForwardDeviceProjectionAttestation =
        serde_json::from_value(transcript["origin_attestation"].clone()).unwrap();
    let core = source.attestation;
    // Sign a distinct regular root from typed source coordinates. Never delete
    // event_authorization from a signed forward sibling and reuse its signature.
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        arkret_models_crypto::DeviceProjectionAttestationCore {
            account_id: core.account_id,
            device_id: core.device_id,
            device_signing_key_did: core.device_signing_key_did,
            hpke_key: core.hpke_key,
            device_authorize_event_id: core.device_authorize_event_id,
            authorized_generation_ref: core.authorized_generation_ref,
            device_status: core.device_status,
            authorization_window: core.authorization_window,
            attested_at: core.attested_at,
            expires_at: core.expires_at,
        },
        source.proof.verification_method,
        &key,
    )
    .unwrap();
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(transcript["commit"].clone()).unwrap();
    arkret_signatures::device_projection::verify_device_projection_attestation(
        &attestation,
        &key.verifying_key(),
        commit.committed_at,
    )
    .unwrap();
    let controller = attestation
        .proof
        .verification_method
        .as_str()
        .split_once('#')
        .unwrap()
        .0;
    let did = Did::new(controller).unwrap();
    let document: DidDocument = serde_json::from_value(json!({
        "id":did, "verificationMethod":[],
        "service":[{"id":format!("{controller}#service"),"type":"ArkretService",
            "serviceKind":"station","serviceEndpoint":"https://station.example/"}]
    }))
    .unwrap();
    // Metadata shape for the codec's Station binding only. A receiver must
    // supply and authenticate the real method-native log/history separately.
    let resolution = AuthenticatedServiceResolution {
        service_id: attestation.attestation.account_id.station_id.clone(),
        service_kind: "station".into(),
        method_history_evidence: ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: "structural-fixture".into(),
                to_method_history_head: "structural-fixture".into(),
                from_version_id: "structural-fixture".into(),
                to_version_id: "structural-fixture".into(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![],
            },
            log_entries: vec![],
            witness_records: vec![],
        },
        normalized_did_document: document,
    };
    // Event and Commit remain the exact formal transcript bytes, including
    // its signer-fact digest. The regular root is independently signed above;
    // this component fixture never claims an actual admission outcome.
    AppletCommittedEvent {
        event: serde_json::from_value(transcript["event"].clone()).unwrap(),
        commit,
        producer_device_evidence: Some(AccountDeviceSignerEvidence {
            device_projection_attestation: attestation,
            service_resolution: resolution,
        }),
    }
}

#[test]
fn original_device_delivery_roundtrips_without_dropping_the_regular_root() {
    let pair = original_device_pair();
    pair.validate_structural().unwrap();
    let value = serde_json::to_value(&pair).unwrap();
    assert_eq!(
        value["producer_device_evidence"].as_object().unwrap().len(),
        2
    );
    assert!(
        value["producer_device_evidence"]["device_projection_attestation"]["attestation"]
            .get("event_authorization")
            .is_none()
    );
    let restored: AppletCommittedEvent = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(restored, pair);
    assert_eq!(serde_json::to_value(restored).unwrap(), value);
}

#[test]
fn missing_surplus_null_and_forward_sibling_evidence_fail_closed() {
    let pair = original_device_pair();
    let value = serde_json::to_value(&pair).unwrap();
    let mut missing = value.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("producer_device_evidence");
    assert!(serde_json::from_value::<AppletCommittedEvent>(missing).is_err());
    let mut null = value.clone();
    null["producer_device_evidence"] = Value::Null;
    assert!(serde_json::from_value::<AppletCommittedEvent>(null).is_err());
    let mut forward = value.clone();
    forward["producer_device_evidence"]["device_projection_attestation"]["attestation"]["event_authorization"] =
        json!({});
    assert!(serde_json::from_value::<AppletCommittedEvent>(forward).is_err());
    let mut extra = value;
    extra["producer_device_evidence"]["pcr_log"] = json!([]);
    assert!(serde_json::from_value::<AppletCommittedEvent>(extra).is_err());
    let mut surplus = pair.clone();
    surplus.event.actor_id =
        ActorId::service(surplus.event.actual_signer().signing_principal_id().clone());
    assert!(surplus.validate_shape().is_err());
    assert!(serde_json::to_value(surplus).is_err());
    let mut absent = pair;
    absent.producer_device_evidence = None;
    assert!(serde_json::to_value(absent).is_err());
}

#[test]
fn another_account_device_or_origin_station_is_not_a_matching_root() {
    let pair = original_device_pair();
    let mut changed = pair.clone();
    changed
        .producer_device_evidence
        .as_mut()
        .unwrap()
        .device_projection_attestation
        .attestation
        .account_id
        .principal_id = DidCoreId::new("ak:did_core:web:another.example").unwrap();
    assert!(changed.validate_shape().is_err());
    changed = pair.clone();
    changed
        .producer_device_evidence
        .as_mut()
        .unwrap()
        .device_projection_attestation
        .attestation
        .device_id = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000099").unwrap();
    assert!(changed.validate_shape().is_err());
    changed = pair.clone();
    changed
        .producer_device_evidence
        .as_mut()
        .unwrap()
        .service_resolution
        .service_id = DidCoreId::new("ak:did_core:web:another-station.example").unwrap();
    assert!(changed.validate_shape().is_err());
    changed = pair;
    changed
        .producer_device_evidence
        .as_mut()
        .unwrap()
        .service_resolution
        .service_kind = "applet".into();
    assert!(changed.validate_shape().is_err());
}
