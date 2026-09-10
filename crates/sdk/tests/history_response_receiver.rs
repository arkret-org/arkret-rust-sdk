use std::future::Future;
use std::task::{Context, Poll, Waker};

use arkret_models_collaboration::history_key::*;
use arkret_wire::{DidUrl, EventId, Hash, WireError};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn hash() -> Hash {
    format!("sha256:{}", "a".repeat(64)).parse().unwrap()
}

fn signed(bytes: &[u8]) -> Result<String, WireError> {
    arkret_signatures::jws::sign_jws_ed25519(bytes, &SigningKey::from_bytes(&[17; 32]))
        .map_err(WireError::Protocol)
}

fn service_signed(bytes: &[u8]) -> Result<String, WireError> {
    arkret_signatures::jws::sign_jws_ed25519(bytes, &SigningKey::from_bytes(&[23; 32]))
        .map_err(WireError::Protocol)
}

fn with_proof<T: serde::de::DeserializeOwned>(
    mut value: Value,
    field: &str,
    proof: impl serde::Serialize,
) -> T {
    value[field] = serde_json::to_value(proof).unwrap();
    serde_json::from_value(value).unwrap()
}

fn fixture() -> (
    HistoryKeyRequestCreateOutcome,
    HistoryKeyResponseRecord,
    HistorySourceSignerResult,
    DateTime<Utc>,
) {
    let now: DateTime<Utc> = "2026-09-10T00:00:00.000Z".parse().unwrap();
    let expires = "2026-09-11T00:00:00.000Z";
    let vm = DidUrl::new("did:web:alice.example#response").unwrap();
    let service_vm = DidUrl::new("did:web:station.example#history").unwrap();
    let event = EventId::from_event_digest(&hash()).unwrap();
    let actor = json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}});
    let scope =
        json!({"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"});
    let incarnation = json!({"kind":"realm","realm_membership_incarnation_ref":event});
    let request_value = json!({
        "request_id":"ak:history_request:019c0000-0000-7000-8000-000000000001",
        "kind":"ak.history_key.request","effective_scope":scope,
        "requester_actor_id":actor,"requester_sender_domain":"ak:device:019c0000-0000-7000-8000-000000000001",
        "requester_author_profile":"ordinary_human",
        "requester_endpoint_authorization":{"kind":"ordinary_human","requester_device_id":"ak:device:019c0000-0000-7000-8000-000000000001","requester_device_authorize_event_id":event,"requester_device_generation_ref":1},
        "requester_authorization_incarnation":incarnation,"requested_ranges":[{"from_epoch":7,"to_epoch":8}],
        "recipient_hpke_public_key":"A".repeat(43),"expires_at":expires
    });
    let request = HistoryKeyRequest::build_signed_proof(
        vm.clone(),
        now,
        |proof| with_proof(request_value.clone(), "requester_proof", proof),
        signed,
    )
    .unwrap();
    let basis = json!({"leaves":[format!("ak:seal:sha256:{}", "b".repeat(64))]});
    let intent: HistoryGovernanceTraversalIntent = serde_json::from_value(json!({
        "profile":"member_history_delivery","kind":"ak.history_governance.traversal_intent",
        "effective_scope":scope,"mls_group_id":request.effective_scope.canonical_mls_group_id().unwrap(),
        "trusted_history_base_basis":basis,"trusted_current_basis":basis,"target_basis":basis,
        "request_digest":request.request_digest().unwrap(),"requested_ranges":request.requested_ranges,
        "authorization_incarnation":incarnation,"retention":{"kind":"request_expiring","expires_at":expires}
    })).unwrap();
    let retention = HistoryGovernanceTraversalRetention::from_intent(intent).unwrap();
    let receipt_value = json!({
        "kind":"ak.history_key.request_receipt","request_digest":request.request_digest().unwrap(),
        "response_capability_commitment":hash(),"sealed_response_capability_digest":hash(),
        "effective_scope":scope,"requester_sender_domain":request.requester_sender_domain,
        "requester_authorization_incarnation":incarnation,"release_id":"ak:did_core:web:station.example",
        "release_service_binding_ref":event,"release_service_resolution_ref":"resolution-1",
        "release_service_resolution_digest":hash(),"release_service_route_digest":hash(),
        "history_traversal_retention":retention,"accepted_at":"2026-09-10T00:00:00.000Z","expires_at":expires
    });
    let request_receipt = HistoryKeyRequestReceipt::build_signed_proof(
        service_vm.clone(),
        now,
        |proof| with_proof(receipt_value.clone(), "service_proof", proof),
        service_signed,
    )
    .unwrap();
    let accepted = HistoryKeyRequestCreateOutcome {
        kind: HistoryKeyRequestAcceptedKind::Value,
        request,
        request_receipt,
        sealed_history_response_capability: SealedHistoryResponseCapability {
            enc: "AA".into(),
            ciphertext: "AA".into(),
        },
    };
    accepted.validate().unwrap();
    let evidence = format!("ak:signer_evidence:{}", hash());
    let source_value = json!({
        "response_id":"ak:history_response:019c0000-0000-7000-8000-000000000002",
        "effective_scope":scope,"source_actor_id":actor,"source_sender_domain":"source.example",
        "source_signer_evidence_ref":evidence,
        "request_digest":accepted.request.request_digest().unwrap(),
        "request_receipt_digest":accepted.request_receipt.request_receipt_digest().unwrap(),"expires_at":expires,
        "content":{"kind":"ak.history_key.response_manifest","chunks":[{"chunk_response_id":"ak:history_response:019c0000-0000-7000-8000-000000000003","chunk_index":0,"covered_epoch_range":{"from_epoch":7,"to_epoch":8}}]}
    });
    let source_record = HistoryKeyResponseSendRequestBody::build_signed_proof(
        vm.clone(),
        now,
        |proof| with_proof(source_value.clone(), "source_proof", proof),
        signed,
    )
    .unwrap();
    let mut admission = HistoryManifestAdmission {
        kind: HistoryManifestAdmissionKind::Value,
        manifest_digest: source_record.manifest_digest().unwrap(),
        request_digest: source_record.request_digest.clone(),
        request_receipt_digest: source_record.request_receipt_digest.clone(),
        traversal_intent_digest: accepted
            .request_receipt
            .history_traversal_retention
            .traversal_intent_digest
            .clone(),
        authorized_ranges: accepted.request.requested_ranges.clone(),
        t0_pass: HistoryManifestAdmissionPass::Value,
        manifest_admission_digest: hash(),
    };
    admission.manifest_admission_digest = admission.canonical_digest_without_field().unwrap();
    let record_value = json!({
        "sequence":1,"cursor":"ak:cursor:YQ","record_digest":hash(),"sent_at":"2026-09-10T00:00:00.000Z",
        "manifest_admission":admission,"release_service_signer_evidence_ref":evidence,"source_record":source_record
    });
    let record = HistoryKeyResponseRecord::build_signed_proof(
        service_vm,
        now,
        |proof| {
            let mut record: HistoryKeyResponseRecord =
                with_proof(record_value.clone(), "service_proof", proof);
            record.record_digest = record.response_record_digest().unwrap();
            record
        },
        service_signed,
    )
    .unwrap();
    record.validate().unwrap();
    let signer_result = HistorySourceSignerResult::Authenticated {
        source_signer_evidence_ref: arkret_wire::SignerEvidenceRef::new(evidence).unwrap(),
        signer_kind: HistorySourceSignerKind::Principal,
        signer_id: "ak:did_core:web:alice.example".parse().unwrap(),
        verification_method: vm,
        public_key_b64u: arkret_wire::Base64UrlString::new(
            arkret_wire::base64url::base64url_encode(
                SigningKey::from_bytes(&[17; 32]).verifying_key().as_bytes(),
            ),
        )
        .unwrap(),
    };
    (accepted, record, signer_result, now)
}

fn verify(
    accepted: &HistoryKeyRequestCreateOutcome,
    record: &HistoryKeyResponseRecord,
    signer: &HistorySourceSignerResult,
    now: DateTime<Utc>,
) -> Result<arkret::VerifiedHistoryResponseRecord, WireError> {
    let mut future = std::pin::pin!(arkret::verify_history_response_record(
        accepted,
        record,
        signer,
        None,
        now,
        |_, _| panic!("ordinary sources must not require an MLS checkpoint or signer closure")
    ));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("ordinary source verification must not await external authority"),
    }
}

#[test]
fn principal_source_verifies_real_signature_without_governance_checkpoint() {
    // The caller has authenticated its own Station and accepted its authority
    // results. This test verifies SourceProof and recipient binding, not service
    // authorization or service DID resolution.
    let (accepted, record, signer, now) = fixture();
    assert!(matches!(
        verify(&accepted, &record, &signer, now).unwrap(),
        arkret::VerifiedHistoryResponseRecord::Manifest { .. }
    ));
    let mut wrong_key = signer.clone();
    if let HistorySourceSignerResult::Authenticated {
        public_key_b64u, ..
    } = &mut wrong_key
    {
        *public_key_b64u =
            arkret_wire::Base64UrlString::new(arkret_wire::base64url::base64url_encode(
                SigningKey::from_bytes(&[18; 32]).verifying_key().as_bytes(),
            ))
            .unwrap();
    }
    let error = verify(&accepted, &record, &wrong_key, now).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("history source proof is invalid")
    );
}

#[test]
fn source_manifest_cannot_be_replayed_to_another_recipient_request() {
    let (mut accepted, record, signer, now) = fixture();
    let mut wire = serde_json::to_value(&accepted.request).unwrap();
    wire["recipient_hpke_public_key"] = json!(arkret_wire::base64url::base64url_encode(&[1; 32]));
    accepted.request = HistoryKeyRequest::build_signed_proof(
        accepted.request.requester_proof.verification_method.clone(),
        now,
        |proof| with_proof(wire.clone(), "requester_proof", proof),
        signed,
    )
    .unwrap();
    accepted.validate().unwrap();
    let error = verify(&accepted, &record, &signer, now).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not bind the accepted request")
    );
}
