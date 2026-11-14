use super::*;

fn kat() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .unwrap()["single_submit_recovery_kat"]
        .clone()
}
fn candidate(kat: &serde_json::Value) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(
            kat["qualified_inputs"]["candidate_public_key"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    }
}
fn method(kat: &serde_json::Value) -> DidUrl {
    DidUrl::new(
        kat["qualified_inputs"]["candidate_method"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}
fn station() -> PublicKeyMaterial {
    let seed: [u8; 32] = core::array::from_fn(|index| index as u8 + 33);
    PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes()
            .to_vec(),
    }
}

#[test]
fn original_receipt_two_producer_proofs_and_possession_are_real_signatures() {
    let kat = kat();
    let receipt: RecoveryReceipt = serde_json::from_value(kat["receipt"].clone()).unwrap();
    verify_recovery_receipt(&receipt, &method(&kat), &candidate(&kat)).unwrap();
    assert_eq!(
        receipt.receipt_digest().unwrap().as_str(),
        kat["receipt_digest"].as_str().unwrap()
    );
    let mut changed = receipt.clone();
    changed.welcome_count += 1;
    assert!(verify_recovery_receipt(&changed, &method(&kat), &candidate(&kat)).is_err());
    let seed: [u8; 32] = core::array::from_fn(|index| index as u8 + 1);
    sign_recovery_receipt(&mut changed, &SigningKey::from_bytes(&seed)).unwrap();
    verify_recovery_receipt(&changed, &method(&kat), &candidate(&kat)).unwrap();
    assert_ne!(
        receipt.receipt_digest().unwrap(),
        changed.receipt_digest().unwrap()
    );
}

#[test]
fn completion_authenticates_two_actual_contiguous_commits() {
    let kat = kat();
    let completed: RecoveryTransactionCompletion =
        serde_json::from_value(kat["expected_outcome"].clone()).unwrap();
    let commits: [RealmCommit; 2] = serde_json::from_value(kat["native_commits"].clone()).unwrap();
    let signer = DidUrl::new("did:web:station.example#service-1").unwrap();
    verify_recovery_completion(&completed, &commits, &signer, &station()).unwrap();
    let mut changed = commits.clone();
    changed[1].previous_commit_ref = changed[0].previous_commit_ref.clone();
    assert!(verify_recovery_completion(&completed, &changed, &signer, &station()).is_err());
    let mut changed = completed;
    changed
        .completion_attestation
        .reanchor_event_ref
        .stream_position += 1;
    assert!(verify_recovery_completion(&changed, &commits, &signer, &station()).is_err());
}

#[cfg(any(
    feature = "collaboration",
    feature = "service-identity",
    feature = "webvh"
))]
#[test]
fn fresh_completion_holder_is_signed_by_the_accepted_identity_key() {
    let kat = kat();
    let request = serde_json::from_value(kat["completion_request"].clone()).unwrap();
    verify_recovery_completion_holder(&request, &method(&kat), &candidate(&kat)).unwrap();
    let mut changed = request;
    changed.accepted_device_possession_proof.holder_jkt = "A".repeat(43);
    assert!(verify_recovery_completion_holder(&changed, &method(&kat), &candidate(&kat)).is_err());
}
