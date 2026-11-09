//! Frozen Source signing bytes; no native issuer or storage claim.
use arkret_models_crypto::{ContentBackupSourceAttestation, ContentBackupSourceDraft};
use arkret_schema_conformance::spec_json_artifact;
use ed25519_dalek::{Signer as _, SigningKey};

fn cases() -> Vec<serde_json::Value> {
    spec_json_artifact("fixtures/content-backup-source-fixture.json").unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn unsigned_source_draft_matches_independent_human_agent_known_answers() {
    for case in cases() {
        let expected: ContentBackupSourceAttestation =
            serde_json::from_value(case["attestation"].clone()).unwrap();
        let draft = ContentBackupSourceDraft::from(&expected);
        let bytes = draft.signing_payload_bytes().unwrap();
        assert_eq!(hex::encode(&bytes), case["signing_hex"].as_str().unwrap());
        let seed: [u8; 32] = hex::decode(case["service_signing_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut signature = expected.signature.clone();
        signature.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&seed).sign(&bytes).to_bytes(),
            ))
            .unwrap();
        let actual = draft.into_attestation(signature).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.signing_payload_bytes().unwrap(), bytes);
    }
}

#[test]
fn unsigned_source_refuses_invalid_window_before_any_signature_exists() {
    for case in cases() {
        let expected: ContentBackupSourceAttestation =
            serde_json::from_value(case["attestation"].clone()).unwrap();
        let mut draft = ContentBackupSourceDraft::from(&expected);
        draft.expires_at = draft.attested_at;
        assert!(draft.signing_payload_bytes().is_err());
        draft.expires_at = draft.attested_at + chrono::Duration::seconds(301);
        assert!(draft.signing_payload_bytes().is_err());
    }
}

#[test]
fn actual_signature_must_use_the_drafts_service_method() {
    for case in cases() {
        let expected: ContentBackupSourceAttestation =
            serde_json::from_value(case["attestation"].clone()).unwrap();
        let draft = ContentBackupSourceDraft::from(&expected);
        let mut signature = expected.signature;
        signature.kid = arkret_wire::NonEmptyString::new("did:web:wrong.example#key").unwrap();
        assert!(draft.into_attestation(signature).is_err());
    }
}
