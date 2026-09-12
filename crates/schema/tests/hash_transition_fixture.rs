use arkret_canonical::{DigestSuite, canonical_json_bytes, digest, digest_bytes_from_slices};
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::EventId;
use serde_json::Value;

fn assert_seal_commit(value: &Value, suite: DigestSuite) {
    let body_bytes = canonical_bytes(value, "seal_body_canonical_bytes_utf8");
    let seal_digest = digest(suite, &body_bytes);
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    let transcript = serde_json::json!({
        "context": "ak.seal.commit.v1",
        "seal_digest": seal_digest,
        "configuration_ref": body["configuration_ref"],
        "notary_seq": body["notary_seq"],
        "view": 0,
    });
    assert_eq!(
        digest(suite, canonical_json_bytes(&transcript).unwrap()),
        value["notary_signature_payload_digest"].as_str().unwrap()
    );
    assert_eq!(
        format!("ak:seal:{seal_digest}"),
        value["seal_id"].as_str().unwrap()
    );
}

fn canonical_bytes(value: &Value, field: &str) -> Vec<u8> {
    let bytes = value[field].as_str().unwrap().as_bytes().to_vec();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(canonical_json_bytes(&parsed).unwrap(), bytes);
    bytes
}

fn assert_sha256(value: &Value, bytes_field: &str, digest_field: &str) {
    assert_eq!(
        digest(DigestSuite::Sha256, canonical_bytes(value, bytes_field)),
        value[digest_field].as_str().unwrap()
    );
}

fn assert_receipt(receipt: &Value) {
    let bytes_preimage =
        hex::decode(receipt["bytes_digest_preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        digest(DigestSuite::Sha256, bytes_preimage),
        receipt["bytes_digest"].as_str().unwrap()
    );
    assert_sha256(
        receipt,
        "receipt_core_canonical_bytes_utf8",
        "signature_payload_digest",
    );
    assert_sha256(receipt, "receipt_canonical_bytes_utf8", "receipt_digest");
    canonical_bytes(receipt, "accepted_event_canonical_bytes_utf8");
    canonical_bytes(receipt, "signature_transcript_canonical_bytes_utf8");
}

fn assert_event_id(digest_wire: &str, expected_id: &str, suite: DigestSuite) {
    let raw: [u8; 32] = hex::decode(digest_wire.split_once(':').unwrap().1)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(EventId::from_digest(suite, raw).as_str(), expected_id);
}

#[test]
fn hash_transition_fixture_authenticates_genesis_and_transition_bytes() {
    let fixture = spec_json_artifact("fixtures/hash-transition-fixture.json").unwrap();
    let genesis = &fixture["cases"][0];
    assert_sha256(
        genesis,
        "create_event_digest_preimage_canonical_bytes_utf8",
        "create_event_digest",
    );
    assert_event_id(
        genesis["create_event_digest"].as_str().unwrap(),
        genesis["create_event_id"].as_str().unwrap(),
        DigestSuite::Sha256,
    );
    assert_eq!(
        genesis["genesis_availability_receipt_digests"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "genesis has no predecessor availability authority"
    );
    assert_eq!(
        genesis["genesis_availability_negative_mutation"]
            .as_str()
            .unwrap(),
        "non_empty_receipt_commitment"
    );
    assert_eq!(
        digest(
            DigestSuite::Blake3,
            hex::decode(genesis["state_leaf_preimage_hex"].as_str().unwrap()).unwrap(),
        ),
        genesis["state_root"].as_str().unwrap()
    );
    assert_eq!(
        digest(
            DigestSuite::Blake3,
            hex::decode(genesis["control_event_leaf_preimage_hex"].as_str().unwrap()).unwrap(),
        ),
        genesis["control_event_set_root"].as_str().unwrap()
    );
    assert_seal_commit(genesis, DigestSuite::Blake3);

    let transition = &fixture["cases"][1];
    assert_sha256(
        transition,
        "snapshot_canonical_bytes_utf8",
        "realm_state_snapshot_commitment",
    );
    assert_sha256(
        transition,
        "transition_event_digest_preimage_canonical_bytes_utf8",
        "transition_event_digest",
    );
    assert_event_id(
        transition["transition_event_digest"].as_str().unwrap(),
        transition["transition_event_id"].as_str().unwrap(),
        DigestSuite::Sha256,
    );
    assert_receipt(&transition["transition_availability_receipt"]);
    assert_eq!(
        digest(
            DigestSuite::Sha256,
            hex::decode(
                transition["previous_state_leaf_preimage_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        ),
        transition["previous_state_root"].as_str().unwrap()
    );
    assert_eq!(
        digest(
            DigestSuite::Blake3,
            hex::decode(transition["next_state_leaf_preimage_hex"].as_str().unwrap()).unwrap(),
        ),
        transition["state_root"].as_str().unwrap()
    );

    let leaves = transition["control_event_leaf_preimages_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            digest_bytes_from_slices(
                DigestSuite::Blake3,
                &[&hex::decode(value.as_str().unwrap()).unwrap()],
            )
        })
        .collect::<Vec<_>>();
    let root = digest(
        DigestSuite::Blake3,
        [&[1][..], &leaves[0], &leaves[1]].concat(),
    );
    assert_eq!(root, transition["control_event_set_root"].as_str().unwrap());
    assert_seal_commit(transition, DigestSuite::Blake3);
    assert_eq!(
        digest(
            DigestSuite::Blake3,
            canonical_bytes(
                transition,
                "successor_event_digest_preimage_canonical_bytes_utf8",
            ),
        ),
        transition["successor_event_digest"].as_str().unwrap()
    );
    assert_event_id(
        transition["successor_event_digest"].as_str().unwrap(),
        transition["successor_event_id"].as_str().unwrap(),
        DigestSuite::Blake3,
    );
}
