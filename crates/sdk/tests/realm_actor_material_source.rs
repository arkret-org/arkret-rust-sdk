//! Same-cut private current sources and their signed material boundary.
use arkret::*;
use arkret_signatures::PublicKeyMaterial;
use serde_json::{Value, json};

fn fixture() -> (Value, PublicKeyMaterial) {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-signature-kat-fixture.json"),
    ).unwrap()).unwrap();
    let case = &fixture["cases"][3];
    let mut value = case["unsigned_projection"].clone();
    value["signature"] = case["signature"].clone();
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: base64url_decode(case["public_key_b64u"].as_str().unwrap()).unwrap(),
    };
    (value, key)
}

#[test]
fn private_current_source_is_required_and_matches_exact_row_cut() {
    let (value, _) = fixture();
    let valid: RealmActorMaterialOutcome = serde_json::from_value(value.clone()).unwrap();
    valid.validate().unwrap();
    let mut missing = value.clone();
    missing["result"]["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_ref");
    assert!(serde_json::from_value::<RealmActorMaterialOutcome>(missing).is_err());
    let stream = value["result"]["entries"][0]["source_ref"]["stream_ref"].clone();
    for (field, replacement) in [
        ("commit_id", json!(RealmCommitId::from_digest([91; 32]))),
        ("stream_position", json!(1)),
        (
            "stream_ref",
            json!({"kind":"realm","realm_id":stream["realm_id"]}),
        ),
    ] {
        let mut changed = value.clone();
        changed["result"]["entries"][0]["source_ref"][field] = replacement;
        let changed: RealmActorMaterialOutcome = serde_json::from_value(changed).unwrap();
        assert!(
            changed.validate().is_err(),
            "source mismatch accepted: {field}"
        );
    }
    let mut later_head = value;
    later_head["control_stream_head"]["stream_position"] = json!(7);
    later_head["control_stream_head"]["commit_id"] = json!(RealmCommitId::from_digest([92; 32]));
    let later: RealmActorMaterialOutcome = serde_json::from_value(later_head).unwrap();
    later.validate().unwrap();
}

#[test]
fn event_identity_in_private_current_source_is_covered_by_material_signature() {
    let (value, key) = fixture();
    let verify = |value: Value| {
        let material: RealmActorMaterialOutcome = serde_json::from_value(value).unwrap();
        verify_detached_object_signature(
            &material.signature,
            &arkret_canonical::canonical::unsigned_value(&material, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmActorMaterial,
            &key,
        )
    };
    verify(value.clone()).unwrap();
    let mut changed = value;
    changed["result"]["entries"][0]["source_ref"]["event_id"] =
        json!(EventId::from_digest(DigestSuite::Sha256, [93; 32]));
    assert!(verify(changed).is_err());
}
