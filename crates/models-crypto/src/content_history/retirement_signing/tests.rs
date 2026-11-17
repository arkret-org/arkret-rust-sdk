//! Published byte vectors; no native scope state or terminal eligibility claim.
use super::*;

fn fixture() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json").unwrap()
        ["scope_retirement"]
        .clone()
}

#[test]
fn unsigned_retirement_variants_preserve_original_exact_bytes_and_fields() {
    let fixture = fixture();
    for state in ["removed", "terminated"] {
        let full = fixture["results"][state]["retirement_proof"].clone();
        let proof: ContentScopeRetirementProof = serde_json::from_value(full.clone()).unwrap();
        let unsigned = ContentScopeRetirementProofUnsigned::from(&proof);
        let mut expected = full;
        expected.as_object_mut().unwrap().remove("signature");
        assert_eq!(serde_json::to_value(&unsigned).unwrap(), expected);
        assert_eq!(
            unsigned.signing_bytes().unwrap(),
            hex::decode(fixture[format!("{state}_signing_hex")].as_str().unwrap()).unwrap()
        );
        let (ContentScopeRetirementProof::Removed { signature, .. }
        | ContentScopeRetirementProof::Terminated { signature, .. }) = &proof;
        assert_eq!(unsigned.with_signature(signature.clone()).unwrap(), proof);
    }
}

#[test]
fn unsigned_delivery_preserves_original_exact_bytes_and_fields() {
    let fixture = fixture();
    for state in ["removed", "terminated"] {
        let full = fixture["deliveries"][state]["delivery_attestation"].clone();
        let delivery: ContentScopeRetirementDeliveryAttestation =
            serde_json::from_value(full.clone()).unwrap();
        let unsigned = ContentScopeRetirementDeliveryUnsigned::from(&delivery);
        let mut expected = full;
        expected.as_object_mut().unwrap().remove("signature");
        assert_eq!(serde_json::to_value(&unsigned).unwrap(), expected);
        if state == "removed" {
            assert_eq!(
                unsigned.signing_bytes().unwrap(),
                hex::decode(fixture["delivery_signing_hex"].as_str().unwrap()).unwrap()
            );
        }
        assert_eq!(
            unsigned.with_signature(delivery.signature.clone()).unwrap(),
            delivery
        );
    }
}

#[test]
fn unsigned_retirement_keeps_the_original_shape_refusals_after_signing() {
    let fixture = fixture();
    let proof: ContentScopeRetirementProof =
        serde_json::from_value(fixture["results"]["removed"]["retirement_proof"].clone()).unwrap();
    let ContentScopeRetirementProof::Removed { signature, .. } = &proof else {
        panic!("removed vector")
    };
    let mut unsigned = ContentScopeRetirementProofUnsigned::from(&proof);
    if let ContentScopeRetirementProofUnsigned::Removed {
        remaining_old_leaf_count,
        ..
    } = &mut unsigned
    {
        *remaining_old_leaf_count = 1;
    }
    assert!(unsigned.with_signature(signature.clone()).is_err());
    let delivery: ContentScopeRetirementDeliveryAttestation =
        serde_json::from_value(fixture["deliveries"]["removed"]["delivery_attestation"].clone())
            .unwrap();
    let mut unsigned = ContentScopeRetirementDeliveryUnsigned::from(&delivery);
    unsigned.expires_at = unsigned.attested_at;
    assert!(unsigned.with_signature(delivery.signature.clone()).is_err());
}
