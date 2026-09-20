use arkret_schema::sdk_conformance::{
    SdkConformanceClaim, SdkConformanceClaimError, SdkConformanceContract,
};
use arkret_signatures::{PublicKeyMaterial, verify_detached_ed25519_signature};
use serde_json::Value;

fn artifacts_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec/spec/v1/artifacts")
}

fn contract() -> SdkConformanceContract {
    let artifacts = artifacts_root();
    let profiles: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("profiles/conformance-profiles.json")).unwrap(),
    )
    .unwrap();
    let registry: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("registry/vector-registry.json")).unwrap(),
    )
    .unwrap();
    let active = registry["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["status"] == "active")
        .map(|row| row["vector_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    SdkConformanceContract::from_value(&profiles["sdk_conformance_contract"], active).unwrap()
}

fn verify_claim_signature(
    _: &arkret_schema::sdk_conformance::SdkClaimIssuer,
    proof: &arkret_schema::sdk_conformance::SdkConformanceProof,
    signing_bytes: &[u8],
) -> bool {
    let Some(multibase) = proof
        .kid
        .split('#')
        .next()
        .and_then(|did| did.strip_prefix("did:key:"))
    else {
        return false;
    };
    verify_detached_ed25519_signature(
        &PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        signing_bytes,
        &proof.signature,
    )
}

#[test]
fn published_claim_fixture_uses_real_signature_and_distinct_negative_failures() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts_root().join("fixtures/sdk-conformance-claim-fixture.json"))
            .unwrap(),
    )
    .unwrap();
    let contract = contract();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();

    for (name, expected) in [
        ("valid_signed_artifact_bound_claim", "accept"),
        ("bad_signature_semantic_rejected", "signature_invalid"),
        (
            "wrong_contract_binding_semantic_rejected",
            "governance_binding_mismatch",
        ),
    ] {
        let case = cases.iter().find(|case| case["name"] == name).unwrap();
        let claim: SdkConformanceClaim = serde_json::from_value(case["instance"].clone()).unwrap();
        let result = claim.validate_against_contract(
            &contract,
            &claim.sdk_artifact.digest,
            &claim.spec_revision,
            verify_claim_signature,
        );
        match expected {
            "accept" => result.unwrap(),
            "signature_invalid" => {
                assert_eq!(
                    result.unwrap_err(),
                    SdkConformanceClaimError::SignatureInvalid
                )
            }
            "governance_binding_mismatch" => assert!(matches!(
                result,
                Err(SdkConformanceClaimError::BindingMismatch(_))
            )),
            _ => unreachable!(),
        }
    }
}
