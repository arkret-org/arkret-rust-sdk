use arkret_models_collaboration::objects::profiles::IdentityLink;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/identity-link-kat.json")).unwrap()
}

#[test]
fn historical_identity_link_matches_independent_signed_transcript() {
    let vector = vector();
    let link: IdentityLink = serde_json::from_value(vector["link"].clone()).unwrap();
    let registry = arkret_schema_conformance::schema_registry_from_spec_artifacts(
        arkret_schema_conformance::default_spec_artifacts_dir().unwrap(),
    )
    .unwrap();
    registry
        .validate_value(IdentityLink::SCHEMA, &vector["link"])
        .unwrap();
    let input = link.canonical_proof_input().unwrap();
    assert_eq!(input, vector["preimage_utf8"].as_str().unwrap().as_bytes());
    assert_eq!(
        link.canonical_payload_digest().unwrap().as_str(),
        vector["digest"]
    );
    link.validate_minimal().unwrap();
    let public = arkret_canonical::base64url_decode(
        link.response_signing_public_key_base64url
            .as_str()
            .as_bytes(),
    )
    .unwrap();
    let signature = arkret_canonical::base64url_decode(link.proof.signature.as_bytes()).unwrap();
    let public = VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    public.verify_strict(&input, &signature).unwrap();
    let mut wrong_domain = input;
    wrong_domain[3] ^= 1;
    assert!(public.verify_strict(&wrong_domain, &signature).is_err());
}

#[test]
fn historical_identity_link_preserves_required_presence_and_optional_absence() {
    let link = vector()["link"].clone();
    for field in ["schema", "status", "pairwise_id", "proof"] {
        let mut absent = link.clone();
        absent.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<IdentityLink>(absent).is_err(),
            "{field}"
        );
    }
    for field in [
        "strand_id",
        "track_name",
        "mls_group_id",
        "expires_at",
        "disclosure_policy_id",
    ] {
        let mut null = link.clone();
        null[field] = Value::Null;
        assert!(
            serde_json::from_value::<IdentityLink>(null).is_err(),
            "{field}"
        );
    }
    let parsed: IdentityLink = serde_json::from_value(link.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), link);
}
