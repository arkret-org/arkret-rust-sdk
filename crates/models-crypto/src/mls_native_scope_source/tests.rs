//! Standard packaged Spec vectors only: no native keeper/current claim.
use super::*;

fn fixture() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/mls-native-scope-source-fixture.json")
        .unwrap()
}

fn pair() -> (
    MlsNativeScopeSourceRequestBody,
    MlsNativeScopeSourceResponseBody,
) {
    let data = fixture();
    (
        serde_json::from_value(data["case"]["request"].clone()).unwrap(),
        serde_json::from_value(data["case"]["response"].clone()).unwrap(),
    )
}

#[test]
fn native_source_standard_pair_matches_the_only_signing_preimage() {
    let (request, response) = pair();
    request.validate().unwrap();
    response.validate_for_request(&request).unwrap();
    let expected = hex::decode(fixture()["case"]["signing_bytes_hex"].as_str().unwrap()).unwrap();
    assert_eq!(response.signing_bytes(&request).unwrap(), expected);
    assert_eq!(
        mls_native_scope_source_signing_bytes(&request, &response.qualification).unwrap(),
        expected
    );
}

#[test]
fn native_source_boolean_vector_refuses_numeric_zero_one_and_null() {
    for value in [
        serde_json::json!(0),
        serde_json::json!(1),
        serde_json::Value::Null,
    ] {
        let mut data = fixture()["case"]["response"].clone();
        data["qualification"]["desired_qualifications"][1] = value;
        assert!(serde_json::from_value::<MlsNativeScopeSourceResponseBody>(data).is_err());
    }
}

#[test]
fn native_source_closed_selector_and_response_have_no_alias_fields() {
    let mut data = fixture()["case"]["request"].clone();
    data["endpoint_sources"][0]["claim_id"] =
        serde_json::json!("ak:keypackage_claim:019a0000-0000-7000-8000-000000000001");
    assert!(serde_json::from_value::<MlsNativeScopeSourceRequestBody>(data).is_err());
    let mut data = fixture()["case"]["response"].clone();
    data["source_id"] = fixture()["case"]["request"]["source_id"].clone();
    assert!(serde_json::from_value::<MlsNativeScopeSourceResponseBody>(data).is_err());
}

#[test]
fn native_source_candidate_length_and_immutable_create_retype_are_checked() {
    let (mut request, mut response) = pair();
    response
        .qualification
        .desired_qualifications
        .as_mut()
        .unwrap()
        .pop();
    assert!(response.validate_for_request(&request).is_err());
    request
        .sidecar_membership_basis
        .as_mut()
        .unwrap()
        .sidecar_create_event_ref = request.genesis_event_ref.clone().unwrap();
    assert!(request.validate().is_err());
}

#[test]
fn native_source_authorization_bit_never_echoes_an_endpoint() {
    let (request, mut response) = pair();
    let endpoint = serde_json::from_value::<ContentEndpoint>(
        fixture()["case"]["qualified_endpoint_context_not_H_leaf_attestation"].clone(),
    )
    .unwrap();
    response.qualification.endpoint_qualifications[0] =
        MlsNativeScopeEndpointQualification::Qualified {
            endpoint: Some(Box::new(endpoint)),
            keypackage_ref: None,
        };
    assert!(response.validate_for_request(&request).is_err());
}

#[test]
fn native_source_boolean_positions_project_the_original_desired_principals() {
    let (request, response) = pair();
    let expected = request
        .sidecar_membership_basis
        .as_ref()
        .unwrap()
        .candidate_joins[0]
        .agent_actor_id
        .signing_principal_id()
        .clone();
    assert_eq!(
        response
            .qualification
            .desired_agent_ids_for(&request)
            .unwrap(),
        Some(vec![expected])
    );
}

#[test]
fn native_source_duplicate_endpoint_selectors_are_refused() {
    let (mut request, _) = pair();
    request
        .endpoint_sources
        .push(request.endpoint_sources[0].clone());
    assert!(request.validate().is_err());
}

#[test]
fn native_scope_basis_fixtures_match_the_only_registered_projection() {
    let cases = fixture()["basis_cases"].clone();
    for name in ["before", "installed_empty_fence", "controller_rejoin"] {
        let basis: MlsNativeScopeBasis = serde_json::from_value(cases[name].clone()).unwrap();
        let expected = cases[format!("{name}_digest")].as_str().unwrap();
        assert_eq!(basis.digest().unwrap().as_str(), expected);
        assert_eq!(
            serde_json::to_value(basis.canonicalized().unwrap()).unwrap(),
            cases[name]
        );
    }
}

#[test]
fn native_scope_installed_projection_reuses_original_i_without_leaf_keys() {
    // Only original I primitive coordinates are exercised here; the mutated
    // attestation is not presented as a new valid H signature/native source.
    let cases = fixture()["basis_cases"].clone();
    let input = &cases["first_source_intent_only_not_native_proof"]["attestation"];
    let history =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let mut original: crate::ContentRecoveryScopeCleanupAuthorization =
        serde_json::from_value(history["scope_retirement"]["authorization"].clone()).unwrap();
    original.replacement = serde_json::from_value(input["replacement"].clone()).unwrap();
    original.inventory_digest = serde_json::from_value(input["inventory_digest"].clone()).unwrap();
    original.inventory_entry = serde_json::from_value(input["inventory_entry"].clone()).unwrap();
    original.nonce_base64url = input["nonce_base64url"].as_str().unwrap().to_owned();
    let expected: MlsNativeScopeFenceBasisEntry =
        serde_json::from_value(cases["installed_first_source_I_projection"].clone()).unwrap();
    let endpoints: Vec<ContentEndpoint> = expected
        .covered_authorizations
        .iter()
        .map(|covered| ContentEndpoint {
            actor_id: covered.actor_id.clone(),
            endpoint: covered.endpoint.clone(),
            authorization_event_ref: covered.authorization_event_ref.clone(),
            signature_key_base64url: arkret_canonical::base64url_encode(&[19; 32]),
        })
        .collect();
    let mut duplicate_key_context = endpoints.clone();
    for endpoint in &endpoints {
        let mut other_key = endpoint.clone();
        other_key.signature_key_base64url = arkret_canonical::base64url_encode(&[20; 32]);
        duplicate_key_context.push(other_key);
    }
    assert_eq!(
        MlsNativeScopeFenceBasisEntry::from_installed_source(&original, &duplicate_key_context)
            .unwrap(),
        expected
    );
    assert!(
        MlsNativeScopeFenceBasisEntry::from_installed_source(&original, &[])
            .unwrap()
            .covered_authorizations
            .is_empty()
    );
}

#[test]
fn native_scope_basis_refuses_duplicated_intent_and_wrong_create_coordinates() {
    let cases = fixture()["basis_cases"].clone();
    let mut basis: MlsNativeScopeBasis =
        serde_json::from_value(cases["installed_empty_fence"].clone()).unwrap();
    basis.endpoint_fences.push(basis.endpoint_fences[0].clone());
    assert!(basis.digest().is_err());
    let mut basis: MlsNativeScopeBasis = serde_json::from_value(cases["before"].clone()).unwrap();
    basis
        .sidecar_membership_basis
        .as_mut()
        .unwrap()
        .sidecar_create_event_ref = basis.genesis_event_ref.clone().unwrap();
    assert!(basis.digest().is_err());
}
