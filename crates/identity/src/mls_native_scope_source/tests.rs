//! Real H method-native Service history/signatures; no G/native role assertion.
use super::*;

fn pair() -> (
    MlsNativeScopeSourceRequestBody,
    MlsNativeScopeSourceResponseBody,
    AuthenticatedServiceResolution,
) {
    let data = arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-native-scope-source-fixture.json",
    )
    .unwrap();
    let mut request: MlsNativeScopeSourceRequestBody =
        serde_json::from_value(data["case"]["request"].clone()).unwrap();
    let mut response: MlsNativeScopeSourceResponseBody =
        serde_json::from_value(data["case"]["response"].clone()).unwrap();
    let native = crate::content_scope_cleanup::original_cleanup_source_for_delivery_test(
        response.qualification.issued_at,
    );
    request.destination_id = native.origin_resolution.service_id.clone();
    let basis = request.sidecar_membership_basis.as_mut().unwrap();
    basis.controller_account_id.station_id = request.destination_id.clone();
    for join in &mut basis.candidate_joins {
        let account = join.agent_actor_id.as_account_id().unwrap();
        join.agent_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            account.principal_id.clone(),
            request.destination_id.clone(),
        ));
    }
    response.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[173; 32],
        native.attestation.verification_method.as_str(),
        &response.signing_bytes(&request).unwrap(),
    )
    .unwrap();
    (request, response, native.origin_resolution)
}

#[test]
fn native_scope_source_verifies_real_h_history_and_exact_query_signature() {
    let (request, response, resolution) = pair();
    let now = response.qualification.issued_at;
    verify_mls_native_scope_source_pair(
        &request,
        &response,
        &request,
        &resolution,
        now,
        response.qualification.expires_at,
    )
    .unwrap();
    let cold: MlsNativeScopeSourceResponseBody =
        serde_json::from_slice(&arkret_canonical::canonical_json_bytes(&response).unwrap())
            .unwrap();
    assert_eq!(response, cold);
    verify_mls_native_scope_source_pair(
        &request,
        &cold,
        &request,
        &resolution,
        now,
        response.qualification.expires_at,
    )
    .unwrap();
}

#[test]
fn native_scope_source_changed_expected_basis_challenge_and_deadline_reject() {
    let (request, response, resolution) = pair();
    let now = response.qualification.issued_at;
    let mut changed = request.clone();
    changed.g_basis_digest = arkret_wire::Hash::new(format!("sha256:{}", "a1".repeat(32))).unwrap();
    assert!(
        verify_mls_native_scope_source_pair(
            &request,
            &response,
            &changed,
            &resolution,
            now,
            response.qualification.expires_at
        )
        .is_err()
    );
    changed = request.clone();
    changed.query_nonce_base64url =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(&[17; 32])).unwrap();
    assert!(
        verify_mls_native_scope_source_pair(
            &changed,
            &response,
            &changed,
            &resolution,
            now,
            response.qualification.expires_at
        )
        .is_err()
    );
    assert!(
        verify_mls_native_scope_source_pair(
            &request,
            &response,
            &request,
            &resolution,
            response.qualification.expires_at,
            response.qualification.expires_at
        )
        .is_err()
    );
    assert!(
        verify_mls_native_scope_source_pair(&request, &response, &request, &resolution, now, now)
            .is_err()
    );
}
