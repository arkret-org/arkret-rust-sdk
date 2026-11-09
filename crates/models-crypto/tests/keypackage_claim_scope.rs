//! Target binding and signature tests, not native membership or census proofs.

use arkret_models_crypto::{
    KeyPackagesClaimRequestBody, PeerKeyPackageClaimPurpose, PeerKeyPackageClaimShapeError,
    PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimFields,
    keypackage_claim_authorization_signing_bytes,
};
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::{Hash, MlsGroupId, RealmId, ScopeRef, StrandId};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Value, json};

fn fixture() -> Value {
    spec_json_artifact("fixtures/mimi-key-material-claim-fixture.json").unwrap()
}

fn request() -> KeyPackagesClaimRequestBody {
    serde_json::from_value(fixture()["request"].clone()).unwrap()
}

fn scopes(realm: &RealmId) -> Vec<ScopeRef> {
    vec![
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::new(realm.as_str().replacen(
                "ak:realm:",
                "ak:circle:",
                1,
            ))
            .unwrap(),
        },
        ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: arkret_wire::SidecarId::new(realm.as_str().replacen(
                "ak:realm:",
                "ak:sidecar:",
                1,
            ))
            .unwrap(),
        },
    ]
}

#[test]
fn original_formal_signature_binds_complete_scope_and_cannot_be_retargeted() {
    let f = fixture();
    let mut request = request();
    request.validate_shape().unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), f["request"]);
    let fields = request.unsigned_request();
    assert_eq!(
        serde_json::to_value(&fields).unwrap(),
        f["outcome"]["claim_outcome"]["claim_receipt"]["request"]
    );
    let public: [u8; 32] =
        arkret_canonical::base64url_decode(f["participant_public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let key = VerifyingKey::from_bytes(&public).unwrap();
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &request.requester_authorization
    else {
        panic!("formal fixture is a Device participant");
    };
    let signature = Signature::from_slice(
        &arkret_canonical::base64url_decode(signature.signature.as_str()).unwrap(),
    )
    .unwrap();
    let input = keypackage_claim_authorization_signing_bytes(
        &fields,
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    key.verify(&input, &signature).unwrap();
    request.effective_scope = scopes(&request.intended_realm_id).remove(1);
    request.mls_group_id = request.effective_scope.canonical_mls_group_id().unwrap();
    request.validate_shape().unwrap();
    let retargeted = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    assert_ne!(input, retargeted);
    assert!(key.verify(&retargeted, &signature).is_err());
}

#[test]
fn all_executable_scope_kinds_survive_the_unsigned_projection_without_defaulting() {
    let mut request = request();
    let mut groups = std::collections::BTreeSet::new();
    for scope in scopes(&request.intended_realm_id) {
        request.mls_group_id = scope.canonical_mls_group_id().unwrap();
        request.effective_scope = scope.clone();
        request.validate_shape().unwrap();
        let fields = request.unsigned_request();
        fields.validate_shape().unwrap();
        assert_eq!(fields.effective_scope, scope);
        groups.insert(request.mls_group_id.to_string());
    }
    assert_eq!(groups.len(), 3);
}

#[test]
fn wrong_realm_group_and_non_executable_scope_fail_before_claim_authoring() {
    let original = request();
    let mut bad_realm = original.clone();
    bad_realm.intended_realm_id =
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    assert_ne!(bad_realm.intended_realm_id, original.intended_realm_id);
    let mut bad_group = original.clone();
    bad_group.mls_group_id = MlsGroupId::new("A".repeat(43)).unwrap();
    let mut non_executable = original;
    non_executable.effective_scope = ScopeRef::RealmGenesis;
    for changed in [bad_realm, bad_group, non_executable] {
        assert_eq!(
            changed.validate_shape(),
            Err(PeerKeyPackageClaimShapeError::InvalidEffectiveScope)
        );
        assert!(
            keypackage_claim_authorization_signing_bytes(
                &changed.unsigned_request(),
                &changed.service_binding,
                &changed.requester_authorization
            )
            .is_err()
        );
    }
}

#[test]
fn direct_claim_is_bound_to_its_original_realm_and_rejects_subscope_rebinding() {
    let mut request = request();
    request.claim_purpose = PeerKeyPackageClaimPurpose::DirectConversation;
    request.strand_id = Some(
        StrandId::new(
            request
                .intended_realm_id
                .as_str()
                .replacen("ak:realm:", "ak:strand:", 1),
        )
        .unwrap(),
    );
    request.pair_key = Some(Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap());
    request.last_resort_allowed = Some(false);
    request.validate_shape().unwrap();
    for scope in scopes(&request.intended_realm_id).into_iter().skip(1) {
        request.mls_group_id = scope.canonical_mls_group_id().unwrap();
        request.effective_scope = scope;
        assert_eq!(
            request.validate_shape(),
            Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields)
        );
    }
}

#[test]
fn both_carriers_reject_missing_null_or_renamed_scope() {
    let f = fixture();
    for unsigned in [false, true] {
        let original = if unsigned {
            &f["outcome"]["claim_outcome"]["claim_receipt"]["request"]
        } else {
            &f["request"]
        };
        let scope = original["effective_scope"].clone();
        for renamed in [None, Some("effective_scope"), Some("scope")] {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove("effective_scope");
            if let Some(name) = renamed {
                changed[name] = if name == "scope" {
                    scope.clone()
                } else {
                    json!(null)
                };
            }
            if unsigned {
                assert!(serde_json::from_value::<PeerKeyPackagesClaimFields>(changed).is_err());
            } else {
                assert!(serde_json::from_value::<KeyPackagesClaimRequestBody>(changed).is_err());
            }
        }
    }
}

#[test]
fn realm_actor_target_and_requester_keep_their_realm_or_circle_scope_ceiling() {
    let f = spec_json_artifact("fixtures/realm-actor-signature-kat-fixture.json").unwrap();
    let target: PeerKeyPackagesClaimFields =
        serde_json::from_value(f["mls_claim_handoff"]["claim_receipt"]["request"].clone()).unwrap();
    target.validate_shape().unwrap();
    let mut requester = target.clone();
    requester.requester_account_id = None;
    requester.requester_actor_id = requester.target_actor_id.take();
    requester.target_account_id = request().target_account_id;
    for mut fields in [target, requester] {
        for scope in scopes(&fields.intended_realm_id) {
            fields.mls_group_id = scope.canonical_mls_group_id().unwrap();
            fields.effective_scope = scope.clone();
            if matches!(scope, ScopeRef::Sidecar { .. }) {
                assert_eq!(
                    fields.validate_shape(),
                    Err(PeerKeyPackageClaimShapeError::InvalidAuthorizationModel)
                );
            } else {
                fields.validate_shape().unwrap();
            }
        }
    }
}
