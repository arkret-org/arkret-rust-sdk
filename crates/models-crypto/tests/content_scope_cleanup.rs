use arkret_canonical::{canonical_json_bytes, sha256_digest};
use arkret_models_crypto::{
    ContentCleanupInventory, ContentRecoveryInventory, ContentScopeCleanup,
};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::{Value, json};

fn fixture() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json").unwrap()
}

fn inventory_digest(inventory: &ContentRecoveryInventory) -> arkret_wire::Hash {
    let mut bytes = b"ak.content.recovery_inventory.v1\n".to_vec();
    bytes.extend(canonical_json_bytes(inventory).unwrap());
    arkret_wire::Hash::new(sha256_digest(bytes)).unwrap()
}

fn validate(f: &Value, result: &Value) -> arkret_wire::Result<()> {
    // This exercises codec/binding only, not Native authority, migration
    // qualification, governor signatures or a durable removal transaction.
    let inventory: ContentRecoveryInventory =
        serde_json::from_value(f["scope_retirement"]["inventory"].clone()).unwrap();
    ContentCleanupInventory {
        inventory_digest: inventory_digest(&inventory),
        scope_cleanups: vec![serde_json::from_value(result.clone()).unwrap()],
    }
    .validate_for_inventory(&inventory, &inventory_digest(&inventory))
}

#[test]
fn formal_retirement_codec_preserves_the_original_bytes_and_closed_states() {
    let f = fixture();
    for state in ["removed", "terminated"] {
        let original = &f["scope_retirement"]["results"][state];
        let result: ContentScopeCleanup = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(
            canonical_json_bytes(&result).unwrap(),
            canonical_json_bytes(original).unwrap()
        );
        assert!(original["retirement_proof"]["epoch"].is_string());
        validate(&f, original).unwrap();
        for member in ["winning_commit", "root_refs", "backup_refs"] {
            let mut disclosed = original.clone();
            disclosed[member] = json!([]);
            assert!(serde_json::from_value::<ContentScopeCleanup>(disclosed).is_err());
        }
        let mut wrong_epoch = original.clone();
        wrong_epoch["retirement_proof"]["epoch"] = json!(0);
        assert!(serde_json::from_value::<ContentScopeCleanup>(wrong_epoch).is_err());
    }
    let mut mixed = f["scope_retirement"]["results"]["terminated"].clone();
    mixed["retirement_proof"]["remaining_old_leaf_count"] = json!(0);
    assert!(serde_json::from_value::<ContentScopeCleanup>(mixed).is_err());
}

#[test]
fn retirement_binding_rejects_cross_subject_scope_state_and_inventory_substitution() {
    let f = fixture();
    let original = &f["scope_retirement"]["results"]["removed"];
    for pointer in [
        "/retirement_proof/inventory_digest",
        "/retirement_proof/inventory_entry_digest",
        "/retirement_proof/nonce_base64url",
        "/retirement_proof/remaining_old_leaf_count",
        "/retirement_proof/replacement/signature_key_base64url",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = match pointer {
            "/retirement_proof/nonce_base64url" => json!("AA"),
            "/retirement_proof/remaining_old_leaf_count" => json!(1),
            "/retirement_proof/replacement/signature_key_base64url" => {
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            }
            _ => json!(format!("sha256:{}", "09".repeat(32))),
        };
        assert!(validate(&f, &changed).is_err(), "{pointer}");
    }
    let mut changed = original.clone();
    changed["state"] = json!("terminated");
    assert!(validate(&f, &changed).is_err());
    let mut changed = original.clone();
    changed["genesis_event_ref"] = json!(arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [91; 32],
    ));
    assert!(validate(&f, &changed).is_err());
}

#[test]
fn rekeyed_result_requires_zero_old_leaves_and_nonempty_unique_references() {
    let f = fixture();
    let retired = &f["scope_retirement"]["results"]["removed"];
    let original = json!({
        "state":"rekeyed", "effective_scope":retired["effective_scope"],
        "genesis_event_ref":retired["genesis_event_ref"],
        "winning_commit":retired["retirement_proof"]["scope_cut"],
        "remaining_old_leaf_count":0,
        "root_refs":[f["kat"]["content_context"]["root_ref"]],
        "backup_refs":f["kat"]["envelope"]["encryption_context"]["protection"]["backup_refs"],
    });
    validate(&f, &original).unwrap();
    for field in ["root_refs", "backup_refs"] {
        let mut changed = original.clone();
        changed[field] = json!([]);
        assert!(validate(&f, &changed).is_err());
        changed[field] = json!([original[field][0], original[field][0]]);
        assert!(validate(&f, &changed).is_err());
    }
    let mut changed = original;
    changed["remaining_old_leaf_count"] = json!(1);
    assert!(validate(&f, &changed).is_err());
}

#[test]
fn formal_cleanup_signing_domains_and_two_projection_roles_remain_separate() {
    use arkret_models_crypto::{
        ContentRecoveryScopeCleanupAuthorization, ContentRecoveryScopeCleanupRequestBody,
        ContentRecoveryScopeCleanupResponseBody, ContentRecoveryScopeCleanupSelfResponseBody,
    };

    let f = fixture();
    let f = &f["scope_retirement"];
    let source: ContentRecoveryScopeCleanupAuthorization =
        serde_json::from_value(f["authorization"].clone()).unwrap();
    assert_eq!(
        hex::encode(source.signing_bytes().unwrap()),
        f["authorization_signing_hex"]
    );
    for state in ["removed", "terminated"] {
        let response: ContentRecoveryScopeCleanupResponseBody =
            serde_json::from_value(f["deliveries"][state].clone()).unwrap();
        response.validate_for_source(&source).unwrap();
        let ContentRecoveryScopeCleanupResponseBody::Retired(retired) = &response else {
            panic!()
        };
        assert_eq!(
            hex::encode(retired.cleanup.retirement_proof.signing_bytes().unwrap()),
            f[format!("{state}_signing_hex")],
        );
        assert_eq!(
            source.intent_digest().unwrap().as_str(),
            f["results"][state]["retirement_proof"]["request_digest"]
        );
    }
    let ContentRecoveryScopeCleanupResponseBody::Retired(retired) =
        serde_json::from_value(f["deliveries"]["removed"].clone()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        hex::encode(retired.delivery_attestation.signing_bytes().unwrap()),
        f["delivery_signing_hex"]
    );
    for group in [f, &f["handoff"]] {
        let source: ContentRecoveryScopeCleanupAuthorization =
            serde_json::from_value(group["authorization"].clone()).unwrap();
        let request = ContentRecoveryScopeCleanupRequestBody {
            authorization_event_ref: source.replacement.authorization_event_ref.clone(),
            inventory_digest: source.inventory_digest.clone(),
            effective_scope: source.inventory_entry.effective_scope.clone(),
            genesis_event_ref: source.inventory_entry.genesis_event_ref.clone(),
            nonce_base64url: source.nonce_base64url.clone(),
            delivery_challenge_base64url: source.delivery_challenge_base64url.clone(),
        };
        for state in ["removed", "terminated"] {
            // The formal handoff fixture currently has a separate Native
            // topology review (2216 R6); this asserts byte/role binding only.
            let value = &group["self_deliveries"][state];
            let response: ContentRecoveryScopeCleanupSelfResponseBody =
                serde_json::from_value(value.clone()).unwrap();
            response.validate_for_request(&request).unwrap();
            response.delivery.validate_for_source(&source).unwrap();
            assert_eq!(
                canonical_json_bytes(&response).unwrap(),
                canonical_json_bytes(value).unwrap()
            );
            for pointer in [
                "/attestor_signing_key/proof_digest",
                "/delivery_signing_key/delivery_digest",
            ] {
                let mut changed = value.clone();
                *changed.pointer_mut(pointer).unwrap() =
                    json!(format!("sha256:{}", "08".repeat(32)));
                let changed: ContentRecoveryScopeCleanupSelfResponseBody =
                    serde_json::from_value(changed).unwrap();
                assert!(changed.validate_for_request(&request).is_err());
            }
            let mut changed = value.clone();
            let old = changed["attestor_signing_key"].clone();
            changed["attestor_signing_key"] = changed["delivery_signing_key"].clone();
            changed["delivery_signing_key"] = old;
            assert!(
                serde_json::from_value::<ContentRecoveryScopeCleanupSelfResponseBody>(changed)
                    .is_err()
            );
        }
        let pending: ContentRecoveryScopeCleanupSelfResponseBody =
            serde_json::from_value(json!({"delivery":{"state":"pending"}})).unwrap();
        pending.validate_for_request(&request).unwrap();
        let mut disclosed = serde_json::to_value(pending).unwrap();
        disclosed["attestor_signing_key"] =
            group["self_deliveries"]["removed"]["attestor_signing_key"].clone();
        let disclosed: ContentRecoveryScopeCleanupSelfResponseBody =
            serde_json::from_value(disclosed).unwrap();
        assert!(disclosed.validate_for_request(&request).is_err());
    }
}
