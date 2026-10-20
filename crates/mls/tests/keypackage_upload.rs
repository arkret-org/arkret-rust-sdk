use arkret_mls::{ArkretMlsIdentity, ArkretMlsSigner};
use arkret_models_crypto::{
    MlsEndpointIdentity, keypackages_upload_signing_input, mls_basic_credential_identity,
};
use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId, DidUrl, EventId};

fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

#[test]
fn realm_device_restores_full_identity_and_signs_closed_durable_receipts() {
    use arkret_models_crypto::{RecipientMlsDurableReceipt, RecipientMlsDurableSigner};
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "consume_single_claim")
        .unwrap();
    let mut receipt: RecipientMlsDurableReceipt =
        serde_json::from_value(case["unsigned_request"]["recipient_durable_receipt"].clone())
            .unwrap();
    let principal = DidCoreId::new("ak:did_core:webvh:zRealmActorFixture").unwrap();
    let actor = ActorId::realm(arkret_wire::RealmActorId::new(
        receipt.realm_id.clone(),
        principal.clone(),
    ));
    let device = DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000d").unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[101; 32]);
    let identity = ArkretMlsIdentity::new_realm_device(
        actor.clone(),
        device.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let saved = identity.export_private_state().unwrap();
    let endpoint = MlsEndpointIdentity::human_device(principal, device.clone());
    let restored =
        ArkretMlsIdentity::restore_from_private_state(actor.clone(), endpoint.clone(), &saved)
            .unwrap();
    let record = restored.key_package_record().unwrap();
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(
        &arkret_canonical::base64url_decode(record.keypackage.as_str()).unwrap(),
        0,
    )
    .unwrap();
    assert!(
        matches!(leaf.credential, arkret_mls::AuthorLeafCredential::Basic { identity } if identity == mls_basic_credential_identity(&actor).unwrap())
    );
    let method = DidUrl::new("did:webvh:zRealmActorFixture:applet.example#runtime").unwrap();
    receipt.recipient = RecipientMlsDurableSigner::RealmDevice {
        recipient_actor_id: actor.clone(),
        recipient_device_id: device,
        device_verification_method: method.clone(),
    };
    let signed = restored
        .sign_recipient_mls_durable_receipt(receipt)
        .unwrap();
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key.verifying_key().to_bytes(),
        method.as_str(),
        &signed.canonical_signing_bytes().unwrap(),
        &signed.signature,
    )
    .unwrap();
    let wire = serde_json::to_value(&signed).unwrap();
    assert_eq!(wire["recipient_actor_id"], serde_json::json!(actor));
    assert!(wire.get("recipient_account_id").is_none());
    let parsed = serde_json::from_value::<RecipientMlsDurableReceipt>(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        serde_json::to_value(&signed).unwrap()
    );
    let claim_id = serde_json::from_value(case["unsigned_request"]["claim_id"].clone()).unwrap();
    let consume = restored
        .signed_key_packages_consume_request(claim_id, signed.clone())
        .unwrap();
    consume.validate_shape().unwrap();
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key.verifying_key().to_bytes(),
        method.as_str(),
        &arkret_models_crypto::keypackages_consume_signing_input(&consume.unsigned()).unwrap(),
        &consume.signature,
    )
    .unwrap();
    let mut mixed = wire;
    mixed["recipient_account_id"] = serde_json::to_value(super_account()).unwrap();
    assert!(serde_json::from_value::<RecipientMlsDurableReceipt>(mixed).is_err());
    let mut snapshot: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    snapshot["profile"]["kind"] = "human_device".into();
    assert!(
        ArkretMlsIdentity::restore_from_private_state(
            actor.clone(),
            endpoint.clone(),
            &serde_json::to_vec(&snapshot).unwrap()
        )
        .is_err()
    );
    let foreign = ActorId::realm(arkret_wire::RealmActorId::new(
        arkret_wire::RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [102; 32],
        )),
        actor.signing_principal_id().clone(),
    ));
    assert!(
        ArkretMlsIdentity::restore_from_private_state(foreign.clone(), endpoint, &saved).is_err()
    );
    let mut wrong = signed;
    if let RecipientMlsDurableSigner::RealmDevice {
        recipient_actor_id, ..
    } = &mut wrong.recipient
    {
        *recipient_actor_id = foreign;
    }
    assert!(
        restored
            .sign_recipient_mls_durable_receipt(wrong.clone())
            .is_err()
    );
    assert!(
        restored
            .signed_key_packages_consume_request(consume.claim_id, wrong)
            .is_err()
    );
}

fn super_account() -> AccountId {
    actor().as_account_id().unwrap().clone()
}

#[test]
fn human_and_restored_agent_produce_the_exact_closed_upload_and_full_actor_credential() {
    let seed = [95; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let method = DidUrl::new("did:web:alice.example#runtime").unwrap();
    let human = ArkretMlsIdentity::new_human_device(
        actor(),
        DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000d").unwrap(),
        ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [95; 32]);
    let agent = ArkretMlsIdentity::new_agent(
        actor(),
        method.clone(),
        authorization.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let restored = ArkretMlsIdentity::restore_from_private_state(
        actor(),
        MlsEndpointIdentity::agent_runtime(
            actor().as_account_id().unwrap().principal_id.clone(),
            method.clone(),
            authorization,
        )
        .unwrap(),
        &agent.export_private_state().unwrap(),
    )
    .unwrap();
    for identity in [human, restored] {
        let records = [
            identity.key_package_record().unwrap(),
            identity.key_package_record().unwrap(),
        ];
        let upload = identity
            .signed_key_packages_upload_request(&records, method.as_str())
            .unwrap();
        upload.validate_shape().unwrap();
        let wire = serde_json::to_value(&upload).unwrap();
        assert!(wire.get("pairwise_verification_method").is_none());
        assert!(wire.get("intended_realm_id").is_none());
        let parsed: arkret_models_crypto::KeyPackagesUploadRequestBody =
            serde_json::from_value(wire).unwrap();
        let input = keypackages_upload_signing_input(&parsed.unsigned()).unwrap();
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &key.verifying_key().to_bytes(),
            method.as_str(),
            &input,
            &parsed.endpoint_signature,
        )
        .unwrap();
        let bytes = arkret_canonical::base64url_decode(records[0].keypackage.as_str()).unwrap();
        let leaf = arkret_mls::author_leaf_from_key_package_bytes(&bytes, 0).unwrap();
        assert!(
            matches!(leaf.credential, arkret_mls::AuthorLeafCredential::Basic { identity } if identity == mls_basic_credential_identity(&actor()).unwrap())
        );
    }
    assert!(
        agent
            .signed_key_packages_upload_request(
                &[agent.key_package_record().unwrap()],
                "did:web:alice.example#other"
            )
            .is_err()
    );
}

#[test]
fn claim_projection_preserves_full_actor_active_suite_and_claimed_state() {
    let identity = ArkretMlsIdentity::new_human_device(
        actor(),
        DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000d").unwrap(),
        ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(&[98; 32])),
    )
    .unwrap();
    let record = identity.key_package_record().unwrap();
    let MlsEndpointIdentity::HumanDevice {
        principal_id,
        device_id,
    } = record.endpoint.clone()
    else {
        panic!("device endpoint")
    };
    let mut claim = arkret_models_crypto::KeyPackageClaimRecord {
        claim_id: "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc".to_owned(),
        keypackage_ref: record.keypackage_ref.to_string(),
        actor_id: record.actor_id.clone(),
        principal_id,
        device_id: Some(device_id),
        agent_id: None,
        agent_verification_method: None,
        keypackage: record.keypackage.clone(),
        capabilities: record.capabilities.clone(),
        device_authorize_event_id: Some(EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [98; 32],
        )),
        agent_key_authorize_event_id: None,
        expires_at: record.expires_at.unwrap(),
        revocation_status: Some("active".to_owned()),
        last_resort: Some(false),
    };
    let projected = arkret_mls::mls_key_package_record_from_claim(&claim).unwrap();
    assert_eq!(projected.actor_id, record.actor_id);
    assert_eq!(projected.endpoint, record.endpoint);
    assert_eq!(projected.cipher_suites, record.cipher_suites);
    assert_eq!(projected.keypackage, record.keypackage);
    assert_eq!(
        projected.state,
        arkret_models_crypto::MlsKeyPackageState::Claimed
    );
    let original = claim.clone();
    claim.actor_id = ActorId::account(AccountId::new(
        claim.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    ));
    assert!(arkret_mls::mls_key_package_record_from_claim(&claim).is_err());
    claim = original.clone();
    claim.capabilities = vec!["ak.content.v1".to_owned()];
    assert!(arkret_mls::mls_key_package_record_from_claim(&claim).is_err());
    claim = original;
    claim.keypackage_ref = format!("sha256:{}", "0".repeat(64));
    assert!(arkret_mls::mls_key_package_record_from_claim(&claim).is_err());
}

#[test]
fn human_durable_receipt_signing_rejects_another_station_before_signing() {
    use arkret_models_crypto::{RecipientMlsDurableReceipt, RecipientMlsDurableSigner};
    let key = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
    let device = DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000d").unwrap();
    let identity = ArkretMlsIdentity::new_human_device(
        actor(),
        device.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "consume_single_claim")
        .unwrap();
    let mut receipt: RecipientMlsDurableReceipt =
        serde_json::from_value(case["unsigned_request"]["recipient_durable_receipt"].clone())
            .unwrap();
    let method = DidUrl::new("did:web:alice.example#runtime").unwrap();
    receipt.recipient = RecipientMlsDurableSigner::Device {
        recipient_account_id: actor().as_account_id().unwrap().clone(),
        recipient_device_id: device,
        device_verification_method: method.clone(),
    };
    let signed = identity
        .sign_recipient_mls_durable_receipt(receipt)
        .unwrap();
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key.verifying_key().to_bytes(),
        method.as_str(),
        &signed.canonical_signing_bytes().unwrap(),
        &signed.signature,
    )
    .unwrap();
    let mut wrong = signed;
    let RecipientMlsDurableSigner::Device {
        recipient_account_id,
        ..
    } = &mut wrong.recipient
    else {
        unreachable!()
    };
    recipient_account_id.station_id =
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(identity.sign_recipient_mls_durable_receipt(wrong).is_err());
}
