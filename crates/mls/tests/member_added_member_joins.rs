//! A member who joined from a Welcome can add the next member: the Welcome it
//! seals carries the ratchet tree the added member joins with
//! (encryption-and-audit.md §2.2, RFC 9420 §12.4.3.3).

use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsAddMemberResult};
use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload, MlsKeyPackageState};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventFullView, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, DeviceId, DidCoreId, DidUrl, Event,
    EventId, EventKind, Hash, KeypackageClaimId, MlsWelcomeDelivery, MlsWelcomeDeliveryId,
    MlsWelcomeRecipientEndpoint, RealmCommit, RealmCommitAuthorityRef, RealmCommitId, RealmId,
    ScopeRef,
};

const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";

fn actor(label: &str) -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn device(seed: u8) -> DeviceId {
    DeviceId::new(format!(
        "ak:device:01904100-0000-7000-8000-0000000000{seed:02x}"
    ))
    .unwrap()
}

/// A human device MLS endpoint of `actor` under a fixed device key.
fn identity(actor: &ActorId, seed: u8) -> ArkretMlsIdentity {
    ArkretMlsIdentity::new_human_device(
        actor.clone(),
        device(seed),
        ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[seed; 32],
        )),
    )
    .unwrap()
}

fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::new(REALM).unwrap(),
    }
}

fn signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:station.example#authority").unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: chrono::Utc::now(),
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

/// The accepted `ak.mls.commit` carrying `add`, over `base` at `position`.
fn accepted(
    committer: &ActorId,
    base: &EventId,
    add: &MlsAddMemberResult,
    binding: MlsGovernanceBindingPayload,
    position: u64,
) -> CommittedEventFullView {
    let payload = MlsCommitPayload::new(base.clone(), 0, &add.commit, binding).unwrap();
    let serde_json::Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
        unreachable!("an MLS Commit payload is an object")
    };
    let event = Event {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [position as u8; 32]),
        kind: EventKind::MlsCommit,
        realm_id: RealmId::new(REALM).unwrap(),
        scope_ref: scope(),
        actor_id: committer.clone(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        created_at: chrono::Utc::now(),
        semantic_refs: Vec::new(),
        payload: payload.into_iter().collect(),
        producer_proof: None,
    };
    let commit = RealmCommit {
        commit_id: RealmCommitId::from_digest([position as u8; 32]),
        realm_id: RealmId::new(REALM).unwrap(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        },
        stream_position: position,
        previous_commit_ref: Some(RealmCommitId::from_digest([0x70; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x71; 32],
        )),
        committed_at: chrono::Utc::now(),
        signature: signature(DetachedSignatureContext::RealmCommit),
    };
    CommittedEventFullView { commit, event }
}

fn delivery(
    view: &CommittedEventFullView,
    recipient: &ActorId,
    endpoint: &DeviceId,
    add: &MlsAddMemberResult,
) -> MlsWelcomeDelivery {
    MlsWelcomeDelivery {
        welcome_id: MlsWelcomeDeliveryId::new(
            "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000091".to_owned(),
        )
        .unwrap(),
        realm_id: RealmId::new(REALM).unwrap(),
        effective_scope: scope(),
        commit_event_ref: view.event.event_id.clone(),
        recipient_actor_id: recipient.clone(),
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: endpoint.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64.clone(),
        producer_proof: signature(DetachedSignatureContext::MlsWelcomeDelivery),
    }
}

fn claimed(identity: &ArkretMlsIdentity, claim: u8) -> arkret_models_crypto::MlsKeyPackageRecord {
    let mut record = identity.key_package_record().unwrap();
    record.state = MlsKeyPackageState::Claimed;
    record.claim_id = Some(
        KeypackageClaimId::new(format!(
            "ak:keypackage_claim:01904100-0000-7000-8000-0000000000{claim:02x}"
        ))
        .unwrap()
        .as_str()
        .to_owned(),
    );
    record
}

#[test]
fn a_member_that_joined_from_a_welcome_adds_the_next_member() {
    let (alice, bob, carol) = (actor("alice"), actor("bob"), actor("carol"));
    let genesis = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x72; 32]);
    let mut alice_group = identity(&alice, 1)
        .create_group_with_governance_binding(
            &scope(),
            &MlsGovernanceBindingPayload::new(scope(), None, 0, 0, 0).unwrap(),
        )
        .unwrap();

    let bob_identity = identity(&bob, 2);
    let first_binding =
        MlsGovernanceBindingPayload::new(scope(), Some(genesis.clone()), 0, 1, 0).unwrap();
    let first = alice_group
        .add_member_with_governance_binding(&claimed(&bob_identity, 0x81), &first_binding)
        .unwrap();
    let first_view = accepted(&alice, &genesis, &first, first_binding, 1);
    let mut bob_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        bob_identity,
        &delivery(&first_view, &bob, &device(2), &first),
        &first_view,
    )
    .unwrap();
    assert_eq!(bob_group.epoch(), 1);
    #[cfg(feature = "test-utils")]
    let alice_epoch_one = {
        alice_group
            .install_recovered_own_commit(&first_view, &genesis)
            .unwrap();
        alice_group
            .install_test_leaf_bindings(vec![
                identity(&alice, 1).endpoint_identity(),
                identity(&bob, 2).endpoint_identity(),
            ])
            .unwrap();
        alice_group.export_state_record().unwrap()
    };

    let carol_identity = identity(&carol, 3);
    let second_binding =
        MlsGovernanceBindingPayload::new(scope(), Some(first_view.event.event_id.clone()), 1, 2, 0)
            .unwrap();
    let second = bob_group
        .add_member_with_governance_binding(&claimed(&carol_identity, 0x82), &second_binding)
        .unwrap();
    let second_view = accepted(&bob, &first_view.event.event_id, &second, second_binding, 2);
    let carol_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        carol_identity,
        &delivery(&second_view, &carol, &device(3), &second),
        &second_view,
    )
    .expect("the joined member's Welcome carries the ratchet tree");
    assert_eq!(carol_group.epoch(), 2);
    #[cfg(feature = "test-utils")]
    {
        let base = &first_view.event.event_id;
        let wrong_base = genesis.clone();
        let mut rejected = ArkretMlsGroup::restore_from_state_record(&alice_epoch_one).unwrap();
        assert!(
            rejected
                .install_recovered_remote_commit(&second_view, &wrong_base)
                .is_err()
        );
        assert_eq!(rejected.epoch(), 1);
        let mut rejected = ArkretMlsGroup::restore_from_state_record(&alice_epoch_one).unwrap();
        assert!(
            rejected
                .install_recovered_own_commit(&second_view, base)
                .is_err()
        );
        assert_eq!(rejected.epoch(), 1);
        let mut changed = second_view.clone();
        changed.event.payload.get_mut("governance_binding").unwrap()["key_access_revision"] =
            serde_json::json!(1);
        changed.event.payload.insert(
            "covers_key_access_revision".to_owned(),
            serde_json::json!(1),
        );
        let mut rejected = ArkretMlsGroup::restore_from_state_record(&alice_epoch_one).unwrap();
        assert!(
            rejected
                .install_recovered_remote_commit(&changed, base)
                .is_err()
        );
        assert_eq!(rejected.epoch(), 1);
        let mut restored = ArkretMlsGroup::restore_from_state_record(&alice_epoch_one).unwrap();
        assert_eq!(
            restored
                .install_recovered_remote_commit(&second_view, base)
                .unwrap(),
            2
        );
        assert!(
            restored
                .install_recovered_remote_commit(&second_view, base)
                .is_err()
        );
    }
}
