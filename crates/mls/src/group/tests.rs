use arkret_wire::{DeviceId, RealmId};

use super::*;

fn identity() -> ArkretMlsIdentity {
    ArkretMlsIdentity::new_test_human_device(
        ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:mls.example").unwrap(),
            DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
        )),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000071").unwrap(),
    )
    .unwrap()
}

fn realm_scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV").unwrap(),
    }
}

fn second_identity() -> ArkretMlsIdentity {
    ArkretMlsIdentity::new_test_human_device(
        ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:mls-member.example").unwrap(),
            DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
        )),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000072").unwrap(),
    )
    .unwrap()
}

fn event(byte: u8) -> EventId {
    EventId::from_event_digest(&Hash::new(canonical::sha256_digest([byte])).unwrap()).unwrap()
}

fn genesis_binding(scope: &ScopeRef) -> MlsGovernanceBindingPayload {
    let ScopeRef::Realm { realm_id } = scope else {
        panic!("test scope is Realm")
    };
    MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0).unwrap()
}

fn transition_binding(
    scope: &ScopeRef,
    base: EventId,
    revision: u64,
) -> MlsGovernanceBindingPayload {
    binding_for_epochs(scope, base, 0, 1, revision)
}

fn binding_for_epochs(
    scope: &ScopeRef,
    base: EventId,
    previous_epoch: u64,
    next_epoch: u64,
    revision: u64,
) -> MlsGovernanceBindingPayload {
    let ScopeRef::Realm { realm_id } = scope else {
        panic!("test scope is Realm")
    };
    MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base),
        previous_epoch,
        next_epoch,
        revision,
    )
    .unwrap()
}

fn claimed_keypackage(identity: &ArkretMlsIdentity) -> MlsKeyPackageRecord {
    let mut record = identity.key_package_record().unwrap();
    record.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    record.claim_id = Some("ak:keypackage_claim:01904100-0000-7000-8000-000000000073".to_owned());
    record
}

#[test]
fn keypackage_fixture_credentials_decode_to_the_exact_actor() {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-keypackage-endpoint-kat-fixture.json",
    )
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let keypackage = base64url_decode(case["keypackage"].as_str().unwrap().as_bytes()).unwrap();
        let leaf = crate::identity::author_leaf_from_key_package_bytes(&keypackage, 0).unwrap();
        let crate::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            panic!("fixture KeyPackage must carry BasicCredential");
        };
        let actor: ActorId = serde_json::from_value(case["endpoint"]["actor_id"].clone()).unwrap();
        assert_eq!(
            arkret_models_crypto::decode_mls_basic_credential_identity(&identity).unwrap(),
            actor
        );
        assert_eq!(
            identity,
            base64url_decode(case["leaf_credential"].as_str().unwrap().as_bytes()).unwrap()
        );
        assert_eq!(
            std::str::from_utf8(&identity).unwrap(),
            case["leaf_credential_jcs"].as_str().unwrap()
        );
    }
}

/// Only the active registry suite has a wire identity: a KeyPackage the
/// MLS library can build under a reserved suite fails closed instead of
/// being mapped onto the active one.
#[test]
fn keypackage_ciphersuite_maps_only_the_active_registry_row() {
    let identity = identity();
    let active =
        base64url_decode(identity.key_package_record().unwrap().keypackage.as_bytes()).unwrap();
    assert_eq!(
        crate::identity::keypackage_ciphersuite_canonical_id(&active).unwrap(),
        ARKRET_MLS_CIPHERSUITE_CANONICAL_ID
    );

    let reserved =
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(reserved.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(
            arkret_models_crypto::mls_basic_credential_identity(&identity.actor_id).unwrap(),
        )
        .into(),
        signature_key: signer.public().into(),
    };
    let provider = OpenMlsRustCrypto::default();
    let bundle = openmls::prelude::KeyPackage::builder()
        .build(reserved, &provider, &signer, credential)
        .unwrap();
    let reserved_bytes = bundle.key_package().tls_serialize_detached().unwrap();
    let error = crate::identity::keypackage_ciphersuite_canonical_id(&reserved_bytes).unwrap_err();
    assert!(
        error.to_string().contains("unsupported_ciphersuite"),
        "unexpected error: {error}"
    );
    assert!(
        crate::identity::author_leaf_from_key_package_bytes(&reserved_bytes, 0)
            .unwrap_err()
            .to_string()
            .contains("unsupported_ciphersuite")
    );
    assert!(
        crate::identity::keypackage_capabilities_from_key_package_bytes(&reserved_bytes)
            .unwrap_err()
            .to_string()
            .contains("unsupported_ciphersuite")
    );
    let mut reserved_record = identity.key_package_record().unwrap();
    reserved_record.keypackage = base64url_encode(&reserved_bytes);
    reserved_record.keypackage_ref = Hash::new(canonical::sha256_digest(&reserved_bytes)).unwrap();
    reserved_record.cipher_suites = vec![format!("{reserved:?}")];
    assert!(identity.key_package_upload_entry(&reserved_record).is_err());
    assert!(
        decode_key_package(&identity.provider, &reserved_record)
            .unwrap_err()
            .to_string()
            .contains("unsupported_ciphersuite")
    );

    let mut wrong_outer_suite = identity.key_package_record().unwrap();
    wrong_outer_suite.cipher_suites = vec![format!("{reserved:?}")];
    assert!(
        identity
            .key_package_upload_entry(&wrong_outer_suite)
            .is_err()
    );
    assert!(
        decode_key_package(&identity.provider, &wrong_outer_suite)
            .unwrap_err()
            .to_string()
            .contains("unsupported_ciphersuite")
    );

    let mut wrong_actor = identity.key_package_record().unwrap();
    wrong_actor.actor_id = second_identity().actor_id;
    assert!(identity.key_package_upload_entry(&wrong_actor).is_err());
    assert!(decode_key_package(&identity.provider, &wrong_actor).is_err());
    assert!(crate::identity::keypackage_ciphersuite_canonical_id(b"not a keypackage").is_err());
}

/// The policy follows the scope kind, which is what the group is created
/// and restored with. It is no longer recoverable from the `group_id`, and
/// the point of this test is that nothing tries.
#[test]
fn all_effective_scopes_use_station_verifiable_handshakes() {
    let realm_id = RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV").unwrap();
    for scope in [
        realm_scope(),
        ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
            )
            .unwrap(),
        },
    ] {
        assert_eq!(
            handshake_policy(&scope).unwrap(),
            openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY
        );
    }

    let sidecar = ScopeRef::Sidecar {
        realm_id,
        sidecar_id: arkret_wire::SidecarId::new(
            "ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
        )
        .unwrap(),
    };
    assert_eq!(
        handshake_policy(&sidecar).unwrap(),
        openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY
    );
    assert!(handshake_policy(&ScopeRef::RealmGenesis).is_err());
}

/// The group is seeded with the scope's digest, never with scope bytes, so
/// the 43-character wire id is what `group_id()` reports.
#[test]
fn group_is_created_under_the_scope_derived_group_id() {
    let scope = realm_scope();
    let group = identity().create_group(&scope).unwrap();
    assert_eq!(group.group_id(), scope.canonical_mls_group_id().unwrap());
    assert_eq!(group.group_id().as_str().len(), 43);
    assert_eq!(group.scope(), &scope);
}

#[test]
fn governed_group_authenticates_the_genesis_binding_extension() {
    let scope = realm_scope();
    let binding = genesis_binding(&scope);
    let group = identity()
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let extension = group
        .group
        .extensions()
        .unknown(MLS_GOVERNANCE_BINDING_EXTENSION_TYPE)
        .expect("governed group has the registered binding extension");
    assert_eq!(
        MlsGovernanceBindingPayload::from_deterministic_cbor(&extension.0).unwrap(),
        binding
    );
}

#[test]
fn rejected_binding_does_not_queue_add_proposals() {
    let scope = realm_scope();
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let record = claimed_keypackage(&second_identity());
    let wrong_scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FW").unwrap(),
    };
    let wrong_binding = transition_binding(&wrong_scope, event(1), 1);
    let storage_before = snapshot_provider_storage(&group.identity.provider).unwrap();
    let proposals_before = group.group.pending_proposals().count();

    assert!(
        group
            .add_member_with_governance_binding(&record, &wrong_binding)
            .is_err()
    );
    assert_eq!(group.group.pending_proposals().count(), proposals_before);
    assert_eq!(
        snapshot_provider_storage(&group.identity.provider).unwrap(),
        storage_before
    );
    assert_eq!(group.epoch(), 0);
}

#[test]
fn rejected_binding_does_not_queue_remove_proposals() {
    let scope = realm_scope();
    let base = event(1);
    let binding = transition_binding(&scope, base.clone(), 1);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let member = second_identity();
    let add = group
        .add_member_with_governance_binding(&claimed_keypackage(&member), &binding)
        .unwrap();
    let public_state = MlsGovernanceBindingPublicState::new(scope, Some(base), 0, 1);
    group
        .merge_accepted_commit_envelope(&add.commit, &public_state, &binding)
        .unwrap();
    group
        .install_test_leaf_bindings(vec![
            group.identity.endpoint.clone(),
            member.endpoint.clone(),
        ])
        .unwrap();

    let wrong_scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FW").unwrap(),
    };
    let wrong_binding = binding_for_epochs(&wrong_scope, event(2), 1, 2, 2);
    let storage_before = snapshot_provider_storage(&group.identity.provider).unwrap();
    let snapshot_before = group.export_state_record().unwrap().serialized_state;
    let proposals_before = group.group.pending_proposals().count();

    assert!(
        group
            .remove_members_by_actor_with_governance_binding(
                std::slice::from_ref(&member.actor_id),
                &wrong_binding,
            )
            .is_err()
    );
    assert_eq!(group.group.pending_proposals().count(), proposals_before);
    assert_eq!(
        snapshot_provider_storage(&group.identity.provider).unwrap(),
        storage_before
    );
    assert_eq!(
        group.export_state_record().unwrap().serialized_state,
        snapshot_before
    );
    assert_eq!(group.epoch(), 1);
}

#[test]
fn missing_or_mismatched_authenticated_binding_never_advances_epoch() {
    let scope = realm_scope();
    let base = event(1);
    let binding = transition_binding(&scope, base.clone(), 1);
    let public_state =
        MlsGovernanceBindingPublicState::new(scope.clone(), Some(base.clone()), 0, 1);

    let mut unbound = identity().create_group(&scope).unwrap();
    let unbound_commit = unbound.self_update_commit().unwrap();
    let unbound_storage_before = snapshot_provider_storage(&unbound.identity.provider).unwrap();
    let unbound_snapshot_before = unbound.export_state_record().unwrap().serialized_state;
    assert!(
        unbound
            .merge_accepted_commit_envelope(&unbound_commit, &public_state, &binding)
            .is_err()
    );
    assert_eq!(unbound.epoch(), 0);
    assert_eq!(
        snapshot_provider_storage(&unbound.identity.provider).unwrap(),
        unbound_storage_before
    );
    assert_eq!(
        unbound.export_state_record().unwrap().serialized_state,
        unbound_snapshot_before
    );

    let mut governed = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let add = governed
        .add_member_with_governance_binding(&claimed_keypackage(&second_identity()), &binding)
        .unwrap();
    let mismatched = transition_binding(&scope, base.clone(), 2);
    let mismatched_state = MlsGovernanceBindingPublicState::new(scope, Some(base), 0, 2);
    let governed_storage_before = snapshot_provider_storage(&governed.identity.provider).unwrap();
    let governed_snapshot_before = governed.export_state_record().unwrap().serialized_state;
    assert!(
        governed
            .merge_accepted_commit_envelope(&add.commit, &mismatched_state, &mismatched)
            .is_err()
    );
    assert_eq!(governed.epoch(), 0);
    assert_eq!(
        snapshot_provider_storage(&governed.identity.provider).unwrap(),
        governed_storage_before
    );
    assert_eq!(
        governed.export_state_record().unwrap().serialized_state,
        governed_snapshot_before
    );
}

#[test]
fn definitively_rejected_own_commit_releases_only_the_exact_candidate() {
    let scope = realm_scope();
    let binding = transition_binding(&scope, event(1), 1);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let commit = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let record = group.export_state_record().unwrap();
    let mut wrong = commit.clone();
    wrong.commit_digest = Hash::new(canonical::sha256_digest(b"another commit")).unwrap();
    assert!(!group.discard_rejected_own_commit(&wrong).unwrap());
    assert_eq!(
        group.export_state_record().unwrap().serialized_state,
        record.serialized_state
    );
    let mut tampered = commit.clone();
    tampered.commit = commit.commit.clone() + "invalid";
    assert!(group.discard_rejected_own_commit(&tampered).is_err());
    assert!(group.has_pending_commit());
    assert!(group.discard_rejected_own_commit(&commit).unwrap());
    assert_eq!(group.epoch(), 0);
    assert!(!group.has_pending_commit());
    let before: OpenMlsStateSnapshot = serde_json::from_slice(&record.serialized_state).unwrap();
    let after: OpenMlsStateSnapshot =
        serde_json::from_slice(&group.export_state_record().unwrap().serialized_state).unwrap();
    assert_eq!(before.signal_nonce_counter, after.signal_nonce_counter);
    assert_eq!(before.context, after.context);
    for (key, value) in &before.storage_entries {
        if !decode(key).unwrap().starts_with(b"GroupState") {
            assert_eq!(after.storage_entries.get(key), Some(value));
        }
    }
    let mut restored =
        ArkretMlsGroup::restore_from_state_record(&group.export_state_record().unwrap()).unwrap();
    assert!(!restored.has_pending_commit());
    assert!(!restored.discard_rejected_own_commit(&commit).unwrap());
    assert!(
        restored
            .self_update_commit_with_governance_binding(&binding)
            .is_ok()
    );
}

#[test]
fn self_update_authenticates_the_next_governance_binding_before_installation() {
    let scope = realm_scope();
    let base = event(1);
    let genesis = genesis_binding(&scope);
    let binding = transition_binding(&scope, base.clone(), 1);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis)
        .unwrap();
    let commit = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    assert_eq!(group.epoch(), 0);
    let snapshot = group.export_state_record().unwrap();
    assert!(
        group
            .self_update_commit_with_governance_binding(&binding)
            .is_err()
    );
    assert_eq!(
        group.export_state_record().unwrap().serialized_state,
        snapshot.serialized_state
    );
    let mut restored = ArkretMlsGroup::restore_from_state_record(&snapshot).unwrap();
    let public_state = MlsGovernanceBindingPublicState::new(scope, Some(base), 0, 1);
    restored
        .merge_accepted_commit_envelope(&commit, &public_state, &binding)
        .unwrap();
    assert_eq!(restored.epoch(), 1);
    let (info, tree) = restored.public_group_state_bytes().unwrap();
    let tracker =
        crate::MlsPublicGroupTracker::from_external(&info, &tree, restored.group_id().as_str(), 1)
            .unwrap();
    assert_eq!(tracker.governance_binding().unwrap(), binding);
}

#[test]
fn frozen_commit_recovery_preserves_live_ratchets_and_rejects_another_private_base() {
    let scope = realm_scope();
    let binding = transition_binding(&scope, event(1), 1);
    let base = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let base_record = base.export_state_record().unwrap();
    let mut original = ArkretMlsGroup::restore_from_state_record(&base_record).unwrap();
    let accepted = original
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let frozen = original.export_state_record().unwrap();
    let mut live = ArkretMlsGroup::restore_from_state_record(&base_record).unwrap();
    live.group
        .create_message(
            &live.identity.provider,
            &live.identity.signer,
            b"one base-epoch application message",
        )
        .unwrap();
    live.signal_nonce_counter = 7;
    let competing = live
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let before = live.export_state_record().unwrap();
    let mut resumed = live
        .resume_frozen_pending_commit(&frozen, &accepted, &binding)
        .unwrap();
    assert_eq!(resumed.signal_nonce_counter, 7);
    let live_storage = snapshot_provider_storage(&live.identity.provider).unwrap();
    let resumed_storage = snapshot_provider_storage(&resumed.identity.provider).unwrap();
    let frozen_snapshot: OpenMlsStateSnapshot =
        serde_json::from_slice(&frozen.serialized_state).unwrap();
    let mut saw_advanced_ratchet = false;
    for (key, value) in &live_storage {
        if decode(key).unwrap().starts_with(b"MessageSecrets") {
            assert_eq!(resumed_storage.get(key), Some(value));
            saw_advanced_ratchet |= frozen_snapshot.storage_entries.get(key) != Some(value);
        }
    }
    assert!(saw_advanced_ratchet);
    assert!(
        live.resume_frozen_pending_commit(&frozen, &competing, &binding)
            .is_err()
    );
    assert_eq!(
        live.export_state_record().unwrap().serialized_state,
        before.serialized_state
    );
    let mut wrong_base: OpenMlsStateSnapshot = frozen_snapshot;
    let key = wrong_base
        .storage_entries
        .keys()
        .find(|key| decode(key).unwrap().starts_with(b"EpochSecrets"))
        .unwrap()
        .clone();
    wrong_base
        .storage_entries
        .insert(key, encode(b"another epoch secret"));
    let mut wrong_record = frozen;
    wrong_record.serialized_state = serde_json::to_vec(&wrong_base).unwrap();
    assert!(
        live.resume_frozen_pending_commit(&wrong_record, &accepted, &binding)
            .is_err()
    );
    assert_eq!(
        live.export_state_record().unwrap().serialized_state,
        before.serialized_state
    );
    resumed
        .merge_accepted_commit_envelope(
            &accepted,
            &MlsGovernanceBindingPublicState::new(scope, Some(event(1)), 0, 1),
            &binding,
        )
        .unwrap();
    assert_eq!(resumed.epoch(), 1);
    assert!(!resumed.has_pending_commit());
}

#[test]
fn sidecar_frozen_add_verifies_public_transition_without_rewinding_live_ratchets() {
    let realm_id = realm_scope().realm_id_opt().unwrap().clone();
    let sidecar_id =
        arkret_wire::SidecarId::new("ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV")
            .unwrap();
    let scope = ScopeRef::Sidecar {
        realm_id: realm_id.clone(),
        sidecar_id: sidecar_id.clone(),
    };
    let binding_for = |base, previous, next, revision| {
        MlsGovernanceBindingPayload::sidecar(
            realm_id.clone(),
            sidecar_id.clone(),
            base,
            previous,
            next,
            revision,
            Hash::new(canonical::sha256_digest([4])).unwrap(),
            vec![event(5)],
        )
        .unwrap()
    };
    let genesis = binding_for(None, 0, 0, 0);
    let binding = binding_for(Some(event(1)), 0, 1, 1);
    let agent = ArkretMlsIdentity::new_agent(
        ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:mls-agent.example").unwrap(),
            DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
        )),
        arkret_wire::DidUrl::new("did:web:mls-agent.example#runtime-31").unwrap(),
        event(31),
        crate::ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[31; 32],
        )),
    )
    .unwrap();
    let base = identity()
        .create_group_with_governance_binding(&scope, &genesis)
        .unwrap();
    let (group_info, tree) = base.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        base.group_id().as_str(),
        0,
    )
    .unwrap();
    let public_base = tracker.export_state().unwrap();
    let base_record = base.export_state_record().unwrap();
    let mut private = ArkretMlsGroup::restore_from_state_record(&base_record).unwrap();
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(openmls::prelude::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    private
        .group
        .set_configuration(private.identity.provider.storage(), &config)
        .unwrap();
    let private_commit = private
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    assert!(
        tracker
            .process_public_handshake(&decode(&private_commit.commit).unwrap())
            .is_err()
    );
    assert_eq!(tracker.export_state().unwrap(), public_base);
    let mut original = ArkretMlsGroup::restore_from_state_record(&base_record).unwrap();
    let add = original
        .add_member_with_governance_binding(&claimed_keypackage(&agent), &binding)
        .unwrap();
    let frozen = original.export_state_record().unwrap();
    let bytes = decode(&add.commit.commit).unwrap();
    let transition = tracker.process_public_handshake(&bytes).unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        added_leaves,
        consumed_proposals,
        ..
    } = transition
    else {
        panic!("expected an Add Commit");
    };
    assert_eq!(added_leaves.len(), 1);
    assert_eq!(added_leaves[0].actor_id, agent.actor_id);
    assert!(consumed_proposals.iter().any(|p| {
        p.target_after
            .as_ref()
            .is_some_and(|l| l.actor_id == agent.actor_id)
    }));
    assert_eq!(tracker.governance_binding().unwrap(), binding);
    assert_eq!(original.epoch(), 0);
    let protocol = MlsMessageIn::tls_deserialize_exact(bytes.as_slice())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    assert_eq!(protocol.wire_format(), WireFormat::PublicMessage);
    let mut echoed = ArkretMlsGroup::restore_from_state_record(&frozen).unwrap();
    assert!(matches!(
        echoed
            .group
            .process_message(&echoed.identity.provider, protocol)
            .unwrap()
            .into_content(),
        ProcessedMessageContent::OwnPendingCommit,
    ));

    let mut live = ArkretMlsGroup::restore_from_state_record(&base_record).unwrap();
    live.group
        .create_message(
            &live.identity.provider,
            &live.identity.signer,
            b"later application",
        )
        .unwrap();
    live.signal_nonce_counter = 7;
    let competing = live
        .add_member_with_governance_binding(&claimed_keypackage(&agent), &binding)
        .unwrap();
    let before = live.export_state_record().unwrap();
    let mut tampered = add.commit.clone();
    let mut tampered_bytes = bytes;
    *tampered_bytes.last_mut().unwrap() ^= 1;
    tampered.commit = encode(&tampered_bytes);
    tampered.commit_digest = Hash::new(canonical::sha256_digest(&tampered_bytes)).unwrap();
    for candidate in [&competing.commit, &tampered] {
        assert!(
            live.resume_frozen_pending_commit(&frozen, candidate, &binding)
                .is_err()
        );
    }
    let wrong_binding = binding_for(Some(event(2)), 0, 1, 1);
    assert!(
        live.resume_frozen_pending_commit(&frozen, &add.commit, &wrong_binding)
            .is_err()
    );
    let mut wrong: OpenMlsStateSnapshot = serde_json::from_slice(&frozen.serialized_state).unwrap();
    wrong.own_pending_commit_digest = None;
    let mut unbound = frozen.clone();
    unbound.serialized_state = serde_json::to_vec(&wrong).unwrap();
    assert!(ArkretMlsGroup::restore_from_state_record(&unbound).is_err());
    assert!(
        live.resume_frozen_pending_commit(&unbound, &add.commit, &binding)
            .is_err()
    );
    assert_eq!(
        live.export_state_record().unwrap().serialized_state,
        before.serialized_state
    );

    let mut resumed = live
        .resume_frozen_pending_commit(&frozen, &add.commit, &binding)
        .unwrap();
    assert_eq!(resumed.epoch(), 0);
    assert!(resumed.has_pending_commit());
    assert_eq!(resumed.signal_nonce_counter, 7);
    let live_storage = snapshot_provider_storage(&live.identity.provider).unwrap();
    let resumed_storage = snapshot_provider_storage(&resumed.identity.provider).unwrap();
    for (key, value) in &live_storage {
        if decode(key).unwrap().starts_with(b"MessageSecrets") {
            assert_eq!(resumed_storage.get(key), Some(value));
        }
    }
    resumed
        .merge_accepted_commit_envelope(
            &add.commit,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(1)), 0, 1),
            &binding,
        )
        .unwrap();
    assert_eq!(resumed.epoch(), 1);
    assert!(!resumed.has_pending_commit());
    assert!(resumed.own_pending_commit_digest.is_none());
    resumed
        .install_test_leaf_bindings(vec![
            resumed.identity.endpoint.clone(),
            agent.endpoint.clone(),
        ])
        .unwrap();

    // Self updates and Removes retain the exact signed transition binding.
    let rotation_binding = binding_for(Some(event(6)), 1, 2, 1);
    let rotation = resumed
        .self_update_commit_with_governance_binding(&rotation_binding)
        .unwrap();
    let rotation_record = resumed.export_state_record().unwrap();
    let mut rotated = ArkretMlsGroup::restore_from_state_record(&rotation_record).unwrap();
    rotated
        .merge_accepted_commit_envelope(
            &rotation,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(6)), 1, 1),
            &rotation_binding,
        )
        .unwrap();
    rotated
        .install_test_leaf_bindings(vec![
            rotated.identity.endpoint.clone(),
            agent.endpoint.clone(),
        ])
        .unwrap();
    let removal_binding = binding_for(Some(event(7)), 2, 3, 2);
    let removal = rotated
        .remove_members_by_actor_with_governance_binding(
            std::slice::from_ref(&agent.actor_id),
            &removal_binding,
        )
        .unwrap();
    let removal_record = rotated.export_state_record().unwrap();
    let mut removed = ArkretMlsGroup::restore_from_state_record(&removal_record).unwrap();
    removed
        .merge_accepted_commit_envelope(
            &removal.commit,
            &MlsGovernanceBindingPublicState::new(scope, Some(event(7)), 2, 2),
            &removal_binding,
        )
        .unwrap();
    assert_eq!(removed.epoch(), 3);
    assert!(removed.own_pending_commit_digest.is_none());
    assert_eq!(removed.group.members().count(), 1);
}

#[test]
fn governed_self_update_survives_restart_and_advances_the_public_binding() {
    let scope = realm_scope();
    let genesis = genesis_binding(&scope);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis)
        .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let base = event(9);
    let binding = transition_binding(&scope, base.clone(), 3);
    let commit = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let mut restarted =
        ArkretMlsGroup::restore_from_state_record(&group.export_state_record().unwrap()).unwrap();
    assert_eq!(group.epoch(), 0);
    assert_eq!(restarted.epoch(), 0);
    let transition = tracker
        .process_public_handshake(&decode(&commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        previous_epoch,
        epoch,
        added_leaves,
        consumed_proposals,
        ..
    } = transition
    else {
        panic!("a governed self-update must be a public Commit")
    };
    assert_eq!((previous_epoch, epoch), (0, 1));
    assert!(added_leaves.is_empty());
    assert_eq!(tracker.leaves().unwrap().len(), 1);
    assert_eq!(consumed_proposals.len(), 1);
    assert_eq!(consumed_proposals[0].proposal_type, 7);
    let public_state = MlsGovernanceBindingPublicState::new(scope, Some(base), 0, 3);
    let authenticated = tracker.governance_binding().unwrap();
    assert_eq!(authenticated, binding);
    crate::verify_governance_binding_against_public_state_and_payload(
        &authenticated,
        &public_state,
        &binding,
    )
    .unwrap();
    for holder in [&mut group, &mut restarted] {
        holder
            .merge_accepted_commit_envelope(&commit, &public_state, &binding)
            .unwrap();
        assert_eq!(holder.epoch(), 1);
        assert!(holder.group.pending_commit().is_none());
    }
}

#[test]
fn rejected_self_update_binding_does_not_stage_or_write_a_commit() {
    let scope = realm_scope();
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let wrong_binding = binding_for_epochs(&scope, event(2), 1, 2, 2);
    let before = snapshot_provider_storage(&group.identity.provider).unwrap();
    assert!(
        group
            .self_update_commit_with_governance_binding(&wrong_binding)
            .is_err()
    );
    assert!(group.group.pending_commit().is_none());
    assert_eq!(
        snapshot_provider_storage(&group.identity.provider).unwrap(),
        before
    );
    assert_eq!(group.epoch(), 0);
}

#[test]
fn public_tracker_follows_the_governed_add_commit_binding() {
    let scope = realm_scope();
    let genesis = genesis_binding(&scope);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis)
        .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    assert_eq!(tracker.governance_binding().unwrap(), genesis);
    assert_eq!(
        tracker.ciphersuite_canonical_id().unwrap(),
        group.group_ciphersuite_canonical_id().unwrap()
    );

    let member = second_identity();
    let binding = transition_binding(&scope, event(9), 1);
    let added = group
        .add_member_with_governance_binding(&claimed_keypackage(&member), &binding)
        .unwrap();
    let transition = tracker
        .process_public_handshake(&decode(&added.commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        previous_epoch,
        epoch,
        added_leaves,
        sender_leaf,
        consumed_proposals,
        ..
    } = transition
    else {
        panic!("an Add Commit is a public Commit transition")
    };
    assert_eq!((previous_epoch, epoch), (0, 1));
    assert_eq!(tracker.governance_binding().unwrap(), binding);
    assert_eq!(
        sender_leaf
            .unwrap()
            .actor_id
            .signing_principal_id()
            .as_str(),
        "ak:did_core:web:mls.example"
    );
    assert_eq!(added_leaves.len(), 1);
    assert_eq!(consumed_proposals.len(), 2);
    assert_eq!(consumed_proposals[0].ordinal, 0);
    assert_eq!(consumed_proposals[0].proposal_type, 1);
    assert_eq!(consumed_proposals[1].ordinal, 1);
    assert_eq!(consumed_proposals[1].proposal_type, 7);
    let parsed_add = crate::verify_add_proposal_leaf(&consumed_proposals[0].proposal_wire).unwrap();
    assert_eq!(parsed_add.actor_id, member.actor_id);
    let accepted_adds = crate::verify_adds_from_accepted_public_commit(
        &decode(&added.commit.commit).unwrap(),
        group.group_id().as_str(),
        previous_epoch,
    )
    .unwrap();
    assert_eq!(accepted_adds, vec![parsed_add.clone()]);
    let mut trailing = decode(&added.commit.commit).unwrap();
    trailing.push(0);
    assert!(
        crate::verify_adds_from_accepted_public_commit(
            &trailing,
            group.group_id().as_str(),
            previous_epoch
        )
        .is_err()
    );
    assert!(
        crate::verify_adds_from_accepted_public_commit(
            &decode(&added.commit.commit).unwrap(),
            &base64url_encode([0; 32]),
            previous_epoch
        )
        .is_err()
    );
    assert!(
        crate::verify_adds_from_accepted_public_commit(
            &decode(&added.commit.commit).unwrap(),
            group.group_id().as_str(),
            epoch,
        )
        .is_err()
    );
    assert_eq!(parsed_add.leaf_signature_key, added_leaves[0].signature_key);
    assert!(crate::verify_add_proposal_leaf(&consumed_proposals[1].proposal_wire).is_err());
    for malformed in [
        &consumed_proposals[0].proposal_wire[..1],
        &consumed_proposals[0].proposal_wire[..consumed_proposals[0].proposal_wire.len() - 1],
    ] {
        assert!(crate::verify_add_proposal_leaf(malformed).is_err());
    }
    let mut trailing = consumed_proposals[0].proposal_wire.clone();
    trailing.push(0);
    assert!(crate::verify_add_proposal_leaf(&trailing).is_err());
    let mut wrong_signature = consumed_proposals[0].proposal_wire.clone();
    *wrong_signature.last_mut().unwrap() ^= 1;
    assert!(crate::verify_add_proposal_leaf(&wrong_signature).is_err());
    assert!(
        consumed_proposals
            .iter()
            .all(|proposal| !proposal.proposal_wire.is_empty())
    );
    assert_eq!(
        consumed_proposals[0].target_after.as_ref(),
        added_leaves.first()
    );
    assert_eq!(
        added_leaves[0].actor_id.signing_principal_id().as_str(),
        "ak:did_core:web:mls-member.example"
    );
}

#[test]
fn agent_runtime_repair_replaces_retired_authorization_in_one_same_group_commit() {
    assert_agent_runtime_repair(false);
}

#[test]
fn agent_same_key_reauthorization_replaces_the_endpoint_without_membership_revision() {
    assert_agent_runtime_repair(true);
}

fn assert_agent_runtime_repair(same_signing_key: bool) {
    let scope = realm_scope();
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let actor = ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:mls-agent.example").unwrap(),
        DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
    ));
    let runtime = |number: u8, key_number: u8| {
        ArkretMlsIdentity::new_agent(
            actor.clone(),
            arkret_wire::DidUrl::new(format!("did:web:mls-agent.example#runtime-{key_number}"))
                .unwrap(),
            event(number),
            crate::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[key_number; 32]),
            ),
        )
        .unwrap()
    };
    let old = runtime(31, 31);
    let first_binding = transition_binding(&scope, event(9), 1);
    let first = group
        .add_member_with_governance_binding(&claimed_keypackage(&old), &first_binding)
        .unwrap();
    group
        .merge_accepted_commit_envelope(
            &first.commit,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(9)), 0, 1),
            &first_binding,
        )
        .unwrap();
    group
        .install_test_leaf_bindings(vec![group.identity.endpoint.clone(), old.endpoint.clone()])
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker =
        crate::MlsPublicGroupTracker::from_external(&info, &tree, group.group_id().as_str(), 1)
            .unwrap();
    let new = runtime(32, if same_signing_key { 31 } else { 32 });
    let package = claimed_keypackage(&new);
    assert_eq!(
        group
            .member_endpoint_replacement_actor(&new.endpoint, &actor)
            .unwrap(),
        Some(actor.clone())
    );
    assert_eq!(
        group
            .member_endpoint_replacement_actor(&new.endpoint, &group.identity.actor_id)
            .unwrap(),
        None
    );
    let second_device = ArkretMlsIdentity::new_test_human_device(
        group.identity.actor_id.clone(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000074").unwrap(),
    )
    .unwrap();
    assert_eq!(
        group
            .member_endpoint_replacement_actor(&second_device.endpoint, &group.identity.actor_id)
            .unwrap(),
        None
    );
    let group_id = group.group_id();
    let second_binding = binding_for_epochs(&scope, event(10), 1, 2, 1);
    let replacement = group
        .replace_member_endpoint(&package, &actor, Some(&second_binding))
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        consumed_proposals,
        added_leaves,
        ..
    } = tracker
        .process_public_handshake(&decode(&replacement.commit.commit).unwrap())
        .unwrap()
    else {
        panic!("runtime replacement must be a signed Commit")
    };
    assert_eq!(added_leaves.len(), 1);
    assert_eq!(added_leaves[0].actor_id, actor);
    let removed = consumed_proposals
        .iter()
        .find_map(|proposal| proposal.target_before.as_ref())
        .unwrap();
    assert_eq!(removed.actor_id, actor);
    assert_eq!(
        removed.signature_key == added_leaves[0].signature_key,
        same_signing_key
    );
    assert_eq!(
        consumed_proposals
            .iter()
            .filter(|proposal| proposal.proposal_type == 3)
            .count(),
        1
    );
    group
        .merge_accepted_commit_envelope(
            &replacement.commit,
            &MlsGovernanceBindingPublicState::new(scope, Some(event(10)), 1, 1),
            &second_binding,
        )
        .unwrap();
    group
        .install_test_leaf_bindings(vec![group.identity.endpoint.clone(), new.endpoint.clone()])
        .unwrap();
    assert_eq!(group.group_id(), group_id);
    assert_eq!(group.epoch(), 2);
    let leaves = group.verified_leaf_bindings().unwrap();
    assert_eq!(leaves.len(), 2);
    assert!(leaves.iter().any(|leaf| leaf.endpoint == new.endpoint));
    assert!(!leaves.iter().any(|leaf| leaf.endpoint == old.endpoint));
    assert!(!replacement.welcome.ciphertext_b64.as_str().is_empty());
}

#[test]
fn public_tracker_freezes_add_context_remove_from_one_signed_commit_in_wire_order() {
    let scope = realm_scope();
    let genesis = genesis_binding(&scope);
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis)
        .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let member = second_identity();
    let first_binding = transition_binding(&scope, event(9), 1);
    let first = group
        .add_member_with_governance_binding(&claimed_keypackage(&member), &first_binding)
        .unwrap();
    tracker
        .process_public_handshake(&decode(&first.commit.commit).unwrap())
        .unwrap();
    group
        .merge_accepted_commit_envelope(
            &first.commit,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(9)), 0, 1),
            &first_binding,
        )
        .unwrap();
    group
        .install_test_leaf_bindings(vec![
            group.identity.endpoint.clone(),
            member.endpoint.clone(),
        ])
        .unwrap();

    let replacement = group
        .replace_member_endpoint(
            &claimed_keypackage(&member),
            &member.actor_id,
            Some(&binding_for_epochs(&scope, event(10), 1, 2, 2)),
        )
        .unwrap();
    let transition = tracker
        .process_public_handshake(&decode(&replacement.commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        consumed_proposals,
        added_leaves,
        ..
    } = transition
    else {
        panic!("replacement is one signed public Commit")
    };
    assert_eq!(consumed_proposals.len(), 3);
    assert_eq!(consumed_proposals[0].ordinal, 0);
    assert_eq!(consumed_proposals[0].proposal_type, 1);
    assert_eq!(consumed_proposals[1].ordinal, 1);
    assert_eq!(consumed_proposals[1].proposal_type, 7);
    assert_eq!(consumed_proposals[2].ordinal, 2);
    assert_eq!(consumed_proposals[2].proposal_type, 3);
    assert!(consumed_proposals.iter().all(|proposal| {
        proposal.sender_leaf.actor_id == group.identity.actor_id
            && !proposal.proposal_wire.is_empty()
    }));
    let removed = consumed_proposals[2].target_before.as_ref().unwrap();
    let added = consumed_proposals[0].target_after.as_ref().unwrap();
    assert_eq!(removed.actor_id, member.actor_id);
    assert_eq!(added.actor_id, member.actor_id);
    let parsed = crate::verify_add_proposal_leaf(&consumed_proposals[0].proposal_wire).unwrap();
    assert_eq!(parsed.actor_id, member.actor_id);
    assert_eq!(parsed.leaf_signature_key, added.signature_key);
    assert_eq!(added_leaves, vec![added.clone()]);
    assert!(consumed_proposals[2].target_after.is_none());
    assert!(consumed_proposals[0].target_before.is_none());
}

#[test]
fn add_proposal_parser_does_not_bind_reused_leaf_index_to_old_device() {
    let scope = realm_scope();
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let first_device = second_identity();
    let first_binding = binding_for_epochs(&scope, event(9), 0, 1, 1);
    let first = group
        .add_member_with_governance_binding(&claimed_keypackage(&first_device), &first_binding)
        .unwrap();
    let first_transition = tracker
        .process_public_handshake(&decode(&first.commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        added_leaves: first_leaves,
        consumed_proposals: first_proposals,
        ..
    } = first_transition
    else {
        panic!("first Add must be a Commit")
    };
    let first_parsed = crate::verify_add_proposal_leaf(&first_proposals[0].proposal_wire).unwrap();
    assert_eq!(
        first_parsed.leaf_signature_key,
        first_leaves[0].signature_key
    );
    group
        .merge_accepted_commit_envelope(
            &first.commit,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(9)), 0, 1),
            &first_binding,
        )
        .unwrap();
    group
        .install_test_leaf_bindings(vec![
            group.identity.endpoint.clone(),
            first_device.endpoint.clone(),
        ])
        .unwrap();

    let remove_binding = binding_for_epochs(&scope, event(10), 1, 2, 2);
    let removed = group
        .remove_members_by_actor_with_governance_binding(
            std::slice::from_ref(&first_device.actor_id),
            &remove_binding,
        )
        .unwrap();
    tracker
        .process_public_handshake(&decode(&removed.commit.commit).unwrap())
        .unwrap();
    group
        .merge_accepted_commit_envelope(
            &removed.commit,
            &MlsGovernanceBindingPublicState::new(scope.clone(), Some(event(10)), 1, 2),
            &remove_binding,
        )
        .unwrap();
    group
        .install_test_leaf_bindings(vec![group.identity.endpoint.clone()])
        .unwrap();

    let new_device = ArkretMlsIdentity::new_test_human_device(
        first_device.actor_id.clone(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000075").unwrap(),
    )
    .unwrap();
    let readd_binding = binding_for_epochs(&scope, event(11), 2, 3, 3);
    let readd = group
        .add_member_with_governance_binding(&claimed_keypackage(&new_device), &readd_binding)
        .unwrap();
    let transition = tracker
        .process_public_handshake(&decode(&readd.commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        added_leaves,
        consumed_proposals,
        ..
    } = transition
    else {
        panic!("second Add must be a Commit")
    };
    assert_eq!(added_leaves[0].leaf_index, first_leaves[0].leaf_index);
    let readd_parsed =
        crate::verify_add_proposal_leaf(&consumed_proposals[0].proposal_wire).unwrap();
    assert_eq!(readd_parsed.actor_id, first_parsed.actor_id);
    assert_eq!(
        readd_parsed.leaf_signature_key,
        added_leaves[0].signature_key
    );
    assert_ne!(
        readd_parsed.leaf_signature_key,
        first_parsed.leaf_signature_key
    );
}

#[test]
fn add_proposal_parser_distinguishes_simultaneous_devices_of_one_actor() {
    let scope = realm_scope();
    let mut group = identity()
        .create_group_with_governance_binding(&scope, &genesis_binding(&scope))
        .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = crate::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let first = second_identity();
    let second = ArkretMlsIdentity::new_test_human_device(
        first.actor_id.clone(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000076").unwrap(),
    )
    .unwrap();
    let binding = transition_binding(&scope, event(9), 1);
    let committed = group
        .add_members_with_optional_governance_binding(
            &[claimed_keypackage(&first), claimed_keypackage(&second)],
            Some(&binding),
            &[],
        )
        .unwrap();
    let transition = tracker
        .process_public_handshake(&decode(&committed.commit.commit).unwrap())
        .unwrap();
    let crate::MlsPublicHandshakeTransition::Commit {
        added_leaves,
        consumed_proposals,
        ..
    } = transition
    else {
        panic!("two Add Proposals must be one Commit")
    };
    let parsed = consumed_proposals
        .iter()
        .filter(|proposal| proposal.proposal_type == 1)
        .map(|proposal| crate::verify_add_proposal_leaf(&proposal.proposal_wire).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].actor_id, parsed[1].actor_id);
    assert_ne!(parsed[0].leaf_signature_key, parsed[1].leaf_signature_key);
    assert_eq!(added_leaves.len(), 2);
    assert_ne!(added_leaves[0].leaf_index, added_leaves[1].leaf_index);
    for leaf in added_leaves {
        assert!(parsed.iter().any(|add| {
            add.actor_id == leaf.actor_id && add.leaf_signature_key == leaf.signature_key
        }));
    }
}

#[test]
fn outbound_commit_stays_pending_until_authority_acceptance() {
    let mut group = identity().create_group(&realm_scope()).unwrap();
    let base_epoch = group.epoch();

    let commit = group.self_update_commit().unwrap();

    assert_eq!(group.epoch(), base_epoch);
    assert_eq!(commit.epoch, base_epoch + 1);
}
