//! A member who joined from a Welcome can add the next member: the Welcome it
//! seals carries the ratchet tree the added member joins with
//! (encryption-and-audit.md §2.2, RFC 9420 §12.4.3.3).

use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsMemberAdditionArtifacts};
use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload, MlsKeyPackageState};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventFullView, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, DeviceId, DidCoreId, DidUrl, Event,
    EventId, EventKind, Hash, KeypackageClaimId, MlsWelcomeDelivery, MlsWelcomeDeliveryId,
    MlsWelcomeRecipientEndpoint, RealmCommit, RealmCommitAuthorityRef, RealmCommitId, RealmId,
    ScopeRef,
};

const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";

/// RFC/local-journal verification; these synthetic authority receipts do not
/// represent native service admission or product recovery acceptance.
#[test]
fn fresh_external_candidate_survives_restart_and_requires_exact_acceptance() {
    use arkret_mls::{MlsVerifiedLeafBinding, PreparedMlsRecoveryExternalCommit};
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialResponseBody;
    use arkret_models_crypto::{ContentEndpoint, ContentRecoveryBinding, MlsCommitEnvelope};
    use arkret_wire::{Base64UrlString, BlobRef, MlsGroupValue, NonEmptyString};

    fn blob(bytes: &[u8]) -> BlobRef {
        BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::canonical::sha256_digest(bytes)
        ))
        .unwrap()
    }
    fn key(seed: u8) -> Base64UrlString {
        Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap()
    }
    fn bindings(group: &ArkretMlsGroup) -> Vec<MlsVerifiedLeafBinding> {
        group
            .active_author_leaves()
            .into_iter()
            .map(|leaf| {
                let seed = [1, 2, 9]
                    .into_iter()
                    .find(|seed| {
                        key(*seed).as_str()
                            == arkret_canonical::base64url_encode(&leaf.signature_key)
                    })
                    .unwrap();
                MlsVerifiedLeafBinding {
                    leaf_index: leaf.leaf_index,
                    actor_id: if seed == 2 {
                        actor("bob")
                    } else {
                        actor("alice")
                    },
                    endpoint: identity(
                        &if seed == 2 {
                            actor("bob")
                        } else {
                            actor("alice")
                        },
                        seed,
                    )
                    .endpoint_identity(),
                    signature_key: key(seed),
                    device_authorize_event_id: Some(EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [seed; 32],
                    )),
                }
            })
            .collect()
    }
    fn set_payload(view: &mut CommittedEventFullView, payload: MlsCommitPayload) {
        let serde_json::Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
            unreachable!()
        };
        view.event.payload = payload.into_iter().collect();
    }
    let alice = actor("alice");
    let genesis = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x72; 32]);
    let mut old = identity(&alice, 1)
        .create_group_with_governance_binding(
            &scope(),
            &MlsGovernanceBindingPayload::new(scope(), None, 0, 0, 0).unwrap(),
        )
        .unwrap();
    old.install_local_creator_binding(
        alice.clone(),
        Some(EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        )),
    )
    .unwrap();
    let base_binding =
        MlsGovernanceBindingPayload::new(scope(), Some(genesis.clone()), 0, 1, 0).unwrap();
    let add = old
        .add_member_with_governance_binding(
            &claimed(&identity(&actor("bob"), 2), 0x81),
            &base_binding,
        )
        .unwrap();
    let before = old.export_state_record().unwrap();
    let (info, tree) = old
        .pending_public_group_state_bytes(&add.commit, &base_binding)
        .unwrap();
    assert_eq!(
        old.export_state_record().unwrap().serialized_state,
        before.serialized_state
    );
    assert_eq!(old.epoch(), 0);
    let mut base = accepted(&alice, &genesis, &add, base_binding.clone(), 1);
    set_payload(
        &mut base,
        MlsCommitPayload::new(
            genesis.clone(),
            0,
            &add.commit,
            base_binding,
            blob(&info),
            blob(&tree),
        )
        .unwrap(),
    );
    old.install_recovered_own_commit(&base, &genesis).unwrap();
    old.install_verified_leaf_bindings(bindings(&old)).unwrap();
    let material = MlsGroupStateMaterialResponseBody {
        realm_id: RealmId::new(REALM).unwrap(),
        effective_scope: scope(),
        mls_group_id: scope().canonical_mls_group_id().unwrap(),
        epoch: 1,
        group_state_event_id: base.event.event_id.clone(),
        group_info_ref: blob(&info),
        group_info_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(&info))
            .unwrap(),
        ratchet_tree_ref: blob(&tree),
        ratchet_tree_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(&tree))
            .unwrap(),
    };
    let current = MlsGroupValue {
        effective_scope: scope(),
        genesis_event_ref: genesis,
        cipher_suite: NonEmptyString::new(arkret_mls::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap(),
        current_mls_commit_event_ref: base.event.event_id.clone(),
        epoch: 1,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: blob(&tree),
    };
    let recovery = ContentRecoveryBinding {
        replacement: ContentEndpoint {
            actor_id: alice.clone(),
            endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: device(9),
            },
            authorization_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [9; 32],
            ),
            signature_key_base64url: key(9).as_str().to_owned(),
        },
        authorization_event_ref: EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ),
        base_group_state_ref: base.event.event_id.clone(),
        expected_epoch: 1,
        inventory_digest: Hash::new(format!("sha256:{}", "77".repeat(32))).unwrap(),
    };
    let next =
        MlsGovernanceBindingPayload::new(scope(), Some(base.event.event_id.clone()), 1, 2, 0)
            .unwrap();
    let fresh = identity(&alice, 9);
    let endpoint = fresh.endpoint_identity();
    let prepared = PreparedMlsRecoveryExternalCommit::prepare(
        fresh, &base, &material, &current, &recovery, &next,
    )
    .unwrap();
    let frozen = prepared.export_private_state().unwrap();
    let original_commit = prepared.commit().clone();
    let (new_info, new_tree) = prepared.public_group_state_bytes().unwrap();
    drop(prepared);
    let restore = || {
        PreparedMlsRecoveryExternalCommit::restore_private_state(
            &frozen, &alice, &endpoint, &recovery, &current,
        )
        .unwrap()
    };
    let resumed = restore();
    assert_eq!(resumed.commit(), &original_commit);
    assert_eq!(
        resumed.public_group_state_bytes().unwrap(),
        (new_info.clone(), new_tree.clone())
    );
    let mut wrong_episode = recovery.clone();
    wrong_episode.inventory_digest = Hash::new(format!("sha256:{}", "88".repeat(32))).unwrap();
    assert!(
        PreparedMlsRecoveryExternalCommit::restore_private_state(
            &frozen,
            &alice,
            &endpoint,
            &wrong_episode,
            &current
        )
        .is_err()
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&frozen).unwrap();
    tampered["evidence"]["binding"]["key_access_revision"] = "1".into();
    assert!(
        PreparedMlsRecoveryExternalCommit::restore_private_state(
            &serde_json::to_vec(&tampered).unwrap(),
            &alice,
            &endpoint,
            &recovery,
            &current
        )
        .is_err()
    );
    let mut view = accepted(
        &alice,
        &base.event.event_id,
        &MlsMemberAdditionArtifacts {
            commit: original_commit.clone(),
            welcome: add.welcome,
        },
        next.clone(),
        2,
    );
    let payload = MlsCommitPayload::new(
        base.event.event_id.clone(),
        0,
        &original_commit,
        next,
        blob(&new_info),
        blob(&new_tree),
    )
    .unwrap()
    .with_recovery_binding(recovery.clone())
    .unwrap();
    set_payload(&mut view, payload);
    let publication =
        arkret_models_collaboration::authority_commit::MlsGroupStateMaterial::from_bytes(
            &new_info, &new_tree,
        );
    assert_eq!(
        publication.decode_for_event(&view.event).unwrap(),
        (new_info.clone(), new_tree.clone())
    );
    let wrong_publication =
        arkret_models_collaboration::authority_commit::MlsGroupStateMaterial::from_bytes(
            &info, &tree,
        );
    assert_eq!(
        wrong_publication
            .decode_for_event(&view.event)
            .unwrap_err()
            .error_code(),
        Some(arkret_wire::ErrorCode::DigestMismatch)
    );
    let mut wrong = view.clone();
    wrong.event.actor_id = actor("bob");
    assert!(restore().install_accepted(&wrong, Vec::new()).is_err());
    let mut tampered = view.clone();
    tampered.event.payload.insert(
        "group_info_ref".into(),
        serde_json::to_value(blob(b"wrong material")).unwrap(),
    );
    assert!(restore().install_accepted(&tampered, Vec::new()).is_err());
    assert!(restore().install_accepted(&view, Vec::new()).is_err());

    // RFC leaves do not identify endpoints; this map models the independently
    // verified native roster result and is checked against exact tree keys.
    let post_leaves = arkret_mls::validate_public_group_state(
        &new_info,
        &new_tree,
        scope().canonical_mls_group_id().unwrap().as_str(),
        2,
    )
    .unwrap();
    let post_bindings = post_leaves
        .iter()
        .map(|leaf| {
            let seed = if leaf.signature_key == key(1) {
                1
            } else if leaf.signature_key == key(2) {
                2
            } else {
                9
            };
            MlsVerifiedLeafBinding {
                leaf_index: leaf.leaf_index,
                actor_id: leaf.actor_id.clone(),
                endpoint: identity(&leaf.actor_id, seed).endpoint_identity(),
                signature_key: leaf.signature_key.clone(),
                device_authorize_event_id: Some(EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [seed; 32],
                )),
            }
        })
        .collect();
    let recovered = resumed.install_accepted(&view, post_bindings).unwrap();
    assert_eq!(recovered.group_id(), old.group_id());
    recovered
        .verify_installed_historical_base(&view, &view.event.event_id)
        .unwrap();
    let checkpoint = recovered.export_state_record().unwrap();
    drop(recovered);
    let mut recovered = ArkretMlsGroup::restore_from_state_record(&checkpoint).unwrap();
    recovered
        .verify_installed_historical_base(&view, &view.event.event_id)
        .unwrap();
    let mut corrupt = checkpoint;
    let mut state: serde_json::Value = serde_json::from_slice(&corrupt.serialized_state).unwrap();
    state["installed_recovery"]["commit"]["commit_digest"] =
        format!("sha256:{}", "88".repeat(32)).into();
    corrupt.serialized_state = serde_json::to_vec(&state).unwrap();
    assert!(ArkretMlsGroup::restore_from_state_record(&corrupt).is_err());

    old.install_recovered_remote_commit(&view, &base.event.event_id)
        .unwrap();
    old.install_verified_leaf_bindings(bindings(&old)).unwrap();
    let root_context = arkret_models_crypto::ContentRootContext {
        effective_scope: scope(),
        genesis_event_ref: current.genesis_event_ref.clone(),
        epoch: 2,
        group_state_ref: view.event.event_id.clone(),
        cipher_suite: arkret_mls::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: current.genesis_event_ref.clone(),
    };
    let old_root = old.export_content_root(&root_context).unwrap();
    // The External Commit alone does not isolate the old member. Business
    // writes must remain fenced until the subsequent Remove is accepted.
    assert_eq!(
        old_root,
        recovered.export_content_root(&root_context).unwrap()
    );

    let old_index = recovered
        .verified_leaf_bindings()
        .unwrap()
        .into_iter()
        .find(|leaf| leaf.signature_key == key(1))
        .unwrap()
        .leaf_index;
    let cleanup_binding =
        MlsGovernanceBindingPayload::new(scope(), Some(view.event.event_id.clone()), 2, 3, 0)
            .unwrap();
    let removal = recovered
        .remove_members_by_leaf_indices_with_governance_binding(&[old_index], &cleanup_binding)
        .unwrap();
    let (cleanup_info, cleanup_tree) = recovered
        .pending_public_group_state_bytes(&removal.commit, &cleanup_binding)
        .unwrap();
    let mut cleanup = view.clone();
    cleanup.event.event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
    cleanup.commit.event_ref = cleanup.event.event_id.clone();
    cleanup.commit.commit_id = RealmCommitId::from_digest([3; 32]);
    cleanup.commit.stream_position = 3;
    let envelope = MlsCommitEnvelope {
        ratchet_tree: None,
        ..removal.commit
    };
    let mut cleanup_recovery = recovery;
    cleanup_recovery.base_group_state_ref = view.event.event_id.clone();
    cleanup_recovery.expected_epoch = 2;
    set_payload(
        &mut cleanup,
        MlsCommitPayload::new(
            view.event.event_id.clone(),
            0,
            &envelope,
            cleanup_binding,
            blob(&cleanup_info),
            blob(&cleanup_tree),
        )
        .unwrap()
        .with_recovery_binding(cleanup_recovery.clone())
        .unwrap(),
    );
    recovered
        .install_recovered_own_commit(&cleanup, &view.event.event_id)
        .unwrap();
    recovered
        .install_verified_leaf_bindings(bindings(&recovered))
        .unwrap();
    recovered
        .verify_installed_historical_base(&cleanup, &cleanup.event.event_id)
        .unwrap();
    assert_eq!(recovered.verified_leaf_bindings().unwrap().len(), 2);
    assert!(
        recovered
            .verified_leaf_bindings()
            .unwrap()
            .iter()
            .any(|leaf| leaf.actor_id == actor("bob"))
    );
    assert!(
        recovered
            .verified_leaf_bindings()
            .unwrap()
            .iter()
            .all(|leaf| leaf.signature_key != key(1))
    );
    let restored =
        ArkretMlsGroup::restore_from_state_record(&recovered.export_state_record().unwrap())
            .unwrap();
    restored
        .verify_installed_historical_base(&cleanup, &cleanup.event.event_id)
        .unwrap();
    let mut future_context = root_context;
    future_context.epoch = 3;
    future_context.group_state_ref = cleanup.event.event_id.clone();
    let future_root = restored.export_content_root(&future_context).unwrap();
    assert_ne!(old_root, future_root);
    assert!(old.export_content_root(&future_context).is_err());
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let mut context: arkret_models_crypto::ContentContext =
        serde_json::from_value(fixture["kat"]["content_context"].clone()).unwrap();
    context.root_context = future_context;
    context.producer = cleanup_recovery.replacement;
    context.root_ref =
        arkret_crypto::content_history::content_root_ref(&future_root, &context.root_context)
            .unwrap();
    assert!(arkret_crypto::content_history::derive_content_key(&future_root, &context).is_ok());
    assert!(arkret_crypto::content_history::derive_content_key(&old_root, &context).is_err());
}

#[test]
fn attachment_exporter_restores_the_same_key_and_rejects_scope_epoch_drift() {
    use arkret_mls::exporter_kdf::derive_attachment_content_key;
    use arkret_models_crypto::{AttachmentContentKeyContext, AttachmentContentKeySalt};
    let mut group = identity(&actor("attachment-author"), 9)
        .create_group_with_governance_binding(
            &scope(),
            &MlsGovernanceBindingPayload::new(scope(), None, 0, 0, 0).unwrap(),
        )
        .unwrap();
    group
        .install_local_creator_binding(
            actor("attachment-author"),
            Some(EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x74; 32],
            )),
        )
        .unwrap();
    let context = AttachmentContentKeyContext {
        effective_scope: scope(),
        genesis_event_ref: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x72; 32]),
        epoch: group.epoch(),
        scheme: "ak.blob.stream_aead.v1".into(),
        encryption_algorithm: "mls_exporter_aead_xchacha20poly1305_stream".into(),
        content_key_salt: AttachmentContentKeySalt::from_bytes([1; 32]),
        producer: arkret_models_crypto::ContentEndpoint {
            actor_id: actor("attachment-author"),
            endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: device(9),
            },
            authorization_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x74; 32],
            ),
            signature_key_base64url: arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        },
    };
    let root_context = arkret_models_crypto::ContentRootContext {
        effective_scope: context.effective_scope.clone(),
        genesis_event_ref: context.genesis_event_ref.clone(),
        epoch: context.epoch,
        group_state_ref: context.genesis_event_ref.clone(),
        cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: context.genesis_event_ref.clone(),
    };
    let checkpoint = group.export_state_record().unwrap();
    let original = derive_attachment_content_key(&group, &root_context, &context).unwrap();
    let restored = ArkretMlsGroup::restore_from_state_record(&checkpoint).unwrap();
    assert_eq!(
        original.as_slice(),
        derive_attachment_content_key(&restored, &root_context, &context)
            .unwrap()
            .as_slice()
    );
    let mut changed = context.clone();
    changed.content_key_salt = AttachmentContentKeySalt::from_bytes([2; 32]);
    assert_ne!(
        original.as_slice(),
        derive_attachment_content_key(&restored, &root_context, &changed)
            .unwrap()
            .as_slice()
    );
    changed = context.clone();
    changed.epoch += 1;
    assert!(derive_attachment_content_key(&restored, &root_context, &changed).is_err());
    changed = context;
    changed.effective_scope = ScopeRef::Realm {
        realm_id: RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x73; 32],
        )),
    };
    assert!(derive_attachment_content_key(&restored, &root_context, &changed).is_err());
    assert_eq!(
        restored.export_state_record().unwrap().serialized_state,
        checkpoint.serialized_state
    );
}

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
        signature: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

/// The accepted `ak.mls.commit` carrying `add`, over `base` at `position`.
fn accepted(
    committer: &ActorId,
    base: &EventId,
    add: &MlsMemberAdditionArtifacts,
    binding: MlsGovernanceBindingPayload,
    position: u64,
) -> CommittedEventFullView {
    let payload = MlsCommitPayload::new(
        base.clone(),
        0,
        &add.commit,
        binding,
        arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", "11".repeat(32))).unwrap(),
        arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", "22".repeat(32))).unwrap(),
    )
    .unwrap();
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
        producer_signer_fact_digest: None,
        signature: signature(DetachedSignatureContext::RealmCommit),
    };
    CommittedEventFullView { commit, event }
}

fn delivery(
    view: &CommittedEventFullView,
    recipient: &ActorId,
    endpoint: &DeviceId,
    add: &MlsMemberAdditionArtifacts,
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
        ciphertext_base64url: add.welcome.ciphertext_base64url.clone(),
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
    let bob_package = claimed(&bob_identity, 0x81);
    assert!(
        bob_identity
            .holds_private_key_package(&bob_package)
            .unwrap()
    );
    assert!(
        !identity(&carol, 3)
            .holds_private_key_package(&bob_package)
            .unwrap()
    );
    let first = alice_group
        .add_member_with_governance_binding(&bob_package, &first_binding)
        .unwrap();
    let first_view = accepted(&alice, &genesis, &first, first_binding, 1);
    let queued = delivery(&first_view, &bob, &device(2), &first);
    assert!(arkret_mls::welcome_addresses_key_package(&queued, &bob_package).unwrap());
    assert!(
        arkret_mls::welcome_addresses_key_package(&queued, &claimed(&bob_identity, 0x83))
            .is_ok_and(|matched| !matched)
    );
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
