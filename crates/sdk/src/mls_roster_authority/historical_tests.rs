//! Public RFC/roster composition only. The supplied own-Station projection
//! models an already qualified source; this is not Native admission or 24-word
//! recovery evidence. Writer private MLS state and endpoint keys are dropped.

use arkret_canonical::{DigestSuite, canonical_json_bytes, canonical_sha256, sha256_bytes};
use arkret_models_collaboration::mls_roster_authority::{
    MlsRosterAuthorityManifest, MlsRosterAuthorityReadResponseBody, MlsRosterSigningKey,
};
use arkret_models_crypto::{
    ContentContext, ContentEncryptionAlgorithm, ContentProtection, ContentPurpose,
    ContentRootSecret, EventContentPreEncryptionHeader, EventContentRoutingContext,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, BlobRef, Did, DidCoreId, DidUrl, EncryptedPayloadScheme,
    RealmCommit, RealmCommitId, RealmId, ScopeRef,
};
use serde_json::json;

use super::*;

const STATION_METHOD: &str = "did:web:archive-station.example#roster";
const NATIVE_METHOD: &str =
    "did:web:archive-alice.example#ak:device:01904100-0000-7000-8000-000000000001";

fn signed_event(event: Event, seed: [u8; 32]) -> Event {
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        Did::new("did:web:archive-alice.example").unwrap(),
        DidUrl::new(NATIVE_METHOD).unwrap(),
    );
    arkret_test_kit::signed_event::sign_verifiable_event(event, &signer, DigestSuite::Sha256)
        .unwrap()
        .expect_verifiable()
}

fn covering_commit(event: Event) -> CommittedEventFullView {
    let root = EventId::from_digest(
        event.realm_id.digest_suite_code().digest_suite(),
        event.realm_id.digest_bytes(),
    );
    let mut body = json!({
        "realm_id":event.realm_id,"stream_ref":arkret_wire::CommitStreamRef::Realm { realm_id:event.realm_id.clone() },
        "stream_position":0,"previous_commit_ref":null,"event_ref":event.event_id,
        "governance_generation":"0","authority_ref":root,
        "committed_at":arkret_canonical::format_timestamp_canonical(event.created_at),
    });
    body["commit_id"] = serde_json::to_value(RealmCommitId::from_digest(sha256_bytes(
        canonical_json_bytes(&body).unwrap(),
    )))
    .unwrap();
    body["signature"] = serde_json::to_value(
        arkret_signatures::detached_object::sign_detached_object(
            &body,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            DidUrl::new(STATION_METHOD).unwrap(),
            event.created_at,
            &ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let commit: RealmCommit = serde_json::from_value(body).unwrap();
    commit.validate_content_address().unwrap();
    CommittedEventFullView { event, commit }
}

fn sign_manifest(mut body: serde_json::Value) -> MlsRosterAuthorityManifest {
    let mut bytes = b"ak.mls_roster_authority_manifest.v1\n".to_vec();
    bytes.extend(canonical_json_bytes(&body).unwrap());
    body["signature"] = serde_json::to_value(
        arkret_signatures::keypackages::sign_keypackage_signing_input(
            &[43; 32],
            STATION_METHOD,
            &bytes,
        )
        .unwrap(),
    )
    .unwrap();
    serde_json::from_value(body).unwrap()
}

struct Fixture {
    request: MlsMemberRosterAuthorityReadRequestBody,
    pages: Vec<MlsSelfRosterAuthorityReadResponseBody>,
    genesis: CommittedEventFullView,
    material: MlsGroupStateMaterialResponseBody,
    context: ContentRootContext,
    root: ContentRootSecret,
    original: Event,
    envelope: EncryptedEnvelope,
    native_public: [u8; 32],
    recovery: BTreeMap<EventId, MlsGroupStateMaterialResponseBody>,
}

impl Fixture {
    fn input(&self) -> MlsHistoricalContentRosterMaterials<'_> {
        MlsHistoricalContentRosterMaterials {
            request: &self.request,
            pages: &self.pages,
            genesis_original: Some(&self.genesis),
            genesis_material: &self.material,
            content_original: Some(&self.genesis),
            content_material: &self.material,
            recovery_material: &self.recovery,
            root_context: &self.context,
        }
    }
}

fn fixture() -> Fixture {
    let (fixture, group) = fixture_with_group();
    drop(group);
    fixture
}

fn fixture_with_group() -> (Fixture, arkret_mls::ArkretMlsGroup) {
    let scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
    };
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:archive-alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:archive-station.example").unwrap(),
    ));
    let device =
        arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
    let authorize = EventId::from_digest(DigestSuite::Sha256, [18; 32]);
    let mut leaf_seed = [0; 32];
    getrandom::fill(&mut leaf_seed).unwrap();
    let mut native_seed = [0; 32];
    getrandom::fill(&mut native_seed).unwrap();
    let native_public = ed25519_dalek::SigningKey::from_bytes(&native_seed)
        .verifying_key()
        .to_bytes();
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&leaf_seed),
        ),
    )
    .unwrap();
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    group
        .install_local_creator_binding(actor.clone(), Some(authorize.clone()))
        .unwrap();
    let producer = group.local_content_endpoint().unwrap();
    assert_ne!(
        producer.signature_key_base64url,
        arkret_canonical::base64url_encode(native_public)
    );
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let blob = |bytes: &[u8]| {
        BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(bytes)
        ))
        .unwrap()
    };
    let info_ref = blob(&info);
    let tree_ref = blob(&tree);
    let epoch = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        EventKind::MlsGenesis.as_str(), scope.clone(), actor.clone(), json!({
            "cipher_suite":group.group_ciphersuite_canonical_id().unwrap(),
            "group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,
            "creator_leaf_authority":{"leaf_signature_key_base64url":producer.signature_key_base64url,
                "endpoint":producer.endpoint,"authorization_event_ref":authorize},
            "governance_binding":binding,"created_at":"2026-11-10T00:00:00.000Z",
        }),
    ).build_unsigned().unwrap();
    let genesis = covering_commit(signed_event(epoch, native_seed));
    let context = ContentRootContext {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis.event.event_id.clone(),
        epoch: 0,
        group_state_ref: genesis.event.event_id.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id().unwrap().to_owned(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: EventId::from_digest(
            scope.realm_id().digest_suite_code().digest_suite(),
            scope.realm_id().digest_bytes(),
        ),
    };
    let root = group.export_content_root(&context).unwrap();
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &context).unwrap();
    let vectors =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let protection = ContentProtection {
        root_refs: vec![root_ref.clone()],
        blob_refs: vec![],
        backup_refs: serde_json::from_value(
            vectors["kat"]["envelope"]["encryption_context"]["protection"]["backup_refs"].clone(),
        )
        .unwrap(),
    };
    let mut original = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        EventKind::MessageCreate.as_str(), scope.clone(), actor.clone(), json!({
            "strand_id":arkret_wire::StrandId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [29;32])),"track_name":"discussion",
            "content":{"kind":"ak.content.text","body":"original archive body","format":"plain"},
        }),
    ).build_unsigned().unwrap();
    let content = ContentContext {
        root_context: context.clone(),
        root_ref,
        purpose: ContentPurpose::EventBody,
        encryption_scheme: EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer,
        content_key_salt: arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
    };
    let key = arkret_crypto::content_history::derive_content_key(&root, &content).unwrap();
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/json",
        EncryptedPayloadScheme::EpochContentAead,
        scope.clone(),
        original.kind.as_str(),
        0,
        genesis.event.event_id.clone(),
        group.local_content_sender_domain().unwrap(),
        EventContentRoutingContext::None,
        EventContentMaterial {
            key_commitment: arkret_crypto::content_history::content_key_commitment(&content, &key)
                .unwrap(),
            content_context: content,
            outer_event: EventContentMaterial::outer_event_for(&original).unwrap(),
            protection,
        },
    )
    .unwrap();
    let encrypted = group
        .encrypt_payload(header, b"original archive body")
        .unwrap();
    let envelope = encrypted.to_envelope().unwrap();
    original.payload.remove("content");
    original.payload.insert(
        "encrypted_content".into(),
        serde_json::to_value(&envelope).unwrap(),
    );
    let original = signed_event(original, native_seed);
    let request = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: scope.realm_id().clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        target_commit_event_ref: genesis.event.event_id.clone(),
        target_epoch: 0,
        caller_actor_id: actor.clone(),
        cursor: None,
    };
    let material = MlsGroupStateMaterialResponseBody {
        realm_id: request.realm_id.clone(),
        effective_scope: scope,
        mls_group_id: request.mls_group_id.clone(),
        epoch: 0,
        group_state_event_id: genesis.event.event_id.clone(),
        group_info_ref: info_ref.clone(),
        group_info_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(&info))
            .unwrap(),
        ratchet_tree_ref: tree_ref.clone(),
        ratchet_tree_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(&tree))
            .unwrap(),
    };
    let records = vec![MlsRosterRecord::Genesis {
        genesis_event_ref: genesis.event.event_id.clone(),
        actor_id: actor,
        leaf_signature_key_base64url: Base64UrlString::new(
            group
                .local_content_endpoint()
                .unwrap()
                .signature_key_base64url,
        )
        .unwrap(),
        endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id: device },
        authorization_event_ref: authorize,
    }];
    let manifest = sign_manifest(json!({
        "governance_station_id":"ak:did_core:web:archive-station.example","realm_id":request.realm_id,
        "effective_scope":request.effective_scope,"mls_group_id":request.mls_group_id,
        "genesis_event_ref":genesis.event.event_id,"group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,
        "target_commit_event_ref":genesis.event.event_id,"target_epoch":"0","authority_head_commit_event_ref":genesis.event.event_id,
        "caller_actor_id":request.caller_actor_id,"total_record_count":1,"page_count":1,
        "records_digest":canonical_sha256(&records).unwrap(),"issued_at":"2026-11-10T00:00:00.000Z",
    }));
    let pages = vec![MlsSelfRosterAuthorityReadResponseBody {
        roster: MlsRosterAuthorityReadResponseBody {
            manifest,
            page_index: 0,
            records,
            next_cursor: None,
        },
        manifest_signing_key: MlsRosterSigningKey {
            verification_method: DidUrl::new(STATION_METHOD).unwrap(),
            public_key_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                    .verifying_key()
                    .as_bytes(),
            ))
            .unwrap(),
        },
        add_signing_keys: vec![],
        recovery_signing_keys: None,
    }];
    (
        Fixture {
            request,
            pages,
            genesis,
            material,
            context,
            root,
            original,
            envelope,
            native_public,
            recovery: BTreeMap::new(),
        },
        group,
    )
}

#[test]
fn public_epoch_opens_the_original_without_any_private_mls_state() {
    let input = fixture();
    let roster = verify_mls_self_historical_content_roster(input.input()).unwrap();
    let material = roster
        .content_material_for_verified_original(&input.original, &input.envelope)
        .unwrap();
    assert_ne!(
        material.content_context.producer.signature_key_base64url,
        arkret_canonical::base64url_encode(input.native_public)
    );
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&input.original)
        .unwrap();
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        input.original.producer_proof.as_ref().unwrap(),
        &bytes,
        &input.original.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: input.native_public.to_vec(),
        },
        DigestSuite::Sha256,
    )
    .unwrap();
    let header = input
        .envelope
        .reconstruct_pre_encryption_header(
            EncryptedPayloadScheme::EpochContentAead,
            input.original.scope_ref.clone(),
            input.original.kind.as_str(),
            std::str::from_utf8(
                &arkret_models_crypto::mls_basic_credential_identity(
                    input.original.actual_signer(),
                )
                .unwrap(),
            )
            .unwrap(),
            None,
            material,
        )
        .unwrap();
    assert_eq!(
        arkret_crypto::content_history::open_content(
            &input.root,
            &header,
            &input.envelope.ciphertext
        )
        .unwrap(),
        b"original archive body"
    );
}

#[test]
fn historical_public_material_rejects_wrong_epoch_root_basis_and_signed_leaf_substitution() {
    let mut input = fixture();
    input.material.epoch = 1;
    assert!(verify_mls_self_historical_content_roster(input.input()).is_err());
    input.material.epoch = 0;
    input.context.genesis_event_ref = EventId::from_digest(DigestSuite::Sha256, [90; 32]);
    assert!(verify_mls_self_historical_content_roster(input.input()).is_err());
    input.context.genesis_event_ref = input.genesis.event.event_id.clone();
    let MlsRosterRecord::Genesis {
        authorization_event_ref,
        ..
    } = &mut input.pages[0].roster.records[0]
    else {
        unreachable!()
    };
    *authorization_event_ref = EventId::from_digest(DigestSuite::Sha256, [91; 32]);
    let mut body = serde_json::to_value(&input.pages[0].roster.manifest).unwrap();
    body.as_object_mut().unwrap().remove("signature");
    body["records_digest"] = json!(canonical_sha256(&input.pages[0].roster.records).unwrap());
    input.pages[0].roster.manifest = sign_manifest(body);
    assert!(
        verify_mls_self_historical_content_roster(input.input()).is_err(),
        "a genuine service signature cannot replace the original creator authority"
    );
}

fn later_reader_fixture() -> Fixture {
    use arkret_models_collaboration::mls_roster_authority::MlsRosterAddSigningKeys;
    use arkret_models_crypto::MlsKeyPackageState;

    let (mut input, mut group) = fixture_with_group();
    let (_, template, _) = super::super::tests::signed_two_page_roster();
    let mut record = template[1].records[0].clone();
    let MlsRosterRecord::Add { attestation, .. } = &record else {
        unreachable!()
    };
    let actor = attestation.actor_id.clone();
    let arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method,
    } = &attestation.endpoint
    else {
        unreachable!()
    };
    let member = arkret_mls::ArkretMlsIdentity::new_agent(
        actor.clone(),
        verification_method.clone(),
        attestation.authorization_event_ref.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[47; 32]),
        ),
    )
    .unwrap();
    let mut package = member.key_package_record().unwrap();
    package.state = MlsKeyPackageState::Claimed;
    package.claim_id = Some(attestation.claim_id.to_string());
    let info =
        arkret_canonical::base64url_decode(input.material.group_info_base64url.as_str()).unwrap();
    let tree =
        arkret_canonical::base64url_decode(input.material.ratchet_tree_base64url.as_str()).unwrap();
    let mut tracker =
        MlsPublicGroupTracker::from_external(&info, &tree, input.request.mls_group_id.as_str(), 0)
            .unwrap();
    let binding = MlsGovernanceBindingPayload::new(
        input.context.effective_scope.clone(),
        Some(input.genesis.event.event_id.clone()),
        0,
        1,
        1,
    )
    .unwrap();
    let added = group
        .add_member_with_governance_binding(&package, &binding)
        .unwrap();
    let transition = tracker
        .process_public_handshake(
            &arkret_canonical::base64url_decode(&added.commit.commit).unwrap(),
        )
        .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = transition
    else {
        unreachable!()
    };
    let proposal = consumed_proposals
        .iter()
        .find(|proposal| proposal.proposal_type == 1)
        .unwrap();
    let parsed = arkret_mls::verify_add_proposal_leaf(&proposal.proposal_wire).unwrap();
    assert_eq!(parsed.actor_id, actor);
    assert!(
        tracker
            .leaves()
            .unwrap()
            .iter()
            .any(|leaf| leaf.actor_id == actor)
    );
    let (info, tree) = group
        .pending_public_group_state_bytes(&added.commit, &binding)
        .unwrap();
    let blob = |bytes: &[u8]| {
        BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(bytes)
        ))
        .unwrap()
    };
    let payload = MlsCommitPayload::new(
        input.genesis.event.event_id.clone(),
        1,
        &added.commit,
        binding,
        blob(&info),
        blob(&tree),
    )
    .unwrap();
    let original = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        EventKind::MlsCommit.as_str(),
        input.context.effective_scope.clone(),
        input.original.actor_id.clone(),
        serde_json::to_value(payload).unwrap(),
    )
    .build_unsigned()
    .unwrap();
    // This source models an already qualified own-Station result, not Native
    // membership admission. The Add itself is real RFC wire and is validated.
    let commit = signed_event(original, [48; 32]);
    let MlsRosterRecord::Add {
        commit_event_ref,
        sender_actor_id,
        proposal_wire_base64url,
        attestation,
        ..
    } = &mut record
    else {
        unreachable!()
    };
    *commit_event_ref = commit.event_id.clone();
    *sender_actor_id = input.original.actor_id.clone();
    *proposal_wire_base64url =
        Base64UrlString::new(arkret_canonical::base64url_encode(&proposal.proposal_wire)).unwrap();
    attestation.realm_id = input.request.realm_id.clone();
    attestation.effective_scope = input.request.effective_scope.clone();
    attestation.mls_group_id = input.request.mls_group_id.clone();
    attestation.genesis_event_ref = input.genesis.event.event_id.clone();
    attestation.commit_event_ref = commit.event_id.clone();
    attestation.leaf_signature_key_base64url = parsed.leaf_signature_key;
    attestation.claim_record_digest =
        arkret_wire::Hash::new(canonical_sha256(&package).unwrap()).unwrap();
    let receipt = &mut attestation.claim_receipt;
    receipt.request.intended_realm_id = input.request.realm_id.clone();
    receipt.request.effective_scope = input.request.effective_scope.clone();
    receipt.request.mls_group_id = input.request.mls_group_id.clone();
    receipt.request_digest =
        arkret_wire::Hash::new(canonical_sha256(&receipt.request).unwrap()).unwrap();
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[41; 32],
        receipt.signature.kid.as_str(),
        &super::super::peer_keypackage_claim_receipt_signing_bytes(receipt).unwrap(),
    )
    .unwrap();
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[41; 32],
        attestation.signature.kid.as_str(),
        &attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    let key = MlsRosterSigningKey {
        verification_method: DidUrl::new(attestation.signature.kid.as_str()).unwrap(),
        public_key_base64url: Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[41; 32])
                .verifying_key()
                .as_bytes(),
        ))
        .unwrap(),
    };
    let signing_keys = MlsRosterAddSigningKeys {
        record_digest: arkret_wire::Hash::new(canonical_sha256(&record).unwrap()).unwrap(),
        claim_receipt_signing_key: key.clone(),
        attestation_signing_key: key,
    };
    input.request.caller_actor_id = actor;
    input.request.target_epoch = 1;
    input.request.target_commit_event_ref = commit.event_id.clone();
    input.pages[0].roster.records.push(record);
    input.pages[0].add_signing_keys.push(signing_keys);
    let mut manifest = serde_json::to_value(&input.pages[0].roster.manifest).unwrap();
    manifest.as_object_mut().unwrap().remove("signature");
    manifest["caller_actor_id"] = json!(input.request.caller_actor_id);
    manifest["target_epoch"] = json!("1");
    manifest["target_commit_event_ref"] = json!(commit.event_id);
    manifest["authority_head_commit_event_ref"] = json!(commit.event_id);
    manifest["total_record_count"] = json!(2);
    manifest["records_digest"] = json!(canonical_sha256(&input.pages[0].roster.records).unwrap());
    input.pages[0].roster.manifest = sign_manifest(manifest);
    // All member private providers, including the new reader's, are gone.
    drop(group);
    drop(member);
    input
}

#[test]
fn later_authorized_reader_uses_genesis_public_material_without_a_prejoin_event() {
    let input = later_reader_fixture();
    assert_eq!(input.request.target_epoch, 1);
    assert_eq!(input.context.epoch, 0);
    assert_ne!(
        input.request.caller_actor_id,
        *input.original.actual_signer()
    );
    let mut materials = input.input();
    materials.genesis_original = None;
    materials.content_original = None;
    let roster = verify_mls_self_historical_content_roster(materials).unwrap();
    let material = roster
        .content_material_for_verified_original(&input.original, &input.envelope)
        .unwrap();
    let header = input
        .envelope
        .reconstruct_pre_encryption_header(
            EncryptedPayloadScheme::EpochContentAead,
            input.original.scope_ref.clone(),
            input.original.kind.as_str(),
            std::str::from_utf8(
                &arkret_models_crypto::mls_basic_credential_identity(
                    input.original.actual_signer(),
                )
                .unwrap(),
            )
            .unwrap(),
            None,
            material,
        )
        .unwrap();
    assert_eq!(
        arkret_crypto::content_history::open_content(
            &input.root,
            &header,
            &input.envelope.ciphertext
        )
        .unwrap(),
        b"original archive body"
    );
    let mut wrong = input.input();
    let mut context = input.context.clone();
    context.epoch = 2;
    wrong.root_context = &context;
    assert!(verify_mls_self_historical_content_roster(wrong).is_err());
    let mut context = input.context.clone();
    context.group_state_ref = input.request.target_commit_event_ref.clone();
    let mut wrong = input.input();
    wrong.root_context = &context;
    assert!(verify_mls_self_historical_content_roster(wrong).is_err());
}

#[test]
fn old_epoch_authority_excludes_future_adds_and_surplus_recovery_material() {
    let mut input = later_reader_fixture();
    let peer = verify_mls_member_roster_authority_pages(&input.pages, &input.request).unwrap();
    let pages = input
        .pages
        .iter()
        .map(|page| page.roster.clone())
        .collect::<Vec<_>>();
    let old =
        verified_roster_authorities(&pages, &peer, &input.material, &input.recovery, 0).unwrap();
    assert_eq!(old.len(), 1);
    assert!(
        old.iter()
            .all(|binding| binding.actor_id != input.request.caller_actor_id)
    );
    let later =
        verified_roster_authorities(&pages, &peer, &input.material, &input.recovery, 1).unwrap();
    assert_eq!(later.len(), 2);
    input.recovery.insert(
        input.request.target_commit_event_ref.clone(),
        input.material.clone(),
    );
    assert!(verify_mls_self_historical_content_roster(input.input()).is_err());
}
