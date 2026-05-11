use super::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

#[test]
fn webvh_resolver_validates_url_shape_and_log_chain() {
    let did = Did::new("did:webvh:zabc:starid.local:users:alice").unwrap();
    assert_eq!(
        DidWebvhResolver::document_url(&did).unwrap(),
        "https://starid.local/users/alice/did.json"
    );
    assert_eq!(
        DidWebvhResolver::log_url(&did).unwrap(),
        "https://starid.local/users/alice/did.jsonl"
    );

    let mut resolver = DidWebvhResolver::new();
    let document = DidDocument::new(did.clone(), "key-1", "z6Mkkey");
    let body = serde_json::to_vec(&document).unwrap();
    let resolved = resolver
        .insert_from_https_response(
            &did,
            DidWebvhDocumentResponse {
                url: "https://starid.local/users/alice/did.json".to_owned(),
                content_type: "application/did+json".to_owned(),
                body,
            },
        )
        .unwrap();
    assert_eq!(resolved.id, did);
    assert_eq!(resolver.resolve_did(&did).unwrap(), resolved);

    let entry1 = serde_json::json!({
        "versionId": "1-hashA",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": {"scid": "zabc", "method": "did:webvh:1.0", "updateKeys": ["z6Mkkey"]},
        "state": &document
    });
    let entry2 = serde_json::json!({
        "versionId": "2-hashB",
        "versionTime": "2026-05-07T00:00:00Z",
        "parameters": {"scid": "zabc", "prevVersionId": "1-hashA", "updateKeys": ["z6Mkkey"]},
        "state": &document
    });
    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );
    let log = resolver
        .ingest_log(
            &did,
            DidWebvhLogResponse {
                url: "https://starid.local/users/alice/did.jsonl".to_owned(),
                content_type: "application/jsonl".to_owned(),
                body: body.into_bytes(),
            },
        )
        .unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(resolver.latest_entry(&did).unwrap().version_id, "2-hashB");
}

#[test]
fn webvh_resolver_rejects_scid_mismatch() {
    let did = Did::new("did:webvh:zabc:starid.local:users:alice").unwrap();
    let mut resolver = DidWebvhResolver::new();
    let body = serde_json::json!({
        "versionId": "1-x",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": {"scid": "zwrong"},
        "state": {}
    });
    let response = DidWebvhLogResponse {
        url: DidWebvhResolver::log_url(&did).unwrap(),
        content_type: "application/jsonl".to_owned(),
        body: serde_json::to_vec(&body).unwrap(),
    };
    assert!(resolver.ingest_log(&did, response).is_err());
}

#[test]
fn webvh_resolver_rejects_chain_break() {
    let did = Did::new("did:webvh:zabc:starid.local:users:alice").unwrap();
    let mut resolver = DidWebvhResolver::new();
    let entry1 = serde_json::json!({
        "versionId": "1-A",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": {"scid": "zabc"},
        "state": {}
    });
    let entry2 = serde_json::json!({
        "versionId": "2-B",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": {"scid": "zabc", "prevVersionId": "1-WRONG"},
        "state": {}
    });
    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );
    let response = DidWebvhLogResponse {
        url: DidWebvhResolver::log_url(&did).unwrap(),
        content_type: "application/jsonl".to_owned(),
        body: body.into_bytes(),
    };
    assert!(resolver.ingest_log(&did, response).is_err());
}

#[test]
fn identity_resolves_validates_rotates_and_migrates_dids() {
    let alice = did("alice");
    let alice_v2 = did("alice-v2");
    let mut manager = IdentityManager::new();
    manager.upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1")).unwrap();

    assert!(manager.resolve(&alice).unwrap().validate().is_ok());
    manager.rotate_key(&alice, "key-2", "pubkey-2").unwrap();
    assert!(manager.resolve(&alice).unwrap().verification_methods.contains_key("key-2"));

    manager.migrate_did(alice, alice_v2, "proof");
    assert_eq!(manager.migrations().len(), 1);
}

#[test]
fn identity_binds_validates_and_attests_handles() {
    let alice = did("alice");
    let issuer = did("issuer");
    let mut manager = IdentityManager::new();

    let claim = manager.bind_handle("@Alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();
    manager.attest_handle("alice", issuer, "attestation").unwrap();

    let claim = manager.handle_claim("@alice").unwrap();
    assert!(claim.verified);
    assert!(claim.attestation.is_some());
}

#[test]
fn handle_external_proof_profiles_validate_dns_and_well_known_shapes() {
    let alice = did("alice");
    let challenge = "challenge-1";
    let handle = "alice@example.com";
    let proof = handle_claim_proof(handle, &alice, challenge);

    assert_eq!(handle_dns_txt_name(handle).unwrap(), "_contrix-handle.alice.example.com");
    assert_eq!(
        handle_well_known_url(handle).unwrap(),
        "https://example.com/.well-known/contrix/handle/alice.json"
    );
    ExternalHandleProof {
        profile: HandleProofProfile::DnsTxt,
        handle: handle.to_owned(),
        user_id: alice.clone(),
        challenge: challenge.to_owned(),
        proof,
    }
    .validate()
    .unwrap();
    assert!(
        ExternalHandleProof {
            profile: HandleProofProfile::WellKnown,
            handle: handle.to_owned(),
            user_id: alice,
            challenge: challenge.to_owned(),
            proof: "bad-proof".to_owned(),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn did_resolver_adapters_resolve_uuid_web_key_and_keri() {
    let uuid = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
    let web = Did::new("did:web:alice.example").unwrap();
    let web_path = Did::new("did:web:example.com:users:alice").unwrap();
    let keri = Did::new("did:keri:E123456789abcdef").unwrap();
    let key = Did::new("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP").unwrap();

    let mut uuid_resolver = DidUuidResolver::new();
    uuid_resolver.insert(DidDocument::new(uuid.clone(), "root", "uuid-key")).unwrap();

    let mut web_resolver = DidWebResolver::new();
    web_resolver.insert(DidDocument::new(web.clone(), "owner", "web-key")).unwrap();
    let mut keri_resolver = DidKeriResolver::new();
    keri_resolver.insert(DidDocument::new(keri.clone(), "inception", "keri-key")).unwrap();

    assert_eq!(
        DidWebResolver::document_url(&web).unwrap(),
        "https://alice.example/.well-known/did.json"
    );
    assert_eq!(
        DidWebResolver::document_url(&web_path).unwrap(),
        "https://example.com/users/alice/did.json"
    );
    let mut web_https_resolver = DidWebResolver::new();
    let web_body = serde_json::to_vec(&DidDocument::new(web.clone(), "owner", "web-key")).unwrap();
    let web_json: Value = serde_json::from_slice(&web_body).unwrap();
    assert!(web_json.get("verificationMethod").is_some());
    assert!(web_json.get("alsoKnownAs").is_none());
    assert!(web_json.get("updated").is_some());
    assert!(web_json.get("verification_methods").is_none());
    web_https_resolver
        .insert_from_https_response(
            &web,
            DidWebDocumentResponse {
                url: DidWebResolver::document_url(&web).unwrap(),
                content_type: "application/did+json; charset=utf-8".to_owned(),
                body: web_body,
            },
        )
        .unwrap();
    assert!(
        web_https_resolver
            .insert_from_https_response(
                &web,
                DidWebDocumentResponse {
                    url: DidWebResolver::document_url(&web).unwrap(),
                    content_type: "text/plain".to_owned(),
                    body: b"{}".to_vec(),
                },
            )
            .is_err()
    );
    assert!(
        web_https_resolver
            .insert_from_https_response(
                &web,
                DidWebDocumentResponse {
                    url: DidWebResolver::document_url(&web).unwrap(),
                    content_type: "application/json".to_owned(),
                    body: vec![b' '; DID_WEB_MAX_DOCUMENT_BYTES + 1],
                },
            )
            .is_err()
    );

    let mut resolver = CompositeDidResolver::new();
    resolver.push(uuid_resolver);
    resolver.push(web_resolver);
    resolver.push(keri_resolver);
    resolver.push(DidKeyResolver::new());

    assert_eq!(resolver.resolve_did(&uuid).unwrap().verification_methods["root"], "uuid-key");
    assert_eq!(resolver.resolve_did(&web).unwrap().verification_methods["owner"], "web-key");
    assert_eq!(resolver.resolve_did(&keri).unwrap().verification_methods["inception"], "keri-key");

    let key_doc = resolver.resolve_did(&key).unwrap();
    assert_eq!(key_doc.id, key);
    assert!(
        key_doc
            .verification_methods
            .contains_key("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP#z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP")
    );
    assert!(DidKeyResolver::new().resolve_did(&Did::new("did:key:z1111").unwrap()).is_err());
}

#[test]
fn did_key_log_verifies_rotate_recover_and_deactivate_without_changing_did() {
    let alice = did("alice");
    let inception_keys = BTreeMap::from([("key-1".to_owned(), "pub-1".to_owned())]);
    let recovery_keys = BTreeMap::from([("recovery-1".to_owned(), "recover-pub-1".to_owned())]);
    let inception = DidKeyLogEntry::signed(
        0,
        alice.clone(),
        None,
        DidKeyLogOperation::Inception { verification_keys: inception_keys, recovery_keys },
        "key-1",
        "pub-1",
    );

    let rotated_keys = BTreeMap::from([("key-2".to_owned(), "pub-2".to_owned())]);
    let rotate = DidKeyLogEntry::signed(
        1,
        alice.clone(),
        Some(inception.entry_hash()),
        DidKeyLogOperation::Rotate { verification_keys: rotated_keys },
        "key-1",
        "pub-1",
    );

    let recovered_keys = BTreeMap::from([("key-3".to_owned(), "pub-3".to_owned())]);
    let new_recovery_keys = BTreeMap::from([("recovery-2".to_owned(), "recover-pub-2".to_owned())]);
    let recover = DidKeyLogEntry::signed(
        2,
        alice.clone(),
        Some(rotate.entry_hash()),
        DidKeyLogOperation::Recover {
            verification_keys: recovered_keys,
            recovery_keys: new_recovery_keys,
        },
        "recovery-1",
        "recover-pub-1",
    );

    let deactivate = DidKeyLogEntry::signed(
        3,
        alice.clone(),
        Some(recover.entry_hash()),
        DidKeyLogOperation::Deactivate,
        "key-3",
        "pub-3",
    );

    let state =
        verify_did_key_log(&[inception.clone(), rotate.clone(), recover.clone(), deactivate])
            .unwrap();
    assert_eq!(state.did, alice);
    assert!(state.deactivated);
    assert_eq!(state.verification_keys["key-3"], "pub-3");
    assert!(state.to_document().is_err());

    let active = verify_did_key_log(&[inception, rotate, recover]).unwrap();
    assert!(!active.deactivated);
    assert_eq!(active.to_document().unwrap().verification_methods["key-3"], "pub-3");
}

#[test]
fn did_key_log_rejects_did_change_and_bad_proof() {
    let alice = did("alice");
    let bob = did("bob");
    let inception_keys = BTreeMap::from([("key-1".to_owned(), "pub-1".to_owned())]);
    let inception = DidKeyLogEntry::signed(
        0,
        alice,
        None,
        DidKeyLogOperation::Inception {
            verification_keys: inception_keys,
            recovery_keys: BTreeMap::new(),
        },
        "key-1",
        "pub-1",
    );

    let rotate = DidKeyLogEntry::signed(
        1,
        bob,
        Some(inception.entry_hash()),
        DidKeyLogOperation::Rotate {
            verification_keys: BTreeMap::from([("key-2".to_owned(), "pub-2".to_owned())]),
        },
        "key-1",
        "pub-1",
    );
    assert!(verify_did_key_log(&[inception.clone(), rotate]).is_err());

    let mut tampered = inception;
    tampered.proof = "bad-proof".to_owned();
    assert!(verify_did_key_log(&[tampered]).is_err());
}

#[test]
fn did_registry_receipt_verifies_signature_binding() {
    let alice = did("alice");
    let registry = did("registry");
    let receipt = DidRegistryReceipt::signed(
        alice.clone(),
        registry,
        "sha256:abc",
        "did:web:registry.example#key-1",
        "registry-public-key",
    );

    receipt.verify("registry-public-key").unwrap();
    assert!(receipt.verify("wrong-key").is_err());

    let expected = did_registry_receipt_signature(
        &alice,
        &receipt.registry_did,
        &receipt.operation_hash,
        &receipt.verification_method,
        receipt.issued_at,
        "registry-public-key",
    );
    assert_eq!(receipt.signature, expected);
}

#[test]
fn starid_registry_adapter_resolves_records_and_control_proofs() {
    let alice = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
    let registry = did("registry");
    let document = DidDocument::new(alice.clone(), "root", "alice-public-key");
    let receipt = DidRegistryReceipt::signed(
        alice.clone(),
        registry.clone(),
        "sha256:abc",
        "did:web:registry.example#key-1",
        "registry-public-key",
    );
    let record = StaridRegistryRecord {
        did: alice.clone(),
        registry_did: registry.clone(),
        document,
        key_log_head: "sha256:abc".to_owned(),
        current_control_key: "root".to_owned(),
        receipt: Some(receipt),
        resolved_at: Utc::now(),
    };

    let mut adapter = InMemoryStaridRegistryAdapter::new(registry);
    adapter.insert(record).unwrap();
    assert_eq!(adapter.resolve_did(&alice).unwrap().primary_key().unwrap().0, "root");
    assert_eq!(adapter.current_key_log_head(&alice).unwrap(), "sha256:abc");
    assert_eq!(adapter.current_control_key(&alice).unwrap(), "root");
    adapter.verify_registry_receipt(&alice, "registry-public-key").unwrap();

    let challenge = "challenge-1";
    let proof = starid_control_proof(&alice, "root", challenge, "alice-public-key");
    let verified = adapter
        .verify_control_proof(&StaridControlProofRequest {
            did: alice.clone(),
            verification_method: "root".to_owned(),
            challenge: challenge.to_owned(),
            proof,
        })
        .unwrap();
    assert_eq!(verified.did, alice);

    assert!(
        adapter
            .verify_control_proof(&StaridControlProofRequest {
                did: verified.did,
                verification_method: "root".to_owned(),
                challenge: challenge.to_owned(),
                proof: "bad".to_owned(),
            })
            .is_err()
    );
}

#[test]
fn handle_bidirectional_verification_succeeds_with_also_known_as() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    // Create DID document with also_known_as listing the handle
    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@alice".to_owned()];
    manager.upsert_document(doc).unwrap();

    // Bind and verify handle
    let claim = manager.bind_handle("@alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();

    // Bidirectional verification should succeed
    assert!(manager.verify_handle_bidirectional("alice", &alice).is_ok());
}

#[test]
fn handle_bidirectional_verification_fails_without_also_known_as() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    // DID document without also_known_as
    manager.upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1")).unwrap();

    let claim = manager.bind_handle("@alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();

    // Should fail because handle is not in also_known_as
    assert!(manager.verify_handle_bidirectional("alice", &alice).is_err());
}

#[test]
fn handle_bidirectional_verification_fails_when_claim_not_verified() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@alice".to_owned()];
    manager.upsert_document(doc).unwrap();

    // Bind handle but don't verify it
    manager.bind_handle("@alice", alice.clone());

    // Should fail because claim is not verified
    assert!(manager.verify_handle_bidirectional("alice", &alice).is_err());
}

#[test]
fn handle_bidirectional_verification_fails_for_wrong_did() {
    let alice = did("alice");
    let bob = did("bob");
    let mut manager = IdentityManager::new();

    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@alice".to_owned()];
    manager.upsert_document(doc).unwrap();

    let claim = manager.bind_handle("@alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();

    // Should fail because handle belongs to alice, not bob
    assert!(manager.verify_handle_bidirectional("alice", &bob).is_err());
}

#[test]
fn unclaimed_handles_for_did_returns_unlisted_handles() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@alice".to_owned(), "@alice_alt".to_owned()];
    manager.upsert_document(doc).unwrap();

    // Claim one handle
    manager.bind_handle("@alice", alice.clone());

    // Should return the unclaimed one
    let unclaimed = manager.unclaimed_handles_for_did(&alice);
    assert_eq!(unclaimed.len(), 1);
    assert_eq!(unclaimed[0], "@alice_alt");
}

#[test]
fn unclaimed_handles_excludes_urls() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@alice".to_owned(), "https://alice.example".to_owned()];
    manager.upsert_document(doc).unwrap();

    let unclaimed = manager.unclaimed_handles_for_did(&alice);
    assert_eq!(unclaimed.len(), 1);
    assert_eq!(unclaimed[0], "@alice");
}

#[test]
fn handle_bidirectional_with_case_insensitive_matching() {
    let alice = did("alice");
    let mut manager = IdentityManager::new();

    let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
    doc.also_known_as = vec!["@Alice".to_owned()];
    manager.upsert_document(doc).unwrap();

    let claim = manager.bind_handle("@alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();

    // Should succeed despite case difference
    assert!(manager.verify_handle_bidirectional("@Alice", &alice).is_ok());
}

#[test]
fn pairwise_did_derivation_is_deterministic_and_unique() {
    let alice = Did::new("did:web:alice.example").unwrap();
    let bob = Did::new("did:web:bob.example").unwrap();
    let charlie = Did::new("did:web:charlie.example").unwrap();

    let ab1 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
    let ab2 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
    assert_eq!(ab1, ab2, "pairwise DID derivation must be deterministic");

    let ac = PairwiseDidBinding::derive_pairwise_did(&alice, &charlie, None).unwrap();
    assert_ne!(ab1, ac, "different peers must produce different pairwise DIDs");

    let ba = PairwiseDidBinding::derive_pairwise_did(&bob, &alice, None).unwrap();
    assert_ne!(ab1, ba, "asymmetric peer pairs must produce different pairwise DIDs");
}

#[test]
fn pairwise_did_with_scope_varies() {
    let alice = Did::new("did:web:alice.example").unwrap();
    let bob = Did::new("did:web:bob.example").unwrap();

    let no_scope = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
    let with_scope =
        PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("space:01")).unwrap();
    assert_ne!(no_scope, with_scope, "scope must change the derived DID");
}

#[test]
fn pairwise_did_store_insert_resolve_and_purge() {
    let alice = Did::new("did:web:alice.example").unwrap();
    let bob = Did::new("did:web:bob.example").unwrap();
    let pairwise = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();

    let binding = PairwiseDidBinding::new(pairwise.clone(), alice.clone(), bob.clone(), None);
    let mut store = PairwiseDidStore::new();
    store.insert(binding).unwrap();

    assert_eq!(store.resolve_parent(&pairwise), Some(&alice));
    assert!(store.is_valid(&pairwise));
    assert_eq!(store.pairwise_dids_for(&alice).len(), 1);

    // Expired binding is invalid
    let pairwise2 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("x")).unwrap();
    let expired = PairwiseDidBinding::new(pairwise2.clone(), alice, bob, Some("x".to_owned()))
        .with_expiry("2020-01-01T00:00:00Z".parse().unwrap());
    store.insert(expired).unwrap();
    assert!(!store.is_valid(&pairwise2));

    store.purge_expired();
    assert!(store.get(&pairwise2).is_none());
    assert!(store.get(&pairwise).is_some());
}

#[test]
fn pairwise_did_resolution_requires_valid_proof() {
    let alice = Did::new("did:web:alice.example").unwrap();
    let bob = Did::new("did:web:bob.example").unwrap();
    let mallory = Did::new("did:web:mallory.example").unwrap();
    let pairwise = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("space:01")).unwrap();
    let binding = PairwiseDidBinding::new(
        pairwise.clone(),
        alice.clone(),
        bob.clone(),
        Some("space:01".to_owned()),
    );
    let proof = binding.resolution_proof(bob, "challenge-1");
    let mut store = PairwiseDidStore::new();
    store.insert(binding).unwrap();

    assert_eq!(store.resolve_parent_with_proof(&pairwise, &proof).unwrap(), &alice);

    let mut bad_proof = proof.clone();
    bad_proof.requester = mallory;
    assert!(store.resolve_parent_with_proof(&pairwise, &bad_proof).is_err());

    let mut tampered = proof;
    tampered.proof = "bad".to_owned();
    assert!(store.resolve_parent_with_proof(&pairwise, &tampered).is_err());
}

#[test]
fn pairwise_did_visibility_enum_roundtrips() {
    let vis = DidVisibility::Pairwise;
    let json = serde_json::to_string(&vis).unwrap();
    assert_eq!(json, "\"pairwise\"");
    let back: DidVisibility = serde_json::from_str(&json).unwrap();
    assert_eq!(back, DidVisibility::Pairwise);
}
