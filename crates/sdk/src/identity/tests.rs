use super::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn pairwise_did(name: &str) -> Did {
    Did::new(format!("did:key:z{name}")).unwrap()
}

// ---------------------------------------------------------------------------
// did:webvh cryptographic test-vector builder.
//
// These helpers construct a *real* `did:webvh` v1.0 log — proper SCID
// derivation, per-entry hash chain, and `eddsa-jcs-2022` Data Integrity
// proofs signed with Ed25519 — so the verification path in
// [`DidWebvhResolver::ingest_log`] is exercised end-to-end rather than with
// placeholder strings. They mirror, byte-for-byte, the canonicalization the
// verifier performs.
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

/// Multibase `z6Mk…` Ed25519 public key for a signing key.
fn vector_update_key(signing_key: &SigningKey) -> String {
    binding::multicodec_ed25519_public_key(&signing_key.verifying_key())
}

/// Multihash/multibase digest of canonical JSON, matching the verifier's
/// `webvh_multihash_base58`.
fn vector_multihash(value: &Value) -> String {
    let bytes = cokret_core::canonical::canonical_json_bytes(value).unwrap();
    let digest = Sha256::digest(&bytes);
    let mut envelope = vec![0x12u8, 0x20];
    envelope.extend_from_slice(&digest);
    format!("z{}", encode_base58btc(&envelope))
}

/// Derive the SCID from a preliminary first entry (with SCID already blanked
/// to `{SCID}` and no `proof`/`versionId`).
fn vector_derive_scid(preliminary: &Value) -> String {
    let mut p = preliminary.clone();
    let obj = p.as_object_mut().unwrap();
    obj.remove("proof");
    obj.insert("versionId".to_owned(), json!("{SCID}"));
    vector_multihash(&p)
}

/// Attach an `eddsa-jcs-2022` proof: sign `SHA256(JCS(proofConfig)) ||
/// SHA256(JCS(doc-without-proof))` and return the populated entry.
fn vector_sign_entry(mut entry: Value, signing_key: &SigningKey) -> Value {
    let vm = format!("did:key:{0}#{0}", vector_update_key(signing_key));
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "authentication",
        "verificationMethod": vm,
    });
    let doc = entry.clone();
    let config_hash =
        Sha256::digest(cokret_core::canonical::canonical_json_bytes(&proof_config).unwrap());
    let doc_hash = Sha256::digest(cokret_core::canonical::canonical_json_bytes(&doc).unwrap());
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&config_hash);
    signing_input.extend_from_slice(&doc_hash);
    let signature = signing_key.sign(&signing_input).to_bytes();
    let proof_value = format!("z{}", encode_base58btc(&signature));
    let mut proof = proof_config;
    proof.as_object_mut().unwrap().insert("proofValue".to_owned(), json!(proof_value));
    entry.as_object_mut().unwrap().insert("proof".to_owned(), json!([proof]));
    entry
}

/// Build a fully valid 2-entry `did:webvh` log signed by `key1` (entry 1)
/// then rotated to `key2` (entry 2). Returns `(did, jsonl_body)`.
fn vector_valid_log(key1: &SigningKey, key2: &SigningKey) -> (Did, Vec<u8>) {
    let host = "starid.local:users:alice";
    let update1 = vector_update_key(key1);
    let update2 = vector_update_key(key2);

    // --- entry 1: derive SCID from the placeholder form ------------------
    let prelim_state = json!({ "id": "did:webvh:{SCID}:starid.local:users:alice" });
    let prelim_entry1 = json!({
        "versionId": "{SCID}",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": { "method": "did:webvh:1.0", "scid": "{SCID}", "updateKeys": [update1] },
        "state": prelim_state,
    });
    let scid = vector_derive_scid(&prelim_entry1);
    let did = Did::new(format!("did:webvh:{scid}:{host}")).unwrap();
    let state1 = json!({ "id": format!("did:webvh:{scid}:starid.local:users:alice") });

    // versionId hash for entry 1 commits to body with versionId = scid.
    let mut entry1_body = json!({
        "versionId": scid,
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": { "method": "did:webvh:1.0", "scid": scid, "updateKeys": [update1] },
        "state": state1.clone(),
    });
    let hash1 = vector_multihash(&entry1_body);
    let version1 = format!("1-{hash1}");
    entry1_body.as_object_mut().unwrap().insert("versionId".to_owned(), json!(version1));
    let entry1 = vector_sign_entry(entry1_body, key1);

    // --- entry 2: rotates updateKeys to key2, signed by key1 (authorized
    // by the previous version's updateKeys) ------------------------------
    let mut entry2_body = json!({
        "versionId": version1,
        "versionTime": "2026-05-07T00:00:00Z",
        "parameters": { "prevVersionId": version1, "scid": scid, "updateKeys": [update2] },
        "state": state1,
    });
    let hash2 = vector_multihash(&entry2_body);
    let version2 = format!("2-{hash2}");
    entry2_body.as_object_mut().unwrap().insert("versionId".to_owned(), json!(version2));
    let entry2 = vector_sign_entry(entry2_body, key1);

    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );
    (did, body.into_bytes())
}

fn vector_log_response(did: &Did, body: Vec<u8>) -> DidWebvhLogResBody {
    DidWebvhLogResBody {
        url: DidWebvhResolver::log_url(did).unwrap(),
        content_type: "application/jsonl".to_owned(),
        body,
    }
}

#[test]
fn webvh_resolver_validates_url_shape() {
    let did = Did::new("did:webvh:zabc:starid.local:users:alice").unwrap();
    assert_eq!(
        DidWebvhResolver::document_url(&did).unwrap(),
        "https://starid.local/users/alice/did.json"
    );
    assert_eq!(
        DidWebvhResolver::log_url(&did).unwrap(),
        "https://starid.local/users/alice/did.jsonl"
    );
}

#[test]
fn webvh_accepts_valid_signed_log_with_key_rotation() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut resolver = DidWebvhResolver::new();
    let log = resolver.ingest_log(&did, vector_log_response(&did, body)).unwrap();
    assert_eq!(log.len(), 2);
    assert!(resolver.latest_entry(&did).unwrap().version_id.starts_with("2-"));
}

#[test]
fn webvh_rejects_forged_proof_signature() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    // Flip the proofValue of the first entry to a different (valid-form but
    // wrong) signature by re-signing with an unrelated key.
    let mut lines: Vec<Value> = body
        .split(|b| *b == b'\n')
        .filter(|c| !c.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    let attacker = SigningKey::from_bytes(&[1u8; 32]);
    let bad_sig = attacker.sign(b"unrelated").to_bytes();
    lines[0].as_object_mut().unwrap()["proof"][0]
        .as_object_mut()
        .unwrap()
        .insert("proofValue".to_owned(), json!(format!("z{}", encode_base58btc(&bad_sig))));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&did, vector_log_response(&did, tampered)).is_err());
}

#[test]
fn webvh_rejects_proof_value_tampering() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut lines: Vec<Value> = body
        .split(|b| *b == b'\n')
        .filter(|c| !c.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    // Mutate one base58 character of the proofValue (bit-flip in signature).
    let pv = lines[0]["proof"][0]["proofValue"].as_str().unwrap().to_owned();
    let mutated: String = pv
        .chars()
        .enumerate()
        .map(|(i, c)| if i == pv.len() - 1 { if c == 'a' { 'b' } else { 'a' } } else { c })
        .collect();
    lines[0].as_object_mut().unwrap()["proof"][0]
        .as_object_mut()
        .unwrap()
        .insert("proofValue".to_owned(), json!(mutated));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&did, vector_log_response(&did, tampered)).is_err());
}

#[test]
fn webvh_rejects_state_tampering_breaks_entry_hash() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut lines: Vec<Value> = body
        .split(|b| *b == b'\n')
        .filter(|c| !c.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    // Tamper the document state — versionId hash no longer commits to it.
    lines[0].as_object_mut().unwrap().insert("state".to_owned(), json!({ "id": "did:evil" }));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&did, vector_log_response(&did, tampered)).is_err());
}

#[test]
fn webvh_rejects_wrong_scid_in_did() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (_did, body) = vector_valid_log(&key1, &key2);
    // Resolve against a DID whose SCID does not derive from the log.
    let wrong = Did::new("did:webvh:zNOTtheRealScid:starid.local:users:alice").unwrap();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&wrong, vector_log_response(&wrong, body)).is_err());
}

#[test]
fn webvh_rejects_unauthorized_key_rotation() {
    // Entry 2 rotates to key2 but is signed by an attacker key that was
    // never authorized by entry 1's updateKeys.
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let attacker = SigningKey::from_bytes(&[3u8; 32]);
    let host = "starid.local:users:alice";
    let update1 = vector_update_key(&key1);
    let update2 = vector_update_key(&key2);

    let prelim_entry1 = json!({
        "versionId": "{SCID}",
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": { "method": "did:webvh:1.0", "scid": "{SCID}", "updateKeys": [update1] },
        "state": json!({ "id": "did:webvh:{SCID}:starid.local:users:alice" }),
    });
    let scid = vector_derive_scid(&prelim_entry1);
    let did = Did::new(format!("did:webvh:{scid}:{host}")).unwrap();
    let state = json!({ "id": format!("did:webvh:{scid}:starid.local:users:alice") });

    let mut e1 = json!({
        "versionId": scid,
        "versionTime": "2026-05-06T00:00:00Z",
        "parameters": { "method": "did:webvh:1.0", "scid": scid, "updateKeys": [update1] },
        "state": state.clone(),
    });
    let v1 = format!("1-{}", vector_multihash(&e1));
    e1.as_object_mut().unwrap().insert("versionId".to_owned(), json!(v1));
    let entry1 = vector_sign_entry(e1, &key1);

    let mut e2 = json!({
        "versionId": v1,
        "versionTime": "2026-05-07T00:00:00Z",
        "parameters": { "prevVersionId": v1, "scid": scid, "updateKeys": [update2] },
        "state": state,
    });
    let v2 = format!("2-{}", vector_multihash(&e2));
    e2.as_object_mut().unwrap().insert("versionId".to_owned(), json!(v2));
    // Signed by attacker, NOT authorized by entry 1's updateKeys.
    let entry2 = vector_sign_entry(e2, &attacker);

    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    )
    .into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&did, vector_log_response(&did, body)).is_err());
}

#[test]
fn webvh_rejects_missing_proof() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut lines: Vec<Value> = body
        .split(|b| *b == b'\n')
        .filter(|c| !c.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    lines[1].as_object_mut().unwrap().insert("proof".to_owned(), json!([]));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(resolver.ingest_log(&did, vector_log_response(&did, tampered)).is_err());
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

    assert_eq!(handle_dns_txt_name(handle).unwrap(), "_cokret-handle.alice.example.com");
    assert_eq!(
        handle_well_known_url(handle).unwrap(),
        "https://example.com/.well-known/cokret/handle/alice.json"
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
fn did_resolver_adapters_resolve_web_key_and_keri() {
    let web = Did::new("did:web:alice.example").unwrap();
    let web_path = Did::new("did:web:example.com:users:alice").unwrap();
    let keri = Did::new("did:keri:E123456789abcdef").unwrap();
    let key = Did::new("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP").unwrap();

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
            DidWebDocumentResBody {
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
                DidWebDocumentResBody {
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
                DidWebDocumentResBody {
                    url: DidWebResolver::document_url(&web).unwrap(),
                    content_type: "application/json".to_owned(),
                    body: vec![b' '; DID_WEB_MAX_DOCUMENT_BYTES + 1],
                },
            )
            .is_err()
    );

    let mut resolver = CompositeDidResolver::new();
    resolver.push(web_resolver);
    resolver.push(keri_resolver);
    resolver.push(DidKeyResolver::new());

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
    let alice = Did::new("did:webvh:zabc:starid.example:users:alice").unwrap();
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
        .verify_control_proof(&StaridControlProofReqBody {
            did: alice.clone(),
            verification_method: "root".to_owned(),
            challenge: challenge.to_owned(),
            proof,
        })
        .unwrap();
    assert_eq!(verified.did, alice);

    assert!(
        adapter
            .verify_control_proof(&StaridControlProofReqBody {
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
fn pairwise_did_store_insert_resolve_and_purge() {
    let alice = Did::new("did:web:alice.example").unwrap();
    let bob = Did::new("did:web:bob.example").unwrap();
    let pairwise = pairwise_did("pairwisealicebob");

    let binding = PairwiseDidBinding::new(pairwise.clone(), alice.clone(), bob.clone(), None);
    let mut store = PairwiseDidStore::new();
    store.insert(binding).unwrap();

    assert_eq!(store.resolve_parent(&pairwise), Some(&alice));
    assert!(store.is_valid(&pairwise));
    assert_eq!(store.pairwise_dids_for(&alice).len(), 1);

    // Expired binding is invalid
    let pairwise2 = pairwise_did("pairwisealicebobx");
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
    let pairwise = pairwise_did("pairwisealicebobspace01");
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
