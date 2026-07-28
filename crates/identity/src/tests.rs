use arkret_wire::{Hlc, RealmId};

use super::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
}

// did:web-method fixtures for tests that exercise the `did:web` resolver
// surface itself (DidWebResolver / key-log / registry receipt); the method
// under test is did:web here, so these MUST stay did:web.
fn did_web(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn pairwise_did(name: &str) -> Did {
    Did::new(format!("did:key:z{name}")).unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
}

fn hlc() -> Hlc {
    Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
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
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes())
}

/// Bare base58btc multihash digest of canonical JSON, matching the verifier's
/// `webvh_multihash_base58` (did:webvh v1.0 — no multibase `z` prefix).
fn vector_multihash(value: &Value) -> String {
    let bytes = arkret_canonical::canonical::canonical_json_bytes(value).unwrap();
    let digest = arkret_canonical::canonical::sha256_bytes(&bytes);
    let mut envelope = vec![0x12u8, 0x20];
    envelope.extend_from_slice(&digest);
    encode_base58btc(&envelope)
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
        "proofPurpose": "assertionMethod",
        "verificationMethod": vm,
    });
    let doc = entry.clone();
    let config_bytes = arkret_canonical::canonical::canonical_json_bytes(&proof_config).unwrap();
    let doc_bytes = arkret_canonical::canonical::canonical_json_bytes(&doc).unwrap();
    let config_hash = arkret_canonical::canonical::sha256_bytes(&config_bytes);
    let doc_hash = arkret_canonical::canonical::sha256_bytes(&doc_bytes);
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&config_hash);
    signing_input.extend_from_slice(&doc_hash);
    let signature = signing_key.sign(&signing_input).to_bytes();
    let proof_value = format!("z{}", encode_base58btc(&signature));
    let mut proof = proof_config;
    proof
        .as_object_mut()
        .unwrap()
        .insert("proofValue".to_owned(), json!(proof_value));
    entry
        .as_object_mut()
        .unwrap()
        .insert("proof".to_owned(), json!([proof]));
    entry
}

/// Build a fully valid 2-entry `did:webvh` log signed by `key1` (entry 1)
/// then rotated to `key2` (entry 2). Returns `(did, jsonl_body)`.
fn vector_valid_log(key1: &SigningKey, key2: &SigningKey) -> (Did, Vec<u8>) {
    let host = "starid.example.com:users:alice";
    let update1 = vector_update_key(key1);
    let update2 = vector_update_key(key2);
    let update2_commitment = arkret_signatures::webvh::webvh_next_key_hash(&update2).unwrap();

    // --- entry 1: derive SCID from the placeholder form ------------------
    let prelim_state = json!({ "id": "did:webvh:{SCID}:starid.example.com:users:alice" });
    let prelim_entry1 = json!({
        "versionId": "{SCID}",
        "versionTime": "2026-05-06T00:00:00.000Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "{SCID}",
            "updateKeys": [update1],
            "nextKeyHashes": [update2_commitment]
        },
        "state": prelim_state,
    });
    let scid = vector_derive_scid(&prelim_entry1);
    let did = Did::new(format!("did:webvh:{scid}:{host}")).unwrap();
    let state1 = json!({ "id": format!("did:webvh:{scid}:starid.example.com:users:alice") });

    // versionId hash for entry 1 commits to body with versionId = scid.
    let mut entry1_body = json!({
        "versionId": scid,
        "versionTime": "2026-05-06T00:00:00.000Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": scid,
            "updateKeys": [update1],
            "nextKeyHashes": [update2_commitment]
        },
        "state": state1,
    });
    let hash1 = vector_multihash(&entry1_body);
    let version1 = format!("1-{hash1}");
    entry1_body
        .as_object_mut()
        .unwrap()
        .insert("versionId".to_owned(), json!(version1));
    let entry1 = vector_sign_entry(entry1_body, key1);

    // --- entry 2: activates key2 after key1 committed its nextKeyHash.
    // The controller proof is signed by the current key2, never key1. -----
    let mut entry2_body = json!({
        "versionId": version1,
        "versionTime": "2026-05-07T00:00:00.000Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": scid,
            "updateKeys": [update2]
        },
        "state": state1,
    });
    let hash2 = vector_multihash(&entry2_body);
    let version2 = format!("2-{hash2}");
    entry2_body
        .as_object_mut()
        .unwrap()
        .insert("versionId".to_owned(), json!(version2));
    let entry2 = vector_sign_entry(entry2_body, key2);

    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );
    (did, body.into_bytes())
}

fn vector_log_response(did: &Did, body: Vec<u8>) -> DidWebvhLogOutcome {
    DidWebvhLogOutcome {
        url: DidWebvhResolver::log_url(did).unwrap(),
        content_type: "application/jsonl".to_owned(),
        body,
    }
}

#[test]
fn official_did_webvh_witness_vector_verifies_end_to_end() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/did-webvh-witness-official.json"
    ))
    .expect("official witness fixture");
    let did = Did::new(
        fixture
            .get("did")
            .and_then(Value::as_str)
            .expect("fixture did"),
    )
    .expect("valid did");
    let log = fixture
        .get("did_log_entries")
        .and_then(Value::as_array)
        .expect("fixture log")
        .iter()
        .map(|entry| serde_json::to_string(entry).expect("serialize log entry"))
        .collect::<Vec<_>>()
        .join("\n");
    let witness = serde_json::to_vec(
        fixture
            .get("did_witness_json")
            .expect("fixture witness file"),
    )
    .expect("serialize witness file");

    let verified =
        verify_did_webvh_v1_chain_and_witness_bytes(&did, log.as_bytes(), Some(&witness))
            .expect("official controller and witness proofs verify");
    assert_eq!(verified.witness_sets.len(), 1);
    assert_eq!(verified.witness_sets[0].threshold, 1);
    assert_eq!(
        verified.witness_sets[0].verified_witnesses,
        ["did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"]
    );
}

#[test]
fn malformed_did_webvh_witness_policy_never_rounds_down() {
    let malformed = serde_json::json!({
        "method": "did:webvh:1.0",
        "witness": {
            "threshold": 1,
            "witnesses": [{"id": "did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"}],
            "maxAgeSeconds": 3600
        }
    });
    let error = parse_did_webvh_witness_policy(&malformed)
        .expect_err("overlay fields in method parameters fail closed");
    assert_eq!(error.reason_code(), "webvh_witness_parameter_malformed");

    let alias = serde_json::json!({
        "method": "did:webvh:1.0",
        "witness_threshold": 1,
        "witnesses": ["did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"]
    });
    assert!(parse_did_webvh_witness_policy(&alias).is_err());
}

#[test]
fn webvh_resolver_validates_url_shape() {
    let did = Did::new("did:webvh:zabc:starid.example.com:users:alice").unwrap();
    assert_eq!(
        DidWebvhResolver::document_url(&did).unwrap(),
        "https://starid.example.com/users/alice/did.json"
    );
    assert_eq!(
        DidWebvhResolver::log_url(&did).unwrap(),
        "https://starid.example.com/users/alice/did.jsonl"
    );
}

#[test]
fn webvh_accepts_valid_signed_log_with_key_rotation() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut resolver = DidWebvhResolver::new();
    let log = resolver
        .ingest_log(&did, vector_log_response(&did, body))
        .unwrap();
    assert_eq!(log.len(), 2);
    assert!(
        resolver
            .latest_entry(&did)
            .unwrap()
            .version_id
            .starts_with("2-")
    );
}

#[test]
fn webvh_candidate_entry_is_verified_without_publishing_it() {
    use arkret_signatures::webvh::{
        PrincipalEnrollmentDelegation, PrincipalInceptionInput, PrincipalRotationInput,
        prepare_principal_inception, prepare_principal_rotation,
    };
    use chrono::{DateTime, Utc};

    let current_seed = [9u8; 32];
    let current_key = vector_update_key(&SigningKey::from_bytes(&current_seed));
    let next_key = vector_update_key(&SigningKey::from_bytes(&[11u8; 32]));
    let authority_key = vector_update_key(&SigningKey::from_bytes(&[13u8; 32]));
    let authority_did = format!("did:key:{authority_key}");
    let endpoint = "https://starid.example.com/".parse().unwrap();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: DateTime::parse_from_rfc3339("2026-05-06T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        root_seed: &[7u8; 32],
        next_root_public_key_multibase: &current_key,
        enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
            authority_did: &authority_did,
        },
    })
    .unwrap();
    let rotation = prepare_principal_rotation(&PrincipalRotationInput {
        did: &inception.did,
        local_id: &inception.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: DateTime::parse_from_rfc3339("2026-05-07T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        current_root_seed: &current_seed,
        next_root_public_key_multibase: &next_key,
        state: &inception.log_entry["state"],
    })
    .unwrap();
    let did = Did::new(inception.did).unwrap();
    let current_history = format!("{}\n", inception.log_entry).into_bytes();
    let candidate = serde_json::to_vec(&rotation.log_entry).unwrap();
    let verified = verify_did_webvh_v1_candidate_entry_bytes(
        &did,
        &current_history,
        &inception.version_id,
        &candidate,
        &rotation.version_id,
    )
    .unwrap();
    assert_eq!(verified.head_version_id, rotation.version_id);
    assert!(
        verify_did_webvh_v1_candidate_entry_bytes(
            &did,
            &current_history,
            "1-wrong-head",
            &candidate,
            &rotation.version_id,
        )
        .is_err()
    );
}

#[test]
fn webvh_document_and_log_bytes_require_the_verified_head_document() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let entries: Vec<Value> = body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let document_bytes = serde_json::to_vec(&entries[1]["state"]).unwrap();

    let document = verify_did_webvh_document_and_log_bytes(&did, &document_bytes, &body).unwrap();
    assert_eq!(document.id, did);

    let mut mismatched_document = entries[1]["state"].clone();
    mismatched_document["alsoKnownAs"] = json!(["https://attacker.example/"]);
    assert!(
        verify_did_webvh_document_and_log_bytes(
            &did,
            &serde_json::to_vec(&mismatched_document).unwrap(),
            &body,
        )
        .is_err()
    );
}

#[test]
fn canonical_principal_builders_produce_a_verified_rotation_chain() {
    use arkret_signatures::webvh::{
        PrincipalEnrollmentDelegation, PrincipalInceptionInput, PrincipalRotationInput,
        prepare_principal_inception, prepare_principal_rotation,
    };
    use chrono::{DateTime, Utc};

    let root_seed = [7u8; 32];
    let current_seed = [9u8; 32];
    let next_seed = [11u8; 32];
    let current_key = vector_update_key(&SigningKey::from_bytes(&current_seed));
    let next_key = vector_update_key(&SigningKey::from_bytes(&next_seed));
    let authority_key = vector_update_key(&SigningKey::from_bytes(&[13u8; 32]));
    let authority_did = format!("did:key:{authority_key}");
    let endpoint = "https://starid.example.com/".parse().unwrap();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: DateTime::parse_from_rfc3339("2026-05-06T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &current_key,
        enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
            authority_did: &authority_did,
        },
    })
    .unwrap();
    let rotation = prepare_principal_rotation(&PrincipalRotationInput {
        did: &inception.did,
        local_id: &inception.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: DateTime::parse_from_rfc3339("2026-05-07T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        current_root_seed: &current_seed,
        next_root_public_key_multibase: &next_key,
        state: &inception.log_entry["state"],
    })
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let entries = vec![inception.log_entry.clone(), rotation.log_entry.clone()];

    let verified = verify_did_webvh_v1_log(&did, &entries).unwrap();
    assert_eq!(verified.head_version_id, rotation.version_id);
    assert_eq!(verified.active_update_keys, vec![current_key]);

    let mut previous_key_proof = rotation.log_entry;
    previous_key_proof["proof"][0]["verificationMethod"] =
        json!(inception.root_verification_method);
    assert!(verify_did_webvh_v1_log(&did, &[inception.log_entry, previous_key_proof]).is_err());
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
        .insert(
            "proofValue".to_owned(),
            json!(format!("z{}", encode_base58btc(&bad_sig))),
        );
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&did, vector_log_response(&did, tampered))
            .is_err()
    );
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
    let pv = lines[0]["proof"][0]["proofValue"]
        .as_str()
        .unwrap()
        .to_owned();
    let mutated: String = pv
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == pv.len() - 1 {
                if c == 'a' { 'b' } else { 'a' }
            } else {
                c
            }
        })
        .collect();
    lines[0].as_object_mut().unwrap()["proof"][0]
        .as_object_mut()
        .unwrap()
        .insert("proofValue".to_owned(), json!(mutated));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&did, vector_log_response(&did, tampered))
            .is_err()
    );
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
    lines[0]
        .as_object_mut()
        .unwrap()
        .insert("state".to_owned(), json!({ "id": "did:evil" }));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&did, vector_log_response(&did, tampered))
            .is_err()
    );
}

#[test]
fn webvh_rejects_wrong_scid_in_did() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (_did, body) = vector_valid_log(&key1, &key2);
    // Resolve against a DID whose SCID does not derive from the log.
    let wrong = Did::new("did:webvh:zNOTtheRealScid:starid.example.com:users:alice").unwrap();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&wrong, vector_log_response(&wrong, body))
            .is_err()
    );
}

#[test]
fn webvh_scid_derivation_blanks_references_in_object_keys() {
    let skeleton = json!({
        "versionId": "{SCID}",
        "parameters": {
            "scid": "{SCID}",
        },
        "state": {
            "id": "did:webvh:{SCID}:starid.example.com:applets:weather",
            "verificationMethod": {
                "did:webvh:{SCID}:starid.example.com:applets:weather#service-key": "z6Mkfixture",
            },
        },
    });
    let scid = derive_did_webvh_scid(&skeleton).unwrap();
    let realized: Value = serde_json::from_str(
        &serde_json::to_string(&skeleton)
            .unwrap()
            .replace("{SCID}", &scid),
    )
    .unwrap();

    assert_eq!(derive_did_webvh_scid(&realized).unwrap(), scid);
}

#[test]
fn webvh_rejects_unauthorized_key_rotation() {
    // Entry 2 rotates to key2 but is signed by an attacker key that was
    // never authorized by entry 1's updateKeys.
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let attacker = SigningKey::from_bytes(&[3u8; 32]);
    let host = "starid.example.com:users:alice";
    let update1 = vector_update_key(&key1);
    let update2 = vector_update_key(&key2);
    let update2_commitment = arkret_signatures::webvh::webvh_next_key_hash(&update2).unwrap();

    let prelim_entry1 = json!({
        "versionId": "{SCID}",
        "versionTime": "2026-05-06T00:00:00.000Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "{SCID}",
            "updateKeys": [update1],
            "nextKeyHashes": [update2_commitment]
        },
        "state": json!({ "id": "did:webvh:{SCID}:starid.example.com:users:alice" }),
    });
    let scid = vector_derive_scid(&prelim_entry1);
    let did = Did::new(format!("did:webvh:{scid}:{host}")).unwrap();
    let state = json!({ "id": format!("did:webvh:{scid}:starid.example.com:users:alice") });

    let mut e1 = json!({
        "versionId": scid,
        "versionTime": "2026-05-06T00:00:00.000Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": scid,
            "updateKeys": [update1],
            "nextKeyHashes": [update2_commitment]
        },
        "state": state,
    });
    let v1 = format!("1-{}", vector_multihash(&e1));
    e1.as_object_mut()
        .unwrap()
        .insert("versionId".to_owned(), json!(v1));
    let entry1 = vector_sign_entry(e1, &key1);

    let mut e2 = json!({
        "versionId": v1,
        "versionTime": "2026-05-07T00:00:00.000Z",
        "parameters": { "method": "did:webvh:1.0", "scid": scid, "updateKeys": [update2] },
        "state": state,
    });
    let v2 = format!("2-{}", vector_multihash(&e2));
    e2.as_object_mut()
        .unwrap()
        .insert("versionId".to_owned(), json!(v2));
    // Signed by attacker, NOT authorized by entry 1's updateKeys.
    let entry2 = vector_sign_entry(e2, &attacker);

    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    )
    .into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&did, vector_log_response(&did, body))
            .is_err()
    );
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
    lines[1]
        .as_object_mut()
        .unwrap()
        .insert("proof".to_owned(), json!([]));
    let tampered = format!("{}\n{}\n", lines[0], lines[1]).into_bytes();
    let mut resolver = DidWebvhResolver::new();
    assert!(
        resolver
            .ingest_log(&did, vector_log_response(&did, tampered))
            .is_err()
    );
}

#[test]
fn identity_resolves_validates_rotates_and_migrates_dids() {
    let alice = did("alice");
    let alice_v2 = did("alice-v2");
    let mut manager = IdentityManager::new();
    manager
        .upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1"))
        .unwrap();

    assert!(manager.resolve(&alice).unwrap().validate().is_ok());
    manager.rotate_key(&alice, "key-2", "pubkey-2").unwrap();
    assert!(
        manager
            .resolve(&alice)
            .unwrap()
            .verification_methods
            .contains_key("key-2")
    );

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
    manager
        .attest_handle("alice", issuer, "attestation")
        .unwrap();

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

    assert_eq!(
        handle_dns_txt_name(handle).unwrap(),
        "_arkret-handle.alice.example.com"
    );
    assert_eq!(
        handle_well_known_url(handle).unwrap(),
        "https://example.com/.well-known/arkret/handle/alice.json"
    );
    ExternalHandleProof {
        profile: HandleProofProfile::DnsTxt,
        handle: handle.to_owned(),
        subject: alice.clone(),
        challenge: challenge.to_owned(),
        proof,
    }
    .validate()
    .unwrap();
    assert!(
        ExternalHandleProof {
            profile: HandleProofProfile::WellKnown,
            handle: handle.to_owned(),
            subject: alice,
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
    web_resolver
        .insert(DidDocument::new(web.clone(), "owner", "web-key"))
        .unwrap();
    let mut keri_resolver = DidKeriResolver::new();
    keri_resolver
        .insert(DidDocument::new(keri.clone(), "inception", "keri-key"))
        .unwrap();

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
            DidWebDocumentOutcome {
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
                DidWebDocumentOutcome {
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
                DidWebDocumentOutcome {
                    url: DidWebResolver::document_url(&web).unwrap(),
                    content_type: "application/json".to_owned(),
                    body: vec![b' '; DID_WEB_MAX_DOCUMENT_BYTES + 1],
                },
            )
            .is_err()
    );

    let mut resolver = CompositeDidResolver::new().with_policy(ResolverPolicy {
        allowed_methods: vec![
            "did:web:".to_owned(),
            "did:keri:".to_owned(),
            "did:key:".to_owned(),
        ],
        ..ResolverPolicy::default()
    });
    resolver.push(web_resolver);
    resolver.push(keri_resolver);
    resolver.push(DidKeyResolver::new());

    assert_eq!(
        resolver.resolve_did(&web).unwrap().verification_methods["owner"],
        "web-key"
    );
    assert_eq!(
        resolver.resolve_did(&keri).unwrap().verification_methods["inception"],
        "keri-key"
    );

    let key_doc = resolver.resolve_did(&key).unwrap();
    assert_eq!(key_doc.id, key);
    assert!(
        key_doc
            .verification_methods
            .contains_key("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP#z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP")
    );
    assert!(
        DidKeyResolver::new()
            .resolve_did(&Did::new("did:key:z1111").unwrap())
            .is_err()
    );
}

#[test]
fn did_resolver_verifies_event_proof_from_did_document_key() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let actor = did_web("alice");
    let verification_method = format!("{actor}#key-1");
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            actor.clone(),
            verification_method.clone(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let event = Event::new(
        "ak.test.event",
        arkret_wire::ScopeRef::Realm { realm_id: realm() },
        actor,
        1,
        hlc(),
        json!({"ok": true}),
    )
    .unwrap();
    let builder = arkret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(&event).unwrap();
    let mut proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&canonical_bytes))
            .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    // Spec §6: the detached JWS signs the canonical proof binding object,
    // not the raw event bytes. `actor_id` is the Event envelope actor.
    let binding_bytes = proof.canonical_binding_bytes(&event.actor_id).unwrap();
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(&binding_bytes, &signing_key).unwrap();

    let verified = verify_event_proof_with_did_resolver(&event, &proof, &resolver).unwrap();
    assert!(verified.valid);
}

#[test]
fn did_resolver_binds_event_proof_to_executed_by_when_present() {
    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let controller = did_web("controller");
    let bridge = did_web("bridge");
    let verification_method = format!("{bridge}#key-1");
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            bridge.clone(),
            verification_method.clone(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let mut event = Event::new(
        "ak.test.event",
        arkret_wire::ScopeRef::Realm { realm_id: realm() },
        controller,
        1,
        hlc(),
        json!({"ok": true}),
    )
    .unwrap();
    event.executed_by = Some(bridge);
    event.authorization_ref = Some("ak:grant:01904100-0000-7000-8000-cccccccccccc".to_owned());
    let builder = arkret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(&event).unwrap();
    let mut proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&canonical_bytes))
            .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    // Binding object actor_id is the Event envelope `actor_id` (here
    // `controller`), even though the controller binding uses `executed_by`.
    let binding_bytes = proof.canonical_binding_bytes(&event.actor_id).unwrap();
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(&binding_bytes, &signing_key).unwrap();

    let verified = verify_event_proof_with_did_resolver(&event, &proof, &resolver).unwrap();
    assert!(verified.valid);
}

#[test]
fn did_key_log_verifies_schema_shaped_chain() {
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let alice = did_web("alice");
    let verification_method = format!("{alice}#key-1");
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            alice.clone(),
            verification_method.clone(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let mut body = serde_json::Map::new();
    body.insert(
        "update_keys".to_owned(),
        json!([vector_update_key(&signing_key)]),
    );

    let mut inception = DidKeyLogEntry::build(
        alice.clone(),
        0,
        DidKeyLogOperation::Inception,
        None,
        body.clone(),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut inception, &signing_key, &verification_method)
        .unwrap();

    let mut rotate = DidKeyLogEntry::build(
        alice.clone(),
        1,
        DidKeyLogOperation::Rotate,
        Some(inception.head_event_digest.clone()),
        body.clone(),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut rotate, &signing_key, &verification_method).unwrap();

    let mut deactivate = DidKeyLogEntry::build(
        alice.clone(),
        2,
        DidKeyLogOperation::Deactivate,
        Some(rotate.head_event_digest.clone()),
        body.clone(),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut deactivate, &signing_key, &verification_method)
        .unwrap();

    let active = verify_did_key_log(&[inception.clone(), rotate.clone()], &resolver).unwrap();
    assert_eq!(active.did, alice);
    assert_eq!(active.seq, 1);
    assert_eq!(active.head, rotate.head_event_digest);
    assert!(!active.deactivated);

    let state = verify_did_key_log(&[inception, rotate, deactivate], &resolver).unwrap();
    assert!(state.deactivated);
    assert_eq!(state.seq, 2);
}

#[test]
fn did_key_log_rejects_drift_tampering_and_schema_violations() {
    let signing_key = SigningKey::from_bytes(&[23u8; 32]);
    let alice = did_web("alice");
    let bob = did_web("bob");
    let verification_method = format!("{alice}#key-1");
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            alice.clone(),
            verification_method.clone(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let mut body = serde_json::Map::new();
    body.insert(
        "update_keys".to_owned(),
        json!([vector_update_key(&signing_key)]),
    );

    let mut inception = DidKeyLogEntry::build(
        alice.clone(),
        0,
        DidKeyLogOperation::Inception,
        None,
        body.clone(),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut inception, &signing_key, &verification_method)
        .unwrap();

    // DID change mid-chain is rejected.
    let mut rotate_other_did = DidKeyLogEntry::build(
        bob,
        1,
        DidKeyLogOperation::Rotate,
        Some(inception.head_event_digest.clone()),
        body.clone(),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut rotate_other_did, &signing_key, &verification_method)
        .unwrap();
    assert!(verify_did_key_log(&[inception.clone(), rotate_other_did], &resolver).is_err());

    // Tampering with the body after signing breaks the self digest.
    let mut tampered = inception.clone();
    tampered
        .operation_body
        .insert("evil".to_owned(), json!(true));
    assert!(verify_did_key_log(&[tampered], &resolver).is_err());

    // Tampering with the JWS itself fails Ed25519 verification.
    let mut bad_jws = inception.clone();
    let mut parts: Vec<String> = bad_jws.proofs[0]
        .jws
        .split('.')
        .map(ToOwned::to_owned)
        .collect();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(0..1, replacement);
    bad_jws.proofs[0].jws = parts.join(".");
    assert!(verify_did_key_log(&[bad_jws], &resolver).is_err());

    // seq=0 must not carry prev_event_digest (schema allOf rule).
    let mut bad_inception = inception.clone();
    bad_inception.prev_event_digest = Some(inception.head_event_digest.clone());
    assert!(bad_inception.validate().is_err());

    // Hash-chain mismatch is rejected.
    let mut rotate = DidKeyLogEntry::build(
        alice,
        1,
        DidKeyLogOperation::Rotate,
        Some(Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap()),
        body,
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut rotate, &signing_key, &verification_method).unwrap();
    assert!(verify_did_key_log(&[inception, rotate], &resolver).is_err());
}

#[test]
fn did_registry_receipt_verifies_detached_jws_binding() {
    let registry_key = SigningKey::from_bytes(&[24u8; 32]);
    let registry = did_web("registry");
    let verification_method = format!("{registry}#key-1");
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            registry.clone(),
            verification_method.clone(),
            vector_update_key(&registry_key),
        ))
        .unwrap();

    let alice = did("alice");
    let receipt = DidRegistryReceipt::signed(
        arkret_wire::ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000001").unwrap(),
        alice,
        7,
        Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        registry,
        IdentityReceiptWitnessRole::Writer,
        &registry_key,
        &verification_method,
    )
    .unwrap();
    assert_eq!(receipt.schema, DidRegistryReceipt::SCHEMA);
    receipt.verify(&resolver).unwrap();

    // Any field tamper breaks the payload digest binding.
    let mut tampered = receipt.clone();
    tampered.seq = 8;
    assert!(tampered.verify(&resolver).is_err());

    // A wrong registry key fails Ed25519 verification.
    let mut wrong_resolver = DidWebResolver::new();
    wrong_resolver
        .insert(DidDocument::new(
            did_web("registry"),
            format!("{}#key-1", did_web("registry")),
            vector_update_key(&SigningKey::from_bytes(&[25u8; 32])),
        ))
        .unwrap();
    assert!(receipt.verify(&wrong_resolver).is_err());
}

#[test]
fn starid_registry_adapter_resolves_records_and_control_proofs() {
    let registry_key = SigningKey::from_bytes(&[26u8; 32]);
    let registry = did_web("registry");
    let registry_vm = format!("{registry}#key-1");
    let mut registry_resolver = DidWebResolver::new();
    registry_resolver
        .insert(DidDocument::new(
            registry.clone(),
            registry_vm.clone(),
            vector_update_key(&registry_key),
        ))
        .unwrap();

    let alice = Did::new("did:webvh:zabc:starid.example:users:alice").unwrap();
    let head = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let document = DidDocument::new(alice.clone(), "root", "alice-public-key");
    let receipt = DidRegistryReceipt::signed(
        arkret_wire::ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000002").unwrap(),
        alice.clone(),
        0,
        head.clone(),
        registry.clone(),
        IdentityReceiptWitnessRole::Writer,
        &registry_key,
        &registry_vm,
    )
    .unwrap();
    let record = StaridRegistryRecord {
        did: alice.clone(),
        registry_did: registry.clone(),
        document,
        key_log_head: head.as_str().to_owned(),
        current_control_key: "root".to_owned(),
        receipt: Some(receipt),
        resolved_at: Utc::now(),
    };

    let mut adapter = InMemoryStaridRegistryAdapter::new(registry);
    adapter.insert(record).unwrap();
    assert_eq!(
        adapter
            .resolve_did(&alice)
            .unwrap()
            .primary_key()
            .unwrap()
            .0,
        "root"
    );
    assert_eq!(adapter.current_key_log_head(&alice).unwrap(), head.as_str());
    assert_eq!(adapter.current_control_key(&alice).unwrap(), "root");
    adapter
        .verify_registry_receipt(&alice, &registry_resolver)
        .unwrap();

    let challenge = "challenge-1";
    let proof = starid_control_proof(&alice, "root", challenge, "alice-public-key");
    let verified = adapter
        .verify_control_proof(&StaridControlProofRequestBody {
            did: alice.clone(),
            verification_method: "root".to_owned(),
            challenge: challenge.to_owned(),
            proof,
        })
        .unwrap();
    assert_eq!(verified.did, alice);

    assert!(
        adapter
            .verify_control_proof(&StaridControlProofRequestBody {
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
    manager
        .upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1"))
        .unwrap();

    let claim = manager.bind_handle("@alice", alice.clone());
    let proof = handle_claim_proof("alice", &alice, &claim.challenge);
    manager.validate_handle_claim("alice", &proof).unwrap();

    // Should fail because handle is not in also_known_as
    assert!(
        manager
            .verify_handle_bidirectional("alice", &alice)
            .is_err()
    );
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
    assert!(
        manager
            .verify_handle_bidirectional("alice", &alice)
            .is_err()
    );
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
    assert!(
        manager
            .verify_handle_bidirectional("@Alice", &alice)
            .is_ok()
    );
}

#[test]
fn pairwise_did_store_insert_resolve_and_purge() {
    let alice = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let bob = Did::new("did:webvh:z6mkfixture:bob.example").unwrap();
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
        .with_expiry("2020-01-01T00:00:00.000Z".parse().unwrap());
    store.insert(expired).unwrap();
    assert!(!store.is_valid(&pairwise2));

    store.purge_expired();
    assert!(store.get(&pairwise2).is_none());
    assert!(store.get(&pairwise).is_some());
}

#[test]
fn pairwise_did_resolution_requires_valid_proof() {
    let alice = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let bob = Did::new("did:webvh:z6mkfixture:bob.example").unwrap();
    let mallory = Did::new("did:webvh:z6mkfixture:mallory.example").unwrap();
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

    assert_eq!(
        store.resolve_parent_with_proof(&pairwise, &proof).unwrap(),
        &alice
    );

    let mut bad_proof = proof.clone();
    bad_proof.requester = mallory;
    assert!(
        store
            .resolve_parent_with_proof(&pairwise, &bad_proof)
            .is_err()
    );

    let mut tampered = proof;
    tampered.proof = "bad".to_owned();
    assert!(
        store
            .resolve_parent_with_proof(&pairwise, &tampered)
            .is_err()
    );
}

#[test]
fn pairwise_did_visibility_enum_roundtrips() {
    let vis = DidVisibility::Pairwise;
    let json = serde_json::to_string(&vis).unwrap();
    assert_eq!(json, "\"pairwise\"");
    let back: DidVisibility = serde_json::from_str(&json).unwrap();
    assert_eq!(back, DidVisibility::Pairwise);
}
