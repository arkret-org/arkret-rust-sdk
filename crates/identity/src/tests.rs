use arkret_wire::{Did, Hlc, RealmId, project_did_to_core_id};

use super::*;
use crate::helpers::{encode_base58btc, try_did_webvh_url};

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture{name}:{name}.example")).unwrap()
}

// did:web-method fixtures for tests that exercise the `did:web` resolver
// surface itself (DidWebResolver / key-log / registry receipt); the method
// under test is did:web here, so these MUST stay did:web.
fn did_web(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap()
}

fn hlc() -> Hlc {
    Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
}

fn assertion_document(
    authority: &Did,
    verification_method: &DidUrl,
    signing_key: &SigningKey,
) -> DidDocument {
    serde_json::from_value(json!({
        "id": authority,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": authority,
            "publicKeyMultibase": vector_update_key(signing_key)
        }],
        "assertionMethod": [verification_method]
    }))
    .unwrap()
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
    let key = vector_update_key(signing_key);
    let proof = arkret_signatures::build_eddsa_jcs_2022_proof(
        &entry,
        signing_key,
        &format!("did:key:{key}#{key}"),
        arkret_signatures::DataIntegrityProofPurpose::AssertionMethod,
    )
    .unwrap();
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
    assert!(log.last().unwrap().version_id.starts_with("2-"));
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
        PrincipalInceptionInput, PrincipalRotationInput, prepare_principal_inception,
        prepare_principal_rotation,
    };
    use chrono::{DateTime, Utc};

    let root_seed = [7u8; 32];
    let current_seed = [9u8; 32];
    let next_seed = [11u8; 32];
    let current_key = vector_update_key(&SigningKey::from_bytes(&current_seed));
    let next_key = vector_update_key(&SigningKey::from_bytes(&next_seed));
    let endpoint = "https://starid.example.com/".parse().unwrap();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: DateTime::parse_from_rfc3339("2026-05-06T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &current_key,
        witness_policy: None,
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
fn webvh_rejects_unknown_parameter_before_hash_or_proof_processing() {
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[9u8; 32]);
    let (did, body) = vector_valid_log(&key1, &key2);
    let mut entries: Vec<Value> = body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    entries[0]["parameters"]["governance"] = json!({"threshold": 1});

    let error = verify_did_webvh_v1_chain(&did, &entries).unwrap_err();
    assert!(error.to_string().contains("param_invalid"));
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
        resolver
            .resolve_did_document(&web)
            .unwrap()
            .verification_methods["owner"],
        "web-key"
    );
    assert_eq!(
        resolver
            .resolve_did_document(&keri)
            .unwrap()
            .verification_methods["inception"],
        "keri-key"
    );

    let key_doc = resolver.resolve_did_document(&key).unwrap();
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
    let actor_did = did_web("alice");
    let actor_id = project_did_to_core_id(&actor_did).unwrap();
    let verification_method = DidUrl::new(format!("{actor_did}#key-1")).unwrap();
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            actor_did,
            verification_method.as_str(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let event = arkret_wire::test_support::raw_event(
        "ak.test.event",
        arkret_wire::ScopeRef::Realm { realm_id: realm() },
        actor_id.clone(),
        actor_id,
        1,
        hlc(),
        json!({"ok": true}),
    )
    .unwrap();
    let builder = arkret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(&event).unwrap();
    let mut proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method,
        event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&canonical_bytes))
            .unwrap(),
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
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

    let verified = verify_event_proof_with_did_resolver(
        &event,
        &proof,
        &resolver,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(verified.valid);
}

#[test]
fn did_resolver_binds_event_proof_to_executed_by_when_present() {
    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let controller = project_did_to_core_id(&did_web("controller")).unwrap();
    let bridge_did = did_web("bridge");
    let bridge_id = project_did_to_core_id(&bridge_did).unwrap();
    let verification_method = DidUrl::new(format!("{bridge_did}#key-1")).unwrap();
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            bridge_did,
            verification_method.as_str(),
            vector_update_key(&signing_key),
        ))
        .unwrap();

    let mut event = arkret_wire::test_support::raw_event(
        "ak.test.event",
        arkret_wire::ScopeRef::Realm { realm_id: realm() },
        controller.clone(),
        controller,
        1,
        hlc(),
        json!({"ok": true}),
    )
    .unwrap();
    event.executed_by = Some(arkret_wire::ActorId::service(bridge_id));
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new("ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM")
            .unwrap(),
    );
    let builder = arkret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(&event).unwrap();
    let mut proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method,
        event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&canonical_bytes))
            .unwrap(),
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
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

    let verified = verify_event_proof_with_did_resolver(
        &event,
        &proof,
        &resolver,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(verified.valid);
}

#[test]
fn did_registry_receipt_verifies_detached_jws_binding() {
    let registry_key = SigningKey::from_bytes(&[24u8; 32]);
    let registry_did = did_web("registry");
    let registry_id = project_did_to_core_id(&registry_did).unwrap();
    let verification_method = DidUrl::new(format!("{registry_did}#key-1")).unwrap();
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(assertion_document(
            &registry_did,
            &verification_method,
            &registry_key,
        ))
        .unwrap();

    let alice = did("alice");
    let receipt = DidRegistryReceipt::signed(
        arkret_wire::ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000001").unwrap(),
        alice,
        7,
        Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        registry_id,
        IdentityReceiptWitnessRole::Writer,
        &registry_key,
        &verification_method,
    )
    .unwrap();
    assert_eq!(receipt.schema, arkret_wire::SchemaId::IDENTITY_RECEIPT_V1);
    receipt.verify(&resolver).unwrap();

    // Any field tamper breaks the payload digest binding.
    let mut tampered = receipt.clone();
    tampered.seq = 8;
    assert!(tampered.verify(&resolver).is_err());

    // A wrong registry key fails Ed25519 verification.
    let mut wrong_resolver = DidWebResolver::new();
    wrong_resolver
        .insert(assertion_document(
            &did_web("registry"),
            &DidUrl::new(format!("{}#key-1", did_web("registry"))).unwrap(),
            &SigningKey::from_bytes(&[25u8; 32]),
        ))
        .unwrap();
    assert!(receipt.verify(&wrong_resolver).is_err());
}

#[test]
fn did_registry_receipt_binds_current_assertion_authority_and_explicit_controller() {
    let registry = did_web("registry-authority");
    let registry_id = project_did_to_core_id(&registry).unwrap();
    let delegate = did_web("registry-delegate");
    let host = did_web("registry-host");
    let delegate_key = SigningKey::from_bytes(&[35u8; 32]);
    let delegate_method = DidUrl::new(format!("{delegate}#receipt-key")).unwrap();
    let host_method = DidUrl::new(format!("{host}#replacement-key")).unwrap();
    let receipt = DidRegistryReceipt::signed(
        arkret_wire::ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000002").unwrap(),
        did("alice"),
        8,
        Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
        registry_id.clone(),
        IdentityReceiptWitnessRole::Witness,
        &delegate_key,
        &delegate_method,
    )
    .unwrap();
    let delegated_document: DidDocument = serde_json::from_value(json!({
        "id": registry,
        "verificationMethod": [{
            "id": delegate_method,
            "type": "Multikey",
            "controller": registry,
            "publicKeyMultibase": vector_update_key(&delegate_key)
        }],
        "assertionMethod": [delegate_method]
    }))
    .unwrap();
    receipt
        .verify_with_document(&delegated_document)
        .expect("an assertion method explicitly controlled by the registry is valid");

    let replacement_receipt = DidRegistryReceipt::signed(
        arkret_wire::ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000003").unwrap(),
        did("alice"),
        9,
        Hash::new(format!("sha256:{}", "ef".repeat(32))).unwrap(),
        registry_id,
        IdentityReceiptWitnessRole::Writer,
        &delegate_key,
        &host_method,
    )
    .unwrap();
    let host_controlled_document: DidDocument = serde_json::from_value(json!({
        "id": registry,
        "verificationMethod": [{
            "id": host_method,
            "type": "Multikey",
            "controller": host,
            "publicKeyMultibase": vector_update_key(&delegate_key)
        }],
        "assertionMethod": [host_method]
    }))
    .unwrap();
    replacement_receipt
        .verify_with_document(&host_controlled_document)
        .expect_err("a registry host replacement key is not registry authority");

    let mut removed = delegated_document;
    removed
        .raw_properties
        .insert("assertionMethod".to_owned(), json!([]));
    receipt
        .verify_with_document(&removed)
        .expect_err("a removed assertion method must fail closed");
}

// ── did:webvh URL derivation reports why, not just "unsupported" ──
//
// URL derivation is a pure syntax-to-URL function: it reports malformed DIDs
// precisely, and it never answers the separate question of whether this
// deployment may connect to the derived authority. That egress judgment lives
// in the request layer (the shared lock-and-pin guard immediately before
// dispatch); folding it into derivation once reported a legal loopback
// authority as a malformed DID and sent an investigation down the wrong path.

fn webvh_url_error(did: &str) -> DidWebvhUrlError {
    let did = Did::new(did.to_owned()).expect("DID syntax is accepted by the wire type");
    // The resolver flattens to IdentityError::Protocol for the wire, so assert both:
    // that the accessor still refuses, and how the helper classified it.
    DidWebvhResolver::log_url(&did).expect_err("this DID must not yield a URL");
    try_did_webvh_url(&did, "did.jsonl").expect_err("this DID must not yield a URL")
}

#[test]
fn loopback_authority_derives_a_url_egress_is_a_request_layer_decision() {
    // A loopback authority is legal did:webvh syntax. Derivation must succeed;
    // declining the connection target is the request layer's job (the shared
    // egress lock), not the derivation layer's.
    let did = Did::new(
        "did:webvh:QmVyZsGytuMfgNoLET2Uw2VakH5cgUrZP94AJMQhT316zV:127.0.0.1%3A20623:webvh:service"
            .to_owned(),
    )
    .unwrap();
    assert_eq!(
        DidWebvhResolver::log_url(&did).unwrap(),
        "https://127.0.0.1:20623/webvh/service/did.jsonl"
    );
}

#[test]
fn malformed_and_unsupported_forms_stay_distinguishable() {
    // A bare host with no dot cannot host a did:webvh log.
    assert_eq!(
        webvh_url_error("did:webvh:QmVyZsGytuMfgNoLET2Uw2VakH5cgUrZP94AJMQhT316zV:example"),
        DidWebvhUrlError::InvalidAuthority
    );
    // A path segment escaping its directory is malformed syntax.
    assert_eq!(
        webvh_url_error(
            "did:webvh:QmVyZsGytuMfgNoLET2Uw2VakH5cgUrZP94AJMQhT316zV:example.com:..:service"
        ),
        DidWebvhUrlError::InvalidSyntax
    );
    // Another method is not malformed did:webvh syntax; it is simply not
    // this helper's method.
    assert_eq!(
        webvh_url_error("did:web:example.com"),
        DidWebvhUrlError::UnsupportedMethod
    );
}

#[test]
fn a_public_authority_still_derives_every_artifact_url() {
    let did = Did::new(
        "did:webvh:QmVyZsGytuMfgNoLET2Uw2VakH5cgUrZP94AJMQhT316zV:example.com:webvh:service"
            .to_owned(),
    )
    .unwrap();
    assert_eq!(
        DidWebvhResolver::log_url(&did).unwrap(),
        "https://example.com/webvh/service/did.jsonl"
    );
    assert_eq!(
        DidWebvhResolver::document_url(&did).unwrap(),
        "https://example.com/webvh/service/did.json"
    );
    assert_eq!(
        DidWebvhResolver::witness_url(&did).unwrap(),
        "https://example.com/webvh/service/did-witness.json"
    );
}

// ── Caller-closure gate: the derivation layer must stay policy-free ──
//
// The SSRF boundary is the request layer's shared egress lock, not URL
// derivation. This source-level gate fails if a future change reintroduces
// an egress judgment (`host_is_safe_for_outbound` / `classify_host` /
// `classify_ip`) into either derivation helper, because that is exactly the
// coupling that made a legal DID report itself as "unsupported did:webvh
// form" and that prevented deployments from applying their own trust
// anchors.

#[test]
fn url_derivation_helpers_hold_no_egress_judgment() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/helpers.rs");
    let text = std::fs::read_to_string(&path).expect("helpers.rs source");
    let production = text.split("\n#[cfg(test)]").next().unwrap_or(&text);
    let banned = ["host_is_safe_for_outbound", "classify_host", "classify_ip"];
    for (start, end) in [
        (
            "fn did_web_document_url",
            "fn is_allowed_did_web_content_type",
        ),
        ("fn try_did_webvh_url", "fn did_key_material"),
    ] {
        let body = production
            .split(start)
            .nth(1)
            .unwrap_or_else(|| panic!("{start} must exist in helpers.rs"))
            .split(end)
            .next()
            .unwrap_or_else(|| panic!("{end} must follow {start} in helpers.rs"));
        for needle in banned {
            assert!(
                !body
                    .lines()
                    .any(|line| { !line.trim_start().starts_with("//") && line.contains(needle) }),
                "{start} must stay a pure syntax-to-URL derivation; found {needle:?}"
            );
        }
    }
}
