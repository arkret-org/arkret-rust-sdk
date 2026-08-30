use arkret_wire::{CORE_REDUCER_PROFILE, Did, DidUrl};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{merkle, *};
use crate::{DidCoreId, EventId, Hash, Hlc, PayloadSignature, RealmId, SnapshotId};

fn actor() -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
}

fn did() -> Did {
    Did::new("did:webvh:z6mkfixture:generator.example").unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN".to_owned()).unwrap()
}

fn snapshot_v1_event_id(suffix: &str) -> EventId {
    EventId::from_event_digest(
        &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
    )
    .unwrap()
}

fn snapshot_v1_id() -> SnapshotId {
    SnapshotId::new("ak:snapshot:01904100-0000-7000-8000-000000000001".to_owned()).unwrap()
}

fn hash(seed: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn manifest_for_items(
    items: Vec<SnapshotMaterializedItem>,
) -> (SnapshotManifest, Vec<SnapshotChunkPayload>, Vec<Vec<u8>>) {
    let state_digest = state_digest_from_items(&items).unwrap();
    let built =
        build_snapshot_chunks(&snapshot_v1_id(), CORE_REDUCER_PROFILE, items, 4096).unwrap();
    let chunk_payloads = built
        .iter()
        .map(|chunk| chunk.payload.clone())
        .collect::<Vec<_>>();
    let chunk_bytes = built
        .iter()
        .map(|chunk| chunk.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let descriptors = built
        .into_iter()
        .map(|chunk| chunk.descriptor)
        .collect::<Vec<_>>();
    let created_at = "2026-06-01T00:00:00.000Z".parse::<DateTime<Utc>>().unwrap();
    let mut manifest = SnapshotManifest {
        id: snapshot_v1_id(),
        realm_id: realm(),
        reducer_profile: CORE_REDUCER_PROFILE.to_owned(),
        schema_profile_refs: vec!["ak.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: SnapshotFrontier {
            event_ids: vec![snapshot_v1_event_id("000000000001")],
            timeline_hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: EventSetCommitment {
            algorithm: EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: hash(9),
            covered_event_count: 1,
            actor_seq_ranges: Vec::new(),
        },
        chunks: descriptors,
        security_class: SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: arkret_wire::ActorId::service(actor()),
        created_at,
        authority_binding: AuthorityBinding {
            authority_kind: SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: hash(1),
            auth_frontier: vec![snapshot_v1_event_id("000000000001")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: DetachedJwsProof::ed25519(
            DidUrl::new("did:webvh:z6mkfixture:generator.example#snapshot").unwrap(),
            hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_payloads, chunk_bytes)
}

// ── Chunker ───────────────────────────────────────────────────────

#[test]
fn chunker_zero_target_rejected() {
    let err = SnapshotChunker::new(0).unwrap_err();
    assert!(format!("{err}").contains("target_chunk_bytes must be > 0"));
}

#[test]
fn chunker_empty_input_yields_empty() {
    let c = SnapshotChunker::default();
    assert!(c.chunk(&[]).is_empty());
}

#[test]
fn chunker_partitions_with_last_chunk_short() {
    let c = SnapshotChunker::new(4).unwrap();
    let chunks = c.chunk(b"hello world!"); // 12 bytes → 3 chunks of 4
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].chunk_id, 0);
    assert_eq!(chunks[0].bytes, b"hell");
    assert_eq!(chunks[1].chunk_id, 1);
    assert_eq!(chunks[1].bytes, b"o wo");
    assert_eq!(chunks[2].chunk_id, 2);
    assert_eq!(chunks[2].bytes, b"rld!");

    // 13-byte input → 3 chunks (4 / 4 / 5? no — 4 / 4 / 5 isn't right;
    // chunks() of size 4 → 4,4,5 only if step > 4. std slice::chunks
    // is fixed-size so 13/4 = 3 full + 1 short = 4 chunks. Let me re-check.
    let c2 = SnapshotChunker::new(4).unwrap();
    let chunks2 = c2.chunk(b"hello world!!"); // 13 bytes
    assert_eq!(chunks2.len(), 4); // 4+4+4+1
    assert_eq!(chunks2[3].bytes.len(), 1);
}

#[test]
fn chunker_digests_match_recomputation() {
    let c = SnapshotChunker::new(8).unwrap();
    let chunks = c.chunk(b"the quick brown fox jumps over the lazy dog");
    for chunk in &chunks {
        let recomputed = merkle::sha256_digest(&chunk.bytes);
        assert_eq!(chunk.digest, recomputed);
    }
}

#[test]
fn chunker_is_deterministic_across_runs() {
    let c = SnapshotChunker::new(16).unwrap();
    let a = c.chunk(b"the quick brown fox jumps over the lazy dog");
    let b = c.chunk(b"the quick brown fox jumps over the lazy dog");
    assert_eq!(a, b);
}

// ── Merkle tree ───────────────────────────────────────────────────

fn chunks(n: u32) -> Vec<SnapshotChunk> {
    let c = SnapshotChunker::new(4).unwrap();
    let mut bytes = Vec::new();
    for i in 0..(n * 4) {
        bytes.push((i % 256) as u8);
    }
    c.chunk(&bytes)
}

#[test]
fn merkle_empty_rejected() {
    let err = SnapshotMerkleTree::build(&[]).unwrap_err();
    assert!(format!("{err}").contains("at least one chunk"));
}

#[test]
fn merkle_out_of_order_rejected() {
    let mut cs = chunks(2);
    cs.swap(0, 1);
    let err = SnapshotMerkleTree::build(&cs).unwrap_err();
    assert!(format!("{err}").contains("expected"));
}

#[test]
fn merkle_single_leaf_root_is_domain_separated() {
    let cs = chunks(1);
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    assert_eq!(tree.leaf_count(), 1);
    let leaf_data = parse_sha256(&cs[0].digest).unwrap();
    assert_eq!(*tree.root(), format_hash(&hash_leaf(&leaf_data)));
    assert_ne!(tree.root(), &cs[0].digest);
    // Audit path is empty for single-leaf trees.
    assert_eq!(tree.audit_path(0).unwrap().len(), 0);
}

#[test]
fn merkle_two_leaves_root_is_hash_pair() {
    let cs = chunks(2);
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    // root = sha256(0x01 || sha256(0x00 || leaf0) || sha256(0x00 || leaf1)).
    let left = parse_sha256(&cs[0].digest).unwrap();
    let right = parse_sha256(&cs[1].digest).unwrap();
    let expected = hash_node(&hash_leaf(&left), &hash_leaf(&right));
    assert_eq!(*tree.root(), format_hash(&expected));
}

#[test]
fn merkle_audit_path_verifies_each_leaf() {
    for n in [1u32, 2, 3, 4, 5, 8, 11] {
        let cs = chunks(n);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        let root = tree.root().clone();
        for (i, chunk) in cs.iter().enumerate() {
            let path = tree.audit_path(i).unwrap();
            assert!(
                SnapshotMerkleTree::verify(&root, &chunk.digest, i, &path, tree.leaf_count()),
                "audit_path verification failed for n={n} leaf={i}"
            );
        }
    }
}

#[test]
fn merkle_audit_path_rejects_wrong_leaf() {
    let cs = chunks(4);
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    let path = tree.audit_path(0).unwrap();
    // Try to use leaf-0's path with leaf-1's digest — should fail.
    assert!(!SnapshotMerkleTree::verify(
        tree.root(),
        &cs[1].digest,
        0,
        &path,
        tree.leaf_count()
    ));
}

#[test]
fn merkle_out_of_range_index_rejected() {
    let cs = chunks(2);
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    assert!(tree.audit_path(2).is_none());
}

#[test]
fn merkle_duplicate_tail_leaf_changes_root() {
    // Promote-without-duplication: [A,B,C] and [A,B,C,C] MUST NOT
    // share a root (CVE-2012-2459-shaped ambiguity).
    let cs3 = chunks(3);
    let tree3 = SnapshotMerkleTree::build(&cs3).unwrap();
    let mut cs4 = cs3.clone();
    cs4.push(SnapshotChunk {
        chunk_id: 3,
        bytes: cs3[2].bytes.clone(),
        digest: cs3[2].digest.clone(),
    });
    let tree4 = SnapshotMerkleTree::build(&cs4).unwrap();
    assert_ne!(tree3.root(), tree4.root());
}

#[test]
fn merkle_verify_rejects_mismatched_leaf_count() {
    let cs = chunks(3);
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    let path = tree.audit_path(2).unwrap();
    assert!(SnapshotMerkleTree::verify(
        tree.root(),
        &cs[2].digest,
        2,
        &path,
        3
    ));
    // The same proof under a different claimed leaf_count MUST fail.
    assert!(!SnapshotMerkleTree::verify(
        tree.root(),
        &cs[2].digest,
        3,
        &path,
        4
    ));
    assert!(!SnapshotMerkleTree::verify(
        tree.root(),
        &cs[2].digest,
        2,
        &path,
        4
    ));
}

// ── GeneratorProof ─────────────────────────────────────────────────

fn move_sig(payload_digest: Hash) -> PayloadSignature {
    PayloadSignature {
        verification_method: DidUrl::new("did:webvh:z6mkfixture:generator.example#k1").unwrap(),
        payload_digest,
        created_at: Utc::now(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

#[test]
fn generator_proof_body_digest_round_trips() {
    let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
    let digest =
        GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 42, 1024, 256)
            .unwrap();

    let proof = GeneratorProof {
        generator_did: did(),
        realm_id: realm(),
        state_root,
        merkle_root,
        chunk_count: 42,
        total_bytes: 1024,
        chunk_bytes: 256,
        signature: move_sig(digest),
    };
    proof.verify_payload_digest().unwrap();
}

#[test]
fn generator_proof_mismatched_payload_digest_rejected() {
    let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
    let wrong = Hash::new(format!("sha256:{}", "ee".repeat(32))).unwrap();
    let proof = GeneratorProof {
        generator_did: did(),
        realm_id: realm(),
        state_root,
        merkle_root,
        chunk_count: 1,
        total_bytes: 4,
        chunk_bytes: 4,
        signature: move_sig(wrong),
    };
    let err = proof.verify_payload_digest().unwrap_err();
    assert!(format!("{err}").contains("payload_digest mismatch"));
}

#[test]
fn generator_proof_changing_chunk_count_changes_digest() {
    let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
    let d1 =
        GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 1, 4, 4).unwrap();
    let d2 =
        GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 2, 4, 4).unwrap();
    assert_ne!(d1, d2, "chunk_count must be in the canonical bytes");
}

#[test]
fn generator_proof_serializes_with_all_fields() {
    let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
    let digest =
        GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 3, 12, 4).unwrap();
    let proof = GeneratorProof {
        generator_did: did(),
        realm_id: realm(),
        state_root,
        merkle_root,
        chunk_count: 3,
        total_bytes: 12,
        chunk_bytes: 4,
        signature: move_sig(digest),
    };
    let v: Value = serde_json::to_value(&proof).unwrap();
    for f in [
        "generator_did",
        "realm_id",
        "state_root",
        "merkle_root",
        "chunk_count",
        "total_bytes",
        "chunk_bytes",
        "signature",
    ] {
        assert!(v.get(f).is_some(), "missing {f}");
    }
}

#[test]
fn snapshot_chunk_round_trips_base64() {
    let chunk = SnapshotChunk {
        chunk_id: 7,
        bytes: vec![0x00, 0xff, 0x42, 0x55],
        digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
    };
    let s = serde_json::to_string(&chunk).unwrap();
    let back: SnapshotChunk = serde_json::from_str(&s).unwrap();
    assert_eq!(back, chunk);
}

fn event_id(suffix: &str) -> EventId {
    EventId::from_event_digest(
        &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
    )
    .unwrap()
}

fn snapshot_id() -> SnapshotId {
    SnapshotId::new("ak:snapshot:01904100-0000-7000-8000-000000000001").unwrap()
}

fn state_item(kind: &str, id: &str, source_suffix: &str) -> SnapshotMaterializedItem {
    SnapshotMaterializedItem {
        kind: kind.to_owned(),
        id: id.to_owned(),
        object: serde_json::json!({
            "id": id,
            "kind": kind,
            "schema": "ak.schema.test.v1"
        }),
        source_event_id: event_id(source_suffix),
    }
}

#[test]
fn spec_merkle_empty_root_is_sha256_empty() {
    let root = merkle_root_from_hashes(Vec::new()).unwrap();
    assert_eq!(root.as_str(), EMPTY_SHA256_DIGEST);
}

#[test]
fn spec_merkle_rfc6962_fixed_vectors() {
    let leaf =
        |byte: u8| Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap();
    let one = leaf(0x11);
    let two = leaf(0x22);
    let three = leaf(0x33);

    assert_eq!(
        merkle_root_from_hashes(vec![one.clone()]).unwrap().as_str(),
        "sha256:4635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e"
    );
    assert_eq!(
        merkle_root_from_hashes(vec![one.clone(), two.clone()])
            .unwrap()
            .as_str(),
        "sha256:cc15b132263fd4fd2748c0e7cb9e1c4ad0afe70fcf9382ee644c4da8af0286a5"
    );
    assert_eq!(
        merkle_root_from_hashes(vec![one, two, three])
            .unwrap()
            .as_str(),
        "sha256:9bee4401962e94b921336a7910a5a9718836ffcbc545dde0a3f34d858beb5752"
    );
}

#[test]
fn merkle_verify_rejects_wrong_branch() {
    let cs = [0x11, 0x22]
        .into_iter()
        .enumerate()
        .map(|(chunk_id, byte)| SnapshotChunk {
            chunk_id: chunk_id as u32,
            bytes: vec![byte],
            digest: Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        })
        .collect::<Vec<_>>();
    let tree = SnapshotMerkleTree::build(&cs).unwrap();
    let wrong_path = vec![Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap()];
    assert!(!SnapshotMerkleTree::verify(
        tree.root(),
        &cs[0].digest,
        0,
        &wrong_path,
        2
    ));
}

#[test]
fn event_set_commitment_sorts_entries_before_hashing() {
    let a = EventSetLeaf {
        event_id: event_id("000000000001"),
        event_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        actor_seq: 1,
        hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
    };
    let b = EventSetLeaf {
        event_id: event_id("000000000002"),
        event_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
        actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        actor_seq: 1,
        hlc: Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
    };

    let forward = event_set_root(
        &EventSetCommitmentAlgorithm::MerkleEventSetV1,
        &[a.clone(), b.clone()],
    )
    .unwrap();
    let reversed = event_set_root(&EventSetCommitmentAlgorithm::MerkleEventSetV1, &[b, a]).unwrap();

    assert_eq!(forward, reversed);
}

#[test]
fn spec_chunk_builder_uses_item_boundaries_and_digest_refs() {
    let items = vec![
        state_item(
            "message",
            "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "000000000002",
        ),
        state_item(
            "strand",
            "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "000000000001",
        ),
    ];

    let built = build_snapshot_chunks(&snapshot_id(), CORE_REDUCER_PROFILE, items, 240).unwrap();

    assert_eq!(
        built
            .iter()
            .map(|chunk| chunk.payload.items.len())
            .sum::<usize>(),
        2
    );
    for (index, chunk) in built.iter().enumerate() {
        assert_eq!(chunk.payload.index, index as u32);
        assert_eq!(
            chunk.descriptor.digest,
            merkle::sha256_digest(&chunk.canonical_bytes)
        );
        assert_eq!(
            chunk.descriptor.chunk_ref.as_str(),
            format!("ak:blob:{}", chunk.descriptor.digest).as_str()
        );
    }
}

#[test]
fn state_digest_rejects_duplicate_kind_id() {
    let item = state_item(
        "strand",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "000000000001",
    );
    let err = state_digest_from_items(&[item.clone(), item]).unwrap_err();
    assert!(format!("{err}").contains("duplicate snapshot item key"));
}

fn witness_quorum_manifest(witnesses: &[(&str, &str)]) -> SnapshotManifest {
    let item = state_item(
        "strand",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "000000000001",
    );
    let (mut manifest, ..) = manifest_for_items(vec![item]);
    manifest.authority_binding.authority_kind = SnapshotAuthorityKind::WitnessQuorum;
    manifest.verification_hints = Some(SnapshotVerificationHints {
        verification_profile: SnapshotSecurityClass::Standard,
        inclusion_proof_url: None,
        challenge_window_seconds: None,
        conflict_records_digest: None,
        soft_failed_digest: None,
        quarantined_digest: None,
    });
    let created_at = manifest.created_at;
    manifest.authority_binding.witness_attestations = witnesses
        .iter()
        .map(|(core_id, did)| {
            let witness_id = DidCoreId::new((*core_id).to_owned()).unwrap();
            let digest = manifest.witness_attestation_digest(&witness_id).unwrap();
            SnapshotWitnessAttestation {
                witness_id,
                proof: DetachedJwsProof::ed25519(
                    DidUrl::new(format!("{did}#snapshot-witness")).unwrap(),
                    digest,
                    created_at,
                    "header..signature".to_owned(),
                ),
            }
        })
        .collect();
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    manifest
}

fn witness_policy(core_ids: &[&str], threshold: u32) -> SnapshotWitnessQuorumPolicy {
    SnapshotWitnessQuorumPolicy {
        authorized_witnesses: core_ids
            .iter()
            .map(|value| DidCoreId::new((*value).to_owned()).unwrap())
            .collect(),
        threshold,
    }
}

const WITNESS_ONE: (&str, &str) = (
    "ak:did_core:webvh:z6mkwitnessaaa",
    "did:webvh:z6mkwitnessaaa:witness-a.example",
);
const WITNESS_TWO: (&str, &str) = (
    "ak:did_core:webvh:z6mkwitnessbbb",
    "did:webvh:z6mkwitnessbbb:witness-b.example",
);

#[test]
fn witness_attestation_projection_excludes_signatures_and_witness_list() {
    let manifest = witness_quorum_manifest(&[WITNESS_ONE, WITNESS_TWO]);
    let witness_id = DidCoreId::new(WITNESS_ONE.0.to_owned()).unwrap();
    let projection = manifest
        .witness_attestation_projection(&witness_id)
        .unwrap();
    let projection = projection.as_object().unwrap();

    assert_eq!(
        projection["context"],
        Value::String(SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT.to_owned())
    );
    for excluded in [
        "signature",
        "witness_attestations",
        "verification_hints",
        "chunks",
        "created_by",
        "checked_at",
    ] {
        assert!(
            !projection.contains_key(excluded),
            "projection must exclude {excluded}"
        );
    }
    assert_eq!(projection["issuer"], serde_json::to_value(actor()).unwrap());
    assert_eq!(
        projection["snapshot_created_at"],
        "2026-06-01T00:00:00.000Z"
    );
}

#[test]
fn witness_quorum_accepts_sorted_authorized_quorum() {
    let manifest = witness_quorum_manifest(&[WITNESS_ONE, WITNESS_TWO]);
    manifest
        .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0, WITNESS_TWO.0], 2))
        .unwrap();
}

#[test]
fn witness_quorum_rejects_unsorted_or_duplicate_rows() {
    let mut manifest = witness_quorum_manifest(&[WITNESS_ONE, WITNESS_TWO]);
    manifest.authority_binding.witness_attestations.reverse();
    let error = manifest
        .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0, WITNESS_TWO.0], 2))
        .unwrap_err();
    assert_eq!(error.code, SnapshotValidationCode::SchemaViolation);

    let mut duplicated = witness_quorum_manifest(&[WITNESS_ONE, WITNESS_TWO]);
    duplicated.authority_binding.witness_attestations[1].witness_id =
        DidCoreId::new(WITNESS_ONE.0.to_owned()).unwrap();
    let error = duplicated
        .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0, WITNESS_TWO.0], 2))
        .unwrap_err();
    assert_eq!(error.code, SnapshotValidationCode::SchemaViolation);
}

#[test]
fn witness_quorum_requires_attestations_and_policy_threshold() {
    let mut missing = witness_quorum_manifest(&[WITNESS_ONE]);
    missing.authority_binding.witness_attestations.clear();
    assert_eq!(
        missing
            .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0], 1))
            .unwrap_err()
            .code,
        SnapshotValidationCode::SchemaViolation
    );

    let manifest = witness_quorum_manifest(&[WITNESS_ONE]);
    assert_eq!(
        manifest
            .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0], 2))
            .unwrap_err()
            .code,
        SnapshotValidationCode::SnapshotAuthorityUnverified
    );

    let unauthorized = witness_quorum_manifest(&[WITNESS_ONE]);
    assert_eq!(
        unauthorized
            .verify_witness_attestations(&witness_policy(&[WITNESS_TWO.0], 1))
            .unwrap_err()
            .code,
        SnapshotValidationCode::SnapshotAuthorityUnverified
    );
}

#[test]
fn witness_quorum_rejects_manifest_context_and_foreign_controller() {
    let mut wrong_transcript = witness_quorum_manifest(&[WITNESS_ONE]);
    wrong_transcript.authority_binding.witness_attestations[0]
        .proof
        .payload_digest = wrong_transcript.expected_signature_digest().unwrap();
    assert_eq!(
        wrong_transcript
            .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0], 1))
            .unwrap_err()
            .code,
        SnapshotValidationCode::SignatureInvalid
    );

    let mut foreign_controller = witness_quorum_manifest(&[WITNESS_ONE]);
    foreign_controller.authority_binding.witness_attestations[0]
        .proof
        .verification_method = DidUrl::new(format!("{}#snapshot-witness", WITNESS_TWO.1)).unwrap();
    assert_eq!(
        foreign_controller
            .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0], 1))
            .unwrap_err()
            .code,
        SnapshotValidationCode::SignatureInvalid
    );
}
