use arkret_wire::{CORE_REDUCER_PROFILE, Did, DidUrl};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{merkle, *};
use crate::lattice::cas_register::CasHead;
use crate::{
    CellRef, DidCoreId, EventId, Hash, Hlc, PayloadSignature, RealmId, RealmStateSnapshotId,
};

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

fn snapshot_v1_id() -> RealmStateSnapshotId {
    RealmStateSnapshotId::new(
        "ak:realm_state_snapshot:01904100-0000-7000-8000-000000000001".to_owned(),
    )
    .unwrap()
}

fn hash(seed: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn manifest_for_items(
    items: Vec<RealmStateSnapshotMaterializedItem>,
) -> (
    RealmStateSnapshotManifest,
    Vec<RealmStateRealmStateSnapshotChunkPayload>,
    Vec<Vec<u8>>,
) {
    let state_digest = state_digest_from_items(&items).unwrap();
    let built =
        build_realm_state_snapshot_chunks(&snapshot_v1_id(), CORE_REDUCER_PROFILE, items, 4096)
            .unwrap();
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
    let mut manifest = RealmStateSnapshotManifest {
        id: snapshot_v1_id(),
        realm_id: realm(),
        reducer_profile: CORE_REDUCER_PROFILE.to_owned(),
        schema_profile_refs: vec!["ak.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: RealmStateSnapshotFrontier {
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
        security_class: RealmStateSnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: arkret_wire::ActorId::service(actor()),
        created_at,
        authority_binding: AuthorityBinding {
            authority_kind: RealmStateSnapshotAuthorityKind::RealmPolicySnapshotIssuer,
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
    let err = RealmStateRealmStateSnapshotChunker::new(0).unwrap_err();
    assert!(format!("{err}").contains("target_chunk_bytes must be > 0"));
}

#[test]
fn chunker_empty_input_yields_empty() {
    let c = RealmStateRealmStateSnapshotChunker::default();
    assert!(c.chunk(&[]).is_empty());
}

#[test]
fn chunker_partitions_with_last_chunk_short() {
    let c = RealmStateRealmStateSnapshotChunker::new(4).unwrap();
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
    let c2 = RealmStateRealmStateSnapshotChunker::new(4).unwrap();
    let chunks2 = c2.chunk(b"hello world!!"); // 13 bytes
    assert_eq!(chunks2.len(), 4); // 4+4+4+1
    assert_eq!(chunks2[3].bytes.len(), 1);
}

#[test]
fn chunker_digests_match_recomputation() {
    let c = RealmStateRealmStateSnapshotChunker::new(8).unwrap();
    let chunks = c.chunk(b"the quick brown fox jumps over the lazy dog");
    for chunk in &chunks {
        let recomputed = merkle::sha256_digest(&chunk.bytes);
        assert_eq!(chunk.digest, recomputed);
    }
}

#[test]
fn chunker_is_deterministic_across_runs() {
    let c = RealmStateRealmStateSnapshotChunker::new(16).unwrap();
    let a = c.chunk(b"the quick brown fox jumps over the lazy dog");
    let b = c.chunk(b"the quick brown fox jumps over the lazy dog");
    assert_eq!(a, b);
}

// ── Merkle tree ───────────────────────────────────────────────────

fn chunks(n: u32) -> Vec<RealmStateSnapshotChunk> {
    let c = RealmStateRealmStateSnapshotChunker::new(4).unwrap();
    let mut bytes = Vec::new();
    for i in 0..(n * 4) {
        bytes.push((i % 256) as u8);
    }
    c.chunk(&bytes)
}

#[test]
fn merkle_empty_rejected() {
    let err = RealmStateSnapshotMerkleTree::build(&[]).unwrap_err();
    assert!(format!("{err}").contains("at least one chunk"));
}

#[test]
fn merkle_out_of_order_rejected() {
    let mut cs = chunks(2);
    cs.swap(0, 1);
    let err = RealmStateSnapshotMerkleTree::build(&cs).unwrap_err();
    assert!(format!("{err}").contains("expected"));
}

#[test]
fn merkle_single_leaf_root_is_domain_separated() {
    let cs = chunks(1);
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
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
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
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
        let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
        let root = tree.root().clone();
        for (i, chunk) in cs.iter().enumerate() {
            let path = tree.audit_path(i).unwrap();
            assert!(
                RealmStateSnapshotMerkleTree::verify(
                    &root,
                    &chunk.digest,
                    i,
                    &path,
                    tree.leaf_count()
                ),
                "audit_path verification failed for n={n} leaf={i}"
            );
        }
    }
}

#[test]
fn merkle_audit_path_rejects_wrong_leaf() {
    let cs = chunks(4);
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
    let path = tree.audit_path(0).unwrap();
    // Try to use leaf-0's path with leaf-1's digest — should fail.
    assert!(!RealmStateSnapshotMerkleTree::verify(
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
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
    assert!(tree.audit_path(2).is_none());
}

#[test]
fn merkle_duplicate_tail_leaf_changes_root() {
    // Promote-without-duplication: [A,B,C] and [A,B,C,C] MUST NOT
    // share a root (CVE-2012-2459-shaped ambiguity).
    let cs3 = chunks(3);
    let tree3 = RealmStateSnapshotMerkleTree::build(&cs3).unwrap();
    let mut cs4 = cs3.clone();
    cs4.push(RealmStateSnapshotChunk {
        chunk_id: 3,
        bytes: cs3[2].bytes.clone(),
        digest: cs3[2].digest.clone(),
    });
    let tree4 = RealmStateSnapshotMerkleTree::build(&cs4).unwrap();
    assert_ne!(tree3.root(), tree4.root());
}

#[test]
fn merkle_verify_rejects_mismatched_leaf_count() {
    let cs = chunks(3);
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
    let path = tree.audit_path(2).unwrap();
    assert!(RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &cs[2].digest,
        2,
        &path,
        3
    ));
    // The same proof under a different claimed leaf_count MUST fail.
    assert!(!RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &cs[2].digest,
        3,
        &path,
        4
    ));
    assert!(!RealmStateSnapshotMerkleTree::verify(
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
fn realm_state_snapshot_chunk_round_trips_base64() {
    let chunk = RealmStateSnapshotChunk {
        chunk_id: 7,
        bytes: vec![0x00, 0xff, 0x42, 0x55],
        digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
    };
    let s = serde_json::to_string(&chunk).unwrap();
    let back: RealmStateSnapshotChunk = serde_json::from_str(&s).unwrap();
    assert_eq!(back, chunk);
}

fn event_id(suffix: &str) -> EventId {
    EventId::from_event_digest(
        &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
    )
    .unwrap()
}

fn realm_state_snapshot_id() -> RealmStateSnapshotId {
    RealmStateSnapshotId::new("ak:realm_state_snapshot:01904100-0000-7000-8000-000000000001")
        .unwrap()
}

/// A materialized non-`cas_register` cell item (`realm-state-snapshot-schema.md` §3).
fn cell_item(cell: &str, value: Value) -> RealmStateSnapshotMaterializedItem {
    RealmStateSnapshotMaterializedItem::value(CellRef::new(cell.to_owned()).unwrap(), value)
        .unwrap()
}

const STRAND_LIFECYCLE_CELL: &str = "ak:cell:ak.component.strand.lifecycle.v1:ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const MESSAGE_REACTIONS_CELL: &str = "ak:cell:ak.component.message.reactions.v1:ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";

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
        .map(|(chunk_id, byte)| RealmStateSnapshotChunk {
            chunk_id: chunk_id as u32,
            bytes: vec![byte],
            digest: Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        })
        .collect::<Vec<_>>();
    let tree = RealmStateSnapshotMerkleTree::build(&cs).unwrap();
    let wrong_path = vec![Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap()];
    assert!(!RealmStateSnapshotMerkleTree::verify(
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
        actor_id: arkret_wire::ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        ),
        actor_seq: 1,
        hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
    };
    let b = EventSetLeaf {
        event_id: event_id("000000000002"),
        event_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
        actor_id: arkret_wire::ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        ),
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
        cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("archived")),
        cell_item(MESSAGE_REACTIONS_CELL, serde_json::json!([])),
    ];

    let built = build_realm_state_snapshot_chunks(
        &realm_state_snapshot_id(),
        CORE_REDUCER_PROFILE,
        items,
        240,
    )
    .unwrap();

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
            chunk.descriptor.chunk_ref.as_str(),
            format!("ak:blob:{}", merkle::sha256_digest(&chunk.canonical_bytes)).as_str()
        );
    }
}

#[test]
fn state_digest_rejects_duplicate_cell() {
    let item = cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active"));
    let err = state_digest_from_items(&[item.clone(), item]).unwrap_err();
    assert!(format!("{err}").contains("duplicate snapshot item cell"));
}

fn witness_quorum_manifest(witnesses: &[(&str, &str)]) -> RealmStateSnapshotManifest {
    let item = cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active"));
    let (mut manifest, ..) = manifest_for_items(vec![item]);
    manifest.authority_binding.authority_kind = RealmStateSnapshotAuthorityKind::WitnessQuorum;
    manifest.verification_hints = Some(RealmStateSnapshotVerificationHints {
        verification_profile: RealmStateSnapshotSecurityClass::Standard,
        inclusion_proof_url: None,
        challenge_window_seconds: None,
        conflict_records_digest: None,
        soft_failed_digest: None,
        quarantined_digest: None,
        erasure_stubs_digest: None,
    });
    let created_at = manifest.created_at;
    manifest.authority_binding.witness_attestations = witnesses
        .iter()
        .map(|(core_id, did)| {
            let witness_id = DidCoreId::new((*core_id).to_owned()).unwrap();
            let digest = manifest.witness_attestation_digest(&witness_id).unwrap();
            RealmStateSnapshotWitnessAttestation {
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

fn witness_policy(core_ids: &[&str], threshold: u32) -> RealmStateSnapshotWitnessQuorumPolicy {
    RealmStateSnapshotWitnessQuorumPolicy {
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
        Value::String(REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT.to_owned())
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
    assert_eq!(
        projection["issuer"],
        serde_json::to_value(arkret_wire::ActorId::service(actor())).unwrap()
    );
    assert_eq!(
        projection["realm_state_snapshot_created_at"],
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
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SchemaViolation
    );

    let mut duplicated = witness_quorum_manifest(&[WITNESS_ONE, WITNESS_TWO]);
    duplicated.authority_binding.witness_attestations[1].witness_id =
        DidCoreId::new(WITNESS_ONE.0.to_owned()).unwrap();
    let error = duplicated
        .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0, WITNESS_TWO.0], 2))
        .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SchemaViolation
    );
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
        RealmStateSnapshotValidationCode::SchemaViolation
    );

    let manifest = witness_quorum_manifest(&[WITNESS_ONE]);
    assert_eq!(
        manifest
            .verify_witness_attestations(&witness_policy(&[WITNESS_ONE.0], 2))
            .unwrap_err()
            .code,
        RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified
    );

    let unauthorized = witness_quorum_manifest(&[WITNESS_ONE]);
    assert_eq!(
        unauthorized
            .verify_witness_attestations(&witness_policy(&[WITNESS_TWO.0], 1))
            .unwrap_err()
            .code,
        RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified
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
        RealmStateSnapshotValidationCode::SignatureInvalid
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
        RealmStateSnapshotValidationCode::SignatureInvalid
    );
}

/// One head, in the SDK form the lattice produces.
fn cas_head(byte: u8, value: Value) -> CasHead {
    CasHead {
        move_id: Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        value,
    }
}

fn slot_cell() -> CellRef {
    CellRef::new(
        "ak:cell:ak.component.invite.live_target.v1:fAWD6k02hF3JHnquwsCU7inqyb8Qdajftruz5xEWFGc"
            .to_owned(),
    )
    .unwrap()
}

/// `realm-state-snapshot-schema.md` §3: the one item branch is `{kind:"cell", id, state}`,
/// a CAS cell's `state` is its head set, and its identity is the `ak:event:`
/// spelling recovered from the op log's `event_digest`.
#[test]
fn a_cas_cell_item_serializes_to_the_closed_branch() {
    let item =
        RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &[cas_head(0x11, Value::Null)])
            .unwrap();
    let wire = serde_json::to_value(&item).unwrap();

    assert_eq!(wire["kind"], "cell");
    assert_eq!(wire["id"], slot_cell().as_str());
    assert!(wire.get("object").is_none());
    assert!(wire.get("source_event_id").is_none());
    assert!(wire["state"].get("value").is_none());
    let heads = wire["state"]["heads"].as_array().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0]["value"], Value::Null);
    let expected_id =
        EventId::from_event_digest(&cas_head(0x11, serde_json::json!(null)).move_id).unwrap();
    assert_eq!(heads[0]["event_id"], expected_id.as_str());

    assert_eq!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(wire).unwrap(),
        item
    );
}

/// A materialized non-CAS cell serializes to the same branch with a `value`
/// state, and the two state shapes never mix.
#[test]
fn a_value_cell_item_serializes_to_the_closed_branch() {
    let item = cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("archived"));
    let wire = serde_json::to_value(&item).unwrap();
    assert_eq!(wire["kind"], "cell");
    assert_eq!(wire["id"], STRAND_LIFECYCLE_CELL);
    assert_eq!(wire["state"], serde_json::json!({"value": "archived"}));
    assert_eq!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(wire).unwrap(),
        item
    );
}

/// A released slot and an unwritten one both read `null`, so the chunk has to
/// keep the release write's identity or the two become the same snapshot.
#[test]
fn a_released_slot_is_a_member_and_an_unwritten_one_is_not() {
    let released =
        RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &[cas_head(0x22, Value::Null)])
            .unwrap();
    let claimed = RealmStateSnapshotMaterializedItem::cas_cell(
        slot_cell(),
        &[cas_head(0x22, serde_json::json!("ak:event:AUC6Bg"))],
    )
    .unwrap();
    assert_ne!(
        realm_state_snapshot_state_leaf_hash(&released).unwrap(),
        realm_state_snapshot_state_leaf_hash(&claimed).unwrap(),
    );

    // An unwritten cell is not a member at all (§6.2.1), so it cannot be built.
    assert!(RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &[]).is_err());
}

/// Two heads that agree on a value still have two identities, and the leaf must
/// reflect that: a snapshot that collapsed them would let a receiver drop a
/// branch it never observed.
#[test]
fn same_value_heads_keep_both_identities_in_the_leaf() {
    let one = RealmStateSnapshotMaterializedItem::cas_cell(
        slot_cell(),
        &[cas_head(0x33, serde_json::json!("A"))],
    )
    .unwrap();
    let two = RealmStateSnapshotMaterializedItem::cas_cell(
        slot_cell(),
        &[
            cas_head(0x33, serde_json::json!("A")),
            cas_head(0x44, serde_json::json!("A")),
        ],
    )
    .unwrap();
    assert_ne!(
        realm_state_snapshot_state_leaf_hash(&one).unwrap(),
        realm_state_snapshot_state_leaf_hash(&two).unwrap(),
    );
}

/// §4: a snapshot leaf *is* the §6.2.1 `state_root` leaf, byte for byte — for
/// a CAS cell and for a value cell alike — so a control cell has one canonical
/// leaf whether it is proven through a Seal or shipped in a snapshot.
#[test]
fn the_snapshot_leaf_is_the_state_root_leaf() {
    let heads = [cas_head(0x55, serde_json::json!("v"))];
    let item = RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &heads).unwrap();
    let state_root_leaf = crate::state::state_root::cas_leaf_hash(
        &slot_cell(),
        &heads,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(
        realm_state_snapshot_state_leaf_hash(&item)
            .unwrap()
            .as_str(),
        format!("sha256:{}", hex::encode(state_root_leaf)),
    );

    let value_item = cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("archived"));
    let value_leaf = crate::state::state_root::leaf_hash(
        value_item.cell(),
        &crate::lattice::CellState::Value(serde_json::json!("archived")),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(
        realm_state_snapshot_state_leaf_hash(&value_item)
            .unwrap()
            .as_str(),
        format!("sha256:{}", hex::encode(value_leaf)),
    );

    // And the digest suite follows the Realm, not a hard-coded SHA-256.
    let blake = realm_state_snapshot_state_leaf_hash_with_digest_suite(
        &value_item,
        arkret_canonical::DigestSuite::Blake3,
    )
    .unwrap();
    assert!(blake.as_str().starts_with("blake3:"));
}

/// The union is closed: the retired `object` branch, the retired `cas_cell`
/// literal, a state that mixes or misses both shapes, and a state shape that
/// contradicts the cell family's registered lattice are all refused.
#[test]
fn items_outside_the_cell_branch_are_rejected() {
    let object_branch = serde_json::json!({
        "kind": "strand",
        "id": "ak:strand:AVgnD-1YLmV6g-_RiZro8Yzmydn3Q8upFMpAgJW9bsbj",
        "object": {"id": "x"},
        "source_event_id": "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
    });
    assert!(serde_json::from_value::<RealmStateSnapshotMaterializedItem>(object_branch).is_err());

    let cas_cell_literal = serde_json::json!({
        "kind": "cas_cell",
        "id": slot_cell().as_str(),
        "state": {"heads": [{"event_id": event_id("a").as_str(), "value": null}]},
    });
    assert!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(cas_cell_literal).is_err()
    );

    let mixed_state = serde_json::json!({
        "kind": "cell",
        "id": STRAND_LIFECYCLE_CELL,
        "state": {"value": "archived", "heads": []},
    });
    assert!(serde_json::from_value::<RealmStateSnapshotMaterializedItem>(mixed_state).is_err());

    let no_state = serde_json::json!({"kind": "cell", "id": STRAND_LIFECYCLE_CELL});
    assert!(serde_json::from_value::<RealmStateSnapshotMaterializedItem>(no_state).is_err());

    let value_on_cas_family = serde_json::json!({
        "kind": "cell",
        "id": slot_cell().as_str(),
        "state": {"value": "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-"},
    });
    assert!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(value_on_cas_family).is_err()
    );

    let heads_on_value_family = serde_json::json!({
        "kind": "cell",
        "id": STRAND_LIFECYCLE_CELL,
        "state": {"heads": [{"event_id": event_id("a").as_str(), "value": "archived"}]},
    });
    assert!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(heads_on_value_family)
            .is_err()
    );

    let empty_heads = serde_json::json!({
        "kind": "cell",
        "id": slot_cell().as_str(),
        "state": {"heads": []},
    });
    assert!(serde_json::from_value::<RealmStateSnapshotMaterializedItem>(empty_heads).is_err());

    let unregistered_family = serde_json::json!({
        "kind": "cell",
        "id": "ak:cell:ak.component.nowhere.v1:null",
        "state": {"value": 1},
    });
    assert!(
        serde_json::from_value::<RealmStateSnapshotMaterializedItem>(unregistered_family).is_err()
    );
}

/// §6.2.1 orders heads by the decoded token, and a snapshot must not accept a
/// head set in any other order: the order is part of the leaf bytes.
#[test]
fn unsorted_heads_are_rejected() {
    let mut ordered = [cas_head(0x66, Value::Null), cas_head(0x77, Value::Null)];
    let item = RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &ordered).unwrap();
    let mut wire = serde_json::to_value(&item).unwrap();
    wire["state"]["heads"].as_array_mut().unwrap().reverse();
    assert!(serde_json::from_value::<RealmStateSnapshotMaterializedItem>(wire).is_err());

    ordered.reverse();
    assert!(RealmStateSnapshotMaterializedItem::cas_cell(slot_cell(), &ordered).is_err());
}

/// The auxiliary rows are closed objects too: an unknown member on a
/// `conflict_records[]` row or a chunk payload fails to parse.
#[test]
fn auxiliary_rows_and_chunk_payloads_are_closed() {
    let bottom = serde_json::json!({"kind": "bottom_cell", "cell_ref": STRAND_LIFECYCLE_CELL});
    assert!(serde_json::from_value::<RealmStateSnapshotConflictRecord>(bottom.clone()).is_ok());
    let mut extra = bottom;
    extra["note"] = serde_json::json!("x");
    assert!(serde_json::from_value::<RealmStateSnapshotConflictRecord>(extra).is_err());

    let (_, payloads, _) = manifest_for_items(vec![cell_item(
        STRAND_LIFECYCLE_CELL,
        serde_json::json!("active"),
    )]);
    let mut wire = serde_json::to_value(&payloads[0]).unwrap();
    assert_eq!(wire["chunk_kind"], "realm_state_snapshot_chunk");
    assert_eq!(wire["erasure_stubs"], serde_json::json!([]));
    wire["type"] = serde_json::json!("realm_state_snapshot_chunk");
    assert!(serde_json::from_value::<RealmStateRealmStateSnapshotChunkPayload>(wire).is_err());
}

/// The consumer-side recomputation refuses to reorder: unsorted or duplicated
/// items, a reducer profile that drifts from the manifest, or non-contiguous
/// chunk indexes are malformed snapshots, not hints.
#[test]
fn chunk_payload_verification_is_strict() {
    let items = vec![
        cell_item(MESSAGE_REACTIONS_CELL, serde_json::json!([])),
        cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active")),
    ];
    let expected = state_digest_from_items(&items).unwrap();
    let (_, payloads, _) = manifest_for_items(items);
    let suite = arkret_canonical::DigestSuite::Sha256;
    assert_eq!(
        state_digest_from_chunk_payloads(&payloads, CORE_REDUCER_PROFILE, suite).unwrap(),
        expected
    );

    let mut unsorted = payloads.clone();
    unsorted[0].items.reverse();
    assert!(state_digest_from_chunk_payloads(&unsorted, CORE_REDUCER_PROFILE, suite).is_err());

    let mut duplicated = payloads.clone();
    let duplicate = duplicated[0].items[1].clone();
    duplicated.push(RealmStateRealmStateSnapshotChunkPayload {
        index: 1,
        items: vec![duplicate],
        ..payloads[0].clone()
    });
    assert!(state_digest_from_chunk_payloads(&duplicated, CORE_REDUCER_PROFILE, suite).is_err());

    assert!(state_digest_from_chunk_payloads(&payloads, "ak.reducer.other.v1", suite).is_err());

    let mut skipped = payloads.clone();
    skipped[0].index = 1;
    assert!(state_digest_from_chunk_payloads(&skipped, CORE_REDUCER_PROFILE, suite).is_err());
}

fn spec_sync_fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../arkret-spec/spec/v1/artifacts/fixtures/sync-fixture.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap()
}

/// Replays `ak.vector.realm_state_snapshot.state_digest_recompute.v1`: every accept case
/// recomputes the fixture's `state_digest` (and auxiliary digests) from the
/// chunk bytes alone, every reject case is refused, and every published leaf
/// preimage / leaf pair is reproduced from the item.
#[test]
fn spec_snapshot_state_digest_fixture_replays() {
    let fixture = spec_sync_fixture();
    let block = &fixture["snapshot_state_digest"];
    assert_eq!(
        block["vector_id"],
        "ak.vector.realm_state_snapshot.state_digest_recompute.v1"
    );
    let reducer_profile = block["manifest"]["reducer_profile"].as_str().unwrap();
    let cases = block["cases"].as_array().unwrap();

    let canonical_items = cases[0]["chunks"][0]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            serde_json::from_value::<RealmStateSnapshotMaterializedItem>(item.clone()).unwrap()
        })
        .collect::<Vec<_>>();
    for row in block["leaves"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        let item = canonical_items
            .iter()
            .find(|item| item.id() == id)
            .unwrap_or_else(|| panic!("leaf row {id} names no canonical item"));
        let preimage = crate::canonical::canonical_json_bytes(&item.leaf_preimage()).unwrap();
        assert_eq!(
            String::from_utf8(preimage).unwrap(),
            row["leaf_preimage"].as_str().unwrap(),
            "leaf preimage of {id}"
        );
        assert_eq!(
            realm_state_snapshot_state_leaf_hash(item).unwrap().as_str(),
            row["leaf"].as_str().unwrap(),
            "leaf of {id}"
        );
    }
    assert_eq!(
        state_digest_from_items(&canonical_items).unwrap().as_str(),
        block["state_digest"].as_str().unwrap()
    );

    let mut seen = 0usize;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let suite =
            arkret_canonical::digest_suite(case["digest_algorithm"].as_str().unwrap()).unwrap();
        let declared = case["declared_state_digest"].as_str().unwrap();
        let parsed = case["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|chunk| {
                serde_json::from_value::<RealmStateRealmStateSnapshotChunkPayload>(chunk.clone())
            })
            .collect::<Result<Vec<_>, _>>();
        let observed = match parsed {
            Err(_) => None,
            Ok(chunks) => match state_digest_from_chunk_payloads(&chunks, reducer_profile, suite) {
                Ok(root) if root.as_str() == declared => Some(chunks),
                _ => None,
            },
        };
        let expected_accept = case["expected"] == "accept";
        assert_eq!(observed.is_some(), expected_accept, "case {name}");
        if let Some(chunks) = observed {
            if let Some(digest) = case["expected_conflict_records_digest"].as_str() {
                assert_eq!(
                    realm_state_snapshot_conflict_records_digest(&chunks, suite)
                        .unwrap()
                        .as_str(),
                    digest,
                    "conflict_records_digest of {name}"
                );
            }
            if let Some(digest) = case["expected_erasure_stubs_digest"].as_str() {
                assert_eq!(
                    realm_state_snapshot_erasure_stubs_digest(&chunks, suite)
                        .unwrap()
                        .as_str(),
                    digest,
                    "erasure_stubs_digest of {name}"
                );
            }
        }
        seen += 1;
    }
    assert!(seen >= 17, "the fixture publishes {seen} cases");
}
