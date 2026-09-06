use arkret_wire::{CORE_REDUCER_PROFILE, DidUrl};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{merkle, *};
use crate::lattice::cas_register::CasHead;
use crate::{
    CellRef, DidCoreId, EventId, Hash, Hlc, RealmId, RealmStateSnapshotId,
};

fn actor() -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
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
    Vec<RealmStateSnapshotChunkPayload>,
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

// ── Merkle tree ───────────────────────────────────────────────────

/// `n` distinct leaf-data digests, in the order a caller commits to them.
fn leaf_data(n: u32) -> Vec<Hash> {
    (0..n)
        .map(|i| merkle::sha256_digest(&i.to_be_bytes()))
        .collect()
}

#[test]
fn merkle_empty_rejected() {
    let err = RealmStateSnapshotMerkleTree::from_leaf_data(&[]).unwrap_err();
    assert!(format!("{err}").contains("at least one leaf"));
}

#[test]
fn merkle_single_leaf_root_is_domain_separated() {
    let leaves = leaf_data(1);
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
    assert_eq!(tree.leaf_count(), 1);
    let raw = parse_sha256(&leaves[0]).unwrap();
    assert_eq!(*tree.root(), format_hash(&hash_leaf(&raw)));
    assert_ne!(tree.root(), &leaves[0]);
    // Audit path is empty for single-leaf trees.
    assert_eq!(tree.audit_path(0).unwrap().len(), 0);
}

#[test]
fn merkle_two_leaves_root_is_hash_pair() {
    let leaves = leaf_data(2);
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
    // root = sha256(0x01 || sha256(0x00 || leaf0) || sha256(0x00 || leaf1)).
    let left = parse_sha256(&leaves[0]).unwrap();
    let right = parse_sha256(&leaves[1]).unwrap();
    let expected = hash_node(&hash_leaf(&left), &hash_leaf(&right));
    assert_eq!(*tree.root(), format_hash(&expected));
}

#[test]
fn merkle_audit_path_verifies_each_leaf() {
    for n in [1u32, 2, 3, 4, 5, 8, 11] {
        let leaves = leaf_data(n);
        let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
        let root = tree.root().clone();
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.audit_path(i).unwrap();
            assert!(
                RealmStateSnapshotMerkleTree::verify(&root, leaf, i, &path, tree.leaf_count()),
                "audit_path verification failed for n={n} leaf={i}"
            );
        }
    }
}

#[test]
fn merkle_audit_path_rejects_wrong_leaf() {
    let leaves = leaf_data(4);
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
    let path = tree.audit_path(0).unwrap();
    // Try to use leaf-0's path with leaf-1's digest — should fail.
    assert!(!RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &leaves[1],
        0,
        &path,
        tree.leaf_count()
    ));
}

#[test]
fn merkle_out_of_range_index_rejected() {
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaf_data(2)).unwrap();
    assert!(tree.audit_path(2).is_none());
}

#[test]
fn merkle_duplicate_tail_leaf_changes_root() {
    // Promote-without-duplication: [A,B,C] and [A,B,C,C] MUST NOT
    // share a root (CVE-2012-2459-shaped ambiguity).
    let three = leaf_data(3);
    let tree3 = RealmStateSnapshotMerkleTree::from_leaf_data(&three).unwrap();
    let mut four = three.clone();
    four.push(three[2].clone());
    let tree4 = RealmStateSnapshotMerkleTree::from_leaf_data(&four).unwrap();
    assert_ne!(tree3.root(), tree4.root());
}

#[test]
fn merkle_verify_rejects_mismatched_leaf_count() {
    let leaves = leaf_data(3);
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
    let path = tree.audit_path(2).unwrap();
    assert!(RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &leaves[2],
        2,
        &path,
        3
    ));
    // The same proof under a different claimed leaf_count MUST fail.
    assert!(!RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &leaves[2],
        3,
        &path,
        4
    ));
    assert!(!RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &leaves[2],
        2,
        &path,
        4
    ));
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
    let leaves = [0x11u8, 0x22]
        .into_iter()
        .map(|byte| Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap())
        .collect::<Vec<_>>();
    let tree = RealmStateSnapshotMerkleTree::from_leaf_data(&leaves).unwrap();
    let wrong_path = vec![Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap()];
    assert!(!RealmStateSnapshotMerkleTree::verify(
        tree.root(),
        &leaves[0],
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
    assert!(serde_json::from_value::<RealmStateSnapshotChunkPayload>(wire).is_err());
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
    duplicated.push(RealmStateSnapshotChunkPayload {
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
            .map(|chunk| serde_json::from_value::<RealmStateSnapshotChunkPayload>(chunk.clone()))
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

// ── Restore (consumer side) ────────────────────────────────────────

const INVITE_LIVE_TARGET_CELL: &str = "ak:cell:ak.component.invite.live_target.v1:fAWD6k02hF3JHnquwsCU7inqyb8Qdajftruz5xEWFGc";

fn cas_item(cell: &str, heads: &[(&str, Value)]) -> RealmStateSnapshotMaterializedItem {
    let heads = heads
        .iter()
        .map(|(suffix, value)| CasHead {
            move_id: snapshot_v1_event_id(suffix).event_digest(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    // The head set is ordered by the decoded event_id token; under one suite
    // that is the digest hex, so the fixture sorts on it rather than on the
    // base64url spelling, whose alphabet is not byte-ordered.
    let mut heads = heads;
    heads.sort_by(|a, b| a.move_id.as_str().cmp(b.move_id.as_str()));
    RealmStateSnapshotMaterializedItem::cas_cell(CellRef::new(cell.to_owned()).unwrap(), &heads)
        .unwrap()
}

fn restore_options() -> RealmStateSnapshotVerifyOptions {
    RealmStateSnapshotVerifyOptions::standard(
        "2026-06-02T00:00:00.000Z".parse::<DateTime<Utc>>().unwrap(),
        CORE_REDUCER_PROFILE,
    )
}

/// A verifier stand-in for the DID resolution the caller owns. It asserts the
/// transcript it is handed is the manifest's unsigned canonical bytes, which is
/// the only thing the restore path can promise about it.
fn accepting_issuer_verifier(
    expected_transcript: Vec<u8>,
) -> impl FnOnce(&DidUrl, &[u8], &str) -> Result<(), String> {
    move |_method: &DidUrl, transcript: &[u8], jws: &str| {
        assert_eq!(transcript, expected_transcript.as_slice());
        assert!(!jws.is_empty());
        Ok(())
    }
}

fn restore_fixture() -> (
    RealmStateSnapshotManifest,
    Vec<Vec<u8>>,
    Vec<RealmStateSnapshotMaterializedItem>,
) {
    let items = vec![
        cas_item(
            INVITE_LIVE_TARGET_CELL,
            &[
                ("000000000011", Value::Null),
                ("000000000012", serde_json::json!("ak:account:slot-b")),
            ],
        ),
        cell_item(MESSAGE_REACTIONS_CELL, serde_json::json!([])),
        cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("archived")),
    ];
    let (manifest, _, chunk_bytes) = manifest_for_items(items.clone());
    (manifest, chunk_bytes, items)
}

#[test]
fn restore_materializes_values_and_cas_heads() {
    let (manifest, chunk_bytes, _) = restore_fixture();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    assert_eq!(restored.report.item_count, 3);
    assert_eq!(restored.report.state_digest, manifest.state_digest);
    assert_eq!(restored.realm_state_snapshot_ref, manifest.id);

    let lifecycle = CellRef::new(STRAND_LIFECYCLE_CELL.to_owned()).unwrap();
    assert_eq!(
        restored.cell(&lifecycle),
        Some(RestoredCell::Value(serde_json::json!("archived")))
    );

    // A CAS cell comes back as its complete head set, `null` head included:
    // §6.2.1 makes the head set the state, so dropping the released slot would
    // silently turn two active writes into one.
    let invite = CellRef::new(INVITE_LIVE_TARGET_CELL.to_owned()).unwrap();
    let Some(RestoredCell::CasHeads(heads)) = restored.cell(&invite) else {
        panic!("invite cell restored as a value");
    };
    assert_eq!(heads.len(), 2);
    assert!(heads.iter().any(|head| head.value.is_null()));
    assert!(
        heads
            .iter()
            .any(|head| head.value == serde_json::json!("ak:account:slot-b"))
    );
    assert_eq!(
        restored.cas_heads.get(&invite).map(Vec::len),
        Some(2),
        "the restored head set is the joined-view shape, not a settled value"
    );
}

#[test]
fn restore_rejects_a_state_digest_the_chunks_do_not_reproduce() {
    let (mut manifest, chunk_bytes, _) = restore_fixture();
    manifest.state_digest = hash(7);
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::DigestMismatch);
}

#[test]
fn restore_rejects_a_signature_bound_to_another_transcript() {
    let (mut manifest, chunk_bytes, _) = restore_fixture();
    manifest.signature.payload_digest = hash(3);
    let error =
        restore_realm_state_snapshot(&manifest, &chunk_bytes, &restore_options(), |_, _, _| Ok(()))
            .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SignatureInvalid
    );
}

/// The resolver is a parameter, not a documented obligation: a snapshot whose
/// issuer signature does not verify never reaches materialization.
#[test]
fn restore_propagates_a_failed_issuer_signature() {
    let (manifest, chunk_bytes, _) = restore_fixture();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        |_, _, _| Err("verification method is revoked".to_owned()),
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SignatureInvalid
    );
    assert!(format!("{error}").contains("revoked"));
}

#[test]
fn restore_rejects_a_chunk_that_is_not_its_content_address() {
    let (manifest, mut chunk_bytes, _) = restore_fixture();
    chunk_bytes[0].push(b' ');
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::DigestMismatch);
}

#[test]
fn restore_rejects_a_chunk_belonging_to_another_snapshot() {
    let (manifest, _, items) = restore_fixture();
    let other = RealmStateSnapshotId::new(
        "ak:realm_state_snapshot:01904100-0000-7000-8000-00000000dead".to_owned(),
    )
    .unwrap();
    let rebuilt =
        build_realm_state_snapshot_chunks(&other, CORE_REDUCER_PROFILE, items, 4096).unwrap();
    let mut manifest = manifest;
    manifest.chunks = rebuilt.iter().map(|c| c.descriptor.clone()).collect();
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let chunk_bytes = rebuilt
        .iter()
        .map(|c| c.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::SchemaViolation);
}

/// §5: a snapshot outside `realm_state_snapshot_max_acceptance_age_ms` is
/// refused even though every digest and signature still checks out — the auth
/// state it speaks for has drifted.
#[test]
fn restore_rejects_a_snapshot_past_its_acceptance_window() {
    let (manifest, chunk_bytes, _) = restore_fixture();
    let options = RealmStateSnapshotVerifyOptions::standard(
        manifest.created_at
            + chrono::Duration::milliseconds(
                REALM_STATE_SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS + 1,
            ),
        CORE_REDUCER_PROFILE,
    );
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &options,
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified
    );
    assert_eq!(
        realm_state_snapshot_max_acceptance_age_ms(&RealmStateSnapshotSecurityClass::HighAssurance),
        REALM_STATE_SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS,
        "high_assurance tightens the same window rather than using its own rule"
    );
}

/// §6.2: a high-assurance snapshot is not adoptable until the caller has run
/// the witness path or the raw replay. Nothing about the manifest changes; the
/// caller's own readiness is the gate.
#[test]
fn restore_refuses_high_assurance_without_the_supplementary_path() {
    let (mut manifest, chunk_bytes, _) = restore_fixture();
    manifest.security_class = RealmStateSnapshotSecurityClass::HighAssurance;
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript.clone()),
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified
    );

    let mut options = restore_options();
    options.allow_high_assurance = true;
    restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &options,
        accepting_issuer_verifier(transcript),
    )
    .unwrap();
}

/// §3's membership rule. A restored receiver answers `Unknown` — hold — for
/// every Event it has no evidence about, and never `NotCovered`, because
/// `NotCovered` is what revives a superseded write on the §9.3.1.4 merge.
#[test]
fn covered_set_holds_without_evidence() {
    let (manifest, chunk_bytes, _) = restore_fixture();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    let frontier_head = &manifest.frontier.event_ids[0];
    assert_eq!(
        restored.covered_events.membership(frontier_head),
        CoveredEventMembership::Covered,
        "a frontier head is in C by construction"
    );
    assert_eq!(
        restored
            .covered_events
            .membership(&snapshot_v1_event_id("some-older-event")),
        CoveredEventMembership::Unknown
    );
    assert!(!restored.covered_events.is_complete());
}

fn event_set_entry(suffix: &str, actor_seq: u64) -> EventSetLeaf {
    EventSetLeaf {
        event_id: snapshot_v1_event_id(suffix),
        event_digest: snapshot_v1_event_id(suffix).event_digest(),
        actor_id: arkret_wire::ActorId::service(actor()),
        actor_seq,
        hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    }
}

fn manifest_committing(entries: &[EventSetLeaf]) -> (RealmStateSnapshotManifest, Vec<Vec<u8>>) {
    let (mut manifest, chunk_bytes, _) = restore_fixture();
    manifest.event_set_commitment =
        event_set_commitment(EventSetCommitmentAlgorithm::MerkleEventSetV1, entries).unwrap();
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_bytes)
}

/// «保留共享 membership 索引»: with the committed index in hand, and only then,
/// an absent id is provably `NotCovered`.
#[test]
fn covered_set_admits_the_committed_index_and_can_then_say_not_covered() {
    let entries = (1u64..=4)
        .map(|seq| event_set_entry(&format!("covered-{seq}"), seq))
        .collect::<Vec<_>>();
    let (manifest, chunk_bytes) = manifest_committing(&entries);
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let mut restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    let outsider = snapshot_v1_event_id("never-committed");
    assert_eq!(
        restored.covered_events.membership(&outsider),
        CoveredEventMembership::Unknown
    );

    restored
        .covered_events
        .admit_committed_index(entries.clone())
        .unwrap();
    assert!(restored.covered_events.is_complete());
    assert_eq!(
        restored.covered_events.membership(&entries[2].event_id),
        CoveredEventMembership::Covered
    );
    assert_eq!(
        restored.covered_events.membership(&outsider),
        CoveredEventMembership::NotCovered
    );
    assert_eq!(
        restored.covered_events.entry(&entries[2].event_id),
        Some(&entries[2])
    );
}

/// A prefix is not the set. Admitting one would let the receiver answer
/// `NotCovered` for the tail it never saw.
#[test]
fn covered_set_rejects_a_partial_or_altered_index() {
    let entries = (1u64..=4)
        .map(|seq| event_set_entry(&format!("covered-{seq}"), seq))
        .collect::<Vec<_>>();
    let (manifest, chunk_bytes) = manifest_committing(&entries);
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let mut restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    let error = restored
        .covered_events
        .admit_committed_index(entries[..3].to_vec())
        .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::InclusionProofFailed
    );

    let mut swapped = entries.clone();
    swapped[1].actor_seq = 99;
    let error = restored
        .covered_events
        .admit_committed_index(swapped)
        .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::InclusionProofFailed
    );
    assert!(
        !restored.covered_events.is_complete(),
        "a refused index must not leave the set claiming completeness"
    );
}

/// «按现有 root 取得有效证明»: one entry plus its audit path against the
/// manifest's own root turns `Unknown` into `Covered` without the whole index.
#[test]
fn covered_set_admits_one_entry_against_the_manifest_root() {
    let entries = (1u64..=5)
        .map(|seq| event_set_entry(&format!("covered-{seq}"), seq))
        .collect::<Vec<_>>();
    let (manifest, chunk_bytes) = manifest_committing(&entries);
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let mut restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    // The prover's side of §6.2: the same tree the commitment was computed
    // from, in the ordering it fixes, and the audit path straight out of it.
    let (sorted, tree) = event_set_merkle_tree(&entries).unwrap();
    assert_eq!(tree.root(), &manifest.event_set_commitment.root);
    let index = 3usize;
    let audit_path = tree.audit_path(index).unwrap();

    assert_eq!(
        restored.covered_events.membership(&sorted[index].event_id),
        CoveredEventMembership::Unknown
    );
    restored
        .covered_events
        .admit_inclusion_proof(sorted[index].clone(), index, &audit_path)
        .unwrap();
    assert_eq!(
        restored.covered_events.membership(&sorted[index].event_id),
        CoveredEventMembership::Covered
    );
    // One proof is not the index: everything else still holds.
    assert!(!restored.covered_events.is_complete());
    assert_eq!(
        restored.covered_events.membership(&sorted[0].event_id),
        CoveredEventMembership::Unknown
    );

    let error = restored
        .covered_events
        .admit_inclusion_proof(sorted[index].clone(), index + 1, &audit_path)
        .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::InclusionProofFailed
    );
}

/// `ordered_event_id_sha256_v1` hashes the whole sorted array; there is no
/// per-entry path to offer, and pretending otherwise would accept an unproven
/// entry.
#[test]
fn covered_set_refuses_per_entry_proofs_under_the_ordered_algorithm() {
    let entries = vec![event_set_entry("covered-1", 1)];
    let (mut manifest, chunk_bytes, _) = restore_fixture();
    manifest.event_set_commitment = event_set_commitment(
        EventSetCommitmentAlgorithm::OrderedEventIdSha256V1,
        &entries,
    )
    .unwrap();
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let mut restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    let error = restored
        .covered_events
        .admit_inclusion_proof(entries[0].clone(), 0, &[])
        .unwrap_err();
    assert_eq!(
        error.code,
        RealmStateSnapshotValidationCode::InclusionProofFailed
    );
    // The whole-index path still works under that algorithm.
    restored
        .covered_events
        .admit_committed_index(entries)
        .unwrap();
    assert!(restored.covered_events.is_complete());
}

/// §3: `⊥` cells and erased cells have no leaf, and a receiver that dropped
/// them would read them as never written. Both survive the restore.
#[test]
fn restore_carries_bottom_cells_and_erasure_stubs() {
    let items = vec![cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active"))];
    let bottom = CellRef::new(MESSAGE_REACTIONS_CELL.to_owned()).unwrap();
    let erased = CellRef::new(INVITE_LIVE_TARGET_CELL.to_owned()).unwrap();
    let built = build_realm_state_snapshot_chunks_with_auxiliary_lists(
        &snapshot_v1_id(),
        CORE_REDUCER_PROFILE,
        items.clone(),
        4096,
        SnapshotAuxiliaryLists {
            conflict_records: vec![RealmStateSnapshotConflictRecord::BottomCell {
                cell_ref: bottom.clone(),
            }],
            erasure_stubs: vec![SnapshotErasureStub {
                cell_ref: erased.clone(),
                stub: serde_json::json!({"schema": "ak.schema.erasure_verification_stub.v1"}),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let payloads = built.iter().map(|c| c.payload.clone()).collect::<Vec<_>>();
    let chunk_bytes = built
        .iter()
        .map(|c| c.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let (mut manifest, _, _) = manifest_for_items(items);
    manifest.chunks = built.iter().map(|c| c.descriptor.clone()).collect();
    manifest.verification_hints = Some(RealmStateSnapshotVerificationHints {
        verification_profile: RealmStateSnapshotSecurityClass::Standard,
        inclusion_proof_url: None,
        challenge_window_seconds: None,
        conflict_records_digest: Some(
            realm_state_snapshot_conflict_records_digest(
                &payloads,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        ),
        soft_failed_digest: None,
        quarantined_digest: None,
        erasure_stubs_digest: Some(
            realm_state_snapshot_erasure_stubs_digest(
                &payloads,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        ),
    });
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let restored = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap();

    assert!(restored.bottom_cells.contains(&bottom));
    assert!(restored.erasure_stubs.contains_key(&erased));
    assert_eq!(
        restored.cell(&bottom),
        None,
        "a bottom cell has no leaf; the caller reads bottom_cells, not a value"
    );

    // The digest a `verification_hints` entry commits is checked, not trusted.
    let mut tampered = manifest.clone();
    tampered
        .verification_hints
        .as_mut()
        .unwrap()
        .erasure_stubs_digest = Some(hash(6));
    tampered.signature.payload_digest = tampered.expected_signature_digest().unwrap();
    let tampered_transcript = tampered.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &tampered,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(tampered_transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::DigestMismatch);
}

/// An erasure stub is a substitute for a leaf, not an annotation beside one.
#[test]
fn restore_rejects_a_cell_with_both_a_leaf_and_an_erasure_stub() {
    let items = vec![cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active"))];
    let cell = CellRef::new(STRAND_LIFECYCLE_CELL.to_owned()).unwrap();
    let built = build_realm_state_snapshot_chunks_with_auxiliary_lists(
        &snapshot_v1_id(),
        CORE_REDUCER_PROFILE,
        items.clone(),
        4096,
        SnapshotAuxiliaryLists {
            erasure_stubs: vec![SnapshotErasureStub {
                cell_ref: cell,
                stub: serde_json::json!({"schema": "ak.schema.erasure_verification_stub.v1"}),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let payloads = built.iter().map(|c| c.payload.clone()).collect::<Vec<_>>();
    let chunk_bytes = built
        .iter()
        .map(|c| c.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let (mut manifest, _, _) = manifest_for_items(items);
    manifest.chunks = built.iter().map(|c| c.descriptor.clone()).collect();
    manifest.verification_hints = Some(RealmStateSnapshotVerificationHints {
        verification_profile: RealmStateSnapshotSecurityClass::Standard,
        inclusion_proof_url: None,
        challenge_window_seconds: None,
        conflict_records_digest: None,
        soft_failed_digest: None,
        quarantined_digest: None,
        erasure_stubs_digest: Some(
            realm_state_snapshot_erasure_stubs_digest(
                &payloads,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        ),
    });
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::SchemaViolation);
}

/// §3 makes `erasure_stubs_digest` mandatory once any chunk carries a stub: it
/// is the only commitment an erased cell has.
#[test]
fn restore_rejects_erasure_stubs_with_no_commitment() {
    let items = vec![cell_item(STRAND_LIFECYCLE_CELL, serde_json::json!("active"))];
    let built = build_realm_state_snapshot_chunks_with_auxiliary_lists(
        &snapshot_v1_id(),
        CORE_REDUCER_PROFILE,
        items.clone(),
        4096,
        SnapshotAuxiliaryLists {
            erasure_stubs: vec![SnapshotErasureStub {
                cell_ref: CellRef::new(INVITE_LIVE_TARGET_CELL.to_owned()).unwrap(),
                stub: serde_json::json!({"schema": "ak.schema.erasure_verification_stub.v1"}),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let chunk_bytes = built
        .iter()
        .map(|c| c.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let (mut manifest, _, _) = manifest_for_items(items);
    manifest.chunks = built.iter().map(|c| c.descriptor.clone()).collect();
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    let transcript = manifest.unsigned_canonical_bytes().unwrap();
    let error = restore_realm_state_snapshot(
        &manifest,
        &chunk_bytes,
        &restore_options(),
        accepting_issuer_verifier(transcript),
    )
    .unwrap_err();
    assert_eq!(error.code, RealmStateSnapshotValidationCode::SchemaViolation);
    assert!(format!("{error}").contains("erasure_stubs_digest"));
}

/// A hint and a manifest arrive in two responses; the second is only usable
/// when it is the snapshot the first named.
#[test]
fn bootstrap_hint_must_name_the_manifest_it_is_bound_to() {
    use arkret_models_collaboration::sync_frames::realm_state_snapshot::RealmStateSnapshotBootstrap;

    let (manifest, _, _) = restore_fixture();
    let bootstrap = RealmStateSnapshotBootstrap {
        realm_state_snapshot_ref: manifest.id.clone(),
        state_digest: manifest.state_digest.clone(),
        realm_state_snapshot_frontier: manifest.frontier.event_ids.clone(),
        created_by: manifest.created_by.clone(),
        created_at: manifest.created_at,
        authority_binding: serde_json::from_value(
            serde_json::to_value(&manifest.authority_binding).unwrap(),
        )
        .unwrap(),
        signature: serde_json::from_value(serde_json::to_value(&manifest.signature).unwrap())
            .unwrap(),
        verification_hints: None,
    };
    realm_state_snapshot_bootstrap_binds_manifest(&bootstrap, &manifest).unwrap();

    let mut swapped_digest = bootstrap.clone();
    swapped_digest.state_digest = hash(4);
    assert_eq!(
        realm_state_snapshot_bootstrap_binds_manifest(&swapped_digest, &manifest)
            .unwrap_err()
            .code,
        RealmStateSnapshotValidationCode::DigestMismatch
    );

    let mut swapped_ref = bootstrap.clone();
    swapped_ref.realm_state_snapshot_ref = RealmStateSnapshotId::new(
        "ak:realm_state_snapshot:01904100-0000-7000-8000-00000000beef".to_owned(),
    )
    .unwrap();
    assert_eq!(
        realm_state_snapshot_bootstrap_binds_manifest(&swapped_ref, &manifest)
            .unwrap_err()
            .code,
        RealmStateSnapshotValidationCode::SchemaViolation
    );

    let mut swapped_signature = bootstrap;
    swapped_signature.signature.payload_digest = hash(5);
    assert_eq!(
        realm_state_snapshot_bootstrap_binds_manifest(&swapped_signature, &manifest)
            .unwrap_err()
            .code,
        RealmStateSnapshotValidationCode::SignatureInvalid
    );
}
