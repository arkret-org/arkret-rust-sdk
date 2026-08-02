//! MLS control-cell subject derivations and governance-Seal dependency discovery.
//!
//! Per spec [`event-auth-state-resolution.md`](https://arkret.org/spec/v1/zh/authz/event-auth-state-resolution.md)
//! §10, an MLS commit is a **Control Move** — an Event, not a Seal. Its
//! registered contract writes two cells:
//!
//! | cell family | lattice | role |
//! | --- | --- | --- |
//! | `ak.component.mls.epoch.v1` | cas-register | current epoch counter for the MLS group |
//! | `ak.component.mls.key_schedule.v1` | cas-register | latest key schedule pointer |
//!
//! The operations themselves are receiver-derived from `kind + payload`, so
//! nothing here builds them: v1 has no producer-authored effect channel and
//! the cell-subject derivations remain centralized here.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId, SealId};
use arkret_wire::WireError;
use arkret_wire::cell::CellId;

use crate::lattice::CellState;
use crate::lattice::ordered_log::IssuedOp;
use crate::mls_governance_proof::{is_mls_capability_root_component, is_mls_policy_root_component};
use crate::state::{
    CellRegistry, CellStore, SealReject, SealStore, join_cell_seal_batches,
    union_predecessor_covered_events,
};

/// Cell families the MLS commit contract targets.
pub const MLS_EPOCH_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_EPOCH_V1;
pub const KEY_SCHEDULE_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_KEY_SCHEDULE_V1;

/// `ak:cell:ak.component.mls.epoch.v1:<group_id>` — cas-register on the
/// MLS group's current epoch counter.
pub fn mls_epoch_cell_id(group_id: &str) -> Result<CellRef, WireError> {
    if group_id.is_empty() {
        return Err(WireError::Protocol(
            "MLS group_id must not be empty".to_owned(),
        ));
    }
    CellRef::new(format!("ak:cell:{MLS_EPOCH_CELL_FAMILY}:{group_id}"))
        .map_err(|e| WireError::Protocol(format!("invalid mls_epoch cell id: {e}")))
}

/// `ak:cell:ak.component.mls.key_schedule.v1:<group_id>` — cas-register on
/// the MLS group's latest key schedule pointer.
pub fn key_schedule_cell_id(group_id: &str) -> Result<CellRef, WireError> {
    if group_id.is_empty() {
        return Err(WireError::Protocol(
            "MLS group_id must not be empty".to_owned(),
        ));
    }
    CellRef::new(format!("ak:cell:{KEY_SCHEDULE_CELL_FAMILY}:{group_id}"))
        .map_err(|e| WireError::Protocol(format!("invalid key_schedule cell id: {e}")))
}

/// Whether a cell family is one of the three governance inputs
/// `encryption-and-audit.md` §2.5.2 enumerates when rebuilding `M`:
/// (a) membership / device / lifecycle, (b) `policy_root` leaves,
/// (c) `capability_root` leaves.
#[must_use]
pub fn is_governance_coverage_component(component: &str) -> bool {
    crate::mls_governance_proof::is_mls_membership_frontier_component(component)
        || is_mls_policy_root_component(component)
        || is_mls_capability_root_component(component)
}

/// `encryption-and-audit.md` §2.5.2 — rebuild `M`, the governance Seal set an
/// E2EE application DataEvent resolving at `leaves` depends on.
///
/// For every materialized governance cell (see
/// [`is_governance_coverage_component`]) this takes the Control Moves inside
/// `covered_set(leaves)` that still contribute to the cell's joined value, and
/// collects the Seal that first admitted each of them. A Move whose
/// contribution has been superseded by a later one does not enter `M`;
/// concurrent heads all do, which is what the spec's "覆盖每个 contributing
/// head" requires. A `⊥` cell contributes every one of its covered batches —
/// coverage cannot be argued away by a conflict.
///
/// `M` deliberately does **not** contain the resolution Seal merely because it
/// is the resolution point. When `S` carries a governance change, that change's
/// own last-changing Move is admitted by `S`, so `S` still enters `M` through
/// the enumeration below — exactly how a ban or revoke pauses sending.
pub fn required_governance_seals_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeSet<SealId>, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals)?;
    let mut required = BTreeSet::new();
    for cell in cells.list_cells(realm_id)? {
        let component = CellId::from_ref(&cell)
            .map_err(|error| SealReject::Structural(format!("invalid cell id {cell}: {error}")))?;
        if !is_governance_coverage_component(component.component()) {
            continue;
        }
        let batches: Vec<(SealId, Vec<IssuedOp>)> = cells
            .sealed_op_batches_for_cell(realm_id, &cell)?
            .into_iter()
            .filter_map(|(seal, ops)| {
                let covered_ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!covered_ops.is_empty()).then_some((seal, covered_ops))
            })
            .collect();
        if batches.is_empty() {
            continue;
        }
        let binding = registry.resolve(realm_id, &cell)?;
        let lattice = binding.lattice.as_ref();
        let all = batches
            .iter()
            .map(|(_, ops)| ops.clone())
            .collect::<Vec<_>>();
        let joined = join_cell_seal_batches(lattice, &cell, &all);
        if matches!(joined, CellState::Bottom(_)) {
            required.extend(batches.into_iter().map(|(seal, _)| seal));
            continue;
        }
        for (index, (seal, _)) in batches.iter().enumerate() {
            let without = all
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .map(|(_, ops)| ops.clone())
                .collect::<Vec<_>>();
            if join_cell_seal_batches(lattice, &cell, &without) != joined {
                required.insert(seal.clone());
            }
        }
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::Hash;
    use arkret_wire::{LatticeOp, LatticeOpType};
    use serde_json::json;

    use super::*;
    use crate::lattice::SealedOp;

    fn seal(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn event_digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn cell_ids_use_canonical_prefixes() {
        let group = "group.01js0mls0000000000000000";
        assert_eq!(
            mls_epoch_cell_id(group).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.epoch.v1:{group}")
        );
        assert_eq!(
            key_schedule_cell_id(group).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.key_schedule.v1:{group}")
        );
    }

    #[test]
    fn cell_id_helpers_reject_empty_group_id() {
        mls_epoch_cell_id("").unwrap_err();
        key_schedule_cell_id("").unwrap_err();
    }

    #[test]
    fn distinct_groups_have_distinct_epoch_cells() {
        let a = mls_epoch_cell_id("group-A").unwrap();
        let b = mls_epoch_cell_id("group-B").unwrap();
        assert_ne!(a, b);
    }

    mod required_governance_seals {
        use arkret_wire::{Did, Hlc, NotarySig, PayloadSignature, Seal, SealKind};
        use chrono::{TimeZone, Utc};

        use super::*;
        use crate::state::store::memory::{MemoryCellRegistry, MemoryCellStore, MemorySealStore};
        use crate::state::store::{CellStore, SealStore};

        fn realm() -> RealmId {
            RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
        }

        fn hash(byte: u8) -> Hash {
            Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
        }

        fn issued(op: SealedOp) -> IssuedOp {
            IssuedOp {
                issuer: Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
                op,
            }
        }

        fn grant_cell(grant: &str) -> CellRef {
            CellRef::new(format!(
                "ak:cell:ak.component.capability.grant.v1:ak:grant:{grant}"
            ))
            .unwrap()
        }

        /// A data-plane cell family: never part of `M`.
        fn message_cell() -> CellRef {
            CellRef::new("ak:cell:ak.component.message.body.v1:ak:strand:demo".to_owned()).unwrap()
        }

        fn grant_add(tag: &str, marker: &str) -> LatticeOp {
            LatticeOp {
                op_type: LatticeOpType::Add,
                tag: Some(tag.to_owned()),
                value: Some(json!({ "marker": marker })),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            }
        }

        fn materialized_seal(id: SealId, covered: Vec<Hash>) -> Seal {
            Seal {
                id,
                realm_id: realm(),
                predecessor_refs: Vec::new(),
                delta: Vec::new(),
                control_event_set_root: hash(0x22),
                state_root: hash(0x77),
                completeness_root: hash(0x33),
                notary_seq: 1,
                data_view_root: None,
                data_event_set_root: None,
                availability_root: None,
                coverage_scope: None,
                covered_event_digests: covered,
                previous_state_root: None,
                previous_digest_algorithm: None,
                notary_signature: NotarySig::Single(PayloadSignature {
                    extra: Default::default(),
                    alg: "EdDSA".to_owned(),
                    verification_method: arkret_wire::DidUrl::new(
                        "did:webvh:z6mkfixture:notary.example#k1",
                    )
                    .unwrap(),
                    payload_digest: hash(0xff),
                    created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
                    jws: "AAAA.BBBB.CCCC".to_owned(),
                }),
                sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
                hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
                kind: SealKind::Normal,
            }
        }

        #[test]
        fn governance_writes_enter_m_and_data_plane_writes_do_not() {
            let seals = MemorySealStore::default();
            let cells = MemoryCellStore::default();
            let registry = MemoryCellRegistry::default();
            let realm = realm();
            let governance_move = event_digest(0xaa);
            let data_move = event_digest(0xbb);
            let governance_seal =
                materialized_seal(seal(0xa1), vec![governance_move.clone(), data_move.clone()]);
            seals.put(&governance_seal).unwrap();
            cells
                .append_sealed_effects(
                    &realm,
                    &governance_seal.id,
                    &[
                        (
                            grant_cell("0196410c-0000-7000-8000-000000000000"),
                            issued(SealedOp::new(governance_move, grant_add("g0", "active"))),
                        ),
                        (
                            message_cell(),
                            issued(SealedOp::new(data_move, grant_add("d0", "body"))),
                        ),
                    ],
                )
                .unwrap();

            let required = required_governance_seals_at(
                std::slice::from_ref(&governance_seal.id),
                &realm,
                &seals,
                &cells,
                &registry,
            )
            .unwrap();
            // The capability grant pulls its Seal in; the message body does not
            // add anything of its own.
            assert_eq!(
                required,
                BTreeSet::from([governance_seal.id]),
                "only ak.component.capability.* / policy / membership writes define M"
            );
        }

        #[test]
        fn m_never_contains_a_seal_that_only_admitted_non_governance_moves() {
            // The shape that made every E2EE DataEvent unsendable: an
            // `ak.mls.commit` lands in its own Seal, the resolution Seal moves
            // to it, and nothing governance-relevant changed. `M` MUST stay at
            // the earlier governance Seal — a Seal can never cover itself.
            let seals = MemorySealStore::default();
            let cells = MemoryCellStore::default();
            let registry = MemoryCellRegistry::default();
            let realm = realm();
            let grant_move = event_digest(0xaa);
            let commit_move = event_digest(0xbb);
            let governance_seal = materialized_seal(seal(0xa1), vec![grant_move.clone()]);
            let mut commit_seal =
                materialized_seal(seal(0xb1), vec![grant_move.clone(), commit_move.clone()]);
            commit_seal.predecessor_refs = vec![governance_seal.id.clone()];
            seals.put(&governance_seal).unwrap();
            seals.put(&commit_seal).unwrap();
            cells
                .append_sealed_effects(
                    &realm,
                    &governance_seal.id,
                    &[(
                        grant_cell("0196410c-0000-7000-8000-000000000000"),
                        issued(SealedOp::new(grant_move, grant_add("g0", "active"))),
                    )],
                )
                .unwrap();
            let required = required_governance_seals_at(
                std::slice::from_ref(&commit_seal.id),
                &realm,
                &seals,
                &cells,
                &registry,
            )
            .unwrap();
            assert_eq!(required, BTreeSet::from([governance_seal.id]));
            assert!(
                !required.contains(&commit_seal.id),
                "the resolution Seal must never require covering itself"
            );
        }

        #[test]
        fn a_governance_write_after_the_last_commit_reenters_m() {
            // A ban / grant sealed after the last commit is exactly the case
            // §2.5.2 wants to block until a new commit attests it.
            let seals = MemorySealStore::default();
            let cells = MemoryCellStore::default();
            let registry = MemoryCellRegistry::default();
            let realm = realm();
            let first_grant = event_digest(0xaa);
            let second_grant = event_digest(0xcc);
            let old_seal = materialized_seal(seal(0xa1), vec![first_grant.clone()]);
            let mut new_seal =
                materialized_seal(seal(0xc1), vec![first_grant.clone(), second_grant.clone()]);
            new_seal.predecessor_refs = vec![old_seal.id.clone()];
            seals.put(&old_seal).unwrap();
            seals.put(&new_seal).unwrap();
            cells
                .append_sealed_effects(
                    &realm,
                    &old_seal.id,
                    &[(
                        grant_cell("0196410c-0000-7000-8000-000000000000"),
                        issued(SealedOp::new(first_grant, grant_add("g0", "active"))),
                    )],
                )
                .unwrap();
            cells
                .append_sealed_effects(
                    &realm,
                    &new_seal.id,
                    &[(
                        grant_cell("0196410c-0000-7000-8000-000000000001"),
                        issued(SealedOp::new(second_grant, grant_add("g1", "active"))),
                    )],
                )
                .unwrap();

            let required = required_governance_seals_at(
                std::slice::from_ref(&new_seal.id),
                &realm,
                &seals,
                &cells,
                &registry,
            )
            .unwrap();
            assert_eq!(
                required,
                BTreeSet::from([old_seal.id, new_seal.id]),
                "the newly sealed grant must be required, so an epoch that only \
                 attested the old Seal stays blocked"
            );
        }
    }
}
