//! MLS commit Move + `covered_frontier` cell helpers.
//!
//! Per spec [`event-auth-state-resolution.md`](https://cokret.io/spec/v1/zh/authz/event-auth-state-resolution.md)
//! §10, an MLS commit is **a Move**, not an Anchor. It writes three
//! well-known cells:
//!
//! | cell family | lattice | bottom | role |
//! | --- | --- | --- | --- |
//! | `ck.component.mls_epoch.v1` | cas-register | reject | current epoch counter for the MLS group |
//! | `ck.component.key_schedule.v1` | cas-register | reject | latest key schedule pointer |
//! | `ck.component.covered_frontier.v1` | or-set | expose | governance Anchor frontier this MLS group has bound |
//!
//! `cell_subject` for `mls_epoch` / `key_schedule` is the MLS group id;
//! for `covered_frontier` it is the Realm id.
//!
//! The MLS commit Move:
//!
//! - **preconditions** ensure (a) the cas-register epoch matches `prev_epoch`
//!   (otherwise the commit is racing) and (b) the or-set covered_frontier
//!   already contains the governance Anchor that the encrypted message
//!   path will require.
//! - **effects** atomically advance the epoch (cas-register set), set the
//!   new key schedule (cas-register set), and add the new attested
//!   governance frontier tag to the covered_frontier or-set.
//!
//! E2EE message Moves (e.g. `ck.message.create` in an E2EE Realm) MUST
//! independently include a `contains` precondition on covered_frontier_cell
//! for their own `anchor_ref`'s governance frontier. [`e2ee_message_precondition`]
//! produces the exact precondition shape so callers don't have to hand-derive it.

use cokret_core::{
    AnchorId, CellRef, Effect, Hash, LatticeOp, LatticeOpType, Precondition, Predicate,
    PredicateOp, RealmId,
};
use serde_json::Value;

/// Cell families used by MLS commit Moves.
pub const MLS_EPOCH_CELL_FAMILY: &str = "ck.component.mls_epoch.v1";
pub const KEY_SCHEDULE_CELL_FAMILY: &str = "ck.component.key_schedule.v1";
pub const COVERED_FRONTIER_CELL_FAMILY: &str = "ck.component.covered_frontier.v1";

/// `ck:cell:ck.component.mls_epoch.v1:<group_id>` — cas-register on the
/// MLS group's current epoch counter.
pub fn mls_epoch_cell_id(group_id: &str) -> Result<CellRef, cokret_core::Error> {
    if group_id.is_empty() {
        return Err(cokret_core::Error::Protocol("MLS group_id must not be empty".to_owned()));
    }
    CellRef::new(format!("ck:cell:{MLS_EPOCH_CELL_FAMILY}:{group_id}"))
        .map_err(|e| cokret_core::Error::Protocol(format!("invalid mls_epoch cell id: {e}")))
}

/// `ck:cell:ck.component.key_schedule.v1:<group_id>` — cas-register on
/// the MLS group's latest key schedule pointer.
pub fn key_schedule_cell_id(group_id: &str) -> Result<CellRef, cokret_core::Error> {
    if group_id.is_empty() {
        return Err(cokret_core::Error::Protocol("MLS group_id must not be empty".to_owned()));
    }
    CellRef::new(format!("ck:cell:{KEY_SCHEDULE_CELL_FAMILY}:{group_id}"))
        .map_err(|e| cokret_core::Error::Protocol(format!("invalid key_schedule cell id: {e}")))
}

/// `ck:cell:ck.component.covered_frontier.v1:<realm_id>` — or-set listing
/// the governance Anchor frontiers this MLS group is currently bound to.
pub fn covered_frontier_cell_id(realm_id: &RealmId) -> Result<CellRef, cokret_core::Error> {
    CellRef::new(format!("ck:cell:{COVERED_FRONTIER_CELL_FAMILY}:{}", realm_id.as_str()))
        .map_err(|e| cokret_core::Error::Protocol(format!("invalid covered_frontier cell id: {e}")))
}

/// Deterministic or-set tag for "this MLS commit attests Anchor X covers
/// the governance frontier".
///
/// Using the Anchor id verbatim as the tag makes the or-set's `contains`
/// predicate trivially equivalent to "Anchor X is in the covered set".
pub fn governance_frontier_tag(anchor: &AnchorId) -> String {
    anchor.as_str().to_owned()
}

/// Build the preconditions an MLS commit Move MUST carry.
///
/// Per spec §10:
/// - `mls_epoch_cell.head_eq(prev_epoch)` — racing commits fail closed.
/// - `covered_frontier_cell.contains(required_governance_anchor)` — the
///   governance frontier this commit is binding to MUST already be
///   covered by the Realm's covered_frontier or-set.
pub fn mls_commit_preconditions(
    group_id: &str,
    realm_id: &RealmId,
    prev_epoch: u64,
    required_governance_anchor: &AnchorId,
) -> Result<Vec<Precondition>, cokret_core::Error> {
    let epoch_cell = mls_epoch_cell_id(group_id)?;
    let frontier_cell = covered_frontier_cell_id(realm_id)?;
    Ok(vec![
        Precondition {
            cell: epoch_cell,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(Value::from(prev_epoch)),
                values: None,
                predicate_id: None,
            },
        },
        Precondition {
            cell: frontier_cell,
            predicate: Predicate {
                op: PredicateOp::Contains,
                value: Some(Value::String(governance_frontier_tag(required_governance_anchor))),
                values: None,
                predicate_id: None,
            },
        },
    ])
}

/// Build the effects an MLS commit Move MUST carry.
///
/// Three atomic effects:
/// 1. `mls_epoch_cell` <- set new_epoch.
/// 2. `key_schedule_cell` <- set new_schedule (Hash content-addressed).
/// 3. `covered_frontier_cell` <- add(tag = attested governance Anchor id).
pub fn mls_commit_effects(
    group_id: &str,
    realm_id: &RealmId,
    new_epoch: u64,
    new_schedule: &Hash,
    attested_governance_anchor: &AnchorId,
) -> Result<Vec<Effect>, cokret_core::Error> {
    let epoch_cell = mls_epoch_cell_id(group_id)?;
    let schedule_cell = key_schedule_cell_id(group_id)?;
    let frontier_cell = covered_frontier_cell_id(realm_id)?;
    Ok(vec![
        Effect {
            cell: epoch_cell,
            op: LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(Value::from(new_epoch)),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        },
        Effect {
            cell: schedule_cell,
            op: LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(Value::String(new_schedule.as_str().to_owned())),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        },
        Effect {
            cell: frontier_cell,
            op: LatticeOp {
                op_type: LatticeOpType::Add,
                tag: Some(governance_frontier_tag(attested_governance_anchor)),
                value: Some(Value::String(attested_governance_anchor.as_str().to_owned())),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        },
    ])
}

/// Build the precondition an E2EE message Move (e.g. `ck.message.create`
/// in an E2EE Realm) MUST carry to prove the MLS group's
/// `covered_frontier_cell` already covers the Move's `anchor_ref`'s
/// governance frontier.
///
/// Per spec §10: MLS lag only blocks E2EE message / key-schedule Moves
/// (which reference `covered_frontier_cell`); it does not block
/// governance / recovery Moves (which do not reference that cell). So
/// this precondition is added to message / key-schedule Moves but
/// **not** to governance / recovery Moves.
pub fn e2ee_message_precondition(
    realm_id: &RealmId,
    governance_anchor: &AnchorId,
) -> Result<Precondition, cokret_core::Error> {
    let cell = covered_frontier_cell_id(realm_id)?;
    Ok(Precondition {
        cell,
        predicate: Predicate {
            op: PredicateOp::Contains,
            value: Some(Value::String(governance_frontier_tag(governance_anchor))),
            values: None,
            predicate_id: None,
        },
    })
}

/// Convenience: bundle the Move-side primitives an MLS commit needs.
///
/// Callers wrap this into a `Move` along with their own issuer / sig /
/// hlc / anchor_ref / refs. The struct is plain data so it round-trips
/// through serde for fixture replay and federation forwarding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCommitMoveSpec {
    pub preconditions: Vec<Precondition>,
    pub effects: Vec<Effect>,
}

impl MlsCommitMoveSpec {
    /// Compose the spec from raw inputs.
    pub fn build(
        group_id: &str,
        realm_id: &RealmId,
        prev_epoch: u64,
        new_epoch: u64,
        new_schedule: &Hash,
        required_governance_anchor: &AnchorId,
        attested_governance_anchor: &AnchorId,
    ) -> Result<Self, cokret_core::Error> {
        Ok(Self {
            preconditions: mls_commit_preconditions(
                group_id,
                realm_id,
                prev_epoch,
                required_governance_anchor,
            )?,
            effects: mls_commit_effects(
                group_id,
                realm_id,
                new_epoch,
                new_schedule,
                attested_governance_anchor,
            )?,
        })
    }
}

/// Walk a `covered_frontier_cell` join value (or-set output as JSON
/// array) and return whether it covers the given governance Anchor.
///
/// This is the receiver-side check matching [`e2ee_message_precondition`]:
/// when verifying an E2EE message Move, look up the cell value and call
/// this to evaluate `contains`.
pub fn covered_frontier_contains(cell_value: &Value, anchor: &AnchorId) -> bool {
    let Some(arr) = cell_value.as_array() else { return false };
    let needle = governance_frontier_tag(anchor);
    arr.iter().any(|item| {
        // or-set output: `[{tag, value?}, ...]`. Match on either tag (the
        // canonical tag form) or value.
        item.get("tag").and_then(Value::as_str) == Some(needle.as_str())
            || item.get("value").and_then(Value::as_str) == Some(needle.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cokret_core::{
        MoveId,
        lattice::{AnchoredOp, CellState, Lattice, OrSet},
    };

    fn realm() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn anchor(byte: u8) -> AnchorId {
        AnchorId::new(format!("ck:anchor:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn schedule_hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn cell_ids_use_canonical_prefixes() {
        let group = "group.01js0mls0000000000000000";
        assert_eq!(
            mls_epoch_cell_id(group).unwrap().as_str(),
            format!("ck:cell:ck.component.mls_epoch.v1:{group}")
        );
        assert_eq!(
            key_schedule_cell_id(group).unwrap().as_str(),
            format!("ck:cell:ck.component.key_schedule.v1:{group}")
        );
        assert_eq!(
            covered_frontier_cell_id(&realm()).unwrap().as_str(),
            format!("ck:cell:ck.component.covered_frontier.v1:{}", realm().as_str())
        );
    }

    #[test]
    fn cell_id_helpers_reject_empty_group_id() {
        mls_epoch_cell_id("").unwrap_err();
        key_schedule_cell_id("").unwrap_err();
    }

    #[test]
    fn governance_frontier_tag_uses_anchor_id_verbatim() {
        let a = anchor(0xaa);
        assert_eq!(governance_frontier_tag(&a), a.as_str());
    }

    #[test]
    fn preconditions_match_spec_shape() {
        let pres =
            mls_commit_preconditions("group.01js0mls0000000000000000", &realm(), 5, &anchor(0xaa))
                .unwrap();
        assert_eq!(pres.len(), 2);
        // First: head_eq on mls_epoch_cell.
        assert_eq!(
            pres[0].cell.as_str(),
            format!("ck:cell:ck.component.mls_epoch.v1:{}", "group.01js0mls0000000000000000")
        );
        assert_eq!(pres[0].predicate.op, PredicateOp::HeadEq);
        assert_eq!(pres[0].predicate.value.as_ref().unwrap().as_u64().unwrap(), 5);
        // Second: contains on covered_frontier_cell.
        assert_eq!(
            pres[1].cell.as_str(),
            format!("ck:cell:ck.component.covered_frontier.v1:{}", realm().as_str())
        );
        assert_eq!(pres[1].predicate.op, PredicateOp::Contains);
        assert_eq!(
            pres[1].predicate.value.as_ref().unwrap().as_str().unwrap(),
            anchor(0xaa).as_str()
        );
    }

    #[test]
    fn effects_match_spec_shape() {
        let effs = mls_commit_effects(
            "group.01js0mls0000000000000000",
            &realm(),
            6,
            &schedule_hash(0x77),
            &anchor(0xaa),
        )
        .unwrap();
        assert_eq!(effs.len(), 3);

        // 1. set new_epoch on mls_epoch_cell.
        assert_eq!(effs[0].op.op_type, LatticeOpType::Set);
        assert_eq!(effs[0].op.value.as_ref().unwrap().as_u64().unwrap(), 6);

        // 2. set new schedule on key_schedule_cell.
        assert_eq!(effs[1].op.op_type, LatticeOpType::Set);
        assert_eq!(
            effs[1].op.value.as_ref().unwrap().as_str().unwrap(),
            schedule_hash(0x77).as_str()
        );

        // 3. add tag on covered_frontier_cell.
        assert_eq!(effs[2].op.op_type, LatticeOpType::Add);
        assert_eq!(effs[2].op.tag.as_deref(), Some(anchor(0xaa).as_str()));
    }

    #[test]
    fn build_spec_round_trips() {
        let spec = MlsCommitMoveSpec::build(
            "group.01js0mls0000000000000000",
            &realm(),
            5,
            6,
            &schedule_hash(0x77),
            &anchor(0xaa),
            &anchor(0xaa),
        )
        .unwrap();
        assert_eq!(spec.preconditions.len(), 2);
        assert_eq!(spec.effects.len(), 3);
    }

    #[test]
    fn e2ee_message_precondition_targets_covered_frontier() {
        let pre = e2ee_message_precondition(&realm(), &anchor(0xaa)).unwrap();
        assert_eq!(
            pre.cell.as_str(),
            format!("ck:cell:ck.component.covered_frontier.v1:{}", realm().as_str())
        );
        assert_eq!(pre.predicate.op, PredicateOp::Contains);
        assert_eq!(pre.predicate.value.as_ref().unwrap().as_str().unwrap(), anchor(0xaa).as_str());
    }

    #[test]
    fn covered_frontier_contains_resolves_or_set_join() {
        // Build an or-set state by applying an MLS commit's covered_frontier add op.
        let effs = mls_commit_effects(
            "group.01js0mls0000000000000000",
            &realm(),
            6,
            &schedule_hash(0x77),
            &anchor(0xaa),
        )
        .unwrap();
        let frontier_cell = covered_frontier_cell_id(&realm()).unwrap();
        let aop = AnchoredOp::new(move_id(0x11), effs[2].op.clone());
        let state = OrSet.join(&frontier_cell, &[aop]);
        match state {
            CellState::Value(v) => {
                assert!(covered_frontier_contains(&v, &anchor(0xaa)));
                assert!(!covered_frontier_contains(&v, &anchor(0xbb)));
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn covered_frontier_contains_rejects_non_array() {
        assert!(!covered_frontier_contains(&Value::Null, &anchor(0xaa)));
        assert!(!covered_frontier_contains(&Value::String("x".into()), &anchor(0xaa)));
    }

    #[test]
    fn second_commit_extends_covered_frontier() {
        // Two commits adding two different governance Anchors must coexist
        // in the or-set; covered_frontier_contains MUST find both.
        let cell = covered_frontier_cell_id(&realm()).unwrap();
        let e1 = mls_commit_effects(
            "group.01js0mls0000000000000000",
            &realm(),
            6,
            &schedule_hash(0x77),
            &anchor(0xaa),
        )
        .unwrap();
        let e2 = mls_commit_effects(
            "group.01js0mls0000000000000000",
            &realm(),
            7,
            &schedule_hash(0x88),
            &anchor(0xbb),
        )
        .unwrap();
        let aops = vec![
            AnchoredOp::new(move_id(0x11), e1[2].op.clone()),
            AnchoredOp::new(move_id(0x22), e2[2].op.clone()),
        ];
        let state = OrSet.join(&cell, &aops);
        match state {
            CellState::Value(v) => {
                assert!(covered_frontier_contains(&v, &anchor(0xaa)));
                assert!(covered_frontier_contains(&v, &anchor(0xbb)));
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn distinct_groups_have_distinct_epoch_cells() {
        let a = mls_epoch_cell_id("group-A").unwrap();
        let b = mls_epoch_cell_id("group-B").unwrap();
        assert_ne!(a, b);
    }
}
