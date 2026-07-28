//! MLS control-cell subject derivations + the `covered_seals` read.
//!
//! Per spec [`event-auth-state-resolution.md`](https://arkret.org/spec/v1/zh/authz/event-auth-state-resolution.md)
//! §10, an MLS commit is a **Control Move** — an Event, not a Seal. Its
//! registered contract writes three cells:
//!
//! | cell family | lattice | role |
//! | --- | --- | --- |
//! | `ak.component.mls.epoch.v1` | cas-register | current epoch counter for the MLS group |
//! | `ak.component.mls.key_schedule.v1` | cas-register | latest key schedule pointer |
//! | `ak.component.covered_seals.v1` | or-set | governance Seal frontier this MLS group has bound |
//!
//! The operations themselves are receiver-derived from `kind + payload`, so
//! nothing here builds them: v1 has no producer-authored effect channel and
//! the or-set element tags are batch tags the producer cannot name. What
//! remains is the cell-subject derivation and the receiver-side read of the
//! joined `covered_seals` value.

use arkret_identifiers::{CellRef, SealId};
use arkret_wire::WireError;
use serde_json::Value;

/// Cell families the MLS commit contract targets.
pub const MLS_EPOCH_CELL_FAMILY: &str = "ak.component.mls.epoch.v1";
pub const KEY_SCHEDULE_CELL_FAMILY: &str = "ak.component.mls.key_schedule.v1";
pub const COVERED_SEALS_CELL_FAMILY: &str = "ak.component.covered_seals.v1";

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

/// `ak:cell:ak.component.covered_seals.v1:<group_id>` — or-set listing
/// the governance Seal frontiers this MLS group is currently bound to.
///
/// The subject is the MLS group, not the Realm: a Realm holds one MLS group per
/// Circle, so keying on `realm_id` would merge distinct groups' frontiers into a
/// single cell.
pub fn covered_seals_cell_id(group_id: &str) -> Result<CellRef, WireError> {
    if group_id.is_empty() {
        return Err(WireError::Protocol(
            "MLS group_id must not be empty".to_owned(),
        ));
    }
    CellRef::new(format!("ak:cell:{COVERED_SEALS_CELL_FAMILY}:{group_id}"))
        .map_err(|e| WireError::Protocol(format!("invalid covered_seals cell id: {e}")))
}

/// Walk a joined `covered_seals` cell value (or-set output as a JSON array)
/// and return whether it covers the given governance Seal.
///
/// The match is on the element **value**: the registered `or_set_batch_add`
/// projection stores the Seal ref there and derives the tag as a batch digest,
/// so the tag is not the Seal id and MUST NOT be compared against one.
pub fn covered_seals_contains(cell_value: &Value, seal: &SealId) -> bool {
    let Some(arr) = cell_value.as_array() else {
        return false;
    };
    arr.iter()
        .any(|item| item.get("value").and_then(Value::as_str) == Some(seal.as_str()))
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::Hash;
    use arkret_wire::{LatticeOp, LatticeOpType};
    use serde_json::json;

    use super::*;
    use crate::lattice::{CellState, Lattice, OrSet, SealedOp};

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

    /// The or-set `add` an `or_set_batch_add` projection produces: an opaque
    /// batch tag plus the covered Seal ref as the element value.
    fn covered_seal_add(batch_tag: &str, seal: &SealId) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(batch_tag.to_owned()),
            value: Some(Value::String(seal.as_str().to_owned())),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
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
        assert_eq!(
            covered_seals_cell_id(group).unwrap().as_str(),
            format!("ak:cell:ak.component.covered_seals.v1:{group}")
        );
    }

    #[test]
    fn cell_id_helpers_reject_empty_group_id() {
        mls_epoch_cell_id("").unwrap_err();
        key_schedule_cell_id("").unwrap_err();
        covered_seals_cell_id("").unwrap_err();
    }

    #[test]
    fn distinct_groups_have_distinct_epoch_cells() {
        let a = mls_epoch_cell_id("group-A").unwrap();
        let b = mls_epoch_cell_id("group-B").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn covered_seals_contains_resolves_or_set_join() {
        let frontier_cell = covered_seals_cell_id("group.01js0mls0000000000000000").unwrap();
        let aop = SealedOp::new(
            event_digest(0x11),
            covered_seal_add("batch-tag-0", &seal(0xaa)),
        );
        let CellState::Value(value) = OrSet.join(&frontier_cell, &[aop]) else {
            panic!("expected value")
        };
        assert!(covered_seals_contains(&value, &seal(0xaa)));
        assert!(!covered_seals_contains(&value, &seal(0xbb)));
    }

    #[test]
    fn covered_seals_contains_ignores_the_batch_tag() {
        // The tag is a `sha256(tag_context || dot || value)` digest, never the
        // Seal id; reading it as one would accept an unrelated element.
        let value = json!([{ "tag": seal(0xaa).as_str(), "value": "not-a-seal" }]);
        assert!(!covered_seals_contains(&value, &seal(0xaa)));
    }

    #[test]
    fn covered_seals_contains_rejects_non_array() {
        assert!(!covered_seals_contains(&Value::Null, &seal(0xaa)));
        assert!(!covered_seals_contains(
            &Value::String("x".into()),
            &seal(0xaa)
        ));
    }

    #[test]
    fn second_commit_extends_covered_seals() {
        // Two commits binding two different governance Seals must coexist in
        // the or-set; `covered_seals_contains` MUST find both.
        let cell = covered_seals_cell_id("group.01js0mls0000000000000000").unwrap();
        let aops = vec![
            SealedOp::new(
                event_digest(0x11),
                covered_seal_add("batch-tag-0", &seal(0xaa)),
            ),
            SealedOp::new(
                event_digest(0x22),
                covered_seal_add("batch-tag-1", &seal(0xbb)),
            ),
        ];
        let CellState::Value(value) = OrSet.join(&cell, &aops) else {
            panic!("expected value")
        };
        assert!(covered_seals_contains(&value, &seal(0xaa)));
        assert!(covered_seals_contains(&value, &seal(0xbb)));
    }
}
