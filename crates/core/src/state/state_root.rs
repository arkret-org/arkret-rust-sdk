//! Canonical Merkle `state_root` compute (spec §6.2.1 / §6.2.2).
//!
//! Per [cokret-spec event-auth-state-resolution.md §6.2.1 / §6.2.2](
//! ../../cokret-spec/spec/v1/zh/authz/event-auth-state-resolution.md):
//!
//! 1. For each non-`⊥` control cell under the current joined Seal view, build a leaf:
//!    `leaf_preimage = canonical_json({"cell": "<wire>", "state": <state_object>})`, `leaf = H(0x00
//!    || leaf_preimage_utf8_bytes)` (RFC 6962 leaf domain separation).
//! 2. Sort leaves by `cell_wire` Unicode code point ascending.
//! 3. Combine leaves via the unified Seal Merkle rule (§6.2.2): internal node = `H(0x01 || left ||
//!    right)`, odd tail promoted without duplication, single-leaf root equals that leaf's `H(0x00
//!    || ..)` (NOT the bare preimage hash), empty set → `H` over the empty byte string
//!    (`sha256:e3b0...b855`).
//! 4. Wire form: `state_root = "sha256:" + lower_hex(root)`.
//!
//! This is the **Seal-level** Merkle family with `0x00`/`0x01` domain separation,
//! shared with `control_event_set_root` / `data_view_root` / observation roots. It is
//! distinct from the snapshot Merkle family (encoding.md §3.3.1, no prefixes, bare-leaf
//! single root) and the two MUST NOT be interchanged.
//!
//! `bottom.seal_view` MUST be omitted from `<state_object>` — that's
//! handled automatically because `Bottom::seal_view` is
//! `#[serde(skip_serializing_if = "Option::is_none")]` and we set it to
//! `None` before serializing.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::lattice::CellState;
use crate::{Bottom, CellRef, Hash, canonical};

/// Domain-separation prefix for Merkle leaves (RFC 6962, spec §6.2.2).
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for Merkle internal nodes (RFC 6962, spec §6.2.2).
const NODE_PREFIX: u8 = 0x01;

/// Empty-set root: `H` over the empty byte string = `sha256("")` per spec §6.2.2.
pub const EMPTY_STATE_ROOT: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Compute the canonical Merkle root for a cell-state map.
///
/// `cells` is the full list of cells with at least one effect under the
/// current Seal view; values are resolved via
/// [`crate::lattice::Lattice::join`].
/// Empty input returns [`EMPTY_STATE_ROOT`].
pub fn compute_state_root(cells: &BTreeMap<CellRef, CellState>) -> Result<Hash, crate::Error> {
    if cells.is_empty() {
        return Hash::new(EMPTY_STATE_ROOT.to_owned())
            .map_err(|e| crate::Error::Protocol(format!("invalid empty-state hash: {e}")));
    }

    let mut leaves: Vec<(String, [u8; 32])> = Vec::with_capacity(cells.len());
    for (cell, state) in cells {
        let leaf = leaf_hash(cell, state)?;
        leaves.push((cell.as_str().to_owned(), leaf));
    }
    // Sort by cell wire string ascending (Unicode code point).
    leaves.sort_by(|a, b| a.0.cmp(&b.0));

    let mut layer: Vec<[u8; 32]> = leaves.into_iter().map(|(_, h)| h).collect();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < layer.len() {
            // Internal node: H(0x01 || left || right) (spec §6.2.2).
            let mut hasher = Sha256::new();
            hasher.update([NODE_PREFIX]);
            hasher.update(layer[i]);
            hasher.update(layer[i + 1]);
            next.push(hasher.finalize().into());
            i += 2;
        }
        if i < layer.len() {
            // Odd tail: promote without duplication.
            next.push(layer[i]);
        }
        layer = next;
    }
    let root = layer[0];
    Hash::new(format!("sha256:{}", encode_hex(&root)))
        .map_err(|e| crate::Error::Protocol(format!("invalid state root: {e}")))
}

/// Compute the leaf hash for a single cell.
///
/// Public for use by selective Merkle-branch updaters and tests that
/// want to verify per-cell encoding without running the whole tree.
pub fn leaf_hash(cell: &CellRef, state: &CellState) -> Result<[u8; 32], crate::Error> {
    let state_object = match state {
        CellState::Value(v) => json!({ "value": v }),
        CellState::Bottom(b) => {
            // Strip `seal_view` to prevent self-recursion (spec §6.2.1).
            let mut stripped: Bottom = b.clone();
            stripped.seal_view = None;
            json!({ "bottom": stripped })
        }
    };
    let leaf_input: Value = json!({
        "cell": cell.as_str(),
        "state": state_object,
    });
    let bytes = canonical::canonical_json_bytes(&leaf_input)?;
    // Leaf: H(0x00 || leaf_preimage_utf8_bytes) (spec §6.2.2).
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{BottomKind, SealView};

    fn cell(s: &str) -> CellRef {
        CellRef::new(s.to_owned()).unwrap()
    }

    #[test]
    fn empty_map_returns_constant_root() {
        let root = compute_state_root(&BTreeMap::new()).unwrap();
        assert_eq!(root.as_str(), EMPTY_STATE_ROOT);
    }

    #[test]
    fn single_cell_root_equals_leaf_hash() {
        let mut map = BTreeMap::new();
        map.insert(
            cell("ck:cell:ck.component.member.state.v1:did.web.alice.example"),
            CellState::Value(json!("join")),
        );
        let root = compute_state_root(&map).unwrap();
        // Format must match ck:hash:sha256: prefix.
        assert!(root.as_str().starts_with("sha256:"));
        // Single-leaf root MUST equal the leaf hash directly (per spec §6.2.2).
        let leaf = leaf_hash(
            &cell("ck:cell:ck.component.member.state.v1:did.web.alice.example"),
            &CellState::Value(json!("join")),
        )
        .unwrap();
        let leaf_hex: String = leaf.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(root.as_str(), format!("sha256:{leaf_hex}"));
    }

    #[test]
    fn deterministic_across_insertion_order() {
        // Map order doesn't affect output because we sort by cell wire.
        let mut a = BTreeMap::new();
        a.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!(1)));
        a.insert(cell("ck:cell:ck.y:2"), CellState::Value(json!(2)));
        let mut b = BTreeMap::new();
        b.insert(cell("ck:cell:ck.y:2"), CellState::Value(json!(2)));
        b.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!(1)));
        assert_eq!(
            compute_state_root(&a).unwrap(),
            compute_state_root(&b).unwrap()
        );
    }

    #[test]
    fn different_values_yield_different_roots() {
        let mut a = BTreeMap::new();
        a.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!("a")));
        let mut b = BTreeMap::new();
        b.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!("b")));
        assert_ne!(
            compute_state_root(&a).unwrap(),
            compute_state_root(&b).unwrap()
        );
    }

    #[test]
    fn bottom_state_serializes_without_seal_view() {
        // Two Bottoms differing only in seal_view MUST yield the same leaf.
        let mut bottom_a = Bottom::new(BottomKind::Conflict, vec![cell("ck:cell:ck.x:1")]);
        bottom_a.seal_view = Some(SealView {
            leaves: vec![],
            state_root: None,
        });
        let mut bottom_b = bottom_a.clone();
        bottom_b.seal_view = None;

        let h_a = leaf_hash(&cell("ck:cell:ck.x:1"), &CellState::Bottom(bottom_a)).unwrap();
        let h_b = leaf_hash(&cell("ck:cell:ck.x:1"), &CellState::Bottom(bottom_b)).unwrap();
        assert_eq!(h_a, h_b, "seal_view must be stripped before hashing");
    }

    #[test]
    fn three_leaf_tree_uses_odd_promotion() {
        // 3 leaves: layer 0 = [A, B, C], layer 1 = [sha256(A||B), C], layer 2 =
        // sha256(layer1[0]||C). Verify the root is computable and not equal to any single
        // leaf.
        let mut m = BTreeMap::new();
        m.insert(cell("ck:cell:a:1"), CellState::Value(json!("a")));
        m.insert(cell("ck:cell:b:2"), CellState::Value(json!("b")));
        m.insert(cell("ck:cell:c:3"), CellState::Value(json!("c")));
        let root = compute_state_root(&m).unwrap();
        // Must not match any leaf hash.
        let leaf_a = leaf_hash(&cell("ck:cell:a:1"), &CellState::Value(json!("a"))).unwrap();
        let leaf_a_hex: String = leaf_a.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(root.as_str(), format!("sha256:{leaf_a_hex}"));
    }

    #[test]
    fn bottom_kind_affects_root() {
        // Different BottomKind on the same cell MUST yield different leaf hashes.
        let bottom_conflict = Bottom::new(BottomKind::Conflict, vec![cell("ck:cell:x:1")]);
        let bottom_schema = Bottom::new(BottomKind::SchemaError, vec![cell("ck:cell:x:1")]);
        let h_a = leaf_hash(&cell("ck:cell:x:1"), &CellState::Bottom(bottom_conflict)).unwrap();
        let h_b = leaf_hash(&cell("ck:cell:x:1"), &CellState::Bottom(bottom_schema)).unwrap();
        assert_ne!(h_a, h_b);
    }
}
