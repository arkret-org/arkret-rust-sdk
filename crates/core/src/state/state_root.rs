//! Canonical Merkle `state_root` compute (spec §4.2).
//!
//! Per [cokret-spec event-auth-state-resolution.md §4.2](
//! ../../cokret-spec/spec/v1/zh/authz/event-auth-state-resolution.md):
//!
//! 1. For each cell with at least one effect under the current Anchor view,
//!    build a leaf:
//!    `leaf_input = canonical_json({"cell": "<wire>", "state": <state_object>})`
//!    `leaf_hash = sha256(leaf_input)`.
//! 2. Sort `(cell_wire, leaf_hash)` by `cell_wire` ascending.
//! 3. Combine leaf_hash list via RFC 6962-style binary Merkle tree
//!    (odd leaf promotes, no duplication). Empty list → `sha256("")`.
//! 4. Wire form: `state_root = "sha256:" + lower_hex(root)`.
//!
//! `bottom.anchor_view` MUST be omitted from `<state_object>` — that's
//! handled automatically because `Bottom::anchor_view` is
//! `#[serde(skip_serializing_if = "Option::is_none")]` and we set it to
//! `None` before serializing.

use std::collections::BTreeMap;

use crate::{Bottom, CellRef, Hash, canonical, lattice::CellState};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Empty-list root: `sha256("")` per spec §4.2.2.
pub const EMPTY_STATE_ROOT: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Compute the canonical Merkle root for a cell-state map.
///
/// `cells` is the full list of cells with at least one effect under the
/// current Anchor view; values are resolved via
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
            let mut hasher = Sha256::new();
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
            // Strip `anchor_view` to prevent self-recursion (spec §4.2.1).
            let mut stripped: Bottom = b.clone();
            stripped.anchor_view = None;
            json!({ "bottom": stripped })
        }
    };
    let leaf_input: Value = json!({
        "cell": cell.as_str(),
        "state": state_object,
    });
    let bytes = canonical::canonical_json_bytes(&leaf_input)?;
    Ok(Sha256::digest(&bytes).into())
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
    use super::*;
    use crate::{AnchorView, BottomKind};
    use serde_json::json;

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
        // Single-leaf root MUST equal the leaf hash directly (per spec §4.2.2).
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
        assert_eq!(compute_state_root(&a).unwrap(), compute_state_root(&b).unwrap());
    }

    #[test]
    fn different_values_yield_different_roots() {
        let mut a = BTreeMap::new();
        a.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!("a")));
        let mut b = BTreeMap::new();
        b.insert(cell("ck:cell:ck.x:1"), CellState::Value(json!("b")));
        assert_ne!(compute_state_root(&a).unwrap(), compute_state_root(&b).unwrap());
    }

    #[test]
    fn bottom_state_serializes_without_anchor_view() {
        // Two Bottoms differing only in anchor_view MUST yield the same leaf.
        let mut bottom_a = Bottom::new(BottomKind::Conflict, vec![cell("ck:cell:ck.x:1")]);
        bottom_a.anchor_view = Some(AnchorView { leaves: vec![], state_root: None });
        let mut bottom_b = bottom_a.clone();
        bottom_b.anchor_view = None;

        let h_a = leaf_hash(&cell("ck:cell:ck.x:1"), &CellState::Bottom(bottom_a)).unwrap();
        let h_b = leaf_hash(&cell("ck:cell:ck.x:1"), &CellState::Bottom(bottom_b)).unwrap();
        assert_eq!(h_a, h_b, "anchor_view must be stripped before hashing");
    }

    #[test]
    fn three_leaf_tree_uses_odd_promotion() {
        // 3 leaves: layer 0 = [A, B, C], layer 1 = [sha256(A||B), C], layer 2 = sha256(layer1[0]||C).
        // Verify the root is computable and not equal to any single leaf.
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
