//! Canonical Merkle root for Seal-confirmed `sequenced_state` cells.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::state_model::{ResolvedCellState, SequencedStateValue};
use crate::{CellRef, Hash, canonical};

/// The complete Seal-confirmed security state used to compute `state_root`.
#[derive(Clone, Copy, Debug)]
pub struct GovernanceView<'a> {
    pub cells: &'a BTreeMap<CellRef, ResolvedCellState>,
}

impl<'a> GovernanceView<'a> {
    pub fn new(cells: &'a BTreeMap<CellRef, ResolvedCellState>) -> Self {
        Self { cells }
    }
}

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

pub const EMPTY_STATE_ROOT: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn empty_state_root_with_digest_suite(
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    Hash::new(canonical::digest(digest_suite, []))
        .map_err(|error| crate::WireError::Protocol(format!("invalid empty-state hash: {error}")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateInclusionProof {
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

pub fn compute_state_root(
    view: GovernanceView<'_>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let leaves = ordered_state_root_leaves(view, digest_suite)?;
    seal_merkle_root_from_leaf_hashes(
        leaves.into_iter().map(|(_, hash)| hash).collect(),
        digest_suite,
    )
}

/// Stable digest for a settled ordinary projection. This digest is never a
/// Seal `state_root` and carries no security-confirmation meaning.
pub fn value_frontier_digest(
    cells: &BTreeMap<CellRef, ResolvedCellState>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let mut leaf_data = Vec::new();
    for (cell, state) in cells {
        let Some(value) = state.settled_value() else {
            continue;
        };
        leaf_data.push((
            cell.as_str().to_owned(),
            arkret_canonical::canonical_json_bytes(&json!({
                "cell": cell.as_str(),
                "value": value,
            }))?,
        ));
    }
    leaf_data.sort_by(|left, right| left.0.cmp(&right.0));
    seal_merkle_root_from_leaf_data(
        &leaf_data
            .into_iter()
            .map(|(_, data)| data)
            .collect::<Vec<_>>(),
        digest_suite,
    )
}

fn ordered_state_root_leaves(
    view: GovernanceView<'_>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<(String, [u8; 32])>, crate::WireError> {
    let mut leaves = Vec::with_capacity(view.cells.len());
    for (cell, state) in view.cells {
        let ResolvedCellState::Sequenced(state) = state else {
            return Err(crate::WireError::Protocol(format!(
                "state_root cell {} is not Seal-confirmed sequenced_state",
                cell.as_str()
            )));
        };
        leaves.push((
            cell.as_str().to_owned(),
            leaf_hash(cell, state, digest_suite)?,
        ));
    }
    leaves.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(leaves)
}

pub fn state_leaf_canonical_preimage(
    view: GovernanceView<'_>,
    cell: &CellRef,
) -> Result<Vec<u8>, crate::WireError> {
    let ResolvedCellState::Sequenced(state) = view.cells.get(cell).ok_or_else(|| {
        crate::WireError::Protocol(format!(
            "state inclusion target {} is absent",
            cell.as_str()
        ))
    })?
    else {
        return Err(crate::WireError::Protocol(format!(
            "state inclusion target {} is not sequenced_state",
            cell.as_str()
        )));
    };
    leaf_preimage(cell, state)
}

pub fn state_inclusion_proof(
    view: GovernanceView<'_>,
    target_cell: &CellRef,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<StateInclusionProof, crate::WireError> {
    let leaves = ordered_state_root_leaves(view, digest_suite)?;
    let mut index = leaves
        .iter()
        .position(|(cell, _)| cell == target_cell.as_str())
        .ok_or_else(|| {
            crate::WireError::Protocol(format!(
                "state inclusion target {} is absent",
                target_cell.as_str()
            ))
        })?;
    let leaf_count = u64::try_from(leaves.len())
        .map_err(|_| crate::WireError::Protocol("state leaf count exceeds u64".to_owned()))?;
    let leaf_index = u64::try_from(index)
        .map_err(|_| crate::WireError::Protocol("state leaf index exceeds u64".to_owned()))?;
    let leaf_digest = hash_from_raw(leaves[index].1, digest_suite)?;
    let mut layer = leaves.into_iter().map(|(_, hash)| hash).collect::<Vec<_>>();
    let mut inclusion_proof = Vec::new();
    while layer.len() > 1 {
        if index.is_multiple_of(2) {
            if index + 1 < layer.len() {
                inclusion_proof.push(hash_from_raw(layer[index + 1], digest_suite)?);
            }
        } else {
            inclusion_proof.push(hash_from_raw(layer[index - 1], digest_suite)?);
        }
        layer = next_seal_merkle_layer(&layer, digest_suite);
        index /= 2;
    }
    Ok(StateInclusionProof {
        leaf_digest,
        leaf_index,
        leaf_count,
        inclusion_proof,
    })
}

pub fn verify_state_inclusion_proof(
    leaf_digest: &Hash,
    leaf_index: u64,
    leaf_count: u64,
    inclusion_proof: &[Hash],
    expected_root: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<bool, crate::WireError> {
    if leaf_count == 0 || leaf_index >= leaf_count {
        return Ok(false);
    }
    let mut current = raw_from_hash(leaf_digest, digest_suite)?;
    let mut index = leaf_index;
    let mut width = leaf_count;
    let mut siblings = inclusion_proof.iter();
    while width > 1 {
        let has_sibling = if index.is_multiple_of(2) {
            index + 1 < width
        } else {
            true
        };
        if has_sibling {
            let Some(sibling) = siblings.next() else {
                return Ok(false);
            };
            let sibling = raw_from_hash(sibling, digest_suite)?;
            current = if index.is_multiple_of(2) {
                node_hash(current, sibling, digest_suite)
            } else {
                node_hash(sibling, current, digest_suite)
            };
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    if siblings.next().is_some() {
        return Ok(false);
    }
    Ok(hash_from_raw(current, digest_suite)? == *expected_root)
}

pub fn sequenced_state_leaf_digest(
    cell: &CellRef,
    state: &SequencedStateValue,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    hash_from_raw(leaf_hash(cell, state, digest_suite)?, digest_suite)
}

pub fn seal_merkle_root_from_leaf_data(
    leaf_data: &[Vec<u8>],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let leaves = leaf_data
        .iter()
        .map(|data| {
            canonical::digest_bytes_from_slices(
                digest_suite,
                &[&[LEAF_PREFIX][..], data.as_slice()],
            )
        })
        .collect();
    seal_merkle_root_from_leaf_hashes(leaves, digest_suite)
}

pub(crate) fn seal_merkle_audit_path_from_leaf_data(
    leaf_data: &[Vec<u8>],
    leaf_index: usize,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<Hash>, crate::WireError> {
    if leaf_index >= leaf_data.len() {
        return Err(crate::WireError::Protocol(
            "Seal Merkle inclusion target is absent".to_owned(),
        ));
    }
    let mut layer = leaf_data
        .iter()
        .map(|data| {
            canonical::digest_bytes_from_slices(
                digest_suite,
                &[&[LEAF_PREFIX][..], data.as_slice()],
            )
        })
        .collect::<Vec<_>>();
    let mut index = leaf_index;
    let mut branch = Vec::new();
    while layer.len() > 1 {
        if index.is_multiple_of(2) {
            if index + 1 < layer.len() {
                branch.push(hash_from_raw(layer[index + 1], digest_suite)?);
            }
        } else {
            branch.push(hash_from_raw(layer[index - 1], digest_suite)?);
        }
        layer = next_seal_merkle_layer(&layer, digest_suite);
        index /= 2;
    }
    Ok(branch)
}

pub(crate) fn verify_seal_merkle_audit_path_from_leaf_data(
    leaf_data: &[u8],
    leaf_index: u64,
    leaf_count: u64,
    audit_path: &[Hash],
    expected_root: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<bool, crate::WireError> {
    let leaf_digest = hash_from_raw(
        canonical::digest_bytes_from_slices(digest_suite, &[&[LEAF_PREFIX][..], leaf_data]),
        digest_suite,
    )?;
    verify_state_inclusion_proof(
        &leaf_digest,
        leaf_index,
        leaf_count,
        audit_path,
        expected_root,
        digest_suite,
    )
}

fn seal_merkle_root_from_leaf_hashes(
    mut layer: Vec<[u8; 32]>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    if layer.is_empty() {
        return empty_state_root_with_digest_suite(digest_suite);
    }
    while layer.len() > 1 {
        layer = next_seal_merkle_layer(&layer, digest_suite);
    }
    hash_from_raw(layer[0], digest_suite)
}

fn next_seal_merkle_layer(
    layer: &[[u8; 32]],
    digest_suite: arkret_canonical::DigestSuite,
) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(layer.len().div_ceil(2));
    let mut index = 0;
    while index + 1 < layer.len() {
        next.push(node_hash(layer[index], layer[index + 1], digest_suite));
        index += 2;
    }
    if index < layer.len() {
        next.push(layer[index]);
    }
    next
}

fn node_hash(
    left: [u8; 32],
    right: [u8; 32],
    digest_suite: arkret_canonical::DigestSuite,
) -> [u8; 32] {
    canonical::digest_bytes_from_slices(digest_suite, &[&[NODE_PREFIX][..], &left, &right])
}

fn hash_from_raw(
    raw: [u8; 32],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    Hash::new(format!("{}:{}", digest_suite.as_str(), hex::encode(raw)))
        .map_err(|error| crate::WireError::Protocol(format!("invalid state proof hash: {error}")))
}

fn raw_from_hash(
    hash: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<[u8; 32], crate::WireError> {
    let encoded = hash
        .as_str()
        .strip_prefix(&format!("{}:", digest_suite.as_str()))
        .ok_or_else(|| {
            crate::WireError::Protocol(format!(
                "state proof hash must use {}",
                digest_suite.as_str()
            ))
        })?;
    let raw = hex::decode(encoded).map_err(|error| {
        crate::WireError::Protocol(format!("invalid state proof hash: {error}"))
    })?;
    raw.try_into()
        .map_err(|_| crate::WireError::Protocol("state proof hash must be 32 bytes".to_owned()))
}

pub fn leaf_hash(
    cell: &CellRef,
    state: &SequencedStateValue,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<[u8; 32], crate::WireError> {
    let preimage = leaf_preimage(cell, state)?;
    Ok(canonical::digest_bytes_from_slices(
        digest_suite,
        &[&[LEAF_PREFIX][..], &preimage],
    ))
}

pub fn state_leaf_hash_from_state_object(
    cell: &CellRef,
    state_object: Value,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let state: SequencedStateValue = serde_json::from_value(state_object).map_err(|error| {
        crate::WireError::Protocol(format!("invalid sequenced_state leaf: {error}"))
    })?;
    sequenced_state_leaf_digest(cell, &state, digest_suite)
}

fn leaf_preimage(cell: &CellRef, state: &SequencedStateValue) -> Result<Vec<u8>, crate::WireError> {
    arkret_canonical::canonical_json_bytes(&json!({
        "cell": cell.as_str(),
        "state": state,
    }))
    .map_err(Into::into)
}
