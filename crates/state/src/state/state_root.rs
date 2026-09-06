//! Canonical Merkle `state_root` compute (spec §6.2.1 / §6.2.2).
//!
//! Per [arkret-spec event-auth-state-resolution.md §6.2.1 / §6.2.2](
//! ../../arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md):
//!
//! 1. For each member control cell under the current joined Seal view, build a leaf: `leaf_preimage
//!    = canonical_json({"cell": "<wire>", "state": <state_object>})`, `leaf = H(0x00 ||
//!    leaf_preimage_utf8_bytes)` (RFC 6962 leaf domain separation). `<state_object>` has two shapes
//!    and the cell's lattice picks between them:
//!    * `cas_register`: `{"heads":[{"event_id":…,"value":…}]}`, and the membership test is "the
//!      cell has at least one active head" — so a cell whose value is `null` or whose heads diverge
//!      into `⊥` is still a member. Non-membership alone cannot otherwise separate "never written"
//!      from "released" or from "in conflict".
//!    * everything else: `{"value": <lattice_value>}`, and a `⊥` cell is not a member.
//! 2. Sort leaves by `cell_wire` Unicode code point ascending.
//! 3. Combine leaves via the unified Seal Merkle rule (§6.2.2): internal node = `H(0x01 || left ||
//!    right)`, odd tail promoted without duplication, single-leaf root equals that leaf's `H(0x00
//!    || ..)` (NOT the bare preimage hash), empty set → `H` over the empty byte string (the
//!    selected suite digest of the empty byte string).
//! 4. Wire form: `state_root = "<suite>:" + lower_hex(root)`.
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

use crate::lattice::CellState;
use crate::lattice::cas_register::CasHead;
use crate::{CellRef, Hash, canonical};

/// The active `cas_register` heads of every written cell in a joined view.
///
/// Keyed by cell, in the order [`crate::lattice::cas_register::cas_heads`]
/// returns. A cell with no entry has never been written; a cell with an entry
/// always has at least one head.
pub type CasHeadsByCell = BTreeMap<CellRef, Vec<CasHead>>;

/// One joined governance view, in the two halves a `state_root` needs.
///
/// `cells` is what readers and preconditions see: one settled value per cell,
/// or `⊥`. `cas_heads` is the identity half that `cells` structurally cannot
/// carry — a released cell and an unwritten one both read `null`, and a `⊥`
/// cell has no single value at all, yet §6.2.1 requires both to be members with
/// their full head set.
///
/// Both halves come from the same op set, so a caller that builds one without
/// the other has a bug rather than an option. [`compute_state_root`] enforces
/// that: a `cas_register` cell present in `cells` but missing from `cas_heads`
/// is rejected instead of being hashed under the wrong preimage.
#[derive(Clone, Copy, Debug)]
pub struct GovernanceView<'a> {
    pub cells: &'a BTreeMap<CellRef, CellState>,
    pub cas_heads: &'a CasHeadsByCell,
}

impl<'a> GovernanceView<'a> {
    pub fn new(cells: &'a BTreeMap<CellRef, CellState>, cas_heads: &'a CasHeadsByCell) -> Self {
        Self { cells, cas_heads }
    }

    /// A view over a cell map that provably holds no `cas_register` cell.
    ///
    /// Callers that hand-build a state map for a single non-CAS family use this;
    /// it still goes through the same membership check, so naming a CAS family
    /// here fails loudly rather than producing a `{"value":…}` leaf.
    pub fn values_only(cells: &'a BTreeMap<CellRef, CellState>) -> Self {
        Self {
            cells,
            cas_heads: empty_cas_heads(),
        }
    }
}

fn empty_cas_heads() -> &'static CasHeadsByCell {
    static EMPTY: std::sync::OnceLock<CasHeadsByCell> = std::sync::OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// Domain-separation prefix for Merkle leaves (RFC 6962, spec §6.2.2).
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for Merkle internal nodes (RFC 6962, spec §6.2.2).
const NODE_PREFIX: u8 = 0x01;

/// Empty-set root: `H` over the empty byte string = `sha256("")` per spec §6.2.2.
pub const EMPTY_STATE_ROOT: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Compute the empty state root under an explicit Realm digest suite.
pub fn empty_state_root_with_digest_suite(
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    Hash::new(canonical::digest(digest_suite, []))
        .map_err(|error| crate::WireError::Protocol(format!("invalid empty-state hash: {error}")))
}

/// Portable RFC 6962 branch for one non-bottom state cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateInclusionProof {
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// Sibling hashes ordered from the leaf layer toward the root. Odd
    /// promoted nodes contribute no sibling entry.
    pub inclusion_proof: Vec<Hash>,
}

/// Compute the canonical Merkle root for a cell-state map.
///
/// `cells` is the full list of cells with at least one effect under the
/// current Seal view; values are resolved via
/// [`crate::lattice::Lattice::join`].
/// Empty input returns [`EMPTY_STATE_ROOT`].
/// Compute the canonical Merkle root under the Realm's verified digest suite.
pub fn compute_state_root(
    view: GovernanceView<'_>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let mut leaves = state_root_leaves(view, digest_suite)?;
    // Sort by cell wire string ascending (Unicode code point).
    leaves.sort_by(|a, b| a.0.cmp(&b.0));

    seal_merkle_root_from_leaf_hashes(
        leaves.into_iter().map(|(_, hash)| hash).collect(),
        digest_suite,
    )
}

/// A frontier-comparison digest over cell **values**, for any lattice.
///
/// This is deliberately **not** the §6.2.1 governance `state_root`, and callers
/// must not present it as one. Two issuers comparing a filtered projection —
/// `policy_frontier_digest`, an actor-scoped membership frontier — need a
/// stable structured hash over the values they both hold; they do not hold each
/// other's write identities, and the domains those digests cover are defined by
/// their own sections (`realm-and-space.md` §3.6 for the policy frontier).
///
/// It reuses the same leaf preimage and Merkle combination so one implementation
/// serves both, and it skips `⊥` cells for the same reason `state_root` does:
/// a conflicted cell has no single value to compare.
pub fn value_frontier_digest(
    cells: &BTreeMap<CellRef, CellState>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    let mut leaves: Vec<(String, [u8; 32])> = Vec::with_capacity(cells.len());
    for (cell, state) in cells {
        if matches!(state, CellState::Bottom(_)) {
            continue;
        }
        leaves.push((
            cell.as_str().to_owned(),
            leaf_hash(cell, state, digest_suite)?,
        ));
    }
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    seal_merkle_root_from_leaf_hashes(
        leaves.into_iter().map(|(_, hash)| hash).collect(),
        digest_suite,
    )
}

/// The unsorted `(cell_wire, leaf_hash)` member set of one joined view.
///
/// Membership follows §6.2.1: a `cas_register` cell is a member iff it has at
/// least one active head, every other cell is a member iff it resolved to a
/// non-`⊥` value.
fn state_root_leaves(
    view: GovernanceView<'_>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<(String, [u8; 32])>, crate::WireError> {
    let mut leaves: Vec<(String, [u8; 32])> =
        Vec::with_capacity(view.cells.len() + view.cas_heads.len());
    for (cell, heads) in view.cas_heads {
        if heads.is_empty() {
            // "No entry" and "no head" are the same statement: an unwritten cell
            // is not a member. Accepting an empty vector here would make the
            // root depend on whether a producer chose to emit the key.
            continue;
        }
        leaves.push((
            cell.as_str().to_owned(),
            cas_leaf_hash(cell, heads, digest_suite)?,
        ));
    }
    for (cell, state) in view.cells {
        if view.cas_heads.contains_key(cell) {
            continue;
        }
        if arkret_wire::is_registered_causal_register_cell(cell.as_str()) {
            return Err(crate::WireError::Protocol(format!(
                "causal register cell {} resolved to a state without its active heads; \
                 §6.2.1 needs the head set to build its leaf",
                cell.as_str()
            )));
        }
        // §6.2.1: a written causal register keeps its leaf even in `⊥`, and it
        // was handled above out of its head map. Every other `bottom=reject`
        // lattice stays out — its `⊥` is exposed through the failure state and
        // the §9.5 recovery witness instead.
        if matches!(state, CellState::Bottom(_)) {
            continue;
        }
        leaves.push((
            cell.as_str().to_owned(),
            leaf_hash(cell, state, digest_suite)?,
        ));
    }
    Ok(leaves)
}

/// The §6.2.1 leaf of one written `cas_register` cell.
///
/// `heads` is serialized as `{"event_id":…,"value":…}` entries ordered by the
/// decoded 33-octet `event_id` token, which is the order
/// [`crate::lattice::cas_register::cas_heads`] already produces. The identity is
/// recovered from the op's `event_digest` losslessly, so the leaf never depends
/// on a second stored spelling of the same identity.
pub fn cas_leaf_hash(
    cell: &CellRef,
    heads: &[CasHead],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<[u8; 32], crate::WireError> {
    leaf_hash_from_state_object(cell, cas_leaf_state_object(cell, heads)?, digest_suite)
}

/// The `{"heads":[…]}` half of a causal-register leaf.
fn cas_leaf_state_object(cell: &CellRef, heads: &[CasHead]) -> Result<Value, crate::WireError> {
    let mut entries = Vec::with_capacity(heads.len());
    for head in heads {
        let event_id = arkret_wire::EventId::from_event_digest(&head.move_id).map_err(|error| {
            crate::WireError::Protocol(format!(
                "causal register head {} of {} is not a recoverable Event identity: {error}",
                head.move_id.as_str(),
                cell.as_str()
            ))
        })?;
        entries.push(json!({
            "event_id": event_id.as_str(),
            "value": head.value,
        }));
    }
    Ok(json!({ "heads": entries }))
}

/// The exact leaf preimage `state_root` hashes for one member cell.
///
/// Every producer of a portable branch — the MLS governance frontier witness,
/// the invite capability bundle — has to ship the bytes the root actually
/// committed to. A causal register's leaf is built from its active head set
/// (§6.2.1), so spelling it `{"value":…}` commits to a leaf the `state_root`
/// never contained and the receiver's digest check fails with nothing to
/// point at. One definition here, used by both.
pub fn state_leaf_canonical_preimage(
    view: GovernanceView<'_>,
    cell: &CellRef,
) -> Result<Vec<u8>, crate::WireError> {
    let state_object = state_leaf_state_object(view, cell)?;
    arkret_canonical::canonical_json_bytes(&json!({
        "cell": cell.as_str(),
        "state": state_object,
    }))
    .map_err(Into::into)
}

/// The value a causal-register leaf's head set resolves to.
///
/// Mirrors `cas_register::join`: identical head values collapse to that value,
/// and any disagreement is `Bottom`, which has no single value to publish. A
/// receiver holding only the portable leaf has no op log to re-join, so this is
/// the one rule it can apply to the bytes it was given.
pub fn causal_register_leaf_value(heads: &Value) -> Result<Value, crate::WireError> {
    let entries = heads.as_array().ok_or_else(|| {
        crate::WireError::Protocol("state leaf heads must be an array".to_owned())
    })?;
    let mut resolved: Option<&Value> = None;
    for entry in entries {
        let value = entry.get("value").ok_or_else(|| {
            crate::WireError::Protocol("state leaf head carries no value".to_owned())
        })?;
        match resolved {
            Some(existing) if existing != value => {
                return Err(crate::WireError::Protocol(
                    "state leaf heads disagree; the cell is Bottom and has no single value"
                        .to_owned(),
                ));
            }
            _ => resolved = Some(value),
        }
    }
    resolved.cloned().ok_or_else(|| {
        crate::WireError::Protocol(
            "state leaf heads are empty; the cell is not a state_root member".to_owned(),
        )
    })
}

/// The `state` half of a member cell's leaf, in the same shape and by the same
/// membership rule as [`state_root_leaves`].
fn state_leaf_state_object(
    view: GovernanceView<'_>,
    cell: &CellRef,
) -> Result<Value, crate::WireError> {
    if let Some(heads) = view.cas_heads.get(cell) {
        if heads.is_empty() {
            return Err(crate::WireError::Protocol(format!(
                "causal register cell {} has no active head and is not a state_root member",
                cell.as_str()
            )));
        }
        return cas_leaf_state_object(cell, heads);
    }
    if arkret_wire::is_registered_causal_register_cell(cell.as_str()) {
        return Err(crate::WireError::Protocol(format!(
            "causal register cell {} resolved to a state without its active heads; \
             §6.2.1 needs the head set to build its leaf",
            cell.as_str()
        )));
    }
    match view.cells.get(cell) {
        Some(CellState::Value(value)) => Ok(json!({ "value": value })),
        _ => Err(crate::WireError::Protocol(format!(
            "cell {} has no concrete value and is not a state_root member",
            cell.as_str()
        ))),
    }
}

/// Build the portable Merkle branch for `target_cell` in a resolved state map.
///
/// The returned `leaf_index` and `leaf_count` are required because sibling
/// hashes alone cannot encode left/right orientation or odd-tail promotion.
pub fn state_inclusion_proof(
    view: GovernanceView<'_>,
    target_cell: &CellRef,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<StateInclusionProof, crate::WireError> {
    let mut leaves = state_root_leaves(view, digest_suite)?;
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut index = leaves
        .iter()
        .position(|(cell, _)| cell == target_cell.as_str())
        .ok_or_else(|| {
            crate::WireError::Protocol(format!(
                "state inclusion target {} is absent or bottom",
                target_cell.as_str()
            ))
        })?;
    let leaf_count = u64::try_from(leaves.len())
        .map_err(|_| crate::WireError::Protocol("state leaf count exceeds u64".to_owned()))?;
    let leaf_index = u64::try_from(index)
        .map_err(|_| crate::WireError::Protocol("state leaf index exceeds u64".to_owned()))?;
    let leaf_digest = hash_from_raw(leaves[index].1, digest_suite)?;
    let mut layer = leaves.into_iter().map(|(_, hash)| hash).collect::<Vec<_>>();
    let mut branch = Vec::new();
    while layer.len() > 1 {
        if index % 2 == 0 {
            if index + 1 < layer.len() {
                branch.push(hash_from_raw(layer[index + 1], digest_suite)?);
            }
        } else {
            branch.push(hash_from_raw(layer[index - 1], digest_suite)?);
        }
        layer = next_seal_merkle_layer(&layer, digest_suite);
        index /= 2;
    }
    Ok(StateInclusionProof {
        leaf_digest,
        leaf_index,
        leaf_count,
        inclusion_proof: branch,
    })
}

/// Verify a portable state-cell branch against a Seal `state_root`.
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

/// Compute the canonical portable leaf digest for one non-bottom state cell.
///
/// Evidence consumers must recompute this value from the disclosed
/// `(cell_ref, cell_value)` before verifying its Merkle branch. Accepting a
/// caller-supplied leaf digest without this binding would allow a valid branch
/// to be paired with unrelated disclosed state.
pub fn state_value_leaf_digest(
    cell: &CellRef,
    value: &serde_json::Value,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    hash_from_raw(
        leaf_hash(cell, &CellState::Value(value.clone()), digest_suite)?,
        digest_suite,
    )
}

/// Compute a Seal-family Merkle root from already ordered raw leaf data.
///
/// Shared by state/control-event roots and federation frontier commitments.
/// Each input is un-hashed leaf data in the domain's required order. This
/// function adds the leaf prefix, promotes odd tails without duplication,
/// and uses H(empty) for an empty tree; it does not sort or deduplicate inputs.
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

/// Build an RFC 6962 audit path for one leaf in the shared Seal Merkle
/// family. `leaf_data` must already be in the domain-defined canonical order.
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

/// Verify an audit path whose public leaf value is the raw domain leaf data,
/// rather than the already domain-separated leaf hash.
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
    let root = layer[0];
    Hash::new(format!("{}:{}", digest_suite.as_str(), hex::encode(root)))
        .map_err(|e| crate::WireError::Protocol(format!("invalid state root: {e}")))
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
    canonical::digest_bytes_from_slices(digest_suite, &[&[NODE_PREFIX][..], &left[..], &right[..]])
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

/// Compute the leaf hash for a single cell.
///
/// Public for use by selective Merkle-branch updaters and tests that
/// want to verify per-cell encoding without running the whole tree.
pub fn leaf_hash(
    cell: &CellRef,
    state: &CellState,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<[u8; 32], crate::WireError> {
    let state_object = match state {
        CellState::Value(v) => json!({ "value": v }),
        CellState::Bottom(_) => {
            return Err(crate::WireError::Protocol(
                "bottom control cells do not have state_root leaves".to_owned(),
            ));
        }
    };
    leaf_hash_from_state_object(cell, state_object, digest_suite)
}

/// Hash one `{"cell":…,"state":…}` leaf preimage into its Realm-suite wire form.
///
/// This is the single leaf definition the Seal `state_root` and the snapshot
/// `state_digest` share (`realm-state-snapshot-schema.md` §4): a control cell's snapshot
/// leaf is byte-identical to its `state_root` leaf.
pub fn state_leaf_hash_from_state_object(
    cell: &CellRef,
    state_object: serde_json::Value,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, crate::WireError> {
    hash_from_raw(
        leaf_hash_from_state_object(cell, state_object, digest_suite)?,
        digest_suite,
    )
}

/// Hash one `{"cell":…,"state":…}` leaf preimage.
///
/// Both leaf shapes share this tail, so the `0x00` domain separation and the
/// canonical-JSON encoding have exactly one implementation.
fn leaf_hash_from_state_object(
    cell: &CellRef,
    state_object: serde_json::Value,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<[u8; 32], crate::WireError> {
    let leaf_input = json!({
        "cell": cell.as_str(),
        "state": state_object,
    });
    let bytes = canonical::canonical_json_bytes(&leaf_input)?;
    // Leaf: H(0x00 || leaf_preimage_utf8_bytes) (spec §6.2.2).
    Ok(canonical::digest_bytes_from_slices(
        digest_suite,
        &[&[LEAF_PREFIX][..], &bytes],
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::BottomKind;

    const SUITE: arkret_canonical::DigestSuite = arkret_canonical::DigestSuite::Sha256;

    fn cell(s: &str) -> CellRef {
        CellRef::new(s.to_owned()).unwrap()
    }

    #[test]
    fn empty_map_returns_constant_root() {
        let root =
            compute_state_root(GovernanceView::values_only(&BTreeMap::new()), SUITE).unwrap();
        assert_eq!(root.as_str(), EMPTY_STATE_ROOT);
    }

    #[test]
    fn single_cell_root_equals_leaf_hash() {
        // A non-causal family on purpose: `member.state` is an `fsm` and
        // therefore a causal register (§9.3.1.5), so a values-only view of
        // it is refused rather than hashed with the wrong preimage. The
        // single-leaf property this pins is about the tree, not the cell.
        let mut map = BTreeMap::new();
        map.insert(
            cell("ak:cell:ak.component.capability.grant.v1:ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX"),
            CellState::Value(json!([])),
        );
        let root = compute_state_root(GovernanceView::values_only(&map), SUITE).unwrap();
        // Format must match ak:hash:sha256: prefix.
        assert!(root.as_str().starts_with("sha256:"));
        // Single-leaf root MUST equal the leaf hash directly (per spec §6.2.2).
        let leaf = leaf_hash(
            &cell("ak:cell:ak.component.capability.grant.v1:ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX"),
            &CellState::Value(json!([])),
            SUITE,
        )
        .unwrap();
        let leaf_hex: String = leaf.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(root.as_str(), format!("sha256:{leaf_hex}"));
    }

    #[test]
    fn portable_value_leaf_digest_binds_cell_and_value() {
        let cell = cell("ak:cell:ak.component.member.state.v1:did.web.alice.example");
        let value = json!({"accepted_event_id": "ak:event:one"});
        let digest = state_value_leaf_digest(&cell, &value, SUITE).unwrap();
        assert_eq!(
            digest,
            hash_from_raw(
                leaf_hash(&cell, &CellState::Value(value), SUITE).unwrap(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            state_value_leaf_digest(&cell, &json!({"accepted_event_id": "ak:event:two"}), SUITE,)
                .unwrap()
        );
    }

    #[test]
    fn deterministic_across_insertion_order() {
        // Map order doesn't affect output because we sort by cell wire.
        let mut a = BTreeMap::new();
        a.insert(
            cell("ak:cell:ak.component.test.state_x.v1:1"),
            CellState::Value(json!(1)),
        );
        a.insert(
            cell("ak:cell:ak.component.test.state_y.v1:2"),
            CellState::Value(json!(2)),
        );
        let mut b = BTreeMap::new();
        b.insert(
            cell("ak:cell:ak.component.test.state_y.v1:2"),
            CellState::Value(json!(2)),
        );
        b.insert(
            cell("ak:cell:ak.component.test.state_x.v1:1"),
            CellState::Value(json!(1)),
        );
        assert_eq!(
            compute_state_root(GovernanceView::values_only(&a), SUITE).unwrap(),
            compute_state_root(GovernanceView::values_only(&b), SUITE).unwrap()
        );
    }

    #[test]
    fn different_values_yield_different_roots() {
        let mut a = BTreeMap::new();
        a.insert(
            cell("ak:cell:ak.component.test.state_x.v1:1"),
            CellState::Value(json!("a")),
        );
        let mut b = BTreeMap::new();
        b.insert(
            cell("ak:cell:ak.component.test.state_x.v1:1"),
            CellState::Value(json!("b")),
        );
        assert_ne!(
            compute_state_root(GovernanceView::values_only(&a), SUITE).unwrap(),
            compute_state_root(GovernanceView::values_only(&b), SUITE).unwrap()
        );
    }

    #[test]
    fn bottom_state_is_excluded_from_root_and_has_no_leaf() {
        let target = cell("ak:cell:ak.component.test.state_x.v1:1");
        let bottom = CellState::Bottom(crate::Bottom::new(
            BottomKind::Conflict,
            vec![target.clone()],
        ));
        let mut cells = BTreeMap::new();
        cells.insert(target.clone(), bottom.clone());

        assert_eq!(
            compute_state_root(GovernanceView::values_only(&cells), SUITE)
                .unwrap()
                .as_str(),
            EMPTY_STATE_ROOT
        );
        assert!(leaf_hash(&target, &bottom, SUITE).is_err());
    }

    #[test]
    fn three_leaf_tree_uses_odd_promotion() {
        // 3 leaves: layer 0 = [A, B, C], layer 1 = [sha256(A||B), C], layer 2 =
        // sha256(layer1[0]||C). Verify the root is computable and not equal to any single
        // leaf.
        let mut m = BTreeMap::new();
        m.insert(
            cell("ak:cell:ak.component.test.state_a.v1:1"),
            CellState::Value(json!("a")),
        );
        m.insert(
            cell("ak:cell:ak.component.test.state_b.v1:2"),
            CellState::Value(json!("b")),
        );
        m.insert(
            cell("ak:cell:ak.component.test.state_c.v1:3"),
            CellState::Value(json!("c")),
        );
        let root = compute_state_root(GovernanceView::values_only(&m), SUITE).unwrap();
        // Must not match any leaf hash.
        let leaf_a = leaf_hash(
            &cell("ak:cell:ak.component.test.state_a.v1:1"),
            &CellState::Value(json!("a")),
            SUITE,
        )
        .unwrap();
        let leaf_a_hex: String = leaf_a.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(root.as_str(), format!("sha256:{leaf_a_hex}"));
    }

    #[test]
    fn inclusion_proof_covers_every_leaf_and_rejects_tampering() {
        let mut cells = BTreeMap::new();
        for (suffix, value) in [
            ("a", "alpha"),
            ("b", "beta"),
            ("c", "gamma"),
            ("d", "delta"),
            ("e", "epsilon"),
        ] {
            cells.insert(
                cell(&format!("ak:cell:ak.component.test.state_{suffix}.v1:1")),
                CellState::Value(json!(value)),
            );
        }
        let root = compute_state_root(GovernanceView::values_only(&cells), SUITE).unwrap();
        for target in cells.keys() {
            let proof =
                state_inclusion_proof(GovernanceView::values_only(&cells), target, SUITE).unwrap();
            assert!(
                verify_state_inclusion_proof(
                    &proof.leaf_digest,
                    proof.leaf_index,
                    proof.leaf_count,
                    &proof.inclusion_proof,
                    &root,
                    SUITE,
                )
                .unwrap()
            );

            let mut wrong_index = proof.clone();
            wrong_index.leaf_index = (wrong_index.leaf_index + 1) % wrong_index.leaf_count;
            assert!(
                !verify_state_inclusion_proof(
                    &wrong_index.leaf_digest,
                    wrong_index.leaf_index,
                    wrong_index.leaf_count,
                    &wrong_index.inclusion_proof,
                    &root,
                    SUITE,
                )
                .unwrap()
            );

            let mut extra_sibling = proof.clone();
            extra_sibling
                .inclusion_proof
                .push(Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap());
            assert!(
                !verify_state_inclusion_proof(
                    &extra_sibling.leaf_digest,
                    extra_sibling.leaf_index,
                    extra_sibling.leaf_count,
                    &extra_sibling.inclusion_proof,
                    &root,
                    SUITE,
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn bottom_kind_does_not_affect_root() {
        let target = cell("ak:cell:ak.component.test.state_x.v1:1");
        let mut conflict = BTreeMap::new();
        conflict.insert(
            target.clone(),
            CellState::Bottom(crate::Bottom::new(
                BottomKind::Conflict,
                vec![target.clone()],
            )),
        );
        let mut schema = BTreeMap::new();
        schema.insert(
            target.clone(),
            CellState::Bottom(crate::Bottom::new(BottomKind::SchemaError, vec![target])),
        );
        assert_eq!(
            compute_state_root(GovernanceView::values_only(&conflict), SUITE).unwrap(),
            compute_state_root(GovernanceView::values_only(&schema), SUITE).unwrap()
        );
    }

    #[test]
    fn blake3_root_and_branch_use_the_selected_suite() {
        let mut cells = BTreeMap::new();
        let first = cell("ak:cell:ak.component.test.state_a.v1:1");
        let second = cell("ak:cell:ak.component.test.state_b.v1:2");
        cells.insert(first.clone(), CellState::Value(json!("alpha")));
        cells.insert(second, CellState::Value(json!("beta")));

        let root = compute_state_root(
            GovernanceView::values_only(&cells),
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap();
        assert!(root.as_str().starts_with("blake3:"));
        let proof = state_inclusion_proof(
            GovernanceView::values_only(&cells),
            &first,
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap();
        assert!(
            verify_state_inclusion_proof(
                &proof.leaf_digest,
                proof.leaf_index,
                proof.leaf_count,
                &proof.inclusion_proof,
                &root,
                arkret_canonical::DigestSuite::Blake3,
            )
            .unwrap()
        );
        assert!(
            verify_state_inclusion_proof(
                &proof.leaf_digest,
                proof.leaf_index,
                proof.leaf_count,
                &proof.inclusion_proof,
                &root,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
    }
}
