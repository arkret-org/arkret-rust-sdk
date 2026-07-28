//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::event_envelope::Event;
use serde_json::Value;
use thiserror::Error;

use super::state_root::{compute_state_root, seal_merkle_root_from_leaf_data};
use super::store::{CellRegistry, CellStore, ControlEventStore, SealStore};
use super::verify::verify_control_move;
use crate::lattice::ordered_log::IssuedOp;
use crate::lattice::{CellState, SealedOp};
use crate::{CellRef, Hash, ProjectedCellWrite, RealmId, Seal, SealId, canonical};

#[derive(Clone, Debug)]
pub struct SealEffect {
    pub seal: SealId,
    pub accepted_event_digests: Vec<Hash>,
    pub rejected_events: Vec<(Hash, String)>,
    pub post_state_root: Hash,
}

#[derive(Debug, Error)]
pub enum SealReject {
    #[error("Seal structural / signature error: {0}")]
    Structural(String),

    #[error("Seal predecessor_refs contain unknown ids")]
    UnknownPredecessor,

    #[error("Seal.delta contains an event already covered by a predecessor")]
    DeltaAlreadyCovered,

    #[error("Control Event {event_digest} referenced in delta but not in store")]
    MissingControlEvent { event_digest: String },

    #[error("Control Move {event_digest} referenced in delta failed verification: {reason}")]
    ControlMoveRejected {
        event_digest: String,
        reason: String,
    },

    #[error("Control Move {event_digest} carries no seal_basis")]
    MissingSealBasis { event_digest: String },

    #[error(
        "Control Move {event_digest} seal_basis leaf {leaf} is outside the receiving Seal's \
         predecessor closure"
    )]
    SealBasisOutsideClosure { event_digest: String, leaf: String },

    #[error(
        "Control Move {event_digest} declared seal_basis.{field} {declared} does not match the \
         leaves view {recomputed}"
    )]
    SealBasisRootMismatch {
        event_digest: String,
        field: &'static str,
        declared: String,
        recomputed: String,
    },

    #[error("declared control_event_set_root {declared} does not match recomputed {recomputed}")]
    ControlEventSetRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("covered_event_digests does not equal predecessor coverage plus delta")]
    CoveredSetMismatch,

    #[error("declared state_root {declared} does not match recomputed {recomputed}")]
    StateRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("store error: {0}")]
    Store(String),
}

impl From<super::store::StoreError> for SealReject {
    fn from(e: super::store::StoreError) -> Self {
        SealReject::Store(e.to_string())
    }
}

/// Apply one Seal per `event-auth-state-resolution.md` §6.3.
///
/// `verify_proofs` and `project_writes` are injected for the same reasons
/// [`verify_control_move`] takes them: signature verification lives in
/// `arkret-signatures`, and the registry-driven projection evaluator lives in
/// `arkret-schema`, which this crate may not depend on. `project_writes` is
/// the *only* source of cell targets and lattice operations — step 10's
/// "atomically apply the reducer writes derived from kind + payload".
pub fn apply_seal<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String> + Copy,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    seal.validate_id()
        .map_err(|e| SealReject::Structural(format!("id: {e}")))?;
    seal.validate_structural()
        .map_err(|e| SealReject::Structural(e.to_string()))?;
    if !seals.predecessors_known(&seal.predecessor_refs)? {
        return Err(SealReject::UnknownPredecessor);
    }

    let pred_covered = union_predecessor_covered_events(&seal.predecessor_refs, seals)?;
    if seal.delta.iter().any(|m| pred_covered.contains(m)) {
        return Err(SealReject::DeltaAlreadyCovered);
    }

    let mut covered = pred_covered.clone();
    covered.extend(seal.delta.iter().cloned());
    if !seal.covered_event_digests.is_empty() {
        let declared: BTreeSet<Hash> = seal.covered_event_digests.iter().cloned().collect();
        if declared != covered {
            return Err(SealReject::CoveredSetMismatch);
        }
    }
    let recomputed_control_root = control_event_set_root(&covered)?;
    if recomputed_control_root.as_str() != seal.control_event_set_root.as_str() {
        return Err(SealReject::ControlEventSetRootMismatch {
            declared: seal.control_event_set_root.as_str().to_owned(),
            recomputed: recomputed_control_root.as_str().to_owned(),
        });
    }

    // The baseline every Control Move in this batch is evaluated against is
    // frozen at the predecessor view: same-batch writes MUST NOT advance a
    // later Move's precondition basis (§6.3.1 frozen-predecessor rule).
    let pre_state =
        effective_state_for_covered_events(&pred_covered, &seal.realm_id, cells, registry)?;
    let pred_closure = predecessor_seal_closure(&seal.predecessor_refs, seals)?;

    let mut new_events: Vec<(Hash, Event)> = Vec::with_capacity(seal.delta.len());
    for digest in &seal.delta {
        let event = events
            .get(digest)?
            .ok_or_else(|| SealReject::MissingControlEvent {
                event_digest: digest.as_str().to_owned(),
            })?;
        new_events.push((digest.clone(), event));
    }
    let ordered = deterministic_order(new_events);

    let mut accepted: Vec<(Hash, Event, Vec<crate::ProjectionEffect>)> =
        Vec::with_capacity(ordered.len());
    for (digest, event) in ordered {
        verify_seal_basis(
            &digest,
            &event,
            &pred_closure,
            &seal.realm_id,
            seals,
            cells,
            registry,
        )?;
        match verify_control_move(
            &event,
            &seal.realm_id,
            &pre_state,
            registry,
            verify_proofs,
            project_writes,
        ) {
            Ok(effects) => accepted.push((digest, event, effects)),
            Err(reject) => {
                return Err(SealReject::ControlMoveRejected {
                    event_digest: digest.as_str().to_owned(),
                    reason: reject.to_string(),
                });
            }
        }
    }

    let mut new_ops: Vec<(CellRef, IssuedOp)> = Vec::new();
    for (digest, event, effects) in &accepted {
        for effect in effects {
            // The actor travels with the op so ordered-log slots stay keyed by
            // the real actor rather than a synthetic one (9.3.1).
            new_ops.push((
                effect.cell.clone(),
                IssuedOp {
                    issuer: event.actor_id.clone(),
                    op: SealedOp::new(digest.clone(), effect.op.clone()),
                },
            ));
        }
    }
    cells.append_sealed_effects(&seal.realm_id, &seal.id, &new_ops)?;

    let post_state = effective_state_for_covered_events(&covered, &seal.realm_id, cells, registry)?;
    let recomputed_state = compute_state_root(&post_state)
        .map_err(|e| SealReject::Store(format!("state_root recompute failed: {e}")))?;
    if recomputed_state.as_str() != seal.state_root.as_str() {
        cells.rollback_seal(&seal.realm_id, &seal.id)?;
        return Err(SealReject::StateRootMismatch {
            declared: seal.state_root.as_str().to_owned(),
            recomputed: recomputed_state.as_str().to_owned(),
        });
    }

    seals.put(seal)?;
    for (digest, ..) in &accepted {
        events.mark_sealed(digest, &seal.id)?;
    }

    Ok(SealEffect {
        seal: seal.id.clone(),
        accepted_event_digests: accepted.iter().map(|(digest, ..)| digest.clone()).collect(),
        rejected_events: Vec::new(),
        post_state_root: recomputed_state,
    })
}

/// §5.1 steps 2-4: the Control Move's `seal_basis` must name only Seals
/// inside the receiving Seal's predecessor closure, and its two declared
/// roots must equal the roots the receiver recomputes over that leaf view.
///
/// This is split out of [`verify_control_move`] because it is the only part
/// of §5.1 that needs the Seal DAG; the rest is a pure function of the Event
/// and the frozen pre-state.
pub fn verify_seal_basis(
    event_digest: &Hash,
    event: &Event,
    predecessor_closure: &BTreeSet<SealId>,
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<(), SealReject> {
    let basis = event
        .seal_basis
        .as_ref()
        .ok_or_else(|| SealReject::MissingSealBasis {
            event_digest: event_digest.as_str().to_owned(),
        })?;
    for leaf in &basis.leaves {
        if !predecessor_closure.contains(leaf) {
            return Err(SealReject::SealBasisOutsideClosure {
                event_digest: event_digest.as_str().to_owned(),
                leaf: leaf.as_str().to_owned(),
            });
        }
    }
    let view = effective_seal_view(&basis.leaves, realm_id, seals, cells, registry)?;
    if view.control_event_set_root != basis.control_event_set_root {
        return Err(SealReject::SealBasisRootMismatch {
            event_digest: event_digest.as_str().to_owned(),
            field: "control_event_set_root",
            declared: basis.control_event_set_root.as_str().to_owned(),
            recomputed: view.control_event_set_root.as_str().to_owned(),
        });
    }
    if view.state_root != basis.state_root {
        return Err(SealReject::SealBasisRootMismatch {
            event_digest: event_digest.as_str().to_owned(),
            field: "state_root",
            declared: basis.state_root.as_str().to_owned(),
            recomputed: view.state_root.as_str().to_owned(),
        });
    }
    Ok(())
}

/// Every Seal reachable from `predecessor_refs`, the roots included.
///
/// §6.3 step 5 scopes "already sealed" and §5.1 step 2 scopes an admissible
/// `seal_basis` leaf to exactly this set — never to the receiver's own global
/// accepted-Seal set, which would make acceptance depend on leaf arrival
/// order.
pub fn predecessor_seal_closure(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<SealId>, SealReject> {
    let mut out = BTreeSet::new();
    let mut queue: Vec<SealId> = predecessor_refs.to_vec();
    while let Some(id) = queue.pop() {
        if !out.insert(id.clone()) {
            continue;
        }
        let seal = seals
            .get(&id)?
            .ok_or_else(|| SealReject::Store(format!("predecessor {id} not in store")))?;
        queue.extend(seal.predecessor_refs);
    }
    Ok(out)
}

pub fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<EffectiveSealView, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let union_proof = leaf_union_proof(&sorted, seals)?;
    let covered = union_covered_from_proof(&union_proof);
    let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered)?;
    let post_state = effective_state_at(&sorted, realm_id, seals, cells, registry)?;
    let state_root = compute_state_root(&post_state)
        .map_err(|e| SealReject::Store(format!("state_root: {e}")))?;
    let view_hash = joined_control_view_hash(
        &sorted,
        &covered_event_digests,
        &control_event_set_root,
        &state_root,
    )?;

    Ok(EffectiveSealView {
        predecessor_refs: sorted,
        covered_event_digests,
        control_event_set_root,
        state_root,
        union_proof,
        view_hash,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSealView {
    pub predecessor_refs: Vec<SealId>,
    pub covered_event_digests: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub union_proof: Vec<SealLeafUnionProof>,
    pub view_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLeafUnionProof {
    pub leaf: SealId,
    pub covered_event_digests: Vec<Hash>,
    pub control_event_set_root: Hash,
}

pub fn union_predecessor_covered_events(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<Hash>, SealReject> {
    let mut out = BTreeSet::new();
    for predecessor in predecessor_refs {
        collect_covered_events(predecessor, seals, &mut out)?;
    }
    Ok(out)
}

pub fn leaf_union_proof(
    leaves: &[SealId],
    seals: &dyn SealStore,
) -> Result<Vec<SealLeafUnionProof>, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    sorted
        .into_iter()
        .map(|leaf| {
            let mut covered = BTreeSet::new();
            collect_covered_events(&leaf, seals, &mut covered)?;
            let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
            let control_event_set_root = control_event_set_root(&covered)?;
            Ok(SealLeafUnionProof {
                leaf,
                covered_event_digests,
                control_event_set_root,
            })
        })
        .collect()
}

fn union_covered_from_proof(proof: &[SealLeafUnionProof]) -> BTreeSet<Hash> {
    proof
        .iter()
        .flat_map(|leaf| leaf.covered_event_digests.iter().cloned())
        .collect()
}

fn collect_covered_events(
    seal_id: &SealId,
    seals: &dyn SealStore,
    out: &mut BTreeSet<Hash>,
) -> Result<(), SealReject> {
    let seal = seals
        .get(seal_id)?
        .ok_or_else(|| SealReject::Store(format!("predecessor {seal_id} not in store")))?;
    if !seal.covered_event_digests.is_empty() {
        out.extend(seal.covered_event_digests);
        return Ok(());
    }
    for predecessor in &seal.predecessor_refs {
        collect_covered_events(predecessor, seals, out)?;
    }
    out.extend(seal.delta);
    Ok(())
}

pub fn control_event_set_root(covered: &BTreeSet<Hash>) -> Result<Hash, SealReject> {
    let leaves: Result<Vec<Vec<u8>>, SealReject> = covered
        .iter()
        .map(|m| {
            let digest = m.as_str().strip_prefix("sha256:").ok_or_else(|| {
                SealReject::Structural(format!("unsupported control event digest suite: {m}"))
            })?;
            hex::decode(digest).map_err(|e| {
                SealReject::Structural(format!("invalid control event digest {m}: {e}"))
            })
        })
        .collect();
    seal_merkle_root_from_leaf_data(&leaves?)
        .map_err(|e| SealReject::Store(format!("control_event_set_root: {e}")))
}

#[derive(serde::Serialize)]
struct CompletenessLeaf<'a> {
    actor_id: &'a arkret_wire::Did,
    from_seq: u64,
    to_seq: u64,
    event_digests: Vec<&'a Hash>,
}

/// Compute the Seal `completeness_root` from the listed Control Events.
///
/// The caller supplies the exact cumulative covered set. Every covered digest
/// must resolve to exactly one Event; extra Events are ignored.
pub fn control_event_completeness_root(
    events: &[Event],
    covered: &BTreeSet<Hash>,
) -> Result<Hash, SealReject> {
    let mut by_actor = BTreeMap::<arkret_wire::Did, Vec<(u64, Hash)>>::new();
    let mut resolved = BTreeSet::new();
    for event in events {
        let digest = Hash::new(event.event_digest().map_err(|error| {
            SealReject::Structural(format!("Control Event digest failed: {error}"))
        })?)
        .map_err(|error| {
            SealReject::Structural(format!("Control Event digest is invalid: {error}"))
        })?;
        if !covered.contains(&digest) {
            continue;
        }
        if !resolved.insert(digest.clone()) {
            return Err(SealReject::Structural(
                "duplicate listed Control Event digest".to_owned(),
            ));
        }
        by_actor
            .entry(event.actor_id.clone())
            .or_default()
            .push((event.actor_seq, digest));
    }
    if &resolved != covered {
        return Err(SealReject::Structural(
            "Seal coverage contains an unresolved Control Event digest".to_owned(),
        ));
    }

    let mut leaf_data = Vec::with_capacity(by_actor.len());
    for (actor_id, mut actor_events) in by_actor {
        actor_events.sort_by(|left, right| left.cmp(right));
        let from_seq = actor_events
            .first()
            .map(|(sequence, _)| *sequence)
            .expect("actor group is non-empty");
        let to_seq = actor_events
            .last()
            .map(|(sequence, _)| *sequence)
            .expect("actor group is non-empty");
        let leaf = CompletenessLeaf {
            actor_id: &actor_id,
            from_seq,
            to_seq,
            event_digests: actor_events.iter().map(|(_, digest)| digest).collect(),
        };
        leaf_data.push(
            arkret_canonical::canonical_json_bytes(&leaf).map_err(|error| {
                SealReject::Structural(format!("completeness leaf encoding failed: {error}"))
            })?,
        );
    }
    seal_merkle_root_from_leaf_data(&leaf_data)
        .map_err(|error| SealReject::Store(format!("completeness_root: {error}")))
}

pub fn effective_state_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals)?;
    effective_state_for_covered_events(&covered, realm_id, cells, registry)
}

fn effective_state_for_covered_events(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(realm_id)? {
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
        out.insert(
            cell.clone(),
            join_cell_seal_batches(
                binding.lattice.as_ref(),
                &cell,
                &batches.into_iter().map(|(_, ops)| ops).collect::<Vec<_>>(),
            ),
        );
    }
    Ok(out)
}

/// Linearize one Seal's `delta[]` per §6.3.1 steps 2-3.
///
/// Each entry is a Control Move paired with the `event_digest` that
/// `Seal.delta[]` listed it under. Causally ordered Moves come first in
/// causal order; mutually unreachable ones are broken by the canonical
/// `event_digest`-greatest total order. That order fixes the *application*
/// sequence only — it never advances a precondition baseline, which is why
/// `apply_seal` evaluates every Move against one frozen pre-state.
pub fn deterministic_order(mut events: Vec<(Hash, Event)>) -> Vec<(Hash, Event)> {
    let mut out = Vec::with_capacity(events.len());
    while !events.is_empty() {
        let mut ready = Vec::new();
        // Dependencies are named by `event_id`, not by digest: `refs[].id`
        // cites the referenced Event's id, while the batch is keyed by digest.
        let remaining_ids: BTreeSet<String> = events
            .iter()
            .map(|(_, event)| event.event_id.as_str().to_owned())
            .collect();
        let mut blocked = Vec::new();
        for entry in events {
            if causal_dependencies(&entry.1)
                .iter()
                .any(|dep| remaining_ids.contains(dep))
            {
                blocked.push(entry);
            } else {
                ready.push(entry);
            }
        }
        if ready.is_empty() {
            blocked.sort_by(concurrent_control_move_order);
            out.extend(blocked);
            break;
        }
        ready.sort_by(concurrent_control_move_order);
        out.extend(ready);
        events = blocked;
    }
    out
}

fn concurrent_control_move_order(a: &(Hash, Event), b: &(Hash, Event)) -> std::cmp::Ordering {
    b.0.as_str()
        .cmp(a.0.as_str())
        .then_with(|| a.1.hlc.cmp(&b.1.hlc))
        .then_with(|| a.1.actor_id.as_str().cmp(b.1.actor_id.as_str()))
}

fn causal_dependencies(event: &Event) -> Vec<String> {
    event
        .prev_refs
        .iter()
        .map(|id| id.as_str().to_owned())
        .chain(
            event
                .refs
                .iter()
                .filter(|reference| {
                    matches!(
                        reference.role.as_str(),
                        "after" | "parent_event" | "recovery_capability"
                    )
                })
                .map(|reference| reference.id.clone()),
        )
        .collect()
}

fn joined_control_view_hash(
    leaves: &[SealId],
    covered_event_digests: &[Hash],
    control_event_set_root: &Hash,
    state_root: &Hash,
) -> Result<Hash, SealReject> {
    let json = serde_json::json!({
        "schema": "ak.schema.joined_control_view.v1",
        "leaves": leaves.iter().map(|leaf| leaf.as_str()).collect::<Vec<_>>(),
        "covered_event_digests": covered_event_digests
            .iter()
            .map(|event| event.as_str())
            .collect::<Vec<_>>(),
        "control_event_set_root": control_event_set_root.as_str(),
        "state_root": state_root.as_str(),
    });
    let bytes = canonical::canonical_json_bytes(&json)
        .map_err(|e| SealReject::Store(format!("joined_control_view_hash: {e}")))?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| SealReject::Structural(format!("invalid joined control view hash: {e}")))
}

pub fn view_hash(leaves: &[SealId]) -> Result<Hash, crate::Error> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| crate::Error::Protocol(format!("invalid view_hash: {e}")))
}

#[cfg(test)]
mod tests {
    /// Attach a fixed issuer to a sealed op. These fixtures exercise
    /// non-ordered-log lattices, where the issuer is carried but unused.
    fn issued(op: SealedOp) -> IssuedOp {
        IssuedOp {
            issuer: Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            op,
        }
    }

    use arkret_wire::Proof;
    use arkret_wire::event_envelope::{EventRef, ScopeRef};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::lattice::SealedOp;
    use crate::state::store::memory::{
        MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
    };
    use crate::state::store::{CellStore, ControlEventStore, SealStore, control_event_digest};
    use crate::{
        Did, Event, EventId, EventRequirements, Hlc, LatticeOp, LatticeOpType, NotarySig,
        PayloadSignature, ProjectedOp, SealBasis, SealKind,
    };

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn member_cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    /// A Control Move Event. `actor_seq` keeps siblings distinct so each one
    /// hashes to its own `event_digest`.
    fn control_move(
        actor_seq: u64,
        basis: SealBasis,
        prev_refs: Vec<EventId>,
        refs: Vec<EventRef>,
    ) -> Event {
        let mut event = Event {
            event_id: EventId::new(format!("ak:event:0196419b-0000-7000-8000-{actor_seq:012}"))
                .unwrap(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq,
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Some(Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap()),
            prev_refs,
            refs,
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: Some(basis),
            payload: BTreeMap::from([("state".to_owned(), json!("join"))]),
            redacts: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        };
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#k1".to_owned(),
            event_digest: Hash::new(event.event_digest().unwrap()).unwrap(),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn capability_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak:grant:0196410c-0000-7000-8000-000000000000"
                .to_owned(),
        )
        .unwrap()
    }

    fn add_op(tag: &str, marker: &str) -> LatticeOp {
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

    fn dummy_signature() -> PayloadSignature {
        PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:notary.example#k1".to_owned(),
            payload_digest: hash(0xff),
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
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
            notary_signature: NotarySig::Single(dummy_signature()),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        }
    }

    #[test]
    fn control_event_set_root_uses_seal_merkle_domain_separation() {
        let mut one = BTreeSet::new();
        one.insert(move_id(0x11));
        let mut leaf_input = vec![0x00];
        leaf_input.extend([0x11; 32]);
        let expected_leaf = canonical::sha256_bytes(&leaf_input);
        assert_eq!(
            control_event_set_root(&one).unwrap().as_str(),
            format!("sha256:{}", hex::encode(expected_leaf))
        );

        let mut two = one;
        two.insert(move_id(0x22));
        let mut right_input = vec![0x00];
        right_input.extend([0x22; 32]);
        let expected_right = canonical::sha256_bytes(&right_input);
        let expected_root =
            canonical::sha256_bytes_from_slices(&[&[0x01], &expected_leaf, &expected_right]);
        assert_eq!(
            control_event_set_root(&two).unwrap().as_str(),
            format!("sha256:{}", hex::encode(expected_root))
        );
    }

    fn completeness_event(event_id: &str, actor_id: &str, actor_seq: u64) -> Event {
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": "ak.capability.grant",
            "realm_id": realm(),
            "scope_ref": {"kind": "realm", "realm_id": realm()},
            "actor_id": actor_id,
            "actor_seq": actor_seq,
            "created_at": "2026-07-26T00:00:00.000Z",
            "prev_refs": [],
            "payload": {},
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": format!("{actor_id}#device-1"),
                "event_digest": format!("sha256:{}", "a".repeat(64)),
                "created_at": "2026-07-26T00:00:00.000Z",
                "jws": "a..b"
            }]
        }))
        .unwrap()
    }

    #[test]
    fn completeness_root_is_actor_sequence_enveloped_and_requires_exact_coverage() {
        let alice = completeness_event(
            "ak:event:019f0000-0000-7000-8000-000000000001",
            "did:web:alice.example",
            7,
        );
        let bob = completeness_event(
            "ak:event:019f0000-0000-7000-8000-000000000002",
            "did:web:bob.example",
            3,
        );
        let covered = [&alice, &bob]
            .into_iter()
            .map(|event| Hash::new(event.event_digest().unwrap()).unwrap())
            .collect::<BTreeSet<_>>();
        let forward =
            control_event_completeness_root(&[alice.clone(), bob.clone()], &covered).unwrap();
        let reverse =
            control_event_completeness_root(&[bob.clone(), alice.clone()], &covered).unwrap();
        assert_eq!(forward, reverse);
        assert_ne!(forward, control_event_set_root(&covered).unwrap());
        assert!(control_event_completeness_root(&[alice], &covered).is_err());
    }

    #[test]
    fn effective_state_at_filters_ops_by_seal_coverage() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let cell = capability_cell();
        let move_a = move_id(0xaa);
        let move_b = move_id(0xbb);
        let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
        let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);

        cells
            .append_sealed_effects(
                &realm,
                &seal_a.id,
                &[(
                    cell.clone(),
                    issued(SealedOp::new(move_a, add_op("a", "visible-at-a"))),
                )],
            )
            .unwrap();
        cells
            .append_sealed_effects(
                &realm,
                &seal_b.id,
                &[(
                    cell.clone(),
                    issued(SealedOp::new(move_b, add_op("b", "visible-at-b"))),
                )],
            )
            .unwrap();
        seals.put(&seal_a).unwrap();
        seals.put(&seal_b).unwrap();

        let state_a = effective_state_at(
            std::slice::from_ref(&seal_a.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let value_a = state_a
            .get(&cell)
            .and_then(|state| state.clone().into_value())
            .unwrap();
        assert_eq!(
            value_a,
            json!([{ "tag": "a", "value": { "marker": "visible-at-a" } }])
        );

        let state_b = effective_state_at(
            std::slice::from_ref(&seal_b.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let value_b = state_b
            .get(&cell)
            .and_then(|state| state.clone().into_value())
            .unwrap();
        assert_eq!(
            value_b,
            json!([{ "tag": "b", "value": { "marker": "visible-at-b" } }])
        );
    }

    #[test]
    fn effective_seal_view_is_leaf_order_independent() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let move_a = move_id(0xaa);
        let move_b = move_id(0xbb);
        let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
        let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);
        seals.put(&seal_b).unwrap();
        seals.put(&seal_a).unwrap();

        let first = effective_seal_view(
            &[seal_b.id.clone(), seal_a.id.clone()],
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let second = effective_seal_view(
            &[seal_a.id.clone(), seal_b.id.clone()],
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();

        assert_eq!(first.predecessor_refs, vec![seal_a.id, seal_b.id]);
        assert_eq!(first.covered_event_digests, vec![move_a, move_b]);
        assert_eq!(first.union_proof.len(), 2);
        assert_eq!(first.view_hash, second.view_hash);
        assert_eq!(first.state_root, second.state_root);
    }

    #[test]
    fn deterministic_order_respects_causality_then_digest_desc() {
        // Digests are content-derived, so the fixture picks the causal edge and
        // then asserts against the digests the Events actually hash to.
        let basis = SealBasis {
            leaves: vec![seal_id(0x11)],
            control_event_set_root: hash(0x22),
            state_root: hash(0x33),
        };
        let first = control_move(1, basis.clone(), Vec::new(), Vec::new());
        let second = control_move(2, basis.clone(), Vec::new(), Vec::new());
        let dependent = control_move(
            3,
            basis,
            Vec::new(),
            vec![EventRef::new(first.event_id.as_str(), "after")],
        );
        let entry = |event: &Event| (control_event_digest(event).unwrap(), event.clone());

        let ordered = deterministic_order(vec![entry(&dependent), entry(&second), entry(&first)]);
        let ids: Vec<&str> = ordered
            .iter()
            .map(|(_, event)| event.event_id.as_str())
            .collect();

        // `dependent` cites `first`, so it can only appear once `first` has been
        // emitted; the two independent Moves are ordered by greatest digest.
        assert_eq!(ids[2], dependent.event_id.as_str());
        let (independent_first, independent_second) =
            if entry(&first).0.as_str() > entry(&second).0.as_str() {
                (first.event_id.as_str(), second.event_id.as_str())
            } else {
                (second.event_id.as_str(), first.event_id.as_str())
            };
        assert_eq!(ids[0], independent_first);
        assert_eq!(ids[1], independent_second);
    }

    #[test]
    fn deterministic_order_is_input_permutation_independent() {
        let basis = SealBasis {
            leaves: vec![seal_id(0x11)],
            control_event_set_root: hash(0x22),
            state_root: hash(0x33),
        };
        let entries: Vec<(Hash, Event)> = (1..=3)
            .map(|seq| {
                let event = control_move(seq, basis.clone(), Vec::new(), Vec::new());
                (control_event_digest(&event).unwrap(), event)
            })
            .collect();
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(
            deterministic_order(entries)
                .iter()
                .map(|(digest, _)| digest.clone())
                .collect::<Vec<_>>(),
            deterministic_order(reversed)
                .iter()
                .map(|(digest, _)| digest.clone())
                .collect::<Vec<_>>()
        );
    }

    /// A Seal whose `id` is the hash of its own canonical bytes, so
    /// `apply_seal`'s `validate_id` gate passes.
    fn signed_seal(
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        control_event_set_root: Hash,
        state_root: Hash,
        notary_seq: u64,
    ) -> Seal {
        let mut seal = Seal {
            id: seal_id(0x00),
            realm_id: realm(),
            predecessor_refs,
            delta,
            control_event_set_root,
            state_root,
            completeness_root: hash(0x33),
            notary_seq,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(dummy_signature()),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        };
        seal.id = seal.derive_id().unwrap();
        seal
    }

    fn ok_proofs(_: &Event) -> Result<(), String> {
        Ok(())
    }

    fn join_transition_write(_: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        op.from = Some(json!("invited"));
        op.to = Some(json!("join"));
        Ok(vec![ProjectedCellWrite {
            cell: member_cell(),
            op: ProjectedOp::Direct(op),
        }])
    }

    /// Genesis Seal over an empty covered set, plus the `seal_basis` a
    /// Control Move built on it must declare.
    fn genesis_and_basis() -> (Seal, SealBasis) {
        let empty_control_root = control_event_set_root(&BTreeSet::new()).unwrap();
        let empty_state_root = compute_state_root(&BTreeMap::new()).unwrap();
        let genesis = signed_seal(
            Vec::new(),
            Vec::new(),
            empty_control_root.clone(),
            empty_state_root.clone(),
            1,
        );
        let basis = SealBasis {
            leaves: vec![genesis.id.clone()],
            control_event_set_root: empty_control_root,
            state_root: empty_state_root,
        };
        (genesis, basis)
    }

    #[test]
    fn apply_seal_applies_only_projector_derived_writes() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, basis) = genesis_and_basis();
        seals.put(&genesis).unwrap();

        // The Event names no cell and no lattice op anywhere: the projector is
        // the sole source of the `invited -> join` write applied below.
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event).unwrap();
        events.put_pending(&event).unwrap();

        let covered = BTreeSet::from([digest.clone()]);
        let post_state = BTreeMap::from([(member_cell(), CellState::Value(json!("join")))]);
        let seal = signed_seal(
            vec![genesis.id],
            vec![digest.clone()],
            control_event_set_root(&covered).unwrap(),
            compute_state_root(&post_state).unwrap(),
            2,
        );

        let effect = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap();
        assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
        assert_eq!(effect.post_state_root, seal.state_root);

        let ops = cells.sealed_ops_for_cell(&realm(), &member_cell()).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op.move_id, digest);
        assert_eq!(ops[0].issuer, event.actor_id);
        assert_eq!(
            events.list_sealed(&realm(), None, 10).unwrap()[0].seal,
            seal.id
        );
    }

    #[test]
    fn apply_seal_rejects_a_projection_the_receiver_cannot_evaluate() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, basis) = genesis_and_basis();
        seals.put(&genesis).unwrap();
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event).unwrap();
        events.put_pending(&event).unwrap();

        let covered = BTreeSet::from([digest.clone()]);
        let seal = signed_seal(
            vec![genesis.id],
            vec![digest],
            control_event_set_root(&covered).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            2,
        );

        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            |_: &Event| Err("registry declares no contract for this kind".to_owned()),
        )
        .unwrap_err();
        assert!(matches!(error, SealReject::ControlMoveRejected { .. }));
    }

    #[test]
    fn seal_basis_leaf_outside_the_predecessor_closure_rejects() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, mut basis) = genesis_and_basis();
        seals.put(&genesis).unwrap();
        // A concurrent Seal the receiving Seal does not descend from. Admitting
        // it would make acceptance depend on which leaves this receiver happens
        // to hold (§6.3 concurrent-leaf rule).
        basis.leaves = vec![seal_id(0xee)];
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event).unwrap();
        events.put_pending(&event).unwrap();

        let covered = BTreeSet::from([digest.clone()]);
        let seal = signed_seal(
            vec![genesis.id],
            vec![digest],
            control_event_set_root(&covered).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            2,
        );

        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap_err();
        assert!(matches!(error, SealReject::SealBasisOutsideClosure { .. }));
    }

    #[test]
    fn seal_basis_state_root_mismatch_rejects() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, mut basis) = genesis_and_basis();
        seals.put(&genesis).unwrap();
        basis.state_root = hash(0xbe);
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event).unwrap();
        events.put_pending(&event).unwrap();

        let covered = BTreeSet::from([digest.clone()]);
        let seal = signed_seal(
            vec![genesis.id],
            vec![digest],
            control_event_set_root(&covered).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            2,
        );

        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SealReject::SealBasisRootMismatch {
                field: "state_root",
                ..
            }
        ));
    }

    #[test]
    fn predecessor_seal_closure_is_transitive() {
        let seals = MemorySealStore::default();
        let empty_control_root = control_event_set_root(&BTreeSet::new()).unwrap();
        let empty_state_root = compute_state_root(&BTreeMap::new()).unwrap();
        let genesis = signed_seal(
            Vec::new(),
            Vec::new(),
            empty_control_root.clone(),
            empty_state_root.clone(),
            1,
        );
        let middle = signed_seal(
            vec![genesis.id.clone()],
            Vec::new(),
            empty_control_root,
            empty_state_root,
            2,
        );
        seals.put(&genesis).unwrap();
        seals.put(&middle).unwrap();

        let closure = predecessor_seal_closure(std::slice::from_ref(&middle.id), &seals).unwrap();
        assert_eq!(closure, BTreeSet::from([genesis.id, middle.id]));
    }

    #[test]
    fn effective_state_preserves_cross_seal_fsm_order() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let join_id = move_id(0x01);
        let ban_id = move_id(0xff);
        let seal = materialized_seal(seal_id(0xa1), vec![join_id.clone(), ban_id.clone()]);
        let transition = |from: &str, to: &str| LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!(from)),
            to: Some(json!(to)),
            reason: None,
            issuer_seq: None,
        };

        cells
            .append_sealed_effects(
                &realm,
                &seal.id,
                &[
                    (
                        cell.clone(),
                        issued(SealedOp::new(join_id, transition("invited", "join"))),
                    ),
                    (
                        cell.clone(),
                        issued(SealedOp::new(ban_id, transition("join", "ban"))),
                    ),
                ],
            )
            .unwrap();
        seals.put(&seal).unwrap();

        let state = effective_state_at(
            std::slice::from_ref(&seal.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))));
    }

    #[test]
    fn register_seal_batches_distinguish_successors_from_siblings() {
        let cell = CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap();
        let set = |id, value| {
            issued(SealedOp::new(
                move_id(id),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!(value)),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ))
        };
        let lattice = crate::lattice::CasRegister;

        let sequential = vec![vec![set(1, "open")], vec![set(2, "closed")]];
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &sequential),
            CellState::Value(json!("closed"))
        );

        let siblings = vec![vec![set(3, "open"), set(4, "closed")]];
        assert!(matches!(
            join_cell_seal_batches(&lattice, &cell, &siblings),
            CellState::Bottom(_)
        ));

        let duplicate_siblings = vec![vec![set(5, "closed"), set(6, "closed")]];
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &duplicate_siblings),
            CellState::Value(json!("closed"))
        );
    }
}

/// Join one cell's ops, routing `ordered_log` to its issuer-aware entry point.
///
/// `event-auth-state-resolution.md` §9.3.1 scopes ordered-log sequences to
/// `(effect.cell, actor_id)`, so this lattice cannot be joined through the
/// issuer-free [`Lattice::join`]: that path has no way to separate sub-chains
/// and would stamp a synthetic issuer into the `state_root` leaf.
pub fn join_cell(
    lattice: &dyn crate::lattice::Lattice,
    cell: &CellRef,
    ops: &[IssuedOp],
) -> CellState {
    if lattice.kind() == crate::lattice::LatticeKind::OrderedLog {
        return crate::lattice::OrderedLog.join_with_issuers(cell, ops);
    }
    let sealed: Vec<SealedOp> = ops.iter().map(|issued| issued.op.clone()).collect();
    lattice.join(cell, &sealed)
}

/// Join accepted operations while preserving frozen-predecessor Seal batches.
///
/// Register writes in a successor Seal causally replace the previous head.
/// Multiple writes inside one Seal share one predecessor view and therefore
/// remain sibling heads. Other core lattices consume their full accepted
/// history because their join already models ordered transitions or
/// commutative accumulation.
pub fn join_cell_seal_batches(
    lattice: &dyn crate::lattice::Lattice,
    cell: &CellRef,
    batches: &[Vec<IssuedOp>],
) -> CellState {
    match lattice.kind() {
        crate::lattice::LatticeKind::CasRegister | crate::lattice::LatticeKind::MvRegister => {
            batches
                .iter()
                .rev()
                .find(|ops| !ops.is_empty())
                .map_or_else(
                    || lattice.join(cell, &[]),
                    |ops| join_cell(lattice, cell, ops),
                )
        }
        _ => {
            let ops = batches
                .iter()
                .flat_map(|ops| ops.iter().cloned())
                .collect::<Vec<_>>();
            join_cell(lattice, cell, &ops)
        }
    }
}
