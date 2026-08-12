//! The injected cell-write projector and the derivations every bootstrap
//! branch shares.

use std::collections::{BTreeMap, BTreeSet};

use arkret_state::lattice::ordered_log::{IssuedOp, OrderedLog, ensure_unique_ordered_log_slots};
use arkret_state::{CellRegistry, CellState, LatticeKind, SealedOp, compute_state_root};
use arkret_wire::{
    CellRef, Error, Event, EventKind, Hash, ProjectedCellWrite, ProjectionEffect, RealmId, Result,
};

use crate::{
    REALM_AUTHORITY_ROOT_CELL, REALM_CREATE_CELL, REALM_GENESIS_CELL, REALM_NOTARY_CELL,
    REALM_REDUCER_PROFILE_CELL,
};

/// Registry projection evaluator supplied by the caller, normally
/// `arkret_schema::project_registered_cell_writes`.
///
/// The frozen crate layering keeps `arkret-bootstrap` below `arkret-schema`,
/// so the single evaluator is injected rather than linked — the same shape
/// `arkret_state::verify_control_move` uses. Routing every derivation through
/// one evaluator is also what stops a bootstrap branch from re-growing a
/// private table of what an Event writes: v1 deleted the producer-supplied
/// effect array precisely so that only the reducer contract answers that
/// question (`models/event-and-patch.md` section 2.4.2).
pub type CellWriteProjector<'a> =
    &'a dyn Fn(&Event) -> std::result::Result<Vec<ProjectedCellWrite>, String>;

/// Canonical target set an `ak.realm.create` must derive from the registry.
///
/// Keeping this set in one SDK helper prevents receivers from retaining a
/// stale copy when the registered genesis contract gains another cell.
pub fn expected_realm_create_cells(event: &Event) -> BTreeSet<String> {
    let mut cells = [
        REALM_GENESIS_CELL.to_owned(),
        REALM_CREATE_CELL.to_owned(),
        REALM_NOTARY_CELL.to_owned(),
        REALM_REDUCER_PROFILE_CELL.to_owned(),
        REALM_AUTHORITY_ROOT_CELL.to_owned(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if event
        .payload
        .get("object")
        .and_then(|object| object.get("purpose"))
        .and_then(serde_json::Value::as_str)
        == Some("managed_agent_control")
    {
        cells.insert(format!(
            "ak:cell:{}:{}",
            arkret_wire::CellFamilyId::AGENT_STATUS_V1,
            event.actor_id
        ));
    }
    if event
        .payload
        .get("object")
        .and_then(|object| object.get("initial_resolution"))
        .is_some()
    {
        cells.insert(format!(
            "ak:cell:{}:null",
            arkret_wire::CellFamilyId::IDENTITY_RESOLUTION_V1
        ));
    }
    cells
}

/// Project `event` and require every derived write to be directly applicable.
///
/// `transition_to`, `apply_patch` and `remove_observed` resolve their operand
/// against the frozen pre-state. No bootstrap Event kind registers one, and a
/// genesis unit has no accepted pre-state to read, so meeting one here means
/// the registry moved under this crate: fail closed rather than invent an
/// operand.
pub(crate) fn direct_projection(
    event: &Event,
    project: CellWriteProjector<'_>,
) -> Result<Vec<ProjectionEffect>> {
    project(event)
        .map_err(|error| {
            Error::Protocol(format!(
                "bootstrap cell write projection failed for {}: {error}",
                event.kind.as_str()
            ))
        })?
        .iter()
        .map(|write| {
            write.as_direct().ok_or_else(|| {
                Error::Protocol(format!(
                    "bootstrap cell {} needs a frozen pre-state this path cannot supply",
                    write.cell
                ))
            })
        })
        .collect()
}

/// Assert that an `ak.realm.create` projection lands on its canonical genesis
/// leaf set.
///
/// Self PCR, managed Agent PCR and ordinary Realm producers all reach the
/// receiver through the same contract. The five Realm security-root writes
/// are always present, and an `initial_resolution` adds the registered
/// identity-resolution singleton. Profile, membership and policy cells are separate
/// registered Events in branches whose bootstrap unit includes them. Only the targets are asserted:
/// the lattice ops come from the registered `effect_projection` and restating
/// them here would rebuild the producer-side effect table v1 removed.
pub(crate) fn validate_realm_create_projection(
    event: &Event,
    effects: &[ProjectionEffect],
) -> Result<()> {
    if event.kind != EventKind::RealmCreate {
        return Err(Error::Protocol(
            "realm create projection requires ak.realm.create".to_owned(),
        ));
    }
    let expected = expected_realm_create_cells(event);
    let derived = effects
        .iter()
        .map(|effect| effect.cell.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if effects.len() != expected.len() || derived != expected {
        return Err(Error::Protocol(format!(
            "Realm create does not derive its canonical registered genesis cells: expected {expected:?}, derived {derived:?}"
        )));
    }
    Ok(())
}

/// Join every covered Event's derived cell writes and compute the governance
/// `state_root`.
///
/// Producer-side Seal building and receiver-side recomputation must agree, and
/// under v1 the only statement of what an Event writes is the registered
/// reducer contract evaluated over its signed `kind + payload`. So both sides
/// run the same projection over the same signed bytes; nothing a producer could
/// have written down participates.
pub(crate) fn state_root_from_projection(
    realm_id: &RealmId,
    covered: &[(&Event, Hash)],
    project: CellWriteProjector<'_>,
) -> Result<Hash> {
    let mut ops_by_cell = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
    for (event, move_id) in covered {
        let effects = direct_projection(event, project)?;
        // One Event may claim an ordered-log slot at most once: two writes on
        // the same `(cell, issuer_seq)` would share this Event's digest, so the
        // 4.2 tie-break cannot disambiguate them and it is not a collision
        // between two Events either. Reject before anything reaches a lattice.
        if let Err(conflict) = ensure_unique_ordered_log_slots(&effects) {
            return Err(Error::Protocol(format!(
                "bootstrap Event claims ordered-log slot {}#{} twice",
                conflict.cell, conflict.issuer_seq
            )));
        }
        for effect in &effects {
            ops_by_cell
                .entry(effect.cell.clone())
                .or_default()
                .push(IssuedOp {
                    // 9.3.1 keys the ordered log by the envelope `actor_id`.
                    issuer: event.actor_id.clone(),
                    op: SealedOp::from_projection(move_id.clone(), effect),
                });
        }
    }

    let registry = arkret_lattice_registry::build_sdk_cell_registry();
    let mut joined = BTreeMap::new();
    for (cell, issued) in ops_by_cell {
        // No pre-sort: every lattice join is commutative, and ordering by the
        // typed `move_id` string would imply a tie-break `encoding.md` 4.2
        // forbids (the suite prefix would outrank the digest content).
        let binding = registry
            .resolve(realm_id, &cell)
            .map_err(|error| Error::Protocol(format!("bootstrap cell registry: {error}")))?;
        if binding.lattice.kind() == LatticeKind::OrderedLog {
            // A slot that failed closed (digest collision / unresolvable digest)
            // or that carries issuer equivocation MUST NOT be folded into a
            // state root as if it had one settled value.
            let report = OrderedLog.join_with_issuer_report(&issued);
            if !report.fail_closed.is_empty() {
                return Err(Error::Protocol(format!(
                    "bootstrap cell {cell} ordered-log slot failed closed"
                )));
            }
            if !report.equivocations.is_empty() {
                return Err(Error::Protocol(format!(
                    "bootstrap cell {cell} contains issuer equivocation"
                )));
            }
        }
        let state = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &issued);
        if matches!(state, CellState::Bottom(_)) {
            return Err(Error::Protocol(format!(
                "bootstrap cell {cell} resolved to Bottom"
            )));
        }
        joined.insert(cell, state);
    }
    compute_state_root(&joined)
        .map_err(|error| Error::Protocol(format!("bootstrap state root: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_wire::Event;
    use serde_json::json;

    use super::expected_realm_create_cells;

    #[test]
    fn principal_genesis_expects_the_registered_singleton_resolution_cell() {
        let event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G",
            "kind": "ak.realm.create",
            "scope_ref": {"kind": "realm_genesis"},
            "actor_id": "ak:did_core:webvh:z6mkfixture",
            "actor_seq": 0,
            "created_at": "2026-08-11T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "object": {
                    "initial_resolution": {
                        "full_id": "did:webvh:z6mkfixture:alice.example",
                        "method_history_head": format!("sha256:{}", "a".repeat(64)),
                        "version_id": "1-fixture"
                    }
                }
            },
            "proofs": []
        }))
        .expect("realm create fixture");

        let expected = expected_realm_create_cells(&event);
        assert!(expected.contains("ak:cell:ak.component.identity.resolution.v1:null"));
        assert!(!expected.contains("ak:cell:ak.component.identity.resolution.v1"));
    }
}
