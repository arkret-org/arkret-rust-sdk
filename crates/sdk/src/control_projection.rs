//! Registered security projection at an exact command execution position.

use std::collections::{BTreeMap, BTreeSet};

use arkret_state::ResolvedCellState;
use arkret_wire::{CellRef, Event};

/// Derive writes and the precise additional security read set from staged state.
/// The resolver follows only grants present at this execution position, so
/// later retained Events cannot alter the authority interpretation of history.
pub fn project_control_writes_at_state(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    state: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<arkret_state::ControlProjection, String> {
    fn authority_audit(
        grant_id: &str,
        state: &BTreeMap<CellRef, ResolvedCellState>,
        reads: &std::cell::RefCell<BTreeSet<CellRef>>,
        visiting: &BTreeSet<String>,
    ) -> Option<arkret_schema::CapabilityAuthorityAudit> {
        if visiting.contains(grant_id) {
            return None;
        }
        let cell = CellRef::new(format!(
            "ak:cell:{}:{grant_id}",
            arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1
        ))
        .ok()?;
        reads.borrow_mut().insert(cell.clone());
        let ResolvedCellState::Sequenced(value) = state.get(&cell)? else {
            return None;
        };
        let entries = value.value.as_array()?;
        if entries.len() != 1 {
            return None;
        }
        let body = entries[0].get("value")?;
        let grant = body.get("grant")?;
        let mut visiting = visiting.clone();
        visiting.insert(grant_id.to_owned());
        arkret_schema::derive_capability_authority_audit(grant, &|parent| {
            authority_audit(parent, state, reads, &visiting)
        })
        .ok()
    }
    let reads = std::cell::RefCell::new(BTreeSet::new());
    let mut frozen = arkret_schema::FrozenPreState::new();
    for (cell, value) in state {
        if let Some(value) = value.settled_value() {
            frozen.insert(cell.clone(), value.clone());
        }
    }
    let writes =
        arkret_schema::project_registered_cell_writes_with_pre_state_and_authority_resolver(
            event,
            digest_suite,
            &frozen,
            &|grant_id| authority_audit(grant_id, state, &reads, &BTreeSet::new()),
        )
        .map_err(|error| match error {
            arkret_schema::EventCellContractError::CapabilityAuthorityDependency { .. } => {
                arkret_wire::ReasonCode::DependencyMissing
                    .as_str()
                    .to_owned()
            }
            error => error.reason_code().to_owned(),
        })?;
    let mut security_reads = reads.into_inner();
    security_reads.extend(frozen.read_cells());
    Ok(arkret_state::ControlProjection {
        writes,
        security_reads: security_reads.into_iter().collect(),
    })
}

/// Project registered security writes with identity CAS at the unit boundary.
#[allow(clippy::too_many_arguments)]
pub fn project_control_writes_with_revision_guard(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    execution_state: &BTreeMap<CellRef, ResolvedCellState>,
    signed_basis_state: &BTreeMap<CellRef, ResolvedCellState>,
    unit_entry_state: &BTreeMap<CellRef, ResolvedCellState>,
    registry: &dyn arkret_state::CellStateRegistry,
) -> Result<arkret_state::ControlProjection, arkret_state::ControlMoveReject> {
    arkret_state::project_control_writes_with_revision_guard(
        event,
        digest_suite,
        execution_state,
        signed_basis_state,
        unit_entry_state,
        registry,
        project_control_writes_at_state,
    )
}
