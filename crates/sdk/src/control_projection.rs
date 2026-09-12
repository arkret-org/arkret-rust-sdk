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
    if event.kind == arkret_wire::EventKind::KeyBackupActiveSeries {
        use arkret_models_collaboration::events_payloads::{
            KeyBackupActiveSeries, key_backup_active_series_head,
            validate_key_backup_active_series_transition,
        };
        let mut targets = writes.iter().filter(|write| {
            arkret_wire::CellId::parse(write.cell_id.as_str()).is_ok_and(|cell| {
                cell.component() == arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
            })
        });
        let target = targets
            .next()
            .ok_or_else(|| "key_backup_active_series_schema_violation".to_owned())?;
        if targets.next().is_some() {
            return Err("key_backup_active_series_schema_violation".into());
        }
        // A missing Cell is also an actual safety read. The generic revision
        // guard binds this predicate to the signed basis and unit-entry state.
        security_reads.insert(target.cell_id.clone());
        let current = match state.get(&target.cell_id) {
            None | Some(ResolvedCellState::Value(serde_json::Value::Null)) => None,
            Some(ResolvedCellState::Sequenced(current)) => {
                let record: KeyBackupActiveSeries = serde_json::from_value(current.value.clone())
                    .map_err(|_| {
                    arkret_wire::ReasonCode::DependencyMissing
                        .as_str()
                        .to_owned()
                })?;
                Some(
                    key_backup_active_series_head(&record)
                        .map_err(|error| error.reason_code().to_owned())?,
                )
            }
            _ => return Err(arkret_wire::ReasonCode::DependencyMissing.as_str().into()),
        };
        let record: KeyBackupActiveSeries = serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        validate_key_backup_active_series_transition(current.as_ref(), &record)
            .map_err(|error| error.reason_code().to_owned())?;
        if let (Some(current), Some(ResolvedCellState::Sequenced(value))) =
            (current.as_ref(), state.get(&target.cell_id))
            && value.revision_event_id != event.event_id
            && current.series_pointer_version.checked_add(1) != Some(record.series_pointer_version)
        {
            // Record-level replay is idempotent, but a different Event must
            // advance the confirmed pointer. Checked arithmetic cannot turn
            // exhaustion into a same-version successor.
            return Err(arkret_wire::ReasonCode::StateMismatch.as_str().into());
        }
    }
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

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_state::{CommandEventResult, OrderedControlUnit, OrderedControlUnitEvent};
    use arkret_wire::{EventKind, ScopeRef};
    use serde_json::json;

    use super::*;

    fn event(version: u64, series: u8, previous: Vec<String>) -> Event {
        let actor = arkret_wire::DidCoreId::new("ak:did_core:web:backup.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        arkret_wire::test_support::raw_event_at(
            EventKind::KeyBackupActiveSeries.as_str(),
            ScopeRef::Realm { realm_id: arkret_wire::RealmId::new(
                "ak:realm:AcvBDtCDG7ajziiuQ2d0YqNmv_FKWuzI2TYPLj5Wsbjq").unwrap() },
            actor.clone(), station.clone(), version,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            json!({
                "schema":"ak.schema.key_backup_active_series.v1",
                "actor_id":arkret_wire::ActorId::account(arkret_wire::AccountId::new(actor,station)),
                "backup_kind":"secret_storage", "active_series_id":series_id(series),
                "series_pointer_version":version, "previous_series_ids":previous,
                "frontier_ref":{
                    "frontier_digest":format!("sha256:{}","3".repeat(64)),
                    "seal_ref":format!("ak:seal:sha256:{}","4".repeat(64)),
                    "device_generation_ref":1
                },
                "issued_at":"2026-04-27T00:00:00.000Z",
                "auth_data":{
                    "verification_method":"did:web:backup.example#device",
                    "signature_algorithm":"Ed25519", "signature":"AA",
                    "device_authorize_event_id":"ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
                }
            }), chrono::DateTime::from_timestamp(1_800_000_000 + version as i64,0).unwrap(),
        ).unwrap()
    }

    fn series_id(id: u8) -> String {
        format!("ak:backup_series:01964137-1000-7000-8000-{id:012x}")
    }

    fn state(event: &Event) -> BTreeMap<CellRef, ResolvedCellState> {
        let writes =
            arkret_schema::project_registered_cell_writes(event, DigestSuite::Sha256).unwrap();
        BTreeMap::from([(
            writes[0].cell_id.clone(),
            ResolvedCellState::Sequenced(arkret_state::SequencedStateValue {
                revision_event_id: event.event_id.clone(),
                value: serde_json::to_value(&event.payload).unwrap(),
            }),
        )])
    }

    fn registry() -> arkret_state::MemoryCellStateRegistry {
        let mut registry = arkret_state::MemoryCellStateRegistry::default();
        registry.register(
            arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1,
            arkret_wire::EventCellExecution::Security,
            arkret_state::StateModelKind::SequencedState,
            arkret_wire::EventCellValueShape::Register,
            None,
        );
        registry
    }

    #[test]
    fn active_series_uses_staged_safety_state_and_records_the_exact_read() {
        let first = event(1, 1, vec![]);
        let initial = state(&first);
        assert!(project_control_writes_at_state(&first, DigestSuite::Sha256, &initial).is_ok());
        let mut same_record_new_event = first.clone();
        same_record_new_event.actor_seq += 1;
        same_record_new_event
            .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        assert_ne!(first.event_id, same_record_new_event.event_id);
        assert!(
            project_control_writes_at_state(&same_record_new_event, DigestSuite::Sha256, &initial)
                .is_err()
        );
        let second = event(2, 2, vec![series_id(1)]);
        let projection =
            project_control_writes_at_state(&second, DigestSuite::Sha256, &initial).unwrap();
        assert_eq!(
            projection.security_reads,
            initial.keys().cloned().collect::<Vec<_>>()
        );
        assert!(
            project_control_writes_at_state(&event(4, 4, vec![]), DigestSuite::Sha256, &initial)
                .is_err()
        );
        assert!(
            project_control_writes_at_state(&event(1, 2, vec![]), DigestSuite::Sha256, &initial)
                .is_err()
        );
        assert!(
            project_control_writes_at_state(
                &event(2, 2, vec![series_id(2)]),
                DigestSuite::Sha256,
                &initial
            )
            .is_err()
        );
        // The list describes retained material, not an append-only protocol set.
        assert!(
            project_control_writes_at_state(
                &event(2, 2, vec![series_id(1), series_id(1)]),
                DigestSuite::Sha256,
                &initial
            )
            .is_err()
        );
        assert!(
            project_control_writes_at_state(
                &event(3, 3, vec![]),
                DigestSuite::Sha256,
                &state(&second)
            )
            .is_ok()
        );
        assert!(
            project_control_writes_with_revision_guard(
                &second,
                DigestSuite::Sha256,
                &state(&event(2, 3, vec![])),
                &initial,
                &state(&event(2, 3, vec![])),
                &registry()
            )
            .is_err()
        );
    }

    #[test]
    fn active_series_unit_members_advance_from_the_preceding_member_and_roll_back_gaps() {
        let first = event(1, 1, vec![]);
        let initial = state(&first);
        for (last_version, expected) in [
            (3, arkret_wire::CommandOutcome::Committed),
            (4, arkret_wire::CommandOutcome::Rejected),
        ] {
            let unit = OrderedControlUnit {
                events: [event(2, 2, vec![]), event(last_version, 3, vec![])]
                    .into_iter()
                    .map(|event| OrderedControlUnitEvent {
                        digest: event.event_id.event_digest(),
                        event,
                        digest_suite: DigestSuite::Sha256,
                    })
                    .collect(),
            };
            let registry = registry();
            let outcome = arkret_state::execute_ordered_control_units(
                &first.realm_id,
                &initial,
                &registry,
                &[unit],
                DigestSuite::Sha256,
                false,
                |member, stage, entry| match project_control_writes_with_revision_guard(
                    &member.event,
                    DigestSuite::Sha256,
                    stage,
                    &initial,
                    entry,
                    &registry,
                ) {
                    Ok(projection) => Ok(CommandEventResult::Applied(
                        projection
                            .writes
                            .iter()
                            .map(|write| write.as_direct().unwrap())
                            .collect(),
                    )),
                    Err(_) => Ok(CommandEventResult::Rejected(
                        arkret_wire::ReasonCode::StateMismatch,
                    )),
                },
            )
            .unwrap();
            assert_eq!(outcome.command_results[0].outcome, expected);
            if expected == arkret_wire::CommandOutcome::Rejected {
                assert_eq!(outcome.post_state, initial);
                assert!(outcome.new_security_ops.is_empty());
            } else {
                assert_eq!(
                    outcome
                        .post_state
                        .values()
                        .next()
                        .unwrap()
                        .settled_value()
                        .unwrap()["series_pointer_version"],
                    json!(3)
                );
            }
        }
    }
}
