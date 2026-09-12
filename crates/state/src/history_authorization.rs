//! Membership facts derived from one accepted governance view.
//!
//! This module consumes trusted reducer inputs, not remote assertions. It
//! neither verifies signatures nor confers current release authorization.

use arkret_models_collaboration::history_key::AuthorizationIncarnation;
use arkret_wire::{ActorId, CellRef, Event, EventId, HistoryEffectiveScope, SealBasis, WireError};
use serde_json::Value;

use crate::mls_governance_proof::ReplayEventLookup;
use crate::{CellStateRegistry, CellStore, ResolvedCellState, SealStore};

/// An exact membership result, independent of whether MLS has consumed its Add.
/// No serialization or public field constructor can turn checkpoint material
/// into this result. The creating query requires an already verified store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMembership {
    pub(crate) scope: HistoryEffectiveScope,
    pub(crate) actor: ActorId,
    pub(crate) incarnation: AuthorizationIncarnation,
}

impl VerifiedMembership {
    pub fn scope(&self) -> &HistoryEffectiveScope {
        &self.scope
    }

    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    pub fn incarnation(&self) -> &AuthorizationIncarnation {
        &self.incarnation
    }
}

fn membership_cell(
    actor: &ActorId,
    scope: Option<&arkret_wire::CircleId>,
) -> arkret_wire::Result<CellRef> {
    let mut coordinates = Vec::new();
    if let Some(circle) = scope {
        coordinates.push(Value::String(circle.as_str().to_owned()));
    }
    coordinates.push(Value::String(actor.canonical_key()?));
    let subject = arkret_wire::cell::composite_subject(&coordinates)?;
    let family = if scope.is_some() {
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
    } else {
        arkret_wire::CellFamilyId::MEMBER_STATE_V1
    };
    Ok(CellRef::new(arkret_wire::cell::subject_cell(
        family, &subject,
    ))?)
}

fn unique_join(
    cells: &std::collections::BTreeMap<CellRef, ResolvedCellState>,
    cell: &CellRef,
) -> arkret_wire::Result<EventId> {
    match cells.get(cell) {
        Some(ResolvedCellState::Sequenced(state)) if state.value.as_str() == Some("join") => {
            Ok(state.revision_event_id.clone())
        }
        _ => Err(WireError::Protocol(
            "membership has no unique effective join identity".to_owned(),
        )),
    }
}

/// Query accepted stores at this exact basis using confirmed sequenced state.
/// Invite acceptance and recovery use the same head identity as any other
/// registered producer; payload kind is not an authorization discriminator.
pub async fn membership_at_verified_basis(
    scope: &HistoryEffectiveScope,
    actor: &ActorId,
    basis: &SealBasis,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellStateRegistry,
    events: &dyn ReplayEventLookup,
) -> arkret_wire::Result<VerifiedMembership> {
    basis.validate_protocol_bounds()?;
    for leaf in &basis.leaves {
        let seal = seals
            .get(leaf)
            .await
            .map_err(|error| WireError::Protocol(error.to_string()))?
            .ok_or_else(|| {
                WireError::Protocol("membership basis Seal is unavailable".to_owned())
            })?;
        if seal.realm_id != *scope.realm_id() {
            return Err(WireError::Protocol(
                "membership basis contains a cross-Realm Seal".to_owned(),
            ));
        }
    }
    let realm_cell = membership_cell(actor, None)?;
    let mut targets = vec![realm_cell.clone()];
    if let Some(circle) = scope.circle_id() {
        targets.push(membership_cell(actor, Some(circle))?);
    }
    let view =
        crate::effective_joined_view_at(&basis.leaves, scope.realm_id(), seals, cells, registry)
            .await
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    for target in &targets {
        if !view.cells.contains_key(target) {
            return Err(WireError::Protocol(format!(
                "membership cell {target} is unavailable at the requested basis"
            )));
        }
    }
    let realm_join = unique_join(&view.cells, &realm_cell)?;
    let incarnation = if let Some(circle) = scope.circle_id() {
        let circle_join = unique_join(&view.cells, &membership_cell(actor, Some(circle))?)?;
        let activation = events
            .event(&circle_join.event_digest())
            .await?
            .ok_or_else(|| {
                WireError::Protocol("Circle membership activation bytes are unavailable".to_owned())
            })?;
        if activation.event_id != circle_join || activation.realm_id != *scope.realm_id() {
            return Err(WireError::Protocol(
                "Circle membership activation identity differs".to_owned(),
            ));
        }
        let activation_basis = activation.seal_basis.as_ref().ok_or_else(|| {
            WireError::Protocol("Circle membership activation has no signed basis".to_owned())
        })?;
        let covered = crate::covered_events_for_seal_basis(&activation_basis.leaves, seals)
            .await
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if !covered.contains(&realm_join.event_digest()) {
            return Err(WireError::Protocol(
                "Circle reactivation does not causally cover the current Realm incarnation"
                    .to_owned(),
            ));
        }
        AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref: realm_join,
            circle_membership_incarnation_ref: circle_join,
        }
    } else {
        AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref: realm_join,
        }
    };
    Ok(VerifiedMembership {
        scope: scope.clone(),
        actor: actor.clone(),
        incarnation,
    })
}

/// Resolve current membership and its MLS floor from the same accepted stores.
/// A Genesis initial membership is the reducer result at its signed basis;
/// the author and sequence of a membership producer cannot establish it.
#[allow(clippy::too_many_arguments)]
pub async fn member_history_at_verified_basis(
    scope: &HistoryEffectiveScope,
    actor: &ActorId,
    basis: &SealBasis,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellStateRegistry,
    events: &dyn ReplayEventLookup,
    retained_events: &[Event],
) -> arkret_wire::Result<(VerifiedMembership, Option<u64>)> {
    let membership =
        membership_at_verified_basis(scope, actor, basis, seals, cells, registry, events).await?;
    let group = scope.canonical_mls_group_id()?;
    let cell =
        crate::mls_cells::mls_epoch_cell_id(&arkret_wire::ScopeRef::from(scope.clone()), &group)?;
    let view =
        crate::effective_joined_view_at(&basis.leaves, scope.realm_id(), seals, cells, registry)
            .await
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    let Some((transition, epoch)) = epoch_transition_from_state(scope, view.cells.get(&cell))?
    else {
        return Ok((membership, None));
    };
    let lineage =
        crate::direct_traversal::winning_mls_lineage(retained_events, scope, &transition, epoch)?;
    let genesis = lineage
        .first()
        .ok_or_else(|| WireError::Protocol("winning MLS lineage has no Genesis".to_owned()))?;
    let genesis_membership = if genesis.actor_id == *actor {
        let genesis_basis = genesis.seal_basis.as_ref().ok_or_else(|| {
            WireError::Protocol("accepted MLS Genesis has no signed membership basis".to_owned())
        })?;
        Some(
            membership_at_verified_basis(
                scope,
                actor,
                genesis_basis,
                seals,
                cells,
                registry,
                events,
            )
            .await?,
        )
    } else {
        None
    };
    let epoch = crate::direct_traversal::history_join_epoch_from_verified_membership(
        retained_events,
        &membership,
        genesis_membership
            .as_ref()
            .map(VerifiedMembership::incarnation),
        &lineage,
    )?;
    Ok((membership, epoch))
}

fn epoch_transition_from_state(
    scope: &HistoryEffectiveScope,
    state: Option<&ResolvedCellState>,
) -> arkret_wire::Result<Option<(EventId, u64)>> {
    let Some(state) = state else {
        return Ok(None);
    };
    let ResolvedCellState::Sequenced(state) = state else {
        return Err(WireError::Protocol(
            "MLS epoch cell is not confirmed sequenced_state".to_owned(),
        ));
    };
    let value = &state.value;
    if value.get("mls_group_id").and_then(Value::as_str)
        != Some(scope.canonical_mls_group_id()?.as_str())
        || value.get("effective_scope")
            != Some(&serde_json::to_value(arkret_wire::ScopeRef::from(
                scope.clone(),
            ))?)
    {
        return Err(WireError::Protocol(
            "winning MLS epoch cell has inconsistent group or scope".to_owned(),
        ));
    }
    let transition = value
        .get("transition_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WireError::Protocol("winning MLS epoch cell lacks transition_ref".to_owned())
        })?;
    let epoch = value
        .get("next_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| WireError::Protocol("winning MLS epoch cell lacks next_epoch".to_owned()))?;
    Ok(Some((EventId::new(transition.to_owned())?, epoch)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_selection_requires_confirmed_sequenced_state() {
        let scope = HistoryEffectiveScope::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
            )
            .unwrap(),
        };
        let first = EventId::new("ak:event:ARrXzX07X_prHPMAeOGPMrI4_sUFneJW2aYSvHN_-9aQ").unwrap();
        let value = |id: &EventId| {
            serde_json::json!({
                "effective_scope": arkret_wire::ScopeRef::from(scope.clone()),
                "mls_group_id": scope.canonical_mls_group_id().unwrap(),
                "transition_ref": id,
                "next_epoch": 1,
            })
        };
        let state = ResolvedCellState::Sequenced(crate::SequencedStateValue {
            revision_event_id: first.clone(),
            value: value(&first),
        });
        assert_eq!(
            epoch_transition_from_state(&scope, Some(&state)).unwrap(),
            Some((first.clone(), 1))
        );
        assert!(
            epoch_transition_from_state(&scope, Some(&ResolvedCellState::Value(value(&first))))
                .is_err()
        );
        assert_eq!(epoch_transition_from_state(&scope, None).unwrap(), None);
    }

    #[test]
    fn invite_accept_uses_the_registered_actor_cell_without_a_membership_payload() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
            )
            .unwrap(),
        };
        let event = arkret_wire::test_support::raw_event(
            arkret_wire::event_kind_str::INVITE_ACCEPT, scope, principal, station, 1,
            arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({"invite_id": "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA"}),
        ).unwrap();
        let cell = membership_cell(&event.actor_id, None).unwrap();
        let writes = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let write = writes.iter().find(|write| write.cell_id == cell).unwrap();
        let mut registry = crate::MemoryCellStateRegistry::default();
        registry
            .register_domain_transition(
                arkret_wire::CellFamilyId::MEMBER_STATE_V1,
                Some(Value::String("leave".into())),
                vec![(Value::String("leave".into()), Value::String("join".into()))],
            )
            .unwrap();
        let pre = std::collections::BTreeMap::from([(
            cell.clone(),
            crate::ResolvedCellState::Sequenced(crate::SequencedStateValue {
                revision_event_id: event.event_id.clone(),
                value: Value::String("leave".into()),
            }),
        )]);
        let effects =
            crate::resolve_projected_write(write, &event.realm_id, &pre, &registry).unwrap();
        let state = ResolvedCellState::Sequenced(crate::SequencedStateValue {
            revision_event_id: event.event_id.clone(),
            value: effects[0].op.to.clone().unwrap(),
        });
        let cells = std::collections::BTreeMap::from([(cell.clone(), state)]);
        assert_eq!(unique_join(&cells, &cell).unwrap(), event.event_id);
        assert!(!event.payload.contains_key("member_id"));
    }
}
