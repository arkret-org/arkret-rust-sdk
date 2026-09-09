//! Membership facts derived from one accepted governance view.
//!
//! This module consumes trusted reducer inputs, not remote assertions. It
//! neither verifies signatures nor confers current release authorization.

use arkret_models_collaboration::history_key::AuthorizationIncarnation;
use arkret_wire::{ActorId, CellRef, Event, EventId, HistoryEffectiveScope, SealBasis, WireError};
use serde_json::Value;

use crate::mls_governance_proof::ReplayEventLookup;
use crate::{CasHeadsByCell, CellRegistry, CellStore, SealStore};

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

fn unique_join(heads: &CasHeadsByCell, cell: &CellRef) -> arkret_wire::Result<EventId> {
    match heads.get(cell).map(Vec::as_slice) {
        Some([head]) if head.value.as_str() == Some("join") => {
            Ok(EventId::from_event_digest(&head.move_id)?)
        }
        _ => Err(WireError::Protocol(
            "membership has no unique effective join identity".to_owned(),
        )),
    }
}

/// Query accepted stores at this exact basis using the registered FSM heads.
/// Invite acceptance and recovery use the same head identity as any other
/// registered producer; payload kind is not an authorization discriminator.
pub async fn membership_at_verified_basis(
    scope: &HistoryEffectiveScope,
    actor: &ActorId,
    basis: &SealBasis,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
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
    let heads = crate::causal_heads_for_cells_at(
        &basis.leaves,
        scope.realm_id(),
        seals,
        cells,
        registry,
        &targets,
    )
    .await
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let realm_join = unique_join(&heads, &realm_cell)?;
    let incarnation = if let Some(circle) = scope.circle_id() {
        let circle_join = unique_join(&heads, &membership_cell(actor, Some(circle))?)?;
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
        let covered = crate::union_predecessor_covered_events(&activation_basis.leaves, seals)
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
    registry: &dyn CellRegistry,
    events: &dyn ReplayEventLookup,
    retained_events: &[Event],
) -> arkret_wire::Result<(VerifiedMembership, Option<u64>)> {
    let membership =
        membership_at_verified_basis(scope, actor, basis, seals, cells, registry, events).await?;
    let group = scope.canonical_mls_group_id()?;
    let cell =
        crate::mls_cells::mls_epoch_cell_id(&arkret_wire::ScopeRef::from(scope.clone()), &group)?;
    let heads = crate::causal_heads_for_cells_at(
        &basis.leaves,
        scope.realm_id(),
        seals,
        cells,
        registry,
        std::slice::from_ref(&cell),
    )
    .await
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let Some((transition, epoch)) = epoch_transition_from_heads(
        scope,
        heads.get(&cell).map(Vec::as_slice).unwrap_or_default(),
    )?
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

fn epoch_transition_from_heads(
    scope: &HistoryEffectiveScope,
    heads: &[crate::lattice::cas_register::CasHead],
) -> arkret_wire::Result<Option<(EventId, u64)>> {
    let Some(first) = heads.first() else {
        return Ok(None);
    };
    if heads.iter().any(|head| head.value != first.value) {
        return Err(WireError::Protocol("MLS epoch cell is Bottom".to_owned()));
    }
    let value = &first.value;
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
    use crate::lattice::cas_register::CasHead;

    #[test]
    fn epoch_selection_uses_recovered_heads_and_rejects_unresolved_bottom() {
        let scope = HistoryEffectiveScope::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
            )
            .unwrap(),
        };
        let first = EventId::new("ak:event:ARrXzX07X_prHPMAeOGPMrI4_sUFneJW2aYSvHN_-9aQ").unwrap();
        let second = EventId::new("ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC").unwrap();
        let recovery =
            EventId::new("ak:event:AbNAprqpf8plo9xcY8bDOmf3mEUhUCZbN63erkPaxN_8").unwrap();
        let value = |id: &EventId| {
            serde_json::json!({
                "effective_scope": arkret_wire::ScopeRef::from(scope.clone()),
                "mls_group_id": scope.canonical_mls_group_id().unwrap(),
                "transition_ref": id,
                "next_epoch": 1,
            })
        };
        let op = |id: &EventId| crate::LatticeOp {
            op_type: crate::LatticeOpType::Set,
            value: Some(value(id)),
            tag: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let mut writes = vec![
            crate::SealedOp::new(first.event_digest(), op(&first)),
            crate::SealedOp::new(second.event_digest(), op(&second)),
        ];
        let heads = crate::lattice::cas_register::cas_heads(&writes).unwrap();
        assert!(epoch_transition_from_heads(&scope, &heads).is_err());
        // Recovery selects a transition value, but owns a fresh write identity.
        writes.push(crate::SealedOp::superseding(
            recovery.event_digest(),
            op(&first),
            vec![first.event_digest(), second.event_digest()],
        ));
        let heads = crate::lattice::cas_register::cas_heads(&writes).unwrap();
        assert_eq!(heads[0].move_id, recovery.event_digest());
        assert_eq!(
            epoch_transition_from_heads(&scope, &heads).unwrap(),
            Some((first.clone(), 1))
        );
        let same_value_heads = vec![
            heads[0].clone(),
            CasHead {
                move_id: second.event_digest(),
                value: value(&first),
            },
        ];
        assert_eq!(
            epoch_transition_from_heads(&scope, &same_value_heads).unwrap(),
            Some((first, 1))
        );
        assert_eq!(epoch_transition_from_heads(&scope, &[]).unwrap(), None);
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
        let mut registry = crate::MemoryCellRegistry::default();
        registry.register_fsm(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            Some(Value::String("leave".into())),
            vec![(Value::String("leave".into()), Value::String("join".into()))],
            crate::EventCellBottom::Reject,
        );
        let pre = std::collections::BTreeMap::from([(
            cell.clone(),
            crate::CellState::Value(Value::String("leave".into())),
        )]);
        let effects =
            crate::resolve_projected_write(write, &event.realm_id, &pre, &registry).unwrap();
        let ops = effects
            .iter()
            .map(|effect| crate::SealedOp::from_projection(event.event_id.event_digest(), effect))
            .collect::<Vec<_>>();
        let heads = CasHeadsByCell::from([(cell.clone(), crate::fsm_heads(&ops).unwrap())]);
        assert_eq!(unique_join(&heads, &cell).unwrap(), event.event_id);
        assert!(!event.payload.contains_key("member_id"));
    }

    #[test]
    fn membership_head_cases_match_the_normative_fixture() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let cases = fixture["direct_traversal_kat"]["since_join_lineage"]["membership_head_cases"]
            .as_array()
            .unwrap();
        let cell = CellRef::new("ak:cell:ak.component.member.state.v1:subject").unwrap();
        for case in cases {
            let heads = case["heads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|head| CasHead {
                    move_id: EventId::new(head["event_id"].as_str().unwrap())
                        .unwrap()
                        .event_digest(),
                    value: head["value"].clone(),
                })
                .collect::<Vec<_>>();
            let actual = unique_join(&CasHeadsByCell::from([(cell.clone(), heads)]), &cell).ok();
            let expected = case["expected_incarnation"]
                .as_str()
                .map(|value| EventId::new(value).unwrap());
            assert_eq!(actual, expected, "{}", case["name"]);
        }
    }
}
