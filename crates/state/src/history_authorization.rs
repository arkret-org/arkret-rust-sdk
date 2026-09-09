//! Membership facts derived from one accepted governance view.
//!
//! This module consumes trusted reducer inputs, not remote assertions. It
//! neither verifies signatures nor confers current release authorization.

use arkret_models_collaboration::history_key::AuthorizationIncarnation;
use arkret_wire::{ActorId, CellRef, EventId, HistoryEffectiveScope, SealBasis, WireError};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::cas_register::CasHead;

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
