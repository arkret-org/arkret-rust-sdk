//! Typed cell-family adapters and spec-generated state-model bindings.
//!
//! [`build_sdk_state_registry`] installs the complete executable binding table
//! generated from the normative Event-kind registry. [`default_cell_family_registry`]
//! provides typed subject derivation for Event producers and receivers.

mod contract_registry;
mod factory;
mod generated;
mod impls;
mod registry;
mod types;

pub use contract_registry::*;
pub use factory::*;
pub use impls::*;
pub use registry::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_state::state::CellStateRegistry;
    use arkret_state::state_model::{ResolvedCellState, StateModelKind, StateWrite};
    use arkret_wire::{
        CellFamilyId, CellRef, EventCellExecution, EventCellValueShape, EventId, LatticeOp,
        LatticeOpType, RealmId,
    };
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned()).unwrap()
    }

    fn event(byte: u8) -> EventId {
        EventId::new(format!("ak:event:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn generated_bindings_cover_each_active_family_once() {
        let bindings = state_model_bindings_for_sdk_registry();
        let by_family: BTreeMap<_, _> = bindings
            .iter()
            .map(|(family, execution, state_model, value_shape, bottom)| {
                (*family, (*execution, *state_model, *value_shape, *bottom))
            })
            .collect();
        assert_eq!(by_family.len(), bindings.len());
        assert!(
            bindings
                .iter()
                .all(|(_, execution, state_model, _, bottom)| {
                    match execution {
                        EventCellExecution::Security => {
                            *state_model == StateModelKind::SequencedState && bottom.is_none()
                        }
                        EventCellExecution::Data => {
                            *state_model != StateModelKind::SequencedState && bottom.is_some()
                        }
                    }
                })
        );

        let runtime = build_sdk_state_registry();
        for family in by_family.keys() {
            let cell = CellRef::new(format!("ak:cell:{family}:coverage")).unwrap();
            runtime.resolve(&realm(), &cell).unwrap();
        }
    }

    #[test]
    fn causal_register_preserves_distinct_same_value_heads() {
        let registry = build_sdk_state_registry();
        let cell = CellRef::new(format!(
            "ak:cell:{}:fixture",
            CellFamilyId::REALM_PROFILE_V1
        ))
        .unwrap();
        let binding = registry.resolve(&realm(), &cell).unwrap();
        assert_eq!(binding.state_model, StateModelKind::CausalRegister);
        assert_eq!(binding.execution, EventCellExecution::Data);
        assert_eq!(binding.value_shape, EventCellValueShape::Register);

        let write = |event_id| {
            StateWrite::new(
                event_id,
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!({"name": "Arkret"})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            )
        };
        let resolved = binding
            .model
            .resolve(&cell, &[write(event(1)), write(event(2))])
            .unwrap();
        let ResolvedCellState::Bottom(bottom) = resolved else {
            panic!("expected exposed causal conflict")
        };
        assert_eq!(bottom.heads.len(), 2);
        assert_eq!(bottom.heads[0].value, bottom.heads[1].value);
        assert_ne!(bottom.heads[0].event_id, bottom.heads[1].event_id);
    }

    #[test]
    fn transition_contract_is_a_validator_on_sequenced_state() {
        let registry = build_sdk_state_registry();
        let cell =
            CellRef::new(format!("ak:cell:{}:member", CellFamilyId::MEMBER_STATE_V1)).unwrap();
        let binding = registry.resolve(&realm(), &cell).unwrap();
        assert_eq!(binding.state_model, StateModelKind::SequencedState);
        assert!(binding.domain_transition.is_some());
        let transition = LatticeOp {
            op_type: LatticeOpType::Transition,
            from: Some(json!("leave")),
            to: Some(json!("join")),
            ..LatticeOp::empty()
        };
        assert!(
            binding
                .domain_transition
                .as_ref()
                .unwrap()
                .validate(Some(&json!("leave")), &transition)
                .is_ok()
        );
    }
}
