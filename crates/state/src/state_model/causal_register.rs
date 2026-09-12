//! Identity-preserving causal register.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{Bottom, CausalHead, CellRef, EventId, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CausalRegister;

/// Complete causal-register state for one eligibility context.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRegisterState {
    pub covered_event_ids: BTreeSet<EventId>,
    pub heads: Vec<CausalHead>,
}

/// Compute `C` and `H` from authenticated writes.
pub fn causal_heads(writes: &[StateWrite]) -> Result<CausalRegisterState, OpError> {
    let mut unique: BTreeMap<EventId, &StateWrite> = BTreeMap::new();
    for write in writes {
        if CausalRegister.validate_op(&write.op).is_err() {
            continue;
        }
        if let Some(previous) = unique.get(&write.event_id) {
            if previous.op.value != write.op.value {
                return Err(OpError::InvalidValue {
                    kind: "causal_register",
                    field: "event_id",
                    reason: "one Event identity maps to different values".to_owned(),
                });
            }
            continue;
        }
        unique.insert(write.event_id.clone(), write);
    }

    let covered_event_ids: BTreeSet<_> = unique.keys().cloned().collect();
    let superseded: BTreeSet<_> = unique
        .values()
        .flat_map(|write| write.supersedes.iter().cloned())
        .collect();
    let mut heads: Vec<_> = unique
        .into_iter()
        .filter(|(event_id, _)| !superseded.contains(event_id))
        .map(|(event_id, write)| CausalHead {
            event_id,
            value: write.op.value.clone().unwrap_or(Value::Null),
        })
        .collect();
    heads.sort_by(|left, right| {
        left.event_id
            .token_bytes()
            .cmp(&right.event_id.token_bytes())
    });

    Ok(CausalRegisterState {
        covered_event_ids,
        heads,
    })
}

impl StateModel for CausalRegister {
    fn kind(&self) -> StateModelKind {
        StateModelKind::CausalRegister
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        if op.op_type != LatticeOpType::Set {
            return Err(OpError::UnsupportedOpType {
                got: op.op_type.as_str().to_owned(),
                expected_kind: "causal_register",
            });
        }
        if op.value.is_none() {
            return Err(OpError::MissingField {
                kind: "causal_register",
                field: "value",
            });
        }
        Ok(())
    }

    fn resolve(&self, cell: &CellRef, writes: &[StateWrite]) -> Result<ResolvedCellState, OpError> {
        match causal_heads(writes) {
            Ok(state) if state.heads.len() < 2 => Ok(ResolvedCellState::Causal(state)),
            Ok(state) => Ok(ResolvedCellState::Bottom(Bottom::conflict(
                vec![cell.clone()],
                state.heads,
            ))),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::Hash;

    fn event(byte: u8) -> EventId {
        EventId::from_event_digest(
            &Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        )
        .unwrap()
    }

    fn set(value: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Set,
            value: Some(value),
            ..LatticeOp::empty()
        }
    }

    #[test]
    fn preserves_same_value_identities_and_aba() {
        let first = StateWrite::new(event(1), set(json!("A")));
        let sibling = StateWrite::new(event(2), set(json!("A")));
        let returned = StateWrite::superseding(event(3), set(json!("A")), vec![event(1)]);
        let state = causal_heads(&[first, sibling, returned]).unwrap();
        assert_eq!(state.covered_event_ids.len(), 3);
        assert_eq!(
            state
                .heads
                .iter()
                .map(|head| &head.event_id)
                .collect::<Vec<_>>(),
            vec![&event(2), &event(3)]
        );
    }

    #[test]
    fn partial_observation_join_formula_recomputes_from_covered_writes() {
        let first = StateWrite::new(event(1), set(json!("A")));
        let next = StateWrite::superseding(event(2), set(json!("B")), vec![event(1)]);
        let concurrent = StateWrite::new(event(3), set(json!("C")));
        let state = causal_heads(&[concurrent, next, first]).unwrap();
        assert_eq!(
            state
                .heads
                .iter()
                .map(|head| &head.event_id)
                .collect::<Vec<_>>(),
            vec![&event(2), &event(3)]
        );
    }
}
