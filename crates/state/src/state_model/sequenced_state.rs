//! Resolver for safety state in the unique confirmed Realm order.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{
    OpError, ResolvedCellState, SequencedStateValue, StateModel, StateModelKind, StateWrite,
};
use crate::{CellRef, EventCellValueShape, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug)]
pub struct SequencedState {
    value_shape: EventCellValueShape,
}

impl SequencedState {
    pub const fn new(value_shape: EventCellValueShape) -> Self {
        Self { value_shape }
    }

    fn invalid(&self, op: &LatticeOp) -> OpError {
        OpError::UnsupportedOpType {
            got: op.op_type.as_str().to_owned(),
            expected_kind: match self.value_shape {
                EventCellValueShape::Register => "sequenced_state register",
                EventCellValueShape::Set => "sequenced_state set",
                EventCellValueShape::Log => "sequenced_state log",
            },
        }
    }
}

impl StateModel for SequencedState {
    fn kind(&self) -> StateModelKind {
        StateModelKind::SequencedState
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match (self.value_shape, op.op_type) {
            (EventCellValueShape::Register, LatticeOpType::Set) if op.value.is_some() => Ok(()),
            (EventCellValueShape::Register, LatticeOpType::Transition)
                if op.from.is_some() && op.to.is_some() =>
            {
                Ok(())
            }
            (EventCellValueShape::Set, LatticeOpType::Add)
                if op.tag.is_some() && op.value.is_some() =>
            {
                Ok(())
            }
            (EventCellValueShape::Set, LatticeOpType::Remove) if op.tag.is_some() => Ok(()),
            (EventCellValueShape::Log, LatticeOpType::Append)
                if op.value.is_some() && op.issuer_seq.is_some() =>
            {
                Ok(())
            }
            (_, LatticeOpType::Set) if op.value.is_none() => Err(OpError::MissingField {
                kind: "sequenced_state",
                field: "value",
            }),
            (_, LatticeOpType::Transition) if op.from.is_none() => Err(OpError::MissingField {
                kind: "sequenced_state",
                field: "from",
            }),
            (_, LatticeOpType::Transition) if op.to.is_none() => Err(OpError::MissingField {
                kind: "sequenced_state",
                field: "to",
            }),
            (_, LatticeOpType::Add | LatticeOpType::Remove) if op.tag.is_none() => {
                Err(OpError::MissingField {
                    kind: "sequenced_state",
                    field: "tag",
                })
            }
            (_, LatticeOpType::Append) if op.value.is_none() => Err(OpError::MissingField {
                kind: "sequenced_state",
                field: "value",
            }),
            (_, LatticeOpType::Append) if op.issuer_seq.is_none() => Err(OpError::MissingField {
                kind: "sequenced_state",
                field: "issuer_seq",
            }),
            _ => Err(self.invalid(op)),
        }
    }

    fn resolve(
        &self,
        _cell: &CellRef,
        writes: &[StateWrite],
    ) -> Result<ResolvedCellState, OpError> {
        let mut seen = BTreeMap::new();
        let mut ordered = Vec::new();
        for write in writes {
            if let Some(previous) = seen.get(&write.event_id) {
                if previous != &write.op {
                    return Err(OpError::InvalidValue {
                        kind: "sequenced_state",
                        field: "event_id",
                        reason: "one Event identity maps to different operations".to_owned(),
                    });
                }
                continue;
            }
            self.validate_op(&write.op)?;
            seen.insert(write.event_id.clone(), write.op.clone());
            ordered.push(write);
        }
        let Some(last) = ordered.last() else {
            return Ok(ResolvedCellState::Value(Value::Null));
        };

        let value = match self.value_shape {
            EventCellValueShape::Register => ordered
                .iter()
                .map(|write| match write.op.op_type {
                    LatticeOpType::Set => write.op.value.clone().unwrap_or(Value::Null),
                    LatticeOpType::Transition => write.op.to.clone().unwrap_or(Value::Null),
                    _ => unreachable!("validated register operation"),
                })
                .next_back()
                .unwrap_or(Value::Null),
            EventCellValueShape::Set => {
                let mut active = BTreeMap::new();
                for write in &ordered {
                    let tag = write.op.tag.as_deref().expect("validated set tag");
                    match write.op.op_type {
                        LatticeOpType::Add => {
                            active.insert(tag.to_owned(), write.op.value.clone().unwrap());
                        }
                        LatticeOpType::Remove => {
                            active.remove(tag);
                        }
                        _ => unreachable!("validated set operation"),
                    }
                }
                Value::Array(
                    active
                        .into_iter()
                        .map(|(tag_id, value)| json!({ "tag_id": tag_id, "value": value }))
                        .collect(),
                )
            }
            EventCellValueShape::Log => {
                let mut entries = Vec::new();
                for write in &ordered {
                    entries.push((
                        write.op.issuer_seq.expect("validated log sequence"),
                        write.event_id.clone(),
                        write.op.value.clone().expect("validated log value"),
                    ));
                }
                entries.sort_by(|left, right| {
                    left.0
                        .cmp(&right.0)
                        .then_with(|| left.1.token_bytes().cmp(&right.1.token_bytes()))
                });
                Value::Array(
                    entries
                        .into_iter()
                        .map(|(issuer_seq, event_id, value)| {
                            json!({
                                "issuer_seq": issuer_seq,
                                "event_id": event_id,
                                "value": value,
                            })
                        })
                        .collect(),
                )
            }
        };

        Ok(ResolvedCellState::Sequenced(SequencedStateValue {
            revision_event_id: last.event_id.clone(),
            value,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventId, Hash};

    fn event(byte: u8) -> EventId {
        EventId::from_event_digest(
            &Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn register_keeps_the_confirmed_revision_even_for_null() {
        let model = SequencedState::new(EventCellValueShape::Register);
        let set = |value| LatticeOp {
            op_type: LatticeOpType::Set,
            value: Some(value),
            ..LatticeOp::empty()
        };
        let writes = [
            StateWrite::new(event(1), set(json!("occupied"))),
            StateWrite::new(event(2), set(Value::Null)),
        ];
        assert_eq!(
            model.resolve(
                &CellRef::new("ak:cell:ak.component.invite.live_target.v1:slot".to_owned())
                    .unwrap(),
                &writes,
            ),
            Ok(ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: event(2),
                value: Value::Null,
            }))
        );
    }
}
