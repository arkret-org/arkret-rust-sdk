//! Resolver for safety state in the unique confirmed Realm order.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::{
    OpError, ResolvedCellState, SequencedStateValue, StateModel, StateModelKind, StateWrite,
};
use crate::{CellRef, EventCellValueShape, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug)]
pub struct SequencedState {
    value_shape: EventCellValueShape,
}

#[derive(Serialize)]
struct SequencedSetEntry {
    tag_id: String,
    value: Value,
}

#[derive(Serialize)]
struct SequencedLogEntry {
    issuer_seq: u64,
    event_id: crate::EventId,
    value: Value,
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

    /// Apply one write after an already materialized confirmed revision.
    ///
    /// Seal command replay advances safety state one registered unit at a
    /// time. Keeping that operation here makes set and log canonicalization
    /// identical to full history resolution.
    pub fn apply(
        &self,
        current: Option<&ResolvedCellState>,
        write: &StateWrite,
    ) -> Result<ResolvedCellState, OpError> {
        self.validate_op(&write.op)?;
        let current_value = match current {
            None => Value::Null,
            Some(ResolvedCellState::Sequenced(state)) => state.value.clone(),
            Some(ResolvedCellState::Value(Value::Null)) => Value::Null,
            Some(_) => {
                return Err(OpError::InvalidValue {
                    kind: "sequenced_state",
                    field: "current",
                    reason: "current state is not a sequenced revision".to_owned(),
                });
            }
        };
        let value =
            match self.value_shape {
                EventCellValueShape::Register => match write.op.op_type {
                    LatticeOpType::Set => write.op.value.clone().unwrap_or(Value::Null),
                    LatticeOpType::Transition => write.op.to.clone().unwrap_or(Value::Null),
                    _ => unreachable!("validated register operation"),
                },
                EventCellValueShape::Set => {
                    let mut active = BTreeMap::new();
                    if let Some(entries) = current_value.as_array() {
                        for entry in entries {
                            let tag =
                                entry.get("tag_id").and_then(Value::as_str).ok_or_else(|| {
                                    OpError::InvalidValue {
                                        kind: "sequenced_state",
                                        field: "current",
                                        reason: "set entry has no tag_id".to_owned(),
                                    }
                                })?;
                            let value = entry.get("value").cloned().ok_or_else(|| {
                                OpError::InvalidValue {
                                    kind: "sequenced_state",
                                    field: "current",
                                    reason: "set entry has no value".to_owned(),
                                }
                            })?;
                            active.insert(tag.to_owned(), value);
                        }
                    } else if !current_value.is_null() {
                        return Err(OpError::InvalidValue {
                            kind: "sequenced_state",
                            field: "current",
                            reason: "set state is not an array".to_owned(),
                        });
                    }
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
                    Value::Array(
                        active
                            .into_iter()
                            .map(|(tag_id, value)| {
                                serde_json::to_value(SequencedSetEntry { tag_id, value })
                                    .expect("sequenced set entry is JSON serializable")
                            })
                            .collect(),
                    )
                }
                EventCellValueShape::Log => {
                    let mut entries = Vec::new();
                    if let Some(current_entries) = current_value.as_array() {
                        for entry in current_entries {
                            let issuer_seq = entry
                                .get("issuer_seq")
                                .and_then(Value::as_u64)
                                .ok_or_else(|| OpError::InvalidValue {
                                    kind: "sequenced_state",
                                    field: "current",
                                    reason: "log entry has no issuer_seq".to_owned(),
                                })?;
                            let event_id =
                                serde_json::from_value(entry.get("event_id").cloned().ok_or_else(
                                    || OpError::InvalidValue {
                                        kind: "sequenced_state",
                                        field: "current",
                                        reason: "log entry has no event_id".to_owned(),
                                    },
                                )?)
                                .map_err(|error| {
                                    OpError::InvalidValue {
                                        kind: "sequenced_state",
                                        field: "current",
                                        reason: format!("log entry event_id is invalid: {error}"),
                                    }
                                })?;
                            let value = entry.get("value").cloned().ok_or_else(|| {
                                OpError::InvalidValue {
                                    kind: "sequenced_state",
                                    field: "current",
                                    reason: "log entry has no value".to_owned(),
                                }
                            })?;
                            entries.push((issuer_seq, event_id, value));
                        }
                    } else if !current_value.is_null() {
                        return Err(OpError::InvalidValue {
                            kind: "sequenced_state",
                            field: "current",
                            reason: "log state is not an array".to_owned(),
                        });
                    }
                    entries.push((
                        write.op.issuer_seq.expect("validated log sequence"),
                        write.event_id.clone(),
                        write.op.value.clone().expect("validated log value"),
                    ));
                    entries.sort_by(|left, right| {
                        left.0
                            .cmp(&right.0)
                            .then_with(|| left.1.token_bytes().cmp(&right.1.token_bytes()))
                    });
                    Value::Array(
                        entries
                            .into_iter()
                            .map(|(issuer_seq, event_id, value)| {
                                serde_json::to_value(SequencedLogEntry {
                                    issuer_seq,
                                    event_id,
                                    value,
                                })
                                .expect("sequenced log entry is JSON serializable")
                            })
                            .collect(),
                    )
                }
            };
        Ok(ResolvedCellState::Sequenced(SequencedStateValue {
            revision_event_id: write.event_id.clone(),
            value,
        }))
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
        for write in writes {
            self.validate_op(&write.op)?;
        }
        if writes.is_empty() {
            return Ok(ResolvedCellState::Value(Value::Null));
        }
        let mut state = None;
        for write in writes {
            state = Some(self.apply(state.as_ref(), write)?);
        }
        Ok(state.expect("non-empty ordered writes produce state"))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

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

    #[test]
    fn one_event_may_apply_multiple_registered_writes_to_one_set_cell() {
        let model = SequencedState::new(EventCellValueShape::Set);
        let identity = event(3);
        let writes = [
            StateWrite::new(
                identity.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Add,
                    tag: Some("prior".to_owned()),
                    value: Some(json!({"state": "active"})),
                    ..LatticeOp::empty()
                },
            ),
            StateWrite::new(
                identity.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Remove,
                    tag: Some("prior".to_owned()),
                    ..LatticeOp::empty()
                },
            ),
        ];

        assert_eq!(
            model
                .resolve(
                    &CellRef::new("ak:cell:ak.component.agent.key.v1:slot".to_owned()).unwrap(),
                    &writes,
                )
                .unwrap(),
            ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: identity,
                value: Value::Array(Vec::new()),
            })
        );
    }
}
