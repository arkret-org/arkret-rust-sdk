//! Domain transition validation layered over registered state models.

use serde_json::Value;

use super::OpError;
use crate::{LatticeOp, LatticeOpType};

/// Closed transition table for one domain value.
#[derive(Clone, Debug)]
pub struct DomainTransitionRule {
    allowed_transitions: Vec<(Value, Value)>,
    initial_state: Option<Value>,
}

impl DomainTransitionRule {
    pub fn new(allowed_transitions: Vec<(Value, Value)>) -> Self {
        Self {
            allowed_transitions,
            initial_state: None,
        }
    }

    pub fn with_initial(mut self, initial_state: Value) -> Self {
        self.initial_state = Some(initial_state);
        self
    }

    pub fn initial_state(&self) -> Option<&Value> {
        self.initial_state.as_ref()
    }

    pub fn validate(&self, current: Option<&Value>, op: &LatticeOp) -> Result<(), OpError> {
        if op.op_type != LatticeOpType::Transition {
            return Err(OpError::UnsupportedOpType {
                got: op.op_type.as_str().to_owned(),
                expected_kind: "domain_transition",
            });
        }
        let from = op.from.as_ref().ok_or(OpError::MissingField {
            kind: "domain_transition",
            field: "from",
        })?;
        let to = op.to.as_ref().ok_or(OpError::MissingField {
            kind: "domain_transition",
            field: "to",
        })?;
        let actual = current
            .or(self.initial_state.as_ref())
            .unwrap_or(&Value::Null);
        if actual != from {
            return Err(OpError::InvalidValue {
                kind: "domain_transition",
                field: "from",
                reason: format!("expected current value {actual}, got {from}"),
            });
        }
        if !self
            .allowed_transitions
            .iter()
            .any(|(allowed_from, allowed_to)| allowed_from == from && allowed_to == to)
        {
            return Err(OpError::InvalidValue {
                kind: "domain_transition",
                field: "transition",
                reason: format!("transition from {from} to {to} is not registered"),
            });
        }
        Ok(())
    }
}

pub const MEMBERSHIP_INITIAL_STATE: &str = "leave";

/// Resolve the unique confirmed membership sequence and return the Event that
/// most recently entered `target`.
pub fn membership_transition_heads_into(
    ops: &[crate::state_model::ordered_log::IssuedOp],
    target: &str,
) -> Result<Vec<crate::Hash>, String> {
    let mut current = Value::String(MEMBERSHIP_INITIAL_STATE.to_owned());
    let mut current_event = None;
    let mut seen = std::collections::BTreeMap::new();
    for issued in ops {
        let write = &issued.op;
        if let Some(previous) = seen.get(&write.event_id) {
            if previous != &write.op {
                return Err("one membership Event identity carries two transitions".to_owned());
            }
            continue;
        }
        let from =
            write.op.from.as_ref().ok_or_else(|| {
                format!("membership Event {} omits transition.from", write.event_id)
            })?;
        let to =
            write.op.to.as_ref().ok_or_else(|| {
                format!("membership Event {} omits transition.to", write.event_id)
            })?;
        if write.op.op_type != LatticeOpType::Transition || from != &current {
            return Err(format!(
                "membership Event {} is not valid at confirmed value {current}",
                write.event_id
            ));
        }
        current = to.clone();
        current_event = Some(write.event_id.clone());
        seen.insert(write.event_id.clone(), write.op.clone());
    }
    if current.as_str() == Some(target) {
        Ok(current_event
            .into_iter()
            .map(|event_id| event_id.event_digest())
            .collect())
    } else {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn transition_rule_checks_the_actual_pre_state() {
        let rule = DomainTransitionRule::new(vec![(json!("leave"), json!("join"))])
            .with_initial(json!("leave"));
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            from: Some(json!("leave")),
            to: Some(json!("join")),
            ..LatticeOp::empty()
        };
        rule.validate(None, &op).unwrap();
        assert!(rule.validate(Some(&json!("join")), &op).is_err());
    }
}
