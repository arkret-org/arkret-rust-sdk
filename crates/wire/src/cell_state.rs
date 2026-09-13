//! Complete canonical Cell states shared by snapshots and command commitments.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ActorId, CellRef, EventCellStateModel, EventId, Hash, Result, WireError};

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for EventCellStateModel {
    fn to_schema(_: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .enum_values(
                [
                    Self::CausalRegister,
                    Self::SequencedState,
                    Self::OrSet,
                    Self::OrderedLog,
                    Self::Counter,
                ]
                .iter()
                .map(|model| model.as_str()),
            )
            .into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCausalWinner {
    pub event_id: EventId,
    pub depth: u64,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCausalState {
    pub covered_event_ids: Vec<EventId>,
    pub winner: CanonicalCausalWinner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSequencedState {
    pub revision_event_id: EventId,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSetEntry {
    pub tag_id: String,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOrSetValue {
    pub adds: Vec<CanonicalSetEntry>,
    pub removed_tag_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOrSetState {
    pub value: CanonicalOrSetValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalLogEntry {
    pub event_digest: Hash,
    pub issuer_id: ActorId,
    pub issuer_seq: u64,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOrderedLogState {
    pub value: Vec<CanonicalLogEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCounterEntry {
    pub issuer_id: ActorId,
    pub positive: u64,
    pub negative: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCounterState {
    pub value: Vec<CanonicalCounterEntry>,
}

/// The family registry selects the state shape; producers cannot select a model.
/// Decode with `from_state_object` because empty log and counter arrays have the
/// same JSON shape and must be interpreted using the registered model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CanonicalCellState {
    CausalRegister(CanonicalCausalState),
    SequencedState(CanonicalSequencedState),
    OrSet(CanonicalOrSetState),
    OrderedLog(CanonicalOrderedLogState),
    Counter(CanonicalCounterState),
}

fn invalid(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

impl CanonicalCellState {
    pub fn state_model(&self) -> EventCellStateModel {
        match self {
            Self::CausalRegister(_) => EventCellStateModel::CausalRegister,
            Self::SequencedState(_) => EventCellStateModel::SequencedState,
            Self::OrSet(_) => EventCellStateModel::OrSet,
            Self::OrderedLog(_) => EventCellStateModel::OrderedLog,
            Self::Counter(_) => EventCellStateModel::Counter,
        }
    }

    pub fn to_state_object(&self) -> Value {
        serde_json::to_value(self).expect("canonical Cell state is JSON serializable")
    }

    pub fn from_state_object(model: EventCellStateModel, value: Value) -> Result<Self> {
        let state = match model {
            EventCellStateModel::CausalRegister => {
                Self::CausalRegister(serde_json::from_value(value)?)
            }
            EventCellStateModel::SequencedState => {
                Self::SequencedState(serde_json::from_value(value)?)
            }
            EventCellStateModel::OrSet => Self::OrSet(serde_json::from_value(value)?),
            EventCellStateModel::OrderedLog => Self::OrderedLog(serde_json::from_value(value)?),
            EventCellStateModel::Counter => Self::Counter(serde_json::from_value(value)?),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate_for_cell(&self, cell: &CellRef) -> Result<()> {
        if registered_cell_state_model(cell)? != self.state_model() {
            return Err(invalid(format!(
                "Cell {cell} state does not match its registered model"
            )));
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::CausalRegister(state) => {
                if state.covered_event_ids.is_empty()
                    || !state
                        .covered_event_ids
                        .windows(2)
                        .all(|p| p[0].token_bytes() < p[1].token_bytes())
                    || state.winner.depth > 9_007_199_254_740_991
                {
                    return Err(invalid(
                        "causal state requires nonempty sorted unique coverage and a JSON-safe winner depth",
                    ));
                }
                let covered: BTreeSet<_> = state.covered_event_ids.iter().collect();
                if !covered.contains(&state.winner.event_id) {
                    return Err(invalid("causal winner is absent from the Cell coverage"));
                }
            }
            Self::SequencedState(_) => {}
            Self::OrSet(state) => {
                if !state
                    .value
                    .adds
                    .windows(2)
                    .all(|p| p[0].tag_id < p[1].tag_id)
                    || !state.value.removed_tag_ids.windows(2).all(|p| p[0] < p[1])
                {
                    return Err(invalid("OR-set dots must be sorted and unique"));
                }
                for tag in state
                    .value
                    .adds
                    .iter()
                    .map(|entry| &entry.tag_id)
                    .chain(&state.value.removed_tag_ids)
                {
                    let (event, index) = tag
                        .rsplit_once(':')
                        .ok_or_else(|| invalid("invalid OR-set dot"))?;
                    EventId::new(event.to_owned())?;
                    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(invalid("invalid OR-set dot index"));
                    }
                }
            }
            Self::OrderedLog(state) => {
                let mut previous = None;
                let mut identities = BTreeSet::new();
                for entry in &state.value {
                    if entry.issuer_seq > 9_007_199_254_740_991
                        || !identities.insert(&entry.event_digest)
                    {
                        return Err(invalid(
                            "ordered log contains an invalid sequence or duplicate Event",
                        ));
                    }
                    let (suite, digest) = entry
                        .event_digest
                        .as_str()
                        .split_once(':')
                        .ok_or_else(|| invalid("invalid log digest"))?;
                    let key = (
                        entry.issuer_id.canonical_key()?,
                        entry.issuer_seq,
                        digest.to_owned(),
                        suite.to_owned(),
                    );
                    if previous.as_ref().is_some_and(|old| old >= &key) {
                        return Err(invalid("ordered log entries are not canonically sorted"));
                    }
                    previous = Some(key);
                }
            }
            Self::Counter(state) => {
                let mut previous = None;
                for entry in &state.value {
                    let key = entry.issuer_id.canonical_key()?;
                    if entry.positive > 9_007_199_254_740_991
                        || entry.negative > 9_007_199_254_740_991
                        || previous.as_ref().is_some_and(|old| old >= &key)
                    {
                        return Err(invalid(
                            "counter components must be exact nonnegative integers with unique sorted issuers",
                        ));
                    }
                    previous = Some(key);
                }
            }
        }
        Ok(())
    }
}

pub fn registered_cell_state_model(cell: &CellRef) -> Result<EventCellStateModel> {
    let parsed = crate::CellId::parse(cell.as_str()).map_err(|error| invalid(error.to_string()))?;
    let mut model = None;
    for write in crate::EVENT_KIND_DESCRIPTORS
        .iter()
        .flat_map(|descriptor| descriptor.cell_writes)
    {
        if write.cell_family.map(|family| family.as_str()) == Some(parsed.component()) {
            let declared = write
                .state_model
                .ok_or_else(|| invalid("registered Cell has no state model"))?;
            if model.is_some_and(|previous| previous != declared) {
                return Err(invalid("registered Cell has inconsistent state models"));
            }
            model = Some(declared);
        }
    }
    model.ok_or_else(|| invalid(format!("unregistered Cell {cell}")))
}
