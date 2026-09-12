pub use arkret_schema::Criticality;
use arkret_state::state_model::StateModelKind;
pub use arkret_wire::{EventCellBottom, EventCellExecution, EventCellValueShape};
use serde_json::Value;

/// Stable identification of the logical cell this [`CellFamilyAdapter`] drives.
/// Multiple kinds operating on the same cell (paired kinds, e.g.
/// `ak.capability.grant` + `ak.capability.revoke`) MUST share
/// `component_type` so the receiver treats them as supersedes on the
/// same cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentDescriptor {
    /// Stable URI in the `ak.component.<facet-path>.v<n>` namespace.
    pub component_type: &'static str,
    /// Monotonic version within the same `component_type`.
    pub component_version: u32,
    /// Receiver behaviour for unknown component_type/version.
    pub criticality: Criticality,
}

pub(crate) fn generated_state_model(cell_family: &str) -> StateModelKind {
    crate::generated::SPEC_STATE_MODEL_BINDINGS
        .iter()
        .find_map(|(family, _, state_model, ..)| (*family == cell_family).then_some(*state_model))
        .unwrap_or_else(|| panic!("typed cell adapter {cell_family} has no generated binding"))
}

pub(crate) fn generated_execution(cell_family: &str) -> EventCellExecution {
    crate::generated::SPEC_STATE_MODEL_BINDINGS
        .iter()
        .find_map(|(family, execution, ..)| (*family == cell_family).then_some(*execution))
        .unwrap_or_else(|| panic!("typed cell adapter {cell_family} has no generated binding"))
}

pub(crate) fn generated_value_shape(cell_family: &str) -> EventCellValueShape {
    crate::generated::SPEC_STATE_MODEL_BINDINGS
        .iter()
        .find_map(|(family, _, _, value_shape, _)| (*family == cell_family).then_some(*value_shape))
        .unwrap_or_else(|| panic!("typed cell adapter {cell_family} has no generated binding"))
}

pub(crate) fn generated_bottom_policy(cell_family: &str) -> Option<EventCellBottom> {
    crate::generated::SPEC_STATE_MODEL_BINDINGS
        .iter()
        .find_map(|(family, _, _, _, bottom)| (*family == cell_family).then_some(*bottom))
        .flatten()
}

/// Errors a [`CellFamilyAdapter`] can raise during subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellFamilyAdapterError {
    /// The Event write is missing the typed field used to derive the
    /// cell subject (e.g. `payload.strand_id` for a strand-position cell).
    MissingSubjectField {
        cell_family: &'static str,
        field: &'static str,
    },
    /// A tuple subject could not be encoded into its canonical hash form.
    InvalidCompositeSubject {
        cell_family: &'static str,
        reason: String,
    },
    /// The declared cell family doesn't match this adapter.
    UnknownCellFamily {
        observed: String,
        declared: &'static str,
    },
    /// The adapter was invoked for an Event kind outside its declared dispatch
    /// set.
    UnknownEventKind {
        observed: String,
        cell_family: &'static str,
    },
}

impl std::fmt::Display for CellFamilyAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSubjectField { cell_family, field } => {
                write!(
                    f,
                    "{cell_family} requires effect field `{field}` for cell subject"
                )
            }
            Self::InvalidCompositeSubject {
                cell_family,
                reason,
            } => write!(
                f,
                "{cell_family} composite cell subject could not be encoded: {reason}"
            ),
            Self::UnknownCellFamily { observed, declared } => {
                write!(
                    f,
                    "cell_family `{observed}` is not handled by this adapter ({declared})"
                )
            }
            Self::UnknownEventKind {
                observed,
                cell_family,
            } => write!(
                f,
                "event kind `{observed}` does not dispatch to cell family `{cell_family}`"
            ),
        }
    }
}

impl std::error::Error for CellFamilyAdapterError {}

/// One canonical Arkret cell-family implementation.
///
/// Each impl owns one `cell_family` (e.g. `ak.component.consent.v1`),
/// declares the state model and execution plane that resolve it, and exposes
/// subject derivation for typed Event writes.
pub trait CellFamilyAdapter: Send + Sync {
    /// Stable cell-family id.
    fn cell_family(&self) -> &'static str;

    /// Which normative state model drives this family.
    fn state_model(&self) -> StateModelKind;

    /// Whether writes are ordinary data or Seal-confirmed security state.
    fn execution(&self) -> EventCellExecution;

    /// The resolved value shape required by the registry contract.
    fn value_shape(&self) -> EventCellValueShape;

    /// `reject` → quarantine on Bottom (default, safety-critical cells);
    /// `expose` → render multi-value directly (advisory cells).
    fn bottom_policy(&self) -> Option<EventCellBottom> {
        None
    }

    /// Component metadata for extension handling.
    fn component(&self) -> ComponentDescriptor;

    /// Derive the cell subject from a Move effect's typed fields.
    fn subject_for_effect(
        &self,
        _effect_payload: &Value,
    ) -> Result<Option<String>, CellFamilyAdapterError> {
        Ok(None)
    }

    /// Derive the subject with the Event fields available to registry contracts
    /// whose subject does not live in the payload.
    fn subject_for_event(
        &self,
        _event_kind: &str,
        _envelope_event_id: &arkret_wire::EventId,
        effect_payload: &Value,
    ) -> Result<Option<String>, CellFamilyAdapterError> {
        self.subject_for_effect(effect_payload)
    }
}
