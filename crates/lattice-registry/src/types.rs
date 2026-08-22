pub use arkret_schema::Criticality;
use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_state::state::BottomMode;
use serde_json::Value;

/// Stable identification of the logical cell this [`LatticeKind`] drives.
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

/// Bottom-handling policy for a cell family.
///
/// - `Reject`: when the Lattice's `join` returns a structured `Bottom`, the receiver MUST
///   quarantine the resolved cell and emit `bottom_diagnostics` events. Lattice queries on this
///   cell return `bottom` rather than choosing a winner. This is the v1 default for safety-critical
///   cells (capability, consent, notary).
/// - `Expose`: callers are expected to render the multi-value set directly (e.g. UI shows "two
///   concurrent edits, please reconcile" rather than blocking). Suitable for advisory cells (Strand
///   titles, user profile fields).
/// - `Inert`: the lattice's join cannot produce Bottom. If a stored Bottom is nevertheless
///   observed, it represents an implementation invariant failure and is handled fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomPolicy {
    Reject,
    Expose,
    Inert,
}

pub(crate) fn generated_lattice(cell_family: &str) -> SdkLatticeKind {
    crate::generated::SPEC_LATTICE_BINDINGS
        .iter()
        .find_map(|(family, lattice, _)| (*family == cell_family).then_some(*lattice))
        .unwrap_or_else(|| panic!("typed lattice adapter {cell_family} has no generated binding"))
}

pub(crate) fn generated_bottom_policy(cell_family: &str) -> BottomPolicy {
    let mode = crate::generated::SPEC_LATTICE_BINDINGS
        .iter()
        .find_map(|(family, _, bottom)| (*family == cell_family).then_some(*bottom))
        .unwrap_or_else(|| panic!("typed lattice adapter {cell_family} has no generated binding"));
    match mode {
        BottomMode::Reject => BottomPolicy::Reject,
        BottomMode::Expose => BottomPolicy::Expose,
        BottomMode::Inert => BottomPolicy::Inert,
    }
}

impl BottomPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Expose => "expose",
            Self::Inert => "inert",
        }
    }

    /// Translate to the SDK state-res `BottomMode` that the
    /// `CellRegistry` uses to drive Move/Seal receive-pipeline
    /// bottom handling. The two are 1:1 by design.
    pub fn to_sdk_bottom_mode(self) -> BottomMode {
        match self {
            Self::Reject => BottomMode::Reject,
            Self::Expose => BottomMode::Expose,
            Self::Inert => BottomMode::Inert,
        }
    }
}

/// Errors a [`LatticeKind`] can raise during subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LatticeKindError {
    /// The Move's effects[] is missing the typed field used to derive the
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
    /// The cell_family declared by a Move effect doesn't match this
    /// `LatticeKind`. The dispatcher MUST route to a different impl.
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

impl std::fmt::Display for LatticeKindError {
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
                    "cell_family `{observed}` is not handled by this LatticeKind ({declared})"
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

impl std::error::Error for LatticeKindError {}

/// One canonical Arkret cell-family implementation.
///
/// Each impl owns one `cell_family` (e.g. `ak.component.consent.v1`),
/// declares the lattice algebra that resolves it (one of the six
/// spec-normative lattices from `arkret_state::lattice::LatticeKind`), and
/// exposes subject-derivation + post-resolution validation hooks.
/// Move/Seal receive pipeline iterates sealed Moves, groups effects
/// by `(cell_family, cell_subject)`, and dispatches to the matching
/// `LatticeKind` for per-cell `Lattice::join`.
pub trait LatticeKind: Send + Sync {
    /// Stable cell-family id. Move effects route to this `LatticeKind`
    /// when the effect's `cell` ref has this family path.
    fn cell_family(&self) -> &'static str;

    /// Which of the six normative lattices drives this family. The SDK's
    /// `crate::lattice` module provides the runtime impl.
    fn lattice(&self) -> SdkLatticeKind;

    /// `reject` → quarantine on Bottom (default, safety-critical cells);
    /// `expose` → render multi-value directly (advisory cells).
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    /// Component metadata for extension handling.
    fn component(&self) -> ComponentDescriptor;

    /// Derive the cell subject from a Move effect's typed fields.
    fn subject_for_effect(
        &self,
        _effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        Ok(None)
    }

    /// Derive the subject with the Event fields available to registry contracts
    /// whose subject does not live in the payload.
    fn subject_for_event(
        &self,
        _event_kind: &str,
        _envelope_event_id: &arkret_wire::EventId,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        self.subject_for_effect(effect_payload)
    }
}
