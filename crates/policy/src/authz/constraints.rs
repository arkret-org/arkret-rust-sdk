use serde::{Deserialize, Serialize};

/// Duration used by the runtime grant projection for message edit and redact windows.
///
/// Canonical grant constraints are represented by
/// `arkret_models_collaboration::governance::grant_constraint::GrantConstraint`;
/// this compact value remains only because the service-side projection evaluates
/// those two windows without retaining the full wire constraint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintDuration {
    pub value: u64,
    /// Registered duration unit: `s`, `m`, `h`, or `d`.
    pub unit: String,
}
