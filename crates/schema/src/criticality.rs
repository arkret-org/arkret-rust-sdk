use serde::{Deserialize, Serialize};

/// Closed receiver behavior for an unknown event component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    /// Fail closed when the component is unknown.
    Required,
    /// Warn and ignore the event when the component is unknown.
    Optional,
    /// Silently drop the event when the component is unknown.
    Ignore,
}
