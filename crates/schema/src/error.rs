use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SchemaError>;

/// Stable high-level reason for a schema-validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SchemaValidationReason {
    InstanceInvalid,
}

/// Machine-readable location and keyword for one failed schema assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaValidationIssue {
    pub schema_id: String,
    pub instance_pointer: String,
    pub schema_pointer: String,
    pub keyword: String,
    pub reason: SchemaValidationReason,
    /// Human-readable detail with the rejected instance value masked.
    pub message: String,
}

impl fmt::Display for SchemaValidationIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "schema '{}' validation failed at instance '{}' against '{}' ({}): {}",
            self.schema_id, self.instance_pointer, self.schema_pointer, self.keyword, self.message
        )
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SchemaError {
    #[error("schema validation failed: {0}")]
    Protocol(String),

    #[error("{0}")]
    Validation(SchemaValidationIssue),
}

pub type Error = SchemaError;
