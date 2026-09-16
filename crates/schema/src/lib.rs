//! Typed Arkret schema contracts and runtime validators.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

mod criticality;
mod error;
mod event_validation;
pub mod generated;
pub mod protocol;

pub use arkret_wire::events;
pub use criticality::Criticality;
pub use error::{Result, SchemaError, SchemaValidationIssue, SchemaValidationReason};
pub use event_validation::{EventSchemaExt, validate_event_for_submit, validate_event_wire_schema};
pub use generated::*;
pub use protocol::{
    GeneratedObjectShape, ProtocolSchemaRegistry, SchemaFieldSummary, SchemaValidatorStats,
    SchemaValueTypeSummary,
};

pub mod conformance;
mod payload_validator_profiles;
pub mod sdk_conformance;

pub use conformance::*;
pub use payload_validator_profiles::*;
