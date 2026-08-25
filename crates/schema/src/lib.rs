//! Schema registry and spec-drift helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod error;
mod event_cell_contract;
mod event_validation;
pub mod generated;
mod prepared_event;
pub mod protocol;

pub use arkret_wire::events;
pub use error::{Result, SchemaError, SchemaValidationIssue, SchemaValidationReason};
pub use event_cell_contract::{
    CapabilityAuthorityAudit, CapabilityAuthorityAuditIndex, CapabilityAuthorityProjectionError,
    EventCellContractContext, EventCellContractError, FrozenPreState, batch_add_tag,
    derive_capability_authority_audit, derived_object_id, derived_object_id_for_kind,
    derived_object_ids, derived_object_ids_for_kind, event_derived_id_kinds_for_kind, or_set_dot,
    project_registered_cell_writes, project_registered_cell_writes_with_authority_resolver,
    project_registered_cell_writes_with_pre_state,
    project_registered_cell_writes_with_pre_state_and_authority_resolver,
    project_registered_operation_writes,
    project_registered_operation_writes_with_authority_resolver,
    validate_registered_cell_plane_in_context, validate_registered_cell_writes,
    validate_registered_cell_writes_in_context,
};
pub use event_validation::{EventSchemaExt, validate_event_for_submit, validate_event_wire_schema};
pub use generated::*;
pub use prepared_event::{
    PreparedControlMove, PreparedDataEvent, PreparedEventPlane, PreparedNonReducerEvent,
    PreparedStandardEvent,
};
pub use protocol::{
    GeneratedObjectShape, ProtocolSchemaRegistry, SchemaFieldSummary, SchemaValidatorStats,
    SchemaValueTypeSummary,
};

mod artifacts;
pub mod conformance;
mod payload_validator_profiles;
mod payloads;
pub mod sdk_conformance;

pub use artifacts::*;
pub use conformance::*;
pub use payload_validator_profiles::*;
pub use payloads::*;
