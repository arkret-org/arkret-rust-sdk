//! Schema registry and spec-drift helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use arkret_wire::SchemaId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod error;
mod event_cell_contract;
mod event_validation;
pub mod generated;
mod prepared_event;
pub mod protocol;

pub use arkret_wire::{CORE_SCHEMA_PROFILE, events};
pub use error::{Error, Result, SchemaError, SchemaValidationIssue, SchemaValidationReason};
pub use event_cell_contract::{
    EventCellContractContext, EventCellContractError, FrozenPreState, batch_add_tag,
    derived_object_id, or_set_dot, project_registered_cell_writes,
    project_registered_cell_writes_with_pre_state, validate_registered_cell_plane_in_context,
    validate_registered_cell_writes, validate_registered_cell_writes_in_context,
};
pub use event_validation::{EventSchemaExt, validate_event_for_submit, validate_event_wire_schema};
pub use generated::*;
pub use prepared_event::{
    PreparedControlMove, PreparedDataEvent, PreparedEventPlane, PreparedNonReducerEvent,
    PreparedStandardEvent,
};
pub use protocol::{
    GeneratedObjectShape, ProtocolSchemaRegistry, ProtocolSchemaRegistry as Registry,
    SchemaFieldSummary, SchemaValidatorStats, SchemaValueTypeSummary,
};

mod artifacts;
mod catalog;
pub mod conformance;
mod payloads;
pub mod sdk_conformance;

pub use artifacts::*;
pub use catalog::*;
pub use conformance::*;
pub use payloads::*;

pub const CORE_SCHEMA_IDS: &[&str] = &[
    SchemaId::CURSOR_V1,
    SchemaId::STRAND_V1,
    SchemaId::SPACE_V1,
    SchemaId::VIEW_V1,
    SchemaId::EVENT_V1,
    SchemaId::EVENT_PAYLOAD_V1,
    SchemaId::SEAL_V1,
    SchemaId::BOTTOM_V1,
    SchemaId::SNAPSHOT_V1,
    SchemaId::CAPABILITY_V1,
    SchemaId::PERSONAL_PRODUCTIVITY_V1,
    SchemaId::DRAFT_SYNC_V1,
    SchemaId::CALENDAR_EVENT_V1,
    SchemaId::DISAPPEARING_MESSAGES_V1,
    SchemaId::SEARCH_SERVICE_V1,
    SchemaId::ENCRYPTED_ENVELOPE_V1,
    SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1,
];
