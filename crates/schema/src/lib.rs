//! Schema registry and spec-drift helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod error;
mod event_cell_contract;
mod event_validation;
pub mod generated;
pub mod protocol;

pub use arkret_wire::{
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CALENDAR_EVENT_SCHEMA,
    CAPABILITY_SCHEMA, CORE_SCHEMA_PROFILE, CURSOR_SCHEMA, DISAPPEARING_MESSAGES_SCHEMA,
    DRAFT_SYNC_SCHEMA, ENCRYPTED_ENVELOPE_SCHEMA, EVENT_PAYLOAD_SCHEMA, EVENT_SCHEMA,
    INVITE_DELIVERY_REQUEST_SCHEMA, INVITE_RECEIVE_POLICY_SCHEMA, MORPH_SCHEMA,
    PERSONAL_PRODUCTIVITY_SCHEMA, PRINCIPAL_LOCATOR_SCHEMA, PROFILE_ATTESTED_AUDIT_E2EE,
    PROFILE_DIRECTORY_SERVICE, PROFILE_DISCLOSED_AUDIT_E2EE, REALM_JOIN_CANDIDATE_SCHEMA,
    SEARCH_SERVICE_SCHEMA, SNAPSHOT_SCHEMA, SPACE_SCHEMA, STRAND_SCHEMA, VIEW_SCHEMA, events,
};
pub use error::{Error, Result, SchemaError};
pub use event_cell_contract::{
    EventCellContractContext, EventCellContractError, validate_registered_cell_writes,
    validate_single_target_append_event_contract, validate_single_target_set_event_contract,
    validate_single_target_set_event_contract_in_context,
};
pub use event_validation::{EventSchemaExt, validate_event_for_submit, validate_event_wire_schema};
pub use generated::*;
pub use protocol::{
    GeneratedSchemaField, GeneratedSchemaValidator, GeneratedSchemaValueType,
    ProtocolSchemaRegistry, ProtocolSchemaRegistry as Registry,
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
    CURSOR_SCHEMA,
    STRAND_SCHEMA,
    SPACE_SCHEMA,
    VIEW_SCHEMA,
    EVENT_SCHEMA,
    EVENT_PAYLOAD_SCHEMA,
    ANCHOR_SCHEMA,
    BOTTOM_SCHEMA,
    SNAPSHOT_SCHEMA,
    CAPABILITY_SCHEMA,
    PERSONAL_PRODUCTIVITY_SCHEMA,
    DRAFT_SYNC_SCHEMA,
    CALENDAR_EVENT_SCHEMA,
    DISAPPEARING_MESSAGES_SCHEMA,
    SEARCH_SERVICE_SCHEMA,
    ENCRYPTED_ENVELOPE_SCHEMA,
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
];
