//! Schema registry and spec-drift helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CALENDAR_EVENT_SCHEMA,
    CAPABILITY_SCHEMA, CORE_SCHEMA_PROFILE, CURSOR_SCHEMA, DISAPPEARING_MESSAGES_SCHEMA,
    DRAFT_SYNC_SCHEMA, ENCRYPTED_ENVELOPE_SCHEMA, EVENT_PAYLOAD_SCHEMA, EVENT_SCHEMA, Error,
    STRAND_SCHEMA, GeneratedSchemaValidator, PERSONAL_PRODUCTIVITY_SCHEMA, ProtocolSchemaRegistry,
    REALM_JOIN_CANDIDATE_SCHEMA, Result, SEARCH_SERVICE_SCHEMA, SNAPSHOT_SCHEMA, SPACE_SCHEMA,
    VIEW_SCHEMA,
};
pub use crate::{
    GeneratedSchemaField, GeneratedSchemaValueType, ProtocolSchemaRegistry as Registry,
};

mod artifacts;
mod catalog;
mod payloads;
#[cfg(test)]
mod tests;

pub use artifacts::*;
pub use catalog::*;
pub use payloads::*;

pub mod protocol {
    pub use crate::{
        ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CALENDAR_EVENT_SCHEMA,
        CAPABILITY_SCHEMA, CORE_SCHEMA_PROFILE, CURSOR_SCHEMA, DISAPPEARING_MESSAGES_SCHEMA,
        DRAFT_SYNC_SCHEMA, ENCRYPTED_ENVELOPE_SCHEMA, EVENT_PAYLOAD_SCHEMA, EVENT_SCHEMA,
        STRAND_SCHEMA, GeneratedSchemaField, GeneratedSchemaValidator, GeneratedSchemaValueType,
        PERSONAL_PRODUCTIVITY_SCHEMA, ProtocolSchemaRegistry, SEARCH_SERVICE_SCHEMA,
        SNAPSHOT_SCHEMA, SPACE_SCHEMA, VIEW_SCHEMA,
    };
}

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
