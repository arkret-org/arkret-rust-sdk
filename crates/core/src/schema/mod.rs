//! Schema registry, compatibility contracts and spec-drift helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    AGENT_AUTHORITY_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CAPABILITY_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA, CURSOR_SCHEMA, ENCRYPTED_PAYLOAD_SCHEMA, EVENT_PAYLOAD_SCHEMA,
    EVENT_SCHEMA, Error, FLOW_SCHEMA, GeneratedSchemaValidator, PLACE_SCHEMA,
    ProtocolSchemaRegistry, Result, SCHEMA_COMPATIBILITY_PROFILE, SNAPSHOT_SCHEMA,
    SchemaCompatibilityEntry, SchemaCompatibilityTable, VIEW_SCHEMA,
    schema_version_compatibility_table,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
        AGENT_AUTHORITY_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CAPABILITY_SCHEMA,
        CLIENT_SYNC_RESPONSE_SCHEMA, CURSOR_SCHEMA, ENCRYPTED_PAYLOAD_SCHEMA, EVENT_PAYLOAD_SCHEMA,
        EVENT_SCHEMA, FLOW_SCHEMA, GeneratedSchemaField, GeneratedSchemaValidator,
        GeneratedSchemaValueType, PLACE_SCHEMA, ProtocolSchemaRegistry,
        SCHEMA_COMPATIBILITY_PROFILE, SNAPSHOT_SCHEMA, SchemaCompatibilityEntry,
        SchemaCompatibilityTable, VIEW_SCHEMA, schema_version_compatibility_table,
    };
}

pub const CORE_SCHEMA_IDS: &[&str] = &[
    CURSOR_SCHEMA,
    FLOW_SCHEMA,
    PLACE_SCHEMA,
    VIEW_SCHEMA,
    EVENT_SCHEMA,
    EVENT_PAYLOAD_SCHEMA,
    ANCHOR_SCHEMA,
    AGENT_AUTHORITY_SCHEMA,
    BOTTOM_SCHEMA,
    SNAPSHOT_SCHEMA,
    CAPABILITY_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA,
];

pub fn compatibility_table() -> SchemaCompatibilityTable {
    schema_version_compatibility_table()
}
