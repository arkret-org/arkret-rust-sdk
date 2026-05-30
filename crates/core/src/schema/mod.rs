//! Schema registry and spec-drift helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CAPABILITY_SCHEMA,
    CORE_SCHEMA_PROFILE, CURSOR_SCHEMA, ENCRYPTED_PAYLOAD_SCHEMA, EVENT_PAYLOAD_SCHEMA,
    EVENT_SCHEMA, Error, FLOW_SCHEMA, GeneratedSchemaValidator, ProtocolSchemaRegistry,
    REALM_JOIN_CANDIDATE_SCHEMA, Result, SNAPSHOT_SCHEMA, SPACE_SCHEMA, VIEW_SCHEMA,
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
        ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, ANCHOR_SCHEMA, BOTTOM_SCHEMA, CAPABILITY_SCHEMA,
        CORE_SCHEMA_PROFILE, CURSOR_SCHEMA, ENCRYPTED_PAYLOAD_SCHEMA, EVENT_PAYLOAD_SCHEMA,
        EVENT_SCHEMA, FLOW_SCHEMA, GeneratedSchemaField, GeneratedSchemaValidator,
        GeneratedSchemaValueType, ProtocolSchemaRegistry, SNAPSHOT_SCHEMA, SPACE_SCHEMA,
        VIEW_SCHEMA,
    };
}

pub const CORE_SCHEMA_IDS: &[&str] = &[
    CURSOR_SCHEMA,
    FLOW_SCHEMA,
    SPACE_SCHEMA,
    VIEW_SCHEMA,
    EVENT_SCHEMA,
    EVENT_PAYLOAD_SCHEMA,
    ANCHOR_SCHEMA,
    BOTTOM_SCHEMA,
    SNAPSHOT_SCHEMA,
    CAPABILITY_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
];
