//! Contact event payloads.

use crate::contact_operations::{ContactPeer, ContactScope};
use crate::internal_prelude::*;

fn serialize_initial_version<S: serde::Serializer>(
    version: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    if *version != 1 {
        return Err(serde::ser::Error::custom(
            "contact accepted version must be exactly 1",
        ));
    }
    serializer.serialize_u64(*version)
}

fn deserialize_initial_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    let version = u64::deserialize(deserializer)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "contact accepted version must be exactly 1",
        ));
    }
    Ok(version)
}

fn serialize_successor_version<S: serde::Serializer>(
    version: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    if *version < 2 {
        return Err(serde::ser::Error::custom(
            "contact tombstone version must be at least 2",
        ));
    }
    serializer.serialize_u64(*version)
}

fn deserialize_successor_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    let version = u64::deserialize(deserializer)?;
    if version < 2 {
        return Err(serde::de::Error::custom(
            "contact tombstone version must be at least 2",
        ));
    }
    Ok(version)
}

include!("generated/contact_contracts.rs");
