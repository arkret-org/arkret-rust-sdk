//! Contact event payloads.

use crate::contact_operations::{ContactPeer, ContactScope};
use crate::internal_prelude::*;

fn serialize_contact_version<S: serde::Serializer>(
    version: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    if *version == 0 || *version > 9_007_199_254_740_991 {
        return Err(serde::ser::Error::custom(
            "Contact version is outside the positive safe integer range",
        ));
    }
    serializer.serialize_u64(*version)
}
fn deserialize_contact_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    let version = u64::deserialize(deserializer)?;
    if version == 0 || version > 9_007_199_254_740_991 {
        return Err(serde::de::Error::custom(
            "Contact version is outside the positive safe integer range",
        ));
    }
    Ok(version)
}

include!("generated/contact_contracts.rs");
