//! Contact event payloads.

use crate::internal_prelude::*;
use crate::protocol_journey::{ContactPeer, ContactScopes};

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub peer: ContactPeer,
    pub basis_id: Hash,
    #[serde(
        serialize_with = "serialize_initial_version",
        deserialize_with = "deserialize_initial_version"
    )]
    pub version: u64,
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
    pub granted_to_peer_scopes: ContactScopes,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub peer: ContactPeer,
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestedPayload {
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: ContactScopes,
    pub introduction_evidence_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactTombstonedPayload {
    pub peer: ContactPeer,
    pub basis_id: Hash,
    #[serde(
        serialize_with = "serialize_successor_version",
        deserialize_with = "deserialize_successor_version"
    )]
    pub version: u64,
    pub predecessor_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

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
