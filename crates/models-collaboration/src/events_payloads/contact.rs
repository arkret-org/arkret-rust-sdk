//! Contact event payloads.

use crate::contact_operations::{ContactPeer, ContactScopes};
use crate::internal_prelude::*;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
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
    pub previous_terminal_basis_id: Option<Hash>,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn accepted_value() -> Value {
        json!({
            "peer": {
                "kind": "human",
                "principal_id": "ak:did_core:webvh:z6mkfixturepeer"
            },
            "basis_id": format!("sha256:{}", "a".repeat(64)),
            "version": 1,
            "request_event_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "request_acceptance_receipt_digest": format!("sha256:{}", "b".repeat(64)),
            "previous_terminal_basis_id": format!("sha256:{}", "c".repeat(64)),
            "granted_to_peer_scopes": ["direct_message"]
        })
    }

    fn assert_obsolete_field_rejected<T: serde::de::DeserializeOwned>(
        mut value: Value,
        current: &str,
        obsolete: &str,
    ) {
        let object = value.as_object_mut().unwrap();
        let member = object.remove(current).unwrap();
        object.insert(obsolete.to_owned(), member);
        let error = serde_json::from_value::<T>(value)
            .err()
            .expect("obsolete Contact field name must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn contact_accepted_uses_final_basis_field_names() {
        let payload: ContactAcceptedPayload = serde_json::from_value(accepted_value()).unwrap();
        assert_eq!(
            payload.basis_id.as_str(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(payload.previous_terminal_basis_id.is_some());

        let encoded = serde_json::to_value(payload).unwrap();
        assert!(encoded.get("basis_id").is_some());
        assert!(encoded.get("previous_terminal_basis_id").is_some());
        assert!(encoded.get("contact_round_id").is_none());
        assert!(encoded.get("previous_terminal_contact_round_id").is_none());
    }

    #[test]
    fn contact_accepted_rejects_obsolete_round_field_names() {
        let mut value = accepted_value();
        let object = value.as_object_mut().unwrap();
        let basis_id = object.remove("basis_id").unwrap();
        let previous_terminal_basis_id = object.remove("previous_terminal_basis_id").unwrap();
        object.insert("contact_round_id".to_owned(), basis_id);
        object.insert(
            "previous_terminal_contact_round_id".to_owned(),
            previous_terminal_basis_id,
        );
        let error = serde_json::from_value::<ContactAcceptedPayload>(value)
            .expect_err("obsolete Contact round field names must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn remaining_contact_event_payloads_use_final_basis_field_names() {
        let requested = json!({
            "peer": {"kind": "human", "principal_id": "ak:did_core:webvh:z6mkfixturepeer"},
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": format!("sha256:{}", "d".repeat(64)),
            "previous_terminal_basis_id": format!("sha256:{}", "e".repeat(64))
        });
        let requested_payload: ContactRequestedPayload =
            serde_json::from_value(requested.clone()).unwrap();
        assert!(requested_payload.previous_terminal_basis_id.is_some());
        assert_obsolete_field_rejected::<ContactRequestedPayload>(
            requested,
            "previous_terminal_basis_id",
            "previous_terminal_contact_round_id",
        );

        let tombstoned = json!({
            "peer": {"kind": "human", "principal_id": "ak:did_core:webvh:z6mkfixturepeer"},
            "basis_id": format!("sha256:{}", "f".repeat(64)),
            "version": 2,
            "predecessor_event_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
        });
        let tombstoned_payload: ContactTombstonedPayload =
            serde_json::from_value(tombstoned.clone()).unwrap();
        assert_eq!(
            tombstoned_payload.basis_id.as_str(),
            format!("sha256:{}", "f".repeat(64))
        );
        assert_obsolete_field_rejected::<ContactTombstonedPayload>(
            tombstoned,
            "basis_id",
            "contact_round_id",
        );

        let scope_update = json!({
            "schema": "ak.schema.contact_scope_update.v1",
            "peer": {"kind": "human", "principal_id": "ak:did_core:webvh:z6mkfixturepeer"},
            "basis_id": format!("sha256:{}", "1".repeat(64)),
            "version": 2,
            "predecessor_event_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "granted_to_peer_scopes": ["direct_message"]
        });
        let scope_payload: crate::contact_operations::ContactScopeUpdatePayload =
            serde_json::from_value(scope_update.clone()).unwrap();
        assert_eq!(
            scope_payload.basis_id.as_str(),
            format!("sha256:{}", "1".repeat(64))
        );
        assert_obsolete_field_rejected::<crate::contact_operations::ContactScopeUpdatePayload>(
            scope_update,
            "basis_id",
            "contact_round_id",
        );
    }
}
