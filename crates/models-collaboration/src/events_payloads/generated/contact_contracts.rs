// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=8b8279174d914abd886fafb22ec9d9cfaf6b061168fb526c3200bd83f23b6fc2
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

/// Counterpart: `event-payload.schema.json#/$defs/contact_accepted_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    #[serde(
        serialize_with = "serialize_initial_version",
        deserialize_with = "deserialize_initial_version"
    )]
    pub version: u64,
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub previous_terminal_contact_round_id: Option<Hash>,
    pub granted_to_peer_scopes: Vec<ContactScope>,
}

/// Counterpart: `event-payload.schema.json#/$defs/contact_rejected_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub peer: ContactPeer,
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/contact_requested_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestedPayload {
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    pub introduction_evidence_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub previous_terminal_contact_round_id: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub message: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/contact_tombstoned_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactTombstonedPayload {
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    #[serde(
        serialize_with = "serialize_successor_version",
        deserialize_with = "deserialize_successor_version"
    )]
    pub version: u64,
    pub predecessor_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}
