// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

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
