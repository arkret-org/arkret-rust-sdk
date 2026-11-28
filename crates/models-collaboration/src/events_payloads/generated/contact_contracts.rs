// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/principal-operations.schema.json
// sha256=d20daf5798bec9d03e5c36c21b63f77844c021e545c55d3d7f85ddb2377d2217
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Input: schemas/common-ids.schema.json
// sha256=dadc47194ca411baa38f3a7f44ae8115bec7cbcd98e68a2fffd389fdfc039713
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `event-payload.schema.json#/$defs/contact_accepted_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub trust_domain_id: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub initial_contact_round_id: Option<Hash>,
    #[serde(
        serialize_with = "serialize_contact_version",
        deserialize_with = "deserialize_contact_version"
    )]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub predecessor_event_ref: Option<EventId>,
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
    pub granted_to_peer_scopes: Vec<ContactScope>,
}

/// Counterpart: `event-payload.schema.json#/$defs/contact_rejected_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub trust_domain_id: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub initial_contact_round_id: Option<Hash>,
    #[serde(
        serialize_with = "serialize_contact_version",
        deserialize_with = "deserialize_contact_version"
    )]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub predecessor_event_ref: Option<EventId>,
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
    pub trust_domain_id: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub initial_contact_round_id: Option<Hash>,
    #[serde(
        serialize_with = "serialize_contact_version",
        deserialize_with = "deserialize_contact_version"
    )]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub predecessor_event_ref: Option<EventId>,
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    pub introduction_evidence_digest: Hash,
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
    pub trust_domain_id: TrustDomainId,
    pub initial_contact_round_id: Hash,
    #[serde(
        serialize_with = "serialize_contact_version",
        deserialize_with = "deserialize_contact_version"
    )]
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}
