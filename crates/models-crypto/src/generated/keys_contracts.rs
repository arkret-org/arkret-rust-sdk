// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/keys-operations.schema.json
// sha256=63e01fdb55f85564c68436b3405091890fe2f5a141f77dbe50aa67925c48626c
//
// Bindings: tools/closed-model-bindings.json
// sha256=c5c717d42040392233cf38e4f3236cfeed2d38c2b642d4cf765ba04cf371a3ee

/// Counterpart:
/// `keys-operations.schema.json#/$defs/device_projection_attestation_core/properties/
/// authorization_window`. Exact original device grant window, independent of current-query cache
/// TTL. `keys-operations.schema.json#/$defs/device_projection_attestation_core/properties/
/// authorization_window`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizationWindow {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/device_projection_attestation_core`.
/// Origin Station assertion that one exact device projection is the
/// account's current accepted one.
///
/// This is the whole verification closure of the cross-principal `keys/query`
/// surface. It replaces replaying the PCR genesis and authorization history:
/// that material is account-internal governance,
/// a relationship-gated third party has no business holding it, and the schema
/// never carried it in the first place, so the old closure was unexecutable on
/// the wire. Mirrors
/// `keys-operations.schema.json#/$defs/device_projection_attestation_core`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProjectionAttestationCore {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    pub device_status: DeviceStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authorization_window: DeviceAuthorizationWindow,
}

/// Counterpart: `keys-operations.schema.json#/$defs/verified_device_projection`.
/// Restricted device projection a client receives from its *own* authenticated
/// Station on the self `keys/query` surface.
///
/// The values are the ones the returning Station read out of the origin
/// Station's verified [`DeviceProjectionAttestation`]. The row therefore
/// carries no origin proof and no wrapper whose only job was to verify that
/// proof, and a client MUST NOT treat this projection as portable evidence
/// about the origin. `account_id` and `device_id` are deliberately absent:
/// they are the enclosing [`QueryAccountDeviceEntry::account_id`] and the
/// `device_keys` map key, and the returning Station MUST have checked that the
/// verified attestation named exactly that pair before projecting the row.
/// Mirrors `keys-operations.schema.json#/$defs/verified_device_projection`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDeviceProjection {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    pub device_status: DeviceStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authorization_window: DeviceAuthorizationWindow,
}

/// Counterpart: `keys-operations.schema.json#/$defs/query_device_record`.
/// Per-`(account_id, device_id)` entry in [`KeysQueryOutcome::device_keys`],
/// the client-facing self surface.
///
/// Every field is required. A device whose generation is fenced or conflicted,
/// or which is revoked, is not degraded into a partial row: it is omitted from
/// `device_keys` or reported through the non-enumerating `failures` shape, so
/// an incomplete row can never be mistaken for a usable one. `account_id` and
/// `device_id` are the map keys, not row fields. This is deliberately a
/// different type from [`PeerQueryDeviceRecord`]: the client's Station already
/// verified the origin attestation, so the client gets the restricted
/// projection and never the origin proof. Mirrors
/// `keys-operations.schema.json#/$defs/query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceRecord {
    pub signer_evidence_ref: arkret_wire::SignerEvidenceRef,
    pub algorithms: AlgorithmKeyRecords,
    pub trust_algorithms: Vec<NonEmptyString>,
    pub device_projection: VerifiedDeviceProjection,
}

/// Counterpart: `keys-operations.schema.json#/$defs/peer_query_device_record`.
/// Per-`(account_id, device_id)` entry in
/// [`PeerKeysQueryOutcome::device_keys`], the Station-to-Station surface.
///
/// Every returned row is complete and attested: the origin Station signs the
/// exact projection, so the requesting Station can verify the row itself. A
/// Station MUST NOT turn an unverified peer row into a client result by
/// dropping its proof. Mirrors
/// `keys-operations.schema.json#/$defs/peer_query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryDeviceRecord {
    pub signer_evidence_ref: arkret_wire::SignerEvidenceRef,
    pub algorithms: AlgorithmKeyRecords,
    pub trust_algorithms: Vec<NonEmptyString>,
    pub device_projection_attestation: DeviceProjectionAttestation,
}

/// Counterpart: `keys-operations.schema.json#/$defs/query_account_device_entries/items`.
/// One self-surface device-key result group per exact `AccountId`. Item of
/// `keys-operations.schema.json#/$defs/query_account_device_entries/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAccountDeviceEntry {
    pub account_id: AccountId,
    pub device_keys: QueryDeviceKeys,
}

/// Counterpart: `keys-operations.schema.json#/$defs/peer_query_account_device_entries/items`.
/// One Station-to-Station device-key result group per exact `AccountId`. Item
/// of `keys-operations.schema.json#/$defs/peer_query_account_device_entries/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryAccountDeviceEntry {
    pub account_id: AccountId,
    pub device_keys: PeerQueryDeviceKeys,
}

/// Counterpart: `keys-operations.schema.json#/$defs/human_event_authorization`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEventAuthorization {
    pub event_id: EventId,
    pub verification_method: arkret_wire::DidUrl,
    pub destination_service_id: arkret_wire::DidCoreId,
    pub forward_body_digest: Hash,
    pub authorization_ref: arkret_wire::CommittedEventRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: arkret_wire::CurrentRevision,
    pub governance_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/forward_device_projection_attestation_core`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDeviceProjectionAttestationCore {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    pub device_status: DeviceStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authorization_window: DeviceAuthorizationWindow,
    pub event_authorization: HumanEventAuthorization,
}

/// Counterpart: `keys-operations.schema.json#/$defs/forward_device_projection_attestation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDeviceProjectionAttestation {
    pub attestation: ForwardDeviceProjectionAttestationCore,
    pub proof: ProtocolSignature,
}
