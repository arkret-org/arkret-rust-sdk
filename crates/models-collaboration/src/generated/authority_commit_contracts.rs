// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=1d714ef5fe85dd72cdd39c417a69c70e3c731a324fc62f6d234cd6e8768c4815
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `authority-commit-operations.schema.json#/$defs/mls_genesis_material`.
/// Raw epoch-0 public material of one forwarded `ak.mls.genesis`
/// (`authority-commit-operations.schema.json#/$defs/mls_genesis_material`).
/// The signed Genesis refs are the only digest carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisMaterial {
    pub group_info_bytes_b64: String,
    pub ratchet_tree_bytes_b64: String,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/account_device_historical_signer_fact`.
/// Immutable authorization source, with no target Commit coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceHistoricalSignerFact {
    pub event_id: EventId,
    #[serde(deserialize_with = "deserialize_signing_account_actor")]
    pub actor: ActorId,
    pub device_id: arkret_wire::DeviceId,
    pub verification_method: DidUrl,
    pub key: ResolvedSignerKey,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/historical_producer_signer_fact_entry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalProducerSignerFactEntry {
    pub target: arkret_wire::CommittedEventRef,
    pub producer_signer_fact: HistoricalProducerSignerFact,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/peer_stream_scan_outcome`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStreamScanOutcome {
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub readable_floor: Option<arkret_wire::ReadableFloor>,
    pub truncated: bool,
    pub producer_signer_facts: Vec<HistoricalProducerSignerFactEntry>,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/handoff_request`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffRequest {
    pub handoff: RealmAuthorityHandoff,
    pub final_stream_heads: Vec<CommitStreamHead>,
    pub snapshot: RealmStateSnapshot,
    pub authority_bundle: RealmAuthorityBundle,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub historical_signer_facts: Option<Vec<HistoricalProducerSignerFactEntry>>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_private_state: Option<PcrPrivateHandoffManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub management_private_state: Option<ManagementPrivateHandoffManifest>,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/committed_event_submission`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEventSubmission {
    pub event_submission: EventAdmissionSubmission,
    pub source_commit: RealmCommit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub genesis_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub welcomes: Option<Vec<MlsWelcomeDelivery>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub producer_signer_fact: Option<HistoricalProducerSignerFact>,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/pcr_private_handoff_manifest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPrivateHandoffManifest {
    pub realm_id: RealmId,
    pub holder_account_id: arkret_wire::AccountId,
    pub governance_generation: u64,
    pub effective_stream_head: CommitStreamHead,
    pub nonce: String,
    pub state_digest: Hash,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/management_private_handoff_manifest`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementPrivateHandoffManifest {
    pub realm_id: RealmId,
    pub governance_generation: u64,
    pub final_stream_heads_digest: Hash,
    pub nonce: String,
    pub state_digest: Hash,
}
