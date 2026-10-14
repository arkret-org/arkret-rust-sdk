// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=c33d3a191a8ed8fe663386999548cfc5d4fc93f40cae2a4bf1835018a48527bd
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

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

/// Counterpart: `authority-commit-operations.schema.json#/$defs/human_historical_signer_fact`.
/// Immutable authorization source, with no target Commit coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanHistoricalSignerFact {
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
