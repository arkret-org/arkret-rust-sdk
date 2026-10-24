// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=f95cb1acfa8517176738115925b1795d3b13d206a1d99ddf0b5050f670136d2f
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

/// Counterpart: `authority-commit-operations.schema.json#/$defs/mls_genesis_material`.
/// Raw epoch-0 public material of one forwarded `ak.mls.genesis`
/// (`authority-commit-operations.schema.json#/$defs/mls_genesis_material`).
/// The signed Genesis refs are the only digest carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisMaterial {
    pub group_info_base64url: String,
    pub ratchet_tree_base64url: String,
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

/// Counterpart: `authority-commit-operations.schema.json#/$defs/peer_stream_scan_response_body`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStreamScanResponseBody {
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub readable_floor: Option<arkret_wire::ReadableFloor>,
    pub truncated: bool,
    pub producer_signer_facts: Vec<HistoricalProducerSignerFactEntry>,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_authority_handoff_request_body`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRealmAuthorityHandoffRequestBody {
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
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub effective_stream_head: CommitStreamHead,
    pub nonce: String,
    pub state_digest: Hash,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/management_private_handoff_manifest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementPrivateHandoffManifest {
    pub realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub final_stream_heads_digest: Hash,
    pub nonce: String,
    pub state_digest: Hash,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_device_historical_signer_fact/properties/
/// kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmDeviceHistoricalSignerFactKind {
    #[serde(rename = "realm_device")]
    RealmDevice,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_device_historical_signer_fact`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDeviceHistoricalSignerFact {
    pub kind: RealmDeviceHistoricalSignerFactKind,
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub verification_method: DidUrl,
    pub public_key_base64url: arkret_wire::Base64UrlString,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub device_id: arkret_wire::DeviceId,
    pub authorization_event_id: EventId,
    pub authorized_generation_ref: u64,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_control_historical_signer_fact/properties/
/// kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmControlHistoricalSignerFactKind {
    #[serde(rename = "realm_control")]
    RealmControl,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_control_historical_signer_fact`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmControlHistoricalSignerFact {
    pub kind: RealmControlHistoricalSignerFactKind,
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub verification_method: DidUrl,
    pub public_key_base64url: arkret_wire::Base64UrlString,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub control_event_ref: arkret_wire::CommittedEventRef,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_recovery_service_historical_signer_fact/
/// properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmRecoveryServiceHistoricalSignerFactKind {
    #[serde(rename = "realm_recovery_service")]
    RealmRecoveryService,
}

/// Counterpart:
/// `authority-commit-operations.schema.json#/$defs/realm_recovery_service_historical_signer_fact`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRecoveryServiceHistoricalSignerFact {
    pub kind: RealmRecoveryServiceHistoricalSignerFactKind,
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub target_actor_id: ActorId,
    pub verification_method: DidUrl,
    pub public_key_base64url: arkret_wire::Base64UrlString,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub applet_id: arkret_wire::AppletId,
    pub registration_epoch: Hash,
    pub registration_ref: arkret_wire::CommittedEventRef,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
}
