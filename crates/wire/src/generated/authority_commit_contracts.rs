// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-read-operations.schema.json
// sha256=42278e7c05317c7629724c1cbbe5ab019e87da08d73d014d915898fce20012ab
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=e621293b9e2e5e08de76450a99b0e8069fa9bb92c806fe8dfe3134176e8c63b9
//
// Input: schemas/authorization-operations.schema.json
// sha256=b367d60aeb13aa9e524c5201cc1857d8ac9defd5c78293f696a4f4c0a5d4450b
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=820d763125038f2777a3fc00ba30173c5a5d85cf50f6047457416eff7523d4d3
//
// Input: schemas/current-state.schema.json
// sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//
// Input: schemas/realm-authority-handoff.schema.json
// sha256=3c13fbab2eb3ef175f4074d773997452693c0897b0fe4f7f84cd1702937df062
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/realm-commit.schema.json
// sha256=6feb8f90ab444004084e457cc4c52193dbfc9d630f4739eda7712c21257af590
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

/// Counterpart: `realm-read-operations.schema.json#/$defs/realm_stream_view`.
/// One established authority stream the caller may know exists
/// (`realm-read-operations.schema.json#/$defs/realm_stream_view`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamView {
    pub stream_ref: CommitStreamRef,
    pub head_commit_ref: RealmCommitId,
    pub next_position: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub readable_floor: Option<ReadableFloor>,
}

/// Counterpart: `realm-read-operations.schema.json#/$defs/realm_stream_page`.
/// ACL-filtered stream enumeration page
/// (`realm-read-operations.schema.json#/$defs/realm_stream_page`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamPage {
    pub realm_id: RealmId,
    pub streams: Vec<RealmStreamView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitRequestBody`.
/// Request of `ak.self.actor_private_events.command.submit.v1`: one
/// caller-signed actor-private Event that has no dedicated submit operation.
///
/// Spec: `service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitRequestBody`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPrivateEventSubmitRequestBody {
    pub event: Event,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_authority_root_value`.
/// Closed `current-state.schema.json#/$defs/realm_authority_root_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityRootValue {
    pub controller_actor_id: ActorId,
    pub controller_epoch: u64,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub authority_generation: u64,
    pub authority_event_ref: EventId,
}

/// Counterpart: `realm-authority-handoff.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityHandoff {
    pub handoff_id: RealmAuthorityHandoffId,
    pub realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub from_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub to_generation: u64,
    pub from_service_id: DidCoreId,
    pub to_service_id: DidCoreId,
    pub final_stream_heads_digest: Hash,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_original_digest"
    )]
    pub historical_signer_facts_digest: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_original_digest"
    )]
    pub pcr_private_state_digest: Option<Hash>,
    pub snapshot_ref: RealmSnapshotId,
    pub change_event_ref: EventId,
    pub change_commit_id: RealmCommitId,
    pub old_authority_signature: DetachedObjectSignature,
    pub new_authority_acceptance_signature: DetachedObjectSignature,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_private_state_digest: Option<Hash>,
}

/// Counterpart: `realm-commit.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCommit {
    pub commit_id: RealmCommitId,
    pub realm_id: RealmId,
    pub stream_ref: CommitStreamRef,
    pub stream_position: u64,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub previous_commit_ref: Option<RealmCommitId>,
    pub event_ref: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub governance_generation: u64,
    pub authority_ref: RealmCommitAuthorityRef,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_original_digest"
    )]
    pub producer_signer_fact_digest: Option<Hash>,
    pub signature: DetachedObjectSignature,
}
