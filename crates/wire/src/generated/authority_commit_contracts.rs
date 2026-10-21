// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-read-operations.schema.json
// sha256=5a3d386837724180dd7a845741ff3b9d0de57966d2f29177bcc21cebb17f5e7c
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=1d0ad5c145091c227cb414f5a677679d5e286d16a5e5819328c907b2432e5350
//
// Input: schemas/authz-operations.schema.json
// sha256=a77316365476c8c617f70a84a5bf3f6ee0be723b84b2f4713072cf1ed02e6832
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=cf32adc7dde893269afa676f7f507979b0f1899e2c565185d7a9f752c4f4e2ff
//
// Input: schemas/typed-current-result.schema.json
// sha256=bfee8c04c7b3d9e76727652feaa2e49488bb443f0bb99670a13dd07f2be02fe3
//
// Input: schemas/realm-authority-handoff.schema.json
// sha256=939b4e73ee20754160bfb2ca93660e4bf7d73ee044973ef794904c550002b1ce
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Input: schemas/realm-commit.schema.json
// sha256=5429e875d095ff71e7c0d290032f96c9ac7c89714ea99fd6df70c906759ca5c4
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `realm-read-operations.schema.json#/$defs/realm_stream_row`.
/// One established authority stream the caller may know exists
/// (`realm-read-operations.schema.json#/$defs/realm_stream_row`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamRow {
    pub stream_ref: CommitStreamRef,
    pub head_commit_ref: RealmCommitId,
    pub next_position: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub readable_floor: Option<ReadableFloor>,
}

/// Counterpart: `realm-read-operations.schema.json#/$defs/realm_stream_list`.
/// ACL-filtered stream enumeration page
/// (`realm-read-operations.schema.json#/$defs/realm_stream_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamList {
    pub realm_id: RealmId,
    pub streams: Vec<RealmStreamRow>,
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

/// Counterpart: `typed-current-result.schema.json#/$defs/realm_authority_root_value`.
/// Closed `typed-current-result.schema.json#/$defs/realm_authority_root_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityRootValue {
    pub controller_actor_id: ActorId,
    pub controller_epoch: u64,
    pub authority_generation: u64,
    pub authority_event_ref: EventId,
}

/// Counterpart: `realm-authority-handoff.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityHandoff {
    pub handoff_id: RealmAuthorityHandoffId,
    pub realm_id: RealmId,
    pub from_generation: u64,
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
