// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-read-operations.schema.json
// sha256=42278e7c05317c7629724c1cbbe5ab019e87da08d73d014d915898fce20012ab
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=145ad1e0a66b0548a1e081d8eecb6a8c0f999745dbf1ac50f8039ca1c84b8d0e
//
// Input: schemas/authorization-operations.schema.json
// sha256=b367d60aeb13aa9e524c5201cc1857d8ac9defd5c78293f696a4f4c0a5d4450b
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=8a166319961d452f87d8becf5db9e089008f477e28de749aedc0696a44f9ec7e
//
// Input: schemas/current-state.schema.json
// sha256=b9b2fcecf87470a1def1e55bf536bdb637b04f0e6f42083d5ed9962a80b14c61
//
// Input: schemas/realm-authority-handoff.schema.json
// sha256=3c13fbab2eb3ef175f4074d773997452693c0897b0fe4f7f84cd1702937df062
//
// Input: schemas/account-operations.schema.json
// sha256=0ae0fec5fd63dca4b9df9293eb71936cf73a3eeeae13b2268dc99699c1ed7607
//
// Input: schemas/realm-commit.schema.json
// sha256=6feb8f90ab444004084e457cc4c52193dbfc9d630f4739eda7712c21257af590
//
// Bindings: tools/closed-model-bindings.json
// sha256=db527b364017054646ca12898f9051885245c63852c0c52b9960a568cc897f0f

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
