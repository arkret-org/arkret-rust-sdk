// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-read-operations.schema.json
// sha256=5a3d386837724180dd7a845741ff3b9d0de57966d2f29177bcc21cebb17f5e7c
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=2c16d34f11af288de64af2ee31ea59f1cc46e006dc9091b41aae46d3ea686662
//
// Input: schemas/authz-operations.schema.json
// sha256=a77316365476c8c617f70a84a5bf3f6ee0be723b84b2f4713072cf1ed02e6832
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=0726e92679a034d958f290919dca9450871ac2f9c29dbb97f1a2f93ddc6939ec
//
// Input: schemas/typed-current-result.schema.json
// sha256=448abceebd5661cb1d2db37d9a28dbe85815f08cf0119282307229865080a78b
//
// Input: schemas/realm-authority-handoff.schema.json
// sha256=409c541cd5312829fe6fabadea1b8940ab48e353a457675a557852df561150fd
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/realm-commit.schema.json
// sha256=8210f845973478d08b65e26163fea3a08729c0e4946ac2efcfabe1b5ff086f9a
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

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
    pub snapshot_ref: RealmSnapshotId,
    pub change_event_ref: EventId,
    pub change_commit_id: RealmCommitId,
    pub old_authority_signature: DetachedObjectSignature,
    pub new_authority_acceptance_signature: DetachedObjectSignature,
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
