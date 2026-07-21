//! Collaboration HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json`): events submit/resolve and
//! subscribe frames, ephemeral submission, query projections
//! (space/strand/morph), blob transfer headers, and the MIMI interop
//! operation bodies. Cross-domain aggregation outcomes and auth-domain
//! session bodies stay in `arkret-core`.

use std::collections::BTreeMap;

use arkret_models_crypto::{
    KeyPackageClaimRecord, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimAuthorizationDraft,
    PeerKeyPackagesClaimRequestBody,
};
use arkret_wire::{
    Base64UrlString, BlobRef, ConsentId, Cursor, DeviceId, Did, Error, Event, EventId, EventKind,
    Hash, MimiRoomUri, MlsGroupId, MorphId, MoveId, NonEmptyString, PayloadProof, Proof,
    ProofContextId, RealmId, RelationId, ReportId, Result, SealId, SpaceId, StrandId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::ephemeral::EphemeralEnvelope;
use crate::governance::agent_artifacts::{DeviceMetadata, GrantSnapshot, PublicKey};
use crate::governance::authorization::GrantList;
use crate::governance::peer_contact::ContactIntroductionEvidence;
use crate::objects::blob::BlobUploadMetadata;
use crate::objects::mimi::{
    MimiCiphertext, MimiConsentPurpose, MimiConsentTarget, MimiDelivery, MimiFailure,
    MimiGroupInfo, MimiIdentifier, MimiIdentifierMatch, MimiKeyPackage, MimiNotification,
    MimiNotificationRouting, MimiOhttpContext, MimiOpaquePayload, MimiRoomUpdate,
};
use crate::session_grant_bodies::SessionGrantOutcome;
use crate::sync_frames::client_sync::SyncRequestBody;
use crate::sync_frames::snapshot::SnapshotBootstrap;
use crate::sync_frames::stream_trace::{StreamTraceFrame, StreamTraceFrameKind};

// is_false is used as a serde skip_serializing_if predicate in this module.
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsSubmitStatus {
    Accepted,
    Duplicate,
    Partial,
    HistoricalOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

/// Round 4 — batch `/events/submit` request. Multiple envelopes
/// submitted in a single round trip. The receiver MUST process each
/// envelope independently; partial-success returns the per-envelope
/// rejected list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<Event>,
    /// Optional idempotency key for the entire batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`
/// `rejected` array items: `{id, reason_code, detail?}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitRejectedItem {
    pub id: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitOutcome {
    pub status: EventsSubmitStatus,
    #[serde(default)]
    pub accepted: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<EventId>,
    /// Spec-loose object: `service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`
    /// declares `actor_frontier` as an unconstrained object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_frontier: Option<BTreeMap<String, Value>>,
    /// Spec-loose object: `service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`
    /// declares `realm_frontier` as an unconstrained object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_outcome: Option<Box<EventsSubmitOutcome>>,
}

/// `ak.edge.applet.command.transaction` request body. Carries wire `Event`s
/// plus the collaboration `EphemeralEnvelope` batch, so it lives here rather
/// than with the other applet DTOs in `arkret-models-integration` (which does
/// not depend on this crate).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionRequestBody {
    pub source_service_id: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Vec<EphemeralEnvelope>>,
}

/// Result of `ak.self.events.command.submit_seal` after the receiver has
/// recomputed the Seal body, coverage and post-state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventSealSubmitOutcome {
    pub seal_id: SealId,
    #[serde(default)]
    pub accepted_event_digests: Vec<MoveId>,
    pub post_state_root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventView {
    pub event: Event,
    /// Spec-loose object: `service-operation-dtos.schema.json` declares
    /// `visibility` without property constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsResolveRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsResolveOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EphemeralSubmitOutcome {
    pub accepted: bool,
    pub kind: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatched_to: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub server_received_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionSpaceState {
    Active,
    Archived,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionObjectState {
    Active,
    Archived,
    Redacted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionSpaceRow {
    pub space_id: SpaceId,
    pub realm_id: RealmId,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    pub state: ProjectionSpaceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionSpaceList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub spaces: Vec<ProjectionSpaceRow>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionStrandRow {
    pub strand_id: StrandId,
    pub realm_id: RealmId,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Derived board Space id from `ak.component.strand.position.v1`.
    /// This is read-model state, not canonical Strand object state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_space_id: Option<SpaceId>,
    /// Derived list Space id from `ak.component.strand.position.v1`.
    /// This is read-model state, not canonical Strand object state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_space_id: Option<SpaceId>,
    /// Derived rank inside `list_space_id` from
    /// `ak.component.strand.position.v1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Derived current assignee Actor DIDs from visible active
    /// `assigned_to` Relations. Empty means the Strand is unassigned for
    /// this projection caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_actor_ids: Vec<Did>,
    /// Active assignment Relation edges backing `assigned_actor_ids`.
    /// Clients use `relation_id` to tombstone an assignment during edits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to_relations: Vec<ProjectionAssignedToRelation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    /// COT-06-004 — derived flag: `true` when this Strand is the Realm's
    /// default Strand (`strand_id == Realm.default_strand_id`). Computed at query
    /// time from the Realm projection; never stored as a per-Strand column.
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionAssignedToRelation {
    pub relation_id: RelationId,
    pub actor_id: Did,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionStrandList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub strands: Vec<ProjectionStrandRow>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionMorphRow {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_type: String,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ProjectionMorphList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub morphs: Vec<ProjectionMorphRow>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// NDJSON subscribe-stream frame discriminator.
///
/// `#[non_exhaustive]`: a future spec revision may register additional frame
/// kinds. Downstream `match` expressions MUST carry a `_` arm with
/// fail-closed semantics (ignore/drop an unrecognised frame rather than
/// treating it as an event or a state transition). Deserialisation itself
/// stays closed-set: an unknown wire value still fails the frame parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventsSubscribeFrameKind {
    Event,
    Frontier,
    Heartbeat,
    CatchupComplete,
    EpochRotation,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubscribeFrame {
    pub kind: EventsSubscribeFrameKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
}

impl EventsSubscribeFrame {
    /// Parse one NDJSON line. Empty / whitespace-only lines return
    /// `Ok(None)` so streaming readers can split incrementally.
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame = canonical::from_canonical_json_str(trimmed)?;
        Ok(Some(frame))
    }

    /// True iff this frame requires the client to reset or rebuild its
    /// subscription state.
    pub fn requires_resubscribe(&self) -> bool {
        matches!(
            self.kind,
            EventsSubscribeFrameKind::Dropped | EventsSubscribeFrameKind::ResyncRequired
        )
    }

    /// True iff this frame carries an event payload.
    pub fn is_event(&self) -> bool {
        matches!(self.kind, EventsSubscribeFrameKind::Event)
    }

    /// True iff catch-up replay has reached the live frontier.
    pub fn is_catchup_complete(&self) -> bool {
        matches!(self.kind, EventsSubscribeFrameKind::CatchupComplete)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = EventsSubscribeFrame)))]
pub struct EventsSubscribeFrameOutcome(pub EventsSubscribeFrame);

impl StreamTraceFrame for EventsSubscribeFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self.kind {
            EventsSubscribeFrameKind::Event => StreamTraceFrameKind::Data,
            EventsSubscribeFrameKind::Frontier => StreamTraceFrameKind::Frontier,
            EventsSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
            EventsSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
            EventsSubscribeFrameKind::EpochRotation => StreamTraceFrameKind::EpochRotation,
            EventsSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
            EventsSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
            EventsSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        self.cursor.as_ref().map(|cursor| cursor.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct BlobHeadOutcome {
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Length")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Digest")]
    pub digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Cache-Control")]
    pub cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Type")]
    pub content_type: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "Content-Disposition"
    )]
    pub content_disposition: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = String, format = Binary)))]
pub struct BlobGetOutcome(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialRequestBody {
    pub requester: Did,
    pub strand_id: StrandId,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimi_room_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialOutcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_packages: Vec<MimiKeyPackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info: Option<MimiGroupInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<MimiFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PayloadProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateRequestBody {
    pub mls_group_id: MlsGroupId,
    pub update: MimiRoomUpdate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_transcript_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_actor_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_state_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyRequestBody {
    pub notification: MimiNotification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_provider: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<MimiNotificationRouting>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageRequestBody {
    pub sender_actor_id: Did,
    pub device_id: DeviceId,
    pub ciphertext: MimiCiphertext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub associated_data: Option<MimiOpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    pub delivery: MimiDelivery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiGroupInfoOutcome {
    pub group_info: MimiGroupInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_binding_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiRequestConsentRequestBody {
    pub requester_id: Did,
    pub target: MimiConsentTarget,
    pub purpose: MimiConsentPurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: ConsentId,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiConsentDecision {
    Accept,
    Deny,
    Revoke,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MimiUpdateConsentRequestBody {
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    pub actor_id: Did,
    pub signature: PayloadProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

pub const MIMI_UPDATE_CONSENT_OPERATION_ID: &str = "ak.open.mimi.command.update_consent";

impl MimiUpdateConsentRequestBody {
    /// Canonical request value covered by the operation proof. The detached
    /// proof is omitted to avoid a self-referential digest.
    pub fn unsigned_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("MimiUpdateConsentRequestBody serializes as an object")
            .remove("signature");
        Ok(value)
    }

    /// Digest of the complete request with only the detached proof omitted.
    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload()?)?).map_err(Into::into)
    }

    /// Canonical `ak.mimi-operation-proof-v1` transcript shared by MIMI
    /// consent proof producers and verifiers.
    pub fn signature_binding_bytes(&self) -> Result<Vec<u8>> {
        self.signature.validate_production()?;
        if self.signature.proof_purpose.is_some() {
            return Err(Error::Protocol(
                "MIMI operation proof must not carry proof_purpose".to_owned(),
            ));
        }
        let payload_digest = self.payload_digest()?;
        if self.signature.payload_digest != payload_digest {
            return Err(Error::Protocol(
                "MIMI consent proof payload_digest mismatch".to_owned(),
            ));
        }
        let domain = self
            .signature
            .domain
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Error::Protocol("MIMI operation proof requires domain".to_owned()))?;
        let audience =
            self.signature.audience.as_ref().ok_or_else(|| {
                Error::Protocol("MIMI operation proof requires audience".to_owned())
            })?;
        let binding = serde_json::json!({
            "context": ProofContextId::MIMI_OPERATION_PROOF_V1,
            "payload_digest": payload_digest,
            "issuer": self.actor_id,
            "operation_id": MIMI_UPDATE_CONSENT_OPERATION_ID,
            "verification_method": self.signature.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.signature.created_at),
            "domain": domain,
            "audience": audience,
        });
        canonical::canonical_json_bytes(&binding).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiUpdateConsentOutcome {
    pub status: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryRequestBody {
    #[serde(default)]
    pub identifiers: Vec<MimiIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    #[serde(default)]
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiReportAbuseRequestBody {
    pub strand_id: StrandId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimi_room_uri: Option<MimiRoomUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub target_ref: NonEmptyString,
    pub reporter: Did,
    pub abuse_reason_code: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<MimiOpaquePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<MimiOpaquePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiReportAbuseOutcome {
    pub report_id: ReportId,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to: Vec<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiProxyDownloadRequestBody {
    pub asset_ref: NonEmptyString,
    pub requester: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ohttp_context: Option<MimiOhttpContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MimiProxyDownloadOutcome {
    pub download_ref: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod mimi_consent_tests {
    use arkret_wire::{Audience, proof_kind};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn request() -> MimiUpdateConsentRequestBody {
        let created_at = Utc
            .with_ymd_and_hms(2026, 7, 19, 6, 30, 0)
            .single()
            .unwrap();
        let mut request = MimiUpdateConsentRequestBody {
            consent_id: ConsentId::new(
                "ak:consent:01964137-0000-7000-8000-000000000777".to_owned(),
            )
            .unwrap(),
            decision: MimiConsentDecision::Accept,
            actor_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice".to_owned()).unwrap(),
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:example.com:users:alice#device-1"
                    .to_owned(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at,
                domain: Some("ak:trust_domain:example.com".to_owned()),
                audience: Some(Audience::Single(
                    "did:webvh:z6mkservice:example.com".to_owned(),
                )),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
            reason: Some("accepted after review".to_owned()),
            expires_at: None,
        };
        request.signature.payload_digest = request.payload_digest().unwrap();
        request
    }

    #[test]
    fn mimi_consent_signature_binds_unsigned_payload() {
        let request = request();
        let binding: Value =
            canonical::from_canonical_json_slice(&request.signature_binding_bytes().unwrap())
                .unwrap();

        assert_eq!(
            binding,
            json!({
                "audience": "did:webvh:z6mkservice:example.com",
                "context": "ak.mimi-operation-proof-v1",
                "created_at": "2026-07-19T06:30:00.000Z",
                "domain": "ak:trust_domain:example.com",
                "issuer": "did:webvh:z6mkfixture:example.com:users:alice",
                "operation_id": "ak.open.mimi.command.update_consent",
                "payload_digest": request.payload_digest().unwrap(),
                "verification_method": "did:webvh:z6mkfixture:example.com:users:alice#device-1"
            })
        );
    }

    #[test]
    fn mimi_consent_signature_rejects_event_proof_shape() {
        let mut value = serde_json::to_value(request()).unwrap();
        let signature = value["signature"].as_object_mut().unwrap();
        let digest = signature.remove("payload_digest").unwrap();
        signature.insert("event_digest".to_owned(), digest);

        let error = serde_json::from_value::<MimiUpdateConsentRequestBody>(value)
            .expect_err("Event proof fields must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn mimi_consent_signature_detects_payload_tampering() {
        let mut request = request();
        request.decision = MimiConsentDecision::Revoke;

        assert!(request.signature_binding_bytes().is_err());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventsRangeCompleteness {
    pub attestation_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<Event>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContactState {
    PendingOutgoing,
    PendingIncoming,
    Accepted,
    Rejected,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationBindingState {
    Active,
    Retired,
    Duplicate,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationResolveState {
    Found,
    AuthoringRequired,
    NotFound,
    Retired,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationAuthoringKind {
    RemoteKeypackageClaim,
    DirectConversationMaterialization,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    pub state: DirectConversationBindingState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactAgentProjection {
    pub agent_id: Did,
    pub controller_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactListRow {
    pub peer: Did,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    #[serde(default)]
    pub granted_by_me: Vec<String>,
    #[serde(default)]
    pub granted_to_me: Vec<String>,
    #[serde(default)]
    pub bidirectional_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_consent_grant_ref: Option<EventId>,
    /// Principal Server service DID hosting the peer, when known (e.g. learned
    /// from a cross-Principal-Server contact delivery). Lets the holder address
    /// responses/invites to the peer's home server. Omitted for
    /// same-Principal-Server contacts (spec contact-operations.schema.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
    /// Active agents controlled by this contact that currently accept direct
    /// messages from the authenticated actor. This is a viewer-specific,
    /// fail-closed projection; clients must not infer it from public selector
    /// claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<ContactAgentProjection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<arkret_wire::cursor::Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<arkret_wire::cursor::Cursor>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestOutcome {
    pub request_event_ref: EventId,
    #[serde(default)]
    pub requester_consent_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondRequestBody {
    pub request_id: EventId,
    pub requester: Did,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scopes: Vec<String>,
    /// Cross-Principal-Server addressing (spec §4.1): when the original
    /// `requester` is hosted on a different Principal Server, the responder
    /// supplies the requester's home service DID so the accept / reject fact
    /// is federated back via `ak.peer.contacts.command.submit`. Omit for same-server
    /// responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_service_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondOutcome {
    pub response_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grant_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstoneRequestBody {
    pub contact: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub full_peer_revoke: bool,
    #[serde(default)]
    pub block_peer: bool,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `contact` (the peer) is hosted on a different Principal
    /// Server, the holder supplies the peer's home service DID so the
    /// `ak.contact.tombstoned` fact is federated to the peer's server via
    /// `ak.peer.contacts.command.submit`. Omit for same-server tombstones; when absent
    /// the issuer falls back to the peer's recorded `peer_service_id` on the
    /// stored contact row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstone {
    pub tombstone_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_revoke_refs: Vec<EventId>,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: Did,
    #[serde(default, skip_serializing_if = "is_false")]
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_claim_request: Option<PeerKeyPackagesClaimRequestBody>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DirectConversationMaterializationDraft {
    pub materialization_id: NonEmptyString,
    pub claim_nonce: Base64UrlString,
    pub mls_group_id: MlsGroupId,
    pub mls_genesis_event_ref: EventId,
    pub mls_commit_event_ref: EventId,
    pub mls_welcome_event_ref: EventId,
    pub claimed_keypackage: KeyPackageClaimRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_receipt: Option<PeerKeyPackageClaimReceipt>,
    pub realm_event: Event,
    pub founding_grant_event: Event,
    pub peer_member_event: Event,
    pub main_strand_event: Event,
    pub binding_event: Event,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

impl DirectConversationMaterializationDraft {
    pub fn validate_shape(&self) -> Result<()> {
        let expected = [
            (&self.realm_event, EventKind::REALM_CREATE),
            (&self.founding_grant_event, EventKind::CAPABILITY_GRANT),
            (&self.peer_member_event, EventKind::MEMBER_STATE),
            (&self.main_strand_event, EventKind::STRAND_CREATE),
            (&self.binding_event, EventKind::DIRECT_CONVERSATION_BOUND),
        ];
        if expected
            .iter()
            .any(|(event, kind)| event.kind.as_str() != *kind || !event.proofs.is_empty())
        {
            return Err(Error::Protocol(
                "direct conversation materialization Event draft shape is invalid".into(),
            ));
        }
        if self.realm_event.realm_id != self.peer_member_event.realm_id
            || self.realm_event.realm_id != self.main_strand_event.realm_id
            || self.realm_event.realm_id != self.founding_grant_event.realm_id
            || self.realm_event.actor_id != self.peer_member_event.actor_id
            || self.realm_event.actor_id != self.founding_grant_event.actor_id
            || self.realm_event.actor_id != self.main_strand_event.actor_id
            || self.realm_event.actor_id != self.binding_event.actor_id
        {
            return Err(Error::Protocol(
                "direct conversation materialization Event draft binding is invalid".into(),
            ));
        }
        let founding_payload: crate::events_payloads::capability_circle_consent_contact::CapabilityGrantPayload =
            serde_json::from_value(serde_json::to_value(&self.founding_grant_event.payload)?)
                .map_err(|_| {
                    Error::Protocol(
                        "direct conversation founding grant draft payload is invalid".into(),
                    )
                })?;
        let founding_grant = founding_payload.grant.ok_or_else(|| {
            Error::Protocol("direct conversation founding grant draft is absent".into())
        })?;
        if founding_grant.id != founding_payload.grant_id
            || founding_grant.issuer != self.founding_grant_event.actor_id
            || !founding_grant.proofs.is_empty()
        {
            return Err(Error::Protocol(
                "direct conversation founding grant must be an unsigned issuer draft".into(),
            ));
        }
        let binding: crate::events_payloads::device_identity::DirectConversationBoundPayload =
            serde_json::from_value(serde_json::to_value(&self.binding_event.payload).map_err(
                |_| {
                    Error::Protocol(
                        "direct conversation materialization binding payload is invalid".into(),
                    )
                },
            )?)
            .map_err(|_| {
                Error::Protocol(
                    "direct conversation materialization binding payload is invalid".into(),
                )
            })?;
        if binding.realm_id != self.realm_event.realm_id
            || binding.main_strand_id.as_str()
                != self
                    .main_strand_event
                    .payload
                    .get("object")
                    .and_then(|object| object.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            || !binding
                .member_event_refs
                .iter()
                .any(|event_id| event_id == &self.realm_event.event_id)
            || !binding
                .member_event_refs
                .iter()
                .any(|event_id| event_id == &self.peer_member_event.event_id)
            || binding.main_strand_create_ref != self.main_strand_event.event_id
            || binding.mls_group_id != self.mls_group_id
            || binding.mls_genesis_event_ref != self.mls_genesis_event_ref
            || binding.mls_commit_event_ref != self.mls_commit_event_ref
            || binding.mls_welcome_event_ref != self.mls_welcome_event_ref
        {
            return Err(Error::Protocol(
                "direct conversation materialization binding refs do not match drafts".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveOutcome {
    pub state: DirectConversationResolveState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_kind: Option<DirectConversationAuthoringKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_authorization_draft: Option<PeerKeyPackagesClaimAuthorizationDraft>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization_draft: Option<DirectConversationMaterializationDraft>,
}

impl DirectConversationResolveOutcome {
    pub fn validate_shape(&self) -> Result<()> {
        match self.state {
            DirectConversationResolveState::AuthoringRequired => {
                if self.created != Some(false) {
                    return Err(Error::Protocol(
                        "authoring_required must carry created=false".into(),
                    ));
                }
                match self.authoring_kind {
                    Some(DirectConversationAuthoringKind::RemoteKeypackageClaim)
                        if self.claim_authorization_draft.is_some()
                            && self.materialization_draft.is_none() =>
                    {
                        Ok(())
                    }
                    Some(DirectConversationAuthoringKind::DirectConversationMaterialization)
                        if self.claim_authorization_draft.is_none()
                            && self
                                .materialization_draft
                                .as_ref()
                                .is_some_and(|draft| draft.validate_shape().is_ok()) =>
                    {
                        Ok(())
                    }
                    _ => Err(Error::Protocol(
                        "authoring_required fields do not match authoring_kind".into(),
                    )),
                }
            }
            _ if self.authoring_kind.is_none()
                && self.claim_authorization_draft.is_none()
                && self.materialization_draft.is_none() =>
            {
                Ok(())
            }
            _ => Err(Error::Protocol(
                "non-authoring resolver outcome carries authoring fields".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_session_state: Option<SessionGrantOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = SyncRequestBody)))]
pub struct AccountSubscribeRequestBody(pub SyncRequestBody);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsQueryOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range_completeness: Option<EventsRangeCompleteness>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestRequestBody {
    pub target: Did,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `target` is hosted on a different Principal Server, the
    /// requester MUST supply the target's home service DID so the issuer-side
    /// server can federate the signed `ak.contact.requested` fact via
    /// `ak.peer.contacts.command.submit`. Omit for same-server requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence: Option<ContactIntroductionEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: NonEmptyString,
    pub new_device_pubkey: PublicKey,
    pub challenge_signature: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_grant: Option<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_hint: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = BlobUploadMetadata)))]
pub struct BlobUploadRequestBody(pub BlobUploadMetadata);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = GrantList)))]
pub struct GrantListOutcome(pub GrantList);
