//! Collaboration HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json`): events submit/resolve and
//! subscribe frames, ephemeral submission, query projections
//! (space/strand/morph), blob transfer headers, and the MIMI interop
//! operation bodies. Cross-domain aggregation outcomes and auth-domain
//! session bodies remain with their semantic owners.

use std::collections::BTreeMap;

use arkret_wire::{
    Base64UrlString, BlobRef, CbaProofBundle, ConsentId, ControlProposalAck, Cursor, DeviceId, Did,
    Error, Event, EventId, EventInitialSubmission, Hash, IngressReceipt, MimiRoomUri, MlsGroupId,
    MorphId, NonEmptyString, PayloadProof, Proof, ProofContextId, RealmId, ReasonCode, RelationId,
    ReportId, Result, Seal, SealId, ServiceOperationId, SignalEnvelope, SpaceId, StrandId,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contact_operations::{ContactPeer, ContactScopes};
use crate::direct_conversation_ops::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingUnitSubmission,
};
use crate::event_sync::{RealmActorFrontierView, RealmSealFrontierView};
use crate::governance::agent_artifacts::{DeviceMetadata, GrantSnapshot, PublicKey};
use crate::governance::authorization::GrantList;
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingRequestId(String);

impl DevicePairingRequestId {
    pub fn new(value: String) -> Result<Self> {
        static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"^device_pairing_request:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            )
            .expect("device pairing request id regex")
        });
        if !PATTERN.is_match(&value) {
            return Err(Error::Protocol(
                "device pairing request id must contain a canonical UUIDv7".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DevicePairingRequestId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DevicePairingRequestId> for String {
    fn from(value: DevicePairingRequestId) -> Self {
        value.0
    }
}

impl std::fmt::Display for DevicePairingRequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingCode(String);

impl DevicePairingCode {
    pub fn new(value: String) -> Result<Self> {
        if value.len() != 8
            || !value
                .bytes()
                .all(|byte| b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&byte))
        {
            return Err(Error::Protocol(
                "device pairing code must be 8 Crockford-style characters".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DevicePairingCode {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DevicePairingCode> for String {
    fn from(value: DevicePairingCode) -> Self {
        value.0
    }
}

impl std::fmt::Display for DevicePairingCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventsSubmitStatus {
    Accepted,
    Duplicate,
    Partial,
    HistoricalOnly,
}

/// `ak.self.events.command.submit` request body: either one initial
/// publication or a batch of them.
///
/// An Event never travels alone on this rail — the lease is what bounds the
/// revocation window, so a body carrying a bare Event is not a valid request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum EventsSubmitRequestBody {
    Single(EventInitialSubmission),
    Batch(EventsSubmitBatchRequestBody),
    DirectConversationFounding(DirectConversationFoundingUnitSubmission),
}

/// Closed response union paired with [`EventsSubmitRequestBody`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventsSubmitResponseBody {
    Ordinary(EventsSubmitOutcome),
    DirectConversationFounding(DirectConversationFoundingAcceptanceOutcome),
}

pub use arkret_wire::EventsSubmitBatchRequestBody;

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitRejectedItem`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsSubmitRejectedItem {
    /// 0-based position in the request `events[]`. It is the only way to report
    /// an item whose `id` failed to parse, so it is present whenever the item
    /// could be located positionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub id: String,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Exact CBA shortfall, so the sender extends one bundle instead of
    /// guessing. A bundle MAY be a bounded verifiable superset, so the receiver
    /// never asks for a byte-minimal one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_seal_refs: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_event_digests: Vec<Hash>,
}

impl EventsSubmitRejectedItem {
    pub fn validate_dependency_details(&self) -> Result<()> {
        let has_missing = !self.missing_event_ids.is_empty()
            || !self.missing_event_digests.is_empty()
            || !self.missing_seal_refs.is_empty();
        if (self.reason_code == ReasonCode::DependencyMissing) != has_missing {
            return Err(Error::Protocol(
                "dependency_missing requires typed missing details and other reasons forbid them"
                    .to_owned(),
            ));
        }
        validate_typed_missing_order(
            &self.missing_event_ids,
            &self.missing_event_digests,
            &self.missing_seal_refs,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsDependencyMissingProblem {
    pub reason_code: EventsDependencyMissingReasonCode,
    #[serde(default)]
    pub missing_event_ids: Vec<EventId>,
    #[serde(default)]
    pub missing_event_digests: Vec<Hash>,
    #[serde(default)]
    pub missing_seal_refs: Vec<SealId>,
}

impl EventsDependencyMissingProblem {
    pub fn validate(&self) -> Result<()> {
        if self.missing_event_ids.is_empty()
            && self.missing_event_digests.is_empty()
            && self.missing_seal_refs.is_empty()
        {
            return Err(Error::Protocol(
                "EventsDependencyMissingProblem requires dependency_missing and a non-empty typed missing set"
                    .to_owned(),
            ));
        }
        validate_typed_missing_order(
            &self.missing_event_ids,
            &self.missing_event_digests,
            &self.missing_seal_refs,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum EventsDependencyMissingReasonCode {
    #[serde(rename = "dependency_missing")]
    DependencyMissing,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitOutcome {
    pub status: EventsSubmitStatus,
    #[serde(default)]
    pub accepted: Vec<EventId>,
    /// Newly issued or byte-identical previously issued receipts for the
    /// accepted and duplicate Event digests.
    ///
    /// A service MUST return the stored receipt for an idempotent duplicate;
    /// minting one with a later `received_at` would silently extend a
    /// revocation window that is already fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress_receipts: Vec<IngressReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_proposal_acks: Vec<ControlProposalAck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<EventId>,
    /// Post-submit actor authoring frontiers sorted and unique by
    /// `(realm_id, actor_id)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_actor_frontiers: Vec<RealmActorFrontierView>,
    /// Visible post-submit Realm Seal frontiers sorted and unique by Realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_frontiers: Vec<RealmSealFrontierView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_outcome: Option<Box<EventsSubmitOutcome>>,
}

/// `ak.edge.applet.command.transaction` request body. Carries wire `Event`s
/// plus an optional `SignalEnvelope` batch, so it lives here rather than with
/// the other applet DTOs in `arkret-models-integration` (which does not depend
/// on this crate).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionRequestBody {
    pub source_service_id: Did,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<Vec<SignalEnvelope>>,
}

/// Result of `ak.self.events.command.submit_seal` after the receiver has
/// recomputed the Seal body, coverage and post-state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSealSubmitOutcome {
    pub seal_id: SealId,
    #[serde(default)]
    pub accepted_event_digests: Vec<Hash>,
    pub post_state_root: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventView {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    /// Spec-loose object: `service-operation-dtos.schema.json` declares
    /// `visibility` without property constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsResolveRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seal_refs: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
}

impl EventsResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_ids.is_empty() && self.event_digests.is_empty() && self.seal_refs.is_empty() {
            return Err(Error::Protocol(
                "events resolve requires at least one selector".to_owned(),
            ));
        }
        if self.event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.seal_refs.len() > MAX_PEER_RESOLVE_SEAL_SELECTORS
        {
            return Err(Error::Protocol(
                "events resolve selector limit exceeded".to_owned(),
            ));
        }
        let mut seals = self
            .seal_refs
            .iter()
            .map(SealId::as_str)
            .collect::<Vec<_>>();
        seals.sort_unstable();
        if seals.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Protocol(
                "events resolve seal_refs must be unique".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsResolveOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seals: Vec<Seal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

pub const MAX_PEER_RESOLVE_EVENT_SELECTORS: usize = 1024;
pub const MAX_PEER_RESOLVE_SEAL_SELECTORS: usize = 64;
pub const MAX_PEER_RESOLVE_RESPONSE_BYTES: u32 = 8 * 1024 * 1024;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsResolveRequestBody {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seal_refs: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl PeerEventsResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_ids.is_empty() && self.event_digests.is_empty() && self.seal_refs.is_empty() {
            return Err(Error::Protocol(
                "peer dependency resolve requires at least one selector".to_owned(),
            ));
        }
        if self.event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.seal_refs.len() > MAX_PEER_RESOLVE_SEAL_SELECTORS
        {
            return Err(Error::Protocol(
                "peer dependency resolve selector limit exceeded".to_owned(),
            ));
        }
        if self
            .max_response_bytes
            .is_some_and(|bytes| !(1024..=MAX_PEER_RESOLVE_RESPONSE_BYTES).contains(&bytes))
        {
            return Err(Error::Protocol(
                "peer dependency resolve max_response_bytes is outside 1024..=8388608".to_owned(),
            ));
        }
        validate_typed_missing_order(&self.event_ids, &self.event_digests, &self.seal_refs)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsResolveOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    #[serde(default)]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    #[serde(default)]
    pub missing_event_ids: Vec<EventId>,
    #[serde(default)]
    pub missing_event_digests: Vec<Hash>,
    #[serde(default)]
    pub missing_seal_refs: Vec<SealId>,
}

impl PeerEventsResolveOutcome {
    pub fn validate_structural(&self) -> Result<()> {
        if self.events.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.cba_proof_bundles.len()
                > arkret_wire::event_submission::MAX_SUBMISSION_CBA_BUNDLES
            || self.missing_event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.missing_event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.missing_seal_refs.len() > MAX_PEER_RESOLVE_SEAL_SELECTORS
        {
            return Err(Error::Protocol(
                "peer dependency resolve outcome limit exceeded".to_owned(),
            ));
        }
        validate_typed_missing_order(
            &self.missing_event_ids,
            &self.missing_event_digests,
            &self.missing_seal_refs,
        )?;
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
}

fn validate_typed_missing_order(
    event_ids: &[EventId],
    event_digests: &[Hash],
    seal_refs: &[SealId],
) -> Result<()> {
    fn sorted_unique(values: impl Iterator<Item = String>) -> bool {
        let mut previous: Option<String> = None;
        for value in values {
            if previous.as_ref().is_some_and(|previous| previous >= &value) {
                return false;
            }
            previous = Some(value);
        }
        true
    }
    if !sorted_unique(event_ids.iter().map(ToString::to_string))
        || !sorted_unique(event_digests.iter().map(ToString::to_string))
        || !sorted_unique(seal_refs.iter().map(ToString::to_string))
    {
        return Err(Error::Protocol(
            "typed missing/selectors must be strictly canonical-bytewise sorted and unique"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalSubmitOutcome {
    pub accepted: bool,
    pub realm_id: RealmId,
    /// Digest of the admitted complete encrypted envelope. It exists only for
    /// short-lived replay suppression and local correlation: admitting a
    /// Signal mints no Event id, advances no `actor_seq` and creates no
    /// durable receipt.
    pub envelope_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_recipient_count: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub server_received_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionSpaceState {
    Active,
    Archived,
    Tombstoned,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionObjectState {
    Active,
    Archived,
    Redacted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionSpaceList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub spaces: Vec<ProjectionSpaceRow>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionStrandRow {
    pub strand_id: StrandId,
    pub realm_id: RealmId,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    /// COT-06-004 — derived flag: `true` when this Strand is the Realm's
    /// default Strand (`strand_id == Realm.default_strand_id`). Computed at query
    /// time from the Realm projection; never stored as a per-Strand column.
    #[serde(default)]
    pub is_default: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionAssignedToRelation {
    pub relation_id: RelationId,
    pub actor_id: Did,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionStrandList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub strands: Vec<ProjectionStrandRow>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionMorphRow {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_kind: String,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobGetOutcome(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUpdateOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_state_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotifyRequestBody {
    pub notification: MimiNotification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_provider: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<MimiNotificationRouting>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotifyOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    pub delivery: MimiDelivery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiGroupInfoOutcome {
    pub group_info: MimiGroupInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_binding_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentRequestBody {
    pub requester_id: Did,
    pub target: MimiConsentTarget,
    pub purpose: MimiConsentPurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: ConsentId,
    pub status: NonEmptyString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiConsentDecision {
    Accept,
    Deny,
    Revoke,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiUpdateConsentRequestBody {
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    pub actor_id: Did,
    pub consent_event: EventInitialSubmission,
    pub signature: PayloadProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl MimiUpdateConsentRequestBody {
    pub fn validate_consent_event(&self) -> Result<()> {
        let expected_kind = match self.decision {
            MimiConsentDecision::Accept => "ak.consent.grant",
            MimiConsentDecision::Deny | MimiConsentDecision::Revoke => "ak.consent.revoke",
        };
        let event = &self.consent_event.event;
        if event.kind.as_str() != expected_kind || event.actor_id != self.actor_id {
            return Err(Error::Protocol(
                "MIMI consent decision, event kind, and actor binding mismatch".to_owned(),
            ));
        }
        let payload_consent_id = event.payload.get("consent_id").and_then(Value::as_str);
        if payload_consent_id != Some(self.consent_id.as_str()) {
            return Err(Error::Protocol(
                "MIMI consent event payload.consent_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }

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
            "operation_id": ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT,
            "verification_method": self.signature.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.signature.created_at),
            "domain": domain,
            "audience": audience,
        });
        canonical::canonical_json_bytes(&binding).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiUpdateConsentOutcome {
    pub status: MimiUpdateConsentStatus,
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub event_ref: EventId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiUpdateConsentStatus {
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    #[serde(default)]
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiReportAbuseOutcome {
    pub report_id: ReportId,
    pub status: NonEmptyString,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to: Vec<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiProxyDownloadOutcome {
    pub download_ref: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod mimi_consent_tests {
    use arkret_wire::{Audience, DidUrl, EventKind, EventRequirements, ScopeRef, proof_kind};
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
            consent_event: EventInitialSubmission {
                event: Event {
                    event_id: EventId::new(
                        "ak:event:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                    )
                    .unwrap(),
                    kind: EventKind::ConsentGrant,
                    realm_id: RealmId::new(
                        "ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                    )
                    .unwrap(),
                    scope_ref: ScopeRef::Realm {
                        realm_id: RealmId::new(
                            "ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                        )
                        .unwrap(),
                    },
                    actor_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice".to_owned())
                        .unwrap(),
                    executed_by: None,
                    authorization_ref: None,
                    applet_id: None,
                    external_ref: None,
                    actor_kind: None,
                    actor_seq: 1,
                    created_at,
                    hlc: None,
                    prev_refs: Vec::new(),
                    refs: Vec::new(),
                    causal_refs: Vec::new(),
                    preconditions: Vec::new(),
                    seal_ref: None,
                    auth_context: None,
                    seal_basis: None,
                    payload: [
                        (
                            "consent_id".to_owned(),
                            json!("ak:consent:01964137-0000-7000-8000-000000000777"),
                        ),
                        (
                            "peer".to_owned(),
                            json!("did:webvh:z6mkfixture:example.com:users:bob"),
                        ),
                        ("consent_scope".to_owned(), json!("direct_message")),
                    ]
                    .into_iter()
                    .collect(),
                    redacts: None,
                    unsigned: Default::default(),
                    proofs: Vec::new(),
                    requirements: EventRequirements::default(),
                },
                authorization_lease: None,
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            },
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkfixture:example.com:users:alice#device-1",
                )
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at,
                domain: Some("ak:trust_domain:example.com".to_owned()),
                audience: Some(Audience::Single(
                    "did:webvh:z6mkservice:example.com".to_owned(),
                )),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
            reason: Some(NonEmptyString::new("accepted after review").unwrap()),
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

    #[test]
    fn mimi_consent_event_must_match_decision_actor_and_consent_id() {
        let request = request();
        request.validate_consent_event().unwrap();

        let mut wrong_decision = request.clone();
        wrong_decision.decision = MimiConsentDecision::Revoke;
        assert!(wrong_decision.validate_consent_event().is_err());

        let mut wrong_actor = request.clone();
        wrong_actor.actor_id =
            Did::new("did:webvh:z6mkfixture:example.com:users:mallory".to_owned()).unwrap();
        assert!(wrong_actor.validate_consent_event().is_err());

        let mut wrong_consent = request;
        wrong_consent.consent_event.event.payload.insert(
            "consent_id".to_owned(),
            json!("ak:consent:01964137-0000-7000-8000-000000000778"),
        );
        assert!(wrong_consent.validate_consent_event().is_err());
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsRangeCompleteness {
    pub attestation_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub attestations: Vec<Event>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactState {
    PendingOutgoing,
    PendingIncoming,
    Accepted,
    Rejected,
    Expired,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSummaryState {
    Found,
    Suspended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    pub state: DirectConversationSummaryState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(try_from = "ContactListRowWire")]
pub struct ContactListRow {
    pub peer: ContactPeer,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    pub granted_to_peer_scopes: ContactScopes,
    pub granted_by_peer_scopes: ContactScopes,
    pub bidirectional_scopes: ContactScopes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scopes: Option<ContactScopes>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactListRowWire {
    peer: ContactPeer,
    state: ContactState,
    #[serde(default)]
    request_event_ref: Option<EventId>,
    #[serde(default)]
    response_event_ref: Option<EventId>,
    #[serde(default)]
    tombstone_event_ref: Option<EventId>,
    granted_to_peer_scopes: ContactScopes,
    granted_by_peer_scopes: ContactScopes,
    bidirectional_scopes: ContactScopes,
    #[serde(default)]
    effective_scopes: Option<ContactScopes>,
    #[serde(default)]
    peer_service_id: Option<Did>,
    #[serde(default)]
    direct_conversation: Option<DirectConversationSummary>,
    #[serde(default)]
    agents: Vec<ContactAgentProjection>,
}

impl TryFrom<ContactListRowWire> for ContactListRow {
    type Error = Error;

    fn try_from(wire: ContactListRowWire) -> Result<Self> {
        let row = Self {
            peer: wire.peer,
            state: wire.state,
            request_event_ref: wire.request_event_ref,
            response_event_ref: wire.response_event_ref,
            tombstone_event_ref: wire.tombstone_event_ref,
            granted_to_peer_scopes: wire.granted_to_peer_scopes,
            granted_by_peer_scopes: wire.granted_by_peer_scopes,
            bidirectional_scopes: wire.bidirectional_scopes,
            effective_scopes: wire.effective_scopes,
            peer_service_id: wire.peer_service_id,
            direct_conversation: wire.direct_conversation,
            agents: wire.agents,
        };
        row.validate_shape()?;
        Ok(row)
    }
}

impl ContactListRow {
    pub fn validate_shape(&self) -> Result<()> {
        if self
            .effective_scopes
            .as_ref()
            .is_some_and(|scopes| scopes != &self.bidirectional_scopes)
        {
            return Err(Error::Protocol(
                "effective_scopes must equal bidirectional_scopes when present".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<arkret_wire::cursor::Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ContactList {
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<arkret_wire::cursor::Cursor>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountOidcCallbackOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_session_state: Option<SessionGrantOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
pub struct AccountSubscribeRequestBody(pub SyncRequestBody);

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventsQueryOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
pub struct DevicePairingNonce(Base64UrlString);

impl DevicePairingNonce {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(22..=86).contains(&value.len()) {
            return Err(Error::Protocol(
                "device pairing nonce must contain 22..=86 base64url characters".to_owned(),
            ));
        }
        Ok(Self(
            Base64UrlString::new(value).map_err(|error| Error::Protocol(error.to_owned()))?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for DevicePairingNonce {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DevicePairingNonce> for String {
    fn from(value: DevicePairingNonce) -> Self {
        value.0.as_str().to_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DevicePairingChallengeTranscriptKind {
    #[serde(rename = "ak.device-pairing.challenge.v1")]
    ServerMediated,
    #[serde(rename = "ak.device-pairing.challenge.to_device.v1")]
    ToDevice,
}

impl DevicePairingChallengeTranscriptKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerMediated => "ak.device-pairing.challenge.v1",
            Self::ToDevice => "ak.device-pairing.challenge.to_device.v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingChallengeProof {
    pub transcript: DevicePairingChallengeTranscriptKind,
    /// Device-local key selector — an `ak:device:` id, **not** a DID URL.
    ///
    /// Deliberately not named `verification_method`: every other field of that
    /// name in the protocol resolves to the Arkret verification-method DID URL
    /// profile (`did-usage-and-verification.md` §2.2.1), and carrying a typed
    /// device id under that name was the one counterexample. Reusing the old
    /// name for this value is a hard reject.
    pub kid: DeviceId,
    pub signature_algorithm: NonEmptyString,
    pub transcript_digest: Hash,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingToDeviceChallengeTranscript {
    pub transaction_id: NonEmptyString,
    pub request_canonical_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: DevicePairingCode,
    pub new_device_pubkey: PublicKey,
    pub challenge_proof: DevicePairingChallengeProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
    /// When the approving device recovered this pairing via the server-mediated
    /// short-link (`ak.open.device_pairing.read.resolve`), it echoes the staged
    /// `device_pairing_request_id` here so the server can flip that staged row to
    /// `authorized` (carrying `device_id` + `authorized_event_ref`) for the new
    /// device's status poll to observe. Omitted for direct QR/paste pairing that
    /// never staged server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pairing_request_id: Option<DevicePairingRequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_transcript: Option<DevicePairingToDeviceChallengeTranscript>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_grant: Option<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_hint: Option<BTreeMap<String, Value>>,
}

// ── Device-pairing short-link (server-mediated resolve) ──────────────────
//
// Mirrors the agent-pairing `open` surface (`agent_operations.rs`): a
// not-yet-authorized device stages its device key server-side and receives a
// short `device_pairing_request_id` + `pairing_code` it encodes into a QR
// deep-link. An already-authorized device resolves that token to recover the
// full pairing material, then drives the existing authenticated
// `ak.gate.account.command.pair_device`. See
// `crypto-media/device-lifecycle.md` §2.1.

/// Staging request POSTed by a not-yet-authorized device to the unauthenticated
/// `POST /_arkret/open/device-pairing/requests`
/// (`ak.open.device_pairing.command.stage`). The staged row is account-less and
/// inert until a verified sibling authorizes it.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_stage_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingStageRequestBody {
    pub new_device_pubkey: PublicKey,
    pub client_nonce: DevicePairingNonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
}

/// Outcome of a device-pairing stage: the short handle + code the new device
/// encodes into its QR deep-link, plus the pairing window.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_stage_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingStageOutcome {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
    pub gate_audience: String,
    pub server_nonce: DevicePairingNonce,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Body of the unauthenticated resolve call
/// (`POST /_arkret/open/device-pairing/resolve`,
/// `ak.open.device_pairing.read.resolve`). The token is the compact
/// `base64url({"r":device_pairing_request_id,"c":pairing_code})` envelope; it
/// MUST be carried in the body, never in the URL.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_resolve_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingResolveRequestBody {
    pub pairing_token: String,
}

/// The pairing material an already-authorized device recovers by resolving a
/// device-pairing token, before it drives
/// `ak.gate.account.command.pair_device`.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_bootstrap`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingBootstrap {
    pub arkret_base_url: String,
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
    pub new_device_pubkey: PublicKey,
    pub client_nonce: DevicePairingNonce,
    pub gate_audience: String,
    pub server_nonce: DevicePairingNonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Lifecycle state of a staged device-pairing request.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DevicePairingState {
    /// Staged and awaiting authorization by a verified sibling device.
    PendingAuthorization,
    /// A verified sibling authorized the pairing; the new device is now a
    /// verified device (`device_id` / `authorized_event_ref` populated).
    Authorized,
    /// The pairing window elapsed before authorization.
    Expired,
}

/// Body of the unauthenticated status poll
/// (`POST /_arkret/open/device-pairing/requests/status`,
/// `ak.open.device_pairing.read.status`) the new device calls while waiting
/// for a sibling to approve.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_status_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingStatusRequestBody {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
}

/// Status outcome for a staged device-pairing request.
///
/// Mirrors `device-pairing.schema.json#/$defs/device_pairing_status_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingStatusOutcome {
    pub state: DevicePairingState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
pub struct BlobUploadRequestBody(pub BlobUploadMetadata);

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantListOutcome(pub GrantList);

#[cfg(test)]
mod federation_dependency_tests {
    use super::*;

    fn event_id(suffix: &str) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
        )
        .unwrap()
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned()).unwrap()
    }

    #[test]
    fn peer_resolve_requires_sorted_non_empty_selectors() {
        let valid = PeerEventsResolveRequestBody {
            realm_id: realm_id(),
            event_ids: vec![event_id("1"), event_id("2")],
            event_digests: Vec::new(),
            seal_refs: Vec::new(),
            include_payload: None,
            max_response_bytes: Some(4096),
        };
        assert!(valid.validate().is_ok());

        let mut empty = valid.clone();
        empty.event_ids.clear();
        assert!(empty.validate().is_err());

        let mut unsorted = valid;
        unsorted.event_ids.reverse();
        assert!(unsorted.validate().is_err());
    }

    #[test]
    fn dependency_missing_details_are_closed_and_non_empty() {
        let mut rejected = EventsSubmitRejectedItem {
            index: None,
            id: event_id("1").to_string(),
            reason_code: ReasonCode::DependencyMissing,
            detail: None,
            missing_event_ids: vec![event_id("2")],
            missing_seal_refs: Vec::new(),
            missing_event_digests: Vec::new(),
        };
        assert!(rejected.validate_dependency_details().is_ok());
        rejected.missing_event_ids.clear();
        assert!(rejected.validate_dependency_details().is_err());
        rejected.reason_code = ReasonCode::UnknownField;
        rejected.missing_event_ids.push(event_id("2"));
        assert!(rejected.validate_dependency_details().is_err());
    }
}

#[cfg(test)]
mod device_pairing_tests {
    use super::*;

    #[test]
    fn device_pairing_identifiers_enforce_the_wire_profiles() {
        assert!(
            DevicePairingRequestId::new(
                "device_pairing_request:01964137-0000-7000-8000-0000000000c1".to_owned()
            )
            .is_ok()
        );
        assert!(
            DevicePairingRequestId::new("device_pairing_request:not-a-uuid".to_owned()).is_err()
        );
        assert!(DevicePairingCode::new("7H2K9M4Q".to_owned()).is_ok());
        assert!(DevicePairingCode::new("00000000".to_owned()).is_err());
        assert!(DevicePairingCode::new("TOO-SHORT".to_owned()).is_err());
    }
}
