//! Collaboration HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json`): events submit/resolve and
//! subscribe frames, ephemeral submission, query projections
//! (space/strand/morph), blob transfer headers, and the MIMI interop
//! operation bodies. Cross-domain aggregation outcomes and auth-domain
//! session bodies remain with their semantic owners.

use std::collections::BTreeMap;

use arkret_models_crypto::{
    KeyPackageClaimRecord, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimAuthorizationDraft,
    PeerKeyPackagesClaimRequestBody,
};
use arkret_wire::{
    Base64UrlString, BlobRef, CbaProofBundle, ConsentId, Cursor, DeviceId, Did, Error, Event,
    EventId, EventInitialSubmission, EventKind, GrantId, Hash, IngressReceipt, MimiRoomUri,
    MlsGroupId, MorphId, NonEmptyString, PayloadProof, Proof, ProofContextId, RealmId, RelationId,
    ReportId, Result, SealId, SignalEnvelope, SpaceId, StrandId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event_sync::{RealmActorFrontierView, RealmSealFrontierView};
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

// is_false is used as a serde skip_serializing_if predicate in this module.
fn is_false(value: &bool) -> bool {
    !*value
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventsSubmitRequestBody {
    Single(EventInitialSubmission),
    Batch(EventsSubmitBatchRequestBody),
}

/// Batch `ak.self.events.command.submit` request used by account clients.
///
/// The receiver MUST process each submission independently; partial success
/// returns the per-submission rejected list.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<EventInitialSubmission>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitRejectedItem`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsSubmitRejectedItem {
    /// 0-based position in the request `events[]`. It is the only way to report
    /// an item whose `id` failed to parse, so it is present whenever the item
    /// could be located positionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub id: String,
    pub reason_code: String,
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
        if (self.reason_code == "dependency_missing") != has_missing {
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
    pub reason_code: String,
    #[serde(default)]
    pub missing_event_ids: Vec<EventId>,
    #[serde(default)]
    pub missing_event_digests: Vec<Hash>,
    #[serde(default)]
    pub missing_seal_refs: Vec<SealId>,
}

impl EventsDependencyMissingProblem {
    pub fn validate(&self) -> Result<()> {
        if self.reason_code != "dependency_missing"
            || (self.missing_event_ids.is_empty()
                && self.missing_event_digests.is_empty()
                && self.missing_seal_refs.is_empty())
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
pub struct EventsResolveRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventsResolveOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
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
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
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
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: ConsentId,
    pub status: String,
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub status: String,
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
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationBindingState {
    Active,
    Retired,
    Duplicate,
    NonCanonical,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationResolveState {
    Found,
    AuthoringRequired,
    NotFound,
    Retired,
    NonCanonical,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationAuthoringKind {
    RemoteKeypackageClaim,
    DirectConversationMaterialization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    pub state: DirectConversationBindingState,
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
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<arkret_wire::cursor::Cursor>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRequestOutcome {
    pub request_event_ref: EventId,
    #[serde(default)]
    pub requester_consent_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRespondOutcome {
    pub response_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grant_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactTombstone {
    pub tombstone_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_revoke_refs: Vec<EventId>,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectConversationResolveRequestBody {
    pub peer: Did,
    #[serde(default, skip_serializing_if = "is_false")]
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_claim_request: Option<PeerKeyPackagesClaimRequestBody>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub realm_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub founding_grant_event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub creator_member_event: Option<Event>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub peer_member_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub main_strand_grant_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub main_strand_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub binding_event: Event,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

impl DirectConversationMaterializationDraft {
    pub fn founding_grant_payload(&self) -> Result<crate::events_payloads::CapabilityGrantPayload> {
        self.capability_grant_payload(
            &self.founding_grant_event,
            "direct conversation founding grant draft payload",
        )
    }

    pub fn main_strand_grant_payload(
        &self,
    ) -> Result<crate::events_payloads::CapabilityGrantPayload> {
        self.capability_grant_payload(
            &self.main_strand_grant_event,
            "direct conversation main Strand grant draft payload",
        )
    }

    pub fn founding_grant_id(&self) -> Result<GrantId> {
        Ok(self.founding_grant_payload()?.grant_id)
    }

    pub fn main_strand_grant_id(&self) -> Result<GrantId> {
        Ok(self.main_strand_grant_payload()?.grant_id)
    }

    pub fn expected_event_ids(&self) -> Vec<&EventId> {
        let mut event_ids = vec![
            &self.realm_event.event_id,
            &self.founding_grant_event.event_id,
        ];
        if let Some(event) = &self.creator_member_event {
            event_ids.push(&event.event_id);
        }
        event_ids.extend([
            &self.peer_member_event.event_id,
            &self.main_strand_grant_event.event_id,
            &self.main_strand_event.event_id,
            &self.binding_event.event_id,
        ]);
        event_ids
    }

    fn capability_grant_payload(
        &self,
        event: &Event,
        context: &str,
    ) -> Result<crate::events_payloads::CapabilityGrantPayload> {
        serde_json::from_value(serde_json::to_value(&event.payload)?)
            .map_err(|error| Error::Protocol(format!("{context} is invalid: {error}")))
    }

    pub fn validate_shape(&self) -> Result<()> {
        let mut expected = vec![
            (&self.realm_event, EventKind::REALM_CREATE),
            (&self.founding_grant_event, EventKind::CAPABILITY_GRANT),
            (&self.peer_member_event, EventKind::MEMBER_STATE),
            (&self.main_strand_grant_event, EventKind::CAPABILITY_GRANT),
            (&self.main_strand_event, EventKind::STRAND_CREATE),
            (&self.binding_event, EventKind::DIRECT_CONVERSATION_BOUND),
        ];
        if let Some(event) = &self.creator_member_event {
            expected.push((event, EventKind::MEMBER_STATE));
        }
        if expected
            .iter()
            .any(|(event, kind)| event.kind.as_str() != *kind || !event.proofs.is_empty())
        {
            return Err(Error::Protocol(
                "direct conversation materialization Event draft shape is invalid".into(),
            ));
        }
        if self.creator_member_event.as_ref().is_some_and(|event| {
            self.realm_event.realm_id != event.realm_id
                || self.realm_event.actor_id != event.actor_id
        }) || self.realm_event.realm_id != self.peer_member_event.realm_id
            || self.realm_event.realm_id != self.main_strand_event.realm_id
            || self.realm_event.realm_id != self.founding_grant_event.realm_id
            || self.realm_event.realm_id != self.main_strand_grant_event.realm_id
            || self.realm_event.actor_id != self.peer_member_event.actor_id
            || self.realm_event.actor_id != self.founding_grant_event.actor_id
            || self.realm_event.actor_id != self.main_strand_grant_event.actor_id
            || self.realm_event.actor_id != self.main_strand_event.actor_id
            || self.realm_event.actor_id != self.binding_event.actor_id
        {
            return Err(Error::Protocol(
                "direct conversation materialization Event draft binding is invalid".into(),
            ));
        }
        let founding_payload = self.founding_grant_payload()?;
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
        let strand_grant_payload = self.main_strand_grant_payload()?;
        let strand_grant = strand_grant_payload.grant.ok_or_else(|| {
            Error::Protocol("direct conversation main Strand grant draft is absent".into())
        })?;
        let realm_resource_is_exact = strand_grant.resources.len() == 1
            && strand_grant.resources[0].kind == arkret_wire::ResourceSelectorKind::Realm
            && strand_grant.resources[0].realm_id.as_ref() == Some(&self.realm_event.realm_id)
            && strand_grant.resources[0].match_scope
                == Some(arkret_wire::ResourceMatchScope::RealmWide);
        let subject_is_creator = matches!(
            &strand_grant.subject,
            crate::governance::grant_constraint::CapabilitySubject::Did(subject)
                if subject == &self.main_strand_grant_event.actor_id
        );
        if strand_grant.id != strand_grant_payload.grant_id
            || strand_grant.issuer != self.main_strand_grant_event.actor_id
            || !subject_is_creator
            || strand_grant.actions.as_slice() != [EventKind::STRAND_CREATE]
            || !realm_resource_is_exact
            || !strand_grant.proofs.is_empty()
        {
            return Err(Error::Protocol(
                "direct conversation main Strand grant must be an exact unsigned issuer draft"
                    .into(),
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub verification_method: DeviceId,
    pub alg: NonEmptyString,
    pub transcript_digest: Hash,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingToDeviceChallengeTranscript {
    pub transaction_id: NonEmptyString,
    pub request_canonical_digest: Hash,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    /// short-link (`ak.open.device_pairing.query.resolve`), it echoes the staged
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

/// Body of the unauthenticated resolve call
/// (`POST /_arkret/open/device-pairing/resolve`,
/// `ak.open.device_pairing.query.resolve`). The token is the compact
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
/// `ak.open.device_pairing.query.status`) the new device calls while waiting
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
        EventId::new(format!("ak:event:01964137-0000-7000-8000-{suffix:0>12}")).unwrap()
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:01964137-0000-7000-8000-000000000001".to_owned()).unwrap()
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
            id: event_id("1").to_string(),
            reason_code: "dependency_missing".to_owned(),
            missing_event_ids: vec![event_id("2")],
            ..Default::default()
        };
        assert!(rejected.validate_dependency_details().is_ok());
        rejected.missing_event_ids.clear();
        assert!(rejected.validate_dependency_details().is_err());
        rejected.reason_code = "signature_invalid".to_owned();
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
