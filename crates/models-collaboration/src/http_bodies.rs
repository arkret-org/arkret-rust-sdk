//! Collaboration HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json`): events submit/resolve and
//! subscribe frames, ephemeral submission, query projections
//! (space/strand/morph), blob transfer headers, and the MIMI interop
//! operation bodies. Cross-domain aggregation outcomes and auth-domain
//! session bodies remain with their semantic owners.

use std::collections::BTreeMap;

use arkret_models_identity::ServiceResolutionCarrier;
use arkret_models_identity::agent_signer_evidence::AgentEventAdmissionReceipt;
use arkret_wire::{
    AccountId, ActorId, AppletId, AuditReasonText, Base64UrlString, BlobRef, ConsentId,
    ControlProposalAck, Cursor, DeviceId, DidCoreId, DidKey, Event, EventFederationSubmission,
    EventId, EventInitialSubmission, Hash, IngressReceipt, MimiRoomUri, MlsGroupId, MorphId,
    NonEmptyString, PayloadProof, ProofContextId, RealmId, ReasonCode, RelationId, ReportId,
    Result, Seal, SealId, ServiceOperationId, SignalEnvelope, SpaceId, StrandId, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contact_operations::{
    ContactContinuityEvidence, ContactNextPrepareInput, ContactPeer, ContactScope,
    RequestAcceptanceReceipt,
};
use crate::event_sync::RealmActorFrontierView;
use crate::events_payloads::event_wire::decode_payload_after_kind_validation;
use crate::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, SignatureMaterial,
};
use crate::governance::agent_artifacts::{DeviceMetadata, GrantSnapshot, PublicKey};
use crate::governance::agent_membership_cascade::AgentMembershipCascadeOutcome;
use crate::history_key::{
    DirectorySourceRefAccess, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
};
use crate::objects::blob::BlobUploadMetadata;
use crate::objects::mimi::{
    MimiCiphertext, MimiConsentPurpose, MimiConsentTarget, MimiDelivery, MimiFailure,
    MimiGroupInfo, MimiIdentifier, MimiIdentifierMatch, MimiKeyPackage, MimiNotification,
    MimiNotificationRouting, MimiOhttpContext, MimiOpaquePayload, MimiRoomUpdate,
};
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
            return Err(WireError::Protocol(
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
    type Error = WireError;

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
            return Err(WireError::Protocol(
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
    type Error = WireError;

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

impl EventsSubmitStatus {
    /// The wire token, so a diagnostic can quote what the server actually sent
    /// instead of the Rust variant name. Mirrors `ReasonCode::as_str`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Partial => "partial",
            Self::HistoricalOnly => "historical_only",
        }
    }
}

impl std::fmt::Display for EventsSubmitStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDeliveryStateView {
    Complete,
    Pending,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDeliveryTargetState {
    PendingRoute,
    PendingDelivery,
    Delivered,
    CancelledAuthorityLost,
}

impl EventDeliveryTargetState {
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::PendingRoute | Self::PendingDelivery)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryTargetStatus {
    pub target_id: String,
    pub status: EventDeliveryTargetState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
}

impl EventDeliveryTargetStatus {
    pub fn validate(&self) -> Result<()> {
        let bytes = self.target_id.as_bytes();
        if !(16..=128).contains(&bytes.len())
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            return Err(WireError::Protocol(
                "event delivery target_id must be an opaque 16..128 byte base64url-style token"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryStatusRequestBody {
    pub event_id: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryStatusOutcome {
    pub event_id: EventId,
    pub targets: Vec<EventDeliveryTargetStatus>,
}

impl EventDeliveryStatusOutcome {
    #[must_use]
    pub fn pending_delivery_count(&self) -> u32 {
        self.targets
            .iter()
            .filter(|target| target.status.is_pending())
            .count() as u32
    }

    #[must_use]
    pub fn delivery_state(&self) -> EventDeliveryStateView {
        if self.pending_delivery_count() == 0 {
            EventDeliveryStateView::Complete
        } else {
            EventDeliveryStateView::Pending
        }
    }

    pub fn validate_for_request(&self, request: &EventDeliveryStatusRequestBody) -> Result<()> {
        if self.event_id != request.event_id {
            return Err(WireError::Protocol(
                "event delivery status response event_id does not match the request".to_owned(),
            ));
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.len() > 1000 {
            return Err(WireError::Protocol(
                "event delivery status exceeds the 1000-target bound".to_owned(),
            ));
        }
        let mut previous: Option<&str> = None;
        for target in &self.targets {
            target.validate()?;
            if previous.is_some_and(|previous| previous >= target.target_id.as_str()) {
                return Err(WireError::Protocol(
                    "event delivery targets must be strictly sorted by unique target_id".to_owned(),
                ));
            }
            previous = Some(target.target_id.as_str());
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitRejectedRow`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsSubmitRejectedRow {
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
            return Err(WireError::Protocol(
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

/// `service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitOutcome {
    pub status: EventsSubmitStatus,
    #[serde(default)]
    pub accepted: Vec<EventId>,
    pub pending_delivery_count: u32,
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
    pub agent_event_admission_receipts: Vec<AgentEventAdmissionReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<EventsSubmitRejectedRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<EventId>,
    /// Post-submit actor authoring frontiers sorted and unique by
    /// `(realm_id, actor_id)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontiers: Vec<RealmActorFrontierView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_outcome: Option<Box<EventsSubmitOutcome>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_membership_cascade: Option<AgentMembershipCascadeOutcome>,
}

impl EventsSubmitOutcome {
    #[must_use]
    pub const fn delivery_state(&self) -> EventDeliveryStateView {
        if self.pending_delivery_count == 0 {
            EventDeliveryStateView::Complete
        } else {
            EventDeliveryStateView::Pending
        }
    }

    pub fn validate_delivery_invariants(&self) -> Result<()> {
        if self.status == EventsSubmitStatus::HistoricalOnly {
            if !self.accepted.is_empty() || self.pending_delivery_count != 0 {
                return Err(WireError::Protocol(
                    "historical_only submit outcomes require accepted=[] and delivery complete/0"
                        .to_owned(),
                ));
            }
            let original = self.original_outcome.as_ref().ok_or_else(|| {
                WireError::Protocol(
                    "historical_only submit outcome requires original_outcome".to_owned(),
                )
            })?;
            if original.status == EventsSubmitStatus::HistoricalOnly {
                return Err(WireError::Protocol(
                    "historical_only original_outcome cannot be historical_only".to_owned(),
                ));
            }
            original.validate_delivery_invariants()?;
        }
        let accepted_or_duplicate = self
            .accepted
            .iter()
            .chain(&self.duplicate)
            .collect::<std::collections::BTreeSet<_>>();
        let mut receipt_keys = std::collections::BTreeSet::new();
        for receipt in &self.agent_event_admission_receipts {
            if !accepted_or_duplicate.contains(&receipt.event_id) {
                return Err(WireError::Protocol(
                    "Agent Event admission receipt does not match an accepted or duplicate Event"
                        .to_owned(),
                ));
            }
            let key = (&receipt.event_id, &receipt.receiver_id);
            if !receipt_keys.insert(key) {
                return Err(WireError::Protocol(
                    "Agent Event admission receipts contain a duplicate selector".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// `ak.edge.applet.command.transaction.v1` request body. Carries wire `Event`s
/// plus an optional `SignalEnvelope` batch, so it lives here rather than with
/// the other applet DTOs in `arkret-models-integration` (which does not depend
/// on this crate).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletTransactionRequestBody {
    pub applet_id: AppletId,
    pub source_id: DidCoreId,
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
#[serde(deny_unknown_fields)]
pub struct EventView {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: EventReadRow,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_traversal_access: Option<SelfHistoryTraversalAccess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl EventsResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_ids.is_empty() && self.event_digests.is_empty() {
            return Err(WireError::Protocol(
                "events resolve requires at least one selector".to_owned(),
            ));
        }
        if self.event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
        {
            return Err(WireError::Protocol(
                "events resolve selector limit exceeded".to_owned(),
            ));
        }
        if self
            .max_response_bytes
            .is_some_and(|bytes| !(1024..=MAX_PEER_RESOLVE_RESPONSE_BYTES).contains(&bytes))
        {
            return Err(WireError::Protocol(
                "events resolve max_response_bytes is outside 1024..=8388608".to_owned(),
            ));
        }
        if !unique_strings(self.event_ids.iter().map(EventId::as_str))
            || !unique_strings(self.event_digests.iter().map(Hash::as_str))
        {
            return Err(WireError::Protocol(
                "events resolve selectors must be duplicate-free".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsResolveOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

pub const MAX_SEAL_RESOLVE_SELECTORS: usize = 256;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealResolveRequestCore {
    pub realm_id: RealmId,
    pub seal_refs: Vec<SealId>,
}

impl SealResolveRequestCore {
    pub fn validate(&self) -> Result<()> {
        validate_seal_resolve_selectors(&self.seal_refs)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfSealResolveRequestBody {
    pub realm_id: RealmId,
    pub seal_refs: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_traversal_access: Option<SelfHistoryTraversalAccess>,
}

impl SelfSealResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_seal_resolve_selectors(&self.seal_refs)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSealResolveRequestBody {
    pub realm_id: RealmId,
    pub seal_refs: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_traversal_access: Option<PeerHistoryTraversalAccess>,
}

impl PeerSealResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_seal_resolve_selectors(&self.seal_refs)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealResolveOutcome {
    pub seals: Vec<Seal>,
    pub missing_seal_refs: Vec<SealId>,
}

impl SealResolveOutcome {
    pub fn validate_structural(&self) -> Result<()> {
        for seal in &self.seals {
            seal.validate_structural()?;
        }
        if self.seals.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || !unique_strings(self.missing_seal_refs.iter().map(SealId::as_str))
            || self.seals.iter().any(|seal| {
                self.missing_seal_refs
                    .iter()
                    .any(|missing| missing == &seal.id)
            })
        {
            return Err(WireError::Protocol(
                "Seal resolve outcome must be sorted and duplicate-free".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_peer_request(&self, request: &PeerSealResolveRequestBody) -> Result<()> {
        request.validate()?;
        self.validate_structural()?;
        let returned = self
            .seals
            .iter()
            .map(|seal| seal.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let missing = self
            .missing_seal_refs
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let requested = request
            .seal_refs
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if !returned.is_disjoint(&missing)
            || returned
                .union(&missing)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                != requested
        {
            return Err(WireError::Protocol(
                "peer Seal resolve outcome does not account for every-and-only selector".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_seal_resolve_selectors(seal_refs: &[SealId]) -> Result<()> {
    if seal_refs.is_empty()
        || seal_refs.len() > MAX_SEAL_RESOLVE_SELECTORS
        || !unique_strings(seal_refs.iter().map(SealId::as_str))
    {
        return Err(WireError::Protocol(
            "Seal resolve requires 1..=256 duplicate-free seal_refs".to_owned(),
        ));
    }
    Ok(())
}

fn unique_strings<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut unique = std::collections::BTreeSet::new();
    values.all(|value| unique.insert(value))
}

pub const MAX_PEER_RESOLVE_EVENT_SELECTORS: usize = 1024;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_traversal_access: Option<PeerHistoryTraversalAccess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_source_ref_access: Option<DirectorySourceRefAccess>,
}

impl PeerEventsResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_ids.is_empty() && self.event_digests.is_empty() {
            return Err(WireError::Protocol(
                "peer dependency resolve requires at least one selector".to_owned(),
            ));
        }
        if self.history_traversal_access.is_some() && self.directory_source_ref_access.is_some() {
            return Err(WireError::Protocol(
                "peer resolve access carriers are mutually exclusive".to_owned(),
            ));
        }
        if let Some(access) = &self.directory_source_ref_access {
            access.validate()?;
            if self.event_ids.is_empty() || !self.event_digests.is_empty() {
                return Err(WireError::Protocol(
                    "directory source-ref access requires event_ids and forbids event_digests"
                        .to_owned(),
                ));
            }
            if self.realm_id != access.realm_id
                || self
                    .event_ids
                    .iter()
                    .any(|event_id| !access.source_refs.contains(event_id))
            {
                return Err(WireError::Protocol(
                    "directory source-ref access does not bind every selector".to_owned(),
                ));
            }
        }
        if self.event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
        {
            return Err(WireError::Protocol(
                "peer dependency resolve selector limit exceeded".to_owned(),
            ));
        }
        if self
            .max_response_bytes
            .is_some_and(|bytes| !(1024..=MAX_PEER_RESOLVE_RESPONSE_BYTES).contains(&bytes))
        {
            return Err(WireError::Protocol(
                "peer dependency resolve max_response_bytes is outside 1024..=8388608".to_owned(),
            ));
        }
        if self.include_payload == Some(false) {
            return Err(WireError::Protocol(
                "peer dependency resolve requires the complete accepted Event payload".to_owned(),
            ));
        }
        validate_typed_missing_order(&self.event_ids, &self.event_digests, &[])
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsResolveOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<EventFederationSubmission>,
    pub missing_event_ids: Vec<EventId>,
    pub missing_event_digests: Vec<Hash>,
}

impl PeerEventsResolveOutcome {
    pub fn validate_structural(&self) -> Result<()> {
        if self.events.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.missing_event_ids.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
            || self.missing_event_digests.len() > MAX_PEER_RESOLVE_EVENT_SELECTORS
        {
            return Err(WireError::Protocol(
                "peer dependency resolve outcome limit exceeded".to_owned(),
            ));
        }
        let mut event_ids = std::collections::BTreeSet::new();
        for submission in &self.events {
            submission.validate_structural(
                submission.event.event_id.digest_suite_code().digest_suite(),
            )?;
            if !event_ids.insert(submission.event.event_id.clone()) {
                return Err(WireError::Protocol(
                    "peer dependency resolve events must be duplicate-free".to_owned(),
                ));
            }
        }
        validate_typed_missing_order(&self.missing_event_ids, &self.missing_event_digests, &[])?;
        Ok(())
    }

    pub fn validate_for_request(&self, request: &PeerEventsResolveRequestBody) -> Result<()> {
        request.validate()?;
        self.validate_structural()?;
        let mut returned_ids = std::collections::BTreeSet::new();
        let mut returned_digests = std::collections::BTreeSet::new();
        for submission in &self.events {
            let event = &submission.event;
            let selected_by_id = request.event_ids.contains(&event.event_id);
            let matching_digests = request
                .event_digests
                .iter()
                .filter_map(|expected| {
                    let suite = expected.digest_suite().ok()?;
                    let actual =
                        Hash::new(event.event_digest_with_digest_suite(suite).ok()?).ok()?;
                    (actual == *expected).then_some(actual)
                })
                .collect::<Vec<_>>();
            let selected_by_digest = !matching_digests.is_empty();
            if !selected_by_id && !selected_by_digest {
                return Err(WireError::Protocol(
                    "peer Event resolve returned an unrequested Event".to_owned(),
                ));
            }
            returned_ids.insert(event.event_id.clone());
            returned_digests.extend(matching_digests);
        }
        let missing_ids = self
            .missing_event_ids
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let missing_digests = self
            .missing_event_digests
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        for event_id in &request.event_ids {
            if returned_ids.contains(event_id) == missing_ids.contains(event_id) {
                return Err(WireError::Protocol(
                    "peer Event resolve does not account for every Event id selector".to_owned(),
                ));
            }
        }
        for digest in &request.event_digests {
            if returned_digests.contains(digest) == missing_digests.contains(digest) {
                return Err(WireError::Protocol(
                    "peer Event resolve does not account for every Event digest selector"
                        .to_owned(),
                ));
            }
        }
        if missing_ids
            .iter()
            .any(|event_id| !request.event_ids.contains(event_id))
            || missing_digests
                .iter()
                .any(|digest| !request.event_digests.contains(digest))
        {
            return Err(WireError::Protocol(
                "peer Event resolve reports an unrequested missing selector".to_owned(),
            ));
        }
        let byte_limit = request
            .max_response_bytes
            .unwrap_or(MAX_PEER_RESOLVE_RESPONSE_BYTES) as usize;
        if canonical::canonical_json_bytes(self)?.len() > byte_limit {
            return Err(WireError::Protocol(
                "peer Event resolve outcome exceeds the requested byte limit".to_owned(),
            ));
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
        return Err(WireError::Protocol(
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
    pub created_by: Option<ActorId>,
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

/// `service-operation-dtos.schema.json#/$defs/ProjectionSpaceList`.
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
    /// Derived current full ActorIds, including Station, from visible active
    /// `assigned_to` Relations. Empty means the Strand is unassigned for
    /// this projection caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_actor_ids: Vec<ActorId>,
    /// Active assignment Relation edges backing `assigned_actor_ids`.
    /// Clients use `relation_id` to tombstone an assignment during edits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to_relations: Vec<ProjectionAssignedToRelation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    /// COT-06-004 — derived flag: `true` when this Strand is the Realm's
    /// default Strand (`strand_id == Realm.default_strand_id`). Computed at query
    /// time from the Realm projection; never stored as a per-Strand column.
    pub is_default: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionAssignedToRelation {
    pub relation_id: RelationId,
    pub actor_id: ActorId,
}

/// `service-operation-dtos.schema.json#/$defs/ProjectionStrandList`.
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
    pub created_by: Option<ActorId>,
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

/// `service-operation-dtos.schema.json#/$defs/ProjectionMorphList`.
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
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventsSubscribeFrame {
    Event {
        realm_id: RealmId,
        cursor: Cursor,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        payload: Box<Event>,
    },
    EpochRotation {
        realm_id: RealmId,
        payload: EpochRotationPayload,
    },
    Frontier {
        cursor: Cursor,
    },
    CatchupComplete {
        cursor: Cursor,
    },
    Dropped {
        realm_id: RealmId,
        cursor: Cursor,
        #[serde(skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    ResyncRequired {
        #[serde(skip_serializing_if = "Option::is_none")]
        realm_id: Option<RealmId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    Unauthorized {
        #[serde(skip_serializing_if = "Option::is_none")]
        realm_id: Option<RealmId>,
    },
    Heartbeat,
}

impl<'de> Deserialize<'de> for EventsSubscribeFrame {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EventFields {
            realm_id: RealmId,
            cursor: Cursor,
            payload: Box<Event>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EpochFields {
            realm_id: RealmId,
            payload: EpochRotationPayload,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CursorFields {
            cursor: Cursor,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DroppedFields {
            realm_id: RealmId,
            cursor: Cursor,
            reconnect_after_ms: Option<u64>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ResyncFields {
            realm_id: Option<RealmId>,
            reconnect_after_ms: Option<u64>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct UnauthorizedFields {
            realm_id: Option<RealmId>,
        }

        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("events subscribe frame must be an object"))?;
        let kind = object
            .remove("kind")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| {
                serde::de::Error::custom("events subscribe frame requires string kind")
            })?;
        fn decode<T, E>(value: Value) -> std::result::Result<T, E>
        where
            T: serde::de::DeserializeOwned,
            E: serde::de::Error,
        {
            serde_json::from_value(value).map_err(E::custom)
        }

        let fields = Value::Object(std::mem::take(object));
        match kind.as_str() {
            "event" => {
                let f: EventFields = decode::<_, D::Error>(fields)?;
                Ok(Self::Event {
                    realm_id: f.realm_id,
                    cursor: f.cursor,
                    payload: f.payload,
                })
            }
            "epoch_rotation" => {
                let f: EpochFields = decode::<_, D::Error>(fields)?;
                Ok(Self::EpochRotation {
                    realm_id: f.realm_id,
                    payload: f.payload,
                })
            }
            "frontier" => {
                let f: CursorFields = decode::<_, D::Error>(fields)?;
                Ok(Self::Frontier { cursor: f.cursor })
            }
            "catchup_complete" => {
                let f: CursorFields = decode::<_, D::Error>(fields)?;
                Ok(Self::CatchupComplete { cursor: f.cursor })
            }
            "dropped" => {
                let f: DroppedFields = decode::<_, D::Error>(fields)?;
                validate_reconnect(f.reconnect_after_ms).map_err(serde::de::Error::custom)?;
                Ok(Self::Dropped {
                    realm_id: f.realm_id,
                    cursor: f.cursor,
                    reconnect_after_ms: f.reconnect_after_ms,
                })
            }
            "resync_required" => {
                let f: ResyncFields = decode::<_, D::Error>(fields)?;
                validate_reconnect(f.reconnect_after_ms).map_err(serde::de::Error::custom)?;
                Ok(Self::ResyncRequired {
                    realm_id: f.realm_id,
                    reconnect_after_ms: f.reconnect_after_ms,
                })
            }
            "unauthorized" => {
                let f: UnauthorizedFields = decode::<_, D::Error>(fields)?;
                Ok(Self::Unauthorized {
                    realm_id: f.realm_id,
                })
            }
            "heartbeat" if fields.as_object().is_some_and(serde_json::Map::is_empty) => {
                Ok(Self::Heartbeat)
            }
            "heartbeat" => Err(serde::de::Error::custom(
                "heartbeat forbids all fields except kind",
            )),
            _ => Err(serde::de::Error::custom(format!(
                "unknown events subscribe frame kind {kind}"
            ))),
        }
    }
}

fn validate_reconnect(value: Option<u64>) -> std::result::Result<(), &'static str> {
    if value.is_some_and(|value| !(1..=300_000).contains(&value)) {
        Err("reconnect_after_ms must be in 1..=300000")
    } else {
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRotationPayload {
    pub new_epoch: u32,
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
        matches!(self, Self::Dropped { .. } | Self::ResyncRequired { .. })
    }

    /// True iff catch-up replay has reached the live frontier.
    pub fn is_catchup_complete(&self) -> bool {
        matches!(self, Self::CatchupComplete { .. })
    }

    pub fn kind(&self) -> EventsSubscribeFrameKind {
        match self {
            Self::Event { .. } => EventsSubscribeFrameKind::Event,
            Self::Frontier { .. } => EventsSubscribeFrameKind::Frontier,
            Self::Heartbeat => EventsSubscribeFrameKind::Heartbeat,
            Self::CatchupComplete { .. } => EventsSubscribeFrameKind::CatchupComplete,
            Self::EpochRotation { .. } => EventsSubscribeFrameKind::EpochRotation,
            Self::Dropped { .. } => EventsSubscribeFrameKind::Dropped,
            Self::ResyncRequired { .. } => EventsSubscribeFrameKind::ResyncRequired,
            Self::Unauthorized { .. } => EventsSubscribeFrameKind::Unauthorized,
        }
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        match self {
            Self::Event { cursor, .. }
            | Self::Frontier { cursor }
            | Self::CatchupComplete { cursor }
            | Self::Dropped { cursor, .. } => Some(cursor),
            _ => None,
        }
    }
}

impl StreamTraceFrame for EventsSubscribeFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self.kind() {
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
        self.cursor().map(|cursor| cursor.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiKeyMaterialRequestBody {
    pub requester_id: DidCoreId,
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
    pub proofs: Vec<PayloadProof>,
}

impl MimiKeyMaterialRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1,
            Some(serde_json::to_value(&self.requester_id)?),
            vec![
                ("strand_id", serde_json::to_value(&self.strand_id)?),
                ("device_id", serde_json::to_value(&self.device_id)?),
            ],
            &self.payload_digest()?,
            proof,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiKeyMaterialOutcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keypackages: Vec<MimiKeyPackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info: Option<MimiGroupInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<MimiFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PayloadProof>,
}

impl MimiKeyMaterialOutcome {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_signature(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    /// Outcome families carry no wire issuer field: the signer identity is
    /// borne only by `verification_method` (`mimi-interop.md` §5.1).
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1,
            None,
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }
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
    pub sender_actor_id: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_binding_event: Option<EventInitialSubmission>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUpdateOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_state_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotifyRequestBody {
    pub notification: MimiNotification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_provider_id: Option<DidCoreId>,
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
    pub sender_actor_id: ActorId,
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
    pub rejections: Vec<MimiFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentRequestBody {
    pub requester_id: DidCoreId,
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
    pub proofs: Vec<PayloadProof>,
}

impl MimiRequestConsentRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
            Some(serde_json::to_value(&self.requester_id)?),
            vec![
                ("target", serde_json::to_value(&self.target)?),
                ("purpose", serde_json::to_value(self.purpose)?),
            ],
            &self.payload_digest()?,
            proof,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: ConsentId,
    pub status: MimiRequestConsentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiRequestConsentStatus {
    Requested,
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
    pub actor_id: ActorId,
    pub consent_event: EventInitialSubmission,
    pub signature: PayloadProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
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
            MimiConsentDecision::Accept => arkret_wire::event_kind_str::CONSENT_GRANT,
            MimiConsentDecision::Deny | MimiConsentDecision::Revoke => {
                arkret_wire::event_kind_str::CONSENT_REVOKE
            }
        };
        let event = &self.consent_event.event;
        if event.kind.as_str() != expected_kind || event.actor_id != self.actor_id {
            return Err(WireError::Protocol(
                "MIMI consent decision, event kind, and actor binding mismatch".to_owned(),
            ));
        }
        let payload_consent_id = event.payload.get("consent_id").and_then(Value::as_str);
        if payload_consent_id != Some(self.consent_id.as_str()) {
            return Err(WireError::Protocol(
                "MIMI consent event payload.consent_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical request value covered by the operation proof. The detached
    /// proof is omitted to avoid a self-referential digest.
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_signature(self)
    }

    /// Digest of the complete request with only the detached proof omitted.
    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    /// Canonical `ak.mimi_update_consent_request_proof.v1` transcript shared by
    /// MIMI consent proof producers and verifiers.
    pub fn signature_binding_bytes(&self) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1,
            Some(serde_json::to_value(&self.actor_id)?),
            vec![
                ("consent_id", serde_json::to_value(&self.consent_id)?),
                ("decision", serde_json::to_value(self.decision)?),
            ],
            &self.payload_digest()?,
            &self.signature,
        )
    }
}

/// Canonical unsigned MIMI body for the array-carrier families: the top-level
/// `proofs` member is removed outright — never set to `null` — and every
/// optional field that is actually present is retained (`mimi-interop.md` §5.1).
fn mimi_unsigned_body_without_proofs<T: Serialize>(body: &T) -> Result<Value> {
    let mut value = serde_json::to_value(body)?;
    mimi_body_object_mut(&mut value)?.remove("proofs");
    Ok(value)
}

/// Same rule for the two families whose detached proof is carried by a single
/// top-level `signature` member.
fn mimi_unsigned_body_without_signature<T: Serialize>(body: &T) -> Result<Value> {
    let mut value = serde_json::to_value(body)?;
    mimi_body_object_mut(&mut value)?.remove("signature");
    Ok(value)
}

fn mimi_body_object_mut(value: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    value.as_object_mut().ok_or_else(|| {
        WireError::Protocol("MIMI operation body must serialize as an object".to_owned())
    })
}

fn mimi_payload_digest(unsigned_body: &Value) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(unsigned_body)?).map_err(Into::into)
}

/// Canonical MIMI actor-proof transcript (`mimi-interop.md` §5.1).
///
/// `context` is the object family's own registered context, so a signature that
/// is valid under one family can never be replayed into another and a
/// request/outcome direction swap is blocked by the context alone. `targets`
/// carries the family's verbatim target identifiers in
/// `proof-context-registry.json` `binding_fields` order; `issuer` is present iff
/// the family's wire shape defines an originator field.
fn mimi_proof_binding_bytes(
    context: &str,
    operation_id: &str,
    issuer: Option<Value>,
    targets: Vec<(&'static str, Value)>,
    payload_digest: &Hash,
    proof: &PayloadProof,
) -> Result<Vec<u8>> {
    proof.validate_production()?;
    if proof.proof_purpose.is_some() {
        return Err(WireError::Protocol(
            "MIMI operation proof must not carry proof_purpose".to_owned(),
        ));
    }
    if &proof.payload_digest != payload_digest {
        return Err(WireError::Protocol(
            "MIMI operation proof payload_digest mismatch".to_owned(),
        ));
    }
    let domain = proof
        .domain
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| WireError::Protocol("MIMI operation proof requires domain".to_owned()))?;
    let audience = proof
        .audience
        .as_ref()
        .ok_or_else(|| WireError::Protocol("MIMI operation proof requires audience".to_owned()))?;
    let mut binding = serde_json::Map::new();
    binding.insert("context".to_owned(), Value::String(context.to_owned()));
    binding.insert(
        "payload_digest".to_owned(),
        serde_json::to_value(payload_digest)?,
    );
    if let Some(issuer) = issuer {
        binding.insert("issuer".to_owned(), issuer);
    }
    binding.insert(
        "operation_id".to_owned(),
        Value::String(operation_id.to_owned()),
    );
    for (name, value) in targets {
        binding.insert(name.to_owned(), value);
    }
    binding.insert(
        "verification_method".to_owned(),
        serde_json::to_value(&proof.verification_method)?,
    );
    binding.insert(
        "created_at".to_owned(),
        Value::String(canonical::format_timestamp_canonical(proof.created_at)),
    );
    binding.insert("domain".to_owned(), Value::String(domain.clone()));
    binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
    canonical::canonical_json_bytes(&Value::Object(binding)).map_err(Into::into)
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
    pub requester_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl MimiIdentifierQueryRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    /// `requester` may be absent; the transcript then omits `issuer` entirely
    /// rather than encoding a null (`mimi-interop.md` §5.1).
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        let issuer = match &self.requester_id {
            Some(requester) => Some(serde_json::to_value(requester)?),
            None => None,
        };
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
            issuer,
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    #[serde(default)]
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    pub has_more: bool,
}

impl MimiIdentifierQueryOutcome {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
            None,
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiReportAbuseRequestBody {
    pub strand_id: StrandId,
    pub mimi_room_uri: MimiRoomUri,
    pub realm_id: RealmId,
    pub target_ref: NonEmptyString,
    pub reporter_id: DidCoreId,
    pub source_provider_id: DidCoreId,
    pub reporter_authority: MimiReporterAuthority,
    pub report_event: EventInitialSubmission,
    pub abuse_reason_code: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<MimiOpaquePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<MimiOpaquePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiReporterAuthority {
    pub actor_id: ActorId,
    pub membership_event_id: EventId,
    pub room_binding_event_id: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

impl MimiReportAbuseRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        let authority = value
            .get_mut("reporter_authority")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                WireError::Protocol("MIMI reporter authority must be an object".to_owned())
            })?;
        authority.remove("proof").ok_or_else(|| {
            WireError::Protocol("MIMI reporter authority proof is required".to_owned())
        })?;
        Ok(value)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn reporter_authority_binding_bytes(&self) -> Result<Vec<u8>> {
        let authority = &self.reporter_authority;
        if authority.actor_id.signing_principal_id() != &self.reporter_id {
            return Err(WireError::Protocol(
                "MIMI reporter authority actor does not bind reporter_id".to_owned(),
            ));
        }
        if authority.expires_at <= authority.proof.created_at {
            return Err(WireError::Protocol(
                "MIMI reporter authority expiry must follow proof creation".to_owned(),
            ));
        }
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_REPORTER_AUTHORITY_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1,
            Some(serde_json::to_value(&authority.actor_id)?),
            vec![
                ("reporter_id", serde_json::to_value(&self.reporter_id)?),
                (
                    "source_provider_id",
                    serde_json::to_value(&self.source_provider_id)?,
                ),
                ("mimi_room_uri", serde_json::to_value(&self.mimi_room_uri)?),
                ("realm_id", serde_json::to_value(&self.realm_id)?),
                ("strand_id", serde_json::to_value(&self.strand_id)?),
                ("target_ref", serde_json::to_value(&self.target_ref)?),
                ("report_event", serde_json::to_value(&self.report_event)?),
                (
                    "membership_event_id",
                    serde_json::to_value(&authority.membership_event_id)?,
                ),
                (
                    "room_binding_event_id",
                    serde_json::to_value(&authority.room_binding_event_id)?,
                ),
                (
                    "expires_at",
                    Value::String(canonical::format_timestamp_canonical(authority.expires_at)),
                ),
            ],
            &self.payload_digest()?,
            &authority.proof,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiReportAbuseOutcome {
    pub report_id: ReportId,
    pub status: MimiReportAbuseStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to_ids: Vec<DidCoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiReportAbuseStatus {
    Queued,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiProxyDownloadRequestBody {
    pub asset_ref: NonEmptyString,
    pub requester_id: DidCoreId,
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
    pub binding_event_ref: EventId,
    pub state: DirectConversationSummaryState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAgentProjection {
    pub actor_id: ActorId,
    pub controller_account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/contact_list_row`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(try_from = "ContactListRowWire")]
pub struct ContactListRow {
    pub peer: ContactPeer,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_receipt: Option<RequestAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_prepare_input: Option<ContactNextPrepareInput>,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    pub granted_by_peer_scopes: Vec<ContactScope>,
    pub bidirectional_scopes: Vec<ContactScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scopes: Option<Vec<ContactScope>>,
    /// Station service DID hosting the peer, when known (e.g. learned
    /// from a cross-Station contact delivery). Lets the holder address
    /// responses/invites to the peer's home server. Omitted for
    /// same-Station contacts (spec contact-operations.schema.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_host_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_host_resolution: Option<ServiceResolutionCarrier>,
    /// Portable checkpoint plus the exact remaining tail. Present only after
    /// both participant Stations have committed the same checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_evidence: Option<ContactContinuityEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
    /// Active agents controlled by this contact that currently accept direct
    /// messages from the authenticated actor. This is a viewer-specific,
    /// fail-closed projection; clients must not infer it from public selector
    /// claims.
    #[serde(
        rename = "contact_agents",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub contact_agent_projections: Vec<ContactAgentProjection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactListRowWire {
    peer: ContactPeer,
    state: ContactState,
    #[serde(default)]
    request_event_ref: Option<EventId>,
    #[serde(default)]
    request_receipt: Option<RequestAcceptanceReceipt>,
    #[serde(default)]
    response_event_ref: Option<EventId>,
    #[serde(default)]
    tombstone_event_ref: Option<EventId>,
    #[serde(default)]
    next_prepare_input: Option<ContactNextPrepareInput>,
    granted_to_peer_scopes: Vec<ContactScope>,
    granted_by_peer_scopes: Vec<ContactScope>,
    bidirectional_scopes: Vec<ContactScope>,
    #[serde(default)]
    effective_scopes: Option<Vec<ContactScope>>,
    #[serde(default)]
    peer_host_id: Option<DidCoreId>,
    #[serde(default)]
    peer_host_resolution: Option<ServiceResolutionCarrier>,
    #[serde(default)]
    continuity_evidence: Option<ContactContinuityEvidence>,
    #[serde(default)]
    direct_conversation: Option<DirectConversationSummary>,
    #[serde(default)]
    contact_agents: Vec<ContactAgentProjection>,
}

impl TryFrom<ContactListRowWire> for ContactListRow {
    type Error = WireError;

    fn try_from(wire: ContactListRowWire) -> Result<Self> {
        let row = Self {
            peer: wire.peer,
            state: wire.state,
            request_event_ref: wire.request_event_ref,
            request_receipt: wire.request_receipt,
            response_event_ref: wire.response_event_ref,
            tombstone_event_ref: wire.tombstone_event_ref,
            next_prepare_input: wire.next_prepare_input,
            granted_to_peer_scopes: wire.granted_to_peer_scopes,
            granted_by_peer_scopes: wire.granted_by_peer_scopes,
            bidirectional_scopes: wire.bidirectional_scopes,
            effective_scopes: wire.effective_scopes,
            peer_host_id: wire.peer_host_id,
            peer_host_resolution: wire.peer_host_resolution,
            continuity_evidence: wire.continuity_evidence,
            direct_conversation: wire.direct_conversation,
            contact_agent_projections: wire.contact_agents,
        };
        row.validate_shape()?;
        Ok(row)
    }
}

impl ContactListRow {
    pub fn validate_shape(&self) -> Result<()> {
        if (self.state == ContactState::PendingIncoming) != self.request_receipt.is_some() {
            return Err(WireError::Protocol(
                "request_receipt must be present exactly for pending_incoming Contact rows"
                    .to_owned(),
            ));
        }
        if let Some(receipt) = &self.request_receipt {
            receipt.validate_shape()?;
            if self.request_event_ref.as_ref() != Some(&receipt.core.request_event_ref) {
                return Err(WireError::Protocol(
                    "Contact row request_event_ref does not match request_receipt".to_owned(),
                ));
            }
        }
        if (self.state == ContactState::Accepted) != self.next_prepare_input.is_some() {
            return Err(WireError::Protocol(
                "next_prepare_input must be present exactly for accepted Contact rows".to_owned(),
            ));
        }
        if let Some(input) = &self.next_prepare_input {
            input.validate_shape()?;
        }
        if self
            .effective_scopes
            .as_ref()
            .is_some_and(|scopes| scopes != &self.bidirectional_scopes)
        {
            return Err(WireError::Protocol(
                "effective_scopes must equal bidirectional_scopes when present".to_owned(),
            ));
        }
        Ok(())
    }
}

/// `contact-operations.schema.json#/$defs/contact_list`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ContactList {
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<arkret_wire::cursor::Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventReadRow {
    Event(Event),
    Redacted(RedactedEventView),
    ReferenceLocked(ReferenceLockedEventStub),
}

impl EventReadRow {
    pub fn event(&self) -> Option<&Event> {
        match self {
            Self::Event(event) => Some(event),
            Self::Redacted(_) | Self::ReferenceLocked(_) => None,
        }
    }

    pub fn into_event(self) -> Option<Event> {
        match self {
            Self::Event(event) => Some(event),
            Self::Redacted(_) | Self::ReferenceLocked(_) => None,
        }
    }
}

impl From<Event> for EventReadRow {
    fn from(event: Event) -> Self {
        Self::Event(event)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum RedactedEventViewKind {
    RedactedEventView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum EventRedactionReason {
    ReferenceLocked,
    HistoryNotVisible,
    PolicyHidden,
    Redacted,
    RetentionPruned,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
pub struct HiddenEventField(String);

impl HiddenEventField {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = matches!(value.as_str(), "payload" | "proofs" | "unsigned")
            || value.strip_prefix("payload.").is_some_and(|path| {
                !path.is_empty()
                    && path.split('.').all(|segment| {
                        !segment.is_empty()
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                            })
                    })
            });
        if !valid {
            return Err(WireError::Protocol(
                "hidden event field must be payload, payload.<field path>, proofs, or unsigned"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HiddenEventField {
    type Error = WireError;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<HiddenEventField> for String {
    fn from(value: HiddenEventField) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HiddenEventFields(Vec<HiddenEventField>);

impl HiddenEventFields {
    pub fn new(fields: Vec<HiddenEventField>) -> Result<Self> {
        let unique = fields.iter().collect::<std::collections::BTreeSet<_>>();
        if unique.len() != fields.len() {
            return Err(WireError::Protocol(
                "hidden_fields must not contain duplicates".to_owned(),
            ));
        }
        Ok(Self(fields))
    }

    pub fn as_slice(&self) -> &[HiddenEventField] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<HiddenEventField> {
        self.0
    }
}

impl TryFrom<Vec<HiddenEventField>> for HiddenEventFields {
    type Error = WireError;

    fn try_from(fields: Vec<HiddenEventField>) -> Result<Self> {
        Self::new(fields)
    }
}

impl<'de> Deserialize<'de> for HiddenEventFields {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = Vec::<HiddenEventField>::deserialize(deserializer)?;
        Self::new(fields).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RedactedEventView {
    pub view_kind: RedactedEventViewKind,
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<Hash>,
    pub redaction_reason: EventRedactionReason,
    pub hidden_fields: HiddenEventFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub inclusion_proof: Option<BTreeMap<String, Value>>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub reducer_input: ReducerInputFalse,
}

impl RedactedEventView {
    pub fn event_digest(&self) -> Hash {
        self.event_id.event_digest()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ReferenceLockedEventStubKind {
    ReferenceLockedEventStub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ReferenceLockedEventStatus {
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ReferenceLockedReasonCode {
    ReferenceLocked,
    HistoryNotVisible,
    PolicyHidden,
    NotFoundOrUnauthorized,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReducerInputFalse;

impl Serialize for ReducerInputFalse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for ReducerInputFalse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom("reducer_input must be false"));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReferenceLockedEventStub {
    pub view_kind: ReferenceLockedEventStubKind,
    pub status: ReferenceLockedEventStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<String>)))]
    pub kind: Option<arkret_wire::EventKind>,
    pub realm_id: RealmId,
    pub reason_code: ReferenceLockedReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub inclusion_proof: Option<BTreeMap<String, Value>>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub reducer_input: ReducerInputFalse,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsQueryOutcome {
    // Required by the schema; an absent array is not an empty result page.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<EventReadRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsQueryOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<EventReadRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
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
            return Err(WireError::Protocol(
                "device pairing nonce must contain 22..=86 base64url characters".to_owned(),
            ));
        }
        Ok(Self(
            Base64UrlString::new(value).map_err(|error| WireError::Protocol(error.to_owned()))?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for DevicePairingNonce {
    type Error = WireError;

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

/// The only target-device authority for accepted-device pairing key material.
///
/// This closed object travels out of band. It is deliberately not a field of
/// `AccountDevicePairRequestBody`; the Account Authority reconstructs the same
/// signing object from the request challenge and authorize Event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DevicePairingTargetAttestation {
    pub device_id: DeviceId,
    pub device_public_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub algorithms: Vec<NonEmptyString>,
    pub device_key_algorithm: DevicePairingTargetKeyAlgorithm,
    pub authorization_binding_kind: DeviceAuthorizationBindingKind,
    pub pairing_challenge_transcript_digest: Hash,
    pub device_signature: SignatureMaterial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DevicePairingTargetKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Target-owned accepted-device pairing material before its possession proof.
/// This type is intentionally not serializable, so unsigned attestations cannot
/// accidentally leave the device.
#[derive(Clone, Debug)]
pub struct UnsignedDevicePairingTargetAttestation {
    device_id: DeviceId,
    device_public_key_did: DidKey,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    pairing_challenge_transcript_digest: Hash,
}

impl UnsignedDevicePairingTargetAttestation {
    pub fn new(
        device_id: DeviceId,
        device_public_key_did: DidKey,
        hpke_key: NonEmptyString,
        algorithms: Vec<NonEmptyString>,
        pairing_challenge_transcript_digest: Hash,
    ) -> Result<Self> {
        if algorithms.is_empty()
            || algorithms
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(WireError::Protocol(
                "pairing target algorithms must be non-empty, sorted and unique".to_owned(),
            ));
        }
        Ok(Self {
            device_id,
            device_public_key_did,
            hpke_key,
            algorithms,
            pairing_challenge_transcript_digest,
        })
    }

    pub fn signing_input(&self) -> Result<Vec<u8>> {
        device_pairing_target_attestation_signing_input(
            &self.algorithms,
            self.device_id.as_str(),
            self.device_public_key_did.as_str(),
            self.hpke_key.as_str(),
            self.pairing_challenge_transcript_digest.as_str(),
        )
    }

    pub fn attach_signature(
        self,
        device_signature: SignatureMaterial,
    ) -> DevicePairingTargetAttestation {
        DevicePairingTargetAttestation {
            device_id: self.device_id,
            device_public_key_did: self.device_public_key_did,
            hpke_key: self.hpke_key,
            algorithms: self.algorithms,
            device_key_algorithm: DevicePairingTargetKeyAlgorithm::Ed25519,
            authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
            pairing_challenge_transcript_digest: self.pairing_challenge_transcript_digest,
            device_signature,
        }
    }
}

impl DevicePairingTargetAttestation {
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        if self.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice {
            return Err(WireError::Protocol(
                "pairing target attestation must use accepted_device binding".to_owned(),
            ));
        }
        UnsignedDevicePairingTargetAttestation::new(
            self.device_id.clone(),
            self.device_public_key_did.clone(),
            self.hpke_key.clone(),
            self.algorithms.clone(),
            self.pairing_challenge_transcript_digest.clone(),
        )?
        .signing_input()
    }

    /// Validate the pre-assembly binding before an approving device authors the
    /// exact `ak.device.authorize` Event carried by `pair_device`.
    pub fn validate_against_pair_request(
        &self,
        request: &AccountDevicePairRequestBody,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        request.validate_authorize_event_binding(digest_suite)?;
        let payload: DeviceAuthorizePayload =
            decode_payload_after_kind_validation(&request.authorize_event.event)?;
        let public_key_bytes = arkret_canonical::base64url_decode(
            request.new_device_pubkey.key.as_str(),
        )
        .map_err(|error| WireError::Protocol(format!("invalid pairing public key: {error}")))?;
        let attested_key_bytes = arkret_canonical::decode_ed25519_multibase(
            self.device_public_key_did
                .as_str()
                .strip_prefix("did:key:")
                .expect("DidKey enforces the did:key prefix"),
        )
        .map_err(|error| WireError::Protocol(format!("invalid attested did:key: {error}")))?;
        if self.device_id.as_str() != request.new_device_pubkey.kid.as_str()
            || public_key_bytes.as_slice() != attested_key_bytes.as_slice()
            || self.pairing_challenge_transcript_digest != request.challenge_proof.transcript_digest
            || payload.device_id != self.device_id
            || payload.device_public_key_did.as_str() != self.device_public_key_did.as_str()
            || payload.hpke_key != self.hpke_key
            || payload.algorithms != self.algorithms
            || payload
                .device_key_algorithm
                .as_ref()
                .map(NonEmptyString::as_str)
                != Some("Ed25519")
            || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice
            || payload.device_signature != self.device_signature
        {
            return Err(WireError::Protocol(
                "pairing target attestation does not match the exact pair request/Event".to_owned(),
            ));
        }
        self.signing_input().map(|_| ())
    }
}

fn device_pairing_target_attestation_signing_input(
    algorithms: &[NonEmptyString],
    device_id: &str,
    device_public_key_did: &str,
    hpke_key: &str,
    pairing_challenge_transcript_digest: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SigningObject<'a> {
        algorithms: &'a [NonEmptyString],
        authorization_binding_kind: DeviceAuthorizationBindingKind,
        device_id: &'a str,
        device_key_algorithm: &'static str,
        device_public_key_did: &'a str,
        hpke_key: &'a str,
        pairing_challenge_transcript_digest: &'a str,
    }
    let object = SigningObject {
        algorithms,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        device_id,
        device_key_algorithm: "Ed25519",
        device_public_key_did,
        hpke_key,
        pairing_challenge_transcript_digest,
    };
    let mut bytes = b"ak.device_authorize_accepted_device_possession_proof.v1\n".to_vec();
    bytes.extend(canonical::canonical_json_bytes(&object)?);
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: DevicePairingCode,
    pub new_device_pubkey: PublicKey,
    pub challenge_proof: DevicePairingChallengeProof,
    pub authorize_event: EventInitialSubmission,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
    /// When the approving device recovered this pairing via the server-mediated
    /// short-link (`ak.open.device_pairing.read.resolve.v1`), it echoes the staged
    /// `device_pairing_request_id` here so the server can flip that staged row to
    /// `authorized` (carrying `device_id` + `authorized_event_ref`) for the new
    /// device's status poll to observe. Omitted for direct QR/paste pairing that
    /// never staged server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pairing_request_id: Option<DevicePairingRequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_transcript: Option<DevicePairingToDeviceChallengeTranscript>,
}

impl AccountDevicePairRequestBody {
    /// Validate that the gate only relays the approving device's exact Event.
    pub fn validate_authorize_event_binding(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.authorize_event.validate_structural(digest_suite)?;
        if arkret_wire::EventKind::DeviceAuthorize != self.authorize_event.event.kind {
            return Err(WireError::Protocol(
                "device-pair authorize_event is not ak.device.authorize".to_owned(),
            ));
        }
        let payload: DeviceAuthorizePayload =
            decode_payload_after_kind_validation(&self.authorize_event.event)?;
        let payload_key = payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| {
                WireError::Protocol("device-pair authorize Event key is not did:key".to_owned())
            })?;
        let payload_key =
            arkret_canonical::decode_ed25519_multibase(payload_key).map_err(|error| {
                WireError::Protocol(format!("invalid authorize Event did:key: {error}"))
            })?;
        let request_key = arkret_canonical::base64url_decode(self.new_device_pubkey.key.as_str())
            .map_err(|error| {
            WireError::Protocol(format!("invalid request public key: {error}"))
        })?;
        if payload.device_id.as_str() != self.new_device_pubkey.kid.as_str()
            || request_key.as_slice() != payload_key.as_slice()
            || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice
            || payload
                .device_key_algorithm
                .as_ref()
                .map(NonEmptyString::as_str)
                != Some("Ed25519")
        {
            return Err(WireError::Protocol(
                "device-pair request fields do not match the exact authorize Event payload"
                    .to_owned(),
            ));
        }
        Ok(())
    }
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
// `ak.gate.account.command.pair_device.v1`. See
// `crypto-media/device-lifecycle.md` §2.1.

/// Staging request POSTed by a not-yet-authorized device to the unauthenticated
/// `POST /_arkret/open/device-pairing/requests`
/// (`ak.open.device_pairing.command.stage.v1`). The staged row is account-less and
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
    pub gate_audience_uri: String,
    pub server_nonce: DevicePairingNonce,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Body of the unauthenticated resolve call
/// (`POST /_arkret/open/device-pairing/resolve`,
/// `ak.open.device_pairing.read.resolve.v1`). The token is the compact
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
/// `ak.gate.account.command.pair_device.v1`.
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
    pub gate_audience_uri: String,
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
/// `ak.open.device_pairing.read.status.v1`) the new device calls while waiting
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

#[cfg(test)]
#[path = "http_bodies_tests.rs"]
mod tests;
