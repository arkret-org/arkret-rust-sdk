//! Moderation queue vocabulary and queue-item container
//! (`moderation-queue-item.schema.json`).

use arkret_wire::{DidCoreId, EventId, ModerationQueueItemId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::moderation::ModerationReportPayload;

// ---------------------------------------------------------------------------
// Moderation queue item (moderation-queue-item.schema.json)
// ---------------------------------------------------------------------------

/// Queue-item lifecycle (`moderation-queue-item.schema.json`). v1 is
/// intentionally two-state (content-moderation.md §3.3): `submitted` = report
/// accepted and awaiting handling, `resolved` = handling complete (terminal).
/// The disposition lives on the separate `ak.moderation.decision` event, and
/// §5.4 forbids fabricating additional enum values for policy review items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueStatus {
    Submitted,
    Resolved,
}

/// Priority bucket for queue routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueuePriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Visibility class describing what evidence form the queue carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueVisibility {
    MetadataOnly,
    EncryptedEvidence,
    PlaintextEvidence,
    FrankingProofOnly,
}

/// Evidence-handling policy embedded in a queue item. Both booleans are
/// derived from the same accepted material as `visibility`
/// (content-moderation.md §3.3 item 4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationEvidencePolicy {
    pub plaintext_allowed: bool,
    pub franking_proof_verification_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub retention_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
}

impl ModerationQueueItem {
    pub const SCHEMA: &'static str = SchemaId::MODERATION_QUEUE_ITEM_V1;

    /// The queue item identity of one accepted report Event.
    #[must_use]
    pub fn id_for_report(report_event_id: &EventId) -> ModerationQueueItemId {
        ModerationQueueItemId::from_event_id(report_event_id)
    }
}

include!("generated/moderation_queue_contracts.rs");
