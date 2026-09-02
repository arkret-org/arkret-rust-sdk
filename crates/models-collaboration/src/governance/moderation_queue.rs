//! Moderation queue vocabulary and queue-item container
//! (`moderation-queue-item.schema.json`).

use arkret_wire::{DidCoreId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::moderation::ModerationReport;

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

/// Evidence-handling policy embedded in a queue item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationEvidencePolicy {
    pub plaintext_allowed: bool,
    pub franking_proof_verification_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub retention_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
}

/// Moderation queue container (`ak.component.moderation_queue.v1` cell
/// body). Mirrors `moderation-queue-item.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationQueueItem {
    /// `ak:moderation_queue_item:<uuidv7>`.
    pub id: String,
    /// The full report this queue entry represents.
    pub report: ModerationReport,
    pub status: ModerationQueueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<ModerationQueuePriority>,
    pub visibility: ModerationQueueVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_policy: Option<ModerationEvidencePolicy>,
    /// `ak:event:<44-char-token>` references to audit events recording queue
    /// actions (decisions, redirects, dismissals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_refs: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ModerationQueueItem {
    pub const SCHEMA: &'static str = SchemaId::MODERATION_QUEUE_ITEM_V1;
}

#[cfg(test)]
mod tests {
    use arkret_wire::RealmId;

    use super::*;

    #[test]
    fn queue_item_round_trips() {
        let item = ModerationQueueItem {
            id: "ak:moderation_queue_item:AeI4eUGRmaA9GYZ60CABKT42AUIqRSquqvnvBNywHzeG".to_owned(),
            report: ModerationReport::new(
                "ak:report:AeaUpT-cu-NcupBk54pDQtlp7O3sqCQzjyexZxvQhXbc",
                RealmId::new("ak:realm:AYXp4CiHLjKHg42IhFAbpOD0JiP1L-wLeEGGKcIuox_2").unwrap(),
                "ak:message:AXB4Wy8AgJaUH7vqjxD-xwHRsqpfyTp-qM7_vrf4j7ol",
                "spam",
                DidCoreId::new("ak:did_core:webvh:z6mkfixturereporter").unwrap(),
            ),
            status: ModerationQueueStatus::Submitted,
            priority: Some(ModerationQueuePriority::Normal),
            visibility: ModerationQueueVisibility::MetadataOnly,
            assigned_to_ids: vec![],
            evidence_policy: Some(ModerationEvidencePolicy {
                plaintext_allowed: false,
                franking_proof_verification_required: true,
                retention_expires_at: None,
                legal_hold: None,
            }),
            audit_refs: vec![],
            created_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
            updated_at: None,
        };
        let json_text = serde_json::to_string(&item).unwrap();
        assert!(json_text.contains(r#""status":"submitted""#));
        assert!(json_text.contains(r#""visibility":"metadata_only""#));
        let parsed: ModerationQueueItem = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, item);
    }
}
