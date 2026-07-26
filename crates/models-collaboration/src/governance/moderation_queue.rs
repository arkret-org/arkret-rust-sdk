//! Moderation queue vocabulary and queue-item container
//! (`moderation-queue-item.schema.json`).

use arkret_wire::Did;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::moderation::ModerationReport;

// ---------------------------------------------------------------------------
// Moderation queue item (moderation-queue-item.schema.json)
// ---------------------------------------------------------------------------

/// Lifecycle status shared by `ModerationReport` and `ModerationQueueItem`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueStatus {
    Submitted,
    Triaged,
    Reviewing,
    Actioned,
    Dismissed,
    Appealed,
    Closed,
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
    pub assigned_to: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_policy: Option<ModerationEvidencePolicy>,
    /// `ak:event:<uuidv7>` references to audit events recording queue
    /// actions (decisions, redirects, dismissals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_refs: Vec<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use arkret_wire::RealmId;

    use super::*;

    #[test]
    fn queue_item_round_trips() {
        let item = ModerationQueueItem {
            id: "ak:moderation_queue_item:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            report: ModerationReport::new(
                "ak:report:01970e58-9d21-7000-8000-bbbbbbbbbbbb",
                RealmId::new("ak:realm:01970e58-9d21-7000-8000-cccccccccccc").unwrap(),
                "ak:message:01970e58-9d21-7000-8000-dddddddddddd",
                "spam",
                Did::new("did:webvh:z6mkfixture:reporter.example").unwrap(),
            ),
            status: ModerationQueueStatus::Submitted,
            priority: Some(ModerationQueuePriority::Normal),
            visibility: ModerationQueueVisibility::MetadataOnly,
            assigned_to: vec![],
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
