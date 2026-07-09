//! Moderation queue model.

use super::*;

// ---------------------------------------------------------------------------
// Moderation queue item (moderation-queue-item.schema.json)
// ---------------------------------------------------------------------------

/// Lifecycle status shared by `ModerationReport` and `ModerationQueueItem`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueuePriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Visibility class describing what evidence form the queue carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueVisibility {
    MetadataOnly,
    EncryptedEvidence,
    PlaintextEvidence,
    FrankingProofOnly,
}

/// Evidence-handling policy embedded in a queue item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationEvidencePolicy {
    pub plaintext_allowed: bool,
    pub requires_franking_proof_verification: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
}

/// Moderation queue container (`ak.component.moderation_queue.v1` cell
/// body). Mirrors `moderation-queue-item.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationQueueItem {
    /// `ak:moderation_queue_item:<uuidv7>`.
    pub id: String,
    /// The full report this queue entry represents. Stored as
    /// [`serde_json::Value`] so callers can choose to deserialise into
    /// the existing `ModerationReport` struct without forcing a
    /// circular dependency between this module and `profiles.rs`.
    pub report: Value,
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
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn queue_item_round_trips() {
        let item = ModerationQueueItem {
            id: "ak:moderation_queue_item:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            report: json!({"realm_id": "ak:realm:...", "reason": "spam"}),
            status: ModerationQueueStatus::Submitted,
            priority: Some(ModerationQueuePriority::Normal),
            visibility: ModerationQueueVisibility::MetadataOnly,
            assigned_to: vec![],
            evidence_policy: Some(ModerationEvidencePolicy {
                plaintext_allowed: false,
                requires_franking_proof_verification: true,
                retention_expires_at: None,
                legal_hold: None,
            }),
            audit_refs: vec![],
            created_at: Utc::now(),
            updated_at: None,
        };
        let json_text = serde_json::to_string(&item).unwrap();
        assert!(json_text.contains(r#""status":"submitted""#));
        assert!(json_text.contains(r#""visibility":"metadata_only""#));
        let parsed: ModerationQueueItem = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, item);
    }
}
