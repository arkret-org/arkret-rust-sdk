//! Moderation queue container retained by `arkret-core`.
//!
//! The queue vocabulary enums and evidence policy migrated to
//! `arkret-models-collaboration` (re-exported below).
//! [`ModerationQueueItem`] stays because it embeds the (not yet
//! migrated) `ModerationReport` projection.

pub use arkret_models_collaboration::governance::moderation_queue::*;

use super::*;

/// Moderation queue container (`ak.component.moderation_queue.v1` cell
/// body). Mirrors `moderation-queue-item.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
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
