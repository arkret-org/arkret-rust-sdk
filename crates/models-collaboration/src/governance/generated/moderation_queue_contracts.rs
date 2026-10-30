// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/moderation-queue-item.schema.json
// sha256=5af8478544c5a82f745571105ee5e8b99b1e99ea96f2d052e6333929e7797df0
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

/// Counterpart: `moderation-queue-item.schema.json`.
/// One report item of the moderation queue View
/// (`moderation-queue-item.schema.json`).
///
/// The item is a read-side View over the accepted `moderation_report` typed
/// current result and the `moderation_state` records that point at it, not a
/// second stored state (content-moderation.md Â§3.3): `id` is the report Event
/// id retyped to `moderation_queue_item`, `report` is the complete accepted
/// report payload and `created_at` the accepting Commit time.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationQueueItem {
    pub id: ModerationQueueItemId,
    pub report: ModerationReportPayload,
    pub status: ModerationQueueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub priority: Option<ModerationQueuePriority>,
    pub visibility: ModerationQueueVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub assigned_to_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub evidence_policy: Option<ModerationEvidencePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audit_refs: Option<Vec<EventId>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}
