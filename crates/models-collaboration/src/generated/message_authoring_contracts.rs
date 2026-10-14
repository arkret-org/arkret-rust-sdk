// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/message-authoring.schema.json
// sha256=13a9495a75351ab6b54c74771812d544959986d2d014515117c2fdedfc9a27e1
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

/// Counterpart: `message-authoring.schema.json#/$defs/message_prepare_outcome`.
/// Counterpart for
/// `message-authoring.schema.json#/$defs/message_prepare_outcome`.
///
/// The prepare phase hands back one service-prepared unsigned Event plus the
/// exact request digest it answers; the producer signs that draft and submits
/// it through [`MessageSubmitRequestBody`]. The outcome carries no
/// reservation, predecessor or ordering member: a producer Event has no causal
/// predecessor, and finality is the authority-signed RealmCommit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessagePrepareOutcome {
    pub request_digest: Hash,
    pub draft: PreparedEventDraft,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}
