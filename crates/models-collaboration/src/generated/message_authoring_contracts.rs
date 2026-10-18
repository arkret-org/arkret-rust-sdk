// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/message-authoring.schema.json
// sha256=13a9495a75351ab6b54c74771812d544959986d2d014515117c2fdedfc9a27e1
//
// Bindings: tools/closed-model-bindings.json
// sha256=4262c38f5c99fc4a61ddb6e91e7b7f08062a8a80502ab2cc5dca79d57658ca4b

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
