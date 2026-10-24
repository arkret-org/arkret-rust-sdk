// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=6e557b3350ecfe34a8c4836bb00abf61dce039fa6a5fbbc58b07ec74dbaaba7f
//
// Bindings: tools/closed-model-bindings.json
// sha256=ea613fae32e25a94687889845566828fe050317b185350eceb320391ae60c2f4

/// Counterpart: `event-payload.schema.json#/$defs/strand_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreatePayload {
    pub object: Strand,
}

/// Counterpart: `event-payload.schema.json#/$defs/strand_stage_set_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandStageSetPayload {
    pub strand_id: StrandId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_stage: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/strand_move_payload`.
/// Strong type for `ak.strand.move` payloads
/// (`event-payload.schema.json#/$defs/strand_move_payload`).
///
/// Moves a Strand between List Spaces. The destination is single-sourced by
/// `target_space_id` â€” writers MUST NOT put `list_space_id` directly on the
/// payload (`additionalProperties:false` enforces this; the reducer compiles
/// `target_space_id` into the position cell). `from_space_id` is an optional
/// hint the reducer can infer. Required: `board_space_id`, `strand_id`,
/// `target_space_id`, `rank`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandMovePayload {
    pub board_space_id: SpaceId,
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub from_space_id: Option<SpaceId>,
    pub target_space_id: SpaceId,
    pub rank: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_position_preimage"
    )]
    pub expected_position: Option<StrandPositionCurrent>,
}

/// Counterpart: `event-payload.schema.json#/$defs/strand_reorder_payload`.
/// Strong type for `ak.strand.reorder` payloads
/// (`event-payload.schema.json#/$defs/strand_reorder_payload`).
///
/// Re-ranks a Strand within a single List Space (`space_id`); the Space is not
/// changed. Required: `board_space_id`, `strand_id`, `space_id`, `rank`.
/// `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandReorderPayload {
    pub board_space_id: SpaceId,
    pub strand_id: StrandId,
    pub space_id: SpaceId,
    pub rank: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_position_preimage"
    )]
    pub expected_position: Option<StrandPositionCurrent>,
}

/// Counterpart: `event-payload.schema.json#/$defs/strand_watch_set_payload`.
/// Strong type for `ak.strand.watch.set` payloads
/// (`event-payload.schema.json#/$defs/strand_watch_set_payload`).
///
/// Sets or clears the `(strand_id, watcher_actor_id)` watch cell. Required:
/// `strand_id`, `watcher_actor_id`, `level` (the last may be `null` to clear).
/// Per the schema `allOf`, `level_public` MUST be omitted when `level` is
/// `null`; [`StrandWatchSetPayload::clear`] enforces this and the constructors
/// keep `level_public` separate from the clearing path.
/// `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchSetPayload {
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
    #[serde(deserialize_with = "deserialize_required_watch_level")]
    pub level: Option<StrandWatchLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub level_public: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_watch_preimage"
    )]
    pub expected_value: Option<StrandWatchValue>,
}

/// Counterpart:
/// `event-payload.schema.json#/$defs/strand_watch_set_payload/properties/expected_value/oneOf/1`.
/// CAS guard for `ak.strand.watch.set`
/// (`event-payload.schema.json#/$defs/strand_watch_set_payload` `expected_value`).
///
/// Carries the prior value `{ level, level_public? }` for a
/// whole-value compare. `additionalProperties:false`; `level` is
/// required when present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchExpectedValue {
    pub level: StrandWatchLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub level_public: Option<bool>,
}
