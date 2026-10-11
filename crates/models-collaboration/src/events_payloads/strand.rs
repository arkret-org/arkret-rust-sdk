//! Strand lifecycle and ordering event payloads.

use crate::internal_prelude::*;
use crate::strand_watch_operations::StrandWatchCurrentValue;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreatePayload {
    pub object: Strand,
}

// `strand_move_payload` uses `models::operation_payloads::StrandMovePayload`.

// `strand_reorder_payload` now has a strong type:
// `models::operation_payloads::StrandReorderPayload` (single List-Space
// re-rank; `additionalProperties:false`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandStageSetPayload {
    pub strand_id: StrandId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
}

/// Strong payload for `ak.realm.set_default_strand`.
///
/// Omission and explicit null both assert that the current cell is null; a
/// concrete strand ID asserts that exact current value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSetDefaultStrandPayload {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_default_strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RealmSetDefaultStrandPayload {
    pub fn new(realm_id: RealmId, strand_id: StrandId) -> Self {
        Self {
            realm_id,
            strand_id,
            expected_default_strand_id: None,
            reason: None,
        }
    }

    pub fn expecting(mut self, strand_id: StrandId) -> Self {
        self.expected_default_strand_id = Some(strand_id);
        self
    }
}

// `strand_watch_set_payload` now has a strong type:
// `models::operation_payloads::StrandWatchSetPayload` (carries the
// `StrandWatchLevel` enum / nullable `level` clear path and the
// `level_public`/`expected_value` CAS fields; `additionalProperties:false`).

/// Shared payload for `ak.strand.update` and `ak.strand.tracks.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandPatchPayload {
    pub target_ref: StrandId,
    pub patch: Patch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl StrandPatchPayload {
    /// Classify, reorder, or unclassify a Chat using the exact observed current digest.
    pub fn for_topic(
        strand_id: StrandId,
        topic: Option<StrandTopic>,
        expected_state_digest: Hash,
    ) -> Result<Self> {
        let op = match topic {
            Some(topic) => PatchOp::set(
                serde_json::to_value(topic).map_err(|e| WireError::Protocol(e.to_string()))?,
            ),
            None => PatchOp::unset(),
        };
        let mut patch = Patch::new();
        patch.insert_op("topic", op)?;
        let payload = Self {
            target_ref: strand_id,
            patch,
            expected_state_digest: Some(expected_state_digest),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        self.patch.validate()?;
        for (path, op) in self
            .patch
            .iter()
            .filter(|(path, _)| path.as_str() == "topic" || path.starts_with("topic."))
        {
            if path != "topic" || self.expected_state_digest.is_none() {
                return Err(WireError::Protocol(
                    "Topic update requires whole-field CAS".into(),
                ));
            }
            match op {
                PatchOp::Explicit {
                    op: PatchOpKind::Set,
                    value: Some(value),
                } => {
                    serde_json::from_value::<StrandTopic>(value.clone())
                        .map_err(|e| WireError::Protocol(e.to_string()))?;
                }
                PatchOp::Explicit {
                    op: PatchOpKind::Unset,
                    value: None,
                } => {}
                _ => {
                    return Err(WireError::Protocol(
                        "Topic update requires explicit set or unset".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn for_strand(strand_id: StrandId, patch: Patch) -> Result<Self> {
        let payload = Self {
            target_ref: strand_id,
            patch,
            expected_state_digest: None,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("strand patch payload serialize: {err}")))
    }
}
fn deserialize_position_preimage<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<StrandPositionCurrent>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    StrandPositionCurrent::deserialize(deserializer).map(Some)
}

/// Strong type for `ak.strand.move` payloads
/// (`event-payload.schema.json#/$defs/strand_move_payload`).
///
/// Moves a Strand between List Spaces. The destination is single-sourced by
/// `target_space_id` — writers MUST NOT put `list_space_id` directly on the
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

impl StrandMovePayload {
    pub fn new(
        board_space_id: SpaceId,
        strand_id: StrandId,
        target_space_id: SpaceId,
        rank: impl Into<String>,
    ) -> Self {
        Self {
            board_space_id,
            strand_id,
            target_space_id,
            rank: rank.into(),
            from_space_id: None,
            expected_position: None,
        }
    }

    pub fn with_from_space_id(mut self, from_space_id: SpaceId) -> Self {
        self.from_space_id = Some(from_space_id);
        self
    }

    pub fn with_expected_position(mut self, expected: StrandPositionCurrent) -> Self {
        self.expected_position = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("strand move payload serialize: {err}")))
    }
}

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

impl StrandReorderPayload {
    pub fn new(
        board_space_id: SpaceId,
        strand_id: StrandId,
        space_id: SpaceId,
        rank: impl Into<String>,
    ) -> Self {
        Self {
            board_space_id,
            strand_id,
            space_id,
            rank: rank.into(),
            expected_position: None,
        }
    }

    pub fn with_expected_position(mut self, expected: StrandPositionCurrent) -> Self {
        self.expected_position = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("strand reorder payload serialize: {err}")))
    }
}

/// Watch level for `ak.strand.watch.set`
/// (`event-payload.schema.json#/$defs/strand_watch_set_payload` `level`).
///
/// `null` on the wire (a cleared cell) is modeled as `None` on the
/// [`StrandWatchSetPayload::level`] field rather than a variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrandWatchLevel {
    MentionsOnly,
    Participating,
    All,
    Muted,
}

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
    pub level_public: Option<bool>,
}

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
    /// `None` serializes as JSON `null`, clearing the cell.
    #[serde(deserialize_with = "deserialize_required_watch_level")]
    pub level: Option<StrandWatchLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_public: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_watch_preimage"
    )]
    pub expected_value: Option<StrandWatchCurrentValue>,
}

fn deserialize_required_watch_level<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<StrandWatchLevel>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<StrandWatchLevel>::deserialize(deserializer)
}

fn deserialize_watch_preimage<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<StrandWatchCurrentValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    StrandWatchCurrentValue::deserialize(deserializer).map(Some)
}

impl StrandWatchSetPayload {
    /// Set a concrete watch level. `level_public` opts the level into
    /// non-self projection (ignored for `muted` by the reducer).
    pub fn set(
        strand_id: StrandId,
        watcher_actor_id: ActorId,
        level: StrandWatchLevel,
        level_public: Option<bool>,
    ) -> Self {
        Self {
            strand_id,
            watcher_actor_id,
            level: Some(level),
            level_public,
            expected_value: None,
        }
    }

    /// Clear the watch cell (`level: null`). Per the schema `allOf`,
    /// `level_public` is forced off on this path.
    pub fn clear(strand_id: StrandId, watcher_actor_id: ActorId) -> Self {
        Self {
            strand_id,
            watcher_actor_id,
            level: None,
            level_public: None,
            expected_value: None,
        }
    }

    /// Compare the complete written value, including an explicitly cleared cell.
    /// Omission remains reserved for a Station-confirmed never-written cell.
    pub fn with_expected_value(mut self, expected: StrandWatchCurrentValue) -> Self {
        self.expected_value = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            WireError::Protocol(format!("strand watch set payload serialize: {err}"))
        })
    }
}

#[cfg(test)]
mod position_preimage_tests {
    use serde_json::json;

    use super::{StrandMovePayload, StrandReorderPayload};

    #[test]
    fn move_and_reorder_require_complete_current_value_when_cas_is_present() {
        let board = "ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
        let strand = "ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
        let mut move_wire =
            json!({"board_space_id":board,"strand_id":strand,"target_space_id":board,"rank":"b0"});
        let mut reorder_wire =
            json!({"board_space_id":board,"strand_id":strand,"space_id":board,"rank":"b0"});
        assert!(
            serde_json::from_value::<StrandMovePayload>(move_wire.clone())
                .unwrap()
                .expected_position
                .is_none()
        );
        assert!(
            serde_json::from_value::<StrandReorderPayload>(reorder_wire.clone())
                .unwrap()
                .expected_position
                .is_none()
        );
        for preimage in [
            json!({"list_space_id":board,"rank":"a0"}),
            json!({"rank":"a0"}),
            json!(null),
            json!({"space_id":board,"rank":"a0"}),
            json!({"list_space_id":board,"rank":"a0","relation_id":"ak:relation:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        ] {
            let valid =
                preimage.get("list_space_id").is_some() && preimage.as_object().unwrap().len() == 2;
            move_wire["expected_position"] = preimage.clone();
            reorder_wire["expected_position"] = preimage;
            assert_eq!(
                serde_json::from_value::<StrandMovePayload>(move_wire.clone()).is_ok(),
                valid
            );
            assert_eq!(
                serde_json::from_value::<StrandReorderPayload>(reorder_wire.clone()).is_ok(),
                valid
            );
        }
    }
}
