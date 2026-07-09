use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

/// Optional CAS guard carried on `ak.strand.move`
/// (`event-payload.schema.json#/$defs/strand_move_payload` `expected_position`).
///
/// Compiles to a `head_eq` precondition against the current position cell.
/// All three fields are optional in the spec sub-schema; `additionalProperties
/// :false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandMoveExpectedPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandMovePayload {
    pub board_space_id: SpaceId,
    pub strand_id: StrandId,
    pub target_space_id: SpaceId,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position: Option<StrandMoveExpectedPosition>,
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

    pub fn with_expected_position(mut self, expected: StrandMoveExpectedPosition) -> Self {
        self.expected_position = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand move payload serialize: {err}")))
    }
}

/// Optional CAS guard carried on `ak.strand.reorder`
/// (`event-payload.schema.json#/$defs/strand_reorder_payload` `expected_position`).
///
/// The reorder happens within a single List Space, so unlike
/// [`StrandMoveExpectedPosition`] there is no `space_id` field here.
/// `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandReorderExpectedPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
}

/// Strong type for `ak.strand.reorder` payloads
/// (`event-payload.schema.json#/$defs/strand_reorder_payload`).
///
/// Re-ranks a Strand within a single List Space (`space_id`); the Space is not
/// changed. Required: `board_space_id`, `strand_id`, `space_id`, `rank`.
/// `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandReorderPayload {
    pub board_space_id: SpaceId,
    pub strand_id: StrandId,
    pub space_id: SpaceId,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position: Option<StrandReorderExpectedPosition>,
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

    pub fn with_expected_position(mut self, expected: StrandReorderExpectedPosition) -> Self {
        self.expected_position = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand reorder payload serialize: {err}")))
    }
}

/// Strong type for `ak.strand.tracks.update` payloads
/// (`event-payload.schema.json#/$defs/strand_tracks_update_payload`).
///
/// Track changes target a Strand through `strand_id`, not the generic
/// object-patch `target_ref`. Writers MUST carry either an atomic `patch` or a
/// full replacement `tracks` map; constructors enforce the non-empty branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandTracksUpdatePayload {
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracks: Option<BTreeMap<String, StrandTrackConfig>>,
}

impl StrandTracksUpdatePayload {
    pub fn with_patch(strand_id: StrandId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self {
            strand_id,
            patch: Some(patch),
            tracks: None,
        })
    }

    pub fn with_tracks(
        strand_id: StrandId,
        tracks: BTreeMap<String, StrandTrackConfig>,
    ) -> Result<Self> {
        if tracks.is_empty() {
            return Err(Error::Protocol(
                "strand tracks update requires non-empty tracks".to_owned(),
            ));
        }
        for track_name in tracks.keys() {
            validate_strand_track_name(track_name)?;
        }
        Ok(Self {
            strand_id,
            patch: None,
            tracks: Some(tracks),
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.patch.is_none() && self.tracks.is_none() {
            return Err(Error::Protocol(
                "strand tracks update requires patch or tracks".to_owned(),
            ));
        }
        if let Some(patch) = &self.patch {
            patch.validate()?;
        }
        if let Some(tracks) = &self.tracks {
            if tracks.is_empty() {
                return Err(Error::Protocol(
                    "strand tracks update requires non-empty tracks".to_owned(),
                ));
            }
            for track_name in tracks.keys() {
                validate_strand_track_name(track_name)?;
            }
        }
        serde_json::to_value(self).map_err(Error::from)
    }
}

/// Watch level for `ak.strand.watch.set`
/// (`event-payload.schema.json#/$defs/strand_watch_set_payload` `level`).
///
/// `null` on the wire (a cleared cell) is modeled as `None` on the
/// [`StrandWatchSetPayload::level`] field rather than a variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
/// Carries the prior cell value `{ level, level_public? }` for a `head_eq`
/// compare. `additionalProperties:false`; `level` is required when present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandWatchSetPayload {
    pub strand_id: StrandId,
    pub watcher_actor_id: Did,
    /// `None` serializes as JSON `null`, clearing the cell.
    pub level: Option<StrandWatchLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_public: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<Option<StrandWatchExpectedValue>>,
}

impl StrandWatchSetPayload {
    /// Set a concrete watch level. `level_public` opts the level into
    /// non-self projection (ignored for `muted` by the reducer).
    pub fn set(
        strand_id: StrandId,
        watcher_actor_id: Did,
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
    pub fn clear(strand_id: StrandId, watcher_actor_id: Did) -> Self {
        Self {
            strand_id,
            watcher_actor_id,
            level: None,
            level_public: None,
            expected_value: None,
        }
    }

    pub fn with_expected_value(mut self, expected: Option<StrandWatchExpectedValue>) -> Self {
        self.expected_value = Some(expected);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand watch set payload serialize: {err}")))
    }
}
