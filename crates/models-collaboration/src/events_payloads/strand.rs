//! Strand lifecycle and ordering event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/strand_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreatePayload {
    pub object: Strand,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `strand_move_payload` now has a strong type:
// `models::operation_payloads::StrandMovePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; flat
// board/target Space ids + rank with an optional `expected_position`
// CAS guard, `additionalProperties:false`).

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

/// Payload for `ak.strand.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrandPatchPayload {
    pub target_ref: StrandId,
    pub patch: Patch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl StrandPatchPayload {
    pub fn for_strand(strand_id: StrandId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self {
            target_ref: strand_id,
            patch,
            expected_state_digest: None,
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand patch payload serialize: {err}")))
    }
}
/// Optional CAS guard carried on `ak.strand.move`
/// (`event-payload.schema.json#/$defs/strand_move_payload` `expected_position`).
///
/// Compiles to a `head_eq` precondition against the current position cell.
/// All three fields are optional in the spec sub-schema; `additionalProperties
/// :false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[serde(deny_unknown_fields)]
pub struct StrandMovePayload {
    pub board_space_id: SpaceId,
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_space_id: Option<SpaceId>,
    pub target_space_id: SpaceId,
    pub rank: String,
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
/// Carries the prior cell value `{ level, level_public? }` for a `head_eq`
/// compare. `additionalProperties:false`; `level` is required when present.
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
    pub watcher_actor_id: Did,
    /// `None` serializes as JSON `null`, clearing the cell.
    pub level: Option<StrandWatchLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_public: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<StrandWatchExpectedValue>,
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
        self.expected_value = expected;
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand watch set payload serialize: {err}")))
    }
}

#[cfg(test)]
mod presence_tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-8000-8000-000000000000").unwrap()
    }

    fn strand_id(suffix: &str) -> StrandId {
        StrandId::new(format!("ak:strand:0196419b-0000-8000-8000-{suffix}")).unwrap()
    }

    #[test]
    fn default_strand_cas_normalizes_missing_and_null() {
        let base = json!({
            "realm_id": realm_id(),
            "strand_id": strand_id("000000000001")
        });
        let missing: RealmSetDefaultStrandPayload = serde_json::from_value(base.clone()).unwrap();
        let mut explicit_null = base.clone();
        explicit_null["expected_default_strand_id"] = Value::Null;
        let null: RealmSetDefaultStrandPayload = serde_json::from_value(explicit_null).unwrap();
        let mut explicit_value = base;
        explicit_value["expected_default_strand_id"] = json!(strand_id("000000000002"));
        let value: RealmSetDefaultStrandPayload = serde_json::from_value(explicit_value).unwrap();

        assert_eq!(missing.expected_default_strand_id, None);
        assert_eq!(null.expected_default_strand_id, None);
        assert!(value.expected_default_strand_id.is_some());
        assert!(
            serde_json::to_value(missing)
                .unwrap()
                .get("expected_default_strand_id")
                .is_none()
        );
        assert!(
            serde_json::to_value(null)
                .unwrap()
                .get("expected_default_strand_id")
                .is_none()
        );
    }

    #[test]
    fn watch_cas_normalizes_null_to_the_omitted_empty_value() {
        let payload: StrandWatchSetPayload = serde_json::from_value(json!({
            "strand_id": strand_id("000000000001"),
            "watcher_actor_id": "did:web:alice.example",
            "level": null,
            "expected_value": null
        }))
        .unwrap();
        assert_eq!(payload.expected_value, None);
        assert!(
            serde_json::to_value(payload)
                .unwrap()
                .get("expected_value")
                .is_none()
        );
    }
}
