//! Strand lifecycle and ordering event payloads.

#[cfg(test)]
use arkret_wire::DidCoreId;

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
            .map_err(|err| WireError::Protocol(format!("strand patch payload serialize: {err}")))
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
            .map_err(|err| WireError::Protocol(format!("strand move payload serialize: {err}")))
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
    pub watcher_actor_id: ActorId,
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

    /// Canonical `cas_register` cell this write targets: family
    /// `ak.component.strand.watch.v1` with the tuple subject
    /// `(strand_id, watcher_actor_id)` from the event-kind registry
    /// `cell_writes` contract.
    ///
    /// It lives on the payload because two sides need the same id from the
    /// same place: whoever authors the `ak.audit.accessed` partner of a
    /// `.others` write fills `target_cell_id` with it, and whoever admits the
    /// pair matches against it. `watch_cell_ref_matches_the_registered_contract`
    /// pins the derivation to [`arkret_schema::project_registered_cell_writes`],
    /// so this cannot quietly fork from the registry.
    pub fn cell_ref(&self) -> Result<CellRef> {
        let watcher_actor_key = self.watcher_actor_id.canonical_key()?;
        let subject = composite_subject(&[self.strand_id.as_str(), &watcher_actor_key])?;
        Ok(CellRef::new(format!(
            "ak:cell:{}:{subject}",
            CellFamilyId::STRAND_WATCH_V1
        ))?)
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            WireError::Protocol(format!("strand watch set payload serialize: {err}"))
        })
    }
}

#[cfg(test)]
mod presence_tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j").unwrap()
    }

    fn strand_id(suffix: &str) -> StrandId {
        StrandId::from_event_id(
            &EventId::from_event_digest(
                &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
            )
            .unwrap(),
        )
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

    /// `StrandWatchSetPayload::cell_ref` exists so the audit partner of a
    /// `.others` write and the admission path that matches it agree on
    /// `target_cell_id`. It is only worth having if it stays equal to what the
    /// registered cell contract derives, so assert that directly rather than
    /// restating the tuple-subject recipe.
    #[test]
    fn watch_cell_ref_matches_the_registered_contract() {
        let payload = StrandWatchSetPayload::set(
            strand_id("000000000001"),
            ActorId::account(AccountId::new(
                project_did_to_core_id(&Did::new("did:webvh:z6mkfixturebob:bob.example").unwrap())
                    .unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
            )),
            StrandWatchLevel::Participating,
            None,
        );
        let event = test_support::raw_event(
            "ak.strand.watch.set",
            ScopeRef::Realm {
                realm_id: realm_id(),
            },
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
                .unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            1,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            serde_json::to_value(&payload).unwrap(),
        )
        .unwrap();

        let writes = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].cell_id, payload.cell_ref().unwrap());
    }

    #[test]
    fn watch_cas_normalizes_null_to_the_omitted_empty_value() {
        let payload: StrandWatchSetPayload = serde_json::from_value(json!({
            "strand_id": strand_id("000000000001"),
            "watcher_actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }
            },
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
