//! Projection read-model wire shapes: the Document Morph projection and the
//! Space / Strand / Morph rows a projection list hands back.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, CommitStreamHead, Cursor, MorphId, ObjectStage, ObjectState, RealmId, RelationId,
    Result, SpaceId, SpaceState, StrandId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceProjectionState {
    Accessible,
    LazyLink,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRevision {
    pub stream_heads: Vec<CommitStreamHead>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentMorphProjectionOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub document: DocumentMorphProjection,
    #[serde(default)]
    pub versions: Vec<BTreeMap<String, Value>>,
    #[serde(default)]
    pub relations: Vec<BTreeMap<String, Value>>,
    #[serde(default)]
    pub comments: Vec<BTreeMap<String, Value>>,
    #[serde(default)]
    pub cursor_presence_entries: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub checkpoint: Option<StateRevision>,
}

/// `view.schema.json#/$defs/document_morph_projection_outcome/properties/document`.
///
/// `body` is intentionally unconstrained JSON and `morph_kind` is an open
/// registry string; the Spec does not define a closed discriminated union here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMorphProjection {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

/// Read-model edge backing a Strand `assigned_to` Relation.
///
/// `relation_id` is what clients tombstone to drop an assignment; `actor_id`
/// mirrors the Relation `to_ref`.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionAssignedToRelation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionAssignedToRelation {
    pub relation_id: RelationId,
    pub actor_id: ActorId,
}

/// Projected Morph read-model row.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionMorphRow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionMorphRow {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub state: ObjectState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business-progression stage from the domain current result; `None` when
    /// the object has never been written by `ak.morph.stage.set`. Orthogonal
    /// to the physical lifecycle in `state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<ObjectStage>,
    /// Reducer-derived timestamp of the most recent `stage` transition; never
    /// present without `stage` (`common-fields.md` 5.3.1).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub stage_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ProjectionMorphRow {
    /// `common-fields.md` 5.3.1: `stage_changed_at` must not appear without
    /// `stage`.
    pub fn validate(&self) -> Result<()> {
        validate_stage_pairing(self.stage.as_ref(), self.stage_changed_at.as_ref())
    }
}

/// Projected Space read-model row.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionSpaceRow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionSpaceRow {
    pub space_id: SpaceId,
    pub realm_id: RealmId,
    /// Space kind such as `board`, `list`, `folder`, or a profile-registered
    /// kind.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<arkret_models_crypto::EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    pub state: SpaceState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Projected Strand read-model row.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionStrandRow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionStrandRow {
    pub strand_id: StrandId,
    pub realm_id: RealmId,
    pub state: ObjectState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business-progression stage from the domain current result; `None` when
    /// the object has never been written by `ak.strand.stage.set`. Orthogonal
    /// to the physical lifecycle in `state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<ObjectStage>,
    /// Reducer-derived timestamp of the most recent `stage` transition; never
    /// present without `stage` (`common-fields.md` 5.3.1).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub stage_changed_at: Option<DateTime<Utc>>,
    /// Derived display title from plaintext-visible Strand `metadata.title`;
    /// `None` when metadata is encrypted or hidden from the service profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Derived display summary from plaintext-visible Strand
    /// `metadata.summary`; `None` when metadata is encrypted or hidden from
    /// the service profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Canonical flat Direct Conversation classification, independent of Board placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<crate::objects::strand::StrandTopic>,
    /// Derived board Space id from `strand_position`; not canonical Strand
    /// object state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_space_id: Option<SpaceId>,
    /// Derived list Space id from `strand_position`; not canonical Strand
    /// object state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_space_id: Option<SpaceId>,
    /// Derived rank within `list_space_id` from `strand_position`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Derived current full ActorIds, Station identity preserved, from visible
    /// active `Relation(relation_kind=assigned_to, from_ref=strand_id)`. Empty
    /// means the Strand is unassigned for this projection caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_actor_ids: Vec<ActorId>,
    /// Read-only active `assigned_to` Relation edges backing
    /// `assigned_actor_ids`; clients use `relation_id` to tombstone one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to_relations: Vec<ProjectionAssignedToRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    /// Derived, never independent storage: `true` exactly when `strand_id`
    /// equals the parent Realm projection default_strand_id pointer written by
    /// `ak.realm.set_default_strand`. A stale pointer never resolves to `true`
    /// because the reducer rejects `set_default_strand` against a
    /// non-existent Strand.
    pub is_default: bool,
}

impl ProjectionStrandRow {
    /// `common-fields.md` 5.3.1: `stage_changed_at` must not appear without
    /// `stage`.
    pub fn validate(&self) -> Result<()> {
        validate_stage_pairing(self.stage.as_ref(), self.stage_changed_at.as_ref())
    }
}

fn validate_stage_pairing(
    stage: Option<&ObjectStage>,
    stage_changed_at: Option<&DateTime<Utc>>,
) -> Result<()> {
    if stage.is_none() && stage_changed_at.is_some() {
        return Err(WireError::Protocol(
            "stage_changed_at must not be present without stage".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod projection_row_tests {
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    const MORPH: &str = "ak:morph:AcRp8AmaNRAqSq4CvFtzDkuXfxw3v4PB0rlS-l_n-GX0";
    const SPACE: &str = "ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD";
    const STRAND: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
    const RELATION: &str = "ak:relation:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn actor_value() -> Value {
        json!({
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            }
        })
    }

    fn assigned_relation_value() -> Value {
        json!({"relation_id": RELATION, "actor_id": actor_value()})
    }

    fn morph_row_value() -> Value {
        json!({
            "morph_id": MORPH,
            "realm_id": REALM,
            "morph_kind": "document",
            "title": "Design note",
            "state": "active",
            "state_changed_at": "2026-08-15T00:00:00.000Z",
            "stage": "in_progress",
            "stage_changed_at": "2026-08-15T00:00:01.000Z",
            "created_by": actor_value(),
            "created_at": "2026-08-14T00:00:00.000Z",
            "updated_at": "2026-08-15T00:00:02.000Z"
        })
    }

    fn space_row_value() -> Value {
        json!({
            "space_id": SPACE,
            "realm_id": REALM,
            "kind": "board",
            "title": "Roadmap",
            "parent_space_id": SPACE,
            "rank": "a0",
            "state": "active",
            "state_changed_at": "2026-08-15T00:00:00.000Z",
            "created_by": actor_value(),
            "created_at": "2026-08-14T00:00:00.000Z",
            "updated_at": "2026-08-15T00:00:02.000Z"
        })
    }

    fn strand_row_value() -> Value {
        json!({
            "strand_id": STRAND,
            "realm_id": REALM,
            "state": "active",
            "state_changed_at": "2026-08-15T00:00:00.000Z",
            "stage": "planned",
            "stage_changed_at": "2026-08-15T00:00:01.000Z",
            "title": "Ship the projection rows",
            "summary": "Restore the read-model surface",
            "board_space_id": SPACE,
            "list_space_id": SPACE,
            "rank": "a0",
            "assigned_actor_ids": [actor_value()],
            "assigned_to_relations": [assigned_relation_value()],
            "created_by": actor_value(),
            "created_at": "2026-08-14T00:00:00.000Z",
            "updated_by": actor_value(),
            "updated_at": "2026-08-15T00:00:02.000Z",
            "is_default": true
        })
    }

    fn assert_round_trips<T>(value: Value)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let decoded: T = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
    }

    fn assert_rejects_unknown_member<T>(value: Value)
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut unknown = value;
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unregistered_member".to_owned(), json!(1));
        assert!(serde_json::from_value::<T>(unknown).is_err());
    }

    fn assert_rejects_each_omitted_required_member<T>(value: Value, required: &[&str])
    where
        T: for<'de> Deserialize<'de>,
    {
        for member in required {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(*member);
            assert!(
                serde_json::from_value::<T>(missing).is_err(),
                "{member} must be required"
            );
        }
    }

    #[test]
    fn assigned_to_relation_round_trips_and_is_closed() {
        assert_round_trips::<ProjectionAssignedToRelation>(assigned_relation_value());
        assert_rejects_unknown_member::<ProjectionAssignedToRelation>(assigned_relation_value());
        assert_rejects_each_omitted_required_member::<ProjectionAssignedToRelation>(
            assigned_relation_value(),
            &["relation_id", "actor_id"],
        );
    }

    #[test]
    fn morph_row_round_trips_and_is_closed() {
        assert_round_trips::<ProjectionMorphRow>(morph_row_value());
        assert_rejects_unknown_member::<ProjectionMorphRow>(morph_row_value());
        assert_rejects_each_omitted_required_member::<ProjectionMorphRow>(
            morph_row_value(),
            &["morph_id", "realm_id", "morph_kind", "state"],
        );
    }

    #[test]
    fn space_row_round_trips_and_is_closed() {
        assert_round_trips::<ProjectionSpaceRow>(space_row_value());
        assert_rejects_unknown_member::<ProjectionSpaceRow>(space_row_value());
        assert_rejects_each_omitted_required_member::<ProjectionSpaceRow>(
            space_row_value(),
            &["space_id", "realm_id", "kind", "title", "state"],
        );
    }

    #[test]
    fn strand_row_round_trips_and_is_closed() {
        assert_round_trips::<ProjectionStrandRow>(strand_row_value());
        assert_rejects_unknown_member::<ProjectionStrandRow>(strand_row_value());
        assert_rejects_each_omitted_required_member::<ProjectionStrandRow>(
            strand_row_value(),
            &["strand_id", "realm_id", "state", "is_default"],
        );
    }

    #[test]
    fn stage_changed_at_never_stands_without_stage() {
        let mut value = morph_row_value();
        value.as_object_mut().unwrap().remove("stage");
        let row: ProjectionMorphRow = serde_json::from_value(value).unwrap();
        assert!(row.validate().is_err());

        let mut value = strand_row_value();
        value.as_object_mut().unwrap().remove("stage");
        let row: ProjectionStrandRow = serde_json::from_value(value).unwrap();
        assert!(row.validate().is_err());

        let paired: ProjectionStrandRow = serde_json::from_value(strand_row_value()).unwrap();
        paired.validate().unwrap();
    }

    #[test]
    fn strand_row_projects_the_derived_default_flag_and_assignment_edges() {
        let row: ProjectionStrandRow = serde_json::from_value(strand_row_value()).unwrap();
        assert!(row.is_default);
        assert_eq!(row.assigned_actor_ids.len(), 1);
        assert_eq!(
            row.assigned_to_relations[0].actor_id,
            row.assigned_actor_ids[0]
        );
        assert_eq!(row.assigned_to_relations[0].relation_id.as_str(), RELATION);
    }
}

/// Bounded projection page of Document Morph rows.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionMorphList.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionMorphList {
    pub realm_id: RealmId,
    pub morphs: Vec<ProjectionMorphRow>,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl ProjectionMorphList {
    pub fn validate(&self) -> Result<()> {
        validate_projection_page(
            self.morphs.len(),
            self.total,
            self.has_more,
            self.next_cursor.is_some(),
        )?;
        for row in &self.morphs {
            row.validate()?;
            if row.realm_id != self.realm_id {
                return Err(WireError::Protocol(
                    "projection morph row belongs to another Realm".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Bounded projection page of Space rows.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionSpaceList.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionSpaceList {
    pub realm_id: RealmId,
    pub spaces: Vec<ProjectionSpaceRow>,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl ProjectionSpaceList {
    pub fn validate(&self) -> Result<()> {
        validate_projection_page(
            self.spaces.len(),
            self.total,
            self.has_more,
            self.next_cursor.is_some(),
        )?;
        for row in &self.spaces {
            if row.realm_id != self.realm_id {
                return Err(WireError::Protocol(
                    "projection space row belongs to another Realm".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Bounded projection page of Strand rows.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ProjectionStrandList.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionStrandList {
    pub realm_id: RealmId,
    pub strands: Vec<ProjectionStrandRow>,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl ProjectionStrandList {
    pub fn validate(&self) -> Result<()> {
        validate_projection_page(
            self.strands.len(),
            self.total,
            self.has_more,
            self.next_cursor.is_some(),
        )?;
        for row in &self.strands {
            row.validate()?;
            if row.realm_id != self.realm_id {
                return Err(WireError::Protocol(
                    "projection strand row belongs to another Realm".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// A projection page reports the whole matching population in `total`, so a
/// page that already carries every row cannot also claim more, and a page that
/// claims more has to name where reading resumes.
fn validate_projection_page(
    row_count: usize,
    total: u64,
    has_more: bool,
    has_cursor: bool,
) -> Result<()> {
    if row_count as u64 > total {
        return Err(WireError::Protocol(
            "projection page carries more rows than it reports in total".to_owned(),
        ));
    }
    if has_more != has_cursor {
        return Err(WireError::Protocol(
            "projection page must carry next_cursor exactly when has_more is set".to_owned(),
        ));
    }
    if !has_more && (row_count as u64) != total {
        return Err(WireError::Protocol(
            "a terminal projection page must carry every counted row".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod projection_list_tests {
    use serde_json::json;

    use super::*;

    fn empty_list_value(rows_field: &str) -> Value {
        json!({
            "realm_id": "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
            rows_field: [],
            "total": 0,
            "has_more": false
        })
    }

    #[test]
    fn projection_lists_round_trip_and_reject_unknown_members() {
        let morphs = empty_list_value("morphs");
        let parsed: ProjectionMorphList =
            serde_json::from_value(morphs.clone()).expect("closed morph list");
        parsed.validate().expect("terminal empty page");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), morphs);

        let mut unknown = morphs.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("cursor".to_owned(), json!("ak:cursor:AA"));
        assert!(serde_json::from_value::<ProjectionMorphList>(unknown).is_err());

        let spaces: ProjectionSpaceList =
            serde_json::from_value(empty_list_value("spaces")).expect("closed space list");
        spaces.validate().expect("terminal empty page");
        let strands: ProjectionStrandList =
            serde_json::from_value(empty_list_value("strands")).expect("closed strand list");
        strands.validate().expect("terminal empty page");
    }

    #[test]
    fn projection_lists_require_every_schema_member() {
        for required in ["realm_id", "morphs", "total", "has_more"] {
            let mut missing = empty_list_value("morphs");
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<ProjectionMorphList>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }

    #[test]
    fn projection_page_continuation_is_consistent() {
        let mut claims_more = empty_list_value("morphs");
        claims_more
            .as_object_mut()
            .unwrap()
            .insert("has_more".to_owned(), json!(true));
        let parsed: ProjectionMorphList =
            serde_json::from_value(claims_more).expect("closed morph list");
        assert!(
            parsed.validate().is_err(),
            "has_more without next_cursor names no resume point"
        );

        let mut undercounts = empty_list_value("morphs");
        undercounts
            .as_object_mut()
            .unwrap()
            .insert("total".to_owned(), json!(3));
        let parsed: ProjectionMorphList =
            serde_json::from_value(undercounts).expect("closed morph list");
        assert!(
            parsed.validate().is_err(),
            "a terminal page cannot drop counted rows"
        );
    }
}
