//! Projection objects and collection-position wire models.

use std::collections::BTreeMap;

use arkret_wire::{
    Cursor, Did, EventId, Facet, Hash, Hlc, MorphId, NonEmptyString, RealmId, RelationId, ViewId,
    ViewRenderer,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ObjectRef;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceProjectionState {
    Accessible,
    LazyLink,
    Locked,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewProjectionRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFrontier {
    pub state_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_frontiers: Vec<StateFrontierActor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFrontierActor {
    pub actor_id: Did,
    pub actor_seq: u64,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionObjectKind {
    Realm,
    Space,
    Circle,
    Strand,
    Message,
    Morph,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionObject {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub morph_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(rename = "kind")]
    pub object_kind: ProjectionObjectKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionRowRender {
    Card,
    Row,
    Tile,
    Compact,
    Badge,
    Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRow {
    pub object: ProjectionObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render: Option<ProjectionRowRender>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub display: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<CollectionPosition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub state: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldValuePositionModel {
    #[serde(rename = "field_value")]
    FieldValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValueCollectionPosition {
    pub model: FieldValuePositionModel,
    pub container_id: NonEmptyString,
    pub rank: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationPositionModel {
    #[serde(rename = "relation")]
    Relation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationCollectionPosition {
    pub model: RelationPositionModel,
    pub scope_container_id: ObjectRef,
    pub container_id: ObjectRef,
    pub relation_kind: NonEmptyString,
    pub relation_id: RelationId,
    pub rank: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeWindowPositionModel {
    #[serde(rename = "time_window")]
    TimeWindow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCollectionPosition {
    pub model: TimeWindowPositionModel,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub start: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub end: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<NonEmptyString>,
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrosstabPositionModel {
    #[serde(rename = "crosstab_cell")]
    CrosstabCell,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrosstabCollectionPosition {
    pub model: CrosstabPositionModel,
    pub row_key: NonEmptyString,
    pub column_key: NonEmptyString,
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SortKeyCollectionPosition {
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CollectionPosition {
    FieldValue(FieldValueCollectionPosition),
    Relation(RelationCollectionPosition),
    TimeWindow(TimeWindowCollectionPosition),
    Crosstab(CrosstabCollectionPosition),
    SortKey(SortKeyCollectionPosition),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CollectionGroupValue {
    String(String),
    Number(serde_json::Number),
    Boolean(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldValueGroupModel {
    #[serde(rename = "field_value")]
    FieldValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionFieldValueGroupSource {
    pub model: FieldValueGroupModel,
    pub field: String,
    pub value: CollectionGroupValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationContainerGroupModel {
    #[serde(rename = "relation_container")]
    RelationContainer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionRelationGroupSource {
    pub model: RelationContainerGroupModel,
    pub scope_container_id: ObjectRef,
    pub container_id: ObjectRef,
    pub relation_kind: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivedRelationGroupModel {
    #[serde(rename = "derived_relation")]
    DerivedRelation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionDerivedRelationGroupSource {
    pub model: DerivedRelationGroupModel,
    pub scope_container_id: ObjectRef,
    pub container_id: ObjectRef,
    pub relation_kind: NonEmptyString,
    pub source_cell_id: NonEmptyString,
    pub rank: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeBucketGroupModel {
    #[serde(rename = "time_bucket")]
    TimeBucket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionTimeBucketGroupSource {
    pub model: TimeBucketGroupModel,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub start: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub end: DateTime<Utc>,
    pub timezone: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrosstabCellGroupModel {
    #[serde(rename = "crosstab_cell")]
    CrosstabCell,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCrosstabGroupSource {
    pub model: CrosstabCellGroupModel,
    pub row_key: NonEmptyString,
    pub column_key: NonEmptyString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CollectionGroupSource {
    FieldValue(CollectionFieldValueGroupSource),
    DerivedRelation(CollectionDerivedRelationGroupSource),
    Relation(CollectionRelationGroupSource),
    TimeBucket(CollectionTimeBucketGroupSource),
    Crosstab(CollectionCrosstabGroupSource),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionProjectionGroupWipState {
    Ok,
    OverLimit,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionProjectionGroupView {
    pub key: NonEmptyString,
    pub title: NonEmptyString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CollectionGroupSource>,
    #[serde(default)]
    pub items: Vec<ProjectionRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub limited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_state: Option<CollectionProjectionGroupWipState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionProjectionKind {
    #[serde(rename = "collection")]
    Collection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionProjectionView {
    pub projection: CollectionProjectionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub view_id: ViewId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub frontier: StateFrontier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CollectionProjectionGroupView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ProjectionRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
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
    pub cursor_presence: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub frontier: Option<StateFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMorphProjection {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn projection_object_uses_the_spec_kind_member() {
        let object: ProjectionObject = serde_json::from_value(json!({
            "id": "ak:strand:01904100-0000-7000-8000-000000000011",
            "kind": "strand"
        }))
        .unwrap();
        assert_eq!(object.object_kind, ProjectionObjectKind::Strand);

        let encoded = serde_json::to_value(object).unwrap();
        assert_eq!(encoded["kind"], "strand");
        assert!(encoded.get("object_kind").is_none());
    }
}
