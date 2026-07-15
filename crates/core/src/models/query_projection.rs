use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReferenceProjectionStatus {
    Accessible,
    LazyLink,
    Locked,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ViewProjectionRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StateFrontier {
    pub state_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_frontiers: Vec<StateFrontierActor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StateFrontierActor {
    pub actor_id: Did,
    pub actor_seq: u64,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionObject {
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: ProjectionObjectKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub morph_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionItemRender {
    Card,
    Row,
    Tile,
    Compact,
    Badge,
    Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectionItem {
    pub object: ProjectionObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render: Option<ProjectionItemRender>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub display: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub position: Option<CollectionPosition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub state: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum FieldValuePositionModel {
    #[serde(rename = "field_value")]
    FieldValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct FieldValueCollectionPosition {
    pub model: FieldValuePositionModel,
    pub container_id: NonEmptyString,
    pub rank: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum RelationPositionModel {
    #[serde(rename = "relation")]
    Relation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum TimeWindowPositionModel {
    #[serde(rename = "time_window")]
    TimeWindow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCollectionPosition {
    pub model: TimeWindowPositionModel,
    pub start: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<NonEmptyString>,
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum CrosstabPositionModel {
    #[serde(rename = "crosstab_cell")]
    CrosstabCell,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CrosstabCollectionPosition {
    pub model: CrosstabPositionModel,
    pub row_key: NonEmptyString,
    pub column_key: NonEmptyString,
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SortKeyCollectionPosition {
    pub sort_key: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
pub enum TimeBucketGroupModel {
    #[serde(rename = "time_bucket")]
    TimeBucket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionTimeBucketGroupSource {
    pub model: TimeBucketGroupModel,
    pub start: DateTime<Utc>,
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
    Relation(CollectionRelationGroupSource),
    TimeBucket(CollectionTimeBucketGroupSource),
    Crosstab(CollectionCrosstabGroupSource),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CollectionProjectionGroupWipState {
    Ok,
    OverLimit,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CollectionProjectionGroupView {
    pub key: NonEmptyString,
    pub title: NonEmptyString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub source: Option<CollectionGroupSource>,
    #[serde(default)]
    pub items: Vec<ProjectionItem>,
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CollectionProjectionView {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = String)))]
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
    pub items: Vec<ProjectionItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DocumentMorphProjectionOutcome {
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
    pub frontier: Option<StateFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DocumentMorphProjection {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extensions: BTreeMap<String, Value>,
}
