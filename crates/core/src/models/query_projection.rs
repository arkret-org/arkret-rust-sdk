use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryOutcome<T> {
    pub item: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum QueryProjection {
    Raw,
    Collection,
    Timeline,
    Graph,
    Document,
    Composite,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<QueryProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationQuery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_by: Vec<SortSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SearchRequestBody {
    pub query: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub time_range: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct StateFrontier {
    pub state_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_frontiers: Vec<StateFrontierActor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionFieldValueGroupSource {
    pub model: String,
    pub field: String,
    pub value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionRelationGroupSource {
    pub model: String,
    pub scope_container_id: String,
    pub container_id: String,
    pub relation_kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionTimeBucketGroupSource {
    pub model: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub timezone: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionCrosstabGroupSource {
    pub model: String,
    pub row_key: String,
    pub column_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
pub struct CollectionProjectionGroupView {
    pub key: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionFieldValuePosition {
    pub model: String,
    pub container_id: String,
    pub rank: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionRelationPosition {
    pub model: String,
    pub scope_container_id: String,
    pub container_id: String,
    pub relation_kind: String,
    pub relation_id: RelationId,
    pub rank: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionTimeWindowPosition {
    pub model: String,
    pub start: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    pub sort_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionCrosstabPosition {
    pub model: String,
    pub row_key: String,
    pub column_key: String,
    pub sort_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ObjectLookupVisibility {
    Visible,
    Redacted,
    Partial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ObjectLookupOutcome {
    pub object: ProjectionObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_after: Option<StateFrontier>,
    pub visibility: ObjectLookupVisibility,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct StrandDiscussionTimelineView {
    pub entries: Vec<TimelineProjectionEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<ProjectionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_after: Option<StateFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct StrandDiscussionSummary {
    pub strand: ProjectionObject,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub relation: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summary: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct StrandDiscussionList {
    pub strands: Vec<StrandDiscussionSummary>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summaries: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_after: Option<StateFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationProjectionView {
    #[serde(default)]
    pub notifications: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub counts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InboxView {
    pub items: Vec<ProjectionItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<StateFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SearchMatch {
    pub object: ProjectionObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub highlights: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SearchMatchList {
    pub matches: Vec<SearchMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SpaceHierarchyEdgeStatus {
    Confirmed,
    UnconfirmedLink,
    Rejected,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReferenceProjectionStatus {
    Accessible,
    LazyLink,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceHierarchyChild {
    pub realm_id: RealmId,
    pub edge_status: SpaceHierarchyEdgeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessible: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy_link: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_projection_status: Option<ReferenceProjectionStatus>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summary: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceHierarchyEdge {
    pub parent_space_id: SpaceId,
    pub child_space_id: SpaceId,
    pub edge_status: SpaceHierarchyEdgeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceHierarchyView {
    pub root_space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<ProjectionObject>,
    pub children: Vec<SpaceHierarchyChild>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<SpaceHierarchyEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle_detected: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RawQueryOutcome {
    pub projection: String,
    pub rows: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
    pub frontier: StateFrontier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/view.schema.json#/$defs/view_projection_request_body`.
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
pub struct CollectionProjectionView {
    pub projection: String,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TimelineProjectionEntryType {
    Event,
    Message,
    Activity,
    System,
    Tombstone,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineProjectionEntry {
    pub id: String,
    pub entry_type: TimelineProjectionEntryType,
    pub sort_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<ProjectionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineProjectionView {
    pub projection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub view_id: ViewId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub frontier: StateFrontier,
    pub entries: Vec<TimelineProjectionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GraphProjectionNode {
    pub object: ProjectionObject,
    pub depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GraphProjectionEdge {
    pub relation_id: RelationId,
    pub relation_kind: String,
    pub from_ref: String,
    pub to_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GraphProjectionView {
    pub projection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub view_id: ViewId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub frontier: StateFrontier,
    pub nodes: Vec<GraphProjectionNode>,
    pub edges: Vec<GraphProjectionEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DocumentProjectionSection {
    pub object: ProjectionObject,
    pub sort_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DocumentProjectionView {
    pub projection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub view_id: ViewId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub frontier: StateFrontier,
    pub sections: Vec<DocumentProjectionSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DocumentMorphProjectionOutcome {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CompositeWidgetProjection {
    Collection,
    Timeline,
    Graph,
    Document,
    Composite,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CompositeProjectionWidget {
    pub id: String,
    pub title: String,
    pub projection: CompositeWidgetProjection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub frontier: StateFrontier,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CompositeProjectionView {
    pub projection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    pub view_id: ViewId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub frontier: StateFrontier,
    pub widgets: Vec<CompositeProjectionWidget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CellQueryStatus {
    Value,
    Bottom,
    Conflict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CellQuerySealView {
    pub leaves: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CellQueryEnvelope {
    pub cell: String,
    pub status: CellQueryStatus,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub value: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<BottomDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_view: Option<CellQuerySealView>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventProtocolState {
    PendingSeal,
    Sealed,
    FailedPrecondition,
    FailedBottom,
    RejectedSeal,
    NotaryPaused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventStateView {
    pub event_id: EventId,
    pub event_digest: String,
    pub event_state: EventProtocolState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<BottomDiagnostic>,
}
