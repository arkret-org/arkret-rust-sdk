use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nulls: Option<NullsOrder>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FieldFilter {
    pub field: String,
    pub op: FilterOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum Filter {
    Predicate(FieldFilter),
    And { and: Vec<Filter> },
    Or { or: Vec<Filter> },
    Not { not: Box<Filter> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RelationQuery {
    pub kind: RelationKind,
    pub direction: RelationDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

impl RelationQuery {
    pub fn validate_endpoints(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_kinds: Vec<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_tiebreak: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryConsistency {
    pub wait_for: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryRequest {
    pub space_ids: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<QueryContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_by: Vec<SortSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency: Option<QueryConsistency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryFrontier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<Hlc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryResponse<T = Value> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<QueryFrontier>,
}

// ============================================================================
// Collection projection (T20) — board / list / table renderer responses.
// Per `models/views.md` §6.3.
//
// Unlike `QueryResponse<T>`'s flat item list, a collection projection is
// nested: `groups` (Lists / status columns) each contain `items` (Flows
// with rank + locked-discussion metadata). This shape lets a kanban
// renderer paint the board in one pass without correlating two response
// vectors.
// ============================================================================

/// Top-level response for a `View{kind="collection"}` projection — the
/// canonical shape for kanban / list / table / calendar renderers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionProjectionResponse {
    /// Always `"collection"`. Pinned to `ViewKind::Collection` for
    /// callers that match on it.
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = String)))]
    pub kind: ViewKind,
    /// Renderer hint — `board`, `row`, `table`, `calendar`, `gantt`, …
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = String)))]
    pub renderer: ViewRenderer,
    /// Source View id; clients echo this back so they can correlate
    /// async responses with the active View.
    pub view_id: ViewId,
    /// Frontier (signed Event refs) that this projection was computed
    /// against. Clients should retain this so they can replay against
    /// the same baseline if they need to reproduce the exact rendering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontier: Vec<String>,
    /// Groups are typically Space(kind=list) cells in a kanban or
    /// status-segmented columns in a table. Order is reducer-stable
    /// (rank ascending, then HLC tie-break per spec §10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CollectionProjectionGroup>,
}

/// One column / list / status bucket in a collection projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionProjectionGroup {
    /// Stable id for this group. Typically a `cx:space:` (List form)
    /// or a synthetic id for status / facet buckets.
    pub group_id: String,
    /// Human-readable group title.
    pub title: String,
    /// Reducer-stable rank string used for inter-group ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Items in this group, already sorted (rank ascending then
    /// HLC tie-break) and authz-trimmed by the projection executor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<CollectionProjectionItem>,
    /// Optional hidden item count when `hidden_count_policy != omit`.
    /// When `Some(n)` the group conceptually contains `items.len() + n`
    /// rows; the unseen rows are policy-trimmed and SHOULD NOT leak
    /// titles / counts beyond what the policy permits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_count: Option<u32>,
}

/// A single item (typically a Flow card) inside a projection group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionProjectionItem {
    /// The materialised object — usually a Flow but MAY be a Morph or
    /// Message depending on `View.collection.item_object_types`. The
    /// shape is whatever `Flow` / `Morph` / `Message` deserialise to.
    pub object: Value,
    /// Position metadata: which `contains` Relation places this item
    /// in this group, and at what rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<CollectionProjectionPosition>,
    /// Card-vs-Room visibility split per yougen claude-design's
    /// `card-vs-room-visibility` block. When `Some`, indicates the
    /// item has a discussion track; when the discussion is locked
    /// (visibility != "readable"), `lazy_link=true` MUST hold and
    /// no discussion metadata beyond opaque hash MAY be exposed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discussion: Option<CollectionProjectionDiscussion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionProjectionPosition {
    /// `cx:relation:` id for the `contains` Relation that places this
    /// item in this group. Stable across reducer recomputation.
    pub relation_id: String,
    /// Rank string (lexicographic). Same ordering rules as
    /// `CollectionProjectionGroup::rank`.
    pub rank: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionProjectionDiscussion {
    /// Whether the discussion track is enabled on this Flow.
    pub enabled: bool,
    /// `readable` (caller MAY render thread / member preview) or
    /// `locked` (caller MUST treat as opaque link only).
    pub visibility: String,
    /// True when the discussion is referenced via cross-Space
    /// lazy_link — caller MUST NOT expand title / members / counts.
    #[serde(default)]
    pub lazy_link: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct View {
    pub schema: String,
    pub id: ViewId,
    pub space_id: SpaceId,
    pub kind: ViewKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub query: QueryRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<CollectionViewConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphViewConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<SortSpec>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CollectionViewConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_facets: Vec<Facet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_render: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouping: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GraphViewConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_relation_kinds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}
