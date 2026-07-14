//! View and space schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/space.schema.json#/$defs/metadata_encryption_floor`.
pub type MetadataEncryptionFloor = String;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/collection_config`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_object_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_facets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_render: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_order_by: Option<Vec<SortSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_fields: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping: Option<CollectionGrouping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/collection_grouping`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionGrouping {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lanes: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_relation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_relation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub columns_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_count_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_limit_enforcement: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/query`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<Vec<SortSpec>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfigWidgetsItem {
    pub widget_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_view_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<QueryValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    pub widgets: Vec<DashboardConfigWidgetsItem>,
}

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/document_config`.
pub type DocumentConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/field_path`.
pub type FieldPath = String;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/graph_config`.
pub type GraphConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/timeline_config`.
pub type TimelineConfig = BTreeMap<String, Value>;
