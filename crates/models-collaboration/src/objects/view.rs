//! View and space schema artifact counterparts.

use std::collections::BTreeMap;

use arkret_wire::RealmId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::objects::queries::SortSpec;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/query`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_kinds: Option<Vec<String>>,
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
