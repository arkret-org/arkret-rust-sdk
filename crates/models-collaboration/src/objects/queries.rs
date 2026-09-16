//! Query, filter, and View definition wire shapes.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, CommitStreamHead, Cursor, Facet, FilterOp, NullsOrder, RealmId, RelationDirection,
    RelationKind, Result, SchemaId, SortDirection, SpaceId, ViewId, ViewKind, ViewRenderer,
    ViewVisibility, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::objects::relation::RelationEndpoint;
use crate::objects::view::DashboardConfig;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/sort_spec`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nulls: Option<NullsOrder>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    pub op: FilterOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Predicate(FieldFilter),
    And { and: Vec<Filter> },
    Or { or: Vec<Filter> },
    Not { not: Box<Filter> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationQuery {
    pub kind: RelationKind,
    pub direction: RelationDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<RelationEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<RelationEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

impl RelationQuery {
    pub fn validate_endpoints(&self) -> Result<()> {
        for endpoint in self.source_ref.iter().chain(self.target_ref.iter()) {
            endpoint.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueryContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_kinds: Vec<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_tiebreak: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryConsistency {
    pub wait_for: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewQuery {
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_heads: Vec<CommitStreamHead>,
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
#[serde(deny_unknown_fields)]
pub struct View {
    pub schema: String,
    pub id: ViewId,
    pub realm_id: RealmId,
    pub kind: ViewKind,
    /// Optional sharing visibility in the current schema. Private views are
    /// actor-private account data; shared views are canonical Space objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<ViewVisibility>,
    /// Required lifecycle state. The current wire contract has no omitted-state
    /// default: creators must send `active` explicitly.
    pub state: ViewState,
    /// Reducer-derived timestamp, present only for tombstoned Views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub query: ViewQuery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<CollectionConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphViewConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<DashboardConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<SortSpec>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewState {
    Active,
    Tombstoned,
}

impl View {
    pub const SCHEMA: &'static str = SchemaId::VIEW_V1;

    /// Full `ak.schema.view.v1` object check: schema id, the `kind` ↔ typed
    /// config mutual exclusion, the per-kind renderer whitelist, and the
    /// shared lifecycle rule (`views.md` §3.1).
    ///
    /// Deserialization alone is not enough — `deny_unknown_fields` cannot
    /// express "exactly the config matching `kind`". A private View never
    /// reaches a reducer, so this is the only place its definition is checked
    /// at all; see [`View::validate_private_account_data`].
    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(format!(
                "view schema must be {}",
                Self::SCHEMA
            )));
        }
        let present = [
            (
                "collection",
                self.collection.is_some(),
                ViewKind::Collection,
            ),
            ("timeline", self.timeline.is_some(), ViewKind::Timeline),
            ("graph", self.graph.is_some(), ViewKind::Graph),
            ("document", self.document.is_some(), ViewKind::Document),
            ("dashboard", self.dashboard.is_some(), ViewKind::Composite),
        ];
        for (field, is_present, owning_kind) in present {
            match (is_present, owning_kind == self.kind) {
                (true, false) => {
                    return Err(WireError::Protocol(format!(
                        "view kind {:?} must not carry the {field} config",
                        self.kind
                    )));
                }
                (false, true) => {
                    return Err(WireError::Protocol(format!(
                        "view kind {:?} requires the {field} config",
                        self.kind
                    )));
                }
                _ => {}
            }
        }
        if self
            .dashboard
            .as_ref()
            .is_some_and(|dashboard| dashboard.widgets.is_empty())
        {
            return Err(WireError::Protocol(
                "composite view dashboard requires at least one widget".to_owned(),
            ));
        }
        if let Some(renderer) = self.renderer
            && !self.kind.allows_renderer(renderer)
        {
            return Err(WireError::Protocol(format!(
                "view kind {:?} does not allow renderer {renderer:?}",
                self.kind
            )));
        }
        if let Some(collection) = &self.collection {
            collection.validate_extensions()?;
        }
        self.validate_lifecycle()
    }

    /// Additional rules for a View carried as `ak.views.private.<view_id>`
    /// encrypted account data (`views.md` §3.1, `client-preferences.md` §3.2).
    ///
    /// The server only ever sees ciphertext here, so nothing downstream can
    /// re-check any of this — the holder's client is the only enforcement
    /// point.
    pub fn validate_private_account_data(&self, account_data_key: &str) -> Result<()> {
        self.validate()?;
        if self.visibility != Some(ViewVisibility::Private) {
            return Err(WireError::Protocol(
                "private account-data view requires visibility=private".to_owned(),
            ));
        }
        // `state_changed_at` is reducer-derived and `tombstoned` is the shared
        // View terminal. A private View is removed by physically deleting its
        // account-data key, and a published shared View can never be demoted
        // back to private, so neither may appear here.
        if self.state == ViewState::Tombstoned {
            return Err(WireError::Protocol(
                "private account-data view must not carry the shared tombstoned state".to_owned(),
            ));
        }
        if crate::events_payloads::private_view_account_data_key(&self.id) != account_data_key {
            return Err(WireError::Protocol(
                "private view must be stored under ak.views.private.<its own view_id>".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_lifecycle(&self) -> Result<()> {
        match (self.state, self.state_changed_at) {
            (ViewState::Active, None) | (ViewState::Tombstoned, Some(_)) => Ok(()),
            (ViewState::Active, Some(_)) => Err(WireError::Protocol(
                "active view must not carry state_changed_at".to_owned(),
            )),
            (ViewState::Tombstoned, None) => Err(WireError::Protocol(
                "tombstoned view requires state_changed_at".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollectionConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_object_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_facets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_render: Option<CollectionItemRender>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_order_by: Vec<SortSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display_fields: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_policy: Option<CollectionCountPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouping: Option<CollectionGrouping>,
    #[serde(
        default,
        flatten,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_collection_extensions"
    )]
    pub extra: BTreeMap<String, Value>,
}

impl CollectionConfig {
    pub(crate) fn validate_extensions(&self) -> Result<()> {
        validate_collection_extensions(&self.extra)?;
        if let Some(grouping) = &self.grouping {
            validate_collection_extensions(&grouping.extra)?;
        }
        Ok(())
    }
}

fn validate_collection_extensions(extra: &BTreeMap<String, Value>) -> Result<()> {
    // views.md sections 3.3 and 3.4 forbid these keys even though the schema
    // permits other extension members in collection and grouping configs.
    for field in ["page_size", "selection_policy", "wip_limit_enforcement"] {
        if extra.contains_key(field) {
            return Err(WireError::Protocol(format!(
                "schema_violation: View collection configuration must not carry {field}"
            )));
        }
    }
    Ok(())
}

fn deserialize_collection_extensions<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let extra = BTreeMap::deserialize(deserializer)?;
    validate_collection_extensions(&extra).map_err(serde::de::Error::custom)?;
    Ok(extra)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionItemRender {
    Card,
    Row,
    Tile,
    Compact,
    Badge,
    Message,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionCountPolicy {
    Omit,
    AuthorizedEstimate,
    AuthorizedExact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionGroupingMode {
    None,
    Field,
    RelationContainer,
    TimeBucket,
    Matrix,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionGrouping {
    pub mode: CollectionGroupingMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lanes: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_relation_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_relation_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_count_policy: Option<CollectionCountPolicy>,
    #[serde(
        default,
        flatten,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_collection_extensions"
    )]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GraphViewConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_object_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_morph_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_relation_kinds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}
