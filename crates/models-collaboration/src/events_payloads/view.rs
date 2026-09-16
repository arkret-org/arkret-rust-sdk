//! View event payloads.

use crate::internal_prelude::*;
use crate::objects::queries::{CollectionConfig, CollectionGroupingMode, View, ViewState};
use crate::objects::view::{DashboardConfig, QueryValue};

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ViewCreateObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewPayloadWire {
    definition: Option<BTreeMap<String, Value>>,
    expected_state_digest: Option<Hash>,
    object: Option<ViewCreateObject>,
    patch: Option<Patch>,
    view_id: Option<ViewId>,
}

impl ViewPayload {
    pub fn validate(&self) -> Result<()> {
        if self.object.is_none()
            && self.definition.is_none()
            && !(self.view_id.is_some() && self.patch.is_some())
        {
            return schema_violation(
                "View payload requires object, definition, or view_id and patch",
            );
        }
        if let Some(object) = &self.object {
            object.validate()?;
        }
        if let Some(patch) = &self.patch {
            patch.validate()?;
        }
        Ok(())
    }

    pub fn validate_for_create(&self) -> Result<()> {
        self.validate()?;
        if self.object.is_none() {
            return schema_violation("ak.view.create requires its creation object");
        }
        Ok(())
    }

    pub fn validate_for_update(&self) -> Result<()> {
        self.validate()?;
        if self.view_id.is_none() || self.patch.is_none() {
            return schema_violation("ak.view.update requires view_id and patch");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ViewPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            definition: wire.definition,
            expected_state_digest: wire.expected_state_digest,
            object: wire.object,
            patch: wire.patch,
            view_id: wire.view_id,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Create-only View object. Its identity is derived from the enclosing Event,
/// so neither `id` nor `type` is a wire member. Unknown members are accepted
/// only in the schema's restricted `x_*` extension namespace.
/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json`, restricted by
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload/properties/object`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewCreateObject {
    pub schema: String,
    pub realm_id: RealmId,
    pub kind: ViewKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<ViewVisibility>,
    pub state: ViewState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub query: QueryValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<CollectionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<DashboardConfig>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extensions: XExtensionMap,
}

impl ViewCreateObject {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::VIEW_V1 {
            return schema_violation("View creation requires ak.schema.view.v1");
        }
        if self.visibility == Some(ViewVisibility::Private) {
            return schema_violation("private_view_requires_account_data");
        }
        if self.state != ViewState::Active || self.state_changed_at.is_some() {
            return schema_violation(
                "View creation must be active without reducer-derived state_changed_at",
            );
        }
        if self
            .updated_at
            .is_some_and(|updated| updated < self.created_at)
        {
            return schema_violation("View updated_at must not precede created_at");
        }
        for (present, owning_kind) in [
            (self.collection.is_some(), ViewKind::Collection),
            (self.timeline.is_some(), ViewKind::Timeline),
            (self.graph.is_some(), ViewKind::Graph),
            (self.document.is_some(), ViewKind::Document),
            (self.dashboard.is_some(), ViewKind::Composite),
        ] {
            if present != (self.kind == owning_kind) {
                return schema_violation("View kind requires exactly its own configuration");
            }
        }
        if self
            .renderer
            .is_some_and(|renderer| !self.kind.allows_renderer(renderer))
        {
            return schema_violation("View renderer does not match its kind");
        }
        if let Some(collection) = &self.collection {
            validate_collection_config(collection)?;
        }
        if let Some(dashboard) = &self.dashboard {
            if dashboard.widgets.is_empty() {
                return schema_violation("View dashboard requires at least one widget");
            }
            for widget in &dashboard.widgets {
                if !matches!(
                    widget.kind.as_str(),
                    "collection" | "timeline" | "graph" | "document" | "metric" | "text" | "custom"
                ) {
                    return schema_violation("View dashboard widget kind is not registered");
                }
                if widget.source_view_ref.is_none()
                    && widget.query.is_none()
                    && !matches!(widget.kind.as_str(), "text" | "custom")
                {
                    return schema_violation(
                        "View dashboard data widget requires a source or query",
                    );
                }
            }
        }
        Ok(())
    }
}

fn validate_collection_config(collection: &CollectionConfig) -> Result<()> {
    collection.validate_extensions()?;
    if collection.item_object_kinds.is_empty() && collection.item_facets.is_empty() {
        return schema_violation("View collection requires item_object_kinds or item_facets");
    }
    if collection.item_order_by.is_empty() {
        return schema_violation("View collection requires nonempty item_order_by");
    }
    let Some(grouping) = &collection.grouping else {
        return schema_violation("View collection requires grouping");
    };
    let valid = match grouping.mode {
        CollectionGroupingMode::None => true,
        CollectionGroupingMode::Field => grouping.field.is_some() && grouping.lanes.is_some(),
        CollectionGroupingMode::RelationContainer => {
            grouping.board_space_id.is_some() && grouping.item_relation_kind.is_some()
        }
        CollectionGroupingMode::TimeBucket => grouping.start_field.is_some(),
        CollectionGroupingMode::Matrix => {
            grouping.rows_by.is_some() && grouping.columns_by.is_some()
        }
    };
    if !valid {
        return schema_violation("View collection grouping is missing mode-specific fields");
    }
    Ok(())
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_reconcile_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewReconcilePayload {
    pub view_id: ViewId,
    pub definition: View,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewReconcilePayloadWire {
    view_id: ViewId,
    definition: View,
}

impl ViewReconcilePayload {
    pub fn validate(&self) -> Result<()> {
        if self.definition.id != self.view_id {
            return schema_violation("reconciled View definition id must equal payload view_id");
        }
        self.definition.validate()
    }
}

impl<'de> Deserialize<'de> for ViewReconcilePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewReconcilePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            view_id: wire.view_id,
            definition: wire.definition,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}
