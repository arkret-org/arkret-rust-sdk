//! View event payloads.

use crate::internal_prelude::*;
use crate::objects::queries::{CollectionConfig, CollectionGroupingMode};
use crate::objects::view::{DashboardConfig, QueryValue};

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

/// Author-editable View definition, shared by create and reconcile.
/// `view.schema.json#/$defs/view_definition` excludes reducer-owned identity,
/// Realm, schema, provenance and lifecycle members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewDefinition {
    pub kind: ViewKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<ViewVisibility>,
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
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extensions: XExtensionMap,
}

impl ViewDefinition {
    pub fn validate(&self) -> Result<()> {
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

    fn validate_shared(&self) -> Result<()> {
        self.validate()?;
        if self.visibility == Some(ViewVisibility::Private) {
            return schema_violation("private_view_requires_account_data");
        }
        Ok(())
    }
}

/// `event-payload.schema.json#/$defs/view_create_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewCreatePayload {
    pub object: ViewDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewCreatePayloadWire {
    object: ViewDefinition,
}

impl ViewCreatePayload {
    pub fn validate(&self) -> Result<()> {
        self.object.validate_shared()
    }
}

impl<'de> Deserialize<'de> for ViewCreatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewCreatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            object: wire.object,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// `event-payload.schema.json#/$defs/view_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewUpdatePayload {
    pub view_id: ViewId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewUpdatePayloadWire {
    view_id: ViewId,
    patch: Patch,
    expected_state_digest: Option<Hash>,
}

impl ViewUpdatePayload {
    pub fn validate(&self) -> Result<()> {
        self.patch.validate()?;
        if self.patch.iter().any(|(path, op)| {
            path == "visibility" && op.value().is_some_and(|value| value == "private")
        }) {
            return schema_violation("private_view_requires_account_data");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ViewUpdatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewUpdatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            view_id: wire.view_id,
            patch: wire.patch,
            expected_state_digest: wire.expected_state_digest,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
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
    pub definition: ViewDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewReconcilePayloadWire {
    view_id: ViewId,
    definition: ViewDefinition,
}

impl ViewReconcilePayload {
    pub fn validate(&self) -> Result<()> {
        self.definition.validate_shared()
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ViewCreatePayload, ViewReconcilePayload, ViewUpdatePayload};

    #[test]
    fn formal_view_write_shapes_match_the_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../arkret-spec/spec/v1/artifacts/fixtures/view-write-contract-fixture.json"
        ))
        .unwrap();
        for name in [
            "create_payload_accepts_the_author_definition",
            "create_payload_refuses_a_self_reported_creator",
            "create_payload_refuses_a_self_reported_realm",
            "create_payload_refuses_a_self_reported_state",
            "create_payload_refuses_the_derived_id",
            "create_payload_refuses_a_patch",
            "reconcile_payload_accepts_the_author_definition",
            "reconcile_definition_cannot_resurrect_or_tombstone",
            "terminal_state_patch_is_accepted",
            "terminal_state_patch_in_explicit_op_form_is_accepted",
            "terminal_state_patch_with_prestate_guard_is_accepted",
            "update_payload_refuses_a_reducer_derived_member",
            "update_payload_refuses_an_object_snapshot",
            "update_payload_requires_the_subject",
        ] {
            let case = fixture["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            let instance = case["instance"].clone();
            let parsed = match case["schema_ref"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
            {
                "view_create_payload" => {
                    serde_json::from_value::<ViewCreatePayload>(instance).is_ok()
                }
                "view_update_payload" => {
                    serde_json::from_value::<ViewUpdatePayload>(instance).is_ok()
                }
                "view_reconcile_payload" => {
                    serde_json::from_value::<ViewReconcilePayload>(instance).is_ok()
                }
                other => panic!("unexpected View payload schema: {other}"),
            };
            assert_eq!(parsed, case["valid"].as_bool().unwrap(), "{name}");
        }
    }

    #[test]
    fn shared_view_payloads_reject_private_visibility() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../arkret-spec/spec/v1/artifacts/fixtures/view-write-contract-fixture.json"
        ))
        .unwrap();
        let create = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "create_payload_accepts_the_author_definition")
            .unwrap()["instance"]
            .clone();
        let mut private_create = create.clone();
        private_create["object"]["visibility"] = json!("private");
        assert!(serde_json::from_value::<ViewCreatePayload>(private_create).is_err());

        let mut reconcile = json!({
            "view_id": "ak:view:AQwfxZZieb7Udz28u8Z_wXvR3hFpZzHl4sWKOICaiKC6",
            "definition": create["object"]
        });
        reconcile["definition"]["visibility"] = json!("private");
        assert!(serde_json::from_value::<ViewReconcilePayload>(reconcile).is_err());

        for visibility in [json!("private"), json!({"$op":"set", "value":"private"})] {
            assert!(
                serde_json::from_value::<ViewUpdatePayload>(json!({
                    "view_id": "ak:view:AQwfxZZieb7Udz28u8Z_wXvR3hFpZzHl4sWKOICaiKC6",
                    "patch": {"visibility": visibility}
                }))
                .is_err()
            );
        }
    }
}
