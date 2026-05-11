//! High-level space API for Contrix v1.
//!
//! This module provides a high-level interface for working with spaces,
//! including entity management, relations, timeline operations, and membership.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet, VecDeque},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::{
    FlowId, Result,
    base::{BaseClient, SpaceStateType},
    media::{Attachment, MediaMetadata},
    model::{
        BlobRef, Did, Entity, EntityId, EntityType, EventId, FieldFilter, Filter, FilterOp, Flow,
        FlowKind, NullsOrder, OP_ENTITY_CREATE, OP_ENTITY_DELETE, OP_ENTITY_REDACT,
        OP_ENTITY_UPDATE, ObjectState, Operation, OperationId, OperationType, Relation, RelationId,
        RelationKind, RelationState, SortDirection, SortSpec, SpaceId,
    },
    resolver::SpaceState,
};

/// Generate a new UUIDv7-based wire ID with the given Contrix typed prefix
/// (e.g. `cx:operation:`, `cx:flow:`, `cx:entity:`). The result is always
/// 36-char lowercase hex per RFC 9562 §5.7 / `conformance/encoding.md` §4.
mod entity;
mod flow;
mod helpers;
mod membership;
mod query;
mod relation;
#[cfg(test)]
mod tests;

pub use flow::{FlowCreateMetadata, FlowUpdateMetadata};
pub use relation::RelationOperationInput;

use helpers::*;

fn generate_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Entity query options applied to the local resolved state.
#[derive(Clone, Debug, Default)]
pub struct EntityQuery {
    /// Entity types to include. Empty means all types.
    pub entity_types: Vec<EntityType>,
    /// Filters combined with AND semantics.
    pub filters: Vec<Filter>,
    /// Sort specifications applied in order.
    pub order_by: Vec<SortSpec>,
    /// Maximum result count.
    pub limit: Option<usize>,
}

/// Aggregated entity counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntityAggregation {
    /// Total number of entities considered.
    pub total: usize,
    /// Counts grouped by entity type.
    pub by_type: BTreeMap<String, usize>,
    /// Counts grouped by requested field keys.
    pub by_field: BTreeMap<String, BTreeMap<String, usize>>,
}

/// Relation graph traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphTraversal {
    /// Breadth-first traversal.
    BreadthFirst,
    /// Depth-first traversal.
    DepthFirst,
}

/// Entity state at a historical version.
#[derive(Clone, Debug, PartialEq)]
pub struct EntityVersion {
    /// Entity ID.
    pub entity_id: EntityId,
    /// Version number, starting at 0 for creation.
    pub version: u64,
    /// Event that produced this version.
    pub event_id: EventId,
    /// Time the version was produced.
    pub updated_at: DateTime<Utc>,
    /// Entity title at this version.
    pub title: Option<String>,
    /// Entity content at this version.
    pub content: Option<Value>,
    /// Entity fields at this version.
    pub fields: BTreeMap<String, Value>,
    /// Entity object state at this version.
    pub state: Option<ObjectState>,
}

/// Field-level diff between two entity versions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntityVersionDiff {
    /// Title changed.
    pub title_changed: bool,
    /// Content changed.
    pub content_changed: bool,
    /// Field keys added in the target version.
    pub added_fields: Vec<String>,
    /// Field keys removed in the target version.
    pub removed_fields: Vec<String>,
    /// Field keys present in both versions with different values.
    pub changed_fields: Vec<String>,
}

/// Input for batch entity creation.
#[derive(Clone, Debug)]
pub struct BatchCreateEntity {
    pub entity_type: EntityType,
    pub title: Option<String>,
    pub content: Option<Value>,
    pub fields: BTreeMap<String, Value>,
}

/// Input for batch entity update.
#[derive(Clone, Debug)]
pub struct BatchUpdateEntity {
    pub entity_id: EntityId,
    pub title: Option<String>,
    pub content: Option<Value>,
    pub fields: Option<BTreeMap<String, Value>>,
}

/// High-level Space client providing business logic operations.
#[derive(Clone)]
pub struct Space {
    /// Space ID
    pub space_id: SpaceId,
    /// Base client reference
    base_client: Arc<BaseClient>,
    /// Current space state
    state: Arc<SpaceState>,
}

impl Space {
    /// Create a new Space client.
    pub fn new(space_id: SpaceId, base_client: Arc<BaseClient>) -> Self {
        // Try to get existing space state from base client
        let state = if let Some(client_space) = base_client.get_space(&space_id) {
            Arc::new(client_space.space_state)
        } else {
            Arc::new(SpaceState::new(space_id.clone(), "1".to_owned()))
        };

        Self { space_id, base_client, state }
    }

    /// Get the space ID.
    pub fn id(&self) -> &SpaceId {
        &self.space_id
    }

    /// Get the current space state.
    pub fn state(&self) -> &SpaceState {
        &self.state
    }

    /// Refresh the space state from the base client.
    pub fn refresh_state(&mut self) -> Result<()> {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            self.state = Arc::new(client_space.space_state);
        }
        Ok(())
    }

    /// Check if the user is a member of this space.
    pub fn is_joined(&self) -> bool {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            client_space.state == SpaceStateType::Joined
        } else {
            false
        }
    }

    /// Check if the user has been invited to this space.
    pub fn is_invited(&self) -> bool {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            client_space.state == SpaceStateType::Invited
        } else {
            false
        }
    }

    /// Check if the user has left this space.
    pub fn is_left(&self) -> bool {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            client_space.state == SpaceStateType::Left
        } else {
            false
        }
    }

    /// Get notification count for this space.
    pub fn notification_count(&self) -> u64 {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            client_space.notification_count
        } else {
            0
        }
    }

    /// Get highlight count for this space.
    pub fn highlight_count(&self) -> u64 {
        if let Some(client_space) = self.base_client.get_space(&self.space_id) {
            client_space.highlight_count
        } else {
            0
        }
    }

    /// Get the read marker for this space.
    pub fn read_marker(&self) -> Option<String> {
        self.base_client.read_marker(&self.space_id)
    }

    /// Set the read marker for this space.
    pub fn set_read_marker(&self, marker: String) -> Result<()> {
        self.base_client.set_read_marker(&self.space_id, marker)
    }

    /// Get all entities in this space.
    pub fn entities(&self) -> BTreeMap<String, Entity> {
        self.state.entities.clone()
    }

    /// Get all flows in this space.
    pub fn flows(&self) -> BTreeMap<String, Flow> {
        self.state.subjects.clone()
    }

    /// Get a specific flow by ID.
    pub fn get_flow(&self, flow_id: &FlowId) -> Option<Flow> {
        self.state.subjects.get(flow_id.as_str()).cloned()
    }

    /// Find flows by semantic kind.
    pub fn find_flows_by_kind(&self, flow_kind: FlowKind) -> Vec<Flow> {
        self.state.subjects.values().filter(|flow| flow.flow_kind == flow_kind).cloned().collect()
    }

    /// Return active surface relations for a flow.
    pub fn flow_surfaces(&self, flow_id: &FlowId) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|relation| {
                relation.relation_kind == RelationKind::HasSurface
                    && relation.from_ref.as_deref() == Some(flow_id.as_str())
                    && relation_is_active(relation)
            })
            .cloned()
            .collect()
    }

    /// Get a specific entity by ID.
    pub fn get_entity(&self, entity_id: &EntityId) -> Option<Entity> {
        self.state.entities.get(entity_id.as_str()).cloned()
    }

    /// Find entities by type.
    pub fn find_entities_by_type(&self, entity_type: EntityType) -> Vec<Entity> {
        self.state.entities.values().filter(|e| e.entity_type == entity_type).cloned().collect()
    }

    /// Find entities by field value.
    pub fn find_entities_by_field(&self, field_key: &str, field_value: &Value) -> Vec<Entity> {
        self.state
            .entities
            .values()
            .filter(|e| e.fields.get(field_key).map(|v| v == field_value).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Get all relations in this space.
    pub fn relations(&self) -> BTreeMap<String, Relation> {
        self.state.relations.clone()
    }

    /// Get a specific relation by ID.
    pub fn get_relation(&self, relation_id: &RelationId) -> Option<Relation> {
        self.state.relations.get(relation_id.as_str()).cloned()
    }

    /// Find relations by kind.
    pub fn find_relations_by_kind(&self, relation_kind: RelationKind) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.relation_kind == relation_kind)
            .cloned()
            .collect()
    }

    /// Find relations from an entity.
    pub fn find_relations_from_entity(&self, entity_id: &EntityId) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.from_entity_id.as_ref() == Some(entity_id))
            .cloned()
            .collect()
    }

    /// Find relations to an entity.
    pub fn find_relations_to_entity(&self, entity_id: &EntityId) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.to_entity_id.as_ref() == Some(entity_id))
            .cloned()
            .collect()
    }

    /// Get the causal frontier (most recent event IDs).
    pub fn frontier(&self) -> Vec<EventId> {
        self.state.frontier.clone()
    }

    /// Create a snapshot of the current space state.
    pub fn snapshot(&self) -> crate::StateSnapshot {
        self.state.snapshot()
    }

    /// Apply events to update the space state.
    pub fn apply_events(&self, events: Vec<crate::model::Event>) -> Result<()> {
        self.base_client.process_events(&self.space_id, events)
    }

    /// Create a local message send operation using a structured message content object.
    pub fn send_message(&self, content: Value) -> Result<Operation> {
        let mut fields = BTreeMap::new();
        fields.insert("message_kind".to_owned(), json!("custom"));
        self.create_entity_operation(EntityType::Message, None, Some(content), fields)
    }

    /// Create a local plain-text message send operation.
    pub fn send_text(&self, body: impl Into<String>) -> Result<Operation> {
        let body = body.into();
        let mut fields = BTreeMap::new();
        fields.insert("message_kind".to_owned(), json!("text"));
        self.create_entity_operation(
            EntityType::Message,
            None,
            Some(json!({
                "msgtype": "m.text",
                "body": body,
            })),
            fields,
        )
    }

    /// Create a local message edit operation.
    pub fn edit_message(&self, message_id: EntityId, content: Value) -> Result<Operation> {
        let mut fields = BTreeMap::new();
        fields.insert("edited".to_owned(), json!(true));
        let mut operation =
            self.update_entity_operation(message_id.clone(), None, Some(content), Some(fields))?;
        operation.object_type = "message.edit".to_owned();
        operation.object_id = Some(message_id.as_str().to_owned());
        operation.payload["relates_to"] = json!({
            "rel_type": "m.replace",
            "event_id": message_id.as_str(),
        });
        operation.payload["edited_at"] = json!(Utc::now().to_rfc3339());
        Ok(operation)
    }

    /// Create a local message redaction operation.
    pub fn redact_message(
        &self,
        message_id: EntityId,
        reason: Option<String>,
    ) -> Result<Operation> {
        self.base_client.whoami()?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "id": message_id.as_str(),
        });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }
        let mut operation =
            Operation::create(operation_id, self.space_id.clone(), "message.redact", payload);
        operation.operation_type = OperationType::Redact;
        operation.object_id = Some(message_id.as_str().to_owned());
        Ok(operation)
    }

    /// Upload media into the base client's local in-memory media store.
    pub fn upload_media(
        &self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<MediaMetadata> {
        self.base_client.upload_media(bytes, media_type, filename)
    }

    /// Download media from the base client's local in-memory media store.
    pub fn download_media(&self, blob_ref: &BlobRef) -> Option<Vec<u8>> {
        self.base_client.download_media(blob_ref)
    }

    /// Upload an attachment into the base client's local in-memory media store.
    pub fn upload_attachment(
        &self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Attachment> {
        self.base_client.upload_attachment(id, filename, media_type, bytes)
    }

    /// Upload an encrypted attachment into the base client's local in-memory media store.
    pub fn upload_encrypted_attachment(
        &self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        plaintext: impl AsRef<[u8]>,
        key: &[u8],
    ) -> Result<Attachment> {
        self.base_client.upload_encrypted_attachment(id, filename, media_type, plaintext, key)
    }

    /// Download and decrypt an encrypted attachment from the base client.
    pub fn download_decrypted_attachment(&self, id: &str, key: &[u8]) -> Result<Vec<u8>> {
        self.base_client.download_decrypted_attachment(id, key)
    }
}

