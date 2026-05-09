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

/// Advanced entity and relation operations.
impl Space {
    /// Query entities from local resolved state with filters, sorting and limit.
    pub fn query_entities(&self, query: EntityQuery) -> Vec<Entity> {
        let mut entities: Vec<Entity> = self
            .state
            .entities
            .values()
            .filter(|entity| {
                (query.entity_types.is_empty() || query.entity_types.contains(&entity.entity_type))
                    && query.filters.iter().all(|filter| entity_matches_filter(entity, filter))
            })
            .cloned()
            .collect();

        entities.sort_by(|left, right| compare_entities(left, right, &query.order_by));

        if let Some(limit) = query.limit {
            entities.truncate(limit);
        }
        entities
    }

    /// Full-text search over entity title, content and fields.
    pub fn search_entities(&self, query: &str) -> Vec<Entity> {
        let needle = query.to_lowercase();
        self.state
            .entities
            .values()
            .filter(|entity| entity_search_text(entity).contains(&needle))
            .cloned()
            .collect()
    }

    /// Aggregate entities by type and selected field keys.
    pub fn aggregate_entities(&self, field_keys: &[impl AsRef<str>]) -> EntityAggregation {
        let mut aggregation =
            EntityAggregation { total: self.state.entities.len(), ..EntityAggregation::default() };

        for entity in self.state.entities.values() {
            *aggregation.by_type.entry(entity_type_key(&entity.entity_type)).or_default() += 1;

            for field_key in field_keys {
                let field_key = field_key.as_ref();
                if let Some(value) = entity_field_value(entity, field_key) {
                    let value_key = scalar_value_key(&value);
                    *aggregation
                        .by_field
                        .entry(field_key.to_owned())
                        .or_default()
                        .entry(value_key)
                        .or_default() += 1;
                }
            }
        }

        aggregation
    }

    /// Traverse outgoing entity relations from a start entity.
    pub fn traverse_relations(
        &self,
        start: &EntityId,
        relation_kind: Option<RelationKind>,
        traversal: GraphTraversal,
        max_depth: Option<usize>,
    ) -> Vec<EntityId> {
        let mut visited = HashSet::from([start.clone()]);
        let mut output = Vec::new();
        let max_depth = max_depth.unwrap_or(usize::MAX);

        match traversal {
            GraphTraversal::BreadthFirst => {
                let mut queue = VecDeque::from([(start.clone(), 0usize)]);
                while let Some((current, depth)) = queue.pop_front() {
                    if depth >= max_depth {
                        continue;
                    }
                    for next in self.relation_neighbors(&current, relation_kind.as_ref()) {
                        if visited.insert(next.clone()) {
                            output.push(next.clone());
                            queue.push_back((next, depth + 1));
                        }
                    }
                }
            }
            GraphTraversal::DepthFirst => {
                let mut stack = vec![(start.clone(), 0usize)];
                while let Some((current, depth)) = stack.pop() {
                    if depth >= max_depth {
                        continue;
                    }
                    let mut neighbors = self.relation_neighbors(&current, relation_kind.as_ref());
                    neighbors.reverse();
                    for next in neighbors {
                        if visited.insert(next.clone()) {
                            output.push(next.clone());
                            stack.push((next, depth + 1));
                        }
                    }
                }
            }
        }

        output
    }

    /// Find the shortest outgoing relation path between two entities.
    pub fn shortest_relation_path(
        &self,
        start: &EntityId,
        target: &EntityId,
        relation_kind: Option<RelationKind>,
    ) -> Option<Vec<EntityId>> {
        if start == target {
            return Some(vec![start.clone()]);
        }

        let mut visited = HashSet::from([start.clone()]);
        let mut queue = VecDeque::from([(start.clone(), vec![start.clone()])]);

        while let Some((current, path)) = queue.pop_front() {
            for next in self.relation_neighbors(&current, relation_kind.as_ref()) {
                if !visited.insert(next.clone()) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(next.clone());
                if &next == target {
                    return Some(next_path);
                }
                queue.push_back((next, next_path));
            }
        }

        None
    }

    /// Detect whether the directed relation graph contains a cycle.
    pub fn relation_graph_has_cycle(&self, relation_kind: Option<RelationKind>) -> bool {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();

        for entity in self.state.entities.values() {
            if self.relation_cycle_visit(
                &entity.id,
                relation_kind.as_ref(),
                &mut visiting,
                &mut visited,
            ) {
                return true;
            }
        }

        false
    }

    /// Reconstruct version history for an entity from processed state events.
    pub fn entity_versions(&self, entity_id: &EntityId) -> Vec<EntityVersion> {
        let mut versions = Vec::new();
        let mut title = None;
        let mut content = None;
        let mut fields = BTreeMap::new();
        let mut state = None;
        let mut version = None;

        for event in &self.state.state_events {
            if event.content.get("id").and_then(Value::as_str) != Some(entity_id.as_str()) {
                continue;
            }

            match event.kind.as_str() {
                OP_ENTITY_CREATE => {
                    version = Some(0);
                    title = event.content.get("title").and_then(Value::as_str).map(str::to_owned);
                    content = event.content.get("content").cloned();
                    fields = event
                        .content
                        .get("fields")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or_default();
                    state = Some(ObjectState::Active);
                }
                OP_ENTITY_UPDATE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    if let Some(next_title) = event.content.get("title").and_then(Value::as_str) {
                        title = Some(next_title.to_owned());
                    }
                    if let Some(next_content) = event.content.get("content") {
                        content = Some(next_content.clone());
                    }
                    if let Some(next_fields) = event
                        .content
                        .get("fields")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                    {
                        fields = next_fields;
                    }
                    if let Some(next_state) = event.content.get("state").and_then(Value::as_str) {
                        state = parse_object_state(next_state);
                    }
                }
                OP_ENTITY_DELETE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    state = Some(ObjectState::Deleted);
                }
                OP_ENTITY_REDACT => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    content = None;
                    state = Some(ObjectState::Redacted);
                }
                _ => continue,
            }

            versions.push(EntityVersion {
                entity_id: entity_id.clone(),
                version: version.expect("version set by entity event"),
                event_id: event.event_id.clone(),
                updated_at: event.created_at,
                title: title.clone(),
                content: content.clone(),
                fields: fields.clone(),
                state: state.clone(),
            });
        }

        versions
    }

    /// Compare two historical versions of an entity.
    pub fn compare_entity_versions(
        &self,
        entity_id: &EntityId,
        from_version: u64,
        to_version: u64,
    ) -> Option<EntityVersionDiff> {
        let versions = self.entity_versions(entity_id);
        let from = versions.iter().find(|version| version.version == from_version)?;
        let to = versions.iter().find(|version| version.version == to_version)?;

        let from_keys: HashSet<_> = from.fields.keys().cloned().collect();
        let to_keys: HashSet<_> = to.fields.keys().cloned().collect();
        let mut added_fields: Vec<_> = to_keys.difference(&from_keys).cloned().collect();
        let mut removed_fields: Vec<_> = from_keys.difference(&to_keys).cloned().collect();
        let mut changed_fields: Vec<_> = from_keys
            .intersection(&to_keys)
            .filter(|key| from.fields.get(*key) != to.fields.get(*key))
            .cloned()
            .collect();
        added_fields.sort();
        removed_fields.sort();
        changed_fields.sort();

        Some(EntityVersionDiff {
            title_changed: from.title != to.title,
            content_changed: from.content != to.content,
            added_fields,
            removed_fields,
            changed_fields,
        })
    }

    /// Create an update operation that rolls an entity back to a previous version.
    pub fn rollback_entity_operation(
        &self,
        entity_id: EntityId,
        target_version: u64,
    ) -> Result<Operation> {
        let version = self
            .entity_versions(&entity_id)
            .into_iter()
            .find(|version| version.version == target_version)
            .ok_or_else(|| crate::Error::Protocol("entity version not found".to_owned()))?;
        let mut operation = self.update_entity_operation(
            entity_id,
            version.title,
            version.content,
            Some(version.fields),
        )?;
        operation.payload["rollback_to_version"] = json!(target_version);
        Ok(operation)
    }

    /// Create entity operations in batch.
    pub fn batch_create_entity_operations(
        &self,
        items: Vec<BatchCreateEntity>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.create_entity_operation(
                    item.entity_type,
                    item.title,
                    item.content,
                    item.fields,
                )
            })
            .collect()
    }

    /// Create entity update operations in batch.
    pub fn batch_update_entity_operations(
        &self,
        items: Vec<BatchUpdateEntity>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.update_entity_operation(item.entity_id, item.title, item.content, item.fields)
            })
            .collect()
    }

    /// Create entity delete operations in batch.
    pub fn batch_delete_entity_operations(
        &self,
        entity_ids: Vec<EntityId>,
    ) -> Result<Vec<Operation>> {
        entity_ids.into_iter().map(|entity_id| self.delete_entity_operation(entity_id)).collect()
    }

    fn relation_neighbors(
        &self,
        entity_id: &EntityId,
        relation_kind: Option<&RelationKind>,
    ) -> Vec<EntityId> {
        self.state
            .relations
            .values()
            .filter(|relation| relation_is_active(relation))
            .filter(|relation| {
                relation_kind.map(|kind| &relation.relation_kind == kind).unwrap_or(true)
            })
            .filter(|relation| relation.from_entity_id.as_ref() == Some(entity_id))
            .filter_map(|relation| relation.to_entity_id.clone())
            .collect()
    }

    fn relation_cycle_visit(
        &self,
        entity_id: &EntityId,
        relation_kind: Option<&RelationKind>,
        visiting: &mut HashSet<EntityId>,
        visited: &mut HashSet<EntityId>,
    ) -> bool {
        if visited.contains(entity_id) {
            return false;
        }
        if !visiting.insert(entity_id.clone()) {
            return true;
        }

        for next in self.relation_neighbors(entity_id, relation_kind) {
            if self.relation_cycle_visit(&next, relation_kind, visiting, visited) {
                return true;
            }
        }

        visiting.remove(entity_id);
        visited.insert(entity_id.clone());
        false
    }
}

/// Space membership operations.
impl Space {
    /// Create a join operation and update local membership state to joined.
    pub fn join_space(&self) -> Result<Operation> {
        let operation = self.create_join_operation()?;
        self.base_client.update_space_state(&self.space_id, SpaceStateType::Joined)?;
        Ok(operation)
    }

    /// Create a leave operation and update local membership state to left.
    pub fn leave_space(&self) -> Result<Operation> {
        let operation = self.create_leave_operation()?;
        self.base_client.update_space_state(&self.space_id, SpaceStateType::Left)?;
        Ok(operation)
    }

    /// Create an invite operation.
    pub fn invite(&self, user_id: Did, role: Option<String>) -> Result<Operation> {
        self.create_invite_operation(user_id, role)
    }

    /// Create an invite operation for a user to join this space.
    pub fn create_invite_operation(&self, user_id: Did, role: Option<String>) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "target_did": user_id,
            "role": role,
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "invite", payload))
    }

    /// Create a join operation for the current user to join this space.
    pub fn create_join_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "join", payload))
    }

    /// Create a leave operation for the current user to leave this space.
    pub fn create_leave_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "leave", payload))
    }

    /// Create a ban operation for a user in this space.
    pub fn ban(&self, user_id: Did, reason: Option<String>) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "target_did": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "ban", payload))
    }

    /// Create an unban operation for a user in this space.
    pub fn unban(&self, user_id: Did) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "target_did": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "unban", payload))
    }
}

/// Optional flow metadata accepted by [`Space::create_flow_operation_with_metadata`].
///
/// All fields default to "unset" so callers can struct-update the variant
/// they need without naming the rest:
///
/// ```ignore
/// space.create_flow_operation_with_metadata(
///     "Refactor",
///     FlowKind::Discussion,
///     None,
///     None,
///     fields,
///     FlowCreateMetadata { semantic_kind: Some("work_item".into()), ..Default::default() },
/// )?;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowCreateMetadata {
    pub primary_track: Option<String>,
    pub tracks: Vec<String>,
    pub semantic_kind: Option<String>,
}

/// Optional flow metadata accepted by [`Space::update_flow_operation_with_metadata`].
///
/// Identical shape to [`FlowCreateMetadata`] but `tracks` is `Option`:
/// `None` means "leave unchanged", `Some(vec![])` means "clear tracks".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowUpdateMetadata {
    pub primary_track: Option<String>,
    pub tracks: Option<Vec<String>>,
    pub semantic_kind: Option<String>,
}

/// Flow operations within a space.
impl Space {
    /// Create a flow creation operation.
    pub fn create_flow_operation(
        &self,
        title: impl Into<String>,
        flow_kind: FlowKind,
        brief: Option<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_flow_operation_with_metadata(
            title,
            flow_kind,
            brief,
            summary,
            fields,
            FlowCreateMetadata::default(),
        )
    }

    /// Create a flow creation operation with flow metadata.
    pub fn create_flow_operation_with_metadata(
        &self,
        title: impl Into<String>,
        flow_kind: FlowKind,
        brief: Option<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
        metadata: FlowCreateMetadata,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let flow_id = FlowId::new(generate_id("cx:flow:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "flow_id": flow_id.as_str(),
            "title": title.into(),
            "flow_kind": serde_json::to_value(flow_kind)?,
        });

        if let Some(brief) = brief {
            payload["brief"] = json!(brief);
        }
        if let Some(summary) = summary {
            payload["summary"] = json!(summary);
        }
        if let Some(primary_track) = metadata.primary_track {
            payload["primary_track"] = json!(primary_track);
        }
        if !metadata.tracks.is_empty() {
            payload["tracks"] = json!(metadata.tracks);
        }
        if let Some(semantic_kind) = metadata.semantic_kind {
            payload["semantic_kind"] = json!(semantic_kind);
        }
        if !fields.is_empty() {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "flow", payload))
    }

    /// Create a flow update operation.
    pub fn update_flow_operation(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        brief: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_flow_operation_with_metadata(
            flow_id,
            title,
            brief,
            summary,
            fields,
            FlowUpdateMetadata::default(),
        )
    }

    /// Create a flow update operation with extended metadata.
    pub fn update_flow_operation_with_metadata(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        brief: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
        metadata: FlowUpdateMetadata,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({ "flow_id": flow_id.as_str() });

        if let Some(title) = title {
            payload["title"] = json!(title);
        }
        if let Some(brief) = brief {
            payload["brief"] = json!(brief);
        }
        if let Some(summary) = summary {
            payload["summary"] = json!(summary);
        }
        if let Some(primary_track) = metadata.primary_track {
            payload["primary_track"] = json!(primary_track);
        }
        if let Some(tracks) = metadata.tracks {
            payload["tracks"] = json!(tracks);
        }
        if let Some(semantic_kind) = metadata.semantic_kind {
            payload["semantic_kind"] = json!(semantic_kind);
        }
        if let Some(fields) = fields {
            payload["fields"] = json!(fields);
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a flow archive operation.
    pub fn archive_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, OperationType::Delete, "archived")
    }

    /// Create a flow restore operation.
    pub fn restore_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, OperationType::Update, "active")
    }

    fn flow_lifecycle_operation(
        &self,
        flow_id: FlowId,
        operation_type: OperationType,
        state: &str,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.space_id.clone(),
            "flow",
            json!({
                "flow_id": flow_id.as_str(),
                "state": state,
            }),
        );
        operation.operation_type = operation_type;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create an operation linking a flow to a surface object.
    pub fn link_flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: impl Into<String>,
        surface_role: Option<String>,
        primary: bool,
    ) -> Result<Operation> {
        self.flow_surface_operation(
            flow_id,
            surface_ref.into(),
            surface_role,
            primary,
            OperationType::Link,
        )
    }

    /// Create an operation unlinking a flow surface object.
    pub fn unlink_flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: impl Into<String>,
        surface_role: Option<String>,
    ) -> Result<Operation> {
        self.flow_surface_operation(
            flow_id,
            surface_ref.into(),
            surface_role,
            false,
            OperationType::Unlink,
        )
    }

    fn flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: String,
        surface_role: Option<String>,
        primary: bool,
        operation_type: OperationType,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "flow_id": flow_id.as_str(),
            "surface_ref": surface_ref,
        });
        if let Some(surface_role) = surface_role {
            payload["surface_role"] = json!(surface_role);
        }
        if operation_type == OperationType::Link {
            payload["primary"] = json!(primary);
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = operation_type;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a flow move operation.
    pub fn move_flow_operation(
        &self,
        flow_id: FlowId,
        parent_id: FlowId,
        rank: i64,
    ) -> Result<Operation> {
        self.flow_mutation_operation(
            flow_id,
            json!({
                "parent_id": parent_id,
                "rank": rank,
            }),
        )
    }

    /// Create a flow reorder operation.
    pub fn reorder_flow_operation(&self, flow_id: FlowId, rank: i64) -> Result<Operation> {
        self.flow_mutation_operation(flow_id, json!({ "rank": rank }))
    }

    /// Create a flow convert operation.
    pub fn convert_flow_operation(
        &self,
        flow_id: FlowId,
        target_kind: String,
    ) -> Result<Operation> {
        self.flow_mutation_operation(flow_id, json!({ "target_kind": target_kind }))
    }

    fn flow_mutation_operation(
        &self,
        flow_id: FlowId,
        additional_payload: Value,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({ "flow_id": flow_id.as_str() });
        if let Value::Object(map) = additional_payload {
            for (key, value) in map {
                payload[key] = value;
            }
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }
}

/// Legacy subject compatibility operations within a space.
/// Entity operations within a space.
impl Space {
    /// Create an entity creation operation.
    pub fn create_entity_operation(
        &self,
        entity_type: EntityType,
        title: Option<String>,
        content: Option<Value>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let entity_id = EntityId::new(generate_id("cx:entity:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": entity_id.as_str(),
            "entity_type": serde_json::to_value(entity_type)?,
        });

        if let Some(title) = &title {
            payload["title"] = json!(title);
        }
        if let Some(content) = &content {
            payload["content"] = content.clone();
        }
        if !fields.is_empty() {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.create", payload))
    }

    /// Create an entity update operation.
    pub fn update_entity_operation(
        &self,
        entity_id: EntityId,
        title: Option<String>,
        content: Option<Value>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": entity_id.as_str(),
        });

        if let Some(title) = &title {
            payload["title"] = json!(title);
        }
        if let Some(content) = &content {
            payload["content"] = content.clone();
        }
        if let Some(fields) = &fields {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.update", payload))
    }

    /// Create an entity delete operation.
    pub fn delete_entity_operation(&self, entity_id: EntityId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "id": entity_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.delete", payload))
    }
}

/// Input for creating a relation operation.
#[derive(Clone, Debug)]
pub struct RelationOperationInput {
    pub relation_kind: RelationKind,
    pub from_ref: Option<String>,
    pub to_ref: Option<String>,
    pub from_entity_id: Option<EntityId>,
    pub from_actor_id: Option<Did>,
    pub from_space_id: Option<SpaceId>,
    pub to_entity_id: Option<EntityId>,
    pub to_actor_id: Option<Did>,
    pub to_space_id: Option<SpaceId>,
    pub fields: BTreeMap<String, Value>,
}

impl RelationOperationInput {
    pub fn new(relation_kind: RelationKind) -> Self {
        Self {
            relation_kind,
            from_ref: None,
            to_ref: None,
            from_entity_id: None,
            from_actor_id: None,
            from_space_id: None,
            to_entity_id: None,
            to_actor_id: None,
            to_space_id: None,
            fields: BTreeMap::new(),
        }
    }
}

/// Relation operations within a space.
impl Space {
    /// Create a relation creation operation.
    pub fn create_relation_operation(&self, input: RelationOperationInput) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let relation_id = RelationId::new(generate_id("cx:relation:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": relation_id.as_str(),
            "relation_kind": serde_json::to_value(input.relation_kind)?,
        });

        if let Some(from_entity_id) = &input.from_entity_id {
            payload["from_entity_id"] = json!(from_entity_id.as_str());
        }
        if let Some(from_ref) = &input.from_ref {
            payload["from_ref"] = json!(from_ref);
        }
        if let Some(from_actor_id) = &input.from_actor_id {
            payload["from_actor_id"] = json!(from_actor_id.as_str());
        }
        if let Some(from_space_id) = &input.from_space_id {
            payload["from_space_id"] = json!(from_space_id.as_str());
        }
        if let Some(to_entity_id) = &input.to_entity_id {
            payload["to_entity_id"] = json!(to_entity_id.as_str());
        }
        if let Some(to_ref) = &input.to_ref {
            payload["to_ref"] = json!(to_ref);
        }
        if let Some(to_actor_id) = &input.to_actor_id {
            payload["to_actor_id"] = json!(to_actor_id.as_str());
        }
        if let Some(to_space_id) = &input.to_space_id {
            payload["to_space_id"] = json!(to_space_id.as_str());
        }
        if !input.fields.is_empty() {
            payload["fields"] = json!(input.fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "relation.create", payload))
    }

    /// Create a relation delete operation.
    pub fn delete_relation_operation(&self, relation_id: RelationId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "id": relation_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "relation.delete", payload))
    }
}

fn entity_matches_filter(entity: &Entity, filter: &Filter) -> bool {
    match filter {
        Filter::Predicate(predicate) => entity_matches_predicate(entity, predicate),
        Filter::And { and } => and.iter().all(|filter| entity_matches_filter(entity, filter)),
        Filter::Or { or } => or.iter().any(|filter| entity_matches_filter(entity, filter)),
        Filter::Not { not } => !entity_matches_filter(entity, not),
    }
}

fn entity_matches_predicate(entity: &Entity, predicate: &FieldFilter) -> bool {
    let actual = entity_field_value(entity, &predicate.field);
    match &predicate.op {
        FilterOp::Exists => {
            let expected = predicate.value.as_ref().and_then(Value::as_bool).unwrap_or(true);
            actual.is_some() == expected
        }
        FilterOp::Eq => actual.as_ref() == predicate.value.as_ref(),
        FilterOp::Neq => actual.as_ref() != predicate.value.as_ref(),
        FilterOp::In => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(actual), Some(Value::Array(values))) => values.contains(actual),
            _ => false,
        },
        FilterOp::NotIn => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(actual), Some(Value::Array(values))) => !values.contains(actual),
            _ => false,
        },
        FilterOp::Lt | FilterOp::Lte | FilterOp::Gt | FilterOp::Gte => {
            let Some(ordering) = actual
                .as_ref()
                .zip(predicate.value.as_ref())
                .and_then(|(left, right)| compare_json_values(left, right))
            else {
                return false;
            };
            match &predicate.op {
                FilterOp::Lt => ordering == Ordering::Less,
                FilterOp::Lte => matches!(ordering, Ordering::Less | Ordering::Equal),
                FilterOp::Gt => ordering == Ordering::Greater,
                FilterOp::Gte => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => false,
            }
        }
        FilterOp::Contains => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(Value::String(actual)), Some(Value::String(needle))) => actual.contains(needle),
            (Some(Value::Array(values)), Some(needle)) => values.contains(needle),
            (Some(Value::Object(values)), Some(Value::String(key))) => values.contains_key(key),
            _ => false,
        },
        FilterOp::Prefix => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(Value::String(actual)), Some(Value::String(prefix))) => {
                actual.starts_with(prefix)
            }
            _ => false,
        },
        FilterOp::FullText => match predicate.value.as_ref().and_then(Value::as_str) {
            Some(needle) => value_search_text(actual.as_ref()).contains(&needle.to_lowercase()),
            None => false,
        },
    }
}

fn compare_entities(left: &Entity, right: &Entity, order_by: &[SortSpec]) -> Ordering {
    for sort in order_by {
        let ordering = compare_optional_values(
            entity_field_value(left, &sort.field).as_ref(),
            entity_field_value(right, &sort.field).as_ref(),
            sort.nulls.as_ref(),
            &sort.direction,
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    left.id.cmp(&right.id)
}

fn compare_optional_values(
    left: Option<&Value>,
    right: Option<&Value>,
    nulls: Option<&NullsOrder>,
    direction: &SortDirection,
) -> Ordering {
    let null_ordering = |left_is_null: bool| match nulls.unwrap_or(&NullsOrder::Last) {
        NullsOrder::First if left_is_null => Ordering::Less,
        NullsOrder::First => Ordering::Greater,
        NullsOrder::Last if left_is_null => Ordering::Greater,
        NullsOrder::Last => Ordering::Less,
    };

    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => null_ordering(true),
        (Some(_), None) => null_ordering(false),
        (Some(left), Some(right)) => {
            let ordering = compare_json_values(left, right).unwrap_or(Ordering::Equal);
            match direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        }
    }
}

fn compare_json_values(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64()?.partial_cmp(&right.as_f64()?),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Some(left.cmp(right)),
        _ => Some(scalar_value_key(left).cmp(&scalar_value_key(right))),
    }
}

fn entity_field_value(entity: &Entity, field: &str) -> Option<Value> {
    match field {
        "id" => Some(json!(entity.id.as_str())),
        "title" => entity.title.as_ref().map(|title| json!(title)),
        "entity_type" => serde_json::to_value(&entity.entity_type).ok(),
        "state" => entity.state.as_ref().and_then(|state| serde_json::to_value(state).ok()),
        "version" => entity.version.map(|version| json!(version)),
        "created_at" => Some(json!(entity.created_at.to_rfc3339())),
        "updated_at" => entity.updated_at.map(|updated_at| json!(updated_at.to_rfc3339())),
        "content" => entity.content.clone(),
        "labels" => Some(json!(entity.labels)),
        _ if field.starts_with("fields.") => entity.fields.get(&field["fields.".len()..]).cloned(),
        _ if field.starts_with("content.") => entity
            .content
            .as_ref()
            .and_then(|content| value_at_path(content, &field["content.".len()..])),
        _ => entity.fields.get(field).cloned(),
    }
}

fn value_at_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current.clone())
}

fn entity_search_text(entity: &Entity) -> String {
    let mut text = String::new();
    if let Some(title) = &entity.title {
        text.push_str(title);
        text.push(' ');
    }
    if let Some(content) = &entity.content {
        text.push_str(&value_search_text(Some(content)));
        text.push(' ');
    }
    text.push_str(&value_search_text(Some(&json!(entity.fields))));
    text.to_lowercase()
}

fn value_search_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Null) | None => String::new(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::String(value)) => value.to_lowercase(),
        Some(Value::Array(values)) => {
            values.iter().map(|value| value_search_text(Some(value))).collect::<Vec<_>>().join(" ")
        }
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                format!("{} {}", key.to_lowercase(), value_search_text(Some(value)))
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn entity_type_key(entity_type: &EntityType) -> String {
    serde_json::to_value(entity_type)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn scalar_value_key(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "unknown".to_owned()),
    }
}

fn relation_is_active(relation: &Relation) -> bool {
    !matches!(relation.state, Some(RelationState::Deleted | RelationState::Redacted))
}

fn parse_object_state(value: &str) -> Option<ObjectState> {
    match value {
        "active" => Some(ObjectState::Active),
        "archived" => Some(ObjectState::Archived),
        "deleted" => Some(ObjectState::Deleted),
        "redacted" => Some(ObjectState::Redacted),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceId, Event, Hlc, OperationType,
        base::SessionMeta,
        model::{OP_ENTITY_CREATE, OP_ENTITY_UPDATE, OP_RELATION_CREATE},
    };

    fn sessioned_base() -> Arc<BaseClient> {
        let base_client = Arc::new(BaseClient::new());
        let meta = SessionMeta::new(
            Did::new("did:web:alice.example.com").unwrap(),
            DeviceId::new("dev_123").unwrap(),
        );
        base_client.set_session_meta(meta).unwrap();
        base_client
    }

    fn event(kind: &str, seq: u64, space_id: &SpaceId, content: Value) -> Event {
        Event {
            event_id: EventId::new(format!("cx:event:{seq:026}")).unwrap(),
            kind: kind.to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:alice.example.com").unwrap(),
            actor_seq: seq,
            created_at: Utc::now(),
            hlc: Hlc::new(format!("01970e589d21-{seq:08x}-a13f9c2e")).unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content,
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    #[test]
    fn space_checks_membership() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();

        base_client.update_space_state(&space_id, SpaceStateType::Joined).unwrap();

        let space = Space::new(space_id, base_client);
        assert!(space.is_joined());
        assert!(!space.is_invited());
        assert!(!space.is_left());
    }

    #[test]
    fn space_creates_entity_operation() {
        let base_client = Arc::new(BaseClient::new());
        let meta = SessionMeta::new(
            Did::new("did:web:alice.example.com").unwrap(),
            DeviceId::new("dev_123").unwrap(),
        );
        base_client.set_session_meta(meta).unwrap();

        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space = Space::new(space_id.clone(), base_client);

        let op = space
            .create_entity_operation(
                EntityType::Task,
                Some("Test task".to_owned()),
                None,
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(op.operation_type, OperationType::Create);
        assert_eq!(op.space_id, space_id);
        assert!(op.payload["id"].is_string());
    }

    #[test]
    fn space_creates_relation_operation() {
        let base_client = Arc::new(BaseClient::new());
        let meta = SessionMeta::new(
            Did::new("did:web:alice.example.com").unwrap(),
            DeviceId::new("dev_123").unwrap(),
        );
        base_client.set_session_meta(meta).unwrap();

        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space = Space::new(space_id.clone(), base_client);

        let mut input = RelationOperationInput::new(RelationKind::DependsOn);
        input.from_entity_id = Some(EntityId::new("cx:entity:01JS0EN000000000000000001").unwrap());
        input.to_entity_id = Some(EntityId::new("cx:entity:01JS0EN000000000000000002").unwrap());
        let op = space.create_relation_operation(input).unwrap();

        assert_eq!(op.operation_type, OperationType::Create);
        assert_eq!(op.space_id, space_id);
        assert!(op.payload["id"].is_string());
    }

    #[test]
    fn space_creates_flow_operations_and_reads_surfaces() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space = Space::new(space_id.clone(), base_client.clone());

        let create = space
            .create_flow_operation(
                "Payment refactor",
                FlowKind::Initiative,
                Some("Unify payment flows".to_owned()),
                None,
                BTreeMap::new(),
            )
            .unwrap();
        let flow_id = FlowId::new(create.payload["flow_id"].as_str().unwrap()).unwrap();
        assert_eq!(create.operation_type, OperationType::Create);
        assert_eq!(create.object_type, "flow");
        assert_eq!(create.payload["flow_kind"], "initiative");

        let link = space
            .link_flow_surface_operation(
                flow_id.clone(),
                "cx:flow:01JS0CD000000000000000000",
                Some("status_card".to_owned()),
                true,
            )
            .unwrap();
        assert_eq!(link.operation_type, OperationType::Link);
        assert_eq!(link.object_id.as_deref(), Some(flow_id.as_str()));
        assert_eq!(link.payload["surface_role"], "status_card");

        base_client
            .process_events(
                &space_id,
                vec![
                    event(
                        "cx.flow.create",
                        1,
                        &space_id,
                        json!({
                            "flow_id": flow_id.as_str(),
                            "title": "Payment refactor",
                            "flow_kind": "initiative"
                        }),
                    ),
                    event(
                        "cx.flow.link_surface",
                        2,
                        &space_id,
                        json!({
                            "flow_id": flow_id.as_str(),
                            "surface_ref": "cx:flow:01JS0CD000000000000000000",
                            "surface_role": "status_card",
                            "primary": true,
                            "relation_id": "cx:relation:01JS0SR000000000000000000"
                        }),
                    ),
                ],
            )
            .unwrap();

        let refreshed = Space::new(space_id, base_client);
        assert_eq!(refreshed.find_flows_by_kind(FlowKind::Initiative).len(), 1);
        assert_eq!(refreshed.flow_surfaces(&flow_id).len(), 1);
    }

    #[test]
    fn space_queries_searches_and_aggregates_entities() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let task_id = EntityId::new("cx:entity:01JS0EN000000000000000001").unwrap();
        let doc_id = EntityId::new("cx:entity:01JS0EN000000000000000002").unwrap();
        base_client
            .process_events(
                &space_id,
                vec![
                    event(
                        OP_ENTITY_CREATE,
                        1,
                        &space_id,
                        json!({
                            "id": task_id.as_str(),
                            "entity_type": "task",
                            "title": "Alpha task",
                            "content": {"body": "implement local search"},
                            "fields": {"status": "todo", "priority": 2}
                        }),
                    ),
                    event(
                        OP_ENTITY_CREATE,
                        2,
                        &space_id,
                        json!({
                            "id": doc_id.as_str(),
                            "entity_type": "document",
                            "title": "Spec",
                            "fields": {"status": "done", "priority": 1}
                        }),
                    ),
                ],
            )
            .unwrap();
        let space = Space::new(space_id, base_client);

        let results = space.query_entities(EntityQuery {
            entity_types: vec![EntityType::Task],
            filters: vec![Filter::Predicate(FieldFilter {
                field: "fields.status".to_owned(),
                op: FilterOp::Eq,
                value: Some(json!("todo")),
            })],
            order_by: vec![SortSpec {
                field: "fields.priority".to_owned(),
                direction: SortDirection::Desc,
                nulls: None,
            }],
            limit: Some(10),
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, task_id);

        assert_eq!(space.search_entities("LOCAL SEARCH").len(), 1);

        let aggregation = space.aggregate_entities(&["fields.status"]);
        assert_eq!(aggregation.total, 2);
        assert_eq!(aggregation.by_type["task"], 1);
        assert_eq!(aggregation.by_field["fields.status"]["todo"], 1);
    }

    #[test]
    fn space_traverses_relation_graph_paths_and_cycles() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let a = EntityId::new("cx:entity:01JS0EN000000000000000011").unwrap();
        let b = EntityId::new("cx:entity:01JS0EN000000000000000012").unwrap();
        let c = EntityId::new("cx:entity:01JS0EN000000000000000013").unwrap();
        base_client
            .process_events(
                &space_id,
                vec![
                    event(
                        OP_ENTITY_CREATE,
                        1,
                        &space_id,
                        json!({"id": a.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        OP_ENTITY_CREATE,
                        2,
                        &space_id,
                        json!({"id": b.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        OP_ENTITY_CREATE,
                        3,
                        &space_id,
                        json!({"id": c.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        OP_RELATION_CREATE,
                        4,
                        &space_id,
                        json!({
                            "id": "cx:relation:01",
                            "relation_kind": "depends_on",
                            "from_entity_id": a.as_str(),
                            "to_entity_id": b.as_str()
                        }),
                    ),
                    event(
                        OP_RELATION_CREATE,
                        5,
                        &space_id,
                        json!({
                            "id": "cx:relation:02",
                            "relation_kind": "depends_on",
                            "from_entity_id": b.as_str(),
                            "to_entity_id": c.as_str()
                        }),
                    ),
                    event(
                        OP_RELATION_CREATE,
                        6,
                        &space_id,
                        json!({
                            "id": "cx:relation:03",
                            "relation_kind": "depends_on",
                            "from_entity_id": c.as_str(),
                            "to_entity_id": a.as_str()
                        }),
                    ),
                ],
            )
            .unwrap();
        let space = Space::new(space_id, base_client);

        assert_eq!(
            space.traverse_relations(
                &a,
                Some(RelationKind::DependsOn),
                GraphTraversal::BreadthFirst,
                Some(2),
            ),
            vec![b.clone(), c.clone()]
        );
        assert_eq!(
            space.shortest_relation_path(&a, &c, Some(RelationKind::DependsOn)).unwrap(),
            vec![a.clone(), b, c]
        );
        assert!(space.relation_graph_has_cycle(Some(RelationKind::DependsOn)));
    }

    #[test]
    fn space_tracks_entity_versions_compares_and_rolls_back() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let entity_id = EntityId::new("cx:entity:01JS0EN000000000000000021").unwrap();
        base_client
            .process_events(
                &space_id,
                vec![
                    event(
                        OP_ENTITY_CREATE,
                        1,
                        &space_id,
                        json!({
                            "id": entity_id.as_str(),
                            "entity_type": "task",
                            "title": "Initial",
                            "fields": {"status": "todo"}
                        }),
                    ),
                    event(
                        OP_ENTITY_UPDATE,
                        2,
                        &space_id,
                        json!({
                            "id": entity_id.as_str(),
                            "title": "Updated",
                            "fields": {"status": "done", "owner": "alice"}
                        }),
                    ),
                ],
            )
            .unwrap();
        let space = Space::new(space_id, base_client);

        let versions = space.entity_versions(&entity_id);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 0);
        assert_eq!(versions[1].version, 1);

        let diff = space.compare_entity_versions(&entity_id, 0, 1).unwrap();
        assert!(diff.title_changed);
        assert_eq!(diff.added_fields, vec!["owner".to_owned()]);
        assert_eq!(diff.changed_fields, vec!["status".to_owned()]);

        let rollback = space.rollback_entity_operation(entity_id, 0).unwrap();
        assert_eq!(rollback.payload["title"], "Initial");
        assert_eq!(rollback.payload["rollback_to_version"], 0);
    }

    #[test]
    fn space_creates_batch_entity_operations() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space = Space::new(space_id, base_client);

        let creates = space
            .batch_create_entity_operations(vec![
                BatchCreateEntity {
                    entity_type: EntityType::Task,
                    title: Some("A".to_owned()),
                    content: None,
                    fields: BTreeMap::new(),
                },
                BatchCreateEntity {
                    entity_type: EntityType::Document,
                    title: Some("B".to_owned()),
                    content: None,
                    fields: BTreeMap::new(),
                },
            ])
            .unwrap();
        assert_eq!(creates.len(), 2);

        let updates = space
            .batch_update_entity_operations(vec![BatchUpdateEntity {
                entity_id: EntityId::new("cx:entity:01JS0EN000000000000000031").unwrap(),
                title: Some("Updated".to_owned()),
                content: None,
                fields: None,
            }])
            .unwrap();
        assert_eq!(updates.len(), 1);

        let deletes = space
            .batch_delete_entity_operations(vec![
                EntityId::new("cx:entity:01JS0EN000000000000000031").unwrap(),
            ])
            .unwrap();
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn space_provides_message_membership_and_media_convenience_helpers() {
        let base_client = sessioned_base();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space = Space::new(space_id.clone(), base_client.clone());
        let bob = Did::new("did:web:bob.example.com").unwrap();

        let text = space.send_text("hello").unwrap();
        assert_eq!(text.object_type, "entity.create");
        assert_eq!(text.payload["entity_type"], "message");
        assert_eq!(text.payload["content"]["body"], "hello");

        let message_id = EntityId::new(text.payload["id"].as_str().unwrap()).unwrap();
        let edit = space.edit_message(message_id.clone(), json!({"body": "updated"})).unwrap();
        assert_eq!(edit.object_type, "message.edit");
        assert_eq!(edit.object_id, Some(message_id.as_str().to_owned()));

        let redact = space.redact_message(message_id, Some("cleanup".to_owned())).unwrap();
        assert_eq!(redact.operation_type, OperationType::Redact);

        let join = space.join_space().unwrap();
        assert_eq!(join.object_type, "join");
        assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Joined);

        let leave = space.leave_space().unwrap();
        assert_eq!(leave.object_type, "leave");
        assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Left);

        assert_eq!(
            space.invite(bob.clone(), Some("member".to_owned())).unwrap().object_type,
            "invite"
        );
        assert_eq!(space.ban(bob.clone(), Some("spam".to_owned())).unwrap().object_type, "ban");
        assert_eq!(space.unban(bob).unwrap().object_type, "unban");

        let media =
            space.upload_media(b"bytes", "text/plain", Some("note.txt".to_owned())).unwrap();
        assert_eq!(space.download_media(&media.blob_ref).unwrap(), b"bytes");

        space
            .upload_encrypted_attachment("att1", "secret.txt", "text/plain", b"secret", b"key")
            .unwrap();
        assert_eq!(space.download_decrypted_attachment("att1", b"key").unwrap(), b"secret");
    }
}
