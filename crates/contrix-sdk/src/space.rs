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
use ulid::Ulid;

use crate::{
    Result,
    base::{BaseClient, SpaceStateType},
    model::{
        Did, Entity, EntityId, EntityType, EventId, FieldFilter, Filter, FilterOp, NullsOrder,
        ObjectState, Operation, OperationId, Relation, RelationId, RelationKind, RelationState,
        SortDirection, SortSpec, SpaceId,
    },
    resolver::SpaceState,
};

/// Generate a new ULID-based ID with the given prefix.
fn generate_id(prefix: &str) -> String {
    let ulid = Ulid::new();
    format!("{}{}", prefix, ulid.to_string())
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
                "cx.entity.create" => {
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
                "cx.entity.update" => {
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
                "cx.entity.delete" => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    state = Some(ObjectState::Deleted);
                }
                "cx.entity.redact" => {
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
}

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

/// Relation operations within a space.
impl Space {
    /// Create a relation creation operation.
    pub fn create_relation_operation(
        &self,
        relation_kind: RelationKind,
        from_entity_id: Option<EntityId>,
        from_actor_id: Option<Did>,
        from_space_id: Option<SpaceId>,
        to_entity_id: Option<EntityId>,
        to_actor_id: Option<Did>,
        to_space_id: Option<SpaceId>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let relation_id = RelationId::new(generate_id("cx:relation:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": relation_id.as_str(),
            "relation_kind": serde_json::to_value(relation_kind)?,
        });

        if let Some(from_entity_id) = &from_entity_id {
            payload["from_entity_id"] = json!(from_entity_id.as_str());
        }
        if let Some(from_actor_id) = &from_actor_id {
            payload["from_actor_id"] = json!(from_actor_id.as_str());
        }
        if let Some(from_space_id) = &from_space_id {
            payload["from_space_id"] = json!(from_space_id.as_str());
        }
        if let Some(to_entity_id) = &to_entity_id {
            payload["to_entity_id"] = json!(to_entity_id.as_str());
        }
        if let Some(to_actor_id) = &to_actor_id {
            payload["to_actor_id"] = json!(to_actor_id.as_str());
        }
        if let Some(to_space_id) = &to_space_id {
            payload["to_space_id"] = json!(to_space_id.as_str());
        }
        if !fields.is_empty() {
            payload["fields"] = json!(fields);
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
    use crate::{DeviceId, Event, Hlc, OperationType, base::SessionMeta};

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

        let op = space
            .create_relation_operation(
                RelationKind::DependsOn,
                Some(EntityId::new("cx:entity:01JS0EN000000000000000001").unwrap()),
                None,
                None,
                Some(EntityId::new("cx:entity:01JS0EN000000000000000002").unwrap()),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(op.operation_type, OperationType::Create);
        assert_eq!(op.space_id, space_id);
        assert!(op.payload["id"].is_string());
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
                        "cx.entity.create",
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
                        "cx.entity.create",
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
                        "cx.entity.create",
                        1,
                        &space_id,
                        json!({"id": a.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        "cx.entity.create",
                        2,
                        &space_id,
                        json!({"id": b.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        "cx.entity.create",
                        3,
                        &space_id,
                        json!({"id": c.as_str(), "entity_type": "task"}),
                    ),
                    event(
                        "cx.relation.create",
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
                        "cx.relation.create",
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
                        "cx.relation.create",
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
                        "cx.entity.create",
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
                        "cx.entity.update",
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
}
