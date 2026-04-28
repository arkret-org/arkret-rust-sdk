//! High-level space API for Contrix v1.
//!
//! This module provides a high-level interface for working with spaces,
//! including entity management, relations, timeline operations, and membership.

use std::{
    collections::BTreeMap,
    sync::Arc,
};

use serde_json::json;
use ulid::Ulid;

use crate::{
    base::{BaseClient, SpaceStateType},
    model::{
        Did, Entity, EntityId, EntityType, EventId, Operation, OperationId, OperationType,
        Relation, RelationId, RelationKind, SpaceId,
    },
    resolver::SpaceState,
    Result,
};

/// Generate a new ULID-based ID with the given prefix.
fn generate_id(prefix: &str) -> String {
    let ulid = Ulid::new();
    format!("{}{}", prefix, ulid.to_string())
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

        Self {
            space_id,
            base_client,
            state,
        }
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
        self.state
            .entities
            .values()
            .filter(|e| e.entity_type == entity_type)
            .cloned()
            .collect()
    }

    /// Find entities by field value.
    pub fn find_entities_by_field(&self, field_key: &str, field_value: &serde_json::Value) -> Vec<Entity> {
        self.state
            .entities
            .values()
            .filter(|e| {
                e.fields
                    .get(field_key)
                    .map(|v| v == field_value)
                    .unwrap_or(false)
            })
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

/// Space membership operations.
impl Space {
    /// Create an invite operation for a user to join this space.
    pub fn create_invite_operation(
        &self,
        user_id: Did,
        role: Option<String>,
    ) -> Result<Operation> {
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "invite",
            payload,
        ))
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "join",
            payload,
        ))
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "leave",
            payload,
        ))
    }
}

/// Entity operations within a space.
impl Space {
    /// Create an entity creation operation.
    pub fn create_entity_operation(
        &self,
        entity_type: EntityType,
        title: Option<String>,
        content: Option<serde_json::Value>,
        fields: BTreeMap<String, serde_json::Value>,
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "entity.create",
            payload,
        ))
    }

    /// Create an entity update operation.
    pub fn update_entity_operation(
        &self,
        entity_id: EntityId,
        title: Option<String>,
        content: Option<serde_json::Value>,
        fields: Option<BTreeMap<String, serde_json::Value>>,
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "entity.update",
            payload,
        ))
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "entity.delete",
            payload,
        ))
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
        fields: BTreeMap<String, serde_json::Value>,
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "relation.create",
            payload,
        ))
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

        Ok(Operation::create(
            operation_id,
            self.space_id.clone(),
            "relation.delete",
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, base::SessionMeta};

    #[test]
    fn space_checks_membership() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();

        base_client
            .update_space_state(&space_id, SpaceStateType::Joined)
            .unwrap();

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
}
