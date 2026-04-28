//! State resolution and event reduction.
//!
//! This module implements the Contrix v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::{canonical::sha256_digest, Did, Entity, Event, EventId, Relation, SpaceId, Result, Error, EntityId, RelationId};

/// Current state of a Space.
#[derive(Clone, Debug)]
pub struct SpaceState {
    /// Space ID
    pub space_id: SpaceId,
    /// Current space version
    pub space_version: String,
    /// Current entities by ID
    pub entities: BTreeMap<String, Entity>,
    /// Current relations by ID
    pub relations: BTreeMap<String, Relation>,
    /// Causal frontier (most recent event IDs)
    pub frontier: Vec<EventId>,
    /// Space state events
    pub state_events: Vec<Event>,
}

impl SpaceState {
    /// Create a new empty space state.
    pub fn new(space_id: SpaceId, space_version: String) -> Self {
        Self {
            space_id,
            space_version,
            entities: BTreeMap::new(),
            relations: BTreeMap::new(),
            frontier: Vec::new(),
            state_events: Vec::new(),
        }
    }

    /// Apply a sequence of events to the state.
    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        // Sort events by causal depth, then HLC, then actor_id, then event_id
        let mut sorted_events: Vec<&Event> = events.iter().collect();
        sorted_events.sort_by(|a, b| {
            // First by causal depth (length of prev_refs chain)
            let depth_a = self.causal_depth(a);
            let depth_b = self.causal_depth(b);
            match depth_a.cmp(&depth_b) {
                std::cmp::Ordering::Equal => {
                    // Then by HLC
                    match a.hlc.cmp(&b.hlc) {
                        std::cmp::Ordering::Equal => {
                            // Then by actor_id (lexicographic)
                            match a.actor_id.as_str().cmp(b.actor_id.as_str()) {
                                std::cmp::Ordering::Equal => {
                                    // Then by event_id (lexicographic)
                                    a.event_id.as_str().cmp(b.event_id.as_str())
                                }
                                other => other,
                            }
                        }
                        other => other,
                    }
                }
                other => other,
            }
        });

        // Apply events in order
        for event in sorted_events {
            self.apply_event(event)?;
        }

        Ok(())
    }

    /// Apply a single event to the state.
    fn apply_event(&mut self, event: &Event) -> Result<()> {
        // Check causal dependencies
        for prev_ref in &event.prev_refs {
            if !self.frontier.contains(prev_ref) && !self.is_processed(prev_ref) {
                return Err(Error::Protocol(format!(
                    "missing causal dependency: {}",
                    prev_ref
                )));
            }
        }

        // Check for redaction
        if let Some(redacted_ref) = &event.redacts {
            self.redact_event(redacted_ref)?;
        }

        // Process event content
        self.process_event_content(event)?;

        // Update frontier
        self.update_frontier(event);

        Ok(())
    }

    /// Process the content of an event and update state.
    fn process_event_content(&mut self, event: &Event) -> Result<()> {
        match event.kind.as_str() {
            "cx.entity.create" => self.create_entity(event)?,
            "cx.entity.update" => self.update_entity(event)?,
            "cx.entity.delete" => self.delete_entity(event)?,
            "cx.entity.redact" => self.redact_entity(event)?,
            "cx.relation.create" => self.create_relation(event)?,
            "cx.relation.delete" => self.delete_relation(event)?,
            "cx.space.upgrade" => self.upgrade_space(event)?,
            "cx.space.tombstone" => self.tombstone_space(event)?,
            _ => {
                // Unknown event type - ignore for forward compatibility
            }
        }

        Ok(())
    }

    /// Create a new entity.
    fn create_entity(&mut self, event: &Event) -> Result<()> {
        let entity_id_str = self.extract_entity_id(&event.content)?;
        let entity_id = EntityId::new(entity_id_str.clone())?;
        let entity_type = self.extract_field(&event.content, "entity_type")?;
        let title = self.extract_optional_field(&event.content, "title");
        let content = self.extract_optional_field(&event.content, "content");
        let fields = self.extract_fields(&event.content)?;

        let entity = Entity {
            schema: "cx.schema.entity.v1".to_owned(),
            id: entity_id,
            object_type: "entity".to_owned(),
            space_id: event.space_id.clone(),
            entity_type,
            title,
            content,
            fields,
            state: Some(crate::ObjectState::Active),
            version: Some(0),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };

        self.entities.insert(entity_id_str, entity);
        Ok(())
    }

    /// Update an existing entity.
    fn update_entity(&mut self, event: &Event) -> Result<()> {
        let entity_id_str = self.extract_entity_id(&event.content)?;

        // Extract all values from event content before borrowing
        let title = self.extract_optional_field::<String>(&event.content, "title");
        let content = self.extract_optional_field::<serde_json::Value>(&event.content, "content");
        let fields = self.extract_optional_field::<BTreeMap<String, serde_json::Value>>(&event.content, "fields");
        let state = self.extract_optional_field::<String>(&event.content, "state");

        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;

        let entity = self.entities.get_mut(&entity_id_str)
            .ok_or_else(|| Error::Protocol(format!("entity not found: {}", entity_id_str)))?;

        // Update fields from event content
        if let Some(title) = title {
            entity.title = Some(title);
        }
        if let Some(content) = content {
            entity.content = Some(content);
        }
        if let Some(fields) = fields {
            entity.fields = fields;
        }
        if let Some(state) = state {
            entity.state = Some(match state.as_str() {
                "active" => crate::ObjectState::Active,
                "archived" => crate::ObjectState::Archived,
                "deleted" => crate::ObjectState::Deleted,
                "redacted" => crate::ObjectState::Redacted,
                _ => return Err(Error::Protocol(format!("invalid state: {}", state))),
            });
        }

        entity.updated_by = Some(actor_id);
        entity.updated_at = Some(created_at);
        if let Some(version) = entity.version {
            entity.version = Some(version + 1);
        }

        Ok(())
    }

    /// Delete an entity.
    fn delete_entity(&mut self, event: &Event) -> Result<()> {
        let entity_id_str = self.extract_entity_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        if let Some(entity) = self.entities.get_mut(&entity_id_str) {
            entity.state = Some(crate::ObjectState::Deleted);
            entity.updated_by = Some(actor_id);
            entity.updated_at = Some(created_at);
        }
        Ok(())
    }

    /// Redact an entity.
    fn redact_entity(&mut self, event: &Event) -> Result<()> {
        let entity_id_str = self.extract_entity_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        if let Some(entity) = self.entities.get_mut(&entity_id_str) {
            entity.state = Some(crate::ObjectState::Redacted);
            entity.content = None; // Clear content
            entity.updated_by = Some(actor_id);
            entity.updated_at = Some(created_at);
        }
        Ok(())
    }

    /// Create a new relation.
    fn create_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        let relation_id = RelationId::new(relation_id_str.clone())?;
        let relation_kind = self.extract_field(&event.content, "relation_kind")?;
        let from_entity_id = self.extract_optional_field(&event.content, "from_entity_id");
        let from_actor_id = self.extract_optional_field::<Did>(&event.content, "from_actor_id");
        let from_space_id = self.extract_optional_field(&event.content, "from_space_id");
        let to_entity_id = self.extract_optional_field(&event.content, "to_entity_id");
        let to_actor_id = self.extract_optional_field::<Did>(&event.content, "to_actor_id");
        let to_space_id = self.extract_optional_field(&event.content, "to_space_id");
        let fields = self.extract_fields(&event.content)?;

        let relation = Relation {
            schema: "cx.schema.relation.v1".to_owned(),
            id: relation_id,
            object_type: "relation".to_owned(),
            space_id: event.space_id.clone(),
            relation_kind,
            from_entity_id,
            from_actor_id,
            from_space_id,
            to_entity_id,
            to_actor_id,
            to_space_id,
            fields,
            state: Some(crate::RelationState::Active),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
        };

        self.relations.insert(relation_id_str, relation);
        Ok(())
    }

    /// Delete a relation.
    fn delete_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            relation.state = Some(crate::RelationState::Deleted);
        }
        Ok(())
    }

    /// Upgrade space schema.
    fn upgrade_space(&mut self, event: &Event) -> Result<()> {
        // Extract upgrade parameters
        if let Some(target_version) = self.extract_optional_field::<String>(&event.content, "target_schema_profile") {
            self.space_version = target_version;
        }
        // TODO: Handle migration policy and compatibility mode
        Ok(())
    }

    /// Tombstone the space.
    fn tombstone_space(&mut self, _event: &Event) -> Result<()> {
        // Mark space as tombstoned - no more writes allowed except maintenance events
        // TODO: Implement tombstone state tracking
        Ok(())
    }

    /// Redact an event.
    fn redact_event(&mut self, _event_id: &EventId) -> Result<()> {
        // Find and redact the event
        // TODO: Implement event redaction in stored events
        Ok(())
    }

    /// Update the causal frontier.
    fn update_frontier(&mut self, event: &Event) {
        // Simple frontier: replace prev_refs with current event
        // TODO: Implement proper frontier computation
        self.frontier = vec![event.event_id.clone()];
    }

    /// Check if an event has been processed.
    fn is_processed(&self, event_id: &EventId) -> bool {
        // Check if event_id is in frontier or was processed
        self.frontier.contains(event_id)
    }

    /// Calculate causal depth for an event.
    fn causal_depth(&self, event: &Event) -> usize {
        let mut depth = 0;
        let mut to_visit: Vec<&EventId> = event.prev_refs.iter().collect();
        let mut visited: std::collections::HashSet<&EventId> = std::collections::HashSet::new();

        while let Some(ref_id) = to_visit.pop() {
            if visited.contains(ref_id) {
                continue;
            }
            visited.insert(ref_id);
            depth += 1;
            // TODO: Follow prev_refs chain (need event index)
        }

        depth
    }

    /// Extract entity_id from event content.
    fn extract_entity_id(&self, content: &serde_json::Value) -> Result<String> {
        self.extract_field(content, "id")
    }

    /// Extract relation_id from event content.
    fn extract_relation_id(&self, content: &serde_json::Value) -> Result<String> {
        self.extract_field(content, "id")
    }

    /// Extract a required field from event content.
    fn extract_field<T: serde::de::DeserializeOwned>(&self, content: &serde_json::Value, field: &str) -> Result<T> {
        let obj = content.as_object()
            .ok_or_else(|| Error::Protocol("event content must be an object".to_owned()))?;

        let value = obj.get(field)
            .ok_or_else(|| Error::Protocol(format!("missing field: {}", field)))?;

        serde_json::from_value(value.clone())
            .map_err(|_| Error::Protocol(format!("invalid field {}: wrong type", field)))
    }

    /// Extract an optional field from event content.
    fn extract_optional_field<T: serde::de::DeserializeOwned>(&self, content: &serde_json::Value, field: &str) -> Option<T> {
        let obj = content.as_object()?;
        let value = obj.get(field)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Extract fields map from event content.
    fn extract_fields(&self, content: &serde_json::Value) -> Result<BTreeMap<String, serde_json::Value>> {
        Ok(self.extract_optional_field(content, "fields")
            .unwrap_or_else(|| BTreeMap::new()))
    }

    /// Create a state snapshot at the current point.
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            space_id: self.space_id.clone(),
            space_version: self.space_version.clone(),
            frontier: self.frontier.clone(),
            entities: self.entities.clone(),
            relations: self.relations.clone(),
            state_hash: self.compute_state_hash(),
            snapshot_timestamp: chrono::Utc::now(),
        }
    }

    /// Compute state hash for verification.
    fn compute_state_hash(&self) -> String {
        // TODO: Implement proper state hash computation
        // For now, return a placeholder
        sha256_digest(format!("{:?}", self.frontier))
    }
}

/// State snapshot at a specific point in time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub space_id: SpaceId,
    pub space_version: String,
    pub frontier: Vec<EventId>,
    pub entities: BTreeMap<String, Entity>,
    pub relations: BTreeMap<String, Relation>,
    pub state_hash: String,
    pub snapshot_timestamp: chrono::DateTime<chrono::Utc>,
}

impl StateSnapshot {
    /// Verify the state hash.
    pub fn verify_hash(&self) -> Result<bool> {
        // TODO: Implement hash verification
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hlc;
    use serde_json::json;

    #[test]
    fn space_state_creates_empty() {
        let state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        assert_eq!(state.entities.len(), 0);
        assert_eq!(state.relations.len(), 0);
    }

    #[test]
    fn space_state_applies_events_in_order() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );

        let actor_id = Did::new("did:web:alice.example.com").unwrap();
        let hlc = Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap();

        let create_event = Event {
            event_id: EventId::new("cx:event:01JS0EV000000000000000000").unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: hlc.clone(),
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({
                "id": "cx:entity:01JS0EN000000000000000000",
                "entity_type": "task",
                "title": "Test task"
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        state.apply_events(&[create_event]).unwrap();
        assert_eq!(state.entities.len(), 1);
    }

    #[test]
    fn space_state_sorts_events_by_hlc() {
        let actor_id = Did::new("did:web:alice.example.com").unwrap();
        let hlc1 = Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap();
        let hlc2 = Hlc::new("01970e589d21-00000002-a13f9c2e").unwrap();

        let event1 = Event {
            event_id: EventId::new("cx:event:01JS0EV000000000000000001").unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: hlc2.clone(), // Later HLC
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({
                "id": "cx:entity:01JS0EN000000000000000001",
                "entity_type": "task",
                "title": "Task 1"
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        let event2 = Event {
            event_id: EventId::new("cx:event:01JS0EV000000000000000002").unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 2,
            created_at: chrono::Utc::now(),
            hlc: hlc1.clone(), // Earlier HLC
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({
                "id": "cx:entity:01JS0EN000000000000000002",
                "entity_type": "task",
                "title": "Task 2"
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );

        state.apply_events(&[event1, event2]).unwrap();

        // event2 should be applied first (earlier HLC)
        assert_eq!(state.frontier.first().unwrap().as_str(), "cx:event:01JS0EV000000000000000001");
    }
}
