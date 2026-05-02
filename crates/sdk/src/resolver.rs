//! State resolution and event reduction.
//!
//! This module implements the Contrix v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Audience, Did, Entity, EntityFacets, EntityId, Error, Event, EventId, Relation, RelationId,
    Result, SpaceId,
    canonical::{canonical_json_bytes, sha256_digest},
    model::{
        OP_CONTAINER_MOVE_ITEM, OP_ENTITY_CREATE, OP_ENTITY_DELETE, OP_ENTITY_REDACT,
        OP_ENTITY_RESTORE, OP_ENTITY_UPDATE, OP_FIELD_POSITION_MOVE, OP_FIELD_POSITION_REORDER,
        OP_RELATION_CREATE, OP_RELATION_DELETE, OP_SPACE_CHILD, OP_SPACE_CREATE,
        OP_SPACE_ORGANIZATION, OP_SPACE_UPDATE, OP_TASK_CREATE, OP_TASK_UPDATE, OP_VIEW_CREATE,
        OP_VIEW_RECONCILE, OP_VIEW_UPDATE,
    },
};

pub const REDUCER_SNAPSHOT_SCHEMA: &str = "cx.schema.reducer_snapshot.v1";
pub const REDUCER_SNAPSHOT_PROFILE: &str = "cx.reducer.v1";

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
    /// Generic resolved state events keyed by `kind|state_key`.
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    /// Message timeline state keyed by message id.
    pub messages: BTreeMap<String, ResolvedMessage>,
    /// Reaction OR-Set keyed by `(message_id, actor, reaction_key)`.
    pub reactions: BTreeMap<String, ResolvedReaction>,
    /// Deterministic conflict decisions recorded during reduction.
    pub conflict_records: Vec<ConflictRecord>,
    /// Causal frontier (most recent event IDs)
    pub frontier: Vec<EventId>,
    /// Space state events
    pub state_events: Vec<Event>,
    processed_events: BTreeMap<EventId, Event>,
    redacted_events: BTreeSet<EventId>,
    tombstone_event_id: Option<EventId>,
}

impl SpaceState {
    /// Create a new empty space state.
    pub fn new(space_id: SpaceId, space_version: String) -> Self {
        Self {
            space_id,
            space_version,
            entities: BTreeMap::new(),
            relations: BTreeMap::new(),
            resolved_state: BTreeMap::new(),
            messages: BTreeMap::new(),
            reactions: BTreeMap::new(),
            conflict_records: Vec::new(),
            frontier: Vec::new(),
            state_events: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: None,
        }
    }

    /// Apply a sequence of events to the state.
    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        let mut event_index = self.processed_events.clone();
        for event in events {
            event_index.insert(event.event_id.clone(), event.clone());
        }

        let mut sorted_events: Vec<&Event> = events.iter().collect();
        sorted_events.sort_by(|a, b| {
            let depth_a = Self::causal_depth_from_index(a, &event_index);
            let depth_b = Self::causal_depth_from_index(b, &event_index);
            depth_a
                .cmp(&depth_b)
                .then_with(|| a.hlc.cmp(&b.hlc))
                .then_with(|| a.actor_id.as_str().cmp(b.actor_id.as_str()))
                .then_with(|| a.actor_seq.cmp(&b.actor_seq))
                .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
        });

        // Apply events in order
        for event in sorted_events {
            self.apply_event(event)?;
        }

        Ok(())
    }

    /// Apply a single event to the state.
    fn apply_event(&mut self, event: &Event) -> Result<()> {
        if self.processed_events.contains_key(&event.event_id) {
            return Ok(());
        }

        // Check causal dependencies
        for prev_ref in &event.prev_refs {
            if !self.is_processed(prev_ref) {
                return Err(Error::Protocol(format!("missing causal dependency: {}", prev_ref)));
            }
        }

        if self.tombstone_event_id.is_some() && !Self::is_maintenance_event(event) {
            return Err(Error::Protocol("space is tombstoned".to_owned()));
        }

        // Check for redaction
        if let Some(redacted_ref) = &event.redacts {
            self.redact_event(redacted_ref)?;
        }

        // Process event content
        self.process_event_content(event)?;

        let mut stored_event = event.clone();
        if self.redacted_events.contains(&stored_event.event_id) {
            stored_event.content = serde_json::json!({});
        }
        self.state_events.push(stored_event.clone());
        self.processed_events.insert(stored_event.event_id.clone(), stored_event);

        // Update frontier
        self.update_frontier(event);

        Ok(())
    }

    /// Process the content of an event and update state.
    fn process_event_content(&mut self, event: &Event) -> Result<()> {
        match event.kind.as_str() {
            // Entity lifecycle
            OP_ENTITY_CREATE => self.create_entity(event)?,
            OP_ENTITY_UPDATE => self.update_entity(event)?,
            OP_ENTITY_DELETE => self.delete_entity(event)?,
            OP_ENTITY_RESTORE => self.restore_entity(event)?,
            OP_ENTITY_REDACT => self.redact_entity(event)?,

            // Relation lifecycle
            OP_RELATION_CREATE => self.create_relation(event)?,
            OP_RELATION_DELETE => self.delete_relation(event)?,
            OP_CONTAINER_MOVE_ITEM => self.move_relation(event)?,

            // Task operations (entity-type-specific wrappers)
            OP_TASK_CREATE => self.create_entity(event)?,
            OP_TASK_UPDATE => self.update_entity(event)?,
            OP_FIELD_POSITION_MOVE | OP_FIELD_POSITION_REORDER => self.update_entity(event)?,

            // View operations
            OP_VIEW_CREATE => self.create_view(event)?,
            OP_VIEW_UPDATE => self.update_view(event)?,
            OP_VIEW_RECONCILE => self.reconcile_view(event)?,

            // Space lifecycle — generic state reduction
            OP_SPACE_CREATE
            | OP_SPACE_UPDATE
            | OP_SPACE_ORGANIZATION
            | OP_SPACE_CHILD
            | "cx.space.parent"
            | "cx.space.inheritance_policy"
            | "cx.space.join_rule"
            | "cx.space.history_visibility"
            | "cx.space.discovery"
            | "cx.space.archive"
            | "cx.space.freeze"
            | "cx.space.destroy" => self.reduce_space_lifecycle_event(event)?,

            // Member / capability / invite / policy / read-marker state
            "cx.member.state"
            | "cx.capability.grant"
            | "cx.capability.delegate"
            | "cx.capability.revoke"
            | "cx.space.policy"
            | "cx.policy.set"
            | "cx.invite.create"
            | "cx.invite.cancel"
            | "cx.invite.accept"
            | "cx.read.marker" => self.reduce_generic_state_event(event)?,

            // Message timeline
            "cx.message.create" => self.create_message(event)?,
            "cx.message.revise" => self.revise_message(event)?,
            "cx.message.redact" => self.redact_message(event)?,

            // Reactions
            "cx.reaction.add" | "cx.reaction.remove" => self.reduce_reaction(event)?,

            // Space upgrade / tombstone
            "cx.space.upgrade" => self.upgrade_space(event)?,
            "cx.space.tombstone" => self.tombstone_space(event)?,

            // Generic redaction
            "cx.redaction" => {
                if let Some(redacted_ref) = &event.redacts {
                    self.redact_event(redacted_ref)?;
                }
            }

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
        let facets = self.extract_optional_field(&event.content, "facets").unwrap_or_default();
        let title = self.extract_optional_field(&event.content, "title");
        let content = self.extract_optional_field(&event.content, "content");
        let fields = self.extract_fields(&event.content)?;

        let entity = Entity {
            schema: "cx.schema.entity.v1".to_owned(),
            id: entity_id,
            object_type: "entity".to_owned(),
            space_id: event.space_id.clone(),
            entity_type,
            facets,
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
        let fields = self.extract_optional_field::<BTreeMap<String, serde_json::Value>>(
            &event.content,
            "fields",
        );
        let facets = self.extract_optional_field::<EntityFacets>(&event.content, "facets");
        let state = self.extract_optional_field::<String>(&event.content, "state");

        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;

        let entity = self
            .entities
            .get_mut(&entity_id_str)
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
        if let Some(facets) = facets {
            entity.facets = facets;
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

    /// Restore a previously deleted/archived entity back to active state.
    fn restore_entity(&mut self, event: &Event) -> Result<()> {
        let entity_id_str = self.extract_entity_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        if let Some(entity) = self.entities.get_mut(&entity_id_str) {
            entity.state = Some(crate::ObjectState::Active);
            entity.updated_by = Some(actor_id);
            entity.updated_at = Some(created_at);
            if let Some(version) = entity.version {
                entity.version = Some(version + 1);
            }
        }
        Ok(())
    }

    /// Move a relation by updating its endpoints.
    fn move_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        let new_to = self.extract_optional_field::<String>(&event.content, "to_entity_id");
        let new_from = self.extract_optional_field::<String>(&event.content, "from_entity_id");

        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            if let Some(new_to) = new_to {
                relation.to_entity_id = Some(EntityId::new(new_to)?);
            }
            if let Some(new_from) = new_from {
                relation.from_entity_id = Some(EntityId::new(new_from)?);
            }
            relation.created_by = actor_id;
            relation.created_at = created_at;
        }
        Ok(())
    }

    /// Create a view (stored as resolved state).
    fn create_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Update a view (stored as resolved state).
    fn update_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Reconcile a view (stored as resolved state).
    fn reconcile_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Reduce space lifecycle events into resolved state.
    fn reduce_space_lifecycle_event(&mut self, event: &Event) -> Result<()> {
        // Space lifecycle events update the space version and are stored as resolved state.
        if (event.kind == "cx.space.create" || event.kind == "cx.space.update")
            && let Some(version) =
                self.extract_optional_field::<String>(&event.content, "space_version")
        {
            self.space_version = version;
        }
        if event.kind == "cx.space.destroy" {
            // Treat destroy as tombstone
            self.tombstone_event_id = Some(event.event_id.clone());
        }
        self.reduce_generic_state_event(event)
    }

    fn reduce_generic_state_event(&mut self, event: &Event) -> Result<()> {
        let state_key = self.state_key_for_event(event)?;
        let family = match event.kind.as_str() {
            "cx.capability.grant" | "cx.capability.delegate" | "cx.capability.revoke" => {
                "cx.capability"
            }
            "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => "cx.invite",
            "cx.space.policy" | "cx.policy.set" => "cx.policy",
            other => other,
        };
        let map_key = format!("{}|{}", family, state_key);
        let candidate = ResolvedStateEvent {
            kind: event.kind.clone(),
            state_key,
            source_event_id: event.event_id.clone(),
            actor_id: event.actor_id.clone(),
            actor_seq: event.actor_seq,
            hlc: event.hlc.clone(),
            content: event.content.clone(),
        };

        match self.resolved_state.get(&map_key) {
            Some(existing) if !Self::generic_state_candidate_wins(existing, &candidate) => {
                self.conflict_records.push(ConflictRecord {
                    key: map_key,
                    winner_event_id: existing.source_event_id.clone(),
                    loser_event_id: candidate.source_event_id,
                    reason: "existing state wins deterministic reducer order".to_owned(),
                });
            }
            Some(existing) => {
                let loser_event_id = existing.source_event_id.clone();
                self.conflict_records.push(ConflictRecord {
                    key: map_key.clone(),
                    winner_event_id: candidate.source_event_id.clone(),
                    loser_event_id,
                    reason: "candidate state wins deterministic reducer order".to_owned(),
                });
                self.resolved_state.insert(map_key, candidate);
            }
            None => {
                self.resolved_state.insert(map_key, candidate);
            }
        }

        Ok(())
    }

    fn create_message(&mut self, event: &Event) -> Result<()> {
        let message_id = self
            .extract_optional_field::<String>(&event.content, "message_id")
            .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
            .unwrap_or_else(|| event.event_id.to_string());
        self.messages.entry(message_id.clone()).or_insert_with(|| ResolvedMessage {
            message_id,
            source_event_id: event.event_id.clone(),
            latest_event_id: event.event_id.clone(),
            created_by: event.actor_id.clone(),
            latest_actor_id: event.actor_id.clone(),
            latest_actor_seq: event.actor_seq,
            latest_hlc: event.hlc.clone(),
            content: event.content.clone(),
            revision_event_ids: Vec::new(),
            redacted: false,
        });
        Ok(())
    }

    fn revise_message(&mut self, event: &Event) -> Result<()> {
        let message_id = self
            .extract_optional_field::<String>(&event.content, "target_message_id")
            .or_else(|| self.extract_optional_field::<String>(&event.content, "message_id"))
            .ok_or_else(|| {
                Error::Protocol("message revision requires target_message_id".to_owned())
            })?;
        let message = self
            .messages
            .get_mut(&message_id)
            .ok_or_else(|| Error::Protocol(format!("message not found: {}", message_id)))?;
        if Self::message_candidate_wins(message, event) {
            message.latest_event_id = event.event_id.clone();
            message.latest_actor_id = event.actor_id.clone();
            message.latest_actor_seq = event.actor_seq;
            message.latest_hlc = event.hlc.clone();
            message.content =
                event.content.get("content").cloned().unwrap_or_else(|| event.content.clone());
            message.redacted = false;
        }
        message.revision_event_ids.push(event.event_id.clone());
        Ok(())
    }

    fn redact_message(&mut self, event: &Event) -> Result<()> {
        let message_id = self
            .extract_optional_field::<String>(&event.content, "target_message_id")
            .or_else(|| self.extract_optional_field::<String>(&event.content, "message_id"))
            .ok_or_else(|| {
                Error::Protocol("message redaction requires target_message_id".to_owned())
            })?;
        if let Some(message) = self.messages.get_mut(&message_id) {
            if Self::message_candidate_wins(message, event) {
                message.latest_event_id = event.event_id.clone();
                message.latest_actor_id = event.actor_id.clone();
                message.latest_actor_seq = event.actor_seq;
                message.latest_hlc = event.hlc.clone();
                message.content = serde_json::json!({});
                message.redacted = true;
            }
            message.revision_event_ids.push(event.event_id.clone());
        }
        Ok(())
    }

    fn reduce_reaction(&mut self, event: &Event) -> Result<()> {
        let message_id = self.extract_field::<String>(&event.content, "message_id")?;
        let reaction_key = self.extract_field::<String>(&event.content, "reaction_key")?;
        let key = format!("{}|{}|{}", message_id, event.actor_id, reaction_key);
        let candidate = ResolvedReaction {
            message_id,
            actor_id: event.actor_id.clone(),
            reaction_key,
            source_event_id: event.event_id.clone(),
            actor_seq: event.actor_seq,
            hlc: event.hlc.clone(),
            active: event.kind == "cx.reaction.add",
        };
        match self.reactions.get(&key) {
            Some(existing) if !Self::reaction_candidate_wins(existing, &candidate) => {}
            _ => {
                self.reactions.insert(key, candidate);
            }
        }
        Ok(())
    }

    /// Upgrade space schema.
    fn upgrade_space(&mut self, event: &Event) -> Result<()> {
        // Extract upgrade parameters
        if let Some(target_version) =
            self.extract_optional_field::<String>(&event.content, "target_schema_profile")
        {
            self.space_version = target_version;
        }
        // TODO: Handle migration policy and compatibility mode
        Ok(())
    }

    /// Tombstone the space.
    fn tombstone_space(&mut self, _event: &Event) -> Result<()> {
        self.tombstone_event_id = Some(_event.event_id.clone());
        Ok(())
    }

    /// Redact an event.
    fn redact_event(&mut self, event_id: &EventId) -> Result<()> {
        self.redacted_events.insert(event_id.clone());
        if let Some(event) = self.processed_events.get_mut(event_id) {
            event.content = serde_json::json!({});
        }
        for event in &mut self.state_events {
            if &event.event_id == event_id {
                event.content = serde_json::json!({});
            }
        }
        Ok(())
    }

    /// Update the causal frontier.
    fn update_frontier(&mut self, event: &Event) {
        let prev_refs: BTreeSet<EventId> = event.prev_refs.iter().cloned().collect();
        self.frontier.retain(|frontier_event| !prev_refs.contains(frontier_event));
        if !self.frontier.contains(&event.event_id) {
            self.frontier.push(event.event_id.clone());
        }
        self.frontier.sort();
    }

    /// Check if an event has been processed.
    fn is_processed(&self, event_id: &EventId) -> bool {
        self.processed_events.contains_key(event_id)
    }

    fn causal_depth_from_index(event: &Event, index: &BTreeMap<EventId, Event>) -> usize {
        fn walk(
            event_id: &EventId,
            index: &BTreeMap<EventId, Event>,
            visiting: &mut BTreeSet<EventId>,
        ) -> usize {
            if !visiting.insert(event_id.clone()) {
                return 0;
            }
            let depth = index
                .get(event_id)
                .map(|event| {
                    event
                        .prev_refs
                        .iter()
                        .map(|prev_ref| 1 + walk(prev_ref, index, visiting))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            visiting.remove(event_id);
            depth
        }

        event
            .prev_refs
            .iter()
            .map(|prev_ref| 1 + walk(prev_ref, index, &mut BTreeSet::new()))
            .max()
            .unwrap_or(0)
    }

    fn is_maintenance_event(event: &Event) -> bool {
        matches!(
            event.kind.as_str(),
            "cx.entity.redact"
                | "cx.message.redact"
                | "cx.space.redact"
                | "cx.space.export"
                | "cx.space.legal_hold"
                | "cx.space.migration_proof"
                | "cx.space.upgrade"
                | "cx.space.destroy"
                | "cx.redaction"
        ) || event.redacts.is_some()
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
    fn extract_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &serde_json::Value,
        field: &str,
    ) -> Result<T> {
        let obj = content
            .as_object()
            .ok_or_else(|| Error::Protocol("event content must be an object".to_owned()))?;

        let value =
            obj.get(field).ok_or_else(|| Error::Protocol(format!("missing field: {}", field)))?;

        serde_json::from_value(value.clone())
            .map_err(|_| Error::Protocol(format!("invalid field {}: wrong type", field)))
    }

    /// Extract an optional field from event content.
    fn extract_optional_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &serde_json::Value,
        field: &str,
    ) -> Option<T> {
        let obj = content.as_object()?;
        let value = obj.get(field)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Extract fields map from event content.
    fn extract_fields(
        &self,
        content: &serde_json::Value,
    ) -> Result<BTreeMap<String, serde_json::Value>> {
        Ok(self.extract_optional_field(content, "fields").unwrap_or_default())
    }

    fn state_key_for_event(&self, event: &Event) -> Result<String> {
        if let Some(state_key) = self.extract_optional_field::<String>(&event.content, "state_key")
        {
            return Ok(state_key);
        }

        match event.kind.as_str() {
            "cx.member.state" => self
                .extract_optional_field::<String>(&event.content, "principal_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "member_id"))
                .ok_or_else(|| {
                    Error::Protocol("member state requires state_key or principal_id".to_owned())
                }),
            "cx.capability.revoke" => self
                .extract_optional_field::<String>(&event.content, "target_capability_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| {
                    Error::Protocol("capability revoke requires target_capability_id".to_owned())
                }),
            "cx.capability.grant" | "cx.capability.delegate" => self
                .extract_optional_field::<String>(&event.content, "capability_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| {
                    Error::Protocol("capability event requires capability_id or id".to_owned())
                }),
            "cx.space.policy" | "cx.policy.set" => Ok(self
                .extract_optional_field::<String>(&event.content, "policy_id")
                .unwrap_or_else(|| "space_policy".to_owned())),
            "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => self
                .extract_optional_field::<String>(&event.content, "invite_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("invite event requires invite_id or id".to_owned())),
            "cx.read.marker" => self
                .extract_optional_field::<String>(&event.content, "scope")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "target_ref"))
                .ok_or_else(|| {
                    Error::Protocol("read marker requires scope or target_ref".to_owned())
                }),
            // Space lifecycle events use the space_id as state key
            "cx.space.create"
            | "cx.space.update"
            | "cx.space.organization"
            | "cx.space.child"
            | "cx.space.parent"
            | "cx.space.inheritance_policy"
            | "cx.space.join_rule"
            | "cx.space.history_visibility"
            | "cx.space.discovery"
            | "cx.space.archive"
            | "cx.space.freeze"
            | "cx.space.destroy" => Ok(event.space_id.as_str().to_owned()),
            // View events use view_id as state key
            "cx.view.create" | "cx.view.update" | "cx.view.reconcile" => self
                .extract_optional_field::<String>(&event.content, "view_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("view event requires view_id or id".to_owned())),
            _ => Ok(String::new()),
        }
    }

    fn generic_state_candidate_wins(
        existing: &ResolvedStateEvent,
        candidate: &ResolvedStateEvent,
    ) -> bool {
        if candidate.kind == "cx.member.state" && existing.kind == "cx.member.state" {
            let existing_rank = membership_rank(&existing.content);
            let candidate_rank = membership_rank(&candidate.content);
            if existing_rank != candidate_rank {
                return candidate_rank > existing_rank;
            }
        }

        candidate
            .hlc
            .cmp(&existing.hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
            .then_with(|| candidate.source_event_id.as_str().cmp(existing.source_event_id.as_str()))
            .is_gt()
    }

    fn message_candidate_wins(existing: &ResolvedMessage, candidate: &Event) -> bool {
        candidate
            .hlc
            .cmp(&existing.latest_hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.latest_actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.latest_actor_seq))
            .then_with(|| candidate.event_id.as_str().cmp(existing.latest_event_id.as_str()))
            .is_gt()
    }

    fn reaction_candidate_wins(existing: &ResolvedReaction, candidate: &ResolvedReaction) -> bool {
        candidate
            .hlc
            .cmp(&existing.hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
            .then_with(|| candidate.source_event_id.as_str().cmp(existing.source_event_id.as_str()))
            .is_gt()
    }

    /// Create a state snapshot at the current point.
    pub fn snapshot(&self) -> StateSnapshot {
        let mut snapshot = StateSnapshot {
            space_id: self.space_id.clone(),
            space_version: self.space_version.clone(),
            frontier: self.frontier.clone(),
            entities: self.entities.clone(),
            relations: self.relations.clone(),
            resolved_state: self.resolved_state.clone(),
            messages: self.messages.clone(),
            reactions: self.reactions.clone(),
            state_hash: self.compute_state_hash(),
            snapshot_timestamp: chrono::Utc::now(),
            tombstone_event_id: self.tombstone_event_id.clone(),
            manifest: None,
        };
        snapshot.manifest = Some(snapshot.manifest());
        snapshot
    }

    pub fn effective_capability(&self, capability_id: &str) -> Option<&ResolvedStateEvent> {
        self.resolved_state.get(&format!("cx.capability|{}", capability_id)).filter(|event| {
            matches!(event.kind.as_str(), "cx.capability.grant" | "cx.capability.delegate")
        })
    }

    pub fn capability_allows(&self, capability_id: &str, action: &str) -> bool {
        self.effective_capability(capability_id)
            .and_then(|event| event.content.get("actions"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|actions| {
                actions.iter().any(|candidate| {
                    candidate.as_str() == Some(action) || candidate.as_str() == Some("*")
                })
            })
    }

    /// Compute state hash for verification.
    pub fn compute_state_hash(&self) -> String {
        crate::canonical::canonical_sha256(&state_hash_payload(StateHashInput {
            space_id: &self.space_id,
            space_version: &self.space_version,
            frontier: &self.frontier,
            entities: &self.entities,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
        .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)))
    }

    pub fn state_merkle_root(&self) -> Result<String> {
        state_merkle_root(&state_hash_payload(StateHashInput {
            space_id: &self.space_id,
            space_version: &self.space_version,
            frontier: &self.frontier,
            entities: &self.entities,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
    }

    fn from_snapshot(snapshot: StateSnapshot) -> Self {
        Self {
            space_id: snapshot.space_id,
            space_version: snapshot.space_version,
            entities: snapshot.entities,
            relations: snapshot.relations,
            resolved_state: snapshot.resolved_state,
            messages: snapshot.messages,
            reactions: snapshot.reactions,
            conflict_records: Vec::new(),
            frontier: snapshot.frontier,
            state_events: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: snapshot.tombstone_event_id,
        }
    }

    pub fn restore_snapshot_or_replay(
        snapshot: Option<StateSnapshot>,
        space_id: SpaceId,
        space_version: impl Into<String>,
        repo_events: &[Event],
    ) -> Result<SnapshotRestore> {
        if let Some(snapshot) = snapshot {
            match snapshot.verify() {
                Ok(()) => {
                    return Ok(SnapshotRestore {
                        state: Self::from_snapshot(snapshot),
                        source: SnapshotRestoreSource::Snapshot,
                        snapshot_error: None,
                    });
                }
                Err(err) => {
                    let mut state = Self::new(space_id, space_version.into());
                    state.apply_events(repo_events)?;
                    return Ok(SnapshotRestore {
                        state,
                        source: SnapshotRestoreSource::RepoReplay,
                        snapshot_error: Some(err.to_string()),
                    });
                }
            }
        }

        let mut state = Self::new(space_id, space_version.into());
        state.apply_events(repo_events)?;
        Ok(SnapshotRestore {
            state,
            source: SnapshotRestoreSource::RepoReplay,
            snapshot_error: None,
        })
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
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    pub messages: BTreeMap<String, ResolvedMessage>,
    pub reactions: BTreeMap<String, ResolvedReaction>,
    pub state_hash: String,
    pub snapshot_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ReducerSnapshotManifest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReducerSnapshotManifest {
    pub schema: String,
    pub reducer_profile: String,
    pub space_id: SpaceId,
    pub space_version: String,
    pub frontier: Vec<EventId>,
    pub state_hash: String,
    pub merkle_root: String,
    pub chunk_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<SnapshotChunkManifest>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SnapshotSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunkManifest {
    pub index: u32,
    pub digest: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotSignature {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub signature: String,
}

impl SnapshotSignature {
    pub fn manifest_binding_payload(
        &self,
        manifest: &ReducerSnapshotManifest,
    ) -> Result<SnapshotSignatureBindingPayload> {
        Ok(SnapshotSignatureBindingPayload {
            payload_hash: crate::canonical::canonical_sha256(&manifest.signature_payload())?,
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotSignatureBindingPayload {
    pub payload_hash: String,
    pub verification_method: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotRestoreSource {
    Snapshot,
    RepoReplay,
}

#[derive(Clone, Debug)]
pub struct SnapshotRestore {
    pub state: SpaceState,
    pub source: SnapshotRestoreSource,
    pub snapshot_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedStateEvent {
    pub kind: String,
    pub state_key: String,
    pub source_event_id: EventId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: crate::Hlc,
    pub content: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedMessage {
    pub message_id: String,
    pub source_event_id: EventId,
    pub latest_event_id: EventId,
    pub created_by: Did,
    pub latest_actor_id: Did,
    pub latest_actor_seq: u64,
    pub latest_hlc: crate::Hlc,
    pub content: serde_json::Value,
    pub revision_event_ids: Vec<EventId>,
    pub redacted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedReaction {
    pub message_id: String,
    pub actor_id: Did,
    pub reaction_key: String,
    pub source_event_id: EventId,
    pub actor_seq: u64,
    pub hlc: crate::Hlc,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

fn membership_rank(content: &serde_json::Value) -> u8 {
    match content.get("membership").and_then(serde_json::Value::as_str) {
        Some("ban") => 4,
        Some("leave") => 3,
        Some("invite") => 2,
        Some("join") => 1,
        _ => 0,
    }
}

impl StateSnapshot {
    /// Verify the state hash.
    pub fn verify_hash(&self) -> Result<bool> {
        Ok(self.compute_state_hash()? == self.state_hash)
    }

    pub fn compute_state_hash(&self) -> Result<String> {
        crate::canonical::canonical_sha256(&self.state_payload())
    }

    pub fn state_merkle_root(&self) -> Result<String> {
        state_merkle_root(&self.state_payload())
    }

    pub fn canonical_snapshot_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&self.state_payload())
    }

    pub fn chunk_manifest(&self, chunk_size: usize) -> Result<Vec<SnapshotChunkManifest>> {
        if chunk_size == 0 {
            return Err(Error::Protocol(
                "snapshot chunk size must be greater than zero".to_owned(),
            ));
        }
        let bytes = self.canonical_snapshot_bytes()?;
        Ok(bytes
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, chunk)| SnapshotChunkManifest {
                index: index as u32,
                digest: sha256_digest(chunk),
                byte_len: chunk.len(),
            })
            .collect())
    }

    pub fn manifest(&self) -> ReducerSnapshotManifest {
        let merkle_root = self
            .state_merkle_root()
            .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)));
        ReducerSnapshotManifest {
            schema: REDUCER_SNAPSHOT_SCHEMA.to_owned(),
            reducer_profile: REDUCER_SNAPSHOT_PROFILE.to_owned(),
            space_id: self.space_id.clone(),
            space_version: self.space_version.clone(),
            frontier: self.frontier.clone(),
            state_hash: self.state_hash.clone(),
            merkle_root,
            chunk_count: 0,
            chunks: Vec::new(),
            created_at: self.snapshot_timestamp,
            signatures: Vec::new(),
        }
    }

    pub fn manifest_with_chunks(&self, chunk_size: usize) -> Result<ReducerSnapshotManifest> {
        let chunks = self.chunk_manifest(chunk_size)?;
        let mut manifest = self.manifest();
        manifest.chunk_count = chunks.len() as u32;
        manifest.chunks = chunks;
        Ok(manifest)
    }

    pub fn verify(&self) -> Result<()> {
        if !self.verify_hash()? {
            return Err(Error::Protocol("snapshot state hash mismatch".to_owned()));
        }
        let actual_root = self.state_merkle_root()?;
        if let Some(manifest) = &self.manifest {
            manifest.verify_against_snapshot(self, &actual_root)?;
        }
        Ok(())
    }

    fn state_payload(&self) -> serde_json::Value {
        state_hash_payload(StateHashInput {
            space_id: &self.space_id,
            space_version: &self.space_version,
            frontier: &self.frontier,
            entities: &self.entities,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        })
    }
}

impl ReducerSnapshotManifest {
    pub fn verify_against_snapshot(
        &self,
        snapshot: &StateSnapshot,
        actual_merkle_root: &str,
    ) -> Result<()> {
        if self.schema != REDUCER_SNAPSHOT_SCHEMA {
            return Err(Error::Protocol("snapshot manifest schema mismatch".to_owned()));
        }
        if self.reducer_profile != REDUCER_SNAPSHOT_PROFILE {
            return Err(Error::Protocol("snapshot manifest reducer profile mismatch".to_owned()));
        }
        if self.space_id != snapshot.space_id
            || self.space_version != snapshot.space_version
            || self.frontier != snapshot.frontier
            || self.state_hash != snapshot.state_hash
        {
            return Err(Error::Protocol("snapshot manifest does not match snapshot".to_owned()));
        }
        if self.merkle_root != actual_merkle_root {
            return Err(Error::Protocol("snapshot manifest merkle root mismatch".to_owned()));
        }
        if self.chunk_count as usize != self.chunks.len() {
            return Err(Error::Protocol("snapshot manifest chunk count mismatch".to_owned()));
        }
        Ok(())
    }

    pub fn verify_chunks<I, B>(&self, chunks: I) -> Result<()>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let chunks: Vec<B> = chunks.into_iter().collect();
        if chunks.len() != self.chunks.len() {
            return Err(Error::Protocol("snapshot chunk count mismatch".to_owned()));
        }
        for (expected, chunk) in self.chunks.iter().zip(chunks.iter()) {
            let chunk = chunk.as_ref();
            if expected.byte_len != chunk.len() {
                return Err(Error::Protocol(format!(
                    "snapshot chunk {} length mismatch",
                    expected.index
                )));
            }
            let actual = sha256_digest(chunk);
            if expected.digest != actual {
                return Err(Error::Protocol(format!(
                    "snapshot chunk {} digest mismatch",
                    expected.index
                )));
            }
        }
        Ok(())
    }

    pub fn signature_payload(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let serde_json::Value::Object(map) = &mut value {
            map.remove("signatures");
        }
        value
    }
}

pub fn verify_snapshot_chunks<I, B>(manifest: &ReducerSnapshotManifest, chunks: I) -> Result<()>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    manifest.verify_chunks(chunks)
}

pub fn state_merkle_root(payload: &serde_json::Value) -> Result<String> {
    let serde_json::Value::Object(map) = payload else {
        return Err(Error::Protocol("state merkle payload must be an object".to_owned()));
    };
    let leaves = map
        .iter()
        .map(|(key, value)| {
            crate::canonical::canonical_sha256(&serde_json::json!({
                "key": key,
                "value": value,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    merkle_root(leaves)
}

pub fn merkle_root(mut leaves: Vec<String>) -> Result<String> {
    if leaves.is_empty() {
        return Ok(sha256_digest([]));
    }
    leaves.sort();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(crate::canonical::canonical_sha256(&serde_json::json!({
                "left": pair[0],
                "right": right,
            }))?);
        }
        leaves = next;
    }
    Ok(leaves.remove(0))
}

struct StateHashInput<'a> {
    space_id: &'a SpaceId,
    space_version: &'a str,
    frontier: &'a [EventId],
    entities: &'a BTreeMap<String, Entity>,
    relations: &'a BTreeMap<String, Relation>,
    resolved_state: &'a BTreeMap<String, ResolvedStateEvent>,
    messages: &'a BTreeMap<String, ResolvedMessage>,
    reactions: &'a BTreeMap<String, ResolvedReaction>,
    tombstone_event_id: &'a Option<EventId>,
}

fn state_hash_payload(input: StateHashInput<'_>) -> serde_json::Value {
    serde_json::json!({
        "space_id": input.space_id,
        "space_version": input.space_version,
        "frontier": input.frontier,
        "entities": input.entities,
        "relations": input.relations,
        "resolved_state": input.resolved_state,
        "messages": input.messages,
        "reactions": input.reactions,
        "tombstone_event_id": input.tombstone_event_id,
    })
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
            actor_id,
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc,
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
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
            hlc: hlc2, // Later HLC
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
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
            actor_id,
            actor_seq: 2,
            created_at: chrono::Utc::now(),
            hlc: hlc1, // Earlier HLC
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
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

    #[test]
    fn member_state_conflict_prefers_ban_semantics() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();

        let leave = Event {
            event_id: EventId::new("cx:event:01JS0M1A000000000000000000").unwrap(),
            kind: "cx.member.state".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:admin-b.example").unwrap(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9d2e").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "state_key": "did:web:alice.example", "membership": "leave" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };
        let ban = Event {
            event_id: EventId::new("cx:event:01JS0M1B000000000000000000").unwrap(),
            kind: "cx.member.state".to_owned(),
            space_id,
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:admin-a.example").unwrap(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "state_key": "did:web:alice.example", "membership": "ban" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        state.apply_events(&[leave, ban]).unwrap();

        let resolved = state.resolved_state.get("cx.member.state|did:web:alice.example").unwrap();
        assert_eq!(resolved.content["membership"], "ban");
        assert_eq!(resolved.source_event_id.as_str(), "cx:event:01JS0M1B000000000000000000");
        assert_eq!(state.conflict_records.len(), 1);
    }

    #[test]
    fn capability_rebind_uses_deterministic_lww_order() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let actor_id = Did::new("did:web:moderator.example").unwrap();

        let revoke = Event {
            event_id: EventId::new("cx:event:01JS0R1E000000000000000000").unwrap(),
            kind: "cx.capability.revoke".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000001-22222222").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "target_capability_id": "cap-chan-post" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };
        let grant = Event {
            event_id: EventId::new("cx:event:01JS0G1F000000000000000000").unwrap(),
            kind: "cx.capability.grant".to_owned(),
            space_id,
            space_version: "1".to_owned(),
            actor_id,
            actor_seq: 2,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000001-33333333").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({
                "capability_id": "cap-chan-post",
                "subject": "did:web:alice.example",
                "actions": ["message.send", "message.react"]
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        state.apply_events(&[revoke, grant]).unwrap();

        let resolved = state.resolved_state.get("cx.capability|cap-chan-post").unwrap();
        assert_eq!(resolved.content["actions"][1], "message.react");
        assert!(state.capability_allows("cap-chan-post", "message.react"));
        assert!(!state.capability_allows("cap-chan-post", "message.delete"));
    }

    #[test]
    fn message_revision_redaction_and_reaction_converge() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let actor_id = Did::new("did:web:alice.example").unwrap();

        let base = Event {
            event_id: EventId::new("cx:event:01JS0MSG000000000000000001").unwrap(),
            kind: "cx.message.create".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000001-11111111").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "message_id": "m1", "body": "hello" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };
        let revise = Event {
            event_id: EventId::new("cx:event:01JS0MSG000000000000000002").unwrap(),
            kind: "cx.message.revise".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: actor_id.clone(),
            actor_seq: 2,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000002-11111111").unwrap(),
            prev_refs: vec![base.event_id.clone()],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "target_message_id": "m1", "content": { "body": "edited" } }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };
        let reaction_add = Event {
            event_id: EventId::new("cx:event:01JS0RCT000000000000000001").unwrap(),
            kind: "cx.reaction.add".to_owned(),
            space_id,
            space_version: "1".to_owned(),
            actor_id,
            actor_seq: 3,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000003-11111111").unwrap(),
            prev_refs: vec![revise.event_id.clone()],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({ "message_id": "m1", "reaction_key": "+1" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        state.apply_events(&[reaction_add, revise, base]).unwrap();

        let message = state.messages.get("m1").unwrap();
        assert_eq!(message.content["body"], "edited");
        assert_eq!(message.revision_event_ids.len(), 1);

        let reaction = state.reactions.get("m1|did:web:alice.example|+1").unwrap();
        assert!(reaction.active);
    }

    #[test]
    fn snapshot_manifest_tracks_state_hash_and_merkle_root() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        let event = entity_event("cx:event:01JS0SNAP00000000000000001", "Snapshot task");

        state.apply_events(std::slice::from_ref(&event)).unwrap();
        let snapshot = state.snapshot();
        let manifest = snapshot.manifest.as_ref().unwrap();

        assert_eq!(manifest.schema, REDUCER_SNAPSHOT_SCHEMA);
        assert_eq!(manifest.reducer_profile, REDUCER_SNAPSHOT_PROFILE);
        assert_eq!(manifest.state_hash, snapshot.state_hash);
        assert_eq!(manifest.merkle_root, snapshot.state_merkle_root().unwrap());
        snapshot.verify().unwrap();
    }

    #[test]
    fn snapshot_chunk_manifest_verifies_digests() {
        let state = SpaceState::new(
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            "1".to_owned(),
        );
        let snapshot = state.snapshot();
        let manifest = snapshot.manifest_with_chunks(16).unwrap();
        let bytes = snapshot.canonical_snapshot_bytes().unwrap();
        let chunks: Vec<Vec<u8>> = bytes.chunks(16).map(|chunk| chunk.to_vec()).collect();

        verify_snapshot_chunks(&manifest, chunks.clone()).unwrap();

        let mut tampered = chunks;
        tampered[0][0] ^= 1;
        assert!(verify_snapshot_chunks(&manifest, tampered).is_err());
    }

    #[test]
    fn merkle_root_is_order_independent_for_leaf_hashes() {
        let a = merkle_root(vec![
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ])
        .unwrap();
        let b = merkle_root(vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        ])
        .unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn restore_snapshot_or_replay_falls_back_on_verification_failure() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let event = entity_event("cx:event:01JS0SNAP00000000000000002", "Replayed task");
        let mut state = SpaceState::new(space_id.clone(), "1".to_owned());
        state.apply_events(std::slice::from_ref(&event)).unwrap();
        let mut snapshot = state.snapshot();
        snapshot.state_hash =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        let restored =
            SpaceState::restore_snapshot_or_replay(Some(snapshot), space_id, "1", &[event])
                .unwrap();

        assert_eq!(restored.source, SnapshotRestoreSource::RepoReplay);
        assert!(restored.snapshot_error.unwrap().contains("state hash mismatch"));
        assert_eq!(restored.state.entities.len(), 1);
    }

    fn entity_event(event_id: &str, title: &str) -> Event {
        Event {
            event_id: EventId::new(event_id).unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:alice.example.com").unwrap(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d22-00000009-11111111").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content: json!({
                "id": "cx:entity:01JS0SNAPENTITY00000000000",
                "entity_type": "task",
                "title": title
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    #[test]
    fn reducer_convergence_is_order_independent() {
        // Property: applying the same events in any permutation produces the same
        // final state, because the reducer sorts by HLC before applying.
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let actor = Did::new("did:web:alice.example.com").unwrap();

        let events: Vec<Event> = (0..5)
            .map(|i| {
                let hlc = Hlc::new(format!("01970e589d22-{i:08x}-11111111")).unwrap();
                Event {
                    event_id: EventId::new(format!("cx:event:01JS0CONV{i:022}")).unwrap(),
                    kind: OP_ENTITY_CREATE.to_owned(),
                    space_id: space_id.clone(),
                    space_version: "1".to_owned(),
                    actor_id: actor.clone(),
                    actor_seq: i + 1,
                    created_at: chrono::Utc::now(),
                    hlc,
                    prev_refs: vec![],
                    auth_refs: vec![],
                    schema_profile_refs: vec![],
                    reducer_profile_ref: None,
                    required_features: vec![],
                    critical_extensions: vec![],
                    redacts: None,
                    content: json!({
                        "id": format!("cx:entity:01JS0CONVENTITY{i:018}"),
                        "entity_type": "task",
                        "title": format!("Task {i}")
                    }),
                    unsigned: BTreeMap::new(),
                    proofs: vec![],
                }
            })
            .collect();

        // Apply in original order.
        let mut state_a = SpaceState::new(space_id.clone(), "1".to_owned());
        state_a.apply_events(&events).unwrap();

        // Apply in reversed order.
        let mut reversed = events.clone();
        reversed.reverse();
        let mut state_b = SpaceState::new(space_id, "1".to_owned());
        state_b.apply_events(&reversed).unwrap();

        // Both must converge to the same entity set and frontier.
        assert_eq!(state_a.entities.len(), state_b.entities.len());
        for (id, entity_a) in &state_a.entities {
            let entity_b = state_b.entities.get(id).unwrap();
            assert_eq!(entity_a.title, entity_b.title);
            assert_eq!(entity_a.version, entity_b.version);
        }
        assert_eq!(state_a.frontier, state_b.frontier);
    }
}
