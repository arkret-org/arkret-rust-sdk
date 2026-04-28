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
    Did, Entity, EntityId, Error, Event, EventId, Relation, RelationId, Result, SpaceId,
    canonical::sha256_digest,
};

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
            "cx.entity.create" => self.create_entity(event)?,
            "cx.entity.update" => self.update_entity(event)?,
            "cx.entity.delete" => self.delete_entity(event)?,
            "cx.entity.restore" => self.restore_entity(event)?,
            "cx.entity.redact" => self.redact_entity(event)?,

            // Relation lifecycle
            "cx.relation.create" => self.create_relation(event)?,
            "cx.relation.delete" => self.delete_relation(event)?,
            "cx.relation.move" => self.move_relation(event)?,

            // Task operations (entity-type-specific wrappers)
            "cx.task.create" => self.create_entity(event)?,
            "cx.task.update" => self.update_entity(event)?,
            "cx.task.move" => self.update_entity(event)?,

            // View operations
            "cx.view.create" => self.create_view(event)?,
            "cx.view.update" => self.update_view(event)?,
            "cx.view.reconcile" => self.reconcile_view(event)?,

            // Space lifecycle — generic state reduction
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
        let fields = self.extract_optional_field::<BTreeMap<String, serde_json::Value>>(
            &event.content,
            "fields",
        );
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
        StateSnapshot {
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
        }
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
    fn compute_state_hash(&self) -> String {
        let payload = serde_json::json!({
            "space_id": self.space_id,
            "space_version": self.space_version,
            "frontier": self.frontier,
            "entities": self.entities,
            "relations": self.relations,
            "resolved_state": self.resolved_state,
            "messages": self.messages,
            "reactions": self.reactions,
            "tombstone_event_id": self.tombstone_event_id,
        });
        crate::canonical::canonical_sha256(&payload)
            .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)))
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
        let payload = serde_json::json!({
            "space_id": self.space_id,
            "space_version": self.space_version,
            "frontier": self.frontier,
            "entities": self.entities,
            "relations": self.relations,
            "resolved_state": self.resolved_state,
            "messages": self.messages,
            "reactions": self.reactions,
            "tombstone_event_id": self.tombstone_event_id,
        });
        Ok(crate::canonical::canonical_sha256(&payload)? == self.state_hash)
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
            actor_id,
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc,
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
            hlc: hlc2, // Later HLC
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
            actor_id,
            actor_seq: 2,
            created_at: chrono::Utc::now(),
            hlc: hlc1, // Earlier HLC
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
            actor_id: Did::new("did:uuid:admin_b").unwrap(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9d2e").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({ "state_key": "did:uuid:alice", "membership": "leave" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };
        let ban = Event {
            event_id: EventId::new("cx:event:01JS0M1B000000000000000000").unwrap(),
            kind: "cx.member.state".to_owned(),
            space_id,
            space_version: "1".to_owned(),
            actor_id: Did::new("did:uuid:admin_a").unwrap(),
            actor_seq: 1,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({ "state_key": "did:uuid:alice", "membership": "ban" }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        };

        state.apply_events(&[leave, ban]).unwrap();

        let resolved = state.resolved_state.get("cx.member.state|did:uuid:alice").unwrap();
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
        let actor_id = Did::new("did:uuid:moderator").unwrap();

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
            redacts: None,
            content: json!({
                "capability_id": "cap-chan-post",
                "subject": "did:uuid:alice",
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
}
