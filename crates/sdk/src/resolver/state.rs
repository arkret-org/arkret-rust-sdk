use super::*;
use super::snapshot::{
    canonicalize_flow_ref, deterministic_flow_surface_relation_id, membership_rank,
    object_state_from_str, patch_fields, patch_state, patch_string, state_hash_payload,
    state_merkle_root, StateHashInput,
};

/// Current state of a Space.
#[derive(Clone, Debug)]
pub struct SpaceState {
    /// Space ID
    pub space_id: SpaceId,
    /// Current space version
    pub space_version: String,
    /// Current flows by ID
    pub subjects: BTreeMap<String, Flow>,
    /// Current entities by ID
    pub entities: BTreeMap<String, Entity>,
    /// Current relations by ID
    pub relations: BTreeMap<String, Relation>,
    /// Generic resolved state events keyed by `kind|subject` (spec Phase 1).
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
    /// True when one or more events were marked `soft_failed` because
    /// their `auth_refs` were not yet materialized at apply time.
    /// Per `event-auth-state-resolution.md` §6.2, the projection MUST be
    /// treated as `read_only` while this is set: callers MUST NOT submit
    /// new writes that depend on unverified auth state.
    pub auth_incomplete: bool,
    /// Event IDs that landed but could not be auth-validated due to a
    /// missing `auth_refs` chain link. They live here, not in
    /// `state_events`, until the missing dependency is materialized.
    pub soft_failed: Vec<EventId>,
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
            subjects: BTreeMap::new(),
            entities: BTreeMap::new(),
            relations: BTreeMap::new(),
            resolved_state: BTreeMap::new(),
            messages: BTreeMap::new(),
            reactions: BTreeMap::new(),
            conflict_records: Vec::new(),
            frontier: Vec::new(),
            state_events: Vec::new(),
            auth_incomplete: false,
            soft_failed: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: None,
        }
    }

    /// Returns `true` when the projection MUST refuse new writes because at
    /// least one applied event is `soft_failed` due to missing `auth_refs`.
    pub fn is_read_only(&self) -> bool {
        self.auth_incomplete
    }

    /// Mark an event as `soft_failed` and flip the projection into the
    /// read-only `auth_incomplete` mode (event-auth-state-resolution.md §6.2).
    ///
    /// Callers SHOULD invoke this when an inbound event references
    /// `auth_refs` that have not yet been pulled. Once the missing
    /// dependency materialises, callers may invoke
    /// [`SpaceState::clear_soft_failed`] to retry reduction.
    pub fn mark_soft_failed(&mut self, event_id: EventId) {
        if !self.soft_failed.iter().any(|id| id == &event_id) {
            self.soft_failed.push(event_id);
        }
        self.auth_incomplete = true;
    }

    /// Drop a soft-failed event marker once its `auth_refs` have been
    /// resolved. Clears `auth_incomplete` only when the soft-failed list
    /// becomes empty.
    pub fn clear_soft_failed(&mut self, event_id: &EventId) {
        self.soft_failed.retain(|id| id != event_id);
        if self.soft_failed.is_empty() {
            self.auth_incomplete = false;
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
            // Preserve envelope fields required for chain validation per
            // event-auth-state-resolution.md §10; clear payload + unsigned.
            stored_event.content = serde_json::json!({});
            stored_event.unsigned.clear();
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

            OP_FLOW_CREATE => self.create_flow(event)?,
            OP_FLOW_UPDATE => self.update_flow(event)?,
            OP_FLOW_ARCHIVE => self.archive_flow(event)?,
            OP_FLOW_RESTORE => self.restore_flow(event)?,
            OP_FLOW_LINK_SURFACE => self.link_flow_surface(event)?,
            OP_FLOW_UNLINK_SURFACE => self.unlink_flow_surface(event)?,
            OP_FLOW_SET_PRIMARY_SURFACE => self.set_primary_flow_surface(event)?,
            OP_FLOW_MOVE | OP_FLOW_REORDER | OP_FLOW_CONVERT => self.touch_flow(event)?,

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
            | "cx.read.marker"
            // Account lifecycle (account-lifecycle.md §3 +
            // event-auth-state-resolution.md). The cell subject is the
            // account DID; the latest event wins per HLC ordering.
            | "cx.account.status"
            | "cx.account.deactivation"
            | "cx.account.erasure"
            // Moderation reports / franks (moderation.md §3).
            // Reports are state events keyed by `(target_ref, reporter)`;
            // franks bind a per-message receipt for E2EE accountability.
            | "cx.moderation.report"
            | "cx.moderation.frank" => self.reduce_generic_state_event(event)?,

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
        let content = self.extract_optional_field::<Value>(&event.content, "content");
        let fields =
            self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "fields");
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
        let from_ref = self.extract_optional_field(&event.content, "from_ref");
        let to_ref = self.extract_optional_field(&event.content, "to_ref");
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
            from_ref,
            to_ref,
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

    fn create_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id = self.extract_flow_id(&event.content)?;
        FlowId::new(flow_id.clone())?;
        let title = self.extract_field::<String>(&event.content, "title")?;
        let flow_kind = self.extract_field::<FlowKind>(&event.content, "flow_kind")?;
        let primary_track = self.extract_optional_field::<String>(&event.content, "primary_track");
        let tracks = self
            .extract_optional_field::<BTreeMap<String, crate::FlowTrackConfig>>(
                &event.content,
                "tracks",
            )
            .unwrap_or_default();
        let semantic_kind = self.extract_optional_field::<String>(&event.content, "semantic_kind");
        let brief = self.extract_optional_field(&event.content, "brief");
        let summary = self.extract_optional_field(&event.content, "summary");
        let fields = self.extract_fields(&event.content)?;
        let state = self
            .extract_optional_field::<String>(&event.content, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?
            .unwrap_or(crate::ObjectState::Active);
        let subject = Flow {
            schema: crate::FLOW_SCHEMA.to_owned(),
            id: flow_id,
            object_type: "flow".to_owned(),
            space_id: event.space_id.clone(),
            title,
            brief,
            summary,
            flow_kind,
            primary_track,
            tracks,
            semantic_kind,
            fields,
            state: Some(state),
            version: Some(0),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        };
        subject.validate_title()?;
        self.subjects.insert(subject.id.clone(), subject);
        Ok(())
    }

    fn update_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        let title = self.extract_optional_field::<String>(&event.content, "title");
        let brief = self.extract_optional_field::<String>(&event.content, "brief");
        let summary = self.extract_optional_field::<String>(&event.content, "summary");
        let fields =
            self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "fields");
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");
        let state = self
            .extract_optional_field::<String>(&event.content, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?;
        let patched_state = patch_state(&patch).transpose()?;
        let primary_track = self
            .extract_optional_field::<String>(&event.content, "primary_track")
            .or_else(|| patch_string(&patch, "primary_track"));
        let tracks = self
            .extract_optional_field::<BTreeMap<String, crate::FlowTrackConfig>>(
                &event.content,
                "tracks",
            )
            .or_else(|| {
                // Patch path is a JSON object map: track_name → FlowTrackConfig.
                patch.as_ref().and_then(|p| p.get("tracks")).and_then(|v| {
                    serde_json::from_value::<BTreeMap<String, crate::FlowTrackConfig>>(v.clone())
                        .ok()
                })
            });
        let semantic_kind = self
            .extract_optional_field::<String>(&event.content, "semantic_kind")
            .or_else(|| patch_string(&patch, "semantic_kind"));

        let subject = self
            .subjects
            .get_mut(&flow_id_str)
            .ok_or_else(|| Error::Protocol(format!("flow not found: {}", flow_id_str)))?;

        if let Some(title) = title.or_else(|| patch_string(&patch, "title")) {
            subject.title = title;
        }
        if let Some(brief) = brief.or_else(|| patch_string(&patch, "brief")) {
            subject.brief = Some(brief);
        }
        if let Some(summary) = summary.or_else(|| patch_string(&patch, "summary")) {
            subject.summary = Some(summary);
        }
        if let Some(primary_track) = primary_track {
            subject.primary_track = Some(primary_track);
        }
        if let Some(tracks) = tracks {
            subject.tracks = tracks;
        }
        if let Some(semantic_kind) = semantic_kind {
            subject.semantic_kind = Some(semantic_kind);
        }
        if let Some(fields) = fields.or_else(|| patch_fields(&patch)) {
            subject.fields = fields;
        }
        if let Some(state) = state.or(patched_state) {
            subject.state = Some(state);
        }
        subject.validate_title()?;
        subject.updated_by = Some(event.actor_id.clone());
        subject.updated_at = Some(event.created_at);
        if let Some(version) = subject.version {
            subject.version = Some(version + 1);
        }
        Ok(())
    }

    fn archive_flow(&mut self, event: &Event) -> Result<()> {
        self.set_flow_state(event, crate::ObjectState::Archived)
    }

    fn restore_flow(&mut self, event: &Event) -> Result<()> {
        self.set_flow_state(event, crate::ObjectState::Active)
    }

    fn set_flow_state(&mut self, event: &Event, state: crate::ObjectState) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&flow_id_str) {
            subject.state = Some(state);
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
            if let Some(version) = subject.version {
                subject.version = Some(version + 1);
            }
        }
        Ok(())
    }

    fn touch_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&flow_id_str) {
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
            if let Some(version) = subject.version {
                subject.version = Some(version + 1);
            }
        }
        Ok(())
    }

    fn link_flow_surface(&mut self, event: &Event) -> Result<()> {
        let relation = self.flow_surface_relation(event, true)?;
        self.relations.insert(relation.id.as_str().to_owned(), relation);
        Ok(())
    }

    fn unlink_flow_surface(&mut self, event: &Event) -> Result<()> {
        let flow_id = self.extract_flow_id(&event.content)?;
        let surface_ref = self.extract_field::<String>(&event.content, "surface_ref")?;
        let relation_id = self.extract_optional_field::<String>(&event.content, "relation_id");
        let surface_role = self.extract_optional_field::<String>(&event.content, "surface_role");
        let matching_id = relation_id.or_else(|| {
            self.relations
                .iter()
                .find(|(_, relation)| {
                    relation.relation_kind == crate::RelationKind::HasSurface
                        && relation.from_ref.as_deref() == Some(flow_id.as_str())
                        && relation.to_ref.as_deref() == Some(surface_ref.as_str())
                        && surface_role.as_ref().is_none_or(|role| {
                            relation.fields.get("surface_role").and_then(Value::as_str)
                                == Some(role.as_str())
                        })
                })
                .map(|(id, _)| id.clone())
        });
        if let Some(relation_id) = matching_id
            && let Some(relation) = self.relations.get_mut(&relation_id)
        {
            relation.state = Some(crate::RelationState::Deleted);
        }
        Ok(())
    }

    fn set_primary_flow_surface(&mut self, event: &Event) -> Result<()> {
        let flow_id = self.extract_flow_id(&event.content)?;
        let surface_role = self.extract_optional_field::<String>(&event.content, "surface_role");
        for relation in self.relations.values_mut() {
            if relation.relation_kind == crate::RelationKind::HasSurface
                && relation.from_ref.as_deref() == Some(flow_id.as_str())
                && surface_role.as_ref().is_none_or(|role| {
                    relation.fields.get("surface_role").and_then(Value::as_str)
                        == Some(role.as_str())
                })
            {
                relation.fields.insert("primary".to_owned(), Value::Bool(false));
            }
        }
        let mut relation = self.flow_surface_relation(event, true)?;
        relation.fields.insert("primary".to_owned(), Value::Bool(true));
        self.relations.insert(relation.id.as_str().to_owned(), relation);
        Ok(())
    }

    fn flow_surface_relation(&self, event: &Event, active: bool) -> Result<Relation> {
        let flow_id = self.extract_flow_id(&event.content)?;
        if !self.subjects.contains_key(&flow_id) {
            return Err(Error::Protocol(format!("flow not found: {}", flow_id)));
        }
        let surface_ref = self.extract_field::<String>(&event.content, "surface_ref")?;
        let relation_id = self
            .extract_optional_field::<String>(&event.content, "relation_id")
            .unwrap_or_else(|| deterministic_flow_surface_relation_id(&event.content));
        let mut fields = BTreeMap::new();
        if let Some(surface_role) =
            self.extract_optional_field::<String>(&event.content, "surface_role")
        {
            fields.insert("surface_role".to_owned(), Value::String(surface_role));
        }
        if let Some(primary) = self.extract_optional_field::<bool>(&event.content, "primary") {
            fields.insert("primary".to_owned(), Value::Bool(primary));
        }

        Ok(Relation {
            schema: crate::RELATION_SCHEMA.to_owned(),
            id: RelationId::new(relation_id)?,
            object_type: "relation".to_owned(),
            space_id: event.space_id.clone(),
            relation_kind: crate::RelationKind::HasSurface,
            from_ref: Some(flow_id),
            to_ref: Some(surface_ref),
            from_entity_id: None,
            from_actor_id: None,
            from_space_id: None,
            to_entity_id: None,
            to_actor_id: None,
            to_space_id: None,
            fields,
            state: Some(if active {
                crate::RelationState::Active
            } else {
                crate::RelationState::Deleted
            }),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
        })
    }

    /// Move a relation by updating its endpoints.
    fn move_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        let new_to = self.extract_optional_field::<String>(&event.content, "to_entity_id");
        let new_from = self.extract_optional_field::<String>(&event.content, "from_entity_id");
        let new_to_ref = self.extract_optional_field::<String>(&event.content, "to_ref");
        let new_from_ref = self.extract_optional_field::<String>(&event.content, "from_ref");

        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            if let Some(new_to) = new_to {
                relation.to_entity_id = Some(EntityId::new(new_to)?);
            }
            if let Some(new_from) = new_from {
                relation.from_entity_id = Some(EntityId::new(new_from)?);
            }
            if let Some(new_to_ref) = new_to_ref {
                relation.to_ref = Some(new_to_ref);
            }
            if let Some(new_from_ref) = new_from_ref {
                relation.from_ref = Some(new_from_ref);
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
        let subject = self.subject_for_event(event)?;
        let family = match event.kind.as_str() {
            "cx.capability.grant" | "cx.capability.delegate" | "cx.capability.revoke" => {
                "cx.capability"
            }
            "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => "cx.invite",
            "cx.space.policy" | "cx.policy.set" => "cx.policy",
            other => other,
        };
        let map_key = format!("{}|{}", family, subject);
        let candidate = ResolvedStateEvent {
            kind: event.kind.clone(),
            subject,
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
    ///
    /// Preserves the canonical envelope fields required for actor-chain
    /// validation per `event-auth-state-resolution.md` §10 (notably
    /// `actor_seq`, `prev_refs`, `auth_refs`, `hlc`, `created_at` and the
    /// envelope digest binding); clears `content` (the payload) and
    /// `unsigned` (server-added hints). MUST NOT touch `event_id` or
    /// `proofs` — these are needed to verify the redaction itself.
    fn redact_event(&mut self, event_id: &EventId) -> Result<()> {
        self.redacted_events.insert(event_id.clone());
        if let Some(event) = self.processed_events.get_mut(event_id) {
            event.content = serde_json::json!({});
            event.unsigned.clear();
        }
        for event in &mut self.state_events {
            if &event.event_id == event_id {
                event.content = serde_json::json!({});
                event.unsigned.clear();
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
    fn extract_entity_id(&self, content: &Value) -> Result<String> {
        self.extract_field(content, "id")
    }

    /// Extract flow_id from event content.
    fn extract_flow_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field::<String>(content, "flow_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .map(|value| canonicalize_flow_ref(&value))
            .ok_or_else(|| Error::Protocol("flow event requires flow_id".to_owned()))
    }

    /// Extract relation_id from event content.
    fn extract_relation_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field(content, "relation_id")
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| Error::Protocol("relation event requires relation_id or id".to_owned()))
    }

    /// Extract a required field from event content.
    fn extract_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &Value,
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
        content: &Value,
        field: &str,
    ) -> Option<T> {
        let obj = content.as_object()?;
        let value = obj.get(field)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Extract fields map from event content.
    fn extract_fields(&self, content: &Value) -> Result<BTreeMap<String, Value>> {
        Ok(self.extract_optional_field(content, "fields").unwrap_or_default())
    }

    /// Derive the cell subject for an event from typed payload fields,
    /// per the spec event-kind-registry's `cell_subject` declaration.
    fn subject_for_event(&self, event: &Event) -> Result<String> {
        match event.kind.as_str() {
            "cx.member.state" => self
                .extract_optional_field::<String>(&event.content, "actor_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "principal_id"))
                .or_else(|| self.extract_optional_field::<String>(&event.content, "member_id"))
                .ok_or_else(|| {
                    Error::Protocol("member state requires payload.actor_id".to_owned())
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
            subjects: self.subjects.clone(),
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
            .and_then(Value::as_array)
            .is_some_and(|actions| {
                actions.iter().any(|candidate| {
                    candidate.as_str() == Some(action) || candidate.as_str() == Some("*")
                })
            })
    }

    /// Compute state hash for verification.
    pub fn compute_state_hash(&self) -> String {
        canonical_sha256(&state_hash_payload(StateHashInput {
            space_id: &self.space_id,
            space_version: &self.space_version,
            frontier: &self.frontier,
            subjects: &self.subjects,
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
            subjects: &self.subjects,
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
            subjects: snapshot.subjects,
            entities: snapshot.entities,
            relations: snapshot.relations,
            resolved_state: snapshot.resolved_state,
            messages: snapshot.messages,
            reactions: snapshot.reactions,
            conflict_records: Vec::new(),
            frontier: snapshot.frontier,
            state_events: Vec::new(),
            auth_incomplete: false,
            soft_failed: Vec::new(),
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

