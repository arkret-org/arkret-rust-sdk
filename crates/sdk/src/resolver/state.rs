use super::snapshot::{
    StateHashInput, canonicalize_flow_ref, membership_rank, object_state_from_str, patch_fields,
    patch_state, patch_string, space_state_from_str, state_digest_payload, state_merkle_root,
};
use super::*;
use crate::events::kinds::FLOW_TRACKS_UPDATE as OP_FLOW_TRACKS_UPDATE;

/// Current reducer state of a Realm.
#[derive(Clone, Debug)]
pub struct RealmState {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Reducer profile used for this state.
    pub reducer_profile: String,
    /// Current flows by ID
    pub subjects: BTreeMap<String, Flow>,
    /// Current Morph objects by ID.
    pub morphs: BTreeMap<String, Morph>,
    /// Current Space (container) objects by ID.
    pub spaces: BTreeMap<String, Space>,
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
    /// Realm state events.
    pub state_events: Vec<Event>,
    /// True when one or more events were marked `soft_failed` because
    /// their authorization refs were not yet materialized at apply time.
    /// Per `event-auth-state-resolution.md` §6.2, the projection MUST be
    /// treated as `read_only` while this is set: callers MUST NOT submit
    /// new writes that depend on unverified auth state.
    pub auth_incomplete: bool,
    /// Event IDs that landed but could not be auth-validated due to a
    /// missing `refs[role=authorized_by]` chain link. They live here, not in
    /// `state_events`, until the missing dependency is materialized.
    pub soft_failed: Vec<EventId>,
    processed_events: BTreeMap<EventId, Event>,
    redacted_events: BTreeSet<EventId>,
    tombstone_event_id: Option<EventId>,
}

impl RealmState {
    /// Create a new empty Realm state.
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            reducer_profile: REDUCER_SNAPSHOT_PROFILE.to_owned(),
            subjects: BTreeMap::new(),
            morphs: BTreeMap::new(),
            spaces: BTreeMap::new(),
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
    /// least one applied event is `soft_failed` due to missing authorization refs.
    pub fn is_read_only(&self) -> bool {
        self.auth_incomplete
    }

    /// Mark an event as `soft_failed` and flip the projection into the
    /// read-only `auth_incomplete` mode (event-auth-state-resolution.md §6.2).
    ///
    /// Callers SHOULD invoke this when an inbound event references
    /// `refs[role=authorized_by]` that have not yet been pulled. Once the missing
    /// dependency materialises, callers may invoke
    /// [`RealmState::clear_soft_failed`] to retry reduction.
    pub fn mark_soft_failed(&mut self, event_id: EventId) {
        if !self.soft_failed.iter().any(|id| id == &event_id) {
            self.soft_failed.push(event_id);
        }
        self.auth_incomplete = true;
    }

    /// Drop a soft-failed event marker once its authorization refs have been
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
                return Err(Error::Protocol(format!(
                    "missing causal dependency: {}",
                    prev_ref
                )));
            }
        }

        if self.tombstone_event_id.is_some() && !Self::is_maintenance_event(event) {
            return Err(Error::Protocol("realm is destroyed".to_owned()));
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
        self.processed_events
            .insert(stored_event.event_id.clone(), stored_event);

        // Update frontier
        self.update_frontier(event);

        Ok(())
    }

    /// Process the content of an event and update state.
    fn process_event_content(&mut self, event: &Event) -> Result<()> {
        match event.kind.as_str() {
            OP_FLOW_CREATE => self.create_flow(event)?,
            OP_FLOW_UPDATE => self.update_flow(event)?,
            OP_FLOW_ARCHIVE => self.archive_flow(event)?,
            OP_FLOW_RESTORE => self.restore_flow(event)?,
            OP_FLOW_MOVE | OP_FLOW_REORDER => self.touch_flow(event)?,
            OP_FLOW_TRACKS_UPDATE => self.update_flow_tracks(event)?,

            OP_MORPH_CREATE => self.create_morph(event)?,
            OP_MORPH_UPDATE => self.update_morph(event)?,
            OP_MORPH_ARCHIVE => self.archive_morph(event)?,
            OP_MORPH_RESTORE => self.restore_morph(event)?,

            OP_SPACE_CREATE => self.create_space(event)?,
            OP_SPACE_UPDATE => self.update_space(event)?,
            OP_SPACE_PARENT => self.set_space_parent(event)?,
            OP_SPACE_ARCHIVE => self.archive_space(event)?,
            OP_SPACE_RESTORE => self.restore_space(event)?,
            OP_SPACE_TOMBSTONE => self.tombstone_space(event)?,

            // Relation lifecycle
            OP_RELATION_CREATE => self.create_relation(event)?,
            OP_RELATION_TOMBSTONE => self.delete_relation(event)?,
            OP_CONTAINER_MOVE_ITEM => self.move_relation(event)?,

            // View operations
            OP_VIEW_CREATE => self.create_view(event)?,
            OP_VIEW_UPDATE => self.update_view(event)?,
            OP_VIEW_RECONCILE => self.reconcile_view(event)?,

            // Realm lifecycle - generic state reduction. Container-level
            // (`ck.space.*`) lifecycle is covered by the OP_SPACE_* arms above.
            "ck.realm.create"
            | "ck.realm.update"
            | "ck.realm.organization"
            | "ck.realm.link"
            | "ck.realm.inheritance_policy"
            | "ck.realm.join_rule"
            | "ck.realm.history_visibility"
            | "ck.realm.discovery"
            | "ck.realm.archive"
            | "ck.realm.freeze"
            | "ck.realm.destroy" => self.reduce_realm_lifecycle_event(event)?,

            // Member / capability / invite / policy / read-marker state
            "ck.member.state"
            | "ck.capability.grant"
            | "ck.capability.delegate"
            | "ck.capability.revoke"
            | "ck.realm.policy"
            | "ck.policy.set"
            | "ck.invite.create"
            | "ck.invite.cancel"
            | "ck.invite.accept"
            | "ck.read_cursor.advance"
            // Account lifecycle (account-lifecycle.md §3 +
            // event-auth-state-resolution.md). The cell subject is the
            // account DID; the latest event wins per HLC ordering.
            | "ck.account.status"
            | "ck.account.deactivation"
            | "ck.account.erasure"
            // Moderation reports / franks (moderation.md §3).
            // Reports are state events keyed by `(target_ref, reporter)`;
            // franks bind a per-message receipt for E2EE accountability.
            | "ck.self.moderation.report"
            | "ck.moderation.franking_proof" => self.reduce_generic_state_event(event)?,

            // Message timeline
            "ck.message.create" => self.create_message(event)?,
            "ck.message.revise" => self.revise_message(event)?,
            "ck.message.redact" => self.redact_message(event)?,

            // Reactions
            "ck.reaction.add" | "ck.reaction.remove" => self.reduce_reaction(event)?,

            // Realm upgrade
            "ck.realm.upgrade" => self.upgrade_realm(event)?,

            // Generic redaction. Round 11 (2026-05-16): also flips Flow /
            // Morph subject state to Redacted per spec common-fields.md
            // §5.1 when the event content carries an `object_ref` pointing
            // to a `ck:flow:` / `ck:morph:` typed-id. State-machine guard
            // rejects already-terminal source with `<kind>_already_terminal`.
            // Space is excluded — spec note "Space has no redacted state" routes
            // Space removal through `ck.space.tombstone` only.
            "ck.redaction" => {
                self.redact_object_for_event(event)?;
                if let Some(redacted_ref) = &event.redacts {
                    self.redact_event(redacted_ref)?;
                }
            }

            _ => {
                // Unknown event types do not affect the local reducer state.
            }
        }

        Ok(())
    }

    fn create_morph(&mut self, event: &Event) -> Result<()> {
        let object = event.content.get("object").unwrap_or(&event.content);
        reject_legacy_morph_metadata_fields(object)?;
        let morph_id_str = self.extract_morph_id(object)?;
        let morph_id = MorphId::new(morph_id_str.clone())?;
        let morph_type = self.extract_field::<String>(object, "morph_type")?;
        let facets = self
            .extract_optional_field::<BTreeMap<String, Value>>(object, "facets")
            .unwrap_or_default();
        let metadata = self.extract_optional_field::<crate::MorphMetadata>(object, "metadata");
        let encrypted_metadata = self.extract_optional_field(object, "encrypted_metadata");
        let content = self.extract_optional_field(object, "content");
        let encrypted_content = self.extract_optional_field(object, "encrypted_content");
        let fields = self.extract_fields(object)?;
        let state = self
            .extract_optional_field::<String>(object, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?
            .unwrap_or(crate::ObjectState::Active);

        let scope_circle_id =
            self.extract_optional_field::<cokret_core::CircleId>(object, "scope_circle_id");
        let schema_refs = self.extract_field::<Vec<String>>(object, "schema_refs")?;
        validate_morph_schema_refs(&schema_refs)?;
        let morph = Morph {
            id: morph_id,
            schema: crate::MORPH_SCHEMA.to_owned(),
            realm_id: event.realm_id.clone(),
            scope_circle_id,
            schema_refs,
            morph_type,
            facets,
            metadata,
            encrypted_metadata,
            content,
            encrypted_content,
            fields,
            state: Some(state),
            state_changed_at: self.extract_optional_field(object, "state_changed_at"),
            stage: self
                .extract_optional_field::<crate::ObjectStage>(object, "stage")
                .unwrap_or(crate::ObjectStage::Draft),
            stage_changed_at: self.extract_optional_field(object, "stage_changed_at"),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            extra: BTreeMap::new(),
        };
        morph.validate_morph_type(&[])?;
        self.morphs.insert(morph_id_str, morph);
        Ok(())
    }

    fn update_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(morph) = self.morphs.get(&morph_id_str)
            && morph.state != Some(crate::ObjectState::Active)
        {
            return Err(Error::Protocol("morph_not_active".to_owned()));
        }
        reject_legacy_morph_metadata_fields(&event.content)?;
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");
        reject_legacy_morph_patch_fields(&patch)?;
        let metadata =
            self.extract_optional_field::<crate::MorphMetadata>(&event.content, "metadata");
        let encrypted_metadata =
            self.extract_optional_field::<Value>(&event.content, "encrypted_metadata");
        let title = metadata
            .as_ref()
            .and_then(|metadata| metadata.title.clone())
            .or_else(|| patch_metadata_string(&patch, "title"));
        let summary = metadata
            .as_ref()
            .and_then(|metadata| metadata.summary.clone())
            .or_else(|| patch_metadata_string(&patch, "summary"));
        let content = self
            .extract_optional_field::<Value>(&event.content, "content")
            .or_else(|| {
                patch
                    .as_ref()
                    .and_then(|patch| patch.get("content").cloned())
            });
        let encrypted_content = self
            .extract_optional_field::<Value>(&event.content, "encrypted_content")
            .or_else(|| {
                patch
                    .as_ref()
                    .and_then(|patch| patch.get("encrypted_content").cloned())
            });
        let fields = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.content, "fields")
            .or_else(|| patch_fields(&patch));
        let facets = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.content, "facets")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("facets")
                        .and_then(|value| serde_json::from_value(value.clone()).ok())
                })
            });
        let state = self
            .extract_optional_field::<String>(&event.content, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?
            .or(patch_state(&patch).transpose()?);

        let morph = self
            .morphs
            .get_mut(&morph_id_str)
            .ok_or_else(|| Error::Protocol(format!("morph not found: {}", morph_id_str)))?;
        if let Some(metadata) = metadata {
            morph.metadata = Some(metadata);
        }
        if let Some(title) = title {
            morph
                .metadata
                .get_or_insert_with(crate::MorphMetadata::default)
                .title = Some(title);
        }
        if let Some(summary) = summary {
            morph
                .metadata
                .get_or_insert_with(crate::MorphMetadata::default)
                .summary = Some(summary);
        }
        if let Some(encrypted_metadata) = encrypted_metadata {
            morph.encrypted_metadata = Some(encrypted_metadata);
            morph.metadata = None;
        }
        if let Some(content) = content {
            morph.content = Some(content);
            morph.encrypted_content = None;
        }
        if let Some(encrypted_content) = encrypted_content {
            morph.encrypted_content = Some(encrypted_content);
            morph.content = None;
        }
        if let Some(fields) = fields {
            morph.fields = fields;
        }
        if let Some(facets) = facets {
            morph.facets = facets;
        }
        if let Some(state) = state {
            morph.state = Some(state);
        }
        morph.updated_by = Some(event.actor_id.clone());
        morph.updated_at = Some(event.created_at);
        Ok(())
    }

    fn set_morph_state(&mut self, event: &Event, state: crate::ObjectState) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        if let Some(morph) = self.morphs.get_mut(&morph_id_str) {
            morph.state = Some(state);
            morph.updated_by = Some(event.actor_id.clone());
            morph.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    // Reducer for `ck.morph.archive`: validate current state == active per
    // cokret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Deleted / Redacted / unset MUST be rejected with
    // `morph_not_active`; unknown Morph is tolerated (causal / backfill).
    fn archive_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        let Some(morph) = self.morphs.get(&morph_id_str) else {
            return Ok(());
        };
        if morph.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("morph_not_active".to_owned()));
        }
        self.set_morph_state(event, crate::ObjectState::Archived)
    }

    // Reducer for `ck.morph.restore`: same state-machine contract as
    // `restore_flow` / `restore_space` — current state MUST == archived.
    // Active / Deleted / Redacted / unset → `morph_not_archived`. Unknown
    // Morph is tolerated for causal / backfill ordering. Morph has no
    // `state_changed_at` field (unlike Flow / Space), so on success we
    // only flip `state` and updated_by/at — matching set_morph_state.
    fn restore_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        let Some(morph) = self.morphs.get(&morph_id_str) else {
            return Ok(());
        };
        if morph.state != Some(crate::ObjectState::Archived) {
            return Err(Error::Protocol("morph_not_archived".to_owned()));
        }
        self.set_morph_state(event, crate::ObjectState::Active)
    }

    fn create_space(&mut self, event: &Event) -> Result<()> {
        let object = event.content.get("object").unwrap_or(&event.content);
        let space_id = self
            .extract_optional_field::<String>(object, "id")
            .ok_or_else(|| Error::Protocol("container object requires id".to_owned()))?;
        let id = SpaceId::new(space_id.clone())?;
        let realm_id = self.extract_field::<RealmId>(object, "realm_id")?;
        let kind = self.extract_field::<String>(object, "kind")?;
        let title = self.extract_field::<String>(object, "title")?;
        let state = self
            .extract_optional_field::<String>(object, "state")
            .map(|state| space_state_from_str(&state))
            .transpose()?
            .unwrap_or(crate::model::SpaceState::Active);

        let space = Space {
            schema: crate::SPACE_SCHEMA.to_owned(),
            id,
            realm_id,
            default_realm_id: self.extract_optional_field(object, "default_realm_id"),
            parent_space_id: self.extract_optional_field(object, "parent_space_id"),
            kind,
            title,
            summary: self.extract_optional_field(object, "summary"),
            rank: self.extract_optional_field(object, "rank"),
            schema_refs: self
                .extract_optional_field(object, "schema_refs")
                .unwrap_or_default(),
            fields: self.extract_fields(object)?,
            labels: self
                .extract_optional_field(object, "labels")
                .unwrap_or_default(),
            avatar_blob_ref: self.extract_optional_field(object, "avatar_blob_ref"),
            state: Some(state),
            state_changed_at: self.extract_optional_field(object, "state_changed_at"),
            scope_circle_id: self.extract_optional_field(object, "scope_circle_id"),
            default_scope_circle_id: self.extract_optional_field(object, "default_scope_circle_id"),
            child_scope_policy: object
                .get("child_scope_policy")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            created_by: self
                .extract_optional_field(object, "created_by")
                .unwrap_or_else(|| event.actor_id.clone()),
            created_at: self
                .extract_optional_field(object, "created_at")
                .unwrap_or(event.created_at),
            updated_by: self.extract_optional_field(object, "updated_by"),
            updated_at: self.extract_optional_field(object, "updated_at"),
            extra: BTreeMap::new(),
        };
        space.validate()?;
        self.spaces.insert(space_id, space);
        Ok(())
    }

    fn update_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(space) = self.spaces.get(&space_id)
            && space.state != Some(crate::model::SpaceState::Active)
        {
            return Err(Error::Protocol("space_not_active".to_owned()));
        }
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");

        let title = self
            .extract_optional_field::<String>(&event.content, "title")
            .or_else(|| patch_string(&patch, "title"));
        let summary = self
            .extract_optional_field::<String>(&event.content, "summary")
            .or_else(|| patch_string(&patch, "summary"));
        let kind = self
            .extract_optional_field::<String>(&event.content, "kind")
            .or_else(|| patch_string(&patch, "kind"));
        let rank = self
            .extract_optional_field::<String>(&event.content, "rank")
            .or_else(|| patch_string(&patch, "rank"));
        let fields = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.content, "fields")
            .or_else(|| patch_fields(&patch));
        let schema_refs = self
            .extract_optional_field::<Vec<String>>(&event.content, "schema_refs")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("schema_refs")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let labels = self
            .extract_optional_field::<Vec<String>>(&event.content, "labels")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("labels")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let avatar_blob_ref = self
            .extract_optional_field(&event.content, "avatar_blob_ref")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("avatar_blob_ref")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let state = self
            .extract_optional_field::<String>(&event.content, "state")
            .or_else(|| patch_string(&patch, "state"))
            .map(|state| space_state_from_str(&state))
            .transpose()?;

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| Error::Protocol(format!("space not found: {}", space_id)))?;
        if let Some(title) = title {
            space.title = title;
        }
        if let Some(summary) = summary {
            space.summary = Some(summary);
        }
        if let Some(kind) = kind {
            space.kind = kind;
        }
        if let Some(rank) = rank {
            space.rank = Some(rank);
        }
        if let Some(fields) = fields {
            space.fields = fields;
        }
        if let Some(schema_refs) = schema_refs {
            space.schema_refs = schema_refs;
        }
        if let Some(labels) = labels {
            space.labels = labels;
        }
        if let Some(avatar_blob_ref) = avatar_blob_ref {
            space.avatar_blob_ref = Some(avatar_blob_ref);
        }
        if let Some(state) = state {
            space.state = Some(state);
            space.state_changed_at = Some(event.created_at);
        }
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        space.validate()?;
        Ok(())
    }

    fn set_space_parent(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let parent_space_id_str = self
            .extract_optional_field::<String>(&event.content, "parent_space_id")
            .ok_or_else(|| {
                Error::Protocol("space parent event requires parent_space_id".to_owned())
            })?;
        let parent_space_id = SpaceId::new(parent_space_id_str)?;
        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| Error::Protocol(format!("space not found: {}", space_id)))?;
        space.parent_space_id = Some(parent_space_id);
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        space.validate()?;
        Ok(())
    }

    fn set_space_state(&mut self, event: &Event, state: crate::model::SpaceState) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        if let Some(space) = self.spaces.get_mut(&space_id) {
            space.state = Some(state);
            space.state_changed_at = Some(event.created_at);
            space.updated_by = Some(event.actor_id.clone());
            space.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    // Reducer for `ck.space.archive`: validate current state == active per
    // cokret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Tombstoned / unset MUST be rejected with `space_not_active`;
    // unknown Space is tolerated (causal / backfill).
    fn archive_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::model::SpaceState::Active) {
            return Err(Error::Protocol("space_not_active".to_owned()));
        }
        self.set_space_state(event, crate::model::SpaceState::Archived)
    }

    // Reducer for `ck.space.tombstone`: validate current state ∈
    // {Active, Archived} per cokret-spec common-fields.md §5.1. Tombstoned /
    // unset MUST be rejected with `space_already_terminal`; unknown Space is
    // tolerated (causal / backfill).
    fn tombstone_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        match space.state {
            Some(crate::model::SpaceState::Active) | Some(crate::model::SpaceState::Archived) => {}
            _ => return Err(Error::Protocol("space_already_terminal".to_owned())),
        }
        self.set_space_state(event, crate::model::SpaceState::Tombstoned)
    }

    // Reducer for `ck.space.restore`: validate current state == archived per
    // cokret-spec space-and-space.md §4.4. Active / Tombstoned / unset MUST
    // be rejected with `space_not_archived`; unknown Space is tolerated
    // (causal / backfill not yet caught up — mirrors set_space_state).
    fn restore_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get_mut(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::model::SpaceState::Archived) {
            return Err(Error::Protocol("space_not_archived".to_owned()));
        }
        space.state = Some(crate::model::SpaceState::Active);
        space.state_changed_at = Some(event.created_at);
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        Ok(())
    }

    /// Create a new relation.
    fn create_relation(&mut self, event: &Event) -> Result<()> {
        let object = event
            .content
            .get("relation")
            .or_else(|| event.content.get("object"))
            .unwrap_or(&event.content);
        let relation_id_str = self.extract_relation_id(object)?;
        let relation_id = RelationId::new(relation_id_str.clone())?;
        let relation_kind = self.extract_field(object, "relation_kind")?;
        let from_ref = self.extract_field(object, "from_ref")?;
        let to_ref = self.extract_field(object, "to_ref")?;
        let rank = self.extract_optional_field(object, "rank");
        let fields = self.extract_fields(object)?;
        let scope_circle_id =
            self.extract_optional_field::<cokret_core::CircleId>(object, "scope_circle_id");
        let effective_scope =
            self.extract_optional_field::<cokret_core::EffectiveScope>(object, "effective_scope");

        let relation = Relation {
            schema: "ck.schema.relation.v1".to_owned(),
            id: relation_id,
            realm_id: event.realm_id.clone(),
            scope_circle_id,
            effective_scope,
            relation_kind,
            from_ref,
            to_ref,
            rank,
            fields,
            state: Some(crate::RelationState::Active),
            state_changed_at: None,
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
        };

        self.relations.insert(relation_id_str, relation);
        Ok(())
    }

    /// Delete a relation.
    fn delete_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            relation.state = Some(crate::RelationState::Tombstoned);
            relation.state_changed_at = Some(event.created_at);
        }
        Ok(())
    }

    fn create_flow(&mut self, event: &Event) -> Result<()> {
        let object = event.content.get("object").unwrap_or(&event.content);
        let flow_id_str = self.extract_flow_id(object)?;
        let flow_id = FlowId::new(flow_id_str.clone())?;
        reject_legacy_flow_metadata_fields(object)?;
        let metadata = self
            .extract_optional_field::<crate::FlowMetadata>(object, "metadata")
            .unwrap_or_default();
        let tracks = self
            .extract_optional_field::<BTreeMap<String, crate::FlowTrackConfig>>(object, "tracks")
            .unwrap_or_else(|| {
                let mut tracks = BTreeMap::new();
                tracks.insert(
                    crate::FLOW_TRACK_NAME_SYNTHESIS.to_owned(),
                    crate::FlowTrackConfig::synthesis(),
                );
                tracks
            });
        let body = self.extract_optional_field(object, "content");
        let encrypted_content = self.extract_optional_field(object, "encrypted_content");
        let encrypted_metadata = self.extract_optional_field(object, "encrypted_metadata");
        let scope_circle_id =
            self.extract_optional_field::<cokret_core::CircleId>(object, "scope_circle_id");
        let state = self
            .extract_optional_field::<String>(object, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?
            .unwrap_or(crate::ObjectState::Active);
        let subject = Flow {
            id: flow_id,
            schema: crate::FLOW_SCHEMA.to_owned(),
            realm_id: event.realm_id.clone(),
            scope_circle_id,
            metadata: Some(metadata),
            encrypted_metadata,
            body,
            encrypted_content,
            tracks,
            state: Some(state),
            state_changed_at: None,
            stage: self
                .extract_optional_field::<crate::ObjectStage>(object, "stage")
                .unwrap_or(crate::ObjectStage::Draft),
            stage_changed_at: self.extract_optional_field(object, "stage_changed_at"),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        };
        subject.validate_title()?;
        self.subjects.insert(flow_id_str, subject);
        Ok(())
    }

    fn update_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        // Spec common-fields.md §5.1 final paragraph: update on a non-active
        // object MUST fail — otherwise an edit would silently revive an
        // archived / tombstoned / redacted Flow, conflicting with the
        // `ck.flow.restore` semantic. Unknown Flow is tolerated below
        // (extract step succeeds, lookup returns None, current code returns
        // Err with "flow not found" — this guard runs before that).
        if let Some(subject) = self.subjects.get(&flow_id_str)
            && subject.state != Some(crate::ObjectState::Active)
        {
            return Err(Error::Protocol("flow_not_active".to_owned()));
        }
        reject_legacy_flow_metadata_fields(&event.content)?;
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");
        reject_legacy_flow_patch_fields(&patch)?;
        let metadata =
            self.extract_optional_field::<crate::FlowMetadata>(&event.content, "metadata");
        let encrypted_metadata =
            self.extract_optional_field::<Value>(&event.content, "encrypted_metadata");
        let body = self.extract_optional_field::<Value>(&event.content, "content");
        let encrypted_content =
            self.extract_optional_field::<Value>(&event.content, "encrypted_content");
        let fields = metadata.as_ref().map(|metadata| metadata.fields.clone());
        let state = self
            .extract_optional_field::<String>(&event.content, "state")
            .map(|state| object_state_from_str(&state))
            .transpose()?;
        let patched_state = patch_state(&patch).transpose()?;
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
        let patched_body = patch
            .as_ref()
            .and_then(|patch| patch.get("content").cloned());
        let patched_encrypted_content = patch
            .as_ref()
            .and_then(|patch| patch.get("encrypted_content").cloned());

        let subject = self
            .subjects
            .get_mut(&flow_id_str)
            .ok_or_else(|| Error::Protocol(format!("flow not found: {}", flow_id_str)))?;

        if let Some(metadata) = metadata {
            subject.metadata = Some(metadata);
        }
        if let Some(title) = patch_metadata_string(&patch, "title") {
            subject
                .metadata
                .get_or_insert_with(crate::FlowMetadata::default)
                .title = Some(title);
        }
        if let Some(summary) = patch_metadata_string(&patch, "summary") {
            subject
                .metadata
                .get_or_insert_with(crate::FlowMetadata::default)
                .summary = Some(summary);
        }
        if let Some(fields) = fields.or_else(|| patch_metadata_fields(&patch)) {
            subject
                .metadata
                .get_or_insert_with(crate::FlowMetadata::default)
                .fields = fields;
        }
        if let Some(encrypted_metadata) = encrypted_metadata {
            subject.encrypted_metadata = Some(encrypted_metadata);
            subject.metadata = None;
        }
        if let Some(body) = body.or(patched_body) {
            subject.body = Some(body);
            subject.encrypted_content = None;
        }
        if let Some(encrypted_content) = encrypted_content.or(patched_encrypted_content) {
            subject.encrypted_content = Some(encrypted_content);
            subject.body = None;
        }
        if let Some(tracks) = tracks {
            subject.tracks = tracks;
        }
        if let Some(state) = state.or(patched_state) {
            subject.state = Some(state);
            subject.state_changed_at = Some(event.created_at);
        }
        subject.validate_title()?;
        subject.updated_by = Some(event.actor_id.clone());
        subject.updated_at = Some(event.created_at);
        Ok(())
    }

    // Reducer for `ck.flow.archive`: validate current state == active per
    // cokret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Deleted / Redacted / unset MUST be rejected with
    // `flow_not_active`; unknown Flow is tolerated (causal / backfill not
    // yet caught up — mirrors archive_morph / archive_space).
    fn archive_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        let Some(subject) = self.subjects.get(&flow_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("flow_not_active".to_owned()));
        }
        self.set_flow_state(event, crate::ObjectState::Archived)
    }

    // Reducer for `ck.flow.restore`: validate current state == archived per
    // cokret-spec common-fields.md §5 (`*.restore` is the canonical
    // archived -> active path; tombstoned / deleted / redacted MUST NOT be
    // restored). Active / Deleted / Redacted / unset MUST be rejected with
    // `flow_not_archived`; unknown Flow is tolerated (causal / backfill
    // not yet caught up — mirrors restore_space).
    fn restore_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        let Some(subject) = self.subjects.get(&flow_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Archived) {
            return Err(Error::Protocol("flow_not_archived".to_owned()));
        }
        self.set_flow_state(event, crate::ObjectState::Active)
    }

    fn set_flow_state(&mut self, event: &Event, state: crate::ObjectState) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&flow_id_str) {
            subject.state = Some(state);
            subject.state_changed_at = Some(event.created_at);
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    fn touch_flow(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&flow_id_str) {
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    /// Reducer for canonical `ck.flow.tracks.update`: merge a batch of
    /// `FlowTrackConfig` entries into `Flow.tracks`. Accepts either a top-level
    /// `tracks` map or `patch.tracks`.
    fn update_flow_tracks(&mut self, event: &Event) -> Result<()> {
        let flow_id_str = self.extract_flow_id(&event.content)?;
        let mut tracks = self
            .extract_optional_field::<BTreeMap<String, crate::FlowTrackConfig>>(
                &event.content,
                "tracks",
            )
            .unwrap_or_default();

        if let Some(patch_tracks) = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch")
            .and_then(|patch| patch.get("tracks").cloned())
            .and_then(|value| {
                serde_json::from_value::<BTreeMap<String, crate::FlowTrackConfig>>(value).ok()
            })
        {
            tracks.extend(patch_tracks);
        }

        if tracks.is_empty() {
            return Err(Error::Protocol(
                "flow tracks update requires tracks".to_owned(),
            ));
        }
        for track_id in tracks.keys() {
            crate::validate_flow_track_name(track_id)?;
        }

        let Some(subject) = self.subjects.get_mut(&flow_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("flow_not_active".to_owned()));
        }
        for (track_id, track) in tracks {
            subject.tracks.insert(track_id, track);
        }
        subject.updated_by = Some(event.actor_id.clone());
        subject.updated_at = Some(event.created_at);
        Ok(())
    }

    /// Move a relation by updating its endpoints.
    fn move_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        let new_to_ref = self.extract_optional_field::<String>(&event.content, "to_ref");
        let new_from_ref = self.extract_optional_field::<String>(&event.content, "from_ref");

        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            if let Some(new_to_ref) = new_to_ref {
                relation.to_ref = new_to_ref;
            }
            if let Some(new_from_ref) = new_from_ref {
                relation.from_ref = new_from_ref;
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

    /// Reduce realm lifecycle events into resolved state.
    fn reduce_realm_lifecycle_event(&mut self, event: &Event) -> Result<()> {
        if event.kind == "ck.realm.destroy" {
            self.tombstone_event_id = Some(event.event_id.clone());
        }
        self.reduce_generic_state_event(event)
    }

    fn reduce_generic_state_event(&mut self, event: &Event) -> Result<()> {
        let subject = self.subject_for_event(event)?;
        let family = match event.kind.as_str() {
            "ck.capability.grant" | "ck.capability.delegate" | "ck.capability.revoke" => {
                "ck.capability"
            }
            "ck.invite.create" | "ck.invite.cancel" | "ck.invite.accept" => "ck.invite",
            "ck.realm.policy" | "ck.policy.set" => "ck.policy",
            other => other,
        };
        let map_key = format!("{}|{}", family, subject);
        let candidate = ResolvedStateEvent {
            kind: event.kind.as_str().to_owned(),
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
        self.messages
            .entry(message_id.clone())
            .or_insert_with(|| ResolvedMessage {
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
            message.content = event
                .content
                .get("content")
                .cloned()
                .unwrap_or_else(|| event.content.clone());
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
            active: event.kind == "ck.reaction.add",
        };
        match self.reactions.get(&key) {
            Some(existing) if !Self::reaction_candidate_wins(existing, &candidate) => {}
            _ => {
                self.reactions.insert(key, candidate);
            }
        }
        Ok(())
    }

    /// Reduce a Realm schema/profile upgrade event.
    fn upgrade_realm(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Redact an event.
    ///
    /// Preserves the canonical envelope fields required for actor-chain
    /// validation per `event-auth-state-resolution.md` §10 (notably
    /// `actor_seq`, `prev_refs`, `refs`, `hlc`, `created_at` and the
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

    /// Round 11 (2026-05-16) — Object-level redaction state-machine
    /// guard for `ck.redaction` events. Looks at the redaction event's
    /// content for `object_ref`, and when that points to a Flow / Morph
    /// subject, flips the projection state to `ObjectState::Redacted` per
    /// spec common-fields.md §5.1. Source state MUST be `Active` or
    /// `Archived`; terminal source (`Deleted` / `Redacted`) MUST
    /// `failed_precondition` with `<kind>_already_terminal`. Unknown
    /// subject is tolerated (causal / backfill window — same convention
    /// as restore guards). Returns `Ok(())` for redactions without
    /// `object_ref` (message-only path). Space (container) is intentionally
    /// excluded because `SpaceState` has no `Redacted` variant — spec routes
    /// Space removal through `ck.space.tombstone` instead.
    fn redact_object_for_event(&mut self, event: &Event) -> Result<()> {
        let Some(object_ref) = self.extract_optional_field::<String>(&event.content, "object_ref")
        else {
            return Ok(());
        };
        if let Some(subject) = self.subjects.get_mut(&object_ref) {
            match subject.state {
                Some(crate::ObjectState::Active) | Some(crate::ObjectState::Archived) => {}
                _ => return Err(Error::Protocol("flow_already_terminal".to_owned())),
            }
            subject.state = Some(crate::ObjectState::Redacted);
            subject.state_changed_at = Some(event.created_at);
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
            return Ok(());
        }
        if let Some(morph) = self.morphs.get_mut(&object_ref) {
            match morph.state {
                Some(crate::ObjectState::Active) | Some(crate::ObjectState::Archived) => {}
                _ => return Err(Error::Protocol("morph_already_terminal".to_owned())),
            }
            morph.state = Some(crate::ObjectState::Redacted);
            morph.updated_by = Some(event.actor_id.clone());
            morph.updated_at = Some(event.created_at);
            return Ok(());
        }
        // Unknown object — causal / backfill window. Tolerate silently
        // (mirrors restore_*/archive_* guards). Note that Space is also
        // hit here when `object_ref` is `ck:space:...` and Space is
        // unmaterialised; that's also fine because ck.redaction targeting
        // a Space is undefined per spec (no `Redacted` variant), and
        // any space removal flow uses `ck.space.tombstone` directly.
        Ok(())
    }

    /// Update the causal frontier.
    fn update_frontier(&mut self, event: &Event) {
        let prev_refs: BTreeSet<EventId> = event.prev_refs.iter().cloned().collect();
        self.frontier
            .retain(|frontier_event| !prev_refs.contains(frontier_event));
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
            "ck.message.redact"
                | "ck.realm.redact"
                | "ck.realm.export"
                | "ck.realm.legal_hold"
                | "ck.realm.migration_proof"
                | "ck.realm.upgrade"
                | "ck.realm.destroy"
                | "ck.redaction"
        ) || event.redacts.is_some()
    }

    /// Extract morph_id from event content.
    fn extract_morph_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field(content, "morph_id")
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| Error::Protocol("morph event requires morph_id or id".to_owned()))
    }

    /// Extract flow_id from event content.
    fn extract_flow_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field::<String>(content, "flow_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .map(|value| canonicalize_flow_ref(&value))
            .ok_or_else(|| Error::Protocol("flow event requires flow_id".to_owned()))
    }

    /// Extract the container `space_id` from event content.
    fn extract_space_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field::<String>(content, "space_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .or_else(|| self.extract_optional_field::<String>(content, "target_ref"))
            .or_else(|| self.extract_optional_field::<String>(content, "object_ref"))
            .ok_or_else(|| Error::Protocol("container event requires space_id".to_owned()))
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

        let value = obj
            .get(field)
            .ok_or_else(|| Error::Protocol(format!("missing field: {}", field)))?;

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
        Ok(self
            .extract_optional_field(content, "fields")
            .unwrap_or_default())
    }

    /// Derive the cell subject for an event from typed payload fields,
    /// per the spec event-kind-registry's `cell_subject` declaration.
    fn subject_for_event(&self, event: &Event) -> Result<String> {
        match event.kind.as_str() {
            "ck.member.state" => self
                .extract_optional_field::<String>(&event.content, "actor_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "principal_id"))
                .or_else(|| self.extract_optional_field::<String>(&event.content, "member_id"))
                .ok_or_else(|| {
                    Error::Protocol("member state requires payload.actor_id".to_owned())
                }),
            "ck.capability.revoke" => self
                .extract_optional_field::<String>(&event.content, "target_capability_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| {
                    Error::Protocol("capability revoke requires target_capability_id".to_owned())
                }),
            "ck.capability.grant" | "ck.capability.delegate" => self
                .extract_optional_field::<String>(&event.content, "capability_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| {
                    Error::Protocol("capability event requires capability_id or id".to_owned())
                }),
            "ck.realm.policy" | "ck.policy.set" => Ok(self
                .extract_optional_field::<String>(&event.content, "policy_id")
                .unwrap_or_else(|| "space_policy".to_owned())),
            "ck.invite.create" | "ck.invite.cancel" | "ck.invite.accept" => self
                .extract_optional_field::<String>(&event.content, "invite_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("invite event requires invite_id or id".to_owned())),
            "ck.read_cursor.advance" => self
                .extract_optional_field::<String>(&event.content, "scope")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "target_ref"))
                .ok_or_else(|| {
                    Error::Protocol("read marker requires scope or target_ref".to_owned())
                }),
            // Realm lifecycle events use the realm_id as state key.
            "ck.realm.create"
            | "ck.realm.update"
            | "ck.realm.organization"
            | "ck.realm.link"
            | "ck.realm.inheritance_policy"
            | "ck.realm.join_rule"
            | "ck.realm.history_visibility"
            | "ck.realm.discovery"
            | "ck.realm.archive"
            | "ck.realm.freeze"
            | "ck.realm.destroy"
            | "ck.realm.upgrade" => Ok(event.realm_id.as_str().to_owned()),
            // View events use view_id as state key
            "ck.view.create" | "ck.view.update" | "ck.view.reconcile" => self
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
        if candidate.kind == "ck.member.state" && existing.kind == "ck.member.state" {
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
            .then_with(|| {
                candidate
                    .source_event_id
                    .as_str()
                    .cmp(existing.source_event_id.as_str())
            })
            .is_gt()
    }

    fn message_candidate_wins(existing: &ResolvedMessage, candidate: &Event) -> bool {
        candidate
            .hlc
            .cmp(&existing.latest_hlc)
            .then_with(|| {
                candidate
                    .actor_id
                    .as_str()
                    .cmp(existing.latest_actor_id.as_str())
            })
            .then_with(|| candidate.actor_seq.cmp(&existing.latest_actor_seq))
            .then_with(|| {
                candidate
                    .event_id
                    .as_str()
                    .cmp(existing.latest_event_id.as_str())
            })
            .is_gt()
    }

    fn reaction_candidate_wins(existing: &ResolvedReaction, candidate: &ResolvedReaction) -> bool {
        candidate
            .hlc
            .cmp(&existing.hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
            .then_with(|| {
                candidate
                    .source_event_id
                    .as_str()
                    .cmp(existing.source_event_id.as_str())
            })
            .is_gt()
    }

    /// Create a state snapshot at the current point.
    pub fn snapshot(&self) -> StateSnapshot {
        let mut snapshot = StateSnapshot {
            realm_id: self.realm_id.clone(),
            reducer_profile: self.reducer_profile.clone(),
            frontier: self.frontier.clone(),
            subjects: self.subjects.clone(),
            morphs: self.morphs.clone(),
            spaces: self.spaces.clone(),
            relations: self.relations.clone(),
            resolved_state: self.resolved_state.clone(),
            messages: self.messages.clone(),
            reactions: self.reactions.clone(),
            state_digest: self.compute_state_digest(),
            snapshot_timestamp: chrono::Utc::now(),
            tombstone_event_id: self.tombstone_event_id.clone(),
            manifest: None,
        };
        snapshot.manifest = Some(snapshot.manifest());
        snapshot
    }

    pub fn effective_capability(&self, capability_id: &str) -> Option<&ResolvedStateEvent> {
        self.resolved_state
            .get(&format!("ck.capability|{}", capability_id))
            .filter(|event| {
                matches!(
                    event.kind.as_str(),
                    "ck.capability.grant" | "ck.capability.delegate"
                )
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
    pub fn compute_state_digest(&self) -> String {
        canonical_sha256(&state_digest_payload(StateHashInput {
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            frontier: &self.frontier,
            subjects: &self.subjects,
            morphs: &self.morphs,
            spaces: &self.spaces,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
        .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)))
    }

    pub fn state_merkle_root(&self) -> Result<String> {
        state_merkle_root(&state_digest_payload(StateHashInput {
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            frontier: &self.frontier,
            subjects: &self.subjects,
            morphs: &self.morphs,
            spaces: &self.spaces,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
    }

    fn from_snapshot(snapshot: StateSnapshot) -> Self {
        Self {
            realm_id: snapshot.realm_id,
            reducer_profile: snapshot.reducer_profile,
            subjects: snapshot.subjects,
            morphs: snapshot.morphs,
            spaces: snapshot.spaces,
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
        realm_id: RealmId,
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
                    let mut state = Self::new(realm_id);
                    state.apply_events(repo_events)?;
                    return Ok(SnapshotRestore {
                        state,
                        source: SnapshotRestoreSource::RepoReplay,
                        snapshot_error: Some(err.to_string()),
                    });
                }
            }
        }

        let mut state = Self::new(realm_id);
        state.apply_events(repo_events)?;
        Ok(SnapshotRestore {
            state,
            source: SnapshotRestoreSource::RepoReplay,
            snapshot_error: None,
        })
    }
}

fn reject_legacy_flow_metadata_fields(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for field in ["title", "summary", "fields", "body", "encrypted_payload"] {
        if object.contains_key(field) {
            return Err(Error::Protocol(format!(
                "flow payload field '{field}' is retired; use metadata.*, content, or encrypted_content"
            )));
        }
    }
    Ok(())
}

fn reject_legacy_flow_patch_fields(patch: &Option<BTreeMap<String, Value>>) -> Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };
    for field in ["title", "summary", "fields", "body", "encrypted_payload"] {
        if patch.contains_key(field) {
            return Err(Error::Protocol(format!(
                "flow patch path '{field}' is retired; use metadata.*, content, or encrypted_content"
            )));
        }
    }
    Ok(())
}

fn reject_legacy_morph_metadata_fields(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for field in ["title", "summary", "encrypted_payload"] {
        if object.contains_key(field) {
            return Err(Error::Protocol(format!(
                "morph payload field '{field}' is retired; use metadata.*, encrypted_metadata, or encrypted_content"
            )));
        }
    }
    if object.contains_key("content") && object.contains_key("encrypted_content") {
        return Err(Error::Protocol(
            "morph payload must not carry both content and encrypted_content".to_owned(),
        ));
    }
    if object.contains_key("metadata") && object.contains_key("encrypted_metadata") {
        return Err(Error::Protocol(
            "morph payload must not carry both metadata and encrypted_metadata".to_owned(),
        ));
    }
    Ok(())
}

fn reject_legacy_morph_patch_fields(patch: &Option<BTreeMap<String, Value>>) -> Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };
    for field in ["title", "summary", "encrypted_payload"] {
        if patch.contains_key(field) {
            return Err(Error::Protocol(format!(
                "morph patch path '{field}' is retired; use metadata.*, encrypted_metadata, or encrypted_content"
            )));
        }
    }
    if patch.contains_key("content") && patch.contains_key("encrypted_content") {
        return Err(Error::Protocol(
            "morph patch must not carry both content and encrypted_content".to_owned(),
        ));
    }
    if patch.contains_key("metadata") && patch.contains_key("encrypted_metadata") {
        return Err(Error::Protocol(
            "morph patch must not carry both metadata and encrypted_metadata".to_owned(),
        ));
    }
    Ok(())
}

fn validate_morph_schema_refs(schema_refs: &[String]) -> Result<()> {
    if schema_refs.is_empty() {
        return Err(Error::Protocol(
            "morph object requires non-empty schema_refs".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for schema_ref in schema_refs {
        if !seen.insert(schema_ref) {
            return Err(Error::Protocol(format!(
                "morph object schema_refs contains duplicate schema ref `{schema_ref}`"
            )));
        }
    }
    Ok(())
}

fn patch_metadata_fields(
    patch: &Option<BTreeMap<String, Value>>,
) -> Option<BTreeMap<String, Value>> {
    let patch = patch.as_ref()?;
    if let Some(value) = patch.get("metadata.fields") {
        return serde_json::from_value(value.clone()).ok();
    }
    patch.get("metadata").and_then(|metadata| {
        metadata
            .get("fields")
            .cloned()
            .and_then(|fields| serde_json::from_value(fields).ok())
    })
}

fn patch_metadata_string(patch: &Option<BTreeMap<String, Value>>, field: &str) -> Option<String> {
    let patch = patch.as_ref()?;
    if let Some(value) = patch.get(&format!("metadata.{field}")) {
        return value.as_str().map(ToOwned::to_owned);
    }
    patch
        .get("metadata")?
        .get(field)?
        .as_str()
        .map(ToOwned::to_owned)
}
