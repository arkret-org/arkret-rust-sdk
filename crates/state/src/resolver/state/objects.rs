use arkret_event_draft::EventPayloadExt;
use arkret_wire::{SchemaId, event_spec};

use super::super::resolved_values::{
    patch_fields, patch_state, patch_string, space_state_from_str,
};
use super::super::*;
use super::RealmState;

impl RealmState {
    pub(super) fn create_morph(&mut self, event: &Event) -> Result<()> {
        let object = event.typed_payload::<event_spec::MorphCreate>()?.object;
        // The object id is derived from this create Event, never read from the
        // payload — the payload MUST NOT carry one (spec
        // `zh/models/common-fields.md` section 6.0).
        let morph_id = arkret_wire::MorphId::from_event_id(&event.event_id);
        let morph_id_str = morph_id.as_str().to_owned();
        let schema_refs = object.schema_refs;
        validate_morph_schema_refs(&schema_refs)?;
        let morph = Morph {
            id: Some(morph_id),
            schema: SchemaId::MORPH_V1.to_owned(),
            realm_id: event.realm_id.clone(),
            scope_circle_id: object.scope_circle_id,
            schema_refs,
            morph_kind: object.morph_kind,
            facets: object.facets,
            metadata: object.metadata,
            encrypted_metadata: object.encrypted_metadata,
            content: object.content,
            encrypted_content: object.encrypted_content,
            fields: object.fields,
            state: Some(object.state.unwrap_or(crate::ObjectState::Active)),
            state_changed_at: object.state_changed_at,
            stage: object.stage,
            stage_changed_at: object.stage_changed_at,
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
        };
        morph.validate_morph_kind(&[])?;
        self.morphs.insert(morph_id_str, morph);
        Ok(())
    }

    pub(super) fn update_morph(&mut self, event: &Event) -> Result<()> {
        let payload = event.typed_payload::<event_spec::MorphUpdate>()?;
        let morph_id_str = payload.target_ref.as_str().to_owned();
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(morph) = self.morphs.get(&morph_id_str)
            && morph.state != Some(crate::ObjectState::Active)
        {
            return Err(WireError::Protocol("morph_not_active".to_owned()));
        }
        let patch = Some(patch_to_value_map(&payload.patch)?);
        let title = patch_metadata_string(&patch, "title");
        let summary = patch_metadata_string(&patch, "summary");
        let content = patch
            .as_ref()
            .and_then(|patch| patch.get("content").cloned())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| WireError::Protocol(format!("invalid Morph content: {error}")))?;
        let encrypted_content = patch
            .as_ref()
            .and_then(|patch| patch.get("encrypted_content").cloned())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                WireError::Protocol(format!("invalid Morph encrypted_content: {error}"))
            })?;
        let fields = patch_fields(&patch);
        let facets = patch.as_ref().and_then(|patch| {
            patch
                .get("facets")
                .and_then(|value| serde_json::from_value(value.clone()).ok())
        });
        let state = patch_state(&patch).transpose()?;

        let morph = self
            .morphs
            .get_mut(&morph_id_str)
            .ok_or_else(|| WireError::Protocol(format!("morph not found: {}", morph_id_str)))?;
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

    pub(super) fn set_morph_state(
        &mut self,
        event: &Event,
        state: crate::ObjectState,
    ) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.payload)?;
        if let Some(morph) = self.morphs.get_mut(&morph_id_str) {
            morph.state = Some(state);
            morph.updated_by = Some(event.actor_id.clone());
            morph.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    // Reducer for `ak.morph.archive`: validate current state == active per
    // arkret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Deleted / Redacted / unset MUST be rejected with
    // `morph_not_active`; unknown Morph is tolerated (causal / backfill).
    pub(super) fn archive_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.payload)?;
        let Some(morph) = self.morphs.get(&morph_id_str) else {
            return Ok(());
        };
        if morph.state != Some(crate::ObjectState::Active) {
            return Err(WireError::Protocol("morph_not_active".to_owned()));
        }
        self.set_morph_state(event, crate::ObjectState::Archived)
    }

    // Reducer for `ak.morph.restore`: same state-machine contract as
    // `restore_strand` / `restore_space` — current state MUST == archived.
    // Active / Deleted / Redacted / unset → `morph_not_archived`. Unknown
    // Morph is tolerated for causal / backfill ordering. Morph has no
    // `state_changed_at` field (unlike Strand / Space), so on success we
    // only flip `state` and updated_by/at — matching set_morph_state.
    pub(super) fn restore_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.payload)?;
        let Some(morph) = self.morphs.get(&morph_id_str) else {
            return Ok(());
        };
        if morph.state != Some(crate::ObjectState::Archived) {
            return Err(WireError::Protocol("morph_not_archived".to_owned()));
        }
        self.set_morph_state(event, crate::ObjectState::Active)
    }

    pub(super) fn create_space(&mut self, event: &Event) -> Result<()> {
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        let object = payload.get("object").unwrap_or(&payload);
        // Derived from this create Event, never read from the payload.
        let id = SpaceId::from_event_id(&event.event_id);
        let space_id = id.as_str().to_owned();
        let realm_id = self.extract_field::<RealmId>(object, "realm_id")?;
        let kind = self.extract_field::<String>(object, "kind")?;
        let title = self.extract_field::<String>(object, "title")?;
        let state = self
            .extract_optional_field::<String>(object, "state")
            .map(|state| space_state_from_str(&state))
            .transpose()?
            .unwrap_or(crate::models::SpaceState::Active);

        let space = Space {
            schema: SchemaId::SPACE_V1.to_owned(),
            id: Some(id),
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
        };
        space.validate()?;
        self.spaces.insert(space_id, space);
        Ok(())
    }

    pub(super) fn update_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(space) = self.spaces.get(&space_id)
            && space.state != Some(crate::models::SpaceState::Active)
        {
            return Err(WireError::Protocol("space_not_active".to_owned()));
        }
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.payload, "patch");

        let title = self
            .extract_optional_field::<String>(&event.payload, "title")
            .or_else(|| patch_string(&patch, "title"));
        let summary = self
            .extract_optional_field::<String>(&event.payload, "summary")
            .or_else(|| patch_string(&patch, "summary"));
        let kind = self
            .extract_optional_field::<String>(&event.payload, "kind")
            .or_else(|| patch_string(&patch, "kind"));
        let rank = self
            .extract_optional_field::<String>(&event.payload, "rank")
            .or_else(|| patch_string(&patch, "rank"));
        let fields = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.payload, "fields")
            .or_else(|| patch_fields(&patch));
        let schema_refs = self
            .extract_optional_field::<Vec<String>>(&event.payload, "schema_refs")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("schema_refs")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let labels = self
            .extract_optional_field::<Vec<String>>(&event.payload, "labels")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("labels")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let avatar_blob_ref = self
            .extract_optional_field(&event.payload, "avatar_blob_ref")
            .or_else(|| {
                patch.as_ref().and_then(|patch| {
                    patch
                        .get("avatar_blob_ref")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                })
            });
        let state = self
            .extract_optional_field::<String>(&event.payload, "state")
            .or_else(|| patch_string(&patch, "state"))
            .map(|state| space_state_from_str(&state))
            .transpose()?;

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| WireError::Protocol(format!("space not found: {}", space_id)))?;
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

    pub(super) fn set_space_parent(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        let parent_space_id_str = self
            .extract_optional_field::<String>(&event.payload, "parent_space_id")
            .ok_or_else(|| {
                WireError::Protocol("space parent event requires parent_space_id".to_owned())
            })?;
        let parent_space_id = SpaceId::new(parent_space_id_str)?;
        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| WireError::Protocol(format!("space not found: {}", space_id)))?;
        space.parent_space_id = Some(parent_space_id);
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        space.validate()?;
        Ok(())
    }

    pub(super) fn set_space_state(
        &mut self,
        event: &Event,
        state: crate::models::SpaceState,
    ) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        if let Some(space) = self.spaces.get_mut(&space_id) {
            space.state = Some(state);
            space.state_changed_at = Some(event.created_at);
            space.updated_by = Some(event.actor_id.clone());
            space.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    // Reducer for `ak.space.archive`: validate current state == active per
    // arkret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Tombstoned / unset MUST be rejected with `space_not_active`;
    // unknown Space is tolerated (causal / backfill).
    pub(super) fn archive_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::models::SpaceState::Active) {
            return Err(WireError::Protocol("space_not_active".to_owned()));
        }
        self.set_space_state(event, crate::models::SpaceState::Archived)
    }

    // Reducer for `ak.space.tombstone`: validate current state ∈
    // {Active, Archived} per arkret-spec common-fields.md §5.1. Tombstoned /
    // unset MUST be rejected with `space_already_terminal`; unknown Space is
    // tolerated (causal / backfill).
    pub(super) fn tombstone_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        match space.state {
            Some(crate::models::SpaceState::Active) | Some(crate::models::SpaceState::Archived) => {
            }
            _ => return Err(WireError::Protocol("space_already_terminal".to_owned())),
        }
        self.set_space_state(event, crate::models::SpaceState::Tombstoned)
    }

    // Reducer for `ak.space.restore`: validate current state == archived per
    // arkret-spec space-and-space.md §4.4. Active / Tombstoned / unset MUST
    // be rejected with `space_not_archived`; unknown Space is tolerated
    // (causal / backfill not yet caught up — mirrors set_space_state).
    pub(super) fn restore_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.payload)?;
        let Some(space) = self.spaces.get_mut(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::models::SpaceState::Archived) {
            return Err(WireError::Protocol("space_not_archived".to_owned()));
        }
        space.state = Some(crate::models::SpaceState::Active);
        space.state_changed_at = Some(event.created_at);
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        Ok(())
    }

    /// Create a new relation.
    pub(super) fn create_relation(&mut self, event: &Event) -> Result<()> {
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        let object = payload
            .get("relation")
            .or_else(|| payload.get("object"))
            .unwrap_or(&payload);
        // Derived from this create Event, never read from the payload.
        let relation_id = RelationId::from_event_id(&event.event_id);
        let relation_id_str = relation_id.as_str().to_owned();
        let relation_kind: crate::RelationKind = self
            .extract_optional_field(object, "relation_kind")
            .or_else(|| self.extract_optional_field(object, "kind"))
            .ok_or_else(|| {
                WireError::Protocol("relation create requires kind or relation_kind".to_owned())
            })?;
        let from_ref = self.extract_field(object, "from_ref")?;
        let to_ref = self.extract_field(object, "to_ref")?;
        let rank = self.extract_optional_field(object, "rank");
        let fields = self.extract_fields(object)?;
        let scope_circle_id =
            self.extract_optional_field::<arkret_wire::CircleId>(object, "scope_circle_id");
        let effective_scope =
            self.extract_optional_field::<arkret_wire::ScopeRef>(object, "effective_scope");

        let relation = Relation {
            schema: SchemaId::RELATION_V1.to_owned(),
            id: Some(relation_id),
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

        relation.validate_endpoints()?;
        self.relations.insert(relation_id_str, relation);
        Ok(())
    }

    /// Delete a relation.
    pub(super) fn delete_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.payload)?;
        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            relation.state = Some(crate::RelationState::Tombstoned);
            relation.state_changed_at = Some(event.created_at);
        }
        Ok(())
    }

    pub(super) fn create_strand(&mut self, event: &Event) -> Result<()> {
        let object = event.typed_payload::<event_spec::StrandCreate>()?.object;
        // Derived from this create Event, never read from the payload.
        let strand_id = arkret_wire::StrandId::from_event_id(&event.event_id);
        let strand_id_str = strand_id.as_str().to_owned();
        let metadata = object.metadata.unwrap_or_default();
        let tracks = if object.tracks.is_empty() {
            let mut tracks = BTreeMap::new();
            tracks.insert(
                crate::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
                crate::StrandTrack::synthesis(),
            );
            tracks
        } else {
            object.tracks
        };
        let subject = Strand {
            id: Some(strand_id),
            schema: SchemaId::STRAND_V1.to_owned(),
            realm_id: event.realm_id.clone(),
            scope_circle_id: object.scope_circle_id,
            schema_refs: object.schema_refs,
            agent_participation: object.agent_participation,
            metadata: Some(metadata),
            encrypted_metadata: object.encrypted_metadata,
            content: object.content,
            encrypted_content: object.encrypted_content,
            tracks,
            state: Some(object.state.unwrap_or(crate::ObjectState::Active)),
            state_changed_at: object.state_changed_at,
            stage: Some(object.stage.unwrap_or(crate::ObjectStage::Draft)),
            stage_changed_at: object.stage_changed_at,
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
        };
        subject.validate_content_surfaces()?;
        subject.validate_profile_activation()?;
        subject.validate_title()?;
        self.subjects.insert(strand_id_str, subject);
        Ok(())
    }

    pub(super) fn update_strand(&mut self, event: &Event) -> Result<()> {
        let payload = event.typed_payload::<event_spec::StrandUpdate>()?;
        let strand_id_str = payload.target_ref.as_str().to_owned();
        // Spec common-fields.md §5.1 final paragraph: update on a non-active
        // object MUST fail — otherwise an edit would silently revive an
        // archived / tombstoned / redacted Strand, conflicting with the
        // `ak.strand.restore` semantic. Unknown Strand is tolerated below
        // (extract step succeeds, lookup returns None, current code returns
        // Err with "strand not found" — this guard runs before that).
        if let Some(subject) = self.subjects.get(&strand_id_str)
            && subject.state != Some(crate::ObjectState::Active)
        {
            return Err(WireError::Protocol("strand_not_active".to_owned()));
        }
        let subject = self
            .subjects
            .get_mut(&strand_id_str)
            .ok_or_else(|| WireError::Protocol(format!("strand not found: {}", strand_id_str)))?;

        // Apply the canonical dotted patch to the complete pre-state. The old
        // reducer inspected only a parent `tracks` value and silently missed
        // canonical paths such as `tracks.synthesis.content`.
        let pre_synthesis = subject
            .tracks
            .get(crate::STRAND_TRACK_NAME_SYNTHESIS)
            .cloned();
        let pre_state = subject.state.clone();
        let mut post_value = payload.patch.apply(&serde_json::to_value(&*subject)?)?;
        normalize_strand_content_pair_writes(&payload.patch, &mut post_value)?;
        let mut post: Strand = serde_json::from_value(post_value).map_err(|error| {
            WireError::Protocol(format!("invalid Strand post-patch object: {error}"))
        })?;

        let post_synthesis = post.tracks.get(crate::STRAND_TRACK_NAME_SYNTHESIS).cloned();
        let synthesis_content_changed = pre_synthesis
            .as_ref()
            .map(|track| (&track.content, &track.encrypted_content))
            != post_synthesis
                .as_ref()
                .map(|track| (&track.content, &track.encrypted_content));
        if synthesis_content_changed
            && (!pre_synthesis
                .as_ref()
                .is_some_and(|track| track.enabled != Some(false))
                || !post_synthesis
                    .as_ref()
                    .is_some_and(|track| track.enabled != Some(false)))
        {
            return Err(WireError::Protocol("track_disabled".to_owned()));
        }

        post.validate_content_surfaces()?;
        post.validate_profile_activation()?;
        post.validate_title()?;
        if post.state != pre_state {
            post.state_changed_at = Some(event.created_at);
        }
        post.updated_by = Some(event.actor_id.clone());
        post.updated_at = Some(event.created_at);
        *subject = post;
        Ok(())
    }

    // Reducer for `ak.strand.archive`: validate current state == active per
    // arkret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Deleted / Redacted / unset MUST be rejected with
    // `strand_not_active`; unknown Strand is tolerated (causal / backfill not
    // yet caught up — mirrors archive_morph / archive_space).
    pub(super) fn archive_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.payload)?;
        let Some(subject) = self.subjects.get(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(WireError::Protocol("strand_not_active".to_owned()));
        }
        self.set_strand_state(event, crate::ObjectState::Archived)
    }

    // Reducer for `ak.strand.restore`: validate current state == archived per
    // arkret-spec common-fields.md §5 (`*.restore` is the canonical
    // archived -> active path; tombstoned / deleted / redacted MUST NOT be
    // restored). Active / Deleted / Redacted / unset MUST be rejected with
    // `strand_not_archived`; unknown Strand is tolerated (causal / backfill
    // not yet caught up — mirrors restore_space).
    pub(super) fn restore_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.payload)?;
        let Some(subject) = self.subjects.get(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Archived) {
            return Err(WireError::Protocol("strand_not_archived".to_owned()));
        }
        self.set_strand_state(event, crate::ObjectState::Active)
    }

    pub(super) fn set_strand_state(
        &mut self,
        event: &Event,
        state: crate::ObjectState,
    ) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.payload)?;
        if let Some(subject) = self.subjects.get_mut(&strand_id_str) {
            subject.state = Some(state);
            subject.state_changed_at = Some(event.created_at);
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    pub(super) fn touch_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.payload)?;
        if let Some(subject) = self.subjects.get_mut(&strand_id_str) {
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    /// Move a relation by updating its endpoints.
    pub(super) fn move_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.payload)?;
        let actor_id = event.actor_id.clone();
        let created_at = event.created_at;
        let new_to_ref = self.extract_optional_field::<arkret_models_collaboration::objects::relation::RelationEndpoint>(&event.payload, "to_ref");
        let new_from_ref = self.extract_optional_field::<arkret_models_collaboration::objects::relation::RelationEndpoint>(&event.payload, "from_ref");

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
}

fn validate_morph_schema_refs(schema_refs: &[String]) -> Result<()> {
    if schema_refs.is_empty() {
        return Err(WireError::Protocol(
            "morph object requires non-empty schema_refs".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for schema_ref in schema_refs {
        if !seen.insert(schema_ref) {
            return Err(WireError::Protocol(format!(
                "morph object schema_refs contains duplicate schema ref `{schema_ref}`"
            )));
        }
    }
    Ok(())
}

fn normalize_strand_content_pair_writes(
    patch: &crate::Patch,
    post_state: &mut Value,
) -> Result<()> {
    let writes_description = patch.iter().any(|(path, _)| path == "content");
    let writes_encrypted_description = patch.iter().any(|(path, _)| path == "encrypted_content");
    if writes_description && writes_encrypted_description {
        return Err(WireError::Protocol(
            "Strand Description patch must write only one of content or encrypted_content"
                .to_owned(),
        ));
    }
    let writes_synthesis = patch
        .iter()
        .any(|(path, _)| path == "tracks.synthesis.content");
    let writes_encrypted_synthesis = patch
        .iter()
        .any(|(path, _)| path == "tracks.synthesis.encrypted_content");
    if writes_synthesis && writes_encrypted_synthesis {
        return Err(WireError::Protocol(
            "Synthesis patch must write only one of tracks.synthesis.content or tracks.synthesis.encrypted_content"
                .to_owned(),
        ));
    }

    let post = post_state
        .as_object_mut()
        .ok_or_else(|| WireError::Protocol("Strand post-state must be an object".to_owned()))?;
    if writes_description {
        post.remove("encrypted_content");
    } else if writes_encrypted_description {
        post.remove("content");
    }

    if writes_synthesis || writes_encrypted_synthesis {
        let synthesis = post
            .get_mut("tracks")
            .and_then(Value::as_object_mut)
            .and_then(|tracks| tracks.get_mut(crate::STRAND_TRACK_NAME_SYNTHESIS))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| WireError::Protocol("track_disabled".to_owned()))?;
        if writes_synthesis {
            synthesis.remove("encrypted_content");
        } else {
            synthesis.remove("content");
        }
    }
    Ok(())
}

fn patch_to_value_map(patch: &crate::Patch) -> Result<BTreeMap<String, Value>> {
    let value = serde_json::to_value(patch)?;
    serde_json::from_value(value).map_err(Into::into)
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
