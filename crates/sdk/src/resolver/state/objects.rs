use super::super::snapshot::{
    object_state_from_str, patch_fields, patch_state, patch_string, space_state_from_str,
};
use super::super::*;
use super::RealmState;

impl RealmState {
    pub(super) fn create_morph(&mut self, event: &Event) -> Result<()> {
        let object = event.content.get("object").unwrap_or(&event.content);
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

    pub(super) fn update_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(morph) = self.morphs.get(&morph_id_str)
            && morph.state != Some(crate::ObjectState::Active)
        {
            return Err(Error::Protocol("morph_not_active".to_owned()));
        }
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");
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

    pub(super) fn set_morph_state(
        &mut self,
        event: &Event,
        state: crate::ObjectState,
    ) -> Result<()> {
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
    pub(super) fn archive_morph(&mut self, event: &Event) -> Result<()> {
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
    // `restore_strand` / `restore_space` — current state MUST == archived.
    // Active / Deleted / Redacted / unset → `morph_not_archived`. Unknown
    // Morph is tolerated for causal / backfill ordering. Morph has no
    // `state_changed_at` field (unlike Strand / Space), so on success we
    // only flip `state` and updated_by/at — matching set_morph_state.
    pub(super) fn restore_morph(&mut self, event: &Event) -> Result<()> {
        let morph_id_str = self.extract_morph_id(&event.content)?;
        let Some(morph) = self.morphs.get(&morph_id_str) else {
            return Ok(());
        };
        if morph.state != Some(crate::ObjectState::Archived) {
            return Err(Error::Protocol("morph_not_archived".to_owned()));
        }
        self.set_morph_state(event, crate::ObjectState::Active)
    }

    pub(super) fn create_space(&mut self, event: &Event) -> Result<()> {
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
            .unwrap_or(crate::models::SpaceState::Active);

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

    pub(super) fn update_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        // Spec common-fields.md §5.1: update on non-active object MUST fail.
        if let Some(space) = self.spaces.get(&space_id)
            && space.state != Some(crate::models::SpaceState::Active)
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

    pub(super) fn set_space_parent(&mut self, event: &Event) -> Result<()> {
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

    pub(super) fn set_space_state(
        &mut self,
        event: &Event,
        state: crate::models::SpaceState,
    ) -> Result<()> {
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
    pub(super) fn archive_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::models::SpaceState::Active) {
            return Err(Error::Protocol("space_not_active".to_owned()));
        }
        self.set_space_state(event, crate::models::SpaceState::Archived)
    }

    // Reducer for `ck.space.tombstone`: validate current state ∈
    // {Active, Archived} per cokret-spec common-fields.md §5.1. Tombstoned /
    // unset MUST be rejected with `space_already_terminal`; unknown Space is
    // tolerated (causal / backfill).
    pub(super) fn tombstone_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get(&space_id) else {
            return Ok(());
        };
        match space.state {
            Some(crate::models::SpaceState::Active) | Some(crate::models::SpaceState::Archived) => {
            }
            _ => return Err(Error::Protocol("space_already_terminal".to_owned())),
        }
        self.set_space_state(event, crate::models::SpaceState::Tombstoned)
    }

    // Reducer for `ck.space.restore`: validate current state == archived per
    // cokret-spec space-and-space.md §4.4. Active / Tombstoned / unset MUST
    // be rejected with `space_not_archived`; unknown Space is tolerated
    // (causal / backfill not yet caught up — mirrors set_space_state).
    pub(super) fn restore_space(&mut self, event: &Event) -> Result<()> {
        let space_id = self.extract_space_id(&event.content)?;
        let Some(space) = self.spaces.get_mut(&space_id) else {
            return Ok(());
        };
        if space.state != Some(crate::models::SpaceState::Archived) {
            return Err(Error::Protocol("space_not_archived".to_owned()));
        }
        space.state = Some(crate::models::SpaceState::Active);
        space.state_changed_at = Some(event.created_at);
        space.updated_by = Some(event.actor_id.clone());
        space.updated_at = Some(event.created_at);
        Ok(())
    }

    /// Create a new relation.
    pub(super) fn create_relation(&mut self, event: &Event) -> Result<()> {
        let object = event
            .content
            .get("relation")
            .or_else(|| event.content.get("object"))
            .unwrap_or(&event.content);
        let relation_id_str = self
            .extract_optional_field::<String>(object, "relation_id")
            .or_else(|| self.extract_optional_field::<String>(object, "id"))
            .unwrap_or_else(|| relation_id_from_event_id(event.event_id.as_str()));
        let relation_id = RelationId::new(relation_id_str.clone())?;
        let relation_kind: crate::RelationKind = self
            .extract_optional_field(object, "relation_kind")
            .or_else(|| self.extract_optional_field(object, "kind"))
            .ok_or_else(|| {
                Error::Protocol("relation create requires kind or relation_kind".to_owned())
            })?;
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
    pub(super) fn delete_relation(&mut self, event: &Event) -> Result<()> {
        let relation_id_str = self.extract_relation_id(&event.content)?;
        if let Some(relation) = self.relations.get_mut(&relation_id_str) {
            relation.state = Some(crate::RelationState::Tombstoned);
            relation.state_changed_at = Some(event.created_at);
        }
        Ok(())
    }

    pub(super) fn create_strand(&mut self, event: &Event) -> Result<()> {
        let object = event.content.get("object").unwrap_or(&event.content);
        let strand_id_str = self.extract_strand_id(object)?;
        let strand_id = StrandId::new(strand_id_str.clone())?;
        let metadata = self
            .extract_optional_field::<crate::StrandMetadata>(object, "metadata")
            .unwrap_or_default();
        let tracks = self
            .extract_optional_field::<BTreeMap<String, crate::StrandTrackConfig>>(object, "tracks")
            .unwrap_or_else(|| {
                let mut tracks = BTreeMap::new();
                tracks.insert(
                    crate::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
                    crate::StrandTrackConfig::synthesis(),
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
        let subject = Strand {
            id: strand_id,
            schema: crate::STRAND_SCHEMA.to_owned(),
            realm_id: event.realm_id.clone(),
            scope_circle_id,
            metadata: Some(metadata),
            encrypted_metadata,
            body,
            encrypted_content,
            tracks,
            state: Some(state),
            state_changed_at: None,
            stage: Some(
                self.extract_optional_field::<crate::ObjectStage>(object, "stage")
                    .unwrap_or(crate::ObjectStage::Draft),
            ),
            stage_changed_at: self.extract_optional_field(object, "stage_changed_at"),
            created_by: event.actor_id.clone(),
            created_at: event.created_at,
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        };
        subject.validate_title()?;
        self.subjects.insert(strand_id_str, subject);
        Ok(())
    }

    pub(super) fn update_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.content)?;
        // Spec common-fields.md §5.1 final paragraph: update on a non-active
        // object MUST fail — otherwise an edit would silently revive an
        // archived / tombstoned / redacted Strand, conflicting with the
        // `ck.strand.restore` semantic. Unknown Strand is tolerated below
        // (extract step succeeds, lookup returns None, current code returns
        // Err with "strand not found" — this guard runs before that).
        if let Some(subject) = self.subjects.get(&strand_id_str)
            && subject.state != Some(crate::ObjectState::Active)
        {
            return Err(Error::Protocol("strand_not_active".to_owned()));
        }
        let patch = self.extract_optional_field::<BTreeMap<String, Value>>(&event.content, "patch");
        let metadata =
            self.extract_optional_field::<crate::StrandMetadata>(&event.content, "metadata");
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
            .extract_optional_field::<BTreeMap<String, crate::StrandTrackConfig>>(
                &event.content,
                "tracks",
            )
            .or_else(|| {
                // Patch path is a JSON object map: track_name → StrandTrackConfig.
                patch.as_ref().and_then(|p| p.get("tracks")).and_then(|v| {
                    serde_json::from_value::<BTreeMap<String, crate::StrandTrackConfig>>(v.clone())
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
            .get_mut(&strand_id_str)
            .ok_or_else(|| Error::Protocol(format!("strand not found: {}", strand_id_str)))?;

        if let Some(metadata) = metadata {
            subject.metadata = Some(metadata);
        }
        if let Some(title) = patch_metadata_string(&patch, "title") {
            subject
                .metadata
                .get_or_insert_with(crate::StrandMetadata::default)
                .title = Some(title);
        }
        if let Some(summary) = patch_metadata_string(&patch, "summary") {
            subject
                .metadata
                .get_or_insert_with(crate::StrandMetadata::default)
                .summary = Some(summary);
        }
        if let Some(fields) = fields.or_else(|| patch_metadata_fields(&patch)) {
            subject
                .metadata
                .get_or_insert_with(crate::StrandMetadata::default)
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

    // Reducer for `ck.strand.archive`: validate current state == active per
    // cokret-spec common-fields.md §5.1 canonical state-transition table.
    // Archived / Deleted / Redacted / unset MUST be rejected with
    // `strand_not_active`; unknown Strand is tolerated (causal / backfill not
    // yet caught up — mirrors archive_morph / archive_space).
    pub(super) fn archive_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.content)?;
        let Some(subject) = self.subjects.get(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("strand_not_active".to_owned()));
        }
        self.set_strand_state(event, crate::ObjectState::Archived)
    }

    // Reducer for `ck.strand.restore`: validate current state == archived per
    // cokret-spec common-fields.md §5 (`*.restore` is the canonical
    // archived -> active path; tombstoned / deleted / redacted MUST NOT be
    // restored). Active / Deleted / Redacted / unset MUST be rejected with
    // `strand_not_archived`; unknown Strand is tolerated (causal / backfill
    // not yet caught up — mirrors restore_space).
    pub(super) fn restore_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.content)?;
        let Some(subject) = self.subjects.get(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Archived) {
            return Err(Error::Protocol("strand_not_archived".to_owned()));
        }
        self.set_strand_state(event, crate::ObjectState::Active)
    }

    pub(super) fn set_strand_state(
        &mut self,
        event: &Event,
        state: crate::ObjectState,
    ) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&strand_id_str) {
            subject.state = Some(state);
            subject.state_changed_at = Some(event.created_at);
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    pub(super) fn touch_strand(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.content)?;
        if let Some(subject) = self.subjects.get_mut(&strand_id_str) {
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
        }
        Ok(())
    }

    /// Move a relation by updating its endpoints.
    pub(super) fn move_relation(&mut self, event: &Event) -> Result<()> {
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

fn relation_id_from_event_id(event_id: &str) -> String {
    match event_id.strip_prefix("ck:event:") {
        Some(suffix) => format!("ck:relation:{suffix}"),
        None => format!("ck:relation:{event_id}"),
    }
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
