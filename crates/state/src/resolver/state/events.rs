use arkret_event_draft::EventPayloadExt;
use arkret_wire::{MessageId, event_spec};

use super::super::*;
use super::RealmState;

impl RealmState {
    /// Reducer for canonical `ak.strand.tracks.update`. This event changes
    /// track configuration only; narrative content remains owned by
    /// `ak.strand.update` and its field-scoped capability.
    pub(super) fn update_strand_tracks(&mut self, event: &Event) -> Result<()> {
        let payload = event.typed_payload::<event_spec::StrandTracksUpdate>()?;
        let strand_id_str = payload.target_ref.as_str().to_owned();
        if payload
            .patch
            .iter()
            .any(|(path, _)| path != "tracks" && !path.starts_with("tracks."))
        {
            return Err(Error::Protocol(
                "ak.strand.tracks.update patch paths must stay under tracks".to_owned(),
            ));
        }

        let Some(subject) = self.subjects.get_mut(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("strand_not_active".to_owned()));
        }
        let previous_tracks = subject.tracks.clone();
        let previous_description = (subject.content.clone(), subject.encrypted_content.clone());
        let post_value = payload.patch.apply(&serde_json::to_value(&*subject)?)?;
        let mut post: Strand = serde_json::from_value(post_value).map_err(|error| {
            Error::Protocol(format!("invalid Strand tracks post-state: {error}"))
        })?;

        let description_unchanged =
            previous_description == (post.content.clone(), post.encrypted_content.clone());
        let track_content_unchanged = |name: &str| {
            let previous = previous_tracks.get(name).map_or((None, None), |track| {
                (track.content.clone(), track.encrypted_content.clone())
            });
            let next = post.tracks.get(name).map_or((None, None), |track| {
                (track.content.clone(), track.encrypted_content.clone())
            });
            previous == next
        };
        if !description_unchanged
            || !track_content_unchanged(crate::STRAND_TRACK_NAME_SYNTHESIS)
            || !track_content_unchanged(crate::STRAND_TRACK_NAME_DISCUSSION)
        {
            return Err(Error::Protocol(
                "ak.strand.tracks.update changes configuration only; Description and Synthesis content require field-scoped ak.strand.update"
                    .to_owned(),
            ));
        }
        post.validate_content_surfaces()?;
        arkret_models_collaboration::objects::profiles::validate_primary_track_transition(
            &previous_tracks,
            &post.tracks,
            None,
        )?;
        post.updated_by = Some(event.actor_id.clone());
        post.updated_at = Some(event.created_at);
        *subject = post;
        Ok(())
    }

    /// Create a view (stored as resolved state).
    pub(super) fn create_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Update a view (stored as resolved state).
    pub(super) fn update_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Reconcile a view (stored as resolved state).
    pub(super) fn reconcile_view(&mut self, event: &Event) -> Result<()> {
        self.reduce_generic_state_event(event)
    }

    /// Reduce realm lifecycle events into resolved state.
    pub(super) fn reduce_realm_lifecycle_event(&mut self, event: &Event) -> Result<()> {
        let reducer_profile = if event.kind == arkret_wire::event_kind_str::REALM_CREATE {
            let profile = event
                .payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("reducer_profile"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::Protocol(
                        "ak.realm.create requires payload.object.reducer_profile".to_owned(),
                    )
                })?;
            if !arkret_wire::is_reducer_profile_id(profile) {
                return Err(Error::Protocol("unsupported_profile".to_owned()));
            }
            Some(profile.to_owned())
        } else {
            None
        };
        if event.kind == arkret_wire::event_kind_str::REALM_DESTROY {
            self.tombstone_event_id = Some(event.event_id.clone());
        }
        self.reduce_generic_state_event(event)?;
        if let Some(profile) = reducer_profile {
            self.reducer_profile = profile;
        }
        Ok(())
    }

    pub(super) fn reduce_generic_state_event(&mut self, event: &Event) -> Result<()> {
        let subject = self.subject_for_event(event)?;
        let family = match event.kind.as_str() {
            arkret_wire::event_kind_str::CAPABILITY_GRANT
            | arkret_wire::event_kind_str::CAPABILITY_REVOKE
            | arkret_wire::event_kind_str::CAPABILITY_RELINQUISH
            | arkret_wire::event_kind_str::CAPABILITY_DERIVED => "ak.capability",
            arkret_wire::event_kind_str::INVITE_CREATE
            | arkret_wire::event_kind_str::INVITE_CANCEL
            | arkret_wire::event_kind_str::INVITE_ACCEPT => "ak.invite",
            arkret_wire::event_kind_str::REALM_POLICY | arkret_wire::event_kind_str::POLICY_SET => {
                "ak.policy"
            }
            other => other,
        };
        let map_key = format!("{}|{}", family, subject);
        let candidate = ResolvedStateEvent {
            kind: event.kind.clone(),
            subject,
            source_event_id: event.event_id.clone(),
            actor_id: event.actor_id.clone(),
            principal_server_id: event.principal_server_id.clone(),
            actor_seq: event.actor_seq,
            hlc: event.hlc.clone(),
            content: Value::Object(event.payload.clone().into_iter().collect()),
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

    pub(super) fn create_message(&mut self, event: &Event) -> Result<()> {
        event.typed_payload::<event_spec::MessageCreate>()?;
        let message_id = MessageId::from_event_id(&event.event_id).to_string();
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
                content: Value::Object(event.payload.clone().into_iter().collect()),
                revision_event_ids: Vec::new(),
                redacted: false,
            });
        Ok(())
    }

    pub(super) fn revise_message(&mut self, event: &Event) -> Result<()> {
        let message_id = self
            .extract_optional_field::<String>(&event.payload, "target_message_id")
            .or_else(|| self.extract_optional_field::<String>(&event.payload, "message_id"))
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
                .payload
                .get("content")
                .cloned()
                .unwrap_or_else(|| Value::Object(event.payload.clone().into_iter().collect()));
            message.redacted = false;
        }
        message.revision_event_ids.push(event.event_id.clone());
        Ok(())
    }

    pub(super) fn redact_message(&mut self, event: &Event) -> Result<()> {
        let message_id = self
            .extract_optional_field::<String>(&event.payload, "target_message_id")
            .or_else(|| self.extract_optional_field::<String>(&event.payload, "message_id"))
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

    pub(super) fn reduce_reaction(&mut self, event: &Event) -> Result<()> {
        let message_id = self.extract_field::<String>(&event.payload, "message_id")?;
        let reaction_key = self.extract_field::<String>(&event.payload, "reaction_key")?;
        let key = format!("{}|{}|{}", message_id, event.actor_id, reaction_key);
        let candidate = ResolvedReaction {
            message_id,
            actor_id: event.actor_id.clone(),
            reaction_key,
            source_event_id: event.event_id.clone(),
            actor_seq: event.actor_seq,
            hlc: event.hlc.clone(),
            active: event.kind == arkret_wire::event_kind_str::REACTION_ADD,
        };
        match self.reactions.get(&key) {
            Some(existing) if !Self::reaction_candidate_wins(existing, &candidate) => {}
            _ => {
                self.reactions.insert(key, candidate);
            }
        }
        Ok(())
    }

    /// Apply the registered reducer-profile transition. The source profile
    /// interprets this Event; only subsequent Events use the target profile.
    pub(super) fn upgrade_realm(&mut self, event: &Event) -> Result<()> {
        let target = self.extract_field::<String>(&event.payload, "target_reducer_profile")?;
        if !arkret_wire::can_upgrade_reducer_profile(&self.reducer_profile, &target) {
            return Err(Error::Protocol("unsupported_profile".to_owned()));
        }
        self.reduce_generic_state_event(event)?;
        self.reducer_profile = target;
        Ok(())
    }

    /// Redact an event.
    ///
    /// Preserves the canonical envelope fields required for actor-chain
    /// validation per `event-auth-state-resolution.md` §10 (notably
    /// `actor_seq`, `prev_refs`, `refs`, `hlc`, `created_at` and the
    /// envelope digest binding); clears `content` (the payload) and
    /// `unsigned` (server-added hints). MUST NOT touch `event_id` or
    /// `proofs` — these are needed to verify the redaction itself.
    pub(super) fn redact_event(&mut self, event_id: &EventId) -> Result<()> {
        self.redacted_events.insert(event_id.clone());
        if let Some(event) = self.processed_events.get_mut(event_id) {
            event.payload = BTreeMap::new();
            event.unsigned.clear();
        }
        for event in &mut self.state_events {
            if &event.event_id == event_id {
                event.payload = BTreeMap::new();
                event.unsigned.clear();
            }
        }
        Ok(())
    }

    /// Object-level redaction state-machine guard for `ak.redaction` events.
    /// Reads the registered object-target member `payload.target_ref` of
    /// `cross_object_redaction_payload`, and when it points to a Strand / Morph
    /// subject, flips the projection state to `ObjectState::Redacted` per
    /// spec common-fields.md §5.1. Source state MUST be `Active` or
    /// `Archived`; terminal source (`Deleted` / `Redacted`) MUST
    /// `failed_precondition` with `<kind>_already_terminal`. Unknown
    /// subject is tolerated (causal / backfill window — same convention
    /// as restore guards). An Event-target redaction (`ak:event:`) has no
    /// object subject and returns `Ok(())`. Space (container) is intentionally
    /// excluded because `SpaceState` has no `Redacted` variant — spec routes
    /// Space removal through `ak.space.tombstone` instead.
    pub(super) fn redact_object_for_event(&mut self, event: &Event) -> Result<()> {
        let Some(target_ref) = self.extract_optional_field::<String>(&event.payload, "target_ref")
        else {
            return Ok(());
        };
        if let Some(subject) = self.subjects.get_mut(&target_ref) {
            match subject.state {
                Some(crate::ObjectState::Active) | Some(crate::ObjectState::Archived) => {}
                _ => return Err(Error::Protocol("strand_already_terminal".to_owned())),
            }
            subject.state = Some(crate::ObjectState::Redacted);
            subject.state_changed_at = Some(event.created_at);
            subject.content = None;
            subject.encrypted_content = None;
            if let Some(synthesis) = subject.tracks.get_mut(crate::STRAND_TRACK_NAME_SYNTHESIS) {
                synthesis.content = None;
                synthesis.encrypted_content = None;
            }
            subject.updated_by = Some(event.actor_id.clone());
            subject.updated_at = Some(event.created_at);
            return Ok(());
        }
        if let Some(morph) = self.morphs.get_mut(&target_ref) {
            match morph.state {
                Some(crate::ObjectState::Active) | Some(crate::ObjectState::Archived) => {}
                _ => return Err(Error::Protocol("morph_already_terminal".to_owned())),
            }
            morph.state = Some(crate::ObjectState::Redacted);
            morph.state_changed_at = Some(event.created_at);
            morph.content = None;
            morph.encrypted_content = None;
            morph.updated_by = Some(event.actor_id.clone());
            morph.updated_at = Some(event.created_at);
            return Ok(());
        }
        // Unknown object — causal / backfill window. Tolerate silently
        // (mirrors restore_*/archive_* guards). Note that Space is also
        // hit here when `target_ref` is `ak:space:...` and Space is
        // unmaterialised; that's also fine because ak.redaction targeting
        // a Space is undefined per spec (no `Redacted` variant), and
        // any space removal strand uses `ak.space.tombstone` directly.
        Ok(())
    }
}
