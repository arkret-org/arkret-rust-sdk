use arkret_models_collaboration::events_payloads::MessageCreatePayload;
use arkret_wire::{EventKind, MessageId};

use super::super::*;
use super::RealmState;

impl RealmState {
    /// Reducer for canonical `ak.strand.tracks.update`: merge a batch of
    /// `StrandTrackConfig` entries into `Strand.tracks`. Accepts either a top-level
    /// `tracks` map or `patch.tracks`.
    pub(super) fn update_strand_tracks(&mut self, event: &Event) -> Result<()> {
        let strand_id_str = self.extract_strand_id(&event.payload)?;
        let mut tracks = self
            .extract_optional_field::<BTreeMap<String, crate::StrandTrackConfig>>(
                &event.payload,
                "tracks",
            )
            .unwrap_or_default();

        if let Some(patch_tracks) = self
            .extract_optional_field::<BTreeMap<String, Value>>(&event.payload, "patch")
            .and_then(|patch| patch.get("tracks").cloned())
            .and_then(|value| {
                serde_json::from_value::<BTreeMap<String, crate::StrandTrackConfig>>(value).ok()
            })
        {
            tracks.extend(patch_tracks);
        }

        if tracks.is_empty() {
            return Err(Error::Protocol(
                "strand tracks update requires tracks".to_owned(),
            ));
        }
        for track_id in tracks.keys() {
            crate::validate_strand_track_name(track_id)?;
        }

        let Some(subject) = self.subjects.get_mut(&strand_id_str) else {
            return Ok(());
        };
        if subject.state != Some(crate::ObjectState::Active) {
            return Err(Error::Protocol("strand_not_active".to_owned()));
        }
        for (track_id, track) in tracks {
            subject.tracks.insert(track_id, track);
        }
        subject.updated_by = Some(event.actor_id.clone());
        subject.updated_at = Some(event.created_at);
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
        if event.kind == "ak.realm.destroy" {
            self.tombstone_event_id = Some(event.event_id.clone());
        }
        self.reduce_generic_state_event(event)
    }

    pub(super) fn reduce_generic_state_event(&mut self, event: &Event) -> Result<()> {
        let subject = self.subject_for_event(event)?;
        let family = match event.kind.as_str() {
            "ak.capability.grant"
            | "ak.capability.delegate"
            | "ak.capability.revoke"
            | "ak.capability.derived" => "ak.capability",
            "ak.invite.create" | "ak.invite.cancel" | "ak.invite.accept" => "ak.invite",
            "ak.realm.policy" | "ak.policy.set" => "ak.policy",
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
        let _payload = event.typed_payload::<MessageCreatePayload>(EventKind::MESSAGE_CREATE)?;
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
            active: event.kind == "ak.reaction.add",
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
    pub(super) fn upgrade_realm(&mut self, event: &Event) -> Result<()> {
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

    /// Round 11 (2026-05-16) — Object-level redaction state-machine
    /// guard for `ak.redaction` events. Looks at the redaction event's
    /// content for `object_ref`, and when that points to a Strand / Morph
    /// subject, flips the projection state to `ObjectState::Redacted` per
    /// spec common-fields.md §5.1. Source state MUST be `Active` or
    /// `Archived`; terminal source (`Deleted` / `Redacted`) MUST
    /// `failed_precondition` with `<kind>_already_terminal`. Unknown
    /// subject is tolerated (causal / backfill window — same convention
    /// as restore guards). Returns `Ok(())` for redactions without
    /// `object_ref` (message-only path). Space (container) is intentionally
    /// excluded because `SpaceState` has no `Redacted` variant — spec routes
    /// Space removal through `ak.space.tombstone` instead.
    pub(super) fn redact_object_for_event(&mut self, event: &Event) -> Result<()> {
        let Some(object_ref) = self.extract_optional_field::<String>(&event.payload, "object_ref")
        else {
            return Ok(());
        };
        if let Some(subject) = self.subjects.get_mut(&object_ref) {
            match subject.state {
                Some(crate::ObjectState::Active) | Some(crate::ObjectState::Archived) => {}
                _ => return Err(Error::Protocol("strand_already_terminal".to_owned())),
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
        // hit here when `object_ref` is `ak:space:...` and Space is
        // unmaterialised; that's also fine because ak.redaction targeting
        // a Space is undefined per spec (no `Redacted` variant), and
        // any space removal strand uses `ak.space.tombstone` directly.
        Ok(())
    }
}
