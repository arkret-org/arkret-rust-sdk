//! Reaction event payloads and the `message_reactions` typed current value.

use crate::internal_prelude::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReactionPayloadWire {
    target_ref: ObjectRef,
    key: String,
    #[serde(default)]
    annotation: Option<String>,
    #[serde(default)]
    encrypted_payload: Option<EncryptedEnvelope>,
}

impl ReactionPayload {
    /// The schema bounds: a formal `object_ref` target, a 1..=128 character
    /// key, an annotation of at most 2048 characters, and no outer annotation
    /// beside an `encrypted_payload`.
    pub fn validate(&self) -> Result<()> {
        if !is_object_ref(&self.target_ref) {
            return Err(WireError::Protocol(
                "reaction target_ref is not a formal object_ref".to_owned(),
            ));
        }
        if !(1..=128).contains(&self.key.chars().count()) {
            return Err(WireError::Protocol(
                "reaction key must be 1..=128 characters".to_owned(),
            ));
        }
        if self
            .annotation
            .as_ref()
            .is_some_and(|annotation| annotation.chars().count() > 2048)
        {
            return Err(WireError::Protocol(
                "reaction annotation exceeds 2048 characters".to_owned(),
            ));
        }
        if self.encrypted_payload.is_some() && self.annotation.is_some() {
            return Err(WireError::Protocol(
                "an encrypted reaction carries its annotation inside encrypted_payload".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ReactionPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReactionPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            target_ref: wire.target_ref,
            key: wire.key,
            annotation: wire.annotation,
            encrypted_payload: wire.encrypted_payload,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageReactionsCurrentValueWire {
    entries: Vec<ReactionCurrentEntry>,
}

impl MessageReactionsCurrentValue {
    /// Install one complete active value, already sorted by full ActorId JCS
    /// bytes and then key UTF-8 bytes. This does not merge historical fragments.
    pub fn new(entries: Vec<ReactionCurrentEntry>) -> Result<Self> {
        let mut previous = None;
        for entry in &entries {
            entry
                .actor_id
                .validate()
                .map_err(|error| invalid(&error.to_string()))?;
            if !(1..=128).contains(&entry.key.chars().count()) {
                return Err(invalid("message_reactions key must be 1..=128 characters"));
            }
            let key = (
                arkret_canonical::canonical_json_bytes(&entry.actor_id)
                    .map_err(|error| invalid(&error.to_string()))?,
                entry.key.as_bytes().to_vec(),
            );
            if previous.as_ref().is_some_and(|prior| prior >= &key) {
                return Err(invalid(
                    "message_reactions actor/key entries are not sorted and unique",
                ));
            }
            previous = Some(key);
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[ReactionCurrentEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<ReactionCurrentEntry> {
        self.entries
    }

    /// The target is carried only by the complete outer selector.
    pub fn validate_for_target(&self, target_ref: &str) -> Result<()> {
        if !is_object_ref(target_ref) {
            return Err(invalid(
                "message_reactions target is not a formal object_ref",
            ));
        }
        Ok(())
    }

    /// Validate a complete trusted row against its atomic stream cut. The
    /// caller binds the authenticated account/scope/selector and atomically
    /// persists the value and checkpoint; history scans never call this as a
    /// reducer. No old Event or historical key is fetched by this method.
    pub fn validate_installation(
        &self,
        target_ref: &str,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
        head: &CommitStreamHead,
        previous: Option<(&Self, &CurrentRevision)>,
    ) -> Result<()> {
        self.validate_for_target(target_ref)?;
        if &head.stream_ref != stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
            || (revision.commit_id == head.commit_id
                && revision.stream_position != head.stream_position)
        {
            return Err(invalid(
                "message_reactions row does not match its stream cut",
            ));
        }
        for entry in &self.entries {
            let source = &entry.source;
            if &source.stream_ref != stream
                || source.stream_position > revision.stream_position
                || ((source.stream_position == revision.stream_position)
                    != (source.commit_id == revision.commit_id))
            {
                return Err(invalid(
                    "message_reactions active source exceeds or differs from its row",
                ));
            }
        }
        if let Some((prior, prior_revision)) = previous {
            if revision.stream_position < prior_revision.stream_position {
                return Err(invalid("message_reactions current revision rollback"));
            }
            if (revision.stream_position == prior_revision.stream_position)
                != (revision.commit_id == prior_revision.commit_id)
            {
                return Err(invalid("message_reactions current revision equivocation"));
            }
            if revision == prior_revision
                && arkret_canonical::canonical_json_bytes(self)
                    .map_err(|error| invalid(&error.to_string()))?
                    != arkret_canonical::canonical_json_bytes(prior)
                        .map_err(|error| invalid(&error.to_string()))?
            {
                return Err(invalid(
                    "message_reactions same revision has different value",
                ));
            }
        }
        Ok(())
    }
}

impl ReactionCurrentEntry {
    /// Check an available original's exact binding. Native producer/authority
    /// verification and historical-read permission remain the caller's gates;
    /// this method does not turn metadata into an Event, signer key or AEAD proof.
    pub fn validate_source_binding(
        &self,
        target_ref: &str,
        original: &CommittedEventFullView,
    ) -> Result<()> {
        let event = &original.event;
        let commit = &original.commit;
        if event.kind != EventKind::ReactionAdd
            || event.actor_id != self.actor_id
            || event.payload.get("target_ref").and_then(Value::as_str) != Some(target_ref)
            || event.payload.get("key").and_then(Value::as_str) != Some(self.key.as_str())
            || event.event_id != self.source.event_id
            || commit.event_ref != event.event_id
            || commit.commit_id != self.source.commit_id
            || commit.stream_ref != self.source.stream_ref
            || commit.stream_position != self.source.stream_position
            || event.realm_id != commit.realm_id
            || CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| invalid(&error.to_string()))?
                != commit.stream_ref
        {
            return Err(invalid(
                "message_reactions source is not the exact accepted active add",
            ));
        }
        commit
            .validate_content_address()
            .map_err(|error| invalid(&error.to_string()))?;
        event
            .verify_event_id_matches_content_with_digest_suite(
                event
                    .event_id
                    .event_digest()
                    .digest_suite()
                    .map_err(|error| invalid(&error.to_string()))?,
            )
            .map_err(|error| invalid(&error.to_string()))?;
        Ok(())
    }
}

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

impl<'de> Deserialize<'de> for MessageReactionsCurrentValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MessageReactionsCurrentValueWire::deserialize(deserializer)?;
        Self::new(wire.entries).map_err(serde::de::Error::custom)
    }
}

include!("generated/reaction_contracts.rs");
