//! Reaction event payloads and the `message_reactions` typed current value.

use crate::exact_current_state::CanonicalEventDot;
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
    assertions: Vec<ReactionAssertionEntry>,
}

impl MessageReactionsCurrentValue {
    /// Build a set from its elements. The elements MUST already be strictly
    /// ascending in canonical dot string order.
    pub fn new(assertions: Vec<ReactionAssertionEntry>) -> Result<Self> {
        if assertions
            .iter()
            .any(|entry| entry.tag_id.write_index() != 0)
        {
            return Err(WireError::Protocol(
                "message_reactions assertion dot must name write index 0".to_owned(),
            ));
        }
        if assertions
            .windows(2)
            .any(|pair| pair[0].tag_id >= pair[1].tag_id)
        {
            return Err(WireError::Protocol(
                "message_reactions dots are not a canonically sorted set".to_owned(),
            ));
        }
        if assertions
            .windows(2)
            .any(|pair| pair[0].value.target_ref != pair[1].value.target_ref)
        {
            return Err(WireError::Protocol(
                "message_reactions assertions name more than one target".to_owned(),
            ));
        }
        Ok(Self { assertions })
    }

    /// Insert one more assertion at its canonical position. A dot already
    /// present is refused; each accepted Event contributes its dot once.
    pub fn with_assertion(mut self, entry: ReactionAssertionEntry) -> Result<Self> {
        match self
            .assertions
            .binary_search_by(|existing| existing.tag_id.cmp(&entry.tag_id))
        {
            Ok(_) => Err(WireError::Protocol(
                "message_reactions already holds this assertion dot".to_owned(),
            )),
            Err(index) => {
                self.assertions.insert(index, entry);
                Self::new(self.assertions)
            }
        }
    }

    pub fn assertions(&self) -> &[ReactionAssertionEntry] {
        &self.assertions
    }

    pub fn into_assertions(self) -> Vec<ReactionAssertionEntry> {
        self.assertions
    }

    /// Every assertion reacts to exactly the selector's `target_ref`.
    pub fn validate_for_target(&self, target_ref: &str) -> Result<()> {
        if self
            .assertions
            .iter()
            .any(|entry| entry.value.target_ref != target_ref)
        {
            return Err(WireError::Protocol(
                "message_reactions assertion reacts to another target".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MessageReactionsCurrentValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MessageReactionsCurrentValueWire::deserialize(deserializer)?;
        Self::new(wire.assertions).map_err(serde::de::Error::custom)
    }
}

include!("generated/reaction_contracts.rs");
