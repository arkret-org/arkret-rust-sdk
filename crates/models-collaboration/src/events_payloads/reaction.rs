//! Reaction event payloads and the `message_reactions` typed current value.

use crate::exact_current_results::CanonicalEventDot;
use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPayload {
    pub target_ref: ObjectRef,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<EncryptedEnvelope>,
}

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

/// One asserted element of the `message_reactions` keyed set
/// (`typed-current-result.schema.json#/$defs/reaction_assertion_entry`): the
/// accepting Event's canonical dot and that Event's complete reaction payload.
///
/// The asserting actor and the polarity (add or remove) are deliberately not
/// element fields: `models/strand-and-message.md` section 9.8.3 reads both from
/// the signed envelope of the Event the dot names.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionAssertionEntry {
    pub tag_id: CanonicalEventDot,
    pub value: ReactionPayload,
}

/// Closed value of the `message_reactions` typed current result
/// (`typed-current-result.schema.json#/$defs/message_reactions_value`): the
/// canonically sorted dot set of reaction assertions on one target.
///
/// `ak.reaction.add` and `ak.reaction.remove` each project exactly one
/// `keyed_set_add`, so every element's dot names write index 0 of its Event,
/// and a remove is itself an element. The join is the keyed-set union of
/// `models/common-fields.md` section 2; membership, deduplication and counts
/// are read-side folds and never part of this value. Decoding enforces the
/// set invariants, so a held value is always a valid set of one target.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionsCurrentValue {
    assertions: Vec<ReactionAssertionEntry>,
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
            .any(|pair| pair[0].tag_id.to_string() >= pair[1].tag_id.to_string())
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
        let tag = entry.tag_id.to_string();
        match self
            .assertions
            .binary_search_by(|existing| existing.tag_id.to_string().cmp(&tag))
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
