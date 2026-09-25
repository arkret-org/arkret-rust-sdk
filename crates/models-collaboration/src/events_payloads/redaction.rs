//! Per-message redaction tombstone wire shape.
//!
//! The `arkret` umbrella re-exports these owner-defined helpers at its root.
//!
//! Spec `models/strand-and-message.md §9` (Message lifecycle): a redacted
//! `ak.message.create` keeps its slot and audit metadata (`event_id`,
//! `created_at`, `sender`, `kind`) while its `content` is cleared and replaced
//! with a redaction tombstone. The message-level `state` flips to `redacted`
//! and `redaction_ref` points at the triggering `ak.message.redact` event.
//!
//! The server message stream (sync timeline / backfill projection) surfaces the
//! tombstone instead of either dropping the row or leaking the original body, so
//! a reader that reloads after a redaction renders a tombstone marker rather
//! than the plaintext.

use arkret_wire::{MessageId, ObjectRef, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::message::{ContentBlock, MessageRedactPayload};
use crate::exact_current_results::CanonicalEventDot;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/cross_object_redaction_payload`.
///
/// `ak.redaction` is the cross-object redaction kind. Per
/// `models/common-fields.md` §5.1 (Message exemption) its target set excludes
/// Message: `message_id` is not a member and `target_ref` cannot spell
/// `ak:message:`, because Message reaches `state=redacted` only through the
/// object-scoped `ak.message.redact`. This type is the single place that
/// decision is enforced; implementations MUST NOT keep a private prefix
/// allow/deny table beside it.
///
/// `target_ref` is the single target carrier. Its lexical space already covers
/// both object targets and `ak:event:` targets, so the registered
/// `ak.component.object.redaction.v1` cell subject is that one scalar and the
/// same target cannot be spelled two ways.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossObjectRedactionPayload {
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserve: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossObjectRedactionPayloadWire {
    target_ref: ObjectRef,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    preserve: Option<Vec<String>>,
}

impl CrossObjectRedactionPayload {
    /// Reject a Message target: it belongs to `ak.message.redact`.
    pub fn validate(&self) -> Result<()> {
        if MessageId::new(self.target_ref.as_str()).is_ok() {
            return Err(WireError::Protocol(
                "cross_object_redaction_payload target_ref MUST NOT name a Message".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CrossObjectRedactionPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CrossObjectRedactionPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            target_ref: wire.target_ref,
            reason: wire.reason,
            preserve: wire.preserve,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// The complete redact payload one `object_redaction` assertion carries
/// (`typed-current-result.schema.json#/$defs/object_redaction_entry`): the
/// Message redact payload for an `ak:message:` subject, the cross-object
/// payload for every other subject.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObjectRedactionAssertionValue {
    Message(MessageRedactPayload),
    CrossObject(CrossObjectRedactionPayload),
}

impl ObjectRedactionAssertionValue {
    /// The verbatim target spelling this assertion redacts.
    pub fn target_ref(&self) -> &str {
        match self {
            Self::Message(payload) => payload.message_id.as_str(),
            Self::CrossObject(payload) => payload.target_ref.as_str(),
        }
    }
}

/// One tagged `object_redaction` assertion: the accepting Event's canonical
/// dot and its unassembled redact payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRedactionEntry {
    pub tag_id: CanonicalEventDot,
    pub value: ObjectRedactionAssertionValue,
}

/// Closed value of the `object_redaction` typed current result
/// (`typed-current-result.schema.json#/$defs/object_redaction_value`): the
/// canonically sorted dot set of committed redactions of one subject. Both
/// writers only add a dot, and the object's own `state` and `redaction_ref`
/// are never mirrored here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRedactionCurrentValue {
    pub assertions: Vec<ObjectRedactionEntry>,
}

impl ObjectRedactionCurrentValue {
    /// Every assertion redacts exactly `target_ref`, the set is non-empty and
    /// its dots are strictly ascending in canonical string order.
    pub fn validate_for_subject(&self, target_ref: &str) -> Result<()> {
        if self.assertions.is_empty() {
            return Err(WireError::Protocol(
                "object_redaction value has no assertion".to_owned(),
            ));
        }
        if self
            .assertions
            .iter()
            .any(|entry| entry.value.target_ref() != target_ref)
        {
            return Err(WireError::Protocol(
                "object_redaction assertion redacts another subject".to_owned(),
            ));
        }
        if self
            .assertions
            .windows(2)
            .any(|pair| pair[0].tag_id.to_string() >= pair[1].tag_id.to_string())
        {
            return Err(WireError::Protocol(
                "object_redaction dots are not a canonically sorted set".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Placeholder body for a redacted message tombstone. Mirrors the
/// erasure / retention placeholder style so renderers can fall back to a
/// human label when they do not special-case the structured marker.
pub const REDACTED_MESSAGE_PLACEHOLDER: &str = "[redacted]";

/// Wire field set on a redacted message tombstone marking the row redacted.
/// Aligns with the Message `state` enum (`active` / `redacted`).
pub const REDACTED_MESSAGE_STATE: &str = "redacted";

/// Replace a message-create timeline value with its redaction tombstone form.
///
/// Preserves audit metadata (`event_id`, `message_id`, `kind`, `created_at`,
/// `sender`, routing ids) and removes every plaintext / derived surface so the
/// original body cannot be recovered from the stream. Adds the structured
/// markers a client folds onto an existing message: `redacted: true`,
/// `state: "redacted"`, `redacted_at`, and (when known) `redaction_ref`.
pub fn redaction_tombstone_message_value(
    event: &mut Value,
    redacted_at: DateTime<Utc>,
    redaction_ref: Option<&str>,
) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    strip_redaction_derived_fields(object);
    object.insert("redacted".to_owned(), json!(true));
    object.insert("state".to_owned(), json!(REDACTED_MESSAGE_STATE));
    object.insert(
        "redacted_at".to_owned(),
        json!(arkret_canonical::format_timestamp_canonical(redacted_at)),
    );
    if let Some(redaction_ref) = redaction_ref
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        object.insert(
            "redaction_ref".to_owned(),
            Value::String(redaction_ref.to_owned()),
        );
    }
    object.insert(
        "content".to_owned(),
        serde_json::to_value(ContentBlock::text(REDACTED_MESSAGE_PLACEHOLDER))
            .expect("typed content block serialization is infallible"),
    );
    object.insert("encrypted".to_owned(), json!(false));
    object.insert("decryption_state".to_owned(), json!("plaintext"));
}

/// Derived / plaintext-bearing fields that MUST NOT survive a message
/// redaction tombstone. Reaction / reply / mention surfaces are dropped so the
/// default view stops exposing them once the target is redacted.
const REDACTION_DERIVED_FIELD_KEYS: &[&str] = &[
    "attachments",
    "blob_refs",
    "encrypted_content",
    "media",
    "mentions",
    "poll",
    "preview",
    "push_snippet",
    "reaction_summary",
    "reactions",
    "relations",
    "reply_to_id",
    "search_terms",
    "search_tokens",
    "snippet",
    "thumbnails",
];

fn strip_redaction_derived_fields(object: &mut Map<String, Value>) {
    for key in REDACTION_DERIVED_FIELD_KEYS {
        object.remove(*key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_id(seed: &[u8]) -> MessageId {
        MessageId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(seed),
        ))
    }

    fn dot(seed: &[u8]) -> String {
        let event_id = arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(seed),
        );
        format!("{event_id}:0")
    }

    #[test]
    fn object_redaction_value_is_a_closed_sorted_set_of_one_subject() {
        let target = message_id(b"redacted message");
        let mut tags = [dot(b"first redact"), dot(b"second redact")];
        tags.sort();
        let wire = json!({"assertions": [
            {"tag_id": tags[0], "value": {"message_id": target, "reason": "spam"}},
            {"tag_id": tags[1], "value": {"message_id": target}},
        ]});
        let value: ObjectRedactionCurrentValue = serde_json::from_value(wire.clone()).unwrap();
        value.validate_for_subject(target.as_str()).unwrap();
        assert!(matches!(
            value.assertions[0].value,
            ObjectRedactionAssertionValue::Message(_)
        ));
        assert_eq!(serde_json::to_value(&value).unwrap(), wire);
        assert!(
            value
                .validate_for_subject(message_id(b"another message").as_str())
                .is_err()
        );

        let mut unsorted = value.clone();
        unsorted.assertions.reverse();
        assert!(unsorted.validate_for_subject(target.as_str()).is_err());
        assert!(
            ObjectRedactionCurrentValue { assertions: vec![] }
                .validate_for_subject(target.as_str())
                .is_err()
        );

        let event_target = dot(b"event target");
        let event_target = event_target.trim_end_matches(":0");
        let cross: ObjectRedactionCurrentValue = serde_json::from_value(json!({"assertions": [
            {"tag_id": tags[0], "value": {"target_ref": event_target, "preserve": ["kind"]}},
        ]}))
        .unwrap();
        cross.validate_for_subject(event_target).unwrap();
        for invalid in [
            json!({"assertions": [{"tag_id": tags[0], "value": {"target_ref": target}}]}),
            json!({"assertions": [{"tag_id": tags[0].trim_end_matches(":0"), "value": {"message_id": target}}]}),
            json!({"assertions": [{"tag_id": tags[0], "value": {"message_id": target}, "extra": 1}]}),
            json!({"assertions": [], "subject": target}),
        ] {
            assert!(
                serde_json::from_value::<ObjectRedactionCurrentValue>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }
}
