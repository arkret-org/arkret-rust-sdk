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

use super::message::ContentBlock;

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
