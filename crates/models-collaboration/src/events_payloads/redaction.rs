//! Per-message redaction tombstone wire shape.
//!
//! Migrated from `arkret-core` (`events/redaction.rs`); a shim there
//! re-exports these helpers to preserve the `arkret_core::` path.
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

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

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
        json!({
            "kind": "ak.content.text",
            "body": REDACTED_MESSAGE_PLACEHOLDER,
        }),
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
    "mention_routing_hint",
    "mention_sidecar_hash",
    "mentions",
    "poll",
    "preview",
    "push_snippet",
    "reaction_summary",
    "reactions",
    "relations",
    "reply_to",
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

    #[test]
    fn tombstone_preserves_audit_metadata_and_strips_body() {
        let mut event = json!({
            "kind": "ak.message.create",
            "event_id": "ak:event:01970e58-0004-7000-8000-0000000005a1",
            "message_id": "ak:message:01970e58-0004-7000-8000-0000000005a1",
            "realm_id": "ak:realm:01970e58-0004-7000-8000-000000000001",
            "sender": "did:webvh:z6mkfixture:bob.example",
            "created_at": "2026-04-26T00:00:00.000Z",
            "content": {"kind": "ak.content.text", "body": "secret"},
            "reactions": [{"actor": "did:webvh:z6mkfixture:alice.example", "key": "+1"}],
            "reply_to": "ak:event:01970e58-0004-7000-8000-0000000005a0",
            "mentions": [{"actor_id": "did:webvh:z6mkfixture:alice.example"}],
        });
        let redacted_at = DateTime::parse_from_rfc3339("2026-04-26T00:05:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        redaction_tombstone_message_value(
            &mut event,
            redacted_at,
            Some("ak:event:01970e58-0004-7000-8000-0000000005a2"),
        );

        assert_eq!(event["kind"], json!("ak.message.create"));
        assert_eq!(
            event["event_id"],
            json!("ak:event:01970e58-0004-7000-8000-0000000005a1")
        );
        assert_eq!(event["redacted"], json!(true));
        assert_eq!(event["state"], json!("redacted"));
        assert_eq!(
            event["redaction_ref"],
            json!("ak:event:01970e58-0004-7000-8000-0000000005a2")
        );
        assert_eq!(
            event["content"]["body"],
            json!(REDACTED_MESSAGE_PLACEHOLDER)
        );
        assert!(event.get("reactions").is_none());
        assert!(event.get("reply_to").is_none());
        assert!(event.get("mentions").is_none());
        assert_eq!(event["created_at"], json!("2026-04-26T00:00:00.000Z"));
    }

    #[test]
    fn tombstone_without_redaction_ref_omits_field() {
        let mut event = json!({
            "kind": "ak.message.create",
            "content": {"kind": "ak.content.text", "body": "secret"},
        });
        let redacted_at = Utc::now();

        redaction_tombstone_message_value(&mut event, redacted_at, None);

        assert!(event.get("redaction_ref").is_none());
        assert_eq!(
            event["content"]["body"],
            json!(REDACTED_MESSAGE_PLACEHOLDER)
        );
    }
}
