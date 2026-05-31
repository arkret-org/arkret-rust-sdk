//! Blind push-payload sanitizer (T1.1).
//!
//! Single source of truth for the Contrix v1 push gateway "blind wakeup"
//! payload contract. Both push gateways (e.g. floria) and gateway clients
//! (e.g. chime) call into the same sanitizer so the allowed/forbidden field
//! rules cannot drift between implementations.
//!
//! ## Scope
//!
//! T0.3 promoted `blind_wakeup` to the gateway default profile. In that
//! profile the push provider's payload must contain only opaque wake-up
//! metadata — it must not carry any stable identifier, sender DID/handle,
//! human-readable name, message body, attachment metadata, call setup, or
//! correlation key that could be used to link two pushes back to the same
//! identity, device, conversation, or thread.
//!
//! ## Allowed fields
//!
//! - `push_target_id` — opaque pseudonym token (see [`is_valid_push_target_id`]).
//! - `wakeup_kind` — closed enum (`message`, `mention`, `reaction`,
//!   `call_invite`).
//! - `badge`, `unread_count`, `count`, `unread` — small non-negative
//!   integers (≤ `MAX_COUNT_VALUE`). May be carried inside a `counts` object.
//! - `push_hint` — closed enum (`new_message`, `incoming_call`,
//!   `mention_self`) **or** the form `l10n_key:<token>` where the token is
//!   ASCII alphanumeric/`._-`, ≤ 64 chars, and never contains PII.
//!
//! ## Forbidden fields
//!
//! Any presence of these top-level or nested keys triggers a
//! [`BlindPayloadReasonCode::ForbiddenField`]:
//!
//! - Correlation identifiers: `event_id`, `message_id`, `flow_id`,
//!   `realm_id`, `space_id`, `place_id`, `thread_id`, `correlation_id`,
//!   `request_id`, `txn_id`.
//! - Sender identity: `sender`, `sender_did`, `sender_handle`,
//!   `sender_display_name`, `sender_name`, `user_name`, `display_name`,
//!   `from`, `to`, `target_did`.
//! - Device identity: `device_did`, `device_url`, `device_id`,
//!   `device_name`.
//! - Content / preview: `body`, `content`, `text`, `message`, `title`,
//!   `subtitle`, `preview`, `summary`, `alert`, `notification_body`,
//!   `notification_title`, `formatted_body`, `template`, `template_vars`,
//!   `reaction`, `reaction_value`.
//! - Attachment metadata: `filename`, `file_name`, `attachment_name`,
//!   `attachment_filename`, `attachment_preview`, `mime_type`, `media_url`.
//! - Space / flow / room names: `space_name`, `flow_name`, `room_name`,
//!   `room_display_name`.
//! - Provider escape hatches: `provider_payload`, `provider_data`,
//!   `notification_payload`, `payload`, `aps`, `android`, `webpush`,
//!   `encrypted_payload`, `ciphertext`.
//! - Call setup: `sdp`, `offer`, `candidate`, `ice`, `ice_candidate`,
//!   `ice_candidates`, `turn`, `turns`, `turn_credential`,
//!   `turn_credentials`, `call_setup`.
//! - View renderers: `facet`, `facets`, `entity_facet`, `entity_facets`,
//!   `view_renderer`, `view_renderers`, `rendered_view`, `renderer`.
//!
//! In addition, any string value containing the literal substring `did:` or
//! the typed-id prefix `cx:` is rejected as a sensitive correlation key,
//! except inside `push_target_id` (which has its own opaque-pseudonym
//! contract — see [`is_valid_push_target_id`]).

use serde_json::Value;
use thiserror::Error;

/// Maximum value permitted for badge / unread / count fields.
///
/// Push providers commonly cap badges at 99+ for UI purposes; we tighten
/// to a small range so blind wakeups can never smuggle a 4-byte stable
/// counter that's effectively an identifier.
pub const MAX_COUNT_VALUE: u64 = 9_999;

/// Closed enum of wakeup_kind values accepted in blind wakeups.
///
pub const ALLOWED_WAKEUP_KINDS: &[&str] = &["message", "mention", "reaction", "call_invite"];

/// Closed enum of `push_hint` values accepted in blind wakeups.
///
/// The `l10n_key:<token>` form is accepted in addition to these literals.
pub const ALLOWED_PUSH_HINTS: &[&str] = &["new_message", "incoming_call", "mention_self"];

/// Fields allowed by the blind wakeup contract.
///
/// Keys not in this list are treated as forbidden when they appear in
/// payloads validated by [`sanitize_blind_payload`].
pub const ALLOWED_BLIND_FIELDS: &[&str] = &[
    "push_target_id",
    "wakeup_kind",
    "push_hint",
    "badge",
    "unread_count",
    "count",
    "unread",
    "counts",
];

/// Reason code for a [`BlindPayloadError`].
///
/// Stable, machine-readable strings so callers (and tests) can match on
/// them without parsing the human message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlindPayloadReasonCode {
    /// A key in the [`ALLOWED_BLIND_FIELDS`] list had a malformed value.
    InvalidFieldValue,
    /// A key was forbidden by name (correlation id, sender info, content,
    /// provider escape hatch, call setup, view renderer, …).
    ForbiddenField,
    /// A string value contained `did:` or `cx:` substring outside the
    /// `push_target_id` opaque-pseudonym slot.
    SensitiveLiteral,
    /// A required field (e.g. `push_target_id` or `wakeup_kind` in strict
    /// mode) is missing.
    MissingRequiredField,
}

impl BlindPayloadReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFieldValue => "invalid_field_value",
            Self::ForbiddenField => "forbidden_field",
            Self::SensitiveLiteral => "sensitive_literal",
            Self::MissingRequiredField => "missing_required_field",
        }
    }
}

impl std::fmt::Display for BlindPayloadReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`sanitize_blind_payload`].
///
/// `field_path` is a dotted/indexed JSON path (e.g.
/// `notification.devices[0].data.default_payload.title`) so callers can
/// point operators at the exact offending field.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("blind payload {reason_code} at `{field_path}`: {message}")]
pub struct BlindPayloadError {
    pub field_path: String,
    pub reason_code: BlindPayloadReasonCode,
    pub message: String,
}

impl BlindPayloadError {
    fn forbidden(field_path: impl Into<String>) -> Self {
        let field_path = field_path.into();
        Self {
            message: format!("field `{field_path}` is forbidden in blind wakeup payloads"),
            field_path,
            reason_code: BlindPayloadReasonCode::ForbiddenField,
        }
    }

    fn invalid(field_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field_path: field_path.into(),
            reason_code: BlindPayloadReasonCode::InvalidFieldValue,
            message: message.into(),
        }
    }

    fn sensitive(field_path: impl Into<String>) -> Self {
        let field_path = field_path.into();
        Self {
            message: format!("field `{field_path}` contains a sensitive `did:` / `cx:` literal"),
            field_path,
            reason_code: BlindPayloadReasonCode::SensitiveLiteral,
        }
    }

    fn missing(field_path: impl Into<String>) -> Self {
        let field_path = field_path.into();
        Self {
            message: format!("required field `{field_path}` is missing"),
            field_path,
            reason_code: BlindPayloadReasonCode::MissingRequiredField,
        }
    }
}

/// Strictness level for [`sanitize_blind_payload_with`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SanitizerMode {
    /// Default sanitizer — reject any forbidden key, sensitive literal, or
    /// out-of-range count. Unknown keys are treated as forbidden so the
    /// allow-list cannot be circumvented by typos or unfamiliar provider
    /// extensions.
    Default,
    /// Strict sanitizer — same checks as `Default` plus the requirement
    /// that `push_target_id` and `wakeup_kind` are present at the top
    /// level. Used by gateway entry points that have already extracted
    /// the wire-model `notification` object.
    Strict,
}

/// Validate that a JSON payload satisfies the blind-wakeup contract.
///
/// Accepts either:
/// * a "notification" object (allow-listed fields at the top level), or
/// * a wrapper object that contains a `notification` field — only the
///   `notification` sub-object is checked against the allow-list; the
///   wrapper itself may carry routing metadata (`operation_id`,
///   `destination_service_did`, `devices`, …) and is recursively scanned
///   only for sensitive literals and forbidden keys, not against the
///   allow-list.
///
/// Use [`sanitize_blind_payload_strict`] for the gateway ingress / push
/// provider variant that also requires `push_target_id` + `wakeup_kind`.
pub fn sanitize_blind_payload(payload: &Value) -> Result<(), BlindPayloadError> {
    sanitize_blind_payload_with(payload, SanitizerMode::Default)
}

/// Like [`sanitize_blind_payload`] but also requires `push_target_id` and
/// `wakeup_kind` to be present in the (extracted) notification object.
pub fn sanitize_blind_payload_strict(payload: &Value) -> Result<(), BlindPayloadError> {
    sanitize_blind_payload_with(payload, SanitizerMode::Strict)
}

/// Lower-level entry point used by [`sanitize_blind_payload`] and
/// [`sanitize_blind_payload_strict`].
pub fn sanitize_blind_payload_with(
    payload: &Value,
    mode: SanitizerMode,
) -> Result<(), BlindPayloadError> {
    let notification = match payload {
        Value::Object(map) => match map.get("notification") {
            Some(Value::Object(inner)) => {
                // Wrapper form: still scan the wrapper for forbidden keys,
                // but skip the wrapper's own allow-list check (the wrapper
                // is the gateway envelope, not the user-visible payload).
                for (key, value) in map {
                    if key == "notification" {
                        continue;
                    }
                    let path = key.clone();
                    if is_forbidden_payload_key(key) {
                        return Err(BlindPayloadError::forbidden(path));
                    }
                    scan_forbidden(&path, value)?;
                }
                inner
            }
            Some(_) => {
                return Err(BlindPayloadError::invalid(
                    "notification",
                    "notification must be a JSON object",
                ));
            }
            None => map,
        },
        _ => {
            return Err(BlindPayloadError::invalid("", "blind payload must be a JSON object"));
        }
    };

    if mode == SanitizerMode::Strict {
        if !notification.contains_key("push_target_id") {
            return Err(BlindPayloadError::missing("push_target_id"));
        }
        if !notification.contains_key("wakeup_kind") {
            return Err(BlindPayloadError::missing("wakeup_kind"));
        }
    }

    for (key, value) in notification {
        if is_forbidden_payload_key(key) {
            return Err(BlindPayloadError::forbidden(key.clone()));
        }
        if !is_allowed_blind_field(key) {
            return Err(BlindPayloadError::forbidden(key.clone()));
        }
        validate_allowed_field(key, value)?;
    }

    Ok(())
}

fn validate_allowed_field(key: &str, value: &Value) -> Result<(), BlindPayloadError> {
    match key {
        "push_target_id" => match value.as_str() {
            Some(raw) if is_valid_push_target_id(raw) => Ok(()),
            Some(_) => Err(BlindPayloadError::invalid(
                key,
                "push_target_id must be an opaque pseudonym (cx:pseudonym:push:<token> \
                 or base64url ≥ 22 chars)",
            )),
            None => Err(BlindPayloadError::invalid(key, "push_target_id must be a string")),
        },
        "wakeup_kind" => match value.as_str() {
            Some(raw) if is_valid_wakeup_kind(raw) => Ok(()),
            Some(_) => Err(BlindPayloadError::invalid(
                key,
                "wakeup_kind must be one of message/mention/reaction/call_invite",
            )),
            None => Err(BlindPayloadError::invalid(key, "wakeup_kind must be a string")),
        },
        "push_hint" => match value.as_str() {
            Some(raw) if is_valid_push_hint(raw) => Ok(()),
            Some(_) => Err(BlindPayloadError::invalid(
                key,
                "push_hint must be one of new_message/incoming_call/mention_self \
                 or `l10n_key:<token>`",
            )),
            None => Err(BlindPayloadError::invalid(key, "push_hint must be a string")),
        },
        "badge" | "unread_count" | "count" | "unread" => validate_count_number(key, value),
        "counts" => validate_counts_tree(key, value),
        _ => Ok(()),
    }
}

fn validate_count_number(path: &str, value: &Value) -> Result<(), BlindPayloadError> {
    match value.as_u64() {
        Some(n) if n <= MAX_COUNT_VALUE => Ok(()),
        Some(_) => {
            Err(BlindPayloadError::invalid(path, format!("count must be ≤ {MAX_COUNT_VALUE}")))
        }
        None => Err(BlindPayloadError::invalid(path, "count must be a non-negative integer")),
    }
}

fn validate_counts_tree(path: &str, value: &Value) -> Result<(), BlindPayloadError> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let next_path = format!("{path}.{key}");
                if is_forbidden_payload_key(key) {
                    return Err(BlindPayloadError::forbidden(next_path));
                }
                validate_counts_tree(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Number(_) => validate_count_number(path, value),
        _ => Err(BlindPayloadError::invalid(
            path,
            "counts entries must be non-negative integers or nested objects of such",
        )),
    }
}

fn scan_forbidden(path: &str, value: &Value) -> Result<(), BlindPayloadError> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let next_path = format!("{path}.{key}");
                if is_forbidden_payload_key(key) {
                    return Err(BlindPayloadError::forbidden(next_path));
                }
                scan_forbidden(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                scan_forbidden(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        Value::String(raw) => check_sensitive_literal(path, raw),
        _ => Ok(()),
    }
}

fn check_sensitive_literal(path: &str, raw: &str) -> Result<(), BlindPayloadError> {
    // push_target_id can legitimately contain a `cx:pseudonym:push:` prefix
    // (the allow-list path validates the rest of the token). For everything
    // else `did:` or `cx:` substrings are correlation leaks.
    if path.ends_with("push_target_id") {
        return Ok(());
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("did:") || lower.contains("cx:") {
        return Err(BlindPayloadError::sensitive(path));
    }
    Ok(())
}

/// Return true if `key` is an allow-listed field name for the blind
/// wakeup contract.
pub fn is_allowed_blind_field(key: &str) -> bool {
    ALLOWED_BLIND_FIELDS.contains(&key)
}

/// Return true if `key` is a forbidden payload key for the blind wakeup
/// contract. Centralised here so chime / floria stay in sync.
pub fn is_forbidden_payload_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        // Correlation identifiers.
        "event_id"
            | "message_id"
            | "flow_id"
            // Realm/Space inversion (spec 59ac1d4): the security-boundary
            // identifier is now `realm_id`; the renamed container identifier
            // continues to use `space_id`. Both are forbidden in blind push
            // payloads since either leaks correlatable scope.
            | "realm_id"
            | "space_id"
            | "place_id"
            | "thread_id"
            | "correlation_id"
            | "request_id"
            | "txn_id"
            | "tracking_id"
            // Sender / target identity.
            | "sender"
            | "sender_did"
            | "sender_handle"
            | "sender_display_name"
            | "sender_name"
            | "user_name"
            | "display_name"
            | "from"
            | "to"
            | "target_did"
            | "actor"
            // Audience mention expansion state. Servers may compute
            // receiver-side `mentions_actor`, but push payloads must not
            // leak which audience was expanded, recipient counts, or the
            // concrete recipient list.
            | "audience"
            | "audiences"
            | "audience_mention"
            | "audience_mentions"
            | "audience_mention_policy"
            | "audience_mention_routing_hint"
            | "audience_recipient_count"
            | "recipient_count"
            | "recipient_counts"
            | "expanded_recipients"
            | "watcher_count"
            | "participant_count"
            | "engaged_count"
            // Device identity.
            | "device_did"
            | "device_url"
            | "device_id"
            | "device_name"
            // Content / preview.
            | "body"
            // Spec rename (head 37ce729): `message_body` → `message_content`.
            | "message_content"
            | "formatted_body"
            | "notification_body"
            | "message"
            | "message_text"
            | "text"
            | "plaintext"
            | "content"
            | "title"
            | "subtitle"
            | "notification_title"
            | "alert"
            | "preview"
            | "summary"
            | "template"
            | "template_vars"
            | "reaction"
            | "reaction_value"
            // Attachment metadata.
            | "filename"
            | "file_name"
            | "attachment_name"
            | "attachment_filename"
            | "attachment_preview"
            | "mime_type"
            | "media_url"
            // Space / flow / room names.
            | "space_name"
            | "flow_name"
            | "room_name"
            | "room_display_name"
            // Provider escape hatches.
            | "provider_payload"
            | "provider_data"
            | "notification_payload"
            | "payload"
            | "aps"
            | "android"
            | "webpush"
            | "encrypted_payload"
            | "ciphertext"
            // Call setup.
            | "sdp"
            | "offer"
            | "candidate"
            | "ice"
            | "ice_candidate"
            | "ice_candidates"
            | "turn"
            | "turns"
            | "turn_credential"
            | "turn_credentials"
            | "call_setup"
            // View renderers.
            | "facet"
            | "facets"
            | "entity_facet"
            | "entity_facets"
            | "view_renderer"
            | "view_renderers"
            | "rendered_view"
            | "renderer"
    )
}

/// Return true if `value` is a valid `push_target_id` (opaque pseudonym).
///
/// Accepts either the typed `cx:pseudonym:push:<token>` form **or** a bare
/// base64url-shaped token (≥ 22 ASCII alphanumeric/`-_` characters, ≤ 128).
/// Rejects DIDs and any other `cx:` typed-id whose prefix is not
/// `cx:pseudonym:push:`.
pub fn is_valid_push_target_id(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("did:") {
        return false;
    }
    let token = if let Some(token) = trimmed.strip_prefix("cx:pseudonym:push:") {
        token
    } else if trimmed.starts_with("cx:") || trimmed.contains(':') {
        return false;
    } else {
        trimmed
    };
    (22..=128).contains(&token.len())
        && token.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

/// Return true if `value` is a valid `wakeup_kind` for blind wakeups.
pub fn is_valid_wakeup_kind(value: &str) -> bool {
    ALLOWED_WAKEUP_KINDS.contains(&value)
}

/// Legacy helper retained for callers that need to validate private extension
/// tokens before mapping them onto the closed v1 wakeup_kind enum.
pub fn is_valid_custom_wakeup_kind(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("did:") || lower.contains("cx:") {
        return false;
    }
    value.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

/// Return true if `value` is a valid `push_hint` for blind wakeups.
pub fn is_valid_push_hint(value: &str) -> bool {
    if ALLOWED_PUSH_HINTS.contains(&value) {
        return true;
    }
    if let Some(token) = value.strip_prefix("l10n_key:") {
        if token.is_empty() || token.len() > 64 {
            return false;
        }
        let lower = token.to_ascii_lowercase();
        if lower.contains("did:") || lower.contains("cx:") {
            return false;
        }
        return token.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_notification() -> Value {
        json!({
            "notification": {
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "counts": { "unread": 1 },
            }
        })
    }

    #[test]
    fn accepts_minimal_blind_payload() {
        sanitize_blind_payload(&ok_notification()).unwrap();
        sanitize_blind_payload_strict(&ok_notification()).unwrap();
    }

    #[test]
    fn accepts_bare_notification_object() {
        sanitize_blind_payload(&json!({
            "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "call_invite",
        }))
        .unwrap();
    }

    #[test]
    fn rejects_title_anywhere() {
        let mut v = ok_notification();
        v["notification"]["title"] = json!("Secret");
        let err = sanitize_blind_payload(&v).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::ForbiddenField);
        assert_eq!(err.field_path, "title");
    }

    #[test]
    fn rejects_event_id() {
        let mut v = ok_notification();
        v["notification"]["event_id"] = json!("cx:event:01JS0EV000000000000000000");
        let err = sanitize_blind_payload(&v).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::ForbiddenField);
    }

    #[test]
    fn rejects_audience_mention_expansion_leaks() {
        for field in [
            "audience",
            "audience_mentions",
            "audience_mention_routing_hint",
            "recipient_count",
            "expanded_recipients",
        ] {
            let mut v = ok_notification();
            v["notification"][field] = json!("flow_engaged");
            let err = sanitize_blind_payload(&v).unwrap_err();
            assert_eq!(err.reason_code, BlindPayloadReasonCode::ForbiddenField);
            assert_eq!(err.field_path, field);
        }
    }

    #[test]
    fn rejects_sender_did_literal_in_extra() {
        // `provider_payload` is forbidden by key name, but even if a
        // gateway tried to smuggle a DID into a value-shaped field we
        // catch it at the wrapper-scan stage.
        let payload = json!({
            "notification": {
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
            },
            "operation_id": "cx.push.notify",
            "context": { "trace": "did:web:alice.example" },
        });
        let err = sanitize_blind_payload(&payload).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::SensitiveLiteral);
        assert_eq!(err.field_path, "context.trace");
    }

    #[test]
    fn rejects_unknown_field_in_notification() {
        let mut v = ok_notification();
        v["notification"]["custom_extension"] = json!("anything");
        let err = sanitize_blind_payload(&v).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::ForbiddenField);
    }

    #[test]
    fn rejects_oversized_count() {
        let mut v = ok_notification();
        v["notification"]["counts"] = json!({ "unread": MAX_COUNT_VALUE + 1 });
        let err = sanitize_blind_payload(&v).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::InvalidFieldValue);
    }

    #[test]
    fn rejects_did_target_id() {
        assert!(!is_valid_push_target_id("did:web:alice.example"));
        assert!(!is_valid_push_target_id("cx:device:01HYZ8Z000000000000000"));
        assert!(is_valid_push_target_id("cx:pseudonym:push:01HYZ8Z000000000000000"));
        assert!(is_valid_push_target_id("01HYZ8Z000000000000000"));
    }

    #[test]
    fn rejects_l10n_key_with_pii() {
        assert!(is_valid_push_hint("l10n_key:message.new"));
        assert!(!is_valid_push_hint("l10n_key:did:web:alice"));
        assert!(!is_valid_push_hint("title:secret"));
    }

    #[test]
    fn strict_requires_push_target_id() {
        let payload = json!({
            "notification": {
                "wakeup_kind": "message"
            }
        });
        let err = sanitize_blind_payload_strict(&payload).unwrap_err();
        assert_eq!(err.reason_code, BlindPayloadReasonCode::MissingRequiredField);
        assert_eq!(err.field_path, "push_target_id");
    }

    #[test]
    fn rejects_correlation_id() {
        let mut v = ok_notification();
        v["notification"]["correlation_id"] = json!("abc");
        assert_eq!(
            sanitize_blind_payload(&v).unwrap_err().reason_code,
            BlindPayloadReasonCode::ForbiddenField
        );
    }
}
