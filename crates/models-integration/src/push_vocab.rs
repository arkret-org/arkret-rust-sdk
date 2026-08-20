//! Push wire vocabulary: closed token sets and validity predicates for
//! blind wakeup payload fields. The blind-payload sanitization behavior
//! that consumes this vocabulary lives in `arkret-policy`.

/// Maximum value permitted for badge / unread / count fields.
///
/// Push providers commonly cap badges at 99+ for UI purposes; we tighten
/// to a small range so blind wakeups can never smuggle a 4-byte stable
/// counter that's effectively an identifier.
pub const MAX_COUNT_VALUE: u64 = 9_999;

/// Closed enum of wakeup_kind values accepted in blind wakeups.
pub const ALLOWED_WAKEUP_KINDS: &[&str] = &[
    "message",
    "mention",
    "assignment",
    "schedule",
    "reaction",
    "call_invite",
    "reminder",
    "scheduled_send",
    "expiry_invalidation",
];

/// Closed enum of `push_hint` values accepted in blind wakeups.
///
/// The `l10n_key:<token>` form is accepted in addition to these literals.
pub const ALLOWED_PUSH_HINTS: &[&str] = &["new_message", "incoming_call", "mention_self"];

/// Closed enum of `timing_profile_hint` values accepted in blind wakeups.
pub const ALLOWED_TIMING_PROFILE_HINTS: &[&str] = &["default", "traffic_metadata_hardened"];

/// Return true if `value` is a valid `push_target_id` (opaque pseudonym).
///
/// Matches the spec pattern exactly:
/// `push-operations.schema.json#/$defs/push_target_id` is
/// `^ak:pseudonym:push:[A-Za-z0-9_-]{22,128}$` — the typed
/// `ak:pseudonym:push:` prefix is mandatory; a bare base64url token, a DID, or
/// any other `ak:` typed id is rejected.
pub fn is_valid_push_target_id(value: &str) -> bool {
    let Some(token) = value.strip_prefix("ak:pseudonym:push:") else {
        return false;
    };
    (22..=128).contains(&token.len())
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

/// Return true if `value` is a valid `wakeup_kind` for blind wakeups.
pub fn is_valid_wakeup_kind(value: &str) -> bool {
    ALLOWED_WAKEUP_KINDS.contains(&value)
}

/// Return true if `value` is a valid `timing_profile_hint` for blind wakeups.
pub fn is_valid_timing_profile_hint(value: &str) -> bool {
    ALLOWED_TIMING_PROFILE_HINTS.contains(&value)
}

/// Helper for callers that need to validate private extension tokens before
/// mapping them onto the closed v1 wakeup_kind enum.
pub fn is_valid_custom_wakeup_kind(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("did:") || lower.contains("ak:") {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
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
        if lower.contains("did:") || lower.contains("ak:") {
            return false;
        }
        return token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    }
    false
}
