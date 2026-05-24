//! T8.2 — property tests for the blind push-payload sanitizer.
//!
//! These tests exercise [`contrix_core::blind_payload_sanitizer`] with
//! randomly-shaped JSON values and assert two core invariants:
//!
//!  1. **No forbidden field ever survives.** If the sanitizer returns
//!     `Ok(())`, scanning the same payload for any name in the SDK's
//!     forbidden-key registry MUST find none — at any nesting depth.
//!  2. **Disguised keys do not slip through.** A handful of look-alike
//!     keys (`Sender`, `EVENT_ID`, `senderdid`, `space-name`, …) are
//!     either rejected (case-insensitive match of the real forbidden
//!     name) or, when not on the list, validated as ordinary unknown
//!     keys (forbidden because the allow-list is closed).
//!  3. **Sensitive literals are caught everywhere except
//!     `push_target_id`.** A string value containing `did:` or `cx:` in
//!     any non-pseudonym slot MUST be rejected.
//!
//! All proptest blocks use 64 cases to keep CI fast.

use contrix_core::blind_payload_sanitizer::{
    BlindPayloadReasonCode, MAX_COUNT_VALUE, is_forbidden_payload_key, sanitize_blind_payload,
    sanitize_blind_payload_strict,
};
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const PROPTEST_CASES: u32 = 64;

/// All keys the SDK marks as forbidden. Mirrors
/// `blind_payload_sanitizer::is_forbidden_payload_key`. If that list
/// expands the property test will still hold because it re-queries the
/// SDK via `is_forbidden_payload_key`; this constant is only used to
/// drive arbitrary inputs that probe each name.
const FORBIDDEN_NAMES: &[&str] = &[
    "event_id",
    "message_id",
    "flow_id",
    // Realm/Space inversion (spec 59ac1d4): the security-boundary identifier
    // is `realm_id`; the renamed container identifier continues to use
    // `space_id`; pre-inversion `place_id` is retained as forbidden alias.
    "realm_id",
    "space_id",
    "place_id",
    "thread_id",
    "correlation_id",
    "request_id",
    "txn_id",
    "tracking_id",
    "sender",
    "sender_did",
    "sender_handle",
    "sender_display_name",
    "sender_name",
    "user_name",
    "display_name",
    "from",
    "to",
    "target_did",
    "actor",
    "device_did",
    "device_url",
    "device_id",
    "device_name",
    "body",
    "message_body",
    "formatted_body",
    "notification_body",
    "message",
    "message_text",
    "text",
    "plaintext",
    "content",
    "title",
    "subtitle",
    "notification_title",
    "alert",
    "preview",
    "summary",
    "template",
    "template_vars",
    "reaction",
    "reaction_value",
    "filename",
    "file_name",
    "attachment_name",
    "attachment_filename",
    "attachment_preview",
    "mime_type",
    "media_url",
    "space_name",
    "flow_name",
    "room_name",
    "room_display_name",
    "provider_payload",
    "provider_data",
    "notification_payload",
    "payload",
    "aps",
    "android",
    "webpush",
    "encrypted_payload",
    "ciphertext",
    "sdp",
    "offer",
    "candidate",
    "ice",
    "ice_candidate",
    "ice_candidates",
    "turn",
    "turns",
    "turn_credential",
    "turn_credentials",
    "call_setup",
    "facet",
    "facets",
    "entity_facet",
    "entity_facets",
    "view_renderer",
    "view_renderers",
    "rendered_view",
    "renderer",
];

/// Strategy: a single forbidden key chosen from the SDK list.
fn arb_forbidden_key() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(FORBIDDEN_NAMES.to_vec())
}

/// Strategy: a plausible "look-alike" key — same letters, different
/// case, plus a few mangled variants like `senderDid`, `space-name`.
fn arb_disguised_key() -> impl Strategy<Value = String> {
    let base = arb_forbidden_key();
    let mangle = 0u8..6u8;
    (base, mangle).prop_map(|(name, kind)| match kind {
        0 => name.to_ascii_uppercase(),
        1 => {
            // Camel-case'd "sender_did" → "SenderDid".
            let mut out = String::with_capacity(name.len());
            let mut upper = true;
            for ch in name.chars() {
                if ch == '_' {
                    upper = true;
                } else if upper {
                    out.extend(ch.to_uppercase());
                    upper = false;
                } else {
                    out.push(ch);
                }
            }
            out
        }
        2 => name.replace('_', "-"),
        3 => format!(" {name}"),
        4 => name.replace('_', ""),
        _ => name.to_owned(),
    })
}

/// Strategy: a random "leaf" JSON value (no nested object/array). Keeps
/// the search space tractable.
fn arb_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|n| json!(n)),
        // Constrain string size so we don't generate megabytes of data.
        ".{0,32}".prop_map(Value::String),
    ]
}

/// Strategy: a JSON value up to depth 3, branching factor ≤ 4. Object
/// keys are short ASCII identifiers so the search space stays small.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = arb_leaf();
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::hash_map("[a-z_]{1,12}", inner, 0..4).prop_map(|m| {
                let mut map = Map::new();
                for (k, v) in m {
                    map.insert(k, v);
                }
                Value::Object(map)
            }),
        ]
    })
}

/// Helper: recursively scan a JSON value for any forbidden key by name.
fn contains_forbidden_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if is_forbidden_payload_key(k) {
                    return true;
                }
                if contains_forbidden_key(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(values) => values.iter().any(contains_forbidden_key),
        _ => false,
    }
}

/// Helper: recursively scan a JSON value for any string containing
/// `did:` or `cx:` (case-insensitive) in any path EXCEPT inside a
/// `push_target_id` slot.
fn contains_sensitive_literal(path: &str, value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.iter().any(|(k, v)| contains_sensitive_literal(&format!("{path}.{k}"), v))
        }
        Value::Array(values) => values
            .iter()
            .enumerate()
            .any(|(i, v)| contains_sensitive_literal(&format!("{path}[{i}]"), v)),
        Value::String(s) => {
            if path.ends_with("push_target_id") {
                return false;
            }
            let lower = s.to_ascii_lowercase();
            lower.contains("did:") || lower.contains("cx:")
        }
        _ => false,
    }
}

/// Build a baseline notification object that passes the sanitizer.
fn ok_notification() -> Value {
    json!({
        "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Property 1 — accepting payload ⇒ no forbidden field at any depth.
    ///
    /// We generate a random JSON value, wrap it inside a notification
    /// envelope, and run the sanitizer. If the sanitizer accepts, the
    /// payload must not carry any name on the forbidden list.
    #[test]
        fn accept_implies_no_forbidden_field(extra in arb_value()) {
            let payload = json!({
                "notification": ok_notification(),
                "extra": extra,
            });
        if sanitize_blind_payload(&payload).is_ok() {
            prop_assert!(
                !contains_forbidden_key(&payload),
                "sanitizer accepted but payload contains forbidden key: {payload:?}"
            );
        }
    }

    /// Property 2 — injecting a forbidden key anywhere (notification or
    /// wrapper) MUST be rejected.
    #[test]
    fn injecting_forbidden_key_is_rejected(
        forbidden in arb_forbidden_key(),
        leaf in arb_leaf(),
        location in 0u8..3u8,
    ) {
        let mut payload = json!({ "notification": ok_notification() });
        match location {
                0 => {
                    // Inside `notification`.
                    payload["notification"][forbidden] = leaf;
                }
                1 => {
                    // At the wrapper top level.
                    payload[forbidden] = leaf;
                }
                _ => {
                    // Inside a nested wrapper object.
                    payload["context"] = json!({ forbidden: leaf });
                }
        }
        let err = sanitize_blind_payload(&payload)
            .expect_err("forbidden key injection must be rejected");
        prop_assert!(
            matches!(
                err.reason_code,
                BlindPayloadReasonCode::ForbiddenField
                    | BlindPayloadReasonCode::SensitiveLiteral
                    | BlindPayloadReasonCode::InvalidFieldValue
            ),
            "expected forbidden/sensitive/invalid, got {err:?}"
        );
    }

    /// Property 3 — strict mode requires `push_target_id` and
    /// `wakeup_kind`; dropping either yields a `MissingRequiredField`.
    #[test]
    fn strict_mode_requires_both_required_keys(drop_target in any::<bool>(), drop_kind in any::<bool>()) {
        let mut notif = Map::new();
        if !drop_target {
            notif.insert(
                "push_target_id".into(),
                json!("cx:pseudonym:push:01HYZ8Z000000000000000"),
            );
        }
        if !drop_kind {
            notif.insert("wakeup_kind".into(), json!("message"));
        }
        let payload = json!({ "notification": Value::Object(notif) });
        let outcome = sanitize_blind_payload_strict(&payload);
        if drop_target || drop_kind {
            let err = outcome.expect_err("strict mode must reject missing required keys");
            prop_assert_eq!(err.reason_code, BlindPayloadReasonCode::MissingRequiredField);
        } else {
            prop_assert!(outcome.is_ok(), "valid strict payload should be accepted");
        }
    }

    /// Property 4 — disguised key (case/dash variants) never sneaks
    /// through. The allow-list is closed, so either the SDK
    /// recognises the case-insensitive forbidden form OR it rejects as
    /// an unknown key.
    #[test]
    fn disguised_keys_never_smuggle_data(key in arb_disguised_key(), leaf in arb_leaf()) {
        let mut payload = ok_notification();
        payload[&key] = leaf;
        let payload = json!({ "notification": payload });
        prop_assert!(
            sanitize_blind_payload(&payload).is_err(),
            "disguised key `{key}` should not survive the closed allow-list"
        );
    }

    /// Property 5 — `did:` / `cx:` literals in any non-pseudonym slot
    /// trigger SensitiveLiteral.
    #[test]
    fn sensitive_literals_caught_everywhere(
        prefix in prop_oneof![Just("did:web:"), Just("cx:event:"), Just("cx:device:")],
        suffix in "[a-z0-9.]{1,32}",
        path_choice in 0u8..2u8,
    ) {
        let literal = format!("{prefix}{suffix}");
        let mut payload = json!({ "notification": ok_notification() });
            match path_choice {
                0 => {
                    payload["context"] = json!({ "trace": literal });
                }
                _ => {
                    payload["context"] = json!({ "nested": { "deep": literal } });
                }
        }
        prop_assert!(
            contains_sensitive_literal("", &payload),
            "sanity check: literal should be in payload"
        );
        prop_assert!(
            sanitize_blind_payload(&payload).is_err(),
            "sanitizer must reject `did:` / `cx:` literal `{literal}`"
        );
    }

    /// Property 6a — Realm/Space inversion strict assertions.
    ///
    /// Both `realm_id` (post-inversion security boundary) and `space_id`
    /// (post-inversion container) MUST be rejected as forbidden keys; the
    /// pre-inversion alias `place_id` is also rejected. Case-insensitive
    /// variants MUST also lose (the sanitizer lowercases before matching).
    /// Camel-case fused variants like `RealmId` are NOT classified as the
    /// underscored token but the closed allow-list still rejects them as
    /// unknown keys — the payload-level assertion below pins that.
    #[test]
    fn realm_space_inversion_identifiers_rejected(
        leaf in arb_leaf(),
        case in 0u8..3u8,
    ) {
        for raw in &["realm_id", "space_id", "place_id"] {
            // is_forbidden_payload_key is the source of truth for the
            // canonical token + case-insensitive form.
            prop_assert!(
                is_forbidden_payload_key(raw),
                "is_forbidden_payload_key MUST classify `{raw}` as forbidden"
            );
            prop_assert!(
                is_forbidden_payload_key(&raw.to_ascii_uppercase()),
                "case-insensitive variant of `{raw}` MUST be classified as forbidden"
            );

            let key: String = match case {
                0 => (*raw).to_owned(),
                1 => raw.to_ascii_uppercase(),
                _ => {
                    // Camel-case'd: `realm_id` -> `RealmId`. The sanitizer
                    // doesn't recognise the underscore-stripped form via
                    // is_forbidden_payload_key, but the closed allow-list
                    // MUST still reject it as an unknown key.
                    let mut out = String::with_capacity(raw.len());
                    let mut upper = true;
                    for ch in raw.chars() {
                        if ch == '_' {
                            upper = true;
                        } else if upper {
                            out.extend(ch.to_uppercase());
                            upper = false;
                        } else {
                            out.push(ch);
                        }
                    }
                    out
                }
            };

            let mut notif = ok_notification();
            notif[&key] = leaf.clone();
            let payload = json!({ "notification": notif });
            prop_assert!(
                sanitize_blind_payload(&payload).is_err(),
                "sanitizer MUST reject blind payload carrying `{key}` (Realm/Space inversion)"
            );
        }
    }

    /// Property 6 — counts above MAX_COUNT_VALUE are rejected; counts
    /// at or below are accepted.
    #[test]
    fn count_boundary_is_enforced(n in 0u64..(MAX_COUNT_VALUE * 3)) {
        let payload = json!({
            "notification": {
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "counts": { "unread": n },
            }
        });
        let outcome = sanitize_blind_payload(&payload);
        if n <= MAX_COUNT_VALUE {
            prop_assert!(outcome.is_ok(), "count {n} should be accepted");
        } else {
            prop_assert!(outcome.is_err(), "count {n} should be rejected");
        }
    }
}
