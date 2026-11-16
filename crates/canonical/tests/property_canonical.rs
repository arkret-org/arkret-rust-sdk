//! T8.2 — property tests for `arkret_canonical`.
//!
//! Pins the *byte-stability* invariant of the canonical-JSON profile:
//!
//!  * Canonical bytes preserve the original value when independently decoded, and encoding the
//!    decoded value yields the same bytes.
//!  * Unicode strings (BMP, supplementary plane, ZWJ sequences) survive the canonical round-trip
//!    without re-encoding tricks.
//!  * Unknown / extra fields are preserved (canonical is not a schema filter — only the encoding
//!    shape is normalised).
//!
//! These guarantees are the foundation for cross-service
//! `payload_digest` agreement: if two services serialise the same logical
//! object via the SDK, they MUST get the same bytes.

use arkret_canonical::{canonical_json_bytes, canonical_json_string, is_nfc};
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const PROPTEST_CASES: u32 = 64;

/// JSON safe-integer bound (`2^53 - 1`) from `encoding.md` §2. Canonical JSON
/// rejects integers outside `[-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER]`, so the
/// generator MUST stay inside this range — values that wide are carried as
/// strings on the wire, not JSON numbers.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Strategy: a primitive JSON leaf (no float — canonical rejects).
fn arb_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(|n| json!(n)),
        // Allow most printable + a few emoji for unicode coverage.
        proptest::collection::vec(
            prop_oneof![
                // ASCII printable, including escapes.
                any::<u8>().prop_map(|b| char::from((b % 95) + 32)),
                // BMP unicode.
                proptest::char::range('\u{0100}', '\u{2FFF}'),
                // Emoji-ish supplementary plane.
                proptest::char::range('\u{1F300}', '\u{1F6FF}'),
            ],
            0..16,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("canonical JSON strings must be NFC", |s| is_nfc(s))
        .prop_map(Value::String),
    ]
}

/// Strategy: a structured JSON value with depth up to 3.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = arb_leaf();
    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::hash_map("[a-zA-Z_][a-zA-Z0-9_]{0,8}", inner, 0..4).prop_map(
                |m| {
                    let mut map = Map::new();
                    for (k, v) in m {
                        map.insert(k, v);
                    }
                    Value::Object(map)
                }
            ),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Decode independently to check value preservation before re-encoding.
    #[test]
    fn canonical_encoding_preserves_value_and_is_idempotent(value in arb_value()) {
        let first = canonical_json_bytes(&value).expect("first encode");
        let parsed: Value = serde_json::from_slice(&first).expect("decode canonical bytes");
        prop_assert_eq!(&parsed, &value);
        let second = canonical_json_bytes(&parsed).expect("encode decoded value");
        prop_assert_eq!(first, second);
    }

    /// Property — canonical encoding of a unicode string preserves it
    /// byte-for-byte through a serde round-trip.
    #[test]
    fn unicode_strings_round_trip(
        s in proptest::collection::vec(
            prop_oneof![
                proptest::char::range('\u{0000}', '\u{007E}'),
                proptest::char::range('\u{0080}', '\u{2FFF}'),
                proptest::char::range('\u{1F300}', '\u{1F9FF}'),
            ],
            0..32,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("canonical JSON strings must be NFC", |s| is_nfc(s))
    ) {
        let value = json!({ "k": s });
        let bytes = canonical_json_bytes(&value).expect("encode unicode");
        let parsed: Value = serde_json::from_slice(&bytes).expect("re-parse canonical bytes");
        prop_assert_eq!(parsed.get("k").and_then(Value::as_str).map(str::to_owned), Some(s));
    }

    /// Property — unknown / extra fields survive the canonical
    /// encoding step (canonical is encoding, not schema-filter).
    #[test]
    fn unknown_fields_preserved(
        known in "[a-z]{1,6}",
        unknown in "[a-z]{1,6}",
        value_a in arb_leaf(),
        value_b in arb_leaf(),
    ) {
        prop_assume!(known != unknown);
        let payload = json!({ known.clone(): value_a, unknown.clone(): value_b });
        let s = canonical_json_string(&payload).expect("encode");
        prop_assert!(s.contains(&unknown), "unknown field `{unknown}` must survive: {s}");
        prop_assert!(s.contains(&known), "known field `{known}` must survive: {s}");
    }
}
