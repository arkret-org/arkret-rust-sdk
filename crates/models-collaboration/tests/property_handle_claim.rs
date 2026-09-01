//! T8.2 — property tests for handle parsing + handle claim validation.
//!
//! Pins three classes of invariant:
//!
//!  1. **Handle canonicalisation is idempotent.** Parsing a well-formed canonical
//!     `<localpart>:<domain>` handle then formatting it MUST yield the same bytes.
//!  2. **`acct:` round-trips synthesise the canonical form.** Any valid `acct:` is convertible to
//!     canonical and back to `acct:` without information loss.
//!  3. Handle parsing rejects structurally unsafe localparts.

use arkret_models_identity::Handle;
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

/// Strategy: a valid canonical RFC 8265 localpart.
fn arb_localpart() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9][a-z0-9._+~\\-]{0,16}",
        Just("小明".to_owned()),
        Just("résumé".to_owned()),
        Just("παράδειγμα".to_owned()),
    ]
}

/// Strategy: a valid domain (2-3 labels of letters/digits).
fn arb_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9]{1,8}", 2..=3).prop_map(|labels| labels.join("."))
}

/// Strategy: a valid canonical handle (no port).
fn arb_handle() -> impl Strategy<Value = String> {
    (arb_localpart(), arb_domain()).prop_map(|(local, domain)| format!("{local}:{domain}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Round-trip: parse → canonical() yields the same input bytes.
    #[test]
    fn canonical_handle_round_trip(handle in arb_handle()) {
        let parsed = Handle::parse(&handle).expect("valid handle parses");
        prop_assert_eq!(parsed.canonical(), handle.as_str());
    }

    /// Input preparation applies the profile while canonical parsing rejects rewrites.
    #[test]
    fn preparation_and_canonical_parse_are_separate(local in "[A-Z][A-Za-z0-9]{0,11}", domain in arb_domain()) {
        let handle = format!("{local}:{domain}");
        prop_assert!(Handle::parse(&handle).is_err());
        let parsed = Handle::prepare(&handle).expect("input prepares");
        let expected = local.to_ascii_lowercase();
        prop_assert_eq!(parsed.localpart(), expected.as_str());
    }

    /// `acct:` form round-trips to canonical and back.
    #[test]
    fn acct_round_trip(local in arb_localpart(), domain in arb_domain()) {
        let handle = Handle::parse(&format!("{local}:{domain}")).expect("valid handle parses");
        let acct = handle.to_acct();
        let parsed = Handle::from_acct(&acct).expect("valid acct parses");
        let again = parsed.to_acct();
        prop_assert_eq!(again, acct);
        prop_assert_eq!(parsed.canonical(), handle.canonical());
    }

    /// Empty and structurally unsafe localparts are rejected at parse time.
    #[test]
    fn rejects_invalid_localpart(local in prop_oneof![Just(String::new()), "[a-z]{1,4}[/@:#?\\\\][a-z]{0,4}", "[a-z]{1,4} [a-z]{1,4}"], domain in arb_domain()) {
        let handle = format!("{local}:{domain}");
        prop_assert!(Handle::parse(&handle).is_err());
    }
}
