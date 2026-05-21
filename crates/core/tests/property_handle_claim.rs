//! T8.2 — property tests for handle URI parsing + handle claim validation.
//!
//! Pins three classes of invariant:
//!
//!  1. **URI canonicalisation is idempotent.** Parsing a well-formed
//!     `contrix://` URI then formatting it MUST yield the same string.
//!     Lower-casing of localpart + domain MUST be applied consistently.
//!  2. **`acct:` round-trips synthesise the canonical form.** Any
//!     valid `acct:` is convertible to canonical `contrix://` and back
//!     to `acct:` without information loss.
//!  3. **`HandleClaim::validate` enforces conditional required fields.**
//!     If `binding_state=verified`, both `handle_uri` and `expires_at`
//!     MUST be present. If `recipient_service_did` is present, both
//!     `handle_uri` + `audience` + `expires_at` MUST also be present.

use chrono::{Duration, Utc};
use contrix_core::Did;
use contrix_core::model::{HandleBindingState, HandleClaim, HandleUri};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

/// Strategy: a valid localpart (lowercase ascii + a few specials).
fn arb_localpart() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._+~\\-]{0,16}"
}

/// Strategy: a valid domain (1-3 labels of letters/digits).
fn arb_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9]{1,8}", 1..=3).prop_map(|labels| labels.join("."))
}

/// Strategy: a valid canonical contrix URI (no port).
fn arb_handle_uri() -> impl Strategy<Value = String> {
    (arb_localpart(), arb_domain())
        .prop_map(|(local, domain)| format!("contrix://{domain}/users/{local}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Round-trip: parse → canonical() yields the same input bytes.
    #[test]
    fn canonical_uri_round_trip(uri in arb_handle_uri()) {
        let parsed = HandleUri::parse(&uri).expect("valid URI parses");
        prop_assert_eq!(parsed.canonical(), uri.as_str());
    }

    /// Localpart is lowercased on parse.
    #[test]
    fn parse_lowercases_localpart(local in "[A-Za-z0-9]{1,12}", domain in arb_domain()) {
        let uri = format!("contrix://{domain}/users/{local}");
        let parsed = HandleUri::parse(&uri).expect("parses");
        let expected = local.to_ascii_lowercase();
        prop_assert_eq!(parsed.localpart(), expected.as_str());
    }

    /// `acct:` form round-trips to canonical and back.
    #[test]
    fn acct_round_trip(local in arb_localpart(), domain in arb_domain()) {
        let acct = format!("acct:{local}@{domain}");
        let parsed = HandleUri::from_acct(&acct).expect("valid acct parses");
        let again = parsed.to_acct();
        prop_assert_eq!(again, acct);
    }

    /// Invalid prefixes (no `contrix://`) are rejected.
    #[test]
    fn rejects_non_contrix_prefix(noise in "[a-z]{1,8}://[a-z]{1,8}/users/[a-z]{1,8}") {
        prop_assume!(!noise.starts_with("contrix://"));
        prop_assert!(HandleUri::parse(&noise).is_err());
    }

    /// MUST rule: binding_state=verified ⇒ requires handle_uri AND expires_at.
    #[test]
    fn verified_state_requires_uri_and_expires(
        has_uri in any::<bool>(),
        has_expiry in any::<bool>(),
        uri in arb_handle_uri(),
    ) {
        let mut claim = HandleClaim::default();
        claim.binding_state = Some(HandleBindingState::Verified);
        if has_uri {
            claim.handle_uri = Some(HandleUri::parse(&uri).unwrap());
        }
        if has_expiry {
            claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        }
        let outcome = claim.validate();
        if has_uri && has_expiry {
            prop_assert!(outcome.is_ok(), "verified+uri+expiry should validate");
        } else {
            prop_assert!(
                outcome.is_err(),
                "verified without uri or expiry MUST be rejected (uri={has_uri}, expiry={has_expiry})"
            );
        }
    }

    /// MUST rule: recipient_service_did set ⇒ requires handle_uri AND
    /// audience AND expires_at.
    #[test]
    fn recipient_service_did_requires_full_binding(
        has_uri in any::<bool>(),
        has_audience in any::<bool>(),
        has_expiry in any::<bool>(),
        uri in arb_handle_uri(),
        audience in "[a-z]{1,8}",
    ) {
        let mut claim = HandleClaim::default();
        claim.recipient_service_did = Some(
            Did::new("did:web:recipient.example".to_owned()).unwrap(),
        );
        if has_uri {
            claim.handle_uri = Some(HandleUri::parse(&uri).unwrap());
        }
        if has_audience {
            claim.audience = Some(format!("did:web:{audience}.example"));
        }
        if has_expiry {
            claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        }
        let outcome = claim.validate();
        if has_uri && has_audience && has_expiry {
            prop_assert!(
                outcome.is_ok(),
                "complete binding (uri+audience+expiry) should validate"
            );
        } else {
            prop_assert!(
                outcome.is_err(),
                "incomplete binding (uri={has_uri}, audience={has_audience}, expiry={has_expiry}) MUST be rejected"
            );
        }
    }

    /// Empty / oversized localparts are rejected at parse time.
    #[test]
    fn rejects_invalid_localpart(local in "[A-Z!@#$%^&*]{0,4}", domain in arb_domain()) {
        let uri = format!("contrix://{domain}/users/{local}");
        // Either lower-cased & rejected for empty or rejected for bad chars.
        if local.is_empty() {
            prop_assert!(HandleUri::parse(&uri).is_err());
        } else if local.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'))) {
            prop_assert!(HandleUri::parse(&uri).is_err());
        }
    }
}
