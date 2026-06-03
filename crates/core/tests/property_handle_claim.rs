//! T8.2 — property tests for handle parsing + handle claim validation.
//!
//! Pins three classes of invariant:
//!
//!  1. **Handle canonicalisation is idempotent.** Parsing a well-formed
//!     `<localpart>:<domain>` handle then formatting it MUST yield the
//!     same string. Lower-casing of localpart + domain MUST be applied
//!     consistently.
//!  2. **`acct:` round-trips synthesise the canonical form.** Any
//!     valid `acct:` is convertible to canonical and back to `acct:`
//!     without information loss.
//!  3. **`HandleClaim::validate` enforces conditional required fields.**
//!     If `binding_state=verified`, both `handle` and `expires_at`
//!     MUST be present. If `member_delivery_binding` is present, both
//!     `handle` + `audience` + `expires_at` MUST also be present.

use chrono::{Duration, Utc};
use cokret_core::Did;
use cokret_core::model::{
    DeliveryBindingHint, Handle, HandleBindingState, HandleClaim, HandleHintBindingSource,
    RecipientServiceType,
};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

/// Strategy: a valid localpart (lowercase ascii + a few specials).
fn arb_localpart() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._+~\\-]{0,16}"
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

    /// Localpart is lowercased on parse.
    #[test]
    fn parse_lowercases_localpart(local in "[A-Za-z0-9]{1,12}", domain in arb_domain()) {
        let handle = format!("{local}:{domain}");
        let parsed = Handle::parse(&handle).expect("parses");
        let expected = local.to_ascii_lowercase();
        prop_assert_eq!(parsed.localpart(), expected.as_str());
    }

    /// `acct:` form round-trips to canonical and back.
    #[test]
    fn acct_round_trip(local in arb_localpart(), domain in arb_domain()) {
        let acct = format!("acct:{local}@{domain}");
        let parsed = Handle::from_acct(&acct).expect("valid acct parses");
        let again = parsed.to_acct();
        prop_assert_eq!(again, acct);
    }

    /// MUST rule: binding_state=verified ⇒ requires handle AND expires_at.
    #[test]
    fn verified_state_requires_handle_and_expires(
        has_handle in any::<bool>(),
        has_expiry in any::<bool>(),
        handle in arb_handle(),
    ) {
        let mut claim = HandleClaim {
            binding_state: Some(HandleBindingState::Verified),
            ..Default::default()
        };
        if has_handle {
            claim.handle = Some(Handle::parse(&handle).unwrap());
        }
        if has_expiry {
            claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        }
        let outcome = claim.validate();
        if has_handle && has_expiry {
            prop_assert!(outcome.is_ok(), "verified+handle+expiry should validate");
        } else {
            prop_assert!(
                outcome.is_err(),
                "verified without handle or expiry MUST be rejected (handle={has_handle}, expiry={has_expiry})"
            );
        }
    }

    /// MUST rule: member_delivery_binding set ⇒ requires handle AND
    /// audience AND expires_at.
    #[test]
    fn member_delivery_binding_requires_full_binding(
        has_handle in any::<bool>(),
        has_audience in any::<bool>(),
        has_expiry in any::<bool>(),
        handle in arb_handle(),
        audience in "[a-z]{1,8}",
    ) {
        let mut claim = HandleClaim {
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_did: Did::new("did:web:recipient.example".to_owned()).unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: Default::default(),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            ..Default::default()
        };
        if has_handle {
            claim.handle = Some(Handle::parse(&handle).unwrap());
        }
        if has_audience {
            claim.audience = Some(format!("did:web:{audience}.example"));
        }
        if has_expiry {
            claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        }
        let outcome = claim.validate();
        if has_handle && has_audience && has_expiry {
            prop_assert!(
                outcome.is_ok(),
                "complete binding (handle+audience+expiry) should validate"
            );
        } else {
            prop_assert!(
                outcome.is_err(),
                "incomplete binding (handle={has_handle}, audience={has_audience}, expiry={has_expiry}) MUST be rejected"
            );
        }
    }

    /// Empty / oversized localparts are rejected at parse time.
    #[test]
    fn rejects_invalid_localpart(local in "[A-Z!@#$%^&*]{0,4}", domain in arb_domain()) {
        let handle = format!("{local}:{domain}");
        // Either lower-cased & rejected for empty or rejected for bad chars.
        if local.is_empty() {
            prop_assert!(Handle::parse(&handle).is_err());
        } else if local.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'))) {
            prop_assert!(Handle::parse(&handle).is_err());
        }
    }
}
