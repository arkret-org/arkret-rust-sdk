//! T8.2 — property tests for handle parsing + handle claim validation.
//!
//! Pins three classes of invariant:
//!
//!  1. **Handle canonicalisation is idempotent.** Parsing a well-formed canonical
//!     `<localpart>:<domain>` handle then formatting it MUST yield the same bytes.
//!  2. **`acct:` round-trips synthesise the canonical form.** Any valid `acct:` is convertible to
//!     canonical and back to `acct:` without information loss.
//!  3. **`HandleClaim::validate` enforces conditional required fields.** If
//!     `binding_state=verified`, both `handle` and `expires_at` MUST be present. If
//!     `member_delivery_binding` is present, both `handle` + `audience` + `expires_at` MUST also be
//!     present.

use arkret_models_identity::{
    DeliveryBindingHint, Handle, HandleBindingState, HandleClaim, HandleHintBindingSource,
    RecipientServiceKind,
};
use arkret_wire::DidCoreId;
use chrono::{Duration, Utc};
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

/// Claim shell with every field written explicitly: `HandleClaim` has no
/// `Default` impl because the schema-required `created_at` must come from a
/// real constructor, not a fabricated placeholder.
fn base_claim() -> HandleClaim {
    HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        handle: None,
        handle_aliases: Vec::new(),
        subject_id: None,
        issuer_id: None,
        vouching_id: None,
        binding_state: None,
        claim_kind: None,
        visibility: None,
        audience: None,
        challenge: None,
        claim_scope: Default::default(),
        member_delivery_binding: None,
        claims: Vec::new(),
        created_at: Utc::now(),
        expires_at: None,
        verified_at: None,
        source_refs: Vec::new(),
        proofs: Vec::new(),
    }
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

    /// MUST rule: binding_state=verified ⇒ requires handle AND expires_at.
    #[test]
    fn verified_state_requires_handle_and_expires(
        has_handle in any::<bool>(),
        has_expiry in any::<bool>(),
        handle in arb_handle(),
    ) {
        let mut claim = HandleClaim {
            binding_state: Some(HandleBindingState::Verified),
            ..base_claim()
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
                recipient_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap(),
                recipient_kind: RecipientServiceKind::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: Default::default(),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            ..base_claim()
        };
        if has_handle {
            claim.handle = Some(Handle::parse(&handle).unwrap());
        }
        if has_audience {
            claim.audience = Some(format!("did:webvh:z6mkfixture:{audience}.example"));
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

    /// Empty and structurally unsafe localparts are rejected at parse time.
    #[test]
    fn rejects_invalid_localpart(local in prop_oneof![Just(String::new()), "[a-z]{1,4}[/@:#?\\\\][a-z]{0,4}", "[a-z]{1,4} [a-z]{1,4}"], domain in arb_domain()) {
        let handle = format!("{local}:{domain}");
        prop_assert!(Handle::parse(&handle).is_err());
    }
}
