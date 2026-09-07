//! Pins the SDK's declared typed-id coverage to the types it actually ships.
//!
//! `SUPPORTED_ID_KINDS` and `SUPPORTED_SPECIAL_FORM_ID_KINDS` feed the
//! `unlisted_id_kinds` / `unlisted_special_form_id_kinds` halves of
//! [`SpecArtifactBundle::drift_report`], which decide whether the SDK covers
//! the spec `id-kind-registry.json`. Until now both lists were hand-copied
//! strings with nothing tying them to `arkret-identifiers`, so either could
//! claim a kind with no newtype behind it, or silently fall behind while the
//! newtypes existed all along. Both failure modes had actually happened: the
//! uuid list lagged five kinds, and the special-form list claimed four kinds
//! the crate shipped no type for.
//!
//! `arkret-identifiers` sits below `arkret-wire` in the frozen layering, so it
//! cannot read the generated registry descriptors itself. This crate can see
//! both sides, which makes it the only correct place for the comparison.

use std::collections::BTreeSet;

use arkret_identifiers::{
    DECLARED_EVENT_TOKEN_ID_KIND_PREFIXES, DECLARED_PRODUCER_ALLOCATED_ID_KIND_PREFIXES,
    DECLARED_SPECIAL_FORM_ID_KINDS, DECLARED_SUITE_TAGGED_FULL_DIGEST_ID_KIND_PREFIXES,
    DECLARED_UUID_ID_KIND_PREFIXES,
};
use arkret_schema_conformance::{SUPPORTED_ID_KINDS, SUPPORTED_SPECIAL_FORM_ID_KINDS};

fn accepts<T: serde::de::DeserializeOwned>(value: &str) -> bool {
    serde_json::from_value::<T>(serde_json::Value::String(value.to_owned())).is_ok()
}

#[test]
fn newly_covered_producer_ids_reject_noncanonical_wire_values() {
    macro_rules! check {
        ($ty:ty, $prefix:literal) => {
            assert!(accepts::<$ty>(concat!(
                $prefix,
                "01987de1-3914-7000-8000-000000000001"
            )));
            for suffix in [
                "01987de1-3914-4000-8000-000000000001",
                "01987DE1-3914-7000-8000-000000000001",
                "01987de1-3914-7000-7000-000000000001",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "free-form",
            ] {
                assert!(!accepts::<$ty>(&format!("{}{}", $prefix, suffix)));
            }
            assert!(!accepts::<$ty>("01987de1-3914-7000-8000-000000000001"));
        };
    }
    check!(arkret_identifiers::HistoryRequestId, "ak:history_request:");
    check!(
        arkret_identifiers::HistoryResponseId,
        "ak:history_response:"
    );
    check!(arkret_identifiers::OperationId, "ak:operation:");
    check!(arkret_identifiers::RecoveryKeyId, "ak:recovery_key:");
    check!(
        arkret_identifiers::ServiceRouteHandoverId,
        "ak:service_route_handover:"
    );
}

#[test]
fn newly_covered_special_forms_enforce_their_registered_shapes() {
    macro_rules! check {
        ($ty:ty, $prefix:literal) => {
            assert!(accepts::<$ty>(&format!("{}{}", $prefix, "a".repeat(64))));
            for suffix in [
                "a".repeat(63),
                "a".repeat(65),
                "A".repeat(64),
                "g".repeat(64),
            ] {
                assert!(!accepts::<$ty>(&format!("{}{}", $prefix, suffix)));
            }
            assert!(!accepts::<$ty>(&"a".repeat(64)));
        };
    }
    check!(
        arkret_identifiers::OrganizationRegistrationChallengeId,
        "ak:organization_registration_challenge:"
    );
    check!(
        arkret_identifiers::OrganizationRegistrationReceiptId,
        "ak:organization_registration_receipt:"
    );
    check!(arkret_wire::SignerEvidenceRef, "ak:signer_evidence:sha256:");
    check!(
        arkret_wire::MembershipCompensationDelegationRef,
        "ak:membership_compensation_delegation:sha256:"
    );
    assert!(accepts::<arkret_identifiers::DidCoreId>(
        "ak:did_core:web:service.example"
    ));
    assert!(!accepts::<arkret_identifiers::DidCoreId>(
        "did:web:service.example"
    ));
    assert!(!accepts::<arkret_identifiers::DidCoreId>(
        "ak:did_core:web:service.example/path"
    ));
}

fn declared_special_kinds() -> BTreeSet<&'static str> {
    DECLARED_SPECIAL_FORM_ID_KINDS
        .iter()
        .copied()
        .chain([
            arkret_wire::SignerEvidenceRef::ID_KIND,
            arkret_wire::MembershipCompensationDelegationRef::ID_KIND,
        ])
        .collect()
}

fn declared_kinds() -> BTreeSet<&'static str> {
    DECLARED_UUID_ID_KIND_PREFIXES
        .iter()
        .chain(DECLARED_EVENT_TOKEN_ID_KIND_PREFIXES)
        .chain(DECLARED_PRODUCER_ALLOCATED_ID_KIND_PREFIXES)
        .chain(DECLARED_SUITE_TAGGED_FULL_DIGEST_ID_KIND_PREFIXES)
        .chain(std::iter::once(&"ak:realm:"))
        .map(|prefix| {
            prefix
                .strip_prefix("ak:")
                .and_then(|rest| rest.strip_suffix(':'))
                .unwrap_or_else(|| panic!("declared id-kind prefix is not `ak:<kind>:`: {prefix}"))
        })
        .collect()
}

#[test]
fn supported_id_kinds_match_the_typed_ids_the_sdk_ships() {
    let declared = declared_kinds();
    let supported: BTreeSet<&str> = SUPPORTED_ID_KINDS.iter().copied().collect();

    let claimed_without_type: Vec<&&str> = supported.difference(&declared).collect();
    assert!(
        claimed_without_type.is_empty(),
        "SUPPORTED_ID_KINDS claims spec coverage for kinds with no typed id in \
         arkret-identifiers: {claimed_without_type:?}. Either add the newtype to the \
         declare_uuid_id_kinds! block or drop the claim — do not leave the drift gate \
         asserting support that does not exist."
    );

    let typed_but_undeclared: Vec<&&str> = declared.difference(&supported).collect();
    assert!(
        typed_but_undeclared.is_empty(),
        "arkret-identifiers ships typed ids that SUPPORTED_ID_KINDS does not declare: \
         {typed_but_undeclared:?}. Add them, otherwise drift_report reports them as \
         unlisted spec entries even though the SDK supports them."
    );
}

#[test]
fn supported_id_kinds_has_no_duplicates() {
    let unique: BTreeSet<&str> = SUPPORTED_ID_KINDS.iter().copied().collect();
    assert_eq!(
        unique.len(),
        SUPPORTED_ID_KINDS.len(),
        "SUPPORTED_ID_KINDS contains duplicate entries; set comparison would hide the \
         second copy"
    );
}

#[test]
fn supported_special_form_id_kinds_match_the_types_the_sdk_ships() {
    let declared: BTreeSet<&str> = declared_special_kinds();
    let supported: BTreeSet<&str> = SUPPORTED_SPECIAL_FORM_ID_KINDS.iter().copied().collect();

    let claimed_without_type: Vec<&&str> = supported.difference(&declared).collect();
    assert!(
        claimed_without_type.is_empty(),
        "SUPPORTED_SPECIAL_FORM_ID_KINDS claims spec coverage for kinds with no type in \
         arkret-identifiers: {claimed_without_type:?}. Either add the type to the \
         declare_special_form_id_kinds! block or drop the claim — do not leave the drift gate \
         asserting support that does not exist."
    );

    let typed_but_undeclared: Vec<&&str> = declared.difference(&supported).collect();
    assert!(
        typed_but_undeclared.is_empty(),
        "arkret-identifiers ships special-form types that SUPPORTED_SPECIAL_FORM_ID_KINDS does \
         not declare: {typed_but_undeclared:?}. Add them, otherwise drift_report reports them as \
         unlisted spec entries even though the SDK supports them."
    );
}

#[test]
fn supported_special_form_id_kinds_has_no_duplicates() {
    let unique: BTreeSet<&str> = SUPPORTED_SPECIAL_FORM_ID_KINDS.iter().copied().collect();
    assert_eq!(
        unique.len(),
        SUPPORTED_SPECIAL_FORM_ID_KINDS.len(),
        "SUPPORTED_SPECIAL_FORM_ID_KINDS contains duplicate entries; set comparison would hide \
         the second copy"
    );
}

/// Guard for the guards: a bug that emptied either side would make the equality
/// assertions above pass vacuously.
#[test]
fn both_sides_of_the_comparison_are_populated() {
    let declared = declared_kinds();
    assert!(
        declared.len() > 40,
        "DECLARED_UUID_ID_KIND_PREFIXES collapsed to {} entries — the declare_uuid_id_kinds! \
         block is no longer collecting prefixes",
        declared.len()
    );
    assert_eq!(
        declared.len(),
        DECLARED_UUID_ID_KIND_PREFIXES.len()
            + DECLARED_EVENT_TOKEN_ID_KIND_PREFIXES.len()
            + DECLARED_PRODUCER_ALLOCATED_ID_KIND_PREFIXES.len()
            + DECLARED_SUITE_TAGGED_FULL_DIGEST_ID_KIND_PREFIXES.len()
            + 1,
        "two typed ids share an `ak:<kind>:` prefix; each prefix must belong to exactly one type"
    );

    let declared_special_forms: BTreeSet<&str> = declared_special_kinds();
    assert!(
        declared_special_forms.len() > 5,
        "DECLARED_SPECIAL_FORM_ID_KINDS collapsed to {} entries — the \
         declare_special_form_id_kinds! block is no longer collecting kinds",
        declared_special_forms.len()
    );
    assert_eq!(
        declared_special_forms.len(),
        DECLARED_SPECIAL_FORM_ID_KINDS.len() + 2,
        "two special-form types claim the same registry kind; each kind must belong to exactly \
         one type"
    );
}
