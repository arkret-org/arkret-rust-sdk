//! Pins the SDK's declared typed-id coverage to the types it actually ships.
//!
//! `SUPPORTED_ID_KINDS` feeds the `unlisted_id_kinds` half of
//! [`SpecArtifactBundle::drift_report`], which decides whether the SDK covers
//! the spec `id-kind-registry.json`. Until now that list was hand-copied
//! strings with nothing tying it to `arkret-identifiers`, so it could claim a
//! kind with no newtype behind it, or — as happened — silently fall five kinds
//! behind while the newtypes existed all along.
//!
//! `arkret-identifiers` sits below `arkret-wire` in the frozen layering, so it
//! cannot read the generated registry descriptors itself. This crate can see
//! both sides, which makes it the only correct place for the comparison.

use std::collections::BTreeSet;

use arkret_identifiers::DECLARED_UUID_ID_KIND_PREFIXES;
use arkret_schema::SUPPORTED_ID_KINDS;

fn declared_kinds() -> BTreeSet<&'static str> {
    DECLARED_UUID_ID_KIND_PREFIXES
        .iter()
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

/// Guard for the guard: a bug that emptied either side would make the equality
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
        DECLARED_UUID_ID_KIND_PREFIXES.len(),
        "two typed ids share an `ak:<kind>:` prefix; each prefix must belong to exactly one type"
    );
}
