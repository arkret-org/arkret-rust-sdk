//! Cross-check between declared conformance profiles and the Cargo features
//! actually compiled into the binary.
//!
//! `arkret_wire::generated::profile_requirements` is a static table with no `#[cfg(feature)]`
//! gates: a `--no-default-features` build still declares the full
//! `e2ee_client` required surface (`ak.mls.*` event kinds,
//! `encrypted_envelope` / `key_backup` schemas), even though that binary has no
//! MLS or key-backup code linked in. `conformance-profiles.md` requires an
//! implementation to "only declare the profiles it actually supports", so a
//! feature-trimmed deployment that keeps declaring `e2ee_client` will accept
//! MLS/backup traffic from peers it can never serve.
//!
//! This module closes that gap at runtime: it derives, from the generated
//! requirement table itself (so it never drifts from the profiles), which Cargo
//! features a declared profile *implies*, then diffs that against the feature
//! set the caller reports as compiled. The derivation is data-driven — a new
//! MLS-bearing profile is caught automatically because it references `ak.mls.*`
//! kinds or the `encrypted_envelope` schema, not because it was hand-listed
//! here.
//!
//! The generated table is not edited (it is a build artifact); the guard lives
//! entirely in this hand-written module and reads the table read-only.

use std::collections::BTreeSet;

// `SchemaId::ENCRYPTED_ENVELOPE_V1` in a profile's required surface implies the `mls`
// feature (E2EE ciphertext envelopes can only be produced/consumed with the MLS
// group crypto compiled in); `SchemaId::KEY_BACKUP_V1` implies the client-side
// key-backup crypto feature.
use arkret_wire::SchemaId;
use arkret_wire::generated::profile_requirements::ProfileRequirementsError;

use crate::profile_semantics::collect_profile_semantic_requirements;

/// A Cargo feature a conformance profile requires but which is not compiled
/// into the current binary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProfileFeatureGap {
    /// The declared profile whose required surface is not backed by code.
    pub profile_id: String,
    /// The Cargo feature the profile's required surface depends on.
    pub required_feature: String,
    /// The concrete requirement (event kind or schema) that implies the
    /// feature, kept for diagnostics so operators can see *why* the feature is
    /// needed.
    pub implied_by: String,
}

/// Cargo feature implied by an MLS-bearing required surface.
pub const FEATURE_MLS: &str = "mls";
/// Cargo feature implied by a client-side key-backup required surface.
pub const FEATURE_BACKUP: &str = "backup";

/// Prefix of every MLS group-messaging event kind.
const MLS_EVENT_KIND_PREFIX: &str = "ak.mls.";

/// Derive every `(required_feature, implied_by)` a set of declared profiles
/// depends on, following profile inheritance. The result is deduplicated and
/// sorted.
///
/// Returns [`ProfileRequirementsError::UnknownProfile`] if a declared profile
/// is not in the generated table.
pub fn implied_features_for_profiles(
    declared: &[&str],
) -> Result<Vec<(String, String)>, ProfileRequirementsError> {
    let requirements = collect_profile_semantic_requirements(declared)?;
    let mut implied: BTreeSet<(String, String)> = BTreeSet::new();

    for kind in &requirements.required_event_kinds {
        if kind.starts_with(MLS_EVENT_KIND_PREFIX) {
            implied.insert((FEATURE_MLS.to_owned(), kind.clone()));
        }
    }
    for schema in &requirements.required_schemas {
        if schema == SchemaId::ENCRYPTED_ENVELOPE_V1 {
            implied.insert((FEATURE_MLS.to_owned(), schema.clone()));
        }
        if schema == SchemaId::KEY_BACKUP_V1 {
            implied.insert((FEATURE_BACKUP.to_owned(), schema.clone()));
        }
    }

    Ok(implied.into_iter().collect())
}

/// Cross-check declared profiles against the compiled Cargo feature set.
///
/// `compiled_features` is the set of features the caller reports as linked in
/// (assembled via `cfg!(feature = "...")` at the call site). Any profile whose
/// required surface implies a feature not present in `compiled_features`
/// yields a [`ProfileFeatureGap`].
///
/// Returns `Ok(())` when every declared profile is fully backed by code, or
/// `Err(gaps)` listing each unmet dependency. Returns an early
/// `Err(vec![gap])`-free error path only for [`ProfileRequirementsError`]
/// (unknown profile), surfaced through the `Result`'s outer type below.
pub fn verify_declared_profiles_against_features(
    declared: &[&str],
    compiled_features: &[&str],
) -> Result<Result<(), Vec<ProfileFeatureGap>>, ProfileRequirementsError> {
    let compiled: BTreeSet<&str> = compiled_features.iter().copied().collect();
    let mut gaps = Vec::new();

    // Re-derive per declared profile (not the merged union) so each gap names
    // the specific profile an operator can drop to become honest.
    for profile_id in declared {
        for (feature, implied_by) in implied_features_for_profiles(&[profile_id])? {
            if !compiled.contains(feature.as_str()) {
                gaps.push(ProfileFeatureGap {
                    profile_id: (*profile_id).to_owned(),
                    required_feature: feature,
                    implied_by,
                });
            }
        }
    }

    gaps.sort();
    gaps.dedup();
    if gaps.is_empty() {
        Ok(Ok(()))
    } else {
        Ok(Err(gaps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2ee_client_implies_mls_and_backup() {
        let implied = implied_features_for_profiles(&["ak.profile.e2ee_client.v1"]).unwrap();
        assert!(
            implied
                .iter()
                .any(|(feature, by)| feature == FEATURE_MLS && by.starts_with("ak.mls.")),
            "e2ee_client requires ak.mls.* kinds -> mls feature: {implied:?}"
        );
        assert!(
            implied.iter().any(
                |(feature, by)| feature == FEATURE_MLS && by == SchemaId::ENCRYPTED_ENVELOPE_V1
            ),
            "e2ee_client requires encrypted_envelope schema -> mls feature: {implied:?}"
        );
        assert!(
            implied
                .iter()
                .any(|(feature, by)| feature == FEATURE_BACKUP && by == SchemaId::KEY_BACKUP_V1),
            "e2ee_client requires key_backup schema -> backup feature: {implied:?}"
        );
    }

    #[test]
    fn minimal_client_implies_no_crypto_features() {
        let implied = implied_features_for_profiles(&["ak.profile.minimal_client.v1"]).unwrap();
        assert!(
            implied.is_empty(),
            "a plaintext core profile must not imply mls/backup: {implied:?}"
        );
    }

    #[test]
    fn gap_detected_when_declaring_e2ee_without_crypto_features() {
        // Simulate a `--no-default-features` build: no crypto features compiled.
        let outcome =
            verify_declared_profiles_against_features(&["ak.profile.e2ee_client.v1"], &[]).unwrap();
        let gaps = outcome.expect_err("declaring e2ee_client with no features must gap");
        // Both mls and backup must be flagged.
        assert!(
            gaps.iter().any(|gap| gap.required_feature == FEATURE_MLS),
            "mls gap missing: {gaps:?}"
        );
        assert!(
            gaps.iter()
                .any(|gap| gap.required_feature == FEATURE_BACKUP),
            "backup gap missing: {gaps:?}"
        );
        for gap in &gaps {
            assert_eq!(gap.profile_id, "ak.profile.e2ee_client.v1");
        }
    }

    #[test]
    fn no_gap_when_features_cover_declaration() {
        let outcome = verify_declared_profiles_against_features(
            &["ak.profile.e2ee_client.v1"],
            &[FEATURE_MLS, FEATURE_BACKUP],
        )
        .unwrap();
        outcome.expect("fully-featured build must not gap on e2ee_client");
    }

    #[test]
    fn plaintext_profile_passes_even_without_features() {
        let outcome =
            verify_declared_profiles_against_features(&["ak.profile.minimal_client.v1"], &[])
                .unwrap();
        outcome.expect("plaintext profile needs no crypto features");
    }

    #[test]
    fn unknown_profile_surfaces_as_error() {
        let err = verify_declared_profiles_against_features(&["ak.profile.does.not.exist.v1"], &[])
            .unwrap_err();
        assert!(matches!(
            err,
            ProfileRequirementsError::UnknownProfile { .. }
        ));
    }

    #[test]
    fn partial_features_flags_only_the_missing_one() {
        // Compile mls but not backup: only the backup dependency should gap.
        let outcome = verify_declared_profiles_against_features(
            &["ak.profile.e2ee_client.v1"],
            &[FEATURE_MLS],
        )
        .unwrap();
        let gaps = outcome.expect_err("backup still missing");
        assert!(
            gaps.iter()
                .all(|gap| gap.required_feature == FEATURE_BACKUP),
            "only backup should be flagged when mls is compiled: {gaps:?}"
        );
    }
}
