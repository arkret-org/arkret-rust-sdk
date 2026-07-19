//! Strand-local constant-time comparison helper.
//!
//! `compute_key_commitment` now lives in
//! [`arkret_crypto::key_verification::compute_key_commitment`] (re-exported by
//! this module's parent). Only the strand's constant-time MAC/commitment
//! comparison stays here, since it delegates to the SDK-wide
//! [`crate::crypto::constant_time_eq`].

/// Constant-time string equality for MAC / commitment comparisons —
/// delegates to the single crate-wide [`crate::crypto::constant_time_eq`].
pub(super) fn ct_eq(a: &str, b: &str) -> bool {
    crate::crypto::constant_time_eq(a, b)
}
