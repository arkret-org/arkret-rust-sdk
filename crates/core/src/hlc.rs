//! Hybrid Logical Clock (HLC) facade retained by `arkret-core`.
//!
//! The stateless value side (format validation, parsing, comparison,
//! future-drift classification) migrated to `arkret_identifiers::hlc`,
//! next to the validated [`crate::Hlc`] newtype. The monotonic
//! [`HlcGenerator`] (wall clock + Realm-scoped node id derivation)
//! migrated to the `arkret-hlc` behavior crate. This module keeps the
//! historical `arkret_core::hlc` panel as pure re-exports.

pub use arkret_hlc::generator::HlcGenerator;
pub use arkret_identifiers::hlc::{
    EXPECTED_FUTURE_SKEW_MS, HARD_FUTURE_SKEW_MS, HLC_MAX_LOGICAL, HLC_MAX_PHYSICAL_MS,
    HlcComponents, HlcFutureDrift, compare_hlc, parse_hlc, time_until_hlc, validate_hlc_format,
    validate_hlc_future_drift,
};
