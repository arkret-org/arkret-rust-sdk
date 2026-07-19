//! Stateless HLC value helpers for the Arkret v1 spec.
//!
//! The validated [`Hlc`] newtype lives in the crate root; this module owns
//! the value-side companions that need no clock or entropy: component
//! parsing, ordering comparison, format validation, and the two-tier
//! future-drift check from `encoding.md` §7.2. The monotonic generator
//! (which needs a wall clock) lives in the `arkret-hlc` behavior crate.

use std::time::Duration;

use crate::{Hlc, IdentifierError, Result};

/// Soft future-drift threshold from encoding.md §7.2.
pub const EXPECTED_FUTURE_SKEW_MS: i64 = 30 * 1000;

/// Hard future-drift cap from encoding.md §7.2.
pub const HARD_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

/// Physical time maximum value (48-bit: 0xffffffffffff ms ≈ 8,925 years)
pub const HLC_MAX_PHYSICAL_MS: u64 = 0xffffffffffff;

/// Logical counter maximum value (16-bit, 4 lowercase hex digits).
pub const HLC_MAX_LOGICAL: u32 = 0xffff;

/// HLC components
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlcComponents {
    /// Physical time in Unix milliseconds (48-bit)
    pub physical_ms: u64,
    /// Logical counter (16-bit)
    pub logical: u32,
    /// Node identifier (8 hex chars)
    pub node_id: String,
}

/// Receiver decision for HLC physical-time drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HlcFutureDrift {
    /// HLC is within the expected future skew threshold or not in the future.
    Accept,
    /// HLC is above the expected threshold but below the hard cap.
    SoftFail,
}

/// Validate HLC format according to Arkret v1 spec.
///
/// Format: `^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$`
pub fn validate_hlc_format(hlc: &str) -> Result<()> {
    parse_validated_hlc(hlc).map(|_| ())
}

fn parse_validated_hlc(hlc: &str) -> Result<Hlc> {
    Hlc::new(hlc.to_owned()).map_err(|_| {
        IdentifierError::Protocol(format!(
            "schema_violation: invalid HLC format: {} (expected format: ^[0-9a-f]{{12}}-[0-9a-f]{{4}}-[0-9a-f]{{8}}$)",
            hlc
        ))
    })
}

/// Parse HLC string into components.
pub fn parse_hlc(hlc: &str) -> Result<HlcComponents> {
    Ok(parse_validated_hlc(hlc)?.components())
}

impl Hlc {
    /// Decompose a validated HLC into its `(physical, logical, node)` parts.
    ///
    /// Infallible: construction already validated the fixed-width form.
    pub fn components(&self) -> HlcComponents {
        let value = self.as_str();
        let physical_ms = u64::from_str_radix(&value[0..12], 16)
            .expect("validated HLC carries a 12-hex physical part");
        let logical = u32::from_str_radix(&value[13..17], 16)
            .expect("validated HLC carries a 4-hex logical part");
        let node_id = value[18..26].to_owned();

        HlcComponents {
            physical_ms,
            logical,
            node_id,
        }
    }
}

/// Validate future drift against the spec's two-tier HLC model.
pub fn validate_hlc_future_drift(hlc: &str, current_time_ms: u64) -> Result<HlcFutureDrift> {
    let parts = parse_hlc(hlc)?;
    if parts.physical_ms <= current_time_ms {
        return Ok(HlcFutureDrift::Accept);
    }

    let future_drift_ms = (parts.physical_ms - current_time_ms) as i64;
    if future_drift_ms > HARD_FUTURE_SKEW_MS {
        return Err(IdentifierError::Protocol(format!(
            "hlc_hard_future_skew: HLC physical time is {future_drift_ms} ms ahead (hard cap {HARD_FUTURE_SKEW_MS} ms)"
        )));
    }
    if future_drift_ms > EXPECTED_FUTURE_SKEW_MS {
        return Ok(HlcFutureDrift::SoftFail);
    }

    Ok(HlcFutureDrift::Accept)
}

/// Compare two HLC values.
///
/// Errors when either HLC fails the strict format validation; otherwise
/// returns the total `(physical, logical, node)` ordering.
pub fn compare_hlc(hlc1: &str, hlc2: &str) -> Result<std::cmp::Ordering> {
    let left = parse_validated_hlc(hlc1)?;
    let right = parse_validated_hlc(hlc2)?;

    Ok(left.cmp(&right))
}

/// Calculate time until HLC expiration (for cursors).
///
/// Returns None if HLC is in the past.
pub fn time_until_hlc(hlc: &str, current_time_ms: u64) -> Option<Duration> {
    let parts = parse_hlc(hlc).ok()?;

    if parts.physical_ms > current_time_ms {
        Some(Duration::from_millis(parts.physical_ms - current_time_ms))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_format_validation_accepts_valid() {
        assert!(validate_hlc_format("000000000001-0001-a13f9c2e").is_ok());
        assert!(validate_hlc_format("01970e589d21-0004-a13f9c2e").is_ok());
        assert!(validate_hlc_format("ffffffffffff-ffff-12345678").is_ok());
    }

    #[test]
    fn hlc_format_validation_rejects_invalid() {
        // Not zero-padded
        assert!(validate_hlc_format("1970e589d21-0001-a13f9c2e").is_err());
        // Missing node part
        assert!(validate_hlc_format("01970e589d21-0001").is_err());
        // Invalid hex
        assert!(validate_hlc_format("xyz-0001-a13f9c2e").is_err());
        // Logical not zero-padded
        assert!(validate_hlc_format("01970e589d21-1-a13f9c2e").is_err());
        // Node too short
        assert!(validate_hlc_format("01970e589d21-0001-a13f").is_err());
        // Invalid logical hex
        assert!(validate_hlc_format("01970e589d21-000g-a13f9c2e").is_err());
    }

    #[test]
    fn hlc_format_validation_reports_schema_violation() {
        let err = validate_hlc_format("01970e589d21-000g-a13f9c2e").unwrap_err();
        assert!(err.to_string().contains("schema_violation"));
    }

    #[test]
    fn parse_hlc_extracts_components() {
        let parts = parse_hlc("01970e589d21-0004-a13f9c2e").unwrap();
        assert_eq!(parts.physical_ms, 0x01970e589d21);
        assert_eq!(parts.logical, 4);
        assert_eq!(parts.node_id, "a13f9c2e");
    }

    #[test]
    fn compare_hlc_lexicographic() {
        // Physical time takes precedence
        assert_eq!(
            compare_hlc("01970e589d21-0001-a13f9c2e", "01970e589d22-0000-a13f9c2e").unwrap(),
            std::cmp::Ordering::Less
        );

        // Logical counter breaks ties
        assert_eq!(
            compare_hlc("01970e589d21-0001-a13f9c2e", "01970e589d21-0002-a13f9c2e").unwrap(),
            std::cmp::Ordering::Less
        );

        // Node ID breaks ties
        assert_eq!(
            compare_hlc("01970e589d21-0001-a13f9c2e", "01970e589d21-0001-b13f9c2e").unwrap(),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn future_drift_has_soft_fail_tier_before_hard_reject() {
        let current = 0x01970e589d21;
        let within_expected = format!(
            "{:012x}-0001-a13f9c2e",
            current + EXPECTED_FUTURE_SKEW_MS as u64
        );
        let soft_fail = format!(
            "{:012x}-0001-a13f9c2e",
            current + EXPECTED_FUTURE_SKEW_MS as u64 + 1
        );
        let hard_reject = format!(
            "{:012x}-0001-a13f9c2e",
            current + HARD_FUTURE_SKEW_MS as u64 + 1
        );

        assert_eq!(
            validate_hlc_future_drift(&within_expected, current).unwrap(),
            HlcFutureDrift::Accept
        );
        assert_eq!(
            validate_hlc_future_drift(&soft_fail, current).unwrap(),
            HlcFutureDrift::SoftFail
        );
        assert!(validate_hlc_future_drift(&hard_reject, current).is_err());
    }

    #[test]
    fn time_until_hlc_calculates_remaining() {
        let current = 0x01970e589d21;
        let future = format!("{:012x}-0001-a13f9c2e", current + 60000); // 1 minute ahead
        let past = format!("{:012x}-0001-a13f9c2e", current - 60000); // 1 minute ago

        assert!(time_until_hlc(&future, current).is_some());
        assert_eq!(
            time_until_hlc(&future, current).unwrap(),
            Duration::from_secs(60)
        );
        assert!(time_until_hlc(&past, current).is_none());
    }

    #[test]
    fn hlc_string_sorting_matches_numeric_sorting() {
        let mut hlcs = vec![
            "01970e589d21-0004-bbbbbbbb",
            "01970e589d20-0009-ffffffff",
            "01970e589d21-0003-ffffffff",
            "01970e589d21-0004-a13f9c2e",
        ];

        hlcs.sort();

        assert_eq!(
            hlcs,
            vec![
                "01970e589d20-0009-ffffffff",
                "01970e589d21-0003-ffffffff",
                "01970e589d21-0004-a13f9c2e",
                "01970e589d21-0004-bbbbbbbb",
            ]
        );
    }

    #[test]
    fn hlc_rejects_uppercase_hex() {
        // HLC must be lowercase
        assert!(validate_hlc_format("01970E589D21-0001-A13F9C2E").is_err());
        assert!(validate_hlc_format("01970e589D21-0001-a13f9c2e").is_err());
    }
}
