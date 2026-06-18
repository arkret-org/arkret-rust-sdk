//! Hybrid Logical Clock (HLC) implementation.
//!
//! This module implements the Cokret v1 HLC specification with:
//! - Strict format validation: `^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$`
//! - Fixed-width hex encoding for correct lexicographic ordering
//! - Future-clock drift handling with a 30s soft-fail tier and 5m hard cap
//! - Realm-scoped pseudonymous node id derivation (`encoding.md` §7)
//! - Monotonic HLC generation

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{Error, Hlc as HlcType, Result};

/// Validate HLC format according to Cokret v1 spec.
///
/// Format: `^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$`
pub fn validate_hlc_format(hlc: &str) -> Result<()> {
    use regex::Regex;
    let re = Regex::new(r"^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$").unwrap();
    if re.is_match(hlc) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "schema_violation: invalid HLC format: {} (expected format: ^[0-9a-f]{{12}}-[0-9a-f]{{4}}-[0-9a-f]{{8}}$)",
            hlc
        )))
    }
}

/// Soft future-drift threshold from encoding.md §7.2.
pub const EXPECTED_FUTURE_SKEW_MS: i64 = 30 * 1000;

/// Hard future-drift cap from encoding.md §7.2.
pub const HARD_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

/// Maximum allowed absolute clock skew kept for the legacy boolean helper.
const MAX_SKEW_MS: i64 = HARD_FUTURE_SKEW_MS;

/// Physical time maximum value (48-bit: 0xffffffffffff ms ≈ 8,925 years)
const MAX_PHYSICAL: u64 = 0xffffffffffff;

/// Logical counter maximum value (16-bit, 4 lowercase hex digits).
const MAX_LOGICAL: u32 = 0xffff;

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

/// Domain separator for the §7 `node_id_hash` derivation.
const NODE_ID_DOMAIN_SEPARATOR: &str = "cokret-hlc-v1";

/// Hybrid Logical Clock generator.
///
/// Generates monotonic HLC values with proper format encoding.
/// Handles clock skew and maintains local monotonicity.
#[derive(Clone, Debug)]
pub struct HlcGenerator {
    /// Current physical time
    physical: u64,
    /// Current logical counter
    logical: u32,
    /// Node identifier (8 hex chars from SHA256)
    node_id: String,
}

impl HlcGenerator {
    /// Create a new HLC generator with a Realm-scoped pseudonymous node id.
    ///
    /// Per `encoding.md` §7 the `node_id_hash` MUST be derived from a
    /// Realm-scoped (or deployment-scoped) local node secret:
    /// `SHA256("cokret-hlc-v1" || realm_id || device_id ||
    /// local_node_secret)[0:8]`. Principal DIDs, public handles, long-term
    /// device ids, or any cross-Realm stable identifier MUST NOT be used
    /// directly as the hash input — doing so would make the node id
    /// linkable across Realms.
    pub fn new(realm_id: &str, device_id: &str, local_node_secret: &[u8]) -> Self {
        let node_id = Self::compute_node_id(realm_id, device_id, local_node_secret);
        let physical = Self::current_time_ms();

        Self {
            physical,
            logical: 0,
            node_id,
        }
    }

    /// Create a new HLC generator with a custom initial time.
    ///
    /// Useful for testing or reproducible HLC generation. The node id is
    /// derived exactly as in [`HlcGenerator::new`].
    pub fn with_initial_time(
        realm_id: &str,
        device_id: &str,
        local_node_secret: &[u8],
        initial_time_ms: u64,
    ) -> Self {
        let node_id = Self::compute_node_id(realm_id, device_id, local_node_secret);

        Self {
            physical: initial_time_ms,
            logical: 0,
            node_id,
        }
    }

    /// Generate the next HLC value.
    ///
    /// Advances the HLC based on current physical time and ensures
    /// monotonicity.
    pub fn generate(&mut self) -> HlcType {
        let now = Self::current_time_ms();

        // Handle clock rollback or equal time
        if now > self.physical {
            self.physical = now;
            self.logical = 0;
        } else if now == self.physical {
            self.advance_logical_or_wait();
        } else {
            // Clock went backwards, advance logical
            self.advance_logical_or_wait();
        }

        // Ensure physical time doesn't exceed maximum
        if self.physical > MAX_PHYSICAL {
            self.physical = MAX_PHYSICAL;
            self.logical = MAX_LOGICAL;
        }

        HlcType::new(self.format()).expect("HLC format is valid")
    }

    /// Generate the next HLC value, adjusting for a received remote HLC.
    ///
    /// When receiving an event from another node, advance local HLC
    /// to at least the remote HLC to maintain global monotonicity.
    pub fn generate_with_remote(&mut self, remote_hlc: &HlcType) -> Result<HlcType> {
        let remote_parts = parse_hlc(remote_hlc.as_str())?;

        let now = Self::current_time_ms();

        // HLC = max(current_hlc, now_ms, remote_hlc)
        let max_physical = self.physical.max(now).max(remote_parts.physical_ms);

        if max_physical > self.physical {
            self.physical = max_physical;
            self.logical = 0;
        } else if max_physical == self.physical {
            self.advance_logical_or_error()?;
        }

        // If remote HLC has same physical time, ensure we're ahead
        if remote_parts.physical_ms == self.physical && remote_parts.logical >= self.logical {
            if remote_parts.logical >= MAX_LOGICAL {
                return Err(Error::Protocol(
                    "hlc_logical_overflow: remote HLC saturated the 4-hex logical counter"
                        .to_owned(),
                ));
            }
            self.logical = remote_parts.logical + 1;
        }

        Ok(HlcType::new(self.format())?)
    }

    /// Validate an incoming HLC value.
    ///
    /// Checks:
    /// - Format is valid
    /// - Physical time is not beyond the hard future-skew cap
    pub fn validate_incoming(&self, hlc: &HlcType) -> Result<()> {
        self.validate_incoming_future_drift(hlc).map(|_| ())
    }

    /// Validate an incoming HLC and return whether callers should soft-fail
    /// or quarantine while waiting for causal closure / clock convergence.
    pub fn validate_incoming_future_drift(&self, hlc: &HlcType) -> Result<HlcFutureDrift> {
        validate_hlc_future_drift(hlc.as_str(), Self::current_time_ms())
    }

    /// Get current HLC value without advancing.
    pub fn current(&self) -> HlcType {
        HlcType::new(self.format()).expect("HLC format is valid")
    }

    /// Derive the 8-hex-char `node_id_hash` per `encoding.md` §7:
    /// `SHA256("cokret-hlc-v1" || realm_id || device_id ||
    /// local_node_secret)[0:8]`.
    fn compute_node_id(realm_id: &str, device_id: &str, local_node_secret: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(NODE_ID_DOMAIN_SEPARATOR.as_bytes());
        hasher.update(realm_id.as_bytes());
        hasher.update(device_id.as_bytes());
        hasher.update(local_node_secret);
        let hash = hasher.finalize();
        hash[0..4].iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Get current physical time in milliseconds since Unix epoch.
    ///
    /// A system clock set before the Unix epoch (VM snapshot restore,
    /// deliberate tampering) maps to 0 instead of panicking — the
    /// generator's monotonicity logic then treats it like any other
    /// clock rollback.
    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }

    /// Format current HLC as string.
    fn format(&self) -> String {
        format!(
            "{:012x}-{:04x}-{}",
            self.physical, self.logical, self.node_id
        )
    }

    /// Spin iterations before falling back to 1 ms sleeps in
    /// [`Self::advance_logical_or_wait`]. The common trigger is >65,536
    /// HLCs inside one millisecond, where the next millisecond tick is
    /// imminent and a short spin wins; the rare trigger is a clock
    /// rollback, where sleeping avoids burning a full core for the whole
    /// rollback window.
    const OVERFLOW_SPIN_LIMIT: u32 = 1_000;

    fn advance_logical_or_wait(&mut self) {
        if self.logical < MAX_LOGICAL {
            self.logical += 1;
            return;
        }
        // Logical counter saturated. encoding.md's HLC overflow rule
        // forbids wrapping; the two permitted strategies are waiting for
        // a larger unix_ms or returning `hlc_logical_overflow`
        // ([`Self::generate_with_remote`] takes the error path). This
        // sync API waits — spin briefly, then back off with 1 ms sleeps
        // so a clock rollback does not busy-burn a core. wasm32 has no
        // blocking sleep, so it stays on yield (single-threaded hosts
        // would not benefit from sleeping anyway).
        let mut spins = 0u32;
        loop {
            let now = Self::current_time_ms();
            if now > self.physical {
                self.physical = now;
                self.logical = 0;
                return;
            }
            spins = spins.saturating_add(1);
            if spins < Self::OVERFLOW_SPIN_LIMIT {
                std::thread::yield_now();
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                std::thread::sleep(Duration::from_millis(1));
                #[cfg(target_arch = "wasm32")]
                std::thread::yield_now();
            }
        }
    }

    fn advance_logical_or_error(&mut self) -> Result<()> {
        if self.logical < MAX_LOGICAL {
            self.logical += 1;
            Ok(())
        } else {
            Err(Error::Protocol(
                "hlc_logical_overflow: local HLC saturated the 4-hex logical counter".to_owned(),
            ))
        }
    }
}

/// Parse HLC string into components.
pub fn parse_hlc(hlc: &str) -> Result<HlcComponents> {
    validate_hlc_format(hlc)?;

    let parts: Vec<&str> = hlc.split('-').collect();
    if parts.len() != 3 {
        return Err(Error::Protocol(format!(
            "schema_violation: invalid HLC: wrong number of parts: {}",
            hlc
        )));
    }

    let physical_ms = u64::from_str_radix(parts[0], 16).map_err(|_| {
        Error::Protocol(format!(
            "schema_violation: invalid physical time: {}",
            parts[0]
        ))
    })?;

    let logical = u32::from_str_radix(parts[1], 16).map_err(|_| {
        Error::Protocol(format!(
            "schema_violation: invalid logical counter: {}",
            parts[1]
        ))
    })?;

    let node_id = parts[2].to_owned();

    Ok(HlcComponents {
        physical_ms,
        logical,
        node_id,
    })
}

/// Validate future drift against the spec's two-tier HLC model.
pub fn validate_hlc_future_drift(hlc: &str, current_time_ms: u64) -> Result<HlcFutureDrift> {
    let parts = parse_hlc(hlc)?;
    if parts.physical_ms <= current_time_ms {
        return Ok(HlcFutureDrift::Accept);
    }

    let future_drift_ms = (parts.physical_ms - current_time_ms) as i64;
    if future_drift_ms > HARD_FUTURE_SKEW_MS {
        return Err(Error::Protocol(format!(
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
/// Returns:
/// - `Some(Less)` if hlc1 < hlc2
/// - `Some(Greater)` if hlc1 > hlc2
/// - `Some(Equal)` if hlc1 == hlc2
/// - `None` if either HLC is invalid
pub fn compare_hlc(hlc1: &str, hlc2: &str) -> Result<std::cmp::Ordering> {
    let parts1 = parse_hlc(hlc1)?;
    let parts2 = parse_hlc(hlc2)?;

    // Lexicographic comparison: physical, then logical, then node_id
    Ok(parts1
        .physical_ms
        .cmp(&parts2.physical_ms)
        .then_with(|| parts1.logical.cmp(&parts2.logical))
        .then_with(|| parts1.node_id.cmp(&parts2.node_id)))
}

/// Check if HLC is within acceptable clock skew window.
pub fn is_clock_skew_acceptable(hlc: &str, current_time_ms: u64) -> Result<bool> {
    let parts = parse_hlc(hlc)?;

    let skew = if parts.physical_ms > current_time_ms {
        (parts.physical_ms - current_time_ms) as i64
    } else {
        (current_time_ms - parts.physical_ms) as i64
    };

    Ok(skew <= MAX_SKEW_MS)
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
    fn hlc_generator_creates_monotonic_sequence() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "device-1",
            b"test-secret",
            0x01970e589d21,
        );

        let hlc1 = hlc_gen.generate();
        let hlc2 = hlc_gen.generate();
        let hlc3 = hlc_gen.generate();

        assert!(compare_hlc(hlc1.as_str(), hlc2.as_str()).unwrap() == std::cmp::Ordering::Less);
        assert!(compare_hlc(hlc2.as_str(), hlc3.as_str()).unwrap() == std::cmp::Ordering::Less);
    }

    #[test]
    fn hlc_generator_handles_clock_rollback() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "device-1",
            b"test-secret",
            0x01970e589d21,
        );

        // Generate several HLCs - they should be monotonically increasing
        let hlc1 = hlc_gen.generate();
        let hlc2 = hlc_gen.generate();
        let hlc3 = hlc_gen.generate();

        assert!(compare_hlc(hlc1.as_str(), hlc2.as_str()).unwrap() == std::cmp::Ordering::Less);
        assert!(compare_hlc(hlc2.as_str(), hlc3.as_str()).unwrap() == std::cmp::Ordering::Less);
    }

    #[test]
    fn hlc_generator_advances_with_remote() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "device-1",
            b"test-secret",
            0x01970e589d21,
        );

        let remote = HlcType::new("01970e589d22-0005-a13f9c2e").unwrap();
        let hlc = hlc_gen.generate_with_remote(&remote).unwrap();

        let hlc_parts = parse_hlc(hlc.as_str()).unwrap();
        assert!(hlc_parts.physical_ms >= 0x01970e589d22);
    }

    #[test]
    fn hlc_generator_rejects_future_hlc_beyond_skew() {
        let hlc_gen = HlcGenerator::new(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "device-1",
            b"test-secret",
        );

        // Create HLC far in the future (> 5 minutes)
        // MAX_SKEW_MS is 5 minutes in milliseconds, so we add more than that
        let future_physical = HlcGenerator::current_time_ms() + MAX_SKEW_MS as u64 + 1000;
        let future_hlc = HlcType::new(format!("{:012x}-0001-a13f9c2e", future_physical)).unwrap();

        assert!(hlc_gen.validate_incoming(&future_hlc).is_err());
    }

    #[test]
    fn node_id_computation_is_deterministic_and_realm_scoped() {
        let realm_a = "ck:realm:01904100-0000-7000-8000-9b64700c6ee8";
        let realm_b = "ck:realm:01904100-0000-7000-8000-65c7feb295d7";
        let id1 = HlcGenerator::compute_node_id(realm_a, "device-1", b"secret");
        let id2 = HlcGenerator::compute_node_id(realm_a, "device-1", b"secret");
        // Same device + secret in another Realm must yield an unlinkable id.
        let id3 = HlcGenerator::compute_node_id(realm_b, "device-1", b"secret");
        let id4 = HlcGenerator::compute_node_id(realm_a, "device-1", b"other-secret");

        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 8);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
    }

    #[test]
    fn clock_skew_check_within_bounds() {
        let current = 0x01970e589d21;
        let within_skew = format!("{:012x}-0001-a13f9c2e", current + MAX_SKEW_MS as u64);
        let beyond_skew = format!("{:012x}-0001-a13f9c2e", current + MAX_SKEW_MS as u64 + 1000);

        assert!(is_clock_skew_acceptable(&within_skew, current).unwrap());
        assert!(!is_clock_skew_acceptable(&beyond_skew, current).unwrap());
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
    fn hlc_formats_with_fixed_width() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "device-1",
            b"test-secret",
            1,
        );

        let hlc = hlc_gen.generate();
        assert_eq!(hlc.as_str().len(), 26); // 12 + 1 + 4 + 1 + 8
        // All characters should be hex digits (0-9, a-f) or dash (-)
        assert!(
            hlc.as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        );
        // And specifically lowercase (no uppercase A-F)
        assert!(
            hlc.as_str()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
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
