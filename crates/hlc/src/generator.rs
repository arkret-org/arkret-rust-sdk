//! Monotonic Hybrid Logical Clock (HLC) generator.
//!
//! This module implements the stateful side of the Arkret v1 HLC
//! specification:
//! - Monotonic HLC generation over a wall clock
//! - Future-clock drift handling with a 30s soft-fail tier and 5m hard cap
//! - Realm-scoped pseudonymous node id derivation (`encoding.md` §7)
//!
//! The stateless value helpers (format validation, parsing, comparison,
//! future-drift classification) live in `arkret_identifiers::hlc` next to
//! the validated [`Hlc`] newtype.

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use arkret_identifiers::Hlc;
use arkret_identifiers::hlc::{HLC_MAX_LOGICAL, HLC_MAX_PHYSICAL_MS, HlcFutureDrift};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{HlcError, Result};

/// Domain separator for the §7 `node_id_hash` derivation.
const NODE_ID_DOMAIN_SEPARATOR: &str = "arkret-hlc-v1";

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
    /// `SHA256("arkret-hlc-v1" || realm_id || device_id ||
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
    /// monotonicity. If the 16-bit logical counter is exhausted within the
    /// current millisecond, this synchronous API waits until physical time
    /// advances instead of wrapping the counter.
    pub fn generate(&mut self) -> Hlc {
        if self
            .advance_for_now_or_error(Self::current_time_ms())
            .is_err()
        {
            self.advance_logical_or_wait();
        }
        self.clamp_physical();

        Hlc::new(self.format()).expect("HLC format is valid")
    }

    /// Generate the next HLC value without blocking.
    ///
    /// Returns `hlc_logical_overflow` when the local clock has not advanced
    /// beyond the generator's current physical millisecond and the 16-bit
    /// logical counter is already saturated.
    pub fn try_generate(&mut self) -> Result<Hlc> {
        self.advance_for_now_or_error(Self::current_time_ms())?;
        self.clamp_physical();
        Ok(Hlc::new(self.format())?)
    }

    /// Generate the next HLC for an explicit scope and caller-supplied clock.
    ///
    /// A single process clock can use this entry point for many Realms while
    /// retaining one monotonic `(physical, logical)` sequence. The node id is
    /// derived independently for every scope, preventing cross-Realm linkage.
    pub fn try_generate_for_scope_at(
        &mut self,
        realm_id: &str,
        device_id: &str,
        local_node_secret: &[u8],
        current_time_ms: u64,
    ) -> Result<Hlc> {
        self.advance_for_now_or_error(current_time_ms)?;
        self.clamp_physical();
        let node_id = Self::compute_node_id(realm_id, device_id, local_node_secret);
        Ok(Hlc::new(self.format_with_node(&node_id))?)
    }

    /// Generate the next HLC value, adjusting for a received remote HLC.
    ///
    /// When receiving an event from another node, advance local HLC
    /// to at least the remote HLC to maintain global monotonicity.
    pub fn generate_with_remote(&mut self, remote_hlc: &Hlc) -> Result<Hlc> {
        let remote_parts = remote_hlc.components();

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
            if remote_parts.logical >= HLC_MAX_LOGICAL {
                return Err(HlcError::Protocol(
                    "hlc_logical_overflow: remote HLC saturated the 4-hex logical counter"
                        .to_owned(),
                ));
            }
            self.logical = remote_parts.logical + 1;
        }

        Ok(Hlc::new(self.format())?)
    }

    /// Validate an incoming HLC value.
    ///
    /// Checks:
    /// - Format is valid
    /// - Physical time is not beyond the hard future-skew cap
    pub fn validate_incoming(&self, hlc: &Hlc) -> Result<()> {
        self.validate_incoming_future_drift(hlc).map(|_| ())
    }

    /// Validate an incoming HLC and return whether callers should soft-fail
    /// or quarantine while waiting for causal closure / clock convergence.
    pub fn validate_incoming_future_drift(&self, hlc: &Hlc) -> Result<HlcFutureDrift> {
        Ok(arkret_identifiers::hlc::validate_hlc_future_drift(
            hlc.as_str(),
            Self::current_time_ms(),
        )?)
    }

    /// Get current HLC value without advancing.
    pub fn current(&self) -> Hlc {
        Hlc::new(self.format()).expect("HLC format is valid")
    }

    /// Derive the 8-hex-char `node_id_hash` per `encoding.md` §7:
    /// `SHA256("arkret-hlc-v1" || realm_id || device_id ||
    /// local_node_secret)[0:8]`.
    fn compute_node_id(realm_id: &str, device_id: &str, local_node_secret: &[u8]) -> String {
        let hash = arkret_canonical::canonical::sha256_bytes_from_slices(&[
            NODE_ID_DOMAIN_SEPARATOR.as_bytes(),
            realm_id.as_bytes(),
            device_id.as_bytes(),
            local_node_secret,
        ]);
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
        self.format_with_node(&self.node_id)
    }

    fn format_with_node(&self, node_id: &str) -> String {
        format!("{:012x}-{:04x}-{}", self.physical, self.logical, node_id)
    }

    /// Spin iterations before falling back to 1 ms sleeps in
    /// [`Self::advance_logical_or_wait`]. The common trigger is >65,536
    /// HLCs inside one millisecond, where the next millisecond tick is
    /// imminent and a short spin wins; the rare trigger is a clock
    /// rollback, where sleeping avoids burning a full core for the whole
    /// rollback window.
    const OVERFLOW_SPIN_LIMIT: u32 = 1_000;

    fn advance_logical_or_wait(&mut self) {
        if self.logical < HLC_MAX_LOGICAL {
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
        if self.logical < HLC_MAX_LOGICAL {
            self.logical += 1;
            Ok(())
        } else {
            Err(HlcError::Protocol(
                "hlc_logical_overflow: local HLC saturated the 4-hex logical counter".to_owned(),
            ))
        }
    }

    fn advance_for_now_or_error(&mut self, now: u64) -> Result<()> {
        if now > self.physical {
            self.physical = now;
            self.logical = 0;
        } else {
            self.advance_logical_or_error()?;
        }
        Ok(())
    }

    fn clamp_physical(&mut self) {
        if self.physical > HLC_MAX_PHYSICAL_MS {
            self.physical = HLC_MAX_PHYSICAL_MS;
            self.logical = HLC_MAX_LOGICAL;
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::hlc::{HARD_FUTURE_SKEW_MS, compare_hlc, parse_hlc};

    use super::*;

    #[test]
    fn hlc_generator_creates_monotonic_sequence() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
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
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
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
    fn hlc_generator_try_generate_reports_logical_overflow_without_waiting() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "device-1",
            b"test-secret",
            HlcGenerator::current_time_ms() + 60_000,
        );
        hlc_gen.logical = HLC_MAX_LOGICAL;

        let err = hlc_gen.try_generate().unwrap_err();
        assert!(err.to_string().contains("hlc_logical_overflow"));
    }

    #[test]
    fn hlc_generator_try_generate_advances_logical_when_not_saturated() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "device-1",
            b"test-secret",
            HlcGenerator::current_time_ms() + 60_000,
        );
        hlc_gen.logical = HLC_MAX_LOGICAL - 1;

        let hlc = hlc_gen.try_generate().unwrap();
        let parts = parse_hlc(hlc.as_str()).unwrap();
        assert_eq!(parts.logical, HLC_MAX_LOGICAL);
    }

    #[test]
    fn hlc_generator_advances_with_remote() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "device-1",
            b"test-secret",
            0x01970e589d21,
        );

        let remote = Hlc::new("01970e589d22-0005-a13f9c2e").unwrap();
        let hlc = hlc_gen.generate_with_remote(&remote).unwrap();

        let hlc_parts = parse_hlc(hlc.as_str()).unwrap();
        assert!(hlc_parts.physical_ms >= 0x01970e589d22);
    }

    #[test]
    fn hlc_generator_rejects_future_hlc_beyond_skew() {
        let hlc_gen = HlcGenerator::new(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "device-1",
            b"test-secret",
        );

        // Create HLC far in the future (> 5 minutes)
        // MAX_SKEW_MS is 5 minutes in milliseconds, so we add more than that
        let future_physical = HlcGenerator::current_time_ms() + HARD_FUTURE_SKEW_MS as u64 + 1000;
        let future_hlc = Hlc::new(format!("{:012x}-0001-a13f9c2e", future_physical)).unwrap();

        assert!(hlc_gen.validate_incoming(&future_hlc).is_err());
    }

    #[test]
    fn node_id_computation_is_deterministic_and_realm_scoped() {
        let realm_a = "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs";
        let realm_b = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
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
    fn scoped_generation_keeps_one_sequence_with_unlinkable_node_ids() {
        let realm_a = "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs";
        let realm_b = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let secret = b"stable-local-secret";
        let mut generator = HlcGenerator::with_initial_time(realm_a, "device-1", secret, 0);

        let first = generator
            .try_generate_for_scope_at(realm_a, "device-1", secret, 1_700_000_000_000)
            .unwrap();
        let second = generator
            .try_generate_for_scope_at(realm_b, "device-1", secret, 1_700_000_000_000)
            .unwrap();
        let first = parse_hlc(first.as_str()).unwrap();
        let second = parse_hlc(second.as_str()).unwrap();

        assert_eq!(first.physical_ms, second.physical_ms);
        assert_eq!(first.logical + 1, second.logical);
        assert_ne!(first.node_id, second.node_id);
    }

    #[test]
    fn hlc_formats_with_fixed_width() {
        let mut hlc_gen = HlcGenerator::with_initial_time(
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
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
}
