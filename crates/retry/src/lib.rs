//! Arkret v1 retry cadence.
//!
//! Pure policy computation: how long to wait before the next attempt, how much
//! jitter to add, when the ladder saturates, and when the retry budget is
//! spent. It deliberately depends on no HTTP client, no async runtime, no clock
//! and no entropy source, so the same curve is used by native servers and by
//! `wasm32-unknown-unknown` clients.
//!
//! # Normative source
//!
//! `arkret-spec/spec/v1/zh/sync/api-conventions.md` §9 is the truth source for
//! the default curve. Two clauses are normative:
//!
//! * §9 (`api-conventions.md:554`) — clients and peer services MUST apply exponential backoff per
//!   `(actor, service DID, endpoint)` combination, so a retry cannot amplify.
//! * §9 (`api-conventions.md:556`, restated at `:533` for `rate_limit_policy`) — the default curve:
//!   first wait **at least 1,000 ms**, **factor 2**, per-attempt ceiling **at least 60,000 ms**,
//!   **0–20% jitter**, and **at most 5 automatic retries within 5 minutes** for the same
//!   combination.
//!
//! Those five numbers are [`SPEC_INITIAL_DELAY`], [`SPEC_FACTOR`],
//! [`SPEC_MAX_DELAY`], [`SPEC_JITTER_RATIO`], [`SPEC_MAX_RETRIES`] and
//! [`SPEC_RETRY_WINDOW`], and [`RetryPolicy::arkret_default`] is the curve they
//! describe. `tests::spec_default_meets_every_normative_bound` is the baseline
//! that keeps it honest.
//!
//! Because the spec states the ceiling as a *lower bound* on the per-attempt
//! cap (the per-attempt cap is at least 60,000 ms), jitter is added **on top of** the capped base
//! rather than re-clamped into it. Re-clamping would collapse the jitter window
//! to zero once the ladder saturates, which is exactly the fleet-synchronizing
//! behavior the jitter clause exists to prevent.
//!
//! # `Retry-After` is a floor, never a clamp
//!
//! `api-conventions.md:545` gives the `Retry-After` header priority over a body
//! `retry_after_ms`, and `:547` forbids truncating a long server value into an
//! earlier retry — fixed by the conformance vector `ak.vector.sdk.retry_after.v1`
//! (`long_value_clamped: false`) and registered as SDK clause 20. Therefore
//! [`RetrySchedule::next_delay_with_hint`] takes the server hint as a hard
//! floor: the returned delay is never shorter than the hint, and the local
//! ladder advances from its own base so a single long hint does not permanently
//! inflate later steps.
//!
//! # Jitter and wasm
//!
//! Jitter must not pull in `rand`, whose default entropy source panics on
//! `wasm32-unknown-unknown`. The caller *injects a seed* and jitter comes from a
//! tiny deterministic SplitMix64 mixer, which keeps the type wasm-safe and its
//! output reproducible in tests. The trade-off: a caller that wants independent
//! jitter across instances must supply a varied seed (an id, a monotonic
//! counter, or host entropy); two schedules built from the same seed produce
//! identical jitter sequences.

use std::time::Duration;

/// `api-conventions.md` §9 — the first wait is at least this long.
pub const SPEC_INITIAL_DELAY: Duration = Duration::from_millis(1_000);

/// `api-conventions.md` §9 — the ladder multiplier.
pub const SPEC_FACTOR: u32 = 2;

/// `api-conventions.md` §9 — the per-attempt ceiling is at least this long.
pub const SPEC_MAX_DELAY: Duration = Duration::from_millis(60_000);

/// `api-conventions.md` §9 — jitter spans 0–20% of the computed delay.
pub const SPEC_JITTER_RATIO: f64 = 0.20;

/// `api-conventions.md` §9 — at most 5 automatic retries per window.
pub const SPEC_MAX_RETRIES: u32 = 5;

/// `api-conventions.md` §9 — the retry-budget window.
pub const SPEC_RETRY_WINDOW: Duration = Duration::from_secs(300);

/// Highest ladder step computed by doubling, so a bogus retry counter cannot
/// turn [`RetryPolicy::base_delay`] into a long loop.
const MAX_LADDER_STEPS: u32 = 32;

/// An exponential backoff curve and its retry budget.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RetryPolicy {
    initial_delay: Duration,
    max_delay: Duration,
    factor: u32,
    jitter_ratio: f64,
    max_retries: u32,
    retry_window: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::arkret_default()
    }
}

impl RetryPolicy {
    /// The `api-conventions.md` §9 default curve. Use this for every retry of
    /// an Arkret protocol endpoint; the numbers are normative, not defaults to
    /// be tuned per service.
    #[must_use]
    pub const fn arkret_default() -> Self {
        Self {
            initial_delay: SPEC_INITIAL_DELAY,
            max_delay: SPEC_MAX_DELAY,
            factor: SPEC_FACTOR,
            jitter_ratio: SPEC_JITTER_RATIO,
            max_retries: SPEC_MAX_RETRIES,
            retry_window: SPEC_RETRY_WINDOW,
        }
    }

    /// A curve for a retry path the spec does not cover — a durable job queue,
    /// a vendor API outside the Arkret protocol surface. Everything except the
    /// two delays keeps the spec defaults.
    #[must_use]
    pub const fn exponential(initial_delay: Duration, max_delay: Duration) -> Self {
        Self {
            initial_delay,
            max_delay,
            factor: SPEC_FACTOR,
            jitter_ratio: SPEC_JITTER_RATIO,
            max_retries: SPEC_MAX_RETRIES,
            retry_window: SPEC_RETRY_WINDOW,
        }
    }

    /// No retries at all: one attempt, then the error is terminal.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            factor: SPEC_FACTOR,
            jitter_ratio: 0.0,
            max_retries: 0,
            retry_window: SPEC_RETRY_WINDOW,
        }
    }

    #[must_use]
    pub const fn with_factor(mut self, factor: u32) -> Self {
        self.factor = factor;
        self
    }

    /// Set the jitter span as a fraction of the computed delay, clamped to
    /// `[0.0, 1.0]`.
    #[must_use]
    pub fn with_jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio.clamp(0.0, 1.0);
        self
    }

    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    #[must_use]
    pub const fn initial_delay(&self) -> Duration {
        self.initial_delay
    }

    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.max_delay
    }

    #[must_use]
    pub const fn factor(&self) -> u32 {
        self.factor
    }

    #[must_use]
    pub const fn jitter_ratio(&self) -> f64 {
        self.jitter_ratio
    }

    #[must_use]
    pub const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    #[must_use]
    pub const fn retry_window(&self) -> Duration {
        self.retry_window
    }

    /// The un-jittered delay before retry number `retry`, counted from zero:
    /// `base_delay(0)` is the wait before the first retry.
    #[must_use]
    pub fn base_delay(&self, retry: u32) -> Duration {
        let ceiling = self.max_delay.max(self.initial_delay);
        let mut delay = self.initial_delay;
        for _ in 0..retry.min(MAX_LADDER_STEPS) {
            if delay >= ceiling {
                return ceiling;
            }
            delay = delay.saturating_mul(self.factor);
        }
        delay.min(ceiling)
    }

    /// [`Self::base_delay`] with this policy's jitter added on top.
    #[must_use]
    pub fn delay(&self, retry: u32, jitter: &mut Jitter) -> Duration {
        apply_jitter(self.base_delay(retry), self.jitter_ratio, jitter)
    }
}

/// A stateful exponential ladder over one [`RetryPolicy`].
#[derive(Clone, Debug)]
pub struct RetrySchedule {
    policy: RetryPolicy,
    jitter: Option<Jitter>,
    retries: u32,
}

impl RetrySchedule {
    /// A ladder bounded by `[initial_delay, max_delay]`. If `max_delay` is
    /// below `initial_delay` it is clamped up, giving a fixed-delay ladder.
    #[must_use]
    pub fn new(initial_delay: Duration, max_delay: Duration) -> Self {
        Self::from_policy(RetryPolicy::exponential(
            initial_delay,
            max_delay.max(initial_delay),
        ))
    }

    /// The `api-conventions.md` §9 ladder.
    #[must_use]
    pub fn arkret_default() -> Self {
        Self::from_policy(RetryPolicy::arkret_default())
    }

    #[must_use]
    pub fn from_policy(policy: RetryPolicy) -> Self {
        Self {
            policy,
            jitter: None,
            retries: 0,
        }
    }

    /// Enable jitter of up to `ratio` of each computed delay, driven by a
    /// deterministic mixer seeded with `seed`. See the module docs for why the
    /// seed is injected rather than drawn from `rand`.
    #[must_use]
    pub fn with_jitter(mut self, ratio: f64, seed: u64) -> Self {
        self.policy = self.policy.with_jitter_ratio(ratio);
        self.jitter = Some(Jitter::from_seed(seed));
        self
    }

    #[must_use]
    pub const fn policy(&self) -> RetryPolicy {
        self.policy
    }

    /// Number of retries taken since the last [`Self::reset`].
    #[must_use]
    pub const fn retries(&self) -> u32 {
        self.retries
    }

    /// Whether the policy's retry count is spent.
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.retries >= self.policy.max_retries
    }

    /// Advance the ladder and return the next delay.
    pub fn next_delay(&mut self) -> Duration {
        self.next_delay_with_hint(None)
    }

    /// Advance the ladder and return the next delay, treating a server
    /// `Retry-After` hint as a hard floor for this step.
    ///
    /// The ladder advances from its own base regardless of the hint, so one
    /// long hint does not permanently inflate the following steps — and the
    /// hint is never truncated downwards (`api-conventions.md:547`).
    pub fn next_delay_with_hint(&mut self, retry_after: Option<Duration>) -> Duration {
        let base = self.policy.base_delay(self.retries);
        self.retries = self.retries.saturating_add(1);
        let computed = match self.jitter.as_mut() {
            Some(jitter) => apply_jitter(base, self.policy.jitter_ratio, jitter),
            None => base,
        };
        match retry_after {
            Some(hint) => computed.max(hint),
            None => computed,
        }
    }

    /// Return the ladder to its initial delay. Call after a successful attempt.
    pub fn reset(&mut self) {
        self.retries = 0;
    }
}

/// A fixed step list, for the spec paths that name explicit intervals instead
/// of a doubling ladder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryLadder {
    steps: &'static [Duration],
    /// Delay repeated once `steps` is spent; `None` ends the ladder.
    ceiling: Option<Duration>,
}

impl RetryLadder {
    /// A ladder that ends after its last step.
    #[must_use]
    pub const fn bounded(steps: &'static [Duration]) -> Self {
        Self {
            steps,
            ceiling: None,
        }
    }

    /// A ladder that repeats `ceiling` indefinitely once `steps` is spent.
    #[must_use]
    pub const fn repeating(steps: &'static [Duration], ceiling: Duration) -> Self {
        Self {
            steps,
            ceiling: Some(ceiling),
        }
    }

    /// The delay before retry number `retry`, counted from zero. `None` once a
    /// bounded ladder is spent.
    #[must_use]
    pub fn step(&self, retry: u32) -> Option<Duration> {
        match usize::try_from(retry) {
            Ok(index) if index < self.steps.len() => Some(self.steps[index]),
            _ => self.ceiling,
        }
    }
}

/// Deterministic, dependency-free jitter mixer (SplitMix64). Not cryptographic.
#[derive(Clone, Debug)]
pub struct Jitter {
    state: u64,
}

impl Jitter {
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// A uniform `f64` in `[0.0, 1.0)`, using the top 53 bits.
    pub fn next_unit(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Add `0..ratio` of `base` to `base`.
///
/// Additive, never subtractive: the spec floors are stated as "at least"
/// (the first wait is at least 1,000 ms), so shaving the delay would breach them.
#[must_use]
pub fn apply_jitter(base: Duration, ratio: f64, jitter: &mut Jitter) -> Duration {
    if ratio <= 0.0 || base.is_zero() {
        return base;
    }
    base.mul_f64(1.0 + ratio.clamp(0.0, 1.0) * jitter.next_unit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn spec_default_meets_every_normative_bound() {
        let policy = RetryPolicy::arkret_default();
        // api-conventions.md:556 — base >= 1000 ms, factor 2, cap >= 60000 ms,
        // 0-20% jitter, at most 5 retries per 5 minutes.
        assert!(policy.initial_delay() >= Duration::from_millis(1_000));
        assert_eq!(policy.factor(), 2);
        assert!(policy.max_delay() >= Duration::from_millis(60_000));
        assert!(policy.jitter_ratio() > 0.0 && policy.jitter_ratio() <= 0.20);
        assert_eq!(policy.max_retries(), 5);
        assert_eq!(policy.retry_window(), Duration::from_secs(300));
    }

    #[test]
    fn spec_default_ladder_doubles_then_saturates() {
        let policy = RetryPolicy::arkret_default();
        let delays: Vec<_> = (0..8).map(|retry| policy.base_delay(retry)).collect();
        assert_eq!(
            delays,
            vec![S(1), S(2), S(4), S(8), S(16), S(32), S(60), S(60)]
        );
    }

    #[test]
    fn jitter_only_ever_lengthens_and_stays_inside_the_span() {
        let policy = RetryPolicy::arkret_default();
        let mut jitter = Jitter::from_seed(0xC0FF_EE12_3456_789A);
        for _ in 0..256 {
            let delay = policy.delay(0, &mut jitter);
            assert!(delay >= S(1), "{delay:?} fell below the 1s spec floor");
            assert!(delay <= Duration::from_millis(1_200), "{delay:?}");
        }
    }

    #[test]
    fn jitter_survives_ladder_saturation() {
        // The cap is a lower bound on the ceiling, not a clamp on the jittered
        // delay: a saturated ladder must still de-correlate a fleet.
        let policy = RetryPolicy::arkret_default();
        let mut jitter = Jitter::from_seed(7);
        let delays: Vec<_> = (0..32).map(|_| policy.delay(20, &mut jitter)).collect();
        assert!(delays.iter().all(|delay| *delay >= S(60)));
        assert!(delays.iter().any(|delay| *delay > S(60)));
        assert!(delays.iter().all(|delay| *delay <= S(72)));
    }

    #[test]
    fn jitter_is_deterministic_for_a_given_seed() {
        let sequence = |seed: u64| {
            let mut schedule = RetrySchedule::arkret_default().with_jitter(0.2, seed);
            (0..8).map(|_| schedule.next_delay()).collect::<Vec<_>>()
        };
        assert_eq!(sequence(42), sequence(42));
        assert_ne!(sequence(42), sequence(7));
    }

    #[test]
    fn schedule_without_jitter_matches_the_bare_ladder() {
        let mut schedule = RetrySchedule::new(S(1), S(8));
        let delays: Vec<_> = (0..6).map(|_| schedule.next_delay()).collect();
        assert_eq!(delays, vec![S(1), S(2), S(4), S(8), S(8), S(8)]);
    }

    #[test]
    fn reset_returns_the_ladder_to_its_initial_delay() {
        let mut schedule = RetrySchedule::new(S(1), S(16));
        assert_eq!(schedule.next_delay(), S(1));
        assert_eq!(schedule.next_delay(), S(2));
        assert_eq!(schedule.next_delay(), S(4));
        schedule.reset();
        assert_eq!(schedule.retries(), 0);
        assert_eq!(schedule.next_delay(), S(1));
    }

    #[test]
    fn ceiling_below_initial_delay_is_clamped_up() {
        let mut schedule = RetrySchedule::new(S(5), S(1));
        assert_eq!(schedule.next_delay(), S(5));
        assert_eq!(schedule.next_delay(), S(5));
    }

    #[test]
    fn server_hint_is_a_floor_and_is_never_clamped_downwards() {
        // ak.vector.sdk.retry_after.v1 — `long_value_clamped: false`.
        let mut schedule = RetrySchedule::arkret_default();
        assert_eq!(schedule.next_delay_with_hint(Some(S(3_600))), S(3_600));
        // The ladder advanced from its own base, not from the hint.
        assert_eq!(schedule.next_delay(), S(2));
        assert_eq!(schedule.next_delay(), S(4));
    }

    #[test]
    fn server_hint_below_the_local_base_does_not_shorten_the_wait() {
        let mut schedule = RetrySchedule::new(S(4), S(60));
        assert_eq!(schedule.next_delay(), S(4));
        assert_eq!(schedule.next_delay(), S(8));
        assert_eq!(schedule.next_delay_with_hint(Some(S(1))), S(16));
    }

    #[test]
    fn schedule_reports_exhaustion_at_the_policy_retry_count() {
        let mut schedule = RetrySchedule::from_policy(RetryPolicy::arkret_default());
        for _ in 0..SPEC_MAX_RETRIES {
            assert!(!schedule.exhausted());
            let _ = schedule.next_delay();
        }
        assert!(schedule.exhausted());
    }

    #[test]
    fn no_retry_policy_never_permits_an_attempt() {
        let policy = RetryPolicy::none();
        assert_eq!(policy.max_retries(), 0);
        let mut schedule = RetrySchedule::from_policy(policy);
        assert!(schedule.exhausted());
        let _ = schedule.next_delay();
        assert!(schedule.exhausted());
    }

    #[test]
    fn bounded_ladder_ends_after_its_last_step() {
        static STEPS: &[Duration] = &[Duration::from_secs(30), Duration::from_secs(120)];
        let ladder = RetryLadder::bounded(STEPS);
        assert_eq!(ladder.step(1), Some(S(120)));
        assert_eq!(ladder.step(2), None);
    }
}
