# arkret-retry

The one retry cadence for the Arkret workspace: backoff curves, jitter and
retry budgets, computed as pure policy.

No HTTP client, no async runtime, no clock, no entropy source. That is what lets
a native server, a `wasm32-unknown-unknown` client and a durable job queue share
one implementation instead of each deriving its own ladder.

## Normative source

`arkret-spec/spec/v1/zh/sync/api-conventions.md` §9 is the truth source:

| Constraint | Value | Where |
| --- | --- | --- |
| first wait | ≥ 1,000 ms | `api-conventions.md:556` |
| factor | 2 | `api-conventions.md:556` |
| per-attempt ceiling | ≥ 60,000 ms | `api-conventions.md:556` |
| jitter | 0–20% | `api-conventions.md:533`, `:556` |
| retry budget | ≤ 5 retries / 5 min per `(actor, service DID, endpoint)` | `api-conventions.md:556` |
| `Retry-After` | header wins over body `retry_after_ms`, and MUST NOT be clamped shorter | `api-conventions.md:545`, `:547`, `ak.vector.sdk.retry_after.v1` |
| pairing status polling | 1s / 2s / 5s / 10s, then ≤ 30s | `key-management.md:369`, `service-http-binding.md:462` |

`RetryPolicy::arkret_default()` is that curve, and
`spec_default_meets_every_normative_bound` is the test that keeps it honest.

## Use

```rust
use arkret_retry::{RetryPolicy, RetrySchedule};

// Arkret protocol endpoints: the normative curve, not a tunable default.
let mut schedule = RetrySchedule::arkret_default().with_jitter(0.2, instance_seed);
let delay = schedule.next_delay_with_hint(server_retry_after);

// A retry path the spec does not cover, e.g. a durable job queue.
let queue = RetryPolicy::exponential(Duration::from_secs(5), Duration::from_secs(2_560))
    .with_max_retries(10);
```

Jitter is **additive**: the spec floors are stated as "at least", so shaving the
delay would breach them. It is also applied *after* the ceiling and not
re-clamped, because a clamp would collapse the jitter window to zero exactly
when a saturated fleet needs it most.
