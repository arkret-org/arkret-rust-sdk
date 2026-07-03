use super::*;

/// Retry configuration for sync failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Initial delay after the first failure.
    pub initial_delay: Duration,
    /// Maximum delay after repeated failures.
    pub max_delay: Duration,
    /// Multiplier applied after each failure.
    pub multiplier: u32,
    /// Apply 0–20% additive random jitter to computed delays so a fleet of
    /// clients does not reconnect in lockstep (api-conventions.md §9 /
    /// client-sync.md §2.2.6).
    pub jitter: bool,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        // client-sync.md §2.2.6 reconnect backoff: start at 1 s, cap at
        // 60 s, exponential, with jitter.
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2,
            jitter: true,
        }
    }
}

/// Exponential backoff state.
#[derive(Clone, Debug)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
    failures: u32,
}

impl ExponentialBackoff {
    /// Create backoff state with a custom configuration.
    pub fn new(config: BackoffConfig) -> Self {
        Self {
            config,
            failures: 0,
        }
    }

    /// Record a failed sync attempt and return the next wait duration.
    pub fn record_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.current_delay()
    }

    /// Clear failure state after a successful sync.
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    /// Number of consecutive failures.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Current delay for the consecutive failure count.
    pub fn current_delay(&self) -> Duration {
        if self.failures == 0 {
            return Duration::ZERO;
        }

        let exponent = self.failures.saturating_sub(1);
        let factor = self.config.multiplier.saturating_pow(exponent);
        let delay = self
            .config
            .initial_delay
            .saturating_mul(factor)
            .min(self.config.max_delay);
        if self.config.jitter {
            apply_backoff_jitter(delay)
        } else {
            delay
        }
    }
}

/// Add 0–20% random jitter to `delay` (api-conventions.md §9). Falls back to
/// the unjittered delay if the OS randomness source fails.
fn apply_backoff_jitter(delay: Duration) -> Duration {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return delay;
    }
    let fraction = f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX);
    delay.mul_f64(1.0 + fraction * 0.2)
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(BackoffConfig::default())
    }
}

/// Result of one sync-loop iteration.
#[derive(Clone, Debug)]
pub enum SyncLoopStep {
    /// A response was processed successfully.
    Updates(SyncUpdates),
    /// Sync failed; caller should wait for `retry_after` before trying again.
    Retry {
        retry_after: Duration,
        error: String,
    },
    /// The caller requested cancellation before a transport request started.
    Cancelled,
    /// A request was deferred because the configured in-flight limit was reached.
    Backpressure { retry_after: Duration },
    /// The stream delivered an `unauthorized` control frame: this session
    /// may no longer consume the account stream. The caller MUST
    /// re-authenticate or sign out (client-sync.md §2.2.5); retrying with
    /// the same session is pointless.
    Unauthorized { reason: Option<String> },
}

/// Minimal transport abstraction used by [`SyncLoop`].
pub trait SyncTransport {
    /// Execute one sync request.
    fn sync(&mut self, request: SyncRequestBody) -> Result<SyncOutcome>;
}

impl<F> SyncTransport for F
where
    F: FnMut(SyncRequestBody) -> Result<SyncOutcome>,
{
    fn sync(&mut self, request: SyncRequestBody) -> Result<SyncOutcome> {
        self(request)
    }
}

pub type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Async transport abstraction used by [`SyncLoop::step_async`].
pub trait AsyncSyncTransport {
    /// Execute one async sync request.
    fn sync_async<'a>(&'a self, request: SyncRequestBody) -> BoxSyncFuture<'a, SyncOutcome>;
}

impl<F, Fut> AsyncSyncTransport for F
where
    F: Fn(SyncRequestBody) -> Fut + Send + Sync,
    Fut: Future<Output = Result<SyncOutcome>> + Send + 'static,
{
    fn sync_async<'a>(&'a self, request: SyncRequestBody) -> BoxSyncFuture<'a, SyncOutcome> {
        Box::pin(self(request))
    }
}

/// Async streaming transport abstraction for `ck.self.events.stream.subscribe`
/// (`/_cokret/self/events/subscribe`).
///
/// Opens the `ck.self.events.stream.subscribe` stream. The transport accepts a single
/// `realm_id` selector; callers that need multi-Realm / actor selectors should
/// use the lower-level HTTP client directly.
pub trait EventsSubscribeTransport {
    /// Streaming response type chosen by the concrete HTTP backend.
    type EventStream;

    /// Open a server-side events subscription stream from an optional cursor.
    fn events_subscribe<'a>(
        &'a self,
        realm_id: &'a str,
        from: Option<&'a str>,
    ) -> BoxSyncFuture<'a, Self::EventStream>;
}

// `BoxSyncFuture` requires `Send`, but on wasm32 reqwest's `Response`
// (and the futures returned by `Client` methods that touch it) hold
// `JsValue` / `Closure` / `wasm_bindgen_futures::JsFuture` types that are
// not `Send`. The browser is single-threaded, so a future-returning
// transport adapter can sidestep this by carrying an `!Send` future
// behind a `LocalBoxFuture` — but that's an embedder concern. We simply
// gate the in-tree adapters out on wasm32 and leave the trait available
// for downstream impls.
#[cfg(all(feature = "client", not(target_arch = "wasm32")))]
impl AsyncSyncTransport for crate::Client {
    fn sync_async<'a>(&'a self, request: SyncRequestBody) -> BoxSyncFuture<'a, SyncOutcome> {
        Box::pin(async move { self.account_subscribe_once(&request).await })
    }
}

#[cfg(all(feature = "client", not(target_arch = "wasm32")))]
impl EventsSubscribeTransport for crate::Client {
    type EventStream = reqwest::Response;

    fn events_subscribe<'a>(
        &'a self,
        realm_id: &'a str,
        from: Option<&'a str>,
    ) -> BoxSyncFuture<'a, Self::EventStream> {
        Box::pin(async move { self.events_subscribe_stream(realm_id, from).await })
    }
}

/// Cancellation token that stays independent of a specific async runtime.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation for future sync work.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Clear a previous cancellation request.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Async sync backpressure settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackpressureConfig {
    /// Maximum number of concurrent transport requests.
    pub max_in_flight_requests: usize,
    /// Delay returned when a caller should retry after backpressure.
    pub retry_after: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 1,
            retry_after: Duration::from_millis(100),
        }
    }
}

/// Runtime-neutral async sync loop controls.
#[derive(Clone, Debug)]
pub struct SyncLoopControl {
    cancellation: CancellationToken,
    backpressure: BackpressureConfig,
    in_flight: Arc<AtomicUsize>,
}

impl SyncLoopControl {
    /// Create controls with default cancellation and single-flight backpressure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an existing cancellation token.
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Set backpressure behavior.
    pub fn with_backpressure(mut self, backpressure: BackpressureConfig) -> Self {
        self.backpressure = backpressure;
        self
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Clear cancellation.
    pub fn reset_cancellation(&self) {
        self.cancellation.reset();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Configured retry delay for backpressure responses.
    pub fn backpressure_retry_after(&self) -> Duration {
        self.backpressure.retry_after
    }

    pub(super) fn try_acquire(&self) -> Option<InFlightPermit> {
        let max = self.backpressure.max_in_flight_requests.max(1);
        let mut current = self.in_flight.load(Ordering::SeqCst);
        loop {
            if current >= max {
                return None;
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(InFlightPermit {
                        in_flight: Arc::clone(&self.in_flight),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Default for SyncLoopControl {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::default(),
            backpressure: BackpressureConfig::default(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub(super) struct InFlightPermit {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Strategy used when a limited timeline indicates a sync gap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncGapStrategy {
    /// Preserve the token and let the caller backfill gaps explicitly.
    #[default]
    PreserveTokenAndBackfill,
    /// Clear the token so the next sync restarts from an initial snapshot.
    ResetTokenOnLimitedTimeline,
}

/// Serializable sync loop state for durable token persistence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLoopSnapshot {
    /// Last accepted sync token.
    pub token: Option<String>,
    /// Long-poll timeout persisted as milliseconds for portability.
    pub timeout_ms: u64,
    /// Gap handling strategy used by the loop.
    pub gap_strategy: SyncGapStrategy,
}

/// Long-polling sync loop state.
pub struct SyncLoop {
    token: Option<String>,
    timeout: Duration,
    filter: Option<SyncFilter>,
    subscriptions: Option<SubscriptionConfig>,
    wait_for: Option<WaitForFrontier>,
    backoff: ExponentialBackoff,
    processor: SyncResponseProcessor,
    gap_strategy: SyncGapStrategy,
}

impl SyncLoop {
    /// Create a sync loop with a 30 second long-poll timeout.
    pub fn new() -> Self {
        Self {
            token: None,
            timeout: Duration::from_secs(30),
            filter: None,
            subscriptions: None,
            wait_for: None,
            backoff: ExponentialBackoff::default(),
            processor: SyncResponseProcessor::new(),
            gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
        }
    }

    /// Restore a loop from a previously persisted snapshot.
    pub fn from_snapshot(snapshot: SyncLoopSnapshot) -> Self {
        let mut sync_loop = Self::new()
            .with_timeout(Duration::from_millis(snapshot.timeout_ms))
            .with_gap_strategy(snapshot.gap_strategy);
        sync_loop.token = snapshot.token;
        sync_loop
    }

    /// Set the long-poll timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the filter sent with each request.
    pub fn with_filter(mut self, filter: SyncFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set subscriptions sent with each request.
    pub fn with_subscriptions(mut self, subscriptions: SubscriptionConfig) -> Self {
        self.subscriptions = Some(subscriptions);
        self
    }

    /// Set a frontier the server should wait for before returning.
    pub fn with_wait_for(mut self, wait_for: WaitForFrontier) -> Self {
        self.wait_for = Some(wait_for);
        self
    }

    /// Set the gap strategy used after limited timelines.
    pub fn with_gap_strategy(mut self, strategy: SyncGapStrategy) -> Self {
        self.gap_strategy = strategy;
        self
    }

    /// Set retry backoff configuration.
    pub fn with_backoff_config(mut self, config: BackoffConfig) -> Self {
        self.backoff = ExponentialBackoff::new(config);
        self
    }

    /// Build the next long-poll request.
    ///
    /// The loop's `timeout` is intentionally not part of the wire request:
    /// `ck.self.account.stream.subscribe` has no client-supplied long-poll
    /// timeout parameter (client-sync.md §2 — the wait window is a server /
    /// deployment default). It only feeds snapshot persistence and the
    /// caller's own scheduling.
    pub fn next_request(&self) -> SyncRequestBody {
        SyncRequestBody {
            after: self.token.clone(),
            catchup: Some(true),
            filter: self.filter.clone(),
            subscriptions: self.subscriptions.clone(),
            wait_for: self.wait_for.clone(),
        }
    }

    fn handle_response(&mut self, response: SyncOutcome) -> SyncLoopStep {
        // Snapshot the pre-response cursor so a processing failure leaves
        // the loop positioned to re-fetch the same batch (at-least-once,
        // operations-sync.md): the token and backoff state only advance
        // after `process` succeeds.
        let cursor = response.cursor.clone();
        match self.processor.process(response) {
            Ok(updates) => {
                self.backoff.reset();
                self.token = Some(cursor);
                if self.gap_strategy == SyncGapStrategy::ResetTokenOnLimitedTimeline
                    && updates.realm_updates.iter().any(|update| {
                        update
                            .timeline
                            .as_ref()
                            .is_some_and(|timeline| timeline.limited)
                    })
                {
                    self.token = None;
                }
                SyncLoopStep::Updates(updates)
            }
            Err(error) => {
                let retry_after = self.backoff.record_failure();
                SyncLoopStep::Retry {
                    retry_after,
                    error: error.to_string(),
                }
            }
        }
    }

    /// React to a transport error, routing structured account-stream
    /// interrupts (client-sync.md §2.2) to their recovery paths.
    fn handle_transport_error(&mut self, error: Error) -> SyncLoopStep {
        match error {
            Error::AccountStreamInterrupt(interrupt) => self.handle_interrupt(interrupt),
            error => {
                let retry_after = self.backoff.record_failure();
                SyncLoopStep::Retry {
                    retry_after,
                    error: error.to_string(),
                }
            }
        }
    }

    /// Apply the spec-mandated recovery for a control interrupt. A
    /// server-directed `reconnect_after_ms` is authoritative and is
    /// returned verbatim as the retry delay (client-sync.md §2.2.6: MUST
    /// prefer the server instruction); without one, reconnection may be
    /// immediate to shrink the inconsistency window.
    fn handle_interrupt(&mut self, interrupt: AccountStreamInterrupt) -> SyncLoopStep {
        match interrupt {
            AccountStreamInterrupt::Dropped {
                cursor,
                reconnect_after_ms,
            } => {
                match cursor {
                    // §2.2.3: reconnect from the frame cursor with catchup
                    // so the server replays the lost account delta.
                    Some(cursor) => self.token = Some(cursor),
                    // The spec requires `dropped` to carry a cursor; a
                    // frame without one degrades to resync semantics so a
                    // known gap is never silently skipped.
                    None => self.token = None,
                }
                SyncLoopStep::Retry {
                    retry_after: Duration::from_millis(reconnect_after_ms.unwrap_or(0)),
                    error: "account stream dropped; reconnecting with catch-up cursor".to_owned(),
                }
            }
            AccountStreamInterrupt::ResyncRequired { reconnect_after_ms } => {
                // §2.2.4: clear the cursor cache and redo initial sync.
                self.token = None;
                SyncLoopStep::Retry {
                    retry_after: Duration::from_millis(reconnect_after_ms.unwrap_or(0)),
                    error: "account stream requires resync; restarting initial sync".to_owned(),
                }
            }
            AccountStreamInterrupt::Unauthorized { reason } => {
                SyncLoopStep::Unauthorized { reason }
            }
        }
    }

    /// Execute one loop iteration.
    ///
    /// The caller owns sleeping and cancellation. This keeps the type portable
    /// across native and WASM runtimes.
    pub fn step<T>(&mut self, transport: &mut T) -> SyncLoopStep
    where
        T: SyncTransport,
    {
        let request = self.next_request();
        match transport.sync(request) {
            Ok(response) => self.handle_response(response),
            Err(error) => self.handle_transport_error(error),
        }
    }

    /// Execute one async loop iteration with default controls.
    pub async fn step_async<T>(&mut self, transport: &T) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        let control = SyncLoopControl::default();
        self.step_async_with_control(transport, &control).await
    }

    /// Execute one async loop iteration with cancellation and backpressure.
    pub async fn step_async_with_control<T>(
        &mut self,
        transport: &T,
        control: &SyncLoopControl,
    ) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        if control.is_cancelled() {
            return SyncLoopStep::Cancelled;
        }
        let Some(_permit) = control.try_acquire() else {
            return SyncLoopStep::Backpressure {
                retry_after: control.backpressure_retry_after(),
            };
        };
        let request = self.next_request();
        match transport.sync_async(request).await {
            Ok(response) => self.handle_response(response),
            Err(error) => self.handle_transport_error(error),
        }
    }

    /// Current sync token.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Pending recovery actions accumulated from processed sync responses.
    pub fn recovery_actions(&self) -> Vec<SyncRecoveryAction> {
        self.processor.recovery_actions()
    }

    /// Drain pending recovery actions after the application schedules them.
    pub fn take_recovery_actions(&mut self) -> Vec<SyncRecoveryAction> {
        self.processor.take_recovery_actions()
    }

    /// Export durable sync loop state.
    pub fn snapshot(&self) -> SyncLoopSnapshot {
        SyncLoopSnapshot {
            token: self.token.clone(),
            timeout_ms: self.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            gap_strategy: self.gap_strategy,
        }
    }

    /// Restore durable token state on an existing loop.
    pub fn restore_snapshot(&mut self, snapshot: SyncLoopSnapshot) {
        self.token = snapshot.token;
        self.timeout = Duration::from_millis(snapshot.timeout_ms);
        self.gap_strategy = snapshot.gap_strategy;
        self.processor.clear();
        self.backoff.reset();
    }

    /// Reset the loop after unrecoverable state loss.
    pub fn reset(&mut self) {
        self.token = None;
        self.backoff.reset();
        self.processor.clear();
    }
}

impl Default for SyncLoop {
    fn default() -> Self {
        Self::new()
    }
}
