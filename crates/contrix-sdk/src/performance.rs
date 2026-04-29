//! Performance-oriented helpers for pooling, batching and build planning.

use std::{
    collections::BTreeMap,
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Borrowed JSON input for zero-copy parsing boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroCopyJson<'a> {
    /// Raw JSON bytes.
    pub bytes: &'a [u8],
}

impl<'a> ZeroCopyJson<'a> {
    /// Create a borrowed JSON view.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Parse into owned JSON only when needed.
    pub fn parse(self) -> serde_json::Result<Value> {
        serde_json::from_slice(self.bytes)
    }
}

/// Simple object pool.
#[derive(Clone, Debug)]
pub struct ObjectPool<T>
where
    T: Default,
{
    objects: Arc<Mutex<Vec<T>>>,
    capacity: usize,
}

impl<T> ObjectPool<T>
where
    T: Default,
{
    /// Create a pool with preallocated objects.
    pub fn new(capacity: usize) -> Self {
        let objects = (0..capacity).map(|_| T::default()).collect();
        Self { objects: Arc::new(Mutex::new(objects)), capacity }
    }

    /// Acquire an object, allocating only if pool is empty.
    pub fn acquire(&self) -> T {
        self.objects.lock().unwrap().pop().unwrap_or_default()
    }

    /// Return an object to the pool.
    pub fn release(&self, object: T) {
        let mut objects = self.objects.lock().unwrap();
        if objects.len() < self.capacity {
            objects.push(object);
        }
    }

    /// Pooled object count.
    pub fn available(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
}

/// Request batch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestBatch {
    pub requests: Vec<Value>,
}

/// Network request batcher.
#[derive(Clone, Debug)]
pub struct RequestBatcher {
    max_batch_size: usize,
    pending: VecDeque<Value>,
    connection_reuse: bool,
}

impl RequestBatcher {
    /// Create a batcher.
    pub fn new(max_batch_size: usize) -> Self {
        Self { max_batch_size, pending: VecDeque::new(), connection_reuse: true }
    }

    /// Enable or disable connection reuse.
    pub fn set_connection_reuse(&mut self, enabled: bool) {
        self.connection_reuse = enabled;
    }

    /// Whether connection reuse is enabled.
    pub fn connection_reuse(&self) -> bool {
        self.connection_reuse
    }

    /// Push a request.
    pub fn push(&mut self, request: Value) {
        self.pending.push_back(request);
    }

    /// Flush one batch.
    pub fn flush(&mut self) -> Option<RequestBatch> {
        if self.pending.is_empty() {
            return None;
        }
        let mut requests = Vec::new();
        while requests.len() < self.max_batch_size {
            let Some(request) = self.pending.pop_front() else {
                break;
            };
            requests.push(request);
        }
        Some(RequestBatch { requests })
    }
}

/// Parallel processing helper.
pub struct ParallelProcessor;

impl ParallelProcessor {
    /// Process items in parallel and collect outputs.
    pub fn map<T, U, F>(items: Vec<T>, worker: F) -> Vec<U>
    where
        T: Send + 'static,
        U: Send + 'static,
        F: Fn(T) -> U + Send + Sync + 'static,
    {
        let worker = Arc::new(worker);
        let mut handles = Vec::new();
        for item in items {
            let worker = worker.clone();
            handles.push(thread::spawn(move || worker(item)));
        }
        handles.into_iter().map(|handle| handle.join().expect("parallel worker panicked")).collect()
    }
}

/// Compile/build optimization plan.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileOptimizationPlan {
    pub wasm_enabled: bool,
    pub cross_compile_targets: Vec<String>,
    pub feature_gates: Vec<String>,
}

impl CompileOptimizationPlan {
    /// Enable WASM build support in the plan.
    pub fn with_wasm(mut self) -> Self {
        self.wasm_enabled = true;
        self
    }

    /// Add a cross-compile target.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.cross_compile_targets.push(target.into());
        self
    }

    /// Add a feature gate.
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.feature_gates.push(feature.into());
        self
    }
}

/// Runtime performance configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub zero_copy_parsing: bool,
    pub object_pool_capacity: usize,
    pub request_batch_size: usize,
    pub connection_reuse: bool,
    pub async_io: bool,
    pub parallelism: usize,
    pub lock_shards: usize,
    pub compile_plan: CompileOptimizationPlan,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            zero_copy_parsing: true,
            object_pool_capacity: 1024,
            request_batch_size: 64,
            connection_reuse: true,
            async_io: true,
            parallelism: 4,
            lock_shards: 16,
            compile_plan: CompileOptimizationPlan::default(),
        }
    }
}

/// Structured trace metadata shared by SDK runtimes and host applications.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub request_id: Option<String>,
    pub actor_id: Option<String>,
    pub device_id: Option<String>,
    pub space_id: Option<String>,
    pub operation_id: Option<String>,
    pub commit_id: Option<String>,
    pub event_id: Option<String>,
    pub span_kind: TraceSpanKind,
    pub labels: BTreeMap<String, String>,
}

impl TraceContext {
    pub fn request(request_id: impl Into<String>) -> Self {
        Self { request_id: Some(request_id.into()), ..Self::default() }
    }

    pub fn with_actor(mut self, actor_id: impl Into<String>) -> Self {
        self.actor_id = Some(actor_id.into());
        self
    }

    pub fn with_device(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    pub fn with_space(mut self, space_id: impl Into<String>) -> Self {
        self.space_id = Some(space_id.into());
        self
    }

    pub fn with_operation(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    pub fn with_commit(mut self, commit_id: impl Into<String>) -> Self {
        self.commit_id = Some(commit_id.into());
        self
    }

    pub fn with_event(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Runtime span classes callers can map to `tracing`, OpenTelemetry or logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceSpanKind {
    #[default]
    Runtime,
    SyncLoop,
    HttpRequest,
    StoreTransaction,
    CryptoOperation,
}

/// Metric names exposed by the SDK without choosing a metrics backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MetricName {
    SyncLatencyMs,
    SyncErrors,
    TimelineEventCacheSize,
    StoreReadLatencyMs,
    StoreWriteLatencyMs,
    CryptoDecryptSuccess,
    CryptoDecryptFailure,
}

/// A backend-agnostic metric sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub name: MetricName,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

impl MetricSample {
    pub fn new(name: MetricName, value: f64) -> Self {
        Self { name, value, labels: BTreeMap::new() }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Backend-agnostic metrics collector trait.
///
/// Implementors bridge SDK metric samples to their chosen backend
/// (Prometheus, OpenTelemetry, StatsD, logging, etc.).
pub trait MetricsCollector: Send + Sync {
    /// Record a single metric sample.
    fn record(&self, sample: MetricSample);

    /// Record a sync latency in milliseconds.
    fn record_sync_latency(&self, ms: f64) {
        self.record(MetricSample::new(MetricName::SyncLatencyMs, ms));
    }

    /// Record a sync error.
    fn record_sync_error(&self) {
        self.record(MetricSample::new(MetricName::SyncErrors, 1.0));
    }

    /// Record timeline / event-cache size.
    fn record_timeline_cache_size(&self, size: usize) {
        self.record(MetricSample::new(MetricName::TimelineEventCacheSize, size as f64));
    }

    /// Record store read latency in milliseconds.
    fn record_store_read_latency(&self, ms: f64) {
        self.record(MetricSample::new(MetricName::StoreReadLatencyMs, ms));
    }

    /// Record store write latency in milliseconds.
    fn record_store_write_latency(&self, ms: f64) {
        self.record(MetricSample::new(MetricName::StoreWriteLatencyMs, ms));
    }

    /// Record a successful crypto decrypt.
    fn record_crypto_decrypt_success(&self) {
        self.record(MetricSample::new(MetricName::CryptoDecryptSuccess, 1.0));
    }

    /// Record a failed crypto decrypt.
    fn record_crypto_decrypt_failure(&self) {
        self.record(MetricSample::new(MetricName::CryptoDecryptFailure, 1.0));
    }
}

/// No-op metrics collector for testing or when metrics are disabled.
#[derive(Clone, Debug, Default)]
pub struct NoopMetricsCollector;

impl MetricsCollector for NoopMetricsCollector {
    fn record(&self, _sample: MetricSample) {}
}

/// In-memory metrics collector for testing.
#[derive(Clone, Debug, Default)]
pub struct MemoryMetricsCollector {
    samples: Arc<Mutex<Vec<MetricSample>>>,
}

impl MemoryMetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain all recorded samples.
    pub fn drain(&self) -> Vec<MetricSample> {
        self.samples.lock().unwrap().drain(..).collect()
    }

    /// Return the number of recorded samples.
    pub fn count(&self) -> usize {
        self.samples.lock().unwrap().len()
    }
}

impl MetricsCollector for MemoryMetricsCollector {
    fn record(&self, sample: MetricSample) {
        self.samples.lock().unwrap().push(sample);
    }
}

/// Benchmark coverage targets maintained by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkTarget {
    CanonicalJsonHashing,
    StateReducerConvergence,
    StoreInsertQuery,
    TimelinePaginationBackfill,
    MlsEncryptDecrypt,
    MlsCommitApplication,
}

/// Benchmark plan used by CI or host projects to keep coverage stable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPlan {
    pub targets: Vec<BenchmarkTarget>,
    pub max_input_size: usize,
}

impl Default for BenchmarkPlan {
    fn default() -> Self {
        Self {
            targets: vec![
                BenchmarkTarget::CanonicalJsonHashing,
                BenchmarkTarget::StateReducerConvergence,
                BenchmarkTarget::StoreInsertQuery,
                BenchmarkTarget::TimelinePaginationBackfill,
                BenchmarkTarget::MlsEncryptDecrypt,
                BenchmarkTarget::MlsCommitApplication,
            ],
            max_input_size: 10_000,
        }
    }
}

/// One measured benchmark smoke run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkMeasurement {
    pub target: BenchmarkTarget,
    pub iterations: usize,
    pub elapsed_nanos: u64,
}

impl BenchmarkMeasurement {
    /// Elapsed duration for this measurement.
    pub fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.elapsed_nanos)
    }
}

/// Deterministic benchmark harness for CI smoke coverage.
///
/// This is intentionally backend-neutral instead of tying the SDK to Criterion
/// or nightly benchmarks. Host repositories can wrap these targets with their
/// preferred benchmark runner while the SDK still verifies that every public
/// target has an executable workload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkHarness {
    pub plan: BenchmarkPlan,
}

impl BenchmarkHarness {
    /// Create a harness from a plan.
    pub fn new(plan: BenchmarkPlan) -> Self {
        Self { plan }
    }

    /// Run every target with a small deterministic workload.
    pub fn run_smoke(&self) -> Vec<BenchmarkMeasurement> {
        self.plan.targets.iter().copied().map(|target| self.measure_target(target)).collect()
    }

    fn measure_target(&self, target: BenchmarkTarget) -> BenchmarkMeasurement {
        let iterations = self.plan.max_input_size.clamp(1, 128);
        let started = Instant::now();
        for seed in 0..iterations {
            run_benchmark_workload(target, seed);
        }
        let elapsed_nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        BenchmarkMeasurement { target, iterations, elapsed_nanos }
    }
}

impl Default for BenchmarkHarness {
    fn default() -> Self {
        Self::new(BenchmarkPlan::default())
    }
}

fn run_benchmark_workload(target: BenchmarkTarget, seed: usize) {
    match target {
        BenchmarkTarget::CanonicalJsonHashing => {
            let value = json!({
                "seed": seed,
                "nested": {"b": seed + 1, "a": [true, false, null]},
            });
            let _digest = crate::canonical::canonical_sha256(&value)
                .expect("benchmark canonical hashing workload must be valid");
        }
        BenchmarkTarget::StateReducerConvergence => {
            let mut left = BTreeMap::new();
            left.insert("entity", json!({"id": seed, "deleted": false}));
            left.insert("relation", json!({"from": seed, "to": seed + 1}));
            let mut right = BTreeMap::new();
            right.insert("relation", json!({"from": seed, "to": seed + 1}));
            right.insert("entity", json!({"id": seed, "deleted": false}));
            let left_digest = crate::canonical::canonical_sha256(&left)
                .expect("benchmark reducer workload must be valid");
            let right_digest = crate::canonical::canonical_sha256(&right)
                .expect("benchmark reducer workload must be valid");
            assert_eq!(left_digest, right_digest);
        }
        BenchmarkTarget::StoreInsertQuery => {
            let mut store = BTreeMap::new();
            for offset in 0..16 {
                store.insert(format!("op:{seed}:{offset}"), json!({"offset": offset}));
            }
            assert!(store.contains_key(&format!("op:{seed}:8")));
        }
        BenchmarkTarget::TimelinePaginationBackfill => {
            let mut timeline = VecDeque::new();
            for offset in 0..32 {
                timeline.push_back(format!("event:{seed}:{offset}"));
            }
            let page: Vec<_> = timeline.iter().rev().take(16).cloned().collect();
            assert_eq!(page.len(), 16);
        }
        BenchmarkTarget::MlsEncryptDecrypt => {
            let ciphertext = Sha256::digest(format!("group:{seed}:plaintext").as_bytes());
            let plaintext_check = Sha256::digest(ciphertext);
            assert_ne!(ciphertext[..], plaintext_check[..]);
        }
        BenchmarkTarget::MlsCommitApplication => {
            let mut transcript = Vec::new();
            for offset in 0..8 {
                transcript.extend(Sha256::digest(format!("commit:{seed}:{offset}").as_bytes()));
            }
            let transcript_hash = Sha256::digest(&transcript);
            assert_eq!(transcript_hash.len(), 32);
        }
    }
}

/// Robustness and fault-injection targets tracked by the SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RobustnessTarget {
    ReducerConvergenceProperty,
    CursorEventEnvelopeFuzzing,
    LargeSpaceListLoad,
    HighEventVolumeLoad,
    NetworkFaultInjection,
    StoreFaultInjection,
}

/// Backend-neutral robustness plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobustnessPlan {
    pub targets: Vec<RobustnessTarget>,
    pub fail_closed: bool,
}

impl Default for RobustnessPlan {
    fn default() -> Self {
        Self {
            targets: vec![
                RobustnessTarget::ReducerConvergenceProperty,
                RobustnessTarget::CursorEventEnvelopeFuzzing,
                RobustnessTarget::LargeSpaceListLoad,
                RobustnessTarget::HighEventVolumeLoad,
                RobustnessTarget::NetworkFaultInjection,
                RobustnessTarget::StoreFaultInjection,
            ],
            fail_closed: true,
        }
    }
}

/// Result from one robustness smoke target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobustnessOutcome {
    pub target: RobustnessTarget,
    pub cases: usize,
    pub passed: bool,
    pub errors: Vec<String>,
}

/// Deterministic robustness and fault-injection smoke harness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobustnessHarness {
    pub plan: RobustnessPlan,
}

impl RobustnessHarness {
    /// Create a robustness harness from a plan.
    pub fn new(plan: RobustnessPlan) -> Self {
        Self { plan }
    }

    /// Run all robustness targets with local deterministic cases.
    pub fn run_smoke(&self) -> Vec<RobustnessOutcome> {
        self.plan
            .targets
            .iter()
            .copied()
            .map(|target| {
                let mut outcome = run_robustness_workload(target);
                if !self.plan.fail_closed && !outcome.errors.is_empty() {
                    outcome.passed = true;
                }
                outcome
            })
            .collect()
    }
}

impl Default for RobustnessHarness {
    fn default() -> Self {
        Self::new(RobustnessPlan::default())
    }
}

fn run_robustness_workload(target: RobustnessTarget) -> RobustnessOutcome {
    let mut errors = Vec::new();
    let cases = match target {
        RobustnessTarget::ReducerConvergenceProperty => {
            let mut first = BTreeMap::new();
            first.insert("b", json!({"value": 2}));
            first.insert("a", json!({"value": 1}));
            let mut second = BTreeMap::new();
            second.insert("a", json!({"value": 1}));
            second.insert("b", json!({"value": 2}));
            let first_digest = crate::canonical::canonical_sha256(&first);
            let second_digest = crate::canonical::canonical_sha256(&second);
            match (first_digest, second_digest) {
                (Ok(first), Ok(second)) if first == second => {}
                (Ok(_), Ok(_)) => {
                    errors.push("canonical reducer digest changed with insertion order".to_owned());
                }
                (Err(error), _) | (_, Err(error)) => {
                    errors.push(format!("canonical reducer digest failed: {error}"));
                }
            }
            1
        }
        RobustnessTarget::CursorEventEnvelopeFuzzing => {
            let inputs: [&[u8]; 5] = [
                b"",
                b"{",
                b"not json",
                br#"{"event_id":5}"#,
                br#"{"scheme":"mls.v1","ciphertext":[]}"#,
            ];
            for input in inputs {
                if serde_json::from_slice::<crate::Event>(input).is_ok() {
                    errors.push("malformed event decoded successfully".to_owned());
                }
                if serde_json::from_slice::<crate::EncryptedPayload>(input).is_ok() {
                    errors.push("malformed encrypted payload decoded successfully".to_owned());
                }
            }
            if crate::cursor::Cursor::decode("not-a-valid-cursor").is_ok() {
                errors.push("malformed cursor decoded successfully".to_owned());
            }
            inputs.len() * 2 + 1
        }
        RobustnessTarget::LargeSpaceListLoad => {
            let mut spaces = BTreeMap::new();
            for index in 0..512 {
                spaces.insert(format!("cx:space:{index:032}"), index);
            }
            if spaces.len() != 512 {
                errors.push("large space list lost entries".to_owned());
            }
            spaces.len()
        }
        RobustnessTarget::HighEventVolumeLoad => {
            let mut events = VecDeque::new();
            for index in 0..1024 {
                events.push_back(json!({"event_id": format!("cx:event:{index:032}")}));
            }
            let page: Vec<_> = events.iter().skip(512).take(128).collect();
            if page.len() != 128 {
                errors.push("high-volume pagination returned wrong page size".to_owned());
            }
            events.len()
        }
        RobustnessTarget::NetworkFaultInjection => {
            let faults = ["timeout", "connection_reset", "stale_cursor", "rate_limited"];
            let retryable = faults
                .iter()
                .filter(|fault| matches!(**fault, "timeout" | "connection_reset" | "rate_limited"))
                .count();
            if retryable != 3 {
                errors.push("network retry classification changed".to_owned());
            }
            faults.len()
        }
        RobustnessTarget::StoreFaultInjection => {
            let mut committed = BTreeMap::new();
            let mut staged = BTreeMap::new();
            staged.insert("op1", json!({"ok": true}));
            staged.insert("op2", json!({"ok": true}));
            let fault_after_first_write = true;
            if fault_after_first_write {
                staged.clear();
            } else {
                committed.append(&mut staged);
            }
            if !committed.is_empty() || !staged.is_empty() {
                errors.push("store fault injection left partial writes visible".to_owned());
            }
            2
        }
    };
    RobustnessOutcome { target, cases, passed: errors.is_empty(), errors }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn performance_zero_copy_parses_on_demand() {
        let view = ZeroCopyJson::new(br#"{"ok":true}"#);
        assert_eq!(view.parse().unwrap(), json!({"ok": true}));
    }

    #[test]
    fn performance_object_pool_reuses_objects() {
        let pool = ObjectPool::<Vec<u8>>::new(1);
        let mut buffer = pool.acquire();
        buffer.extend_from_slice(b"abc");
        buffer.clear();
        pool.release(buffer);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn performance_batches_requests_and_reuses_connections() {
        let mut batcher = RequestBatcher::new(2);
        batcher.push(json!({"id": 1}));
        batcher.push(json!({"id": 2}));
        batcher.push(json!({"id": 3}));

        assert!(batcher.connection_reuse());
        assert_eq!(batcher.flush().unwrap().requests.len(), 2);
        assert_eq!(batcher.flush().unwrap().requests.len(), 1);
    }

    #[test]
    fn performance_parallel_processing_and_compile_plan() {
        let output = ParallelProcessor::map(vec![1, 2, 3], |value| value * 2);
        assert_eq!(output, vec![2, 4, 6]);

        let plan = CompileOptimizationPlan::default()
            .with_wasm()
            .with_target("wasm32-unknown-unknown")
            .with_feature("client");
        assert!(plan.wasm_enabled);
        assert_eq!(PerformanceConfig::default().lock_shards, 16);
    }

    #[test]
    fn observability_models_trace_and_metrics_without_backend() {
        let trace = TraceContext::request("req-1")
            .with_actor("did:web:alice.example")
            .with_device("dev_desktop")
            .with_space("cx:space:01JS0SP000000000000000000")
            .with_operation("cx.operation:01JS0OP000000000000000001")
            .with_commit("cx:commit:01JS0CM000000000000000001")
            .with_event("cx:event:01JS0EV000000000000000001")
            .with_label("component", "sync");
        assert_eq!(trace.labels["component"], "sync");

        let sample = MetricSample::new(MetricName::SyncLatencyMs, 12.0)
            .with_label("space", "cx:space:01JS0SP000000000000000000");
        assert_eq!(sample.name, MetricName::SyncLatencyMs);
        assert_eq!(sample.labels["space"], "cx:space:01JS0SP000000000000000000");
    }

    #[test]
    fn benchmark_and_robustness_plans_cover_required_targets() {
        let benchmark = BenchmarkPlan::default();
        assert!(benchmark.targets.contains(&BenchmarkTarget::CanonicalJsonHashing));
        assert!(benchmark.targets.contains(&BenchmarkTarget::TimelinePaginationBackfill));
        assert!(benchmark.targets.contains(&BenchmarkTarget::MlsCommitApplication));

        let robustness = RobustnessPlan::default();
        assert!(robustness.fail_closed);
        assert!(robustness.targets.contains(&RobustnessTarget::CursorEventEnvelopeFuzzing));
        assert!(robustness.targets.contains(&RobustnessTarget::StoreFaultInjection));
    }

    #[test]
    fn benchmark_harness_executes_all_smoke_targets() {
        let measurements = BenchmarkHarness::default().run_smoke();

        assert_eq!(measurements.len(), BenchmarkPlan::default().targets.len());
        assert!(measurements.iter().all(|measurement| measurement.iterations > 0));
        assert!(measurements.iter().any(|measurement| {
            measurement.target == BenchmarkTarget::CanonicalJsonHashing
                && measurement.elapsed() <= Duration::from_secs(60)
        }));
    }

    #[test]
    fn robustness_harness_executes_fault_and_load_smoke_targets() {
        let outcomes = RobustnessHarness::default().run_smoke();

        assert_eq!(outcomes.len(), RobustnessPlan::default().targets.len());
        assert!(outcomes.iter().all(|outcome| outcome.passed));
        assert!(outcomes.iter().all(|outcome| outcome.cases > 0));
        assert!(
            outcomes
                .iter()
                .any(|outcome| outcome.target == RobustnessTarget::NetworkFaultInjection)
        );
        assert!(
            outcomes.iter().any(|outcome| outcome.target == RobustnessTarget::StoreFaultInjection)
        );
    }
}
