//! Performance-oriented helpers for pooling, batching and build planning.

use std::{
    collections::BTreeMap,
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}
