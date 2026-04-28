//! Performance-oriented helpers for pooling, batching and build planning.

use std::{
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
}
