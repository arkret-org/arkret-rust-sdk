//! Platform embedding and FFI boundary models.
//!
//! The SDK remains a native Rust crate for `0.1.x`. This module records the
//! supported embedding targets and provides backend-neutral shapes that future
//! UniFFI or WASM bindings can map onto without exposing Rust internals.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// Host embedding targets tracked by the SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingTarget {
    /// Native Rust applications and services.
    NativeRust,
    /// Browser and WASM embeddings.
    WasmBrowser,
    /// Swift/Kotlin bindings generated through UniFFI.
    UniffiSwiftKotlin,
}

/// Support level for one embedding target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingSupportLevel {
    /// Supported by the current release train.
    Supported,
    /// Planned after prerequisite runtime work lands.
    Planned,
    /// Deliberately deferred until the public API stabilizes.
    Deferred,
}

/// Versioned support decision for one embedding target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingTargetDecision {
    pub target: EmbeddingTarget,
    pub support: EmbeddingSupportLevel,
    pub milestone: String,
    pub prerequisite: Option<String>,
}

/// Current SDK embedding support decisions.
pub fn embedding_target_decisions() -> Vec<EmbeddingTargetDecision> {
    vec![
        EmbeddingTargetDecision {
            target: EmbeddingTarget::NativeRust,
            support: EmbeddingSupportLevel::Supported,
            milestone: "0.1.x".to_owned(),
            prerequisite: None,
        },
        EmbeddingTargetDecision {
            target: EmbeddingTarget::WasmBrowser,
            support: EmbeddingSupportLevel::Planned,
            milestone: "post-indexeddb-store".to_owned(),
            prerequisite: Some("real IndexedDB repo and crypto stores".to_owned()),
        },
        EmbeddingTargetDecision {
            target: EmbeddingTarget::UniffiSwiftKotlin,
            support: EmbeddingSupportLevel::Deferred,
            milestone: "post-api-stabilization".to_owned(),
            prerequisite: Some("semver-stable public API and callback contract review".to_owned()),
        },
    ]
}

/// Opaque handle families exposed over an FFI boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiHandleKind {
    Client,
    SyncService,
    Timeline,
    Crypto,
}

/// Stable opaque handle suitable for Swift/Kotlin/WASM host maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FfiHandle {
    pub kind: FfiHandleKind,
    pub id: u64,
    pub generation: u64,
}

impl FfiHandle {
    /// Create a non-zero opaque handle.
    pub fn new(kind: FfiHandleKind, id: u64, generation: u64) -> Result<Self> {
        if id == 0 {
            return Err(Error::Protocol("FFI handle id must be non-zero".to_owned()));
        }
        Ok(Self { kind, id, generation })
    }
}

/// Error categories that can cross an FFI boundary without Rust enum layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiErrorCode {
    InvalidId,
    IdempotencyConflict,
    Serialization,
    Crypto,
    Http,
    Mls,
    Api,
    Protocol,
    Cancelled,
}

/// Stable FFI error payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiError {
    pub code: FfiErrorCode,
    pub message: String,
}

impl FfiError {
    /// Build an FFI-safe error from an SDK error.
    pub fn from_error(error: &Error) -> Self {
        let code = match error {
            Error::InvalidId(_) => FfiErrorCode::InvalidId,
            Error::IdempotencyConflict(_) => FfiErrorCode::IdempotencyConflict,
            Error::NonCanonicalNumber | Error::CanonicalJson(_) => FfiErrorCode::Serialization,
            Error::Crypto(_) => FfiErrorCode::Crypto,
            #[cfg(feature = "client")]
            Error::Url(_) | Error::InsecureUrl(_) | Error::Http(_) => FfiErrorCode::Http,
            #[cfg(feature = "mls")]
            Error::Mls(_) => FfiErrorCode::Mls,
            Error::Api { .. } => FfiErrorCode::Api,
            Error::Protocol(_) => FfiErrorCode::Protocol,
        };
        Self { code, message: error.to_string() }
    }

    /// Construct a cancellation error payload.
    pub fn cancelled() -> Self {
        Self { code: FfiErrorCode::Cancelled, message: "operation cancelled".to_owned() }
    }
}

/// Callback result for host event sinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiCallbackAction {
    Continue,
    DropStream,
}

/// Result returned by an event callback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiCallbackResult {
    pub action: FfiCallbackAction,
    pub error: Option<FfiError>,
}

impl FfiCallbackResult {
    /// Continue delivering events.
    pub fn continue_stream() -> Self {
        Self { action: FfiCallbackAction::Continue, error: None }
    }

    /// Drop the event stream, optionally returning an error.
    pub fn drop_stream(error: Option<FfiError>) -> Self {
        Self { action: FfiCallbackAction::DropStream, error }
    }
}

/// Callback-safe event envelope for FFI event streams.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FfiEvent {
    pub stream: FfiHandle,
    pub sequence: u64,
    pub event_type: String,
    pub payload: Value,
}

/// Host event sink contract.
pub trait FfiEventSink: Send + Sync {
    /// Handle one event and tell the SDK whether to continue delivery.
    fn on_event(&self, event: FfiEvent) -> FfiCallbackResult;
}

impl<F> FfiEventSink for F
where
    F: Fn(FfiEvent) -> FfiCallbackResult + Send + Sync,
{
    fn on_event(&self, event: FfiEvent) -> FfiCallbackResult {
        self(event)
    }
}

/// Runtime-neutral cancellation handle for FFI calls.
#[derive(Clone, Debug, Default)]
pub struct FfiCancellationHandle {
    cancelled: Arc<AtomicBool>,
}

impl FfiCancellationHandle {
    /// Create a new cancellation handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Reset the cancellation flag for reuse.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn platform_decisions_document_embedding_targets() {
        let decisions = embedding_target_decisions();

        assert!(decisions.iter().any(|decision| {
            decision.target == EmbeddingTarget::NativeRust
                && decision.support == EmbeddingSupportLevel::Supported
                && decision.milestone == "0.1.x"
        }));
        assert!(decisions.iter().any(|decision| {
            decision.target == EmbeddingTarget::WasmBrowser
                && decision.support == EmbeddingSupportLevel::Planned
        }));
        assert!(decisions.iter().any(|decision| {
            decision.target == EmbeddingTarget::UniffiSwiftKotlin
                && decision.support == EmbeddingSupportLevel::Deferred
        }));
    }

    #[test]
    fn ffi_handles_and_errors_are_stable_shapes() {
        let handle = FfiHandle::new(FfiHandleKind::Client, 7, 1).unwrap();
        assert_eq!(handle.id, 7);
        assert!(FfiHandle::new(FfiHandleKind::Client, 0, 1).is_err());

        let error = FfiError::from_error(&Error::InvalidId("bad".to_owned()));
        assert_eq!(error.code, FfiErrorCode::InvalidId);
        assert!(FfiError::cancelled().message.contains("cancelled"));
    }

    #[test]
    fn ffi_event_sink_and_cancellation_are_callback_safe() {
        let stream = FfiHandle::new(FfiHandleKind::SyncService, 9, 0).unwrap();
        let sink = |event: FfiEvent| {
            assert_eq!(event.stream, stream);
            assert_eq!(event.payload["ok"], true);
            FfiCallbackResult::continue_stream()
        };
        let result = sink.on_event(FfiEvent {
            stream,
            sequence: 1,
            event_type: "sync.update".to_owned(),
            payload: json!({"ok": true}),
        });
        assert_eq!(result.action, FfiCallbackAction::Continue);

        let cancellation = FfiCancellationHandle::new();
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        cancellation.reset();
        assert!(!cancellation.is_cancelled());
    }
}
