//! Platform embedding and FFI boundary models.
//!
//! This module keeps only runtime-facing contracts that browser or host
//! integrations can implement directly: HTTP transport, IndexedDB-like durable
//! storage descriptors, WebCrypto key handles and opaque FFI callback shapes.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// Browser HTTP request shape for WASM transports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHttpReqBody {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl WasmHttpReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.method.trim().is_empty() {
            return Err(Error::Protocol("WASM HTTP method must not be empty".to_owned()));
        }
        if !(self.url.starts_with("https://") || self.url.starts_with("http://localhost")) {
            return Err(Error::Protocol("WASM HTTP URL must be HTTPS or localhost".to_owned()));
        }
        Ok(())
    }
}

/// Browser HTTP response shape returned by WASM transports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHttpOutput {
    pub status: u16,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Host-provided browser transport boundary.
pub trait WasmBrowserHttpTransport {
    fn send_wasm_http(&self, request: WasmHttpReqBody) -> Result<WasmHttpOutput>;
}

impl<F> WasmBrowserHttpTransport for F
where
    F: Fn(WasmHttpReqBody) -> Result<WasmHttpOutput>,
{
    fn send_wasm_http(&self, request: WasmHttpReqBody) -> Result<WasmHttpOutput> {
        self(request)
    }
}

/// IndexedDB store role tracked by WASM embeddings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedDbStoreKind {
    State,
    Crypto,
}

/// IndexedDB database/object-store contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedDbStoreDescriptor {
    pub kind: IndexedDbStoreKind,
    pub database: String,
    pub object_store: String,
    pub schema_version: u32,
    pub quota_bytes: Option<u64>,
}

impl IndexedDbStoreDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.database.trim().is_empty() || self.object_store.trim().is_empty() {
            return Err(Error::Protocol("IndexedDB names must not be empty".to_owned()));
        }
        if self.schema_version == 0 {
            return Err(Error::Protocol("IndexedDB schema version must be non-zero".to_owned()));
        }
        Ok(())
    }
}

/// WebCrypto operation requested by WASM crypto-store adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebCryptoOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    DeriveBits,
}

/// WebCrypto key boundary; browser key material stays outside Rust memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCryptoKeyHandle {
    pub key_id: String,
    pub algorithm: String,
    pub extractable: bool,
    pub usages: Vec<WebCryptoOperation>,
}

impl WebCryptoKeyHandle {
    pub fn validate(&self) -> Result<()> {
        if self.key_id.trim().is_empty() || self.algorithm.trim().is_empty() {
            return Err(Error::Protocol("WebCrypto key id and algorithm are required".to_owned()));
        }
        if self.usages.is_empty() {
            return Err(Error::Protocol("WebCrypto key usages must not be empty".to_owned()));
        }
        Ok(())
    }
}

/// WASM runtime contract bundle used by app and browser tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeContract {
    pub http_transport: bool,
    pub state_store: IndexedDbStoreDescriptor,
    pub crypto_store: IndexedDbStoreDescriptor,
    pub webcrypto_key: WebCryptoKeyHandle,
    pub sync_state_cache: String,
}

impl Default for WasmRuntimeContract {
    fn default() -> Self {
        Self {
            http_transport: true,
            state_store: IndexedDbStoreDescriptor {
                kind: IndexedDbStoreKind::State,
                database: "contrix-state".to_owned(),
                object_store: "records".to_owned(),
                schema_version: 1,
                quota_bytes: Some(64 * 1024 * 1024),
            },
            crypto_store: IndexedDbStoreDescriptor {
                kind: IndexedDbStoreKind::Crypto,
                database: "contrix-crypto".to_owned(),
                object_store: "records".to_owned(),
                schema_version: 1,
                quota_bytes: Some(16 * 1024 * 1024),
            },
            webcrypto_key: WebCryptoKeyHandle {
                key_id: "contrix-webcrypto-root".to_owned(),
                algorithm: "AES-GCM".to_owned(),
                extractable: false,
                usages: vec![WebCryptoOperation::Encrypt, WebCryptoOperation::Decrypt],
            },
            sync_state_cache: "contrix-sync-state".to_owned(),
        }
    }
}

impl WasmRuntimeContract {
    pub fn validate(&self) -> Result<()> {
        if !self.http_transport {
            return Err(Error::Protocol("WASM browser HTTP transport is required".to_owned()));
        }
        self.state_store.validate()?;
        self.crypto_store.validate()?;
        if self.state_store.kind != IndexedDbStoreKind::State {
            return Err(Error::Protocol("WASM state store descriptor has wrong kind".to_owned()));
        }
        if self.crypto_store.kind != IndexedDbStoreKind::Crypto {
            return Err(Error::Protocol("WASM crypto store descriptor has wrong kind".to_owned()));
        }
        self.webcrypto_key.validate()?;
        if self.sync_state_cache.trim().is_empty() {
            return Err(Error::Protocol("WASM sync state cache name must not be empty".to_owned()));
        }
        Ok(())
    }
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
    pub event_kind: String,
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
            event_kind: "cx.sync.account".to_owned(),
            payload: json!({"ok": true}),
        });
        assert_eq!(result.action, FfiCallbackAction::Continue);

        let cancellation = FfiCancellationHandle::new();
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        cancellation.reset();
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    fn wasm_runtime_contract_covers_browser_http_indexeddb_webcrypto_and_sync_cache() {
        let contract = WasmRuntimeContract::default();
        contract.validate().unwrap();
        assert_eq!(contract.state_store.kind, IndexedDbStoreKind::State);
        assert_eq!(contract.crypto_store.kind, IndexedDbStoreKind::Crypto);
        assert!(!contract.webcrypto_key.extractable);

        let transport = |request: WasmHttpReqBody| {
            request.validate()?;
            Ok(WasmHttpOutput {
                status: 200,
                headers: BTreeMap::from([(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )]),
                body: br#"{"ok":true}"#.to_vec(),
            })
        };
        let response = transport
            .send_wasm_http(WasmHttpReqBody {
                method: "POST".to_owned(),
                url: "https://sync.example/contrix/v1/sync".to_owned(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            })
            .unwrap();
        assert_eq!(response.status, 200);

        let mut invalid = contract;
        invalid.crypto_store.kind = IndexedDbStoreKind::State;
        assert!(invalid.validate().is_err());
    }
}
