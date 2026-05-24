//! FFI and WASM runtime contracts.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use contrix_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiHandleKind {
    Client,
    SyncService,
    Timeline,
    CryptoMachine,
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FfiHandle {
    pub kind: FfiHandleKind,
    pub id: u64,
    pub generation: u64,
}

impl FfiHandle {
    pub fn new(kind: FfiHandleKind, id: u64, generation: u64) -> Result<Self> {
        if id == 0 {
            return Err(Error::Protocol("FFI handle id must be non-zero".to_owned()));
        }
        Ok(Self { kind, id, generation })
    }
}

#[derive(Clone, Debug)]
pub struct FfiHandleTable<T> {
    kind: FfiHandleKind,
    next_id: u64,
    generation: u64,
    entries: BTreeMap<u64, T>,
}

impl<T> FfiHandleTable<T> {
    pub fn new(kind: FfiHandleKind) -> Self {
        Self { kind, next_id: 1, generation: 1, entries: BTreeMap::new() }
    }

    pub fn insert(&mut self, value: T) -> FfiHandle {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(id, value);
        FfiHandle { kind: self.kind, id, generation: self.generation }
    }

    pub fn get(&self, handle: FfiHandle) -> Result<&T> {
        self.validate_handle(handle)?;
        self.entries
            .get(&handle.id)
            .ok_or_else(|| Error::Protocol("FFI handle is not registered".to_owned()))
    }

    pub fn remove(&mut self, handle: FfiHandle) -> Result<T> {
        self.validate_handle(handle)?;
        self.entries
            .remove(&handle.id)
            .ok_or_else(|| Error::Protocol("FFI handle is not registered".to_owned()))
    }

    fn validate_handle(&self, handle: FfiHandle) -> Result<()> {
        if handle.kind != self.kind || handle.generation != self.generation || handle.id == 0 {
            return Err(Error::Protocol("FFI handle does not belong to this table".to_owned()));
        }
        Ok(())
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiError {
    pub code: FfiErrorCode,
    pub message: String,
}

impl FfiError {
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
            #[allow(unreachable_patterns)]
            _ => FfiErrorCode::Protocol,
        };
        Self { code, message: error.to_string() }
    }

    pub fn cancelled() -> Self {
        Self { code: FfiErrorCode::Cancelled, message: "operation cancelled".to_owned() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiCallbackAction {
    Continue,
    DropStream,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiCallbackResult {
    pub action: FfiCallbackAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FfiError>,
}

impl FfiCallbackResult {
    pub fn continue_stream() -> Self {
        Self { action: FfiCallbackAction::Continue, error: None }
    }

    pub fn drop_stream(error: Option<FfiError>) -> Self {
        Self { action: FfiCallbackAction::DropStream, error }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FfiEvent {
    pub stream: FfiHandle,
    pub sequence: u64,
    pub event_kind: String,
    pub payload: Value,
}

pub trait FfiEventSink {
    fn emit(&self, event: FfiEvent) -> FfiCallbackResult;
}

impl<F> FfiEventSink for F
where
    F: Fn(FfiEvent) -> FfiCallbackResult,
{
    fn emit(&self, event: FfiEvent) -> FfiCallbackResult {
        self(event)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FfiCancellationHandle {
    cancelled: Arc<AtomicBool>,
}

impl FfiCancellationHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> std::result::Result<(), FfiError> {
        if self.is_cancelled() { Err(FfiError::cancelled()) } else { Ok(()) }
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHttpResBody {
    pub status: u16,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub trait WasmBrowserHttpTransport {
    fn send_wasm_http(&self, request: WasmHttpReqBody) -> Result<WasmHttpResBody>;
}

impl<F> WasmBrowserHttpTransport for F
where
    F: Fn(WasmHttpReqBody) -> Result<WasmHttpResBody>,
{
    fn send_wasm_http(&self, request: WasmHttpReqBody) -> Result<WasmHttpResBody> {
        self(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedDbStoreKind {
    State,
    Crypto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedDbStoreDescriptor {
    pub kind: IndexedDbStoreKind,
    pub database: String,
    pub object_store: String,
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebCryptoOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    DeriveBits,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_table_rejects_wrong_kind_and_removed_handles() {
        let mut table = FfiHandleTable::new(FfiHandleKind::Client);
        let handle = table.insert("client");
        assert_eq!(table.get(handle).unwrap(), &"client");
        assert!(matches!(
            table.get(FfiHandle { kind: FfiHandleKind::Store, ..handle }),
            Err(Error::Protocol(_))
        ));
        assert_eq!(table.remove(handle).unwrap(), "client");
        assert!(matches!(table.get(handle), Err(Error::Protocol(_))));
    }

    #[test]
    fn wasm_runtime_contract_validates_store_and_webcrypto_boundary() {
        WasmRuntimeContract::default().validate().unwrap();
        let mut invalid = WasmRuntimeContract::default();
        invalid.state_store.kind = IndexedDbStoreKind::Crypto;
        assert!(matches!(invalid.validate(), Err(Error::Protocol(_))));
    }

    #[test]
    fn callback_and_cancellation_shapes_are_ffi_safe() {
        let handle = FfiHandle::new(FfiHandleKind::SyncService, 1, 1).unwrap();
        let sink = |event: FfiEvent| {
            assert_eq!(event.stream, handle);
            FfiCallbackResult::continue_stream()
        };
        assert_eq!(
            sink.emit(FfiEvent {
                stream: handle,
                sequence: 1,
                event_kind: "cx.account.subscribe".to_owned(),
                payload: Value::Null,
            }),
            FfiCallbackResult::continue_stream()
        );

        let cancellation = FfiCancellationHandle::default();
        assert!(cancellation.check().is_ok());
        cancellation.cancel();
        assert_eq!(cancellation.check().unwrap_err().code, FfiErrorCode::Cancelled);
    }
}
