//! Platform embedding and FFI boundary models.
//!
//! This module keeps only runtime-facing contracts that browser or host
//! integrations can implement directly: HTTP transport, IndexedDB-like durable
//! storage descriptors, WebCrypto key handles and opaque FFI callback shapes.

// Runtime and host-boundary contracts are owned by `arkret-ffi`. Re-exporting
// the types here keeps one Rust type and one serde shape across SDK and FFI
// consumers.
pub use arkret_ffi::{
    FfiCallbackAction, FfiCallbackResult, FfiCancellationHandle, FfiError, FfiErrorCode, FfiEvent,
    FfiEventSink, FfiHandle, FfiHandleKind, IndexedDbStoreDescriptor, IndexedDbStoreKind,
    WasmBrowserHttpTransport, WasmHttpRequestBody, WasmHttpResponseBody, WasmRuntimeContract,
    WebCryptoKeyHandle, WebCryptoOperation,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::Error;

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
            event_kind: "ak.self.account.stream.subscribe".to_owned(),
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

        let transport = |request: WasmHttpRequestBody| {
            request.validate()?;
            Ok(WasmHttpResponseBody {
                status: 200,
                headers: BTreeMap::from([(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )]),
                body: br#"{"ok":true}"#.to_vec(),
            })
        };
        let response = transport
            .send_wasm_http(WasmHttpRequestBody {
                method: "POST".to_owned(),
                url: "https://sync.example/_arkret/self/account/subscribe".to_owned(),
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
