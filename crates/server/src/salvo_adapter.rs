//! Salvo framework adapter for the Contrix server endpoint registry.
//!
//! This module bridges Salvo's request/response types with the framework-independent
//! `HttpAdapterRequest` / `HttpAdapterResponse` types used by the endpoint registry.
//!
//! # Example
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use contrix_server::{
//!     HttpAdapterRequest, HttpAdapterResponse,
//!     salvo_adapter::contrix_handler,
//! };
//!
//! let handler = contrix_handler(|_request: HttpAdapterRequest| {
//!     Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
//! });
//! ```

use std::collections::BTreeMap;

use salvo::{
    Depot, FlowCtrl, Handler, Request, Response, async_trait,
    http::{HeaderName, HeaderValue, Method, StatusCode},
};

use crate::{EndpointMethod, HttpAdapterRequest, HttpAdapterResponse};

/// Convert a Salvo `Request` into a framework-independent `HttpAdapterRequest`.
pub async fn salvo_to_adapter_request(request: &mut Request) -> HttpAdapterRequest {
    let method = match *request.method() {
        Method::GET => EndpointMethod::Get,
        Method::HEAD => EndpointMethod::Head,
        Method::POST => EndpointMethod::Post,
        Method::PUT => EndpointMethod::Put,
        _ => EndpointMethod::Get,
    };

    let path = request.uri().path().to_owned();
    let query: BTreeMap<String, String> = request
        .uri()
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();

    let headers: BTreeMap<String, String> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_owned(), v.to_owned())))
        .collect();

    let body = request.payload().await.map(|bytes| bytes.to_vec()).unwrap_or_default();

    HttpAdapterRequest { method, path, query, headers, body }
}

/// Write a framework-independent `HttpAdapterResponse` into a Salvo `Response`.
pub fn write_adapter_response_to_salvo(
    adapter_response: HttpAdapterResponse,
    response: &mut Response,
) {
    let status =
        StatusCode::from_u16(adapter_response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response.status_code(status);

    for (key, value) in &adapter_response.headers {
        if let (Ok(name), Ok(val)) =
            (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value))
        {
            response.headers_mut().insert(name, val);
        }
    }

    response.body(adapter_response.body);
}

/// Convert a framework-independent `HttpAdapterResponse` into a Salvo `Response`.
pub fn adapter_response_to_salvo(adapter_response: HttpAdapterResponse) -> Response {
    let mut response = Response::new();
    write_adapter_response_to_salvo(adapter_response, &mut response);
    response
}

/// Salvo `Handler` wrapper around a Contrix endpoint service closure.
pub struct ContrixSalvoHandler<F> {
    service: F,
}

impl<F> ContrixSalvoHandler<F> {
    pub fn new(service: F) -> Self {
        Self { service }
    }
}

#[async_trait]
impl<F> Handler for ContrixSalvoHandler<F>
where
    F: Fn(HttpAdapterRequest) -> contrix_core::Result<HttpAdapterResponse> + Send + Sync + 'static,
{
    async fn handle(
        &self,
        request: &mut Request,
        _depot: &mut Depot,
        response: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let adapter_request = salvo_to_adapter_request(request).await;
        let adapter_response = match (self.service)(adapter_request) {
            Ok(response) => response,
            Err(error) => HttpAdapterResponse {
                status: 500,
                headers: BTreeMap::from([(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )]),
                body: serde_json::to_vec(&serde_json::json!({
                    "error": "internal_error",
                    "message": error.to_string(),
                }))
                .unwrap_or_default(),
            },
        };
        write_adapter_response_to_salvo(adapter_response, response);
    }
}

/// Create a Salvo handler that routes through the Contrix endpoint registry.
///
/// The `service` closure receives `HttpAdapterRequest` and returns
/// `HttpAdapterResponse`, matching the `TowerLikeEndpointService` trait.
pub fn contrix_handler<F>(service: F) -> ContrixSalvoHandler<F>
where
    F: Fn(HttpAdapterRequest) -> contrix_core::Result<HttpAdapterResponse> + Send + Sync + 'static,
{
    ContrixSalvoHandler::new(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_response_converts_status_and_headers() {
        let response = HttpAdapterResponse {
            status: 200,
            headers: BTreeMap::from([
                ("content-type".to_owned(), "application/json".to_owned()),
                ("x-request-id".to_owned(), "req-123".to_owned()),
            ]),
            body: br#"{"ok":true}"#.to_vec(),
        };

        let salvo_response = adapter_response_to_salvo(response).into_hyper();
        assert_eq!(salvo_response.status(), StatusCode::OK);
        assert_eq!(salvo_response.headers()["x-request-id"], "req-123");
    }

    #[test]
    fn adapter_response_handles_error_status() {
        let response = HttpAdapterResponse {
            status: 404,
            headers: BTreeMap::new(),
            body: br#"{"error":"not_found"}"#.to_vec(),
        };
        let salvo_response = adapter_response_to_salvo(response).into_hyper();
        assert_eq!(salvo_response.status(), StatusCode::NOT_FOUND);
    }
}
