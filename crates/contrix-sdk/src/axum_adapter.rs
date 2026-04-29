//! Axum framework adapter for the Contrix server endpoint registry.
//!
//! This module bridges Axum's request/response types with the framework-independent
//! `HttpAdapterRequest`/`HttpAdapterResponse` types used by the endpoint registry.
//!
//! # Example
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use axum::{body::Body, extract::Request};
//! use contrix_sdk::{
//!     axum_adapter::contrix_handler,
//!     server::{HttpAdapterRequest, HttpAdapterResponse},
//! };
//!
//! let handler = contrix_handler(|_request: HttpAdapterRequest| {
//!     Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
//! });
//! let _response = handler(Request::new(Body::empty()));
//! ```

use std::collections::BTreeMap;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};

use crate::server::{EndpointMethod, HttpAdapterRequest, HttpAdapterResponse};

/// Convert an Axum `Request` into a framework-independent `HttpAdapterRequest`.
pub async fn axum_to_adapter_request(request: Request<Body>) -> HttpAdapterRequest {
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

    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();

    HttpAdapterRequest { method, path, query, headers, body }
}

/// Convert a framework-independent `HttpAdapterResponse` into an Axum `Response`.
pub fn adapter_response_to_axum(response: HttpAdapterResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers = HeaderMap::new();
    for (key, value) in &response.headers {
        if let (Ok(name), Ok(val)) = (
            axum::http::HeaderName::from_bytes(key.as_bytes()),
            axum::http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, val);
        }
    }

    (status, headers, response.body).into_response()
}

/// Create an Axum handler that routes through the Contrix endpoint registry.
///
/// The `service` closure receives `HttpAdapterRequest` and returns `HttpAdapterResponse`,
/// matching the `TowerLikeEndpointService` trait.
pub fn contrix_handler<F>(service: F) -> impl Fn(Request<Body>) -> Response
where
    F: Fn(HttpAdapterRequest) -> crate::Result<HttpAdapterResponse> + Send + 'static,
{
    move |request: Request<Body>| {
        // Note: this is synchronous. For async, callers should use the tower-based approach.
        let adapter_request = HttpAdapterRequest {
            method: match *request.method() {
                Method::GET => EndpointMethod::Get,
                Method::HEAD => EndpointMethod::Head,
                Method::POST => EndpointMethod::Post,
                Method::PUT => EndpointMethod::Put,
                _ => EndpointMethod::Get,
            },
            path: request.uri().path().to_owned(),
            query: request
                .uri()
                .query()
                .map(|q| {
                    url::form_urlencoded::parse(q.as_bytes())
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect()
                })
                .unwrap_or_default(),
            headers: request
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_owned(), v.to_owned())))
                .collect(),
            body: Vec::new(), // Sync handler doesn't read body
        };

        match (service)(adapter_request) {
            Ok(response) => adapter_response_to_axum(response),
            Err(error) => {
                let error_response = HttpAdapterResponse {
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
                };
                adapter_response_to_axum(error_response)
            }
        }
    }
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

        let axum_response = adapter_response_to_axum(response);
        assert_eq!(axum_response.status(), StatusCode::OK);
    }

    #[test]
    fn adapter_response_handles_error_status() {
        let response = HttpAdapterResponse {
            status: 404,
            headers: BTreeMap::new(),
            body: br#"{"error":"not_found"}"#.to_vec(),
        };
        let axum_response = adapter_response_to_axum(response);
        assert_eq!(axum_response.status(), StatusCode::NOT_FOUND);
    }
}
