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
//!     HttpAdapterResponse, RoutedHttpAdapterRequest,
//!     salvo_adapter::contrix_router,
//! };
//!
//! let router = contrix_router(|_request: RoutedHttpAdapterRequest| {
//!     Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
//! });
//! ```

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use salvo::{
    Depot, FlowCtrl, Handler, Request, Response, Router, async_trait,
    http::{HeaderName, HeaderValue, Method, StatusCode},
};

use crate::{
    EndpointContract, EndpointMethod, HttpAdapterRequest, HttpAdapterResponse,
    RoutedEndpointService, dispatch_routed_http_request, endpoint_contracts,
};

/// Convert a Salvo `Request` into a framework-independent `HttpAdapterRequest`.
pub async fn salvo_to_adapter_request(
    request: &mut Request,
) -> Result<HttpAdapterRequest, HttpAdapterResponse> {
    let method = match *request.method() {
        Method::GET => EndpointMethod::Get,
        Method::HEAD => EndpointMethod::Head,
        Method::POST => EndpointMethod::Post,
        Method::PUT => EndpointMethod::Put,
        _ => {
            return Err(salvo_adapter_error_response(
                405,
                "cx.error.method_not_allowed",
                "Unsupported Contrix endpoint method",
            ));
        }
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

    Ok(HttpAdapterRequest { method, path, query, headers, body })
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

fn salvo_adapter_error_response(
    status: u16,
    errcode: impl Into<String>,
    error: impl Into<String>,
) -> HttpAdapterResponse {
    HttpAdapterResponse {
        status,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(&serde_json::json!({
            "errcode": errcode.into(),
            "error": error.into(),
        }))
        .unwrap_or_default(),
    }
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
        let adapter_request = match salvo_to_adapter_request(request).await {
            Ok(request) => request,
            Err(response_body) => {
                write_adapter_response_to_salvo(response_body, response);
                return;
            }
        };
        let adapter_response = match (self.service)(adapter_request) {
            Ok(response) => response,
            Err(error) => salvo_adapter_error_response(500, "cx.error.internal", error.to_string()),
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

/// Salvo `Handler` wrapper that dispatches through the Contrix endpoint registry.
pub struct ContrixRoutedSalvoHandler<S> {
    service: Arc<Mutex<S>>,
}

impl<S> Clone for ContrixRoutedSalvoHandler<S> {
    fn clone(&self) -> Self {
        Self { service: Arc::clone(&self.service) }
    }
}

impl<S> ContrixRoutedSalvoHandler<S> {
    pub fn new(service: S) -> Self {
        Self { service: Arc::new(Mutex::new(service)) }
    }
}

#[async_trait]
impl<S> Handler for ContrixRoutedSalvoHandler<S>
where
    S: RoutedEndpointService + Send + 'static,
{
    async fn handle(
        &self,
        request: &mut Request,
        _depot: &mut Depot,
        response: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let adapter_request = match salvo_to_adapter_request(request).await {
            Ok(request) => request,
            Err(response_body) => {
                write_adapter_response_to_salvo(response_body, response);
                return;
            }
        };

        let adapter_response = match self.service.lock() {
            Ok(mut service) => dispatch_routed_http_request(&mut *service, adapter_request),
            Err(_) => salvo_adapter_error_response(
                500,
                "cx.error.internal",
                "Contrix endpoint service lock poisoned",
            ),
        };
        write_adapter_response_to_salvo(adapter_response, response);
    }
}

/// Create a Salvo handler that matches routes through the Contrix endpoint registry.
pub fn contrix_routed_handler<S>(service: S) -> ContrixRoutedSalvoHandler<S>
where
    S: RoutedEndpointService + Send + 'static,
{
    ContrixRoutedSalvoHandler::new(service)
}

/// Build a Salvo `Router` for every registered Contrix endpoint.
///
/// The generated router adds a catch-all route after the explicit endpoint
/// routes, so unknown Contrix paths still return the SDK's standard error
/// envelope instead of a framework-specific 404 body.
pub fn contrix_router<S>(service: S) -> Router
where
    S: RoutedEndpointService + Send + 'static,
{
    let handler = contrix_routed_handler(service);
    let mut router = endpoint_contracts().iter().fold(Router::new(), |router, endpoint| {
        router.push(salvo_route_for_endpoint(endpoint, handler.clone()))
    });
    router = router.push(Router::with_path("{**contrix_rest}").goal(handler));
    router
}

fn salvo_route_for_endpoint<S>(
    endpoint: &EndpointContract,
    handler: ContrixRoutedSalvoHandler<S>,
) -> Router
where
    S: RoutedEndpointService + Send + 'static,
{
    let route = Router::with_path(salvo_path_pattern(endpoint.path));
    match endpoint.method {
        EndpointMethod::Get => route.get(handler),
        EndpointMethod::Head => route.head(handler),
        EndpointMethod::Post => route.post(handler),
        EndpointMethod::Put => route.put(handler),
    }
}

fn salvo_path_pattern(path: &str) -> String {
    path.trim_start_matches('/').to_owned()
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

    #[test]
    fn contrix_router_registers_endpoint_registry_routes() {
        let router = contrix_router(|_request| {
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        });

        assert_eq!(router.routers().len(), endpoint_contracts().len() + 1);
        let debug = format!("{router:?}");
        assert!(debug.contains("api/v1/server/describe"));
        assert!(debug.contains("[GET]"));
        assert!(debug.contains("api/v1/applet/transactions/{txn_id}"));
        assert!(debug.contains("[PUT]"));
        assert!(debug.contains("{**contrix_rest}"));
    }

    #[test]
    fn salvo_path_patterns_are_relative_to_router_root() {
        assert_eq!(salvo_path_pattern("/api/v1/server/describe"), "api/v1/server/describe");
    }
}
