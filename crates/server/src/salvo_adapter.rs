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
    Depot, FlowCtrl, Handler, Request, Response, Router, Scribe, async_trait,
    http::{HeaderName, HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    oapi::{
        self, BasicType, Components, Content, EndpointOutRegister, Object, Operation, RefOr,
        Schema, SchemaFormat, ToResponse, ToSchema,
    },
};
use serde::Serialize;

use crate::{
    EndpointContract, EndpointMethod, HttpAdapterRequest, HttpAdapterResponse,
    RoutedEndpointService, dispatch_routed_http_request, endpoint_contracts,
};

/// JSON response wrapper that integrates Salvo writers with OpenAPI schemas.
///
/// `ContrixJson<T>` serializes any `T: Serialize` to `application/json` and
/// registers the schema for `T` in the OpenAPI document via `T: ToSchema`.
/// The default response status is `200`; use [`ContrixJson::status`] to
/// change it for endpoints that return a different code.
pub struct ContrixJson<T> {
    pub value: T,
    pub status: u16,
    pub description: &'static str,
}

impl<T> ContrixJson<T> {
    /// Wrap `value` with the default `200 OK` response metadata.
    pub fn ok(value: T) -> Self {
        Self { value, status: 200, description: "Contrix JSON response" }
    }

    /// Override the documented status code for this response.
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Override the documented response description.
    pub fn description(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }
}

impl<T> From<T> for ContrixJson<T> {
    fn from(value: T) -> Self {
        Self::ok(value)
    }
}

impl<T> Scribe for ContrixJson<T>
where
    T: Serialize + Send,
{
    fn render(self, response: &mut Response) {
        if self.status != 200 {
            // Render path uses raw u16; `from_u16` returns `Result`, fall back to 500.
            if let Ok(code) = StatusCode::from_u16(self.status) {
                response.status_code(code);
            }
        }
        match serde_json::to_vec(&self.value) {
            Ok(bytes) => {
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/json; charset=utf-8"),
                );
                response.write_body(bytes).ok();
            }
            Err(_) => {
                response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                response
                    .write_body(
                        br#"{"errcode":"cx.error.internal","error":"JSON serialization failed"}"#
                            .as_slice(),
                    )
                    .ok();
            }
        }
    }
}

impl<C> ToResponse for ContrixJson<C>
where
    C: ToSchema,
{
    fn to_response(components: &mut Components) -> RefOr<oapi::Response> {
        let schema = <C as ToSchema>::to_schema(components);
        oapi::Response::new("Contrix JSON response")
            .add_content("application/json", Content::new(schema))
            .into()
    }
}

impl<C> EndpointOutRegister for ContrixJson<C>
where
    C: ToSchema,
{
    fn register(components: &mut Components, operation: &mut Operation) {
        operation.responses.insert("200", Self::to_response(components));
    }
}

/// Install the Contrix-preferred OpenAPI naming policy.
///
/// salvo-oapi's default auto-namer produces dotted-module-path component names
/// like `contrix_core.model.ServerDescription`. Contrix exports use bare type
/// names like `ServerDescription` to match the framework-independent endpoint
/// registry strings. Call this once before building components if you want the
/// bare names; [`contrix_oapi_components`] does this automatically.
///
/// Note: salvo-oapi's namer is process-global state. Calling this after other
/// crates have already registered schemas may collide.
pub fn install_contrix_oapi_namer() {
    use salvo::oapi::naming::{FlexNamer, set_namer};
    set_namer(FlexNamer::new().short_mode(true).generic_delimiter('_', '_'));
}

/// Build Salvo OpenAPI components populated with all Contrix protocol schemas.
pub fn contrix_oapi_components() -> Components {
    install_contrix_oapi_namer();
    let mut components = Components::new();
    register_contrix_oapi_components(&mut components);
    components
}

/// Register all Contrix protocol schemas into the given `Components`.
///
/// This walks every wire-relevant Rust model (`contrix-core` model, sync, and
/// service types) and invokes `<T as ToSchema>::to_schema(components)`. The
/// salvo-oapi macros recursively register dependent component schemas as a
/// side effect, so this function is the single entry point a caller needs.
///
/// In addition, synthetic component names referenced by the framework-
/// independent endpoint registry (path/query parameter bundles, opaque blob
/// bodies, JSON extension points) are registered as plain object schemas so
/// they can be `$ref`-ed safely from generated path documents.
pub fn register_contrix_oapi_components(components: &mut Components) {
    register_typed_schemas(components);
    register_synthetic_schemas(components);
}

/// Register every Rust protocol type that appears as a wire root in the
/// endpoint registry. Dependent schemas are registered transitively by the
/// salvo-oapi macros.
fn register_typed_schemas(components: &mut Components) {
    use contrix_core::*;

    macro_rules! register {
        ($($ty:ty),+ $(,)?) => {
            $( <$ty as ToSchema>::to_schema(components); )+
        };
    }

    register!(
        // Service / metadata helpers
        ApiConventionMetadata,
        HttpTraceMetadata,
        QuotaMetadata,
        RateLimitMetadata,
        ServiceDidAllowlist,
        ServiceEndpointBinding,
        // Sync types
        SyncRequest,
        SyncResponse,
        BackfillRequest,
        BackfillResponse,
        // Core wire types reachable from one or more endpoints
        AppletActorResponse,
        AppletDescription,
        AppletPingResponse,
        AppletProtocolResponse,
        AppletSpaceResponse,
        AppletTransactionRequest,
        AppletTransactionResponse,
        AuthzCheckRequest,
        AuthzCheckResponse,
        AuthzInvitesResponse,
        BlobUploadMetadata,
        BlobUploadResponse,
        Commit,
        DeviceMessagesReceiveResponse,
        DeviceMessagesSendRequest,
        DeviceMessagesSendResponse,
        DirectoryDescription,
        DirectoryResolveHandleRequest,
        DirectoryResolveHandleResponse,
        DirectoryResolveOrganizationRequest,
        DirectoryResolveOrganizationResponse,
        DirectoryResolveSpaceRequest,
        DirectoryResolveSpaceResponse,
        DirectorySearchActorsRequest,
        DirectorySearchActorsResponse,
        DirectorySearchOrganizationsRequest,
        DirectorySearchOrganizationsResponse,
        DirectorySearchSpacesRequest,
        DirectorySearchSpacesResponse,
        DirectorySearchUsersResponse,
        EffectiveGrantsResponse,
        ErrorEnvelope,
        FederationPullOperationsResponse,
        FederationPushOperationsRequest,
        FederationPushOperationsResponse,
        FederationSpaceMembersResponse,
        FederationTransactionRequest,
        FederationTransactionResponse,
        FederationVerifyActorRequest,
        FederationVerifyActorResponse,
        IdentityDescription,
        IdentityDocumentResponse,
        IdentityLogResponse,
        IdentityReceiptsResponse,
        IdentityResolveRequest,
        IdentityResolveResponse,
        IndexDescription,
        IndexEntityResponse,
        IndexInboxResponse,
        IndexNotificationsResponse,
        IndexSearchRequest,
        IndexSearchResponse,
        IndexSpaceHierarchyResponse,
        IndexThreadResponse,
        KeysClaimRequest,
        KeysClaimResponse,
        KeysQueryRequest,
        KeysQueryResponse,
        KeysUploadRequest,
        KeysUploadResponse,
        MediaIceConfigRequest,
        MediaIceConfigResponse,
        ModerationReportRequest,
        ModerationReportResponse,
        OkResponse,
        PolicyCheckRequest,
        PolicyCheckResponse,
        PushNotifyRequest,
        PushNotifyResponse,
        PushRegisterDeviceRequest,
        PushRegisterDeviceResponse,
        PushUnregisterDeviceRequest,
        QueryRequest,
        ServerDescription,
        SubmitDidOperationRequest,
        SubmitDidOperationResponse,
        SyncBackfillResponse,
        SyncDescription,
        SyncSnapshotHeadResponse,
        SyncSubscribeFrame,
    );
}

/// Register synthetic component schemas for endpoint path/query bundles that
/// don't have a dedicated Rust type but are referenced by name from the
/// framework-independent endpoint registry.
fn register_synthetic_schemas(components: &mut Components) {
    const SYNTHETIC_OBJECT_NAMES: &[&str] = &[
        "AccountDevicePairRequest",
        "AccountDevicePairResponse",
        "AccountOidcCallbackRequest",
        "AccountOidcCallbackResponse",
        "AccountSessionGrantRequest",
        "AccountSessionGrantResponse",
        "AdminAccountStatusRequest",
        "AdminModerationQueueQuery",
        "AdminRevokeDeviceRequest",
        "AdminServerStatusQuery",
        "AppletActorPath",
        "AppletDescribeRequest",
        "AppletPingRequest",
        "AppletProtocolPath",
        "AppletSpacePath",
        "AppletThirdPartyLocationsRequest",
        "AppletThirdPartyUsersRequest",
        "AuthzEffectiveGrantsQuery",
        "AuthzInvitesQuery",
        "BlobGetQuery",
        "BlobMetadataHeaders",
        "DeviceMessagesGetQuery",
        "DirectoryDescribeRequest",
        "DirectorySearchUsersQuery",
        "FederationPullOperationsQuery",
        "FederationSpaceMembersQuery",
        "IdentityDescribeRequest",
        "IdentityDocumentQuery",
        "IdentityLogQuery",
        "IdentityReceiptsQuery",
        "IndexDescribeRequest",
        "IndexEntityQuery",
        "IndexInboxQuery",
        "IndexNotificationsQuery",
        "IndexSpaceHierarchyQuery",
        "IndexThreadQuery",
        "KeyPackagesClaimRequest",
        "KeyPackagesClaimResponse",
        "KeyPackagesConsumeRequest",
        "KeyPackagesRevokeRequest",
        "KeyPackagesUploadRequest",
        "MimiConsentRequest",
        "MimiConsentUpdateRequest",
        "MimiFlowUpdateRequest",
        "MimiGroupInfoQuery",
        "MimiIdentifierQueryRequest",
        "MimiKeyMaterialRequest",
        "MimiNotifyRequest",
        "MimiProviderDirectoryRequest",
        "MimiProxyDownloadRequest",
        "MimiReportAbuseRequest",
        "MimiSubmitMessageRequest",
        "PrivateContactDiscoveryRequest",
        "PrivateContactDiscoveryResponse",
        "RepoCommitQuery",
        "RepoCommitsQuery",
        "RepoDescribeQuery",
        "ServerDescribeRequest",
        "SyncBackfillQuery",
        "SyncDescribeRequest",
        "SyncSnapshotHeadQuery",
        "SyncSubscribeQuery",
    ];

    for name in SYNTHETIC_OBJECT_NAMES {
        if !components.schemas.contains_key(*name) {
            let schema: RefOr<Schema> = Object::new()
                .schema_type(BasicType::Object)
                .description(format!(
                    "Contrix synthetic OpenAPI component {name}. \
                     Concrete validation lives in the endpoint contract."
                ))
                .into();
            components.schemas.insert((*name).to_owned(), schema);
        }
    }

    // Opaque binary blob body
    if !components.schemas.contains_key("BinaryBlobBody") {
        let schema: RefOr<Schema> = Object::new()
            .schema_type(BasicType::String)
            .format(SchemaFormat::KnownFormat(oapi::KnownFormat::Binary))
            .description("Raw blob payload returned by `cx.blob.get`.")
            .into();
        components.schemas.insert("BinaryBlobBody".to_owned(), schema);
    }

    // Permissive JSON extension carrier used by Mimi/admin endpoints.
    if !components.schemas.contains_key("JsonValue") {
        let mut obj = Object::new();
        obj.schema_type = oapi::SchemaType::AnyValue;
        obj.description =
            Some("Arbitrary JSON value accepted by Contrix extension points.".to_owned());
        let schema: RefOr<Schema> = Schema::Object(Box::new(obj)).into();
        components.schemas.insert("JsonValue".to_owned(), schema);
    }
}

/// Build a Salvo-native [`oapi::OpenApi`] document seeded with all Contrix
/// component schemas. Path documentation can be appended by combining this
/// model with Salvo's `#[salvo::oapi::endpoint]` handlers.
pub fn contrix_openapi() -> oapi::OpenApi {
    let mut openapi = oapi::OpenApi::new("Contrix v1 Service HTTP Binding", "1.0");
    openapi.components = contrix_oapi_components();
    openapi
}

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
        assert!(debug.contains("api/v1/applet/transactions"));
        assert!(debug.contains("[POST]"));
        assert!(debug.contains("{**contrix_rest}"));
    }

    #[test]
    fn salvo_path_patterns_are_relative_to_router_root() {
        assert_eq!(salvo_path_pattern("/api/v1/server/describe"), "api/v1/server/describe");
    }

    #[test]
    fn oapi_components_register_endpoint_schema_names() {
        let components = contrix_oapi_components();

        // Confirm typed schemas are registered with their short, bare-type names
        // (not the salvo default dotted module path).
        let has = |k: &str| components.schemas.contains_key(k);
        assert!(has("ServerDescription"));
        assert!(has("SyncRequest"));
        assert!(has("ErrorEnvelope"));

        // The schema must contain real properties — not just an opaque object.
        let server_description =
            components.schemas.get("ServerDescription").expect("ServerDescription registered");
        let value = serde_json::to_value(server_description).unwrap();
        assert!(
            value.get("properties").is_some()
                || value.get("$ref").and_then(|r| r.as_str()).is_some(),
            "ServerDescription schema should have properties or be a Ref, got {value:#?}"
        );
    }

    #[test]
    fn salvo_openapi_registers_contrix_components() {
        let openapi = contrix_openapi();
        let value = serde_json::to_value(openapi).unwrap();

        assert_eq!(value["openapi"], "3.1.0");
        assert!(value["components"]["schemas"]["ErrorEnvelope"].is_object());
        assert!(value["components"]["schemas"]["ServerDescription"].is_object());
    }
}
