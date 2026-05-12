use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMiddlewareConfig {
    pub require_authentication: bool,
    pub public_operations: BTreeSet<String>,
    pub require_idempotency_key_for_mutations: bool,
    pub enable_idempotency: bool,
    pub enable_rate_limit: bool,
    pub idempotency_header: String,
}

impl Default for ServerMiddlewareConfig {
    fn default() -> Self {
        Self {
            require_authentication: true,
            public_operations: default_public_operations(),
            require_idempotency_key_for_mutations: true,
            enable_idempotency: true,
            enable_rate_limit: true,
            idempotency_header: "Idempotency-Key".to_owned(),
        }
    }
}

pub fn default_public_operations() -> BTreeSet<String> {
    [
        "cx.server.describe",
        "cx.identity.describe_registry",
        "cx.sync.describe",
        "cx.directory.describe",
        "cx.applet.ping",
        "cx.applet.describe",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub struct ServerMiddlewareStack<S> {
    service: S,
    config: ServerMiddlewareConfig,
    authenticator: Box<dyn ServerAuthenticator + Send>,
    authorizer: Box<dyn ServerAuthorizer + Send>,
    idempotency_store: Box<dyn ServerIdempotencyStore + Send>,
    rate_limiter: Box<dyn ServerRateLimiter + Send>,
}

impl<S> ServerMiddlewareStack<S> {
    pub fn new(service: S) -> Self {
        Self {
            service,
            config: ServerMiddlewareConfig::default(),
            authenticator: Box::new(BearerTokenAuthenticator::default()),
            authorizer: Box::new(OperationScopeAuthorizer),
            idempotency_store: Box::new(MemoryIdempotencyStore::default()),
            rate_limiter: Box::new(MemoryRateLimiter::default()),
        }
    }

    pub fn with_config(mut self, config: ServerMiddlewareConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_authenticator<A>(mut self, authenticator: A) -> Self
    where
        A: ServerAuthenticator + Send + 'static,
    {
        self.authenticator = Box::new(authenticator);
        self
    }

    pub fn with_authorizer<A>(mut self, authorizer: A) -> Self
    where
        A: ServerAuthorizer + Send + 'static,
    {
        self.authorizer = Box::new(authorizer);
        self
    }

    pub fn with_idempotency_store<I>(mut self, idempotency_store: I) -> Self
    where
        I: ServerIdempotencyStore + Send + 'static,
    {
        self.idempotency_store = Box::new(idempotency_store);
        self
    }

    pub fn with_rate_limiter<R>(mut self, rate_limiter: R) -> Self
    where
        R: ServerRateLimiter + Send + 'static,
    {
        self.rate_limiter = Box::new(rate_limiter);
        self
    }
}

impl<S> RoutedEndpointService for ServerMiddlewareStack<S>
where
    S: RoutedEndpointService,
{
    fn call(&mut self, request: RoutedHttpAdapterRequest) -> Result<HttpAdapterResponse> {
        let context = ServerRequestContext::from_routed_request(&request);
        let public_operation = self.config.public_operations.contains(context.operation_id);

        let auth_decision = self.authenticator.authenticate(&context);
        let principal = match auth_decision {
            ServerAuthenticationDecision::Authenticated(principal) => principal,
            ServerAuthenticationDecision::Missing if public_operation => {
                AuthenticatedPrincipal::anonymous()
            }
            ServerAuthenticationDecision::Missing if self.config.require_authentication => {
                return Ok(ServerMiddlewareRejection::new(
                    401,
                    "unauthenticated",
                    "Authentication is required for this Contrix endpoint",
                )
                .into_response());
            }
            ServerAuthenticationDecision::Missing => AuthenticatedPrincipal::anonymous(),
            ServerAuthenticationDecision::Denied(rejection) => return Ok(rejection.into_response()),
        };

        if !public_operation {
            match self.authorizer.authorize(&context, &principal) {
                ServerAuthorizationDecision::Allow => {}
                ServerAuthorizationDecision::Deny(rejection) => {
                    return Ok(rejection.into_response());
                }
            }
        }

        let idempotency = self.prepare_idempotency(&request, &principal)?;
        if let PreparedIdempotency::Hit(response) = idempotency {
            return Ok(response);
        }

        if self.config.enable_rate_limit {
            let rate_limit_key = format!("{}:{}", principal.subject, context.operation_id);
            if let ServerRateLimitDecision::Limited { retry_after_secs } =
                self.rate_limiter.check(&rate_limit_key)
            {
                return Ok(ServerMiddlewareRejection::new(
                    429,
                    "rate_limited",
                    "Contrix endpoint rate limit exceeded",
                )
                .with_header("Retry-After", retry_after_secs.to_string())
                .into_response());
            }
        }

        let response = self.service.call(request)?;
        if let PreparedIdempotency::Miss { key, request_digest } = idempotency
            && response.status < 500
        {
            self.idempotency_store.store(key, request_digest, &response);
        }
        Ok(response)
    }
}

enum PreparedIdempotency {
    NotApplicable,
    Miss { key: ServerIdempotencyKey, request_digest: String },
    Hit(HttpAdapterResponse),
}

impl<S> ServerMiddlewareStack<S> {
    fn prepare_idempotency(
        &mut self,
        request: &RoutedHttpAdapterRequest,
        principal: &AuthenticatedPrincipal,
    ) -> Result<PreparedIdempotency> {
        if !self.config.enable_idempotency || !is_mutating_method(request.request.method) {
            return Ok(PreparedIdempotency::NotApplicable);
        }

        let Some(header) = header_value(&request.request.headers, &self.config.idempotency_header)
        else {
            if self.config.require_idempotency_key_for_mutations {
                return Ok(PreparedIdempotency::Hit(
                    ServerMiddlewareRejection::new(
                        428,
                        "missing_param",
                        "Mutating Contrix endpoints require Idempotency-Key",
                    )
                    .into_response(),
                ));
            }
            return Ok(PreparedIdempotency::NotApplicable);
        };

        let key = ServerIdempotencyKey {
            principal: principal.subject.clone(),
            operation_id: request.operation_id.to_owned(),
            key: header.to_owned(),
        };
        let request_digest = routed_request_digest(request);
        match self.idempotency_store.lookup(&key, &request_digest) {
            ServerIdempotencyDecision::Miss => {
                Ok(PreparedIdempotency::Miss { key, request_digest })
            }
            ServerIdempotencyDecision::Hit(response) => Ok(PreparedIdempotency::Hit(response)),
            ServerIdempotencyDecision::Conflict(rejection) => {
                Ok(PreparedIdempotency::Hit(rejection.into_response()))
            }
        }
    }
}

fn is_mutating_method(method: EndpointMethod) -> bool {
    matches!(method, EndpointMethod::Post | EndpointMethod::Put | EndpointMethod::Delete)
}

fn routed_request_digest(request: &RoutedHttpAdapterRequest) -> String {
    let body_digest = canonical::sha256_digest(&request.request.body);
    canonical::sha256_digest(format!(
        "{}\n{}\n{}\n{}",
        request.operation_id,
        request.request.method.as_str(),
        request.request.path,
        body_digest
    ))
}

pub(super) fn header_value<'a>(
    headers: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

pub fn dispatch_routed_http_request<S>(
    service: &mut S,
    request: HttpAdapterRequest,
) -> HttpAdapterResponse
where
    S: RoutedEndpointService,
{
    if let Err(error) = reject_query_auth(&request.query) {
        return adapter_error_response(400, "invalid_param", error.to_string());
    }

    let Some(matched) = match_endpoint(request.method, &request.path) else {
        return adapter_error_response(404, "not_found", "Contrix endpoint not found");
    };
    let operation_id = matched.contract.operation_id;

    match service.call(RoutedHttpAdapterRequest {
        request,
        operation_id,
        path_parameters: matched.path_parameters,
    }) {
        Ok(mut response) => {
            response
                .headers
                .entry("X-Contrix-Operation-Id".to_owned())
                .or_insert_with(|| operation_id.to_owned());
            response
        }
        Err(error) => adapter_error_response(500, "internal_error", error.to_string()),
    }
}

pub(super) fn adapter_error_response(
    status: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> HttpAdapterResponse {
    let envelope = contrix_core::ErrorEnvelope::new(code, message);
    HttpAdapterResponse {
        status,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(&envelope).unwrap_or_default(),
    }
}
