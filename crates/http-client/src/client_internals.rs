//! Internal transport plumbing for [`Client`].
//!
//! Holds the public accessor methods (`builder`, `new`, `base_url`,
//! `retry_config`) and all the private request-construction / execution
//! helpers. Endpoint modules call into these via `pub(crate)` visibility;
//! they are not part of the public API.

use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignedRequestParts,
    canonical_message, format_signature_header, format_signature_input_component_list,
    parse_signature_input, sign_http_message_for_scenario, sign_message,
};
use arkret_wire::{Problem, ServiceOperationId};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Method, RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::sleep;
use url::Url;

use crate::{
    Auth, Client, ClientBuilder, ClientRequestOptions, Error, HEADER_IDEMPOTENCY_KEY,
    HEADER_OPERATION, HEADER_REQUEST_ID, HEADER_WAIT_FOR, Result, RetryConfig, retry_after_ms,
};

/// Wrap a reqwest transport error into the crate [`Error::Http`] variant at
/// the crate boundary. The wire-model layer carries no reqwest dependency, so
/// the conversion is explicit here instead of a `#[from]` impl.
pub(crate) fn transport_error(error: reqwest::Error) -> Error {
    use std::error::Error as _;
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    Error::Http(message)
}

pub(crate) fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

impl Client {
    pub fn builder(base_url: Url) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    pub fn new(base_url: Url) -> Result<Self> {
        Self::builder(base_url).build()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Clone this authenticated transport for another trusted service base URL.
    ///
    /// The caller must establish that the target is the intended authority
    /// before forwarding credentials (for example through ServiceDescribe).
    /// DPoP proofs are generated for the new request URL; the grant, signer,
    /// refresh reader, and transport settings are retained.
    pub fn with_base_url(&self, base_url: Url) -> Result<Self> {
        validate_base_url(&base_url, self.allow_insecure_localhost)?;
        let mut client = self.clone();
        client.base_url = base_url;
        Ok(client)
    }

    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry
    }

    pub(crate) fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let builder = self.request_unbounded(method, path)?;
        // Bound every regular request when the caller did not configure
        // an explicit client-wide timeout (reqwest's own default is no
        // timeout at all). Streaming endpoints use `request_unbounded`.
        #[cfg(not(target_arch = "wasm32"))]
        let builder = match self.default_timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        Ok(builder)
    }

    pub(crate) fn canonical_json_body<T: Serialize + ?Sized>(
        &self,
        builder: RequestBuilder,
        body: &T,
    ) -> Result<RequestBuilder> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(body)?;
        Ok(builder.header(CONTENT_TYPE, "application/json").body(bytes))
    }

    /// Build a request for a protocol endpoint that is normatively public.
    ///
    /// Public metadata must not inherit the client's bearer, DPoP, device, or
    /// service authentication. Besides avoiding credential disclosure, this
    /// keeps browser GETs CORS-simple instead of introducing a DPoP-triggered
    /// preflight for an endpoint that requires no proof.
    pub(crate) fn public_request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        self.request_without_configured_auth(method, path)
    }

    /// Build a service-authenticated request without forwarding the client's
    /// account/device authorization. The endpoint supplies its independent
    /// service signature at execution time.
    pub(crate) fn service_request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        self.request_without_configured_auth(method, path)
    }

    fn request_without_configured_auth(
        &self,
        method: Method,
        path: &str,
    ) -> Result<RequestBuilder> {
        let builder = self.request_unbounded_inner(method, path, false)?;
        #[cfg(not(target_arch = "wasm32"))]
        let builder = match self.default_timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        Ok(builder)
    }

    /// Build a request without the per-request default total timeout —
    /// for long-lived NDJSON subscribe streams that stay open by design.
    /// The connect-phase timeout still applies at the transport level.
    pub(crate) fn request_unbounded(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        self.request_unbounded_inner(method, path, true)
    }

    fn request_unbounded_inner(
        &self,
        method: Method,
        path: &str,
        include_auth: bool,
    ) -> Result<RequestBuilder> {
        reject_absolute_path(path)?;
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        reject_query_auth_in_url(&url)?;
        // Resolve against the protocol path supplied by the endpoint method,
        // not `url.path()`: deployments may mount Arkret below a base-path
        // prefix which is not part of the operation registry template.
        let selector_path = path.split(['?', '#']).next().unwrap_or(path);
        let canonical_selector_path;
        let selector_path = if selector_path.starts_with('/') {
            selector_path
        } else {
            canonical_selector_path = format!("/{selector_path}");
            canonical_selector_path.as_str()
        };
        let operation = ServiceOperationId::from_http_request(method.as_str(), selector_path)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "no registered Arkret operation for {} {}",
                    method, selector_path
                ))
            })?;
        let method_for_auth = method.clone();
        let url_for_auth = url.clone();
        let mut builder = self
            .http
            .request(method, url)
            .header("Accept", "application/json")
            .header(HEADER_OPERATION, operation.as_str());
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(USER_AGENT, user_agent);
        }
        if include_auth {
            if let Some((source, destination)) = &self.service_signature_identity {
                return Ok(builder
                    .header(crate::HEADER_SOURCE_SERVICE_ID, source.as_str())
                    .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str()));
            }
            if let Some((metadata, destination)) = &self.managed_device_signature_identity {
                let scenario =
                    arkret_signatures::http_signature::http_signature_scenario_descriptor(
                        HttpSignatureScenario::AppletManagedDeviceV1,
                    );
                if !scenario.operations.contains(&operation.as_str()) {
                    return Err(Error::Protocol(
                        "operation is not eligible for managed Device authentication".into(),
                    ));
                }
                let mut metadata = metadata.clone();
                let mut nonce = [0u8; 16];
                getrandom::fill(&mut nonce)
                    .map_err(|e| Error::Protocol(format!("Device nonce entropy: {e}")))?;
                metadata.nonce = arkret_canonical::base64url_encode(nonce);
                return Ok(builder
                    .header(
                        arkret_models_integration::AppletManagedDeviceMetadata::HEADER,
                        metadata.to_header_value()?,
                    )
                    .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str()));
            }
            self.apply_auth(builder, &method_for_auth, &url_for_auth)
        } else {
            Ok(builder)
        }
    }

    pub(crate) fn apply_auth(
        &self,
        mut builder: RequestBuilder,
        method: &Method,
        url: &Url,
    ) -> Result<RequestBuilder> {
        match &self.auth {
            Some(Auth::Bearer(token)) => {
                builder = builder.bearer_auth(token);
            }
            Some(Auth::DeviceProof(proof)) => {
                builder = builder.header("X-Arkret-Device-Proof", proof);
            }
            Some(Auth::ServiceSignature(signature)) => {
                builder = builder
                    .header("Signature", signature)
                    .header("X-Arkret-Service-Signature", "1");
            }
            Some(Auth::Dpop(auth)) => {
                let proof = auth.proof_for(method, url)?;
                validate_header_value("DPoP proof", &proof)?;
                if let Some(token) = auth.access_token() {
                    validate_header_value("DPoP authorization credential", token)?;
                    builder = builder.header("Authorization", format!("DPoP {token}"));
                }
                builder = builder.header("DPoP", proof);
            }
            None => {}
        }
        Ok(builder)
    }

    pub(crate) fn apply_request_options(
        &self,
        mut builder: RequestBuilder,
        options: &ClientRequestOptions,
    ) -> Result<RequestBuilder> {
        if let Some(request_id) = &options.request_id {
            validate_header_value(HEADER_REQUEST_ID, request_id)?;
            builder = builder.header(HEADER_REQUEST_ID, request_id);
        }
        if let Some(idempotency_key) = &options.idempotency_key {
            validate_header_value(HEADER_IDEMPOTENCY_KEY, idempotency_key)?;
            builder = builder.header(HEADER_IDEMPOTENCY_KEY, idempotency_key);
        }
        if let Some(wait_for) = &options.wait_for {
            validate_header_value(HEADER_WAIT_FOR, wait_for)?;
            arkret_wire::Cursor::new(wait_for.clone())
                .map_err(|error| Error::Protocol(error.to_string()))?;
            let request = builder
                .try_clone()
                .ok_or_else(|| Error::Protocol("wait-for requires a replayable request".into()))?
                .build()
                .map_err(transport_error)?;
            let operation = request
                .headers()
                .get(HEADER_OPERATION)
                .and_then(|value| value.to_str().ok())
                .and_then(ServiceOperationId::from_wire);
            if operation.and_then(|operation| operation.wait_for_carrier("http_json"))
                != Some(("header", "X-Arkret-Wait-For"))
            {
                return Err(Error::Protocol(
                    "operation does not register an HTTP wait-for header".into(),
                ));
            }
            if request.headers().contains_key(HEADER_WAIT_FOR) {
                return Err(Error::Protocol("duplicate wait-for header".into()));
            }
            builder = builder.header(HEADER_WAIT_FOR, wait_for);
        }
        Ok(builder)
    }

    pub(crate) async fn send_json<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
    ) -> Result<T> {
        self.send_json_with_headers_and_replay_policy(builder, false)
            .await
            .map(|(body, _headers)| body)
    }

    pub(crate) async fn send_json_limited<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
        limit: usize,
    ) -> Result<T> {
        let response = self
            .execute_with_replay_policy(builder, false, None)
            .await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }
        let body = read_body_limited(response, limit).await?;
        serde_json::from_slice(&body).map_err(Error::from)
    }

    /// Send a request whose protocol operation registry defines durable exact
    /// replay from a stable request identity embedded in the canonical body.
    /// This is intentionally crate-private: ordinary POSTs must not opt into
    /// retry merely because their body happens to be cloneable.
    pub(crate) async fn send_json_protocol_replay_safe<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
    ) -> Result<T> {
        self.send_json_with_headers_and_replay_policy(builder, true)
            .await
            .map(|(body, _headers)| body)
    }

    /// Send an exact-replay operation under one generated HTTP-signature
    /// scenario. Kept crate-private so endpoint owners, rather than arbitrary
    /// callers, select which protocol operations qualify.
    pub(crate) async fn send_json_protocol_replay_safe_for_scenario<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
        scenario: HttpSignatureScenario,
    ) -> Result<T> {
        self.send_json_with_headers_replay_policy_and_scenario(builder, true, Some(scenario))
            .await
            .map(|(body, _headers)| body)
    }

    async fn send_json_with_headers_and_replay_policy<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
        protocol_replay_safe: bool,
    ) -> Result<(T, HeaderMap)> {
        self.send_json_with_headers_replay_policy_and_scenario(builder, protocol_replay_safe, None)
            .await
    }

    async fn send_json_with_headers_replay_policy_and_scenario<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
        protocol_replay_safe: bool,
        signature_scenario: Option<HttpSignatureScenario>,
    ) -> Result<(T, HeaderMap)> {
        let response = self
            .execute_with_replay_policy(builder, protocol_replay_safe, signature_scenario)
            .await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }

        let headers = response.headers().clone();
        let body = read_body_limited(response, MAX_RESPONSE_BODY_BYTES).await?;
        serde_json::from_slice(&body)
            .map(|body| (body, headers))
            .map_err(Error::from)
    }

    pub(crate) async fn send_response(&self, builder: RequestBuilder) -> Result<Response> {
        let response = self.execute(builder).await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }

        Ok(response)
    }

    fn sign_http_message(&self, mut request: reqwest::Request) -> Result<reqwest::Request> {
        let Some(signer) = self.http_message_signer.as_ref() else {
            return Ok(request);
        };
        if !is_http_message_signature_surface(request.url().path()) {
            return Ok(request);
        }

        let body_digest = match request.body() {
            Some(body) => {
                let bytes = body.as_bytes().ok_or_else(|| {
                    Error::Protocol(
                        "HTTP message signing requires a buffered request body".to_owned(),
                    )
                })?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(ContentDigest::compute(
                        bytes,
                        ContentDigestAlgorithm::Sha256,
                    ))
                }
            }
            None => None,
        };

        let mut covered_components = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ];
        if body_digest.is_some() {
            covered_components.push(Component::Header("content-digest".to_owned()));
        }
        let mut signed_headers = Vec::new();
        for header_name in [HEADER_OPERATION, HEADER_IDEMPOTENCY_KEY, HEADER_WAIT_FOR] {
            if let Some(value) = request.headers().get(header_name) {
                let value = value.to_str().map_err(|_| {
                    Error::Protocol(format!(
                        "{header_name} must be visible ASCII for HTTP message signing"
                    ))
                })?;
                let canonical_name = header_name.to_ascii_lowercase();
                covered_components.push(Component::Header(canonical_name.clone()));
                signed_headers.push((canonical_name, value.to_owned()));
            }
        }
        let created = chrono::Utc::now().timestamp();
        let validity = signer.validity_seconds();
        if validity <= 0 || validity > 300 {
            return Err(Error::Protocol(
                "HTTP message signature validity must be within 1..=300 seconds".to_owned(),
            ));
        }
        let expires = created + validity;
        let signature_input_header =
            format_signature_input_component_list("sig1", &covered_components)
                .map_err(|error| Error::Protocol(format!("signature input: {error}")))?;
        let signature_input_header = format!(
            "{signature_input_header};created={created};expires={expires};keyid=\"{}\";alg=\"ed25519\"",
            signer.key_id()
        );
        let signature_input = parse_signature_input(&signature_input_header)
            .map_err(|error| Error::Protocol(format!("signature input: {error}")))?;
        let url = request.url();
        let parts = SignedRequestParts {
            method: request.method().as_str().to_owned(),
            target_uri: url.as_str().to_owned(),
            authority: request_authority(url)?,
            path: url.path().to_owned(),
            headers: signed_headers,
            body_digest: body_digest.as_ref().map(|digest| digest.wire_value.clone()),
        };
        let message = canonical_message(&parts, &signature_input)
            .map_err(|error| Error::Protocol(format!("canonical signature message: {error}")))?;
        let signature_header =
            format_signature_header("sig1", &sign_message(&message, signer.signing_key()))
                .map_err(|error| Error::Protocol(format!("signature header: {error}")))?;

        let headers = request.headers_mut();
        if let Some(digest) = body_digest {
            headers.insert(
                "Content-Digest",
                HeaderValue::from_str(&digest.wire_value)
                    .map_err(|error| Error::Protocol(format!("content-digest header: {error}")))?,
            );
        }
        headers.insert(
            "Signature-Input",
            HeaderValue::from_str(&signature_input_header)
                .map_err(|error| Error::Protocol(format!("signature-input header: {error}")))?,
        );
        headers.insert(
            "Signature",
            HeaderValue::from_str(&signature_header)
                .map_err(|error| Error::Protocol(format!("signature header: {error}")))?,
        );
        Ok(request)
    }

    fn sign_http_message_for_registered_scenario(
        &self,
        mut request: reqwest::Request,
        scenario: HttpSignatureScenario,
    ) -> Result<reqwest::Request> {
        let signer = self.http_message_signer.as_ref().ok_or_else(|| {
            Error::Protocol(
                "registered HTTP-signature scenario requires an HttpMessageSigner".to_owned(),
            )
        })?;
        let body_digest = match request.body() {
            Some(body) => {
                let bytes = body.as_bytes().ok_or_else(|| {
                    Error::Protocol(
                        "HTTP message signing requires a buffered request body".to_owned(),
                    )
                })?;
                (!bytes.is_empty())
                    .then(|| ContentDigest::compute(bytes, ContentDigestAlgorithm::Sha256))
            }
            None => None,
        };
        if let Some(digest) = &body_digest {
            request.headers_mut().insert(
                "Content-Digest",
                HeaderValue::from_str(&digest.wire_value)
                    .map_err(|error| Error::Protocol(format!("content-digest header: {error}")))?,
            );
        }
        let mut applicable_conditionals = Vec::new();
        if body_digest.is_some() {
            applicable_conditionals.push("content-digest");
        }
        if request.headers().contains_key(HEADER_IDEMPOTENCY_KEY) {
            applicable_conditionals.push("idempotency-key");
        }
        let url = request.url();
        let parts = SignedRequestParts {
            method: request.method().as_str().to_owned(),
            target_uri: url.as_str().to_owned(),
            authority: request_authority(url)?,
            path: url.path().to_owned(),
            headers: request
                .headers()
                .iter()
                .map(|(name, value)| {
                    value
                        .to_str()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                        .map_err(|_| {
                            Error::Protocol(format!(
                                "{} must be visible ASCII for HTTP message signing",
                                name.as_str()
                            ))
                        })
                })
                .collect::<Result<Vec<_>>>()?,
            body_digest: body_digest.as_ref().map(|digest| digest.wire_value.clone()),
        };
        let signed = sign_http_message_for_scenario(
            &parts,
            scenario,
            &applicable_conditionals,
            "sig1",
            signer.key_id(),
            chrono::Utc::now().timestamp(),
            signer.signing_key(),
        )
        .map_err(|error| Error::Protocol(format!("HTTP message signature: {error}")))?;
        request.headers_mut().insert(
            "Signature-Input",
            HeaderValue::from_str(&signed.signature_input_header)
                .map_err(|error| Error::Protocol(format!("signature-input header: {error}")))?,
        );
        request.headers_mut().insert(
            "Signature",
            HeaderValue::from_str(&signed.signature_header)
                .map_err(|error| Error::Protocol(format!("signature header: {error}")))?,
        );
        Ok(request)
    }

    fn build_signed_request(
        &self,
        builder: RequestBuilder,
        signature_scenario: Option<HttpSignatureScenario>,
    ) -> Result<reqwest::Request> {
        let mut request = builder.build().map_err(transport_error)?;
        // The inner operation proof and canonical body remain immutable across
        // exact replay. DPoP is an outer per-HTTP-attempt proof and may carry a
        // fresh jti/iat while binding the same method, target and access token.
        if request.headers().contains_key("DPoP")
            && let Some(Auth::Dpop(auth)) = &self.auth
        {
            let proof = auth.proof_for(request.method(), request.url())?;
            validate_header_value("DPoP proof", &proof)?;
            request.headers_mut().insert(
                "DPoP",
                HeaderValue::from_str(&proof)
                    .map_err(|error| Error::Protocol(format!("DPoP proof: {error}")))?,
            );
        }
        let signature_scenario = signature_scenario.or_else(|| {
            if request
                .headers()
                .contains_key(arkret_models_integration::AppletManagedDeviceMetadata::HEADER)
                && self.managed_device_signature_identity.is_some()
            {
                Some(HttpSignatureScenario::AppletManagedDeviceV1)
            } else if request
                .headers()
                .contains_key(crate::HEADER_SOURCE_SERVICE_ID)
                && self.service_signature_identity.is_some()
            {
                Some(HttpSignatureScenario::ServiceToServiceV1)
            } else {
                None
            }
        });
        match signature_scenario {
            Some(scenario) => self.sign_http_message_for_registered_scenario(request, scenario),
            None => self.sign_http_message(request),
        }
    }

    async fn send_request_builder(
        &self,
        builder: RequestBuilder,
        signature_scenario: Option<HttpSignatureScenario>,
    ) -> Result<Response> {
        let request = self.build_signed_request(builder, signature_scenario)?;
        self.http.execute(request).await.map_err(transport_error)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        self.execute_with_replay_policy(builder, false, None).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn execute_with_replay_policy(
        &self,
        builder: RequestBuilder,
        protocol_replay_safe: bool,
        signature_scenario: Option<HttpSignatureScenario>,
    ) -> Result<Response> {
        validate_request_builder(&builder)?;
        if self.retry.max_retries == 0 {
            let response = self
                .send_request_builder(builder, signature_scenario)
                .await?;
            return Ok(response);
        }

        let Some(template) = builder.try_clone() else {
            let response = self
                .send_request_builder(builder, signature_scenario)
                .await?;
            return Ok(response);
        };

        // Blind resends of a non-idempotent request can duplicate a write the
        // server already executed (a 5xx or timeout does not prove the request
        // had no effect). Safe/idempotent HTTP methods are always retryable;
        // POST/PATCH require either an `Idempotency-Key` or the crate-private,
        // operation-specific durable protocol replay contract. Everything else
        // only retries connect-level failures, where the request provably never
        // reached the server.
        let retry_safe = protocol_replay_safe
            || template
                .try_clone()
                .and_then(|clone| clone.build().ok())
                .map(|request| {
                    matches!(
                        *request.method(),
                        Method::GET
                            | Method::HEAD
                            | Method::OPTIONS
                            | Method::TRACE
                            | Method::PUT
                            | Method::DELETE
                    ) || request.method().as_str() == "QUERY"
                        || request.headers().contains_key(HEADER_IDEMPOTENCY_KEY)
                })
                .unwrap_or(false);

        let mut attempts = 0usize;
        loop {
            let attempt_builder = template.try_clone().ok_or_else(|| {
                Error::Protocol("retryable request could not be cloned".to_owned())
            })?;
            let attempt_request = self.build_signed_request(attempt_builder, signature_scenario)?;
            match self.http.execute(attempt_request).await {
                Ok(response)
                    if retry_safe
                        && attempts < self.retry.max_retries
                        && self.retry.should_retry_status(response.status()) =>
                {
                    attempts += 1;
                    sleep(
                        self.retry
                            .retry_delay_from_headers(response.headers(), attempts),
                    )
                    .await;
                }
                Ok(response) => {
                    return Ok(response);
                }
                Err(error)
                    if attempts < self.retry.max_retries && self.retry.retry_network_errors =>
                {
                    attempts += 1;
                    // Timeouts may fire after the server received the request;
                    // only HTTP-idempotent or protocol-replay-safe requests may
                    // resend then.
                    let retryable = error.is_connect() || (retry_safe && error.is_timeout());
                    if !retryable {
                        return Err(transport_error(error));
                    }
                    sleep(self.retry.retry_delay(attempts)).await;
                }
                Err(error) => {
                    return Err(transport_error(error));
                }
            }
        }
    }

    /// Wasm32 fast path. The browser fetch backend has neither a sleep
    /// primitive we can call from the arkret-http-client crate (no
    /// `tokio::time` driver) nor an `is_connect` accessor on
    /// `reqwest::Error`, and status-based retry windows would require
    /// pulling in `gloo-timers` or similar. We deliberately collapse retry
    /// to a single send on wasm32 and let the caller layer their own
    /// retry on top via `wasm-bindgen-futures` if they need it.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        self.execute_with_replay_policy(builder, false, None).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn execute_with_replay_policy(
        &self,
        builder: RequestBuilder,
        _protocol_replay_safe: bool,
        signature_scenario: Option<HttpSignatureScenario>,
    ) -> Result<Response> {
        validate_request_builder(&builder)?;
        // Retry is not implemented on wasm32: execute() sends exactly once and
        // the caller's RetryConfig is ignored (see `ClientBuilder::retry` /
        // `RetryConfig` docs). Callers layer retry above the client if needed.
        let response = self
            .send_request_builder(builder, signature_scenario)
            .await?;
        Ok(response)
    }
}

fn is_http_message_signature_surface(path: &str) -> bool {
    path.starts_with("/_arkret/self/") || path.starts_with("/_arkret/root/")
}

fn request_authority(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Protocol("request URL has no host".to_owned()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

pub(crate) fn validate_base_url(url: &Url, allow_insecure_localhost: bool) -> Result<()> {
    reject_query_auth_in_url(url)?;
    if url.scheme() == "https" {
        return Ok(());
    }

    if allow_insecure_localhost && url.scheme() == "http" && is_localhost(url) {
        return Ok(());
    }

    Err(Error::InsecureUrl(url.to_string()))
}

pub(crate) fn validate_auth(auth: &Auth) -> Result<()> {
    match auth {
        Auth::Bearer(token) | Auth::DeviceProof(token) | Auth::ServiceSignature(token) => {
            validate_header_value("auth material", token)
        }
        Auth::Dpop(auth) => {
            if let Some(token) = auth.access_token() {
                validate_header_value("auth material", token)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || HeaderValue::from_str(value).is_err() {
        return Err(Error::Protocol(format!(
            "{name} must be non-empty and header-safe"
        )));
    }
    Ok(())
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn reject_absolute_path(path: &str) -> Result<()> {
    if path.starts_with("//") || Url::parse(path).is_ok() {
        return Err(Error::Protocol(
            "request path must be relative to the Arkret service".to_owned(),
        ));
    }
    Ok(())
}

fn reject_query_auth_in_url(url: &Url) -> Result<()> {
    for (key, _) in url.query_pairs() {
        if arkret_wire::is_query_auth_parameter(key.as_ref()) {
            return Err(Error::Protocol(
                "query string authentication material is not allowed".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_request_builder(builder: &RequestBuilder) -> Result<()> {
    if let Some(clone) = builder.try_clone() {
        let request = clone.build().map_err(transport_error)?;
        reject_query_auth_in_url(request.url())?;
    }
    Ok(())
}

async fn error_envelope_from_response(response: Response) -> Problem {
    let status = response.status();
    let retry_after_ms = retry_after_ms(response.headers());
    let error = match read_body_limited(response, MAX_RESPONSE_BODY_BYTES).await {
        Ok(body) => serde_json::from_slice::<Problem>(&body).unwrap_or_else(|_| {
            Problem::from_code(
                "internal_error",
                format!("HTTP request failed with status {status}"),
            )
        }),
        Err(_) => Problem::from_code(
            "internal_error",
            format!("HTTP request failed with status {status}"),
        ),
    };
    // api-conventions.md §9: when both the `Retry-After` header and the body
    // `retry_after_ms` are present, the header wins. The body value is only
    // kept when no header was sent.
    match retry_after_ms {
        Some(_) => error.with_retry_after_ms(retry_after_ms),
        None => error,
    }
}

/// Maximum bytes a non-streaming response body may occupy before the read is
/// aborted. Bounds memory against unbounded / decompression-amplified bodies
/// from a hostile or misbehaving peer (gzip is enabled by default). Streaming
/// endpoints have their own per-frame bound (`MAX_SUBSCRIBE_FRAME_BYTES`).
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Read a response body incrementally, failing as soon as the accumulated
/// (post-decompression) size exceeds `limit` — the body is never fully
/// materialized first.
pub(crate) async fn read_body_limited(response: Response, limit: usize) -> Result<Vec<u8>> {
    use futures_util::StreamExt;

    let mut stream = response.bytes_stream();
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(transport_error)?;
        if buffer.len().saturating_add(chunk.len()) > limit {
            return Err(Error::Protocol(format!(
                "response body exceeds the {limit}-byte limit"
            )));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

pub(crate) fn reject_path_segment(segment: &str) -> Result<()> {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('?')
        || segment.contains('#')
        || segment.contains('%')
        || segment == "."
        || segment == ".."
    {
        return Err(Error::Protocol(
            "path segment contains reserved characters".to_owned(),
        ));
    }
    Ok(())
}
