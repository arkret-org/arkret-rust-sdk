//! Internal transport plumbing for [`Client`].
//!
//! Holds the public accessor methods (`builder`, `new`, `base_url`,
//! `retry_config`) and all the private request-construction / execution
//! helpers. Endpoint modules call into these via `pub(crate)` visibility;
//! they are not part of the public API.

use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    format_signature_header, format_signature_input_component_list, parse_signature_input,
    sign_message,
};
use arkret_wire::ErrorEnvelope;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Method, RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::sleep;
use url::Url;

use crate::{
    Auth, Client, ClientBuilder, ClientRequestOptions, Error, HEADER_IDEMPOTENCY_KEY,
    HEADER_REQUEST_ID, HEADER_WAIT_FOR, Result, RetryConfig, retry_after_ms,
};

/// Wrap a reqwest transport error into the crate [`Error::Http`] variant at
/// the crate boundary. The wire-model layer carries no reqwest dependency, so
/// the conversion is explicit here instead of a `#[from]` impl.
pub(crate) fn transport_error(error: reqwest::Error) -> Error {
    Error::Http(error.to_string())
}

#[cfg(feature = "tracing")]
#[derive(Clone, Debug)]
struct RequestTraceFields {
    method: String,
    path: String,
}

#[cfg(feature = "tracing")]
fn request_trace_fields(builder: &RequestBuilder) -> Option<RequestTraceFields> {
    let request = builder.try_clone()?.build().ok()?;
    Some(RequestTraceFields {
        method: request.method().as_str().to_owned(),
        path: request.url().path().to_owned(),
    })
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
        let method_for_auth = method.clone();
        let url_for_auth = url.clone();
        let mut builder = self
            .http
            .request(method, url)
            .header("Accept", "application/json");
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(USER_AGENT, user_agent);
        }
        if include_auth {
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
                    builder = match auth.authorization_scheme {
                        crate::DpopAuthorizationScheme::Bearer => builder.bearer_auth(token),
                        crate::DpopAuthorizationScheme::Dpop => {
                            validate_header_value("DPoP authorization credential", token)?;
                            builder.header("Authorization", format!("DPoP {token}"))
                        }
                    };
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
            builder = builder.header(HEADER_WAIT_FOR, wait_for);
        }
        Ok(builder)
    }

    pub(crate) async fn send_json<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
    ) -> Result<T> {
        self.send_json_with_headers(builder)
            .await
            .map(|(body, _headers)| body)
    }

    pub(crate) async fn send_json_with_headers<T: DeserializeOwned>(
        &self,
        builder: RequestBuilder,
    ) -> Result<(T, HeaderMap)> {
        let response = self.execute(builder).await?;
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

    pub(crate) async fn send_empty(&self, builder: RequestBuilder) -> Result<HeaderMap> {
        let response = self.send_response(builder).await?;
        Ok(response.headers().clone())
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
            headers: Vec::new(),
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

    fn build_signed_request(&self, builder: RequestBuilder) -> Result<reqwest::Request> {
        let request = builder.build().map_err(transport_error)?;
        self.sign_http_message(request)
    }

    async fn send_request_builder(&self, builder: RequestBuilder) -> Result<Response> {
        let request = self.build_signed_request(builder)?;
        self.http.execute(request).await.map_err(transport_error)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        #[cfg(feature = "tracing")]
        let trace = request_trace_fields(&builder);
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                max_retries = self.retry.max_retries,
                "sending Arkret HTTP request"
            );
        }
        if self.retry.max_retries == 0 {
            let response = self.send_request_builder(builder).await?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Arkret HTTP response"
                );
            }
            return Ok(response);
        }

        let Some(template) = builder.try_clone() else {
            let response = self.send_request_builder(builder).await?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Arkret HTTP response"
                );
            }
            return Ok(response);
        };

        // Blind resends of a non-idempotent request can duplicate a write
        // the server already executed (a 5xx or timeout does not prove the
        // request had no effect). Safe/idempotent HTTP methods are always
        // retryable; POST/PATCH only when the caller attached an
        // `Idempotency-Key`. Everything else only retries connect-level
        // failures, where the request provably never reached the server.
        let idempotent = template
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
                ) || request.headers().contains_key(HEADER_IDEMPOTENCY_KEY)
            })
            .unwrap_or(false);

        let mut attempts = 0usize;
        loop {
            let attempt_builder = template.try_clone().ok_or_else(|| {
                Error::Protocol("retryable request could not be cloned".to_owned())
            })?;
            let attempt_request = self.build_signed_request(attempt_builder)?;
            match self.http.execute(attempt_request).await {
                Ok(response)
                    if idempotent
                        && attempts < self.retry.max_retries
                        && self.retry.should_retry_status(response.status()) =>
                {
                    attempts += 1;
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            status = response.status().as_u16(),
                            attempt = attempts,
                            max_retries = self.retry.max_retries,
                            "retrying Arkret HTTP request after retryable status"
                        );
                    }
                    sleep(
                        self.retry
                            .retry_delay_from_headers(response.headers(), attempts),
                    )
                    .await;
                }
                Ok(response) => {
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::debug!(
                            method = %trace.method,
                            path = %trace.path,
                            status = response.status().as_u16(),
                            attempts = attempts + 1,
                            "received Arkret HTTP response"
                        );
                    }
                    return Ok(response);
                }
                Err(error)
                    if attempts < self.retry.max_retries && self.retry.retry_network_errors =>
                {
                    attempts += 1;
                    // Timeouts may fire after the server received the
                    // request; only idempotent requests may resend then.
                    let retryable = error.is_connect() || (idempotent && error.is_timeout());
                    if !retryable {
                        #[cfg(feature = "tracing")]
                        if let Some(trace) = &trace {
                            tracing::warn!(
                                method = %trace.method,
                                path = %trace.path,
                                error = %error,
                                "Arkret HTTP request failed without retry"
                            );
                        }
                        return Err(transport_error(error));
                    }
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            error = %error,
                            attempt = attempts,
                            max_retries = self.retry.max_retries,
                            "retrying Arkret HTTP request after transport error"
                        );
                    }
                    sleep(self.retry.retry_delay(attempts)).await;
                }
                Err(error) => {
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            error = %error,
                            attempts = attempts + 1,
                            "Arkret HTTP request failed"
                        );
                    }
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
        validate_request_builder(&builder)?;
        // Surface the platform parity gap instead of silently ignoring the
        // caller's RetryConfig (see `ClientBuilder::retry` / `RetryConfig`
        // docs): retry is not implemented on wasm32.
        #[cfg(feature = "tracing")]
        if self.retry.max_retries > 0 {
            tracing::warn!(
                max_retries = self.retry.max_retries,
                "RetryConfig is ignored on wasm32: execute() sends exactly once; \
                 layer retry above the client if needed"
            );
        }
        #[cfg(feature = "tracing")]
        let trace = request_trace_fields(&builder);
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                "sending Arkret HTTP request"
            );
        }
        let response = self.send_request_builder(builder).await?;
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                status = response.status().as_u16(),
                "received Arkret HTTP response"
            );
        }
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

async fn error_envelope_from_response(response: Response) -> ErrorEnvelope {
    let status = response.status();
    let retry_after_ms = retry_after_ms(response.headers());
    let error = match read_body_limited(response, MAX_RESPONSE_BODY_BYTES).await {
        Ok(body) => serde_json::from_slice::<ErrorEnvelope>(&body).unwrap_or_else(|_| {
            ErrorEnvelope::new(
                "internal_error",
                format!("HTTP request failed with status {status}"),
            )
        }),
        Err(_) => ErrorEnvelope::new(
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
