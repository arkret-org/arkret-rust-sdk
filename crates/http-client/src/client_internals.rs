//! Internal transport plumbing for [`Client`].
//!
//! Holds the public accessor methods (`builder`, `new`, `base_url`,
//! `retry_config`) and all the private request-construction / execution
//! helpers. Endpoint modules call into these via `pub(crate)` visibility;
//! they are not part of the public API.

use cokret_core::{Error, ErrorEnvelope, Result};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Method, RequestBuilder, Response};
use serde::de::DeserializeOwned;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::sleep;
use url::Url;

use crate::{
    Auth, Client, ClientBuilder, ClientRequestOptions, HEADER_IDEMPOTENCY_KEY, HEADER_REQUEST_ID,
    HEADER_WAIT_FOR, QUERY_AUTH_KEYS, RetryConfig, retry_after_ms,
};

/// Wrap a reqwest transport error into the transport-agnostic
/// `cokret_core::Error::Http` variant at the crate boundary. cokret-core
/// deliberately carries no reqwest dependency (ARCHITECTURE.md: core is the
/// wire-model layer; the HTTP stack lives in this crate), so the conversion
/// is explicit here instead of a `#[from]` impl on the core error type.
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

    /// Build a request without the per-request default total timeout —
    /// for long-lived NDJSON subscribe streams that stay open by design.
    /// The connect-phase timeout still applies at the transport level.
    pub(crate) fn request_unbounded(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        reject_absolute_path(path)?;
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        reject_query_auth_in_url(&url)?;
        let mut builder = self
            .http
            .request(method, url)
            .header("Accept", "application/json");
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(USER_AGENT, user_agent);
        }
        Ok(self.apply_auth(builder))
    }

    pub(crate) fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Some(Auth::Bearer(token)) => builder.bearer_auth(token),
            Some(Auth::DeviceProof(proof)) => builder.header("X-Cokret-Device-Proof", proof),
            Some(Auth::ServiceSignature(signature)) => builder
                .header("Signature", signature)
                .header("X-Cokret-Service-Signature", "1"),
            None => builder,
        }
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
        let response = self.execute(builder).await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }

        response.json().await.map_err(transport_error)
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
                "sending Cokret HTTP request"
            );
        }
        if self.retry.max_retries == 0 {
            let response = builder.send().await.map_err(transport_error)?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Cokret HTTP response"
                );
            }
            return Ok(response);
        }

        let Some(template) = builder.try_clone() else {
            let response = builder.send().await.map_err(transport_error)?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Cokret HTTP response"
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
            match attempt_builder.send().await {
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
                            "retrying Cokret HTTP request after retryable status"
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
                            "received Cokret HTTP response"
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
                                "Cokret HTTP request failed without retry"
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
                            "retrying Cokret HTTP request after transport error"
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
                            "Cokret HTTP request failed"
                        );
                    }
                    return Err(transport_error(error));
                }
            }
        }
    }

    /// Wasm32 fast path. The browser fetch backend has neither a sleep
    /// primitive we can call from the cokret-http-client crate (no
    /// `tokio::time` driver) nor an `is_connect` accessor on
    /// `reqwest::Error`, and status-based retry windows would require
    /// pulling in `gloo-timers` or similar. We deliberately collapse retry
    /// to a single send on wasm32 and let the caller layer their own
    /// retry on top via `wasm-bindgen-futures` if they need it.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        #[cfg(feature = "tracing")]
        let trace = request_trace_fields(&builder);
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                "sending Cokret HTTP request"
            );
        }
        let response = builder.send().await.map_err(transport_error)?;
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                status = response.status().as_u16(),
                "received Cokret HTTP response"
            );
        }
        Ok(response)
    }
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
    let value = match auth {
        Auth::Bearer(token) | Auth::DeviceProof(token) | Auth::ServiceSignature(token) => token,
    };
    validate_header_value("auth material", value)
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
            "request path must be relative to the Cokret service".to_owned(),
        ));
    }
    Ok(())
}

fn reject_query_auth_in_url(url: &Url) -> Result<()> {
    for (key, _) in url.query_pairs() {
        if QUERY_AUTH_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
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
    let error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| {
        ErrorEnvelope::new(
            "internal_error",
            format!("HTTP request failed with status {status}"),
        )
    });
    if error.retry_after_ms().is_none() {
        error.with_retry_after_ms(retry_after_ms)
    } else {
        error
    }
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
