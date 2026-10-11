//! Hardened transport-only materialization of service-resolution carriers.
//!
//! Fetch success never establishes service authority. Callers must still
//! verify method history, current state, freshness and route binding before using its URL.

use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_egress_reqwest::EgressGuard;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{AuthenticatedServiceResolution, ServiceResolutionCarrier};
use arkret_wire::{DidCoreId, ServiceKind, ServiceOperationId};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap};

use crate::client_internals::read_body_limited;
use crate::{
    Error, HEADER_OPERATION, Result, SERVICE_DESCRIBE_FETCH_MAX_BYTES,
    SERVICE_RESOLUTION_FETCH_MAX_BYTES, SERVICE_RESOLUTION_FETCH_TIMEOUT,
};

/// Complete bounded material; transport success grants no authority.
#[derive(Clone, Debug)]
pub struct MaterializedServiceResolution {
    pub resolution: Box<AuthenticatedServiceResolution>,
    pub canonical_bytes: Vec<u8>,
}
impl MaterializedServiceResolution {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn authenticated_resolution(&self) -> &AuthenticatedServiceResolution {
        &self.resolution
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ServiceResolutionFetcher {
    egress_policy: OutboundPolicy,
}

impl Default for ServiceResolutionFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceResolutionFetcher {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            egress_policy: OutboundPolicy::public_https(),
        }
    }

    /// Construct a fetcher with a caller-authorized, target-scoped egress
    /// exception. The carrier itself remains canonical HTTPS regardless.
    #[must_use]
    pub const fn with_egress_policy(egress_policy: OutboundPolicy) -> Self {
        Self { egress_policy }
    }

    /// Materialize an inline or URL carrier without treating it as authority.
    pub async fn materialize(
        &self,
        carrier: &ServiceResolutionCarrier,
        expected_service_id: &DidCoreId,
    ) -> Result<MaterializedServiceResolution> {
        carrier
            .validate_shape(expected_service_id)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        match carrier {
            ServiceResolutionCarrier::Inline { inline } => {
                let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(inline)
                    .map_err(|error| Error::Protocol(error.to_string()))?;
                Ok(MaterializedServiceResolution {
                    resolution: Box::new(inline.clone()),
                    canonical_bytes,
                })
            }
            ServiceResolutionCarrier::ResolutionUrl { resolution_url } => tokio::time::timeout(
                SERVICE_RESOLUTION_FETCH_TIMEOUT,
                self.fetch_url(resolution_url, expected_service_id),
            )
            .await
            .map_err(|_| {
                Error::Protocol("service resolution fetch exceeded 5 seconds".to_owned())
            })?,
        }
    }

    /// Fetch the role-scoped endpoint confirmation from a base URL that the
    /// caller has already authenticated through verified DID method state.
    ///
    /// Transport success is not authority. Callers must validate the typed
    /// description and compare its stable route-binding projection with the
    /// verified DID endpoint before using any dynamic metadata.
    pub async fn fetch_describe(
        &self,
        verified_base_url: &str,
        service_kind: ServiceKind,
    ) -> Result<ServiceDescribe> {
        self.fetch_describe_with_timeout(
            verified_base_url,
            service_kind,
            SERVICE_RESOLUTION_FETCH_TIMEOUT,
        )
        .await
    }

    async fn fetch_describe_with_timeout(
        &self,
        verified_base_url: &str,
        service_kind: ServiceKind,
        timeout: Duration,
    ) -> Result<ServiceDescribe> {
        if !service_kind.valid_in("service_describe") {
            return Err(Error::Protocol(format!(
                "service kind {} is not valid for ServiceDescribe",
                service_kind.as_str()
            )));
        }
        let base = CanonicalServiceUrl::canonicalize(verified_base_url)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if base.to_string() != verified_base_url {
            return Err(Error::Protocol(
                "verified service base URL is not canonical".to_owned(),
            ));
        }
        let mut url = reqwest::Url::parse(&format!("{base}_arkret/describe"))
            .map_err(|error| Error::Protocol(format!("invalid describe URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("service_kind", service_kind.as_str());
        let bytes = tokio::time::timeout(
            timeout,
            self.fetch_bounded(
                url,
                timeout,
                "service describe",
                SERVICE_DESCRIBE_FETCH_MAX_BYTES,
                ServiceOperationId::ServerReadDescribeV1,
            ),
        )
        .await
        .map_err(|_| Error::Protocol("service describe fetch exceeded 5 seconds".to_owned()))??;
        serde_json::from_slice(&bytes)
            .map_err(|error| Error::Protocol(format!("invalid ServiceDescribe JSON: {error}")))
    }

    async fn fetch_url(
        &self,
        resolution_url: &str,
        expected_service_id: &DidCoreId,
    ) -> Result<MaterializedServiceResolution> {
        let parsed = reqwest::Url::parse(resolution_url)
            .map_err(|error| Error::Protocol(format!("invalid service resolution URL: {error}")))?;
        let canonical_bytes = self
            .fetch_bounded(
                parsed,
                SERVICE_RESOLUTION_FETCH_TIMEOUT,
                "service resolution",
                SERVICE_RESOLUTION_FETCH_MAX_BYTES,
                ServiceOperationId::OpenServiceReadResolutionV1,
            )
            .await?;
        let resolution: AuthenticatedServiceResolution =
            arkret_canonical::canonical::from_canonical_json_slice(&canonical_bytes)
                .map_err(|error| Error::Protocol(error.to_string()))?;
        resolution
            .validate_shape(expected_service_id, chrono::Utc::now())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(MaterializedServiceResolution {
            resolution: Box::new(resolution),
            canonical_bytes,
        })
    }

    async fn fetch_bounded(
        &self,
        parsed: reqwest::Url,
        timeout: Duration,
        purpose: &str,
        max_bytes: usize,
        operation: ServiceOperationId,
    ) -> Result<Vec<u8>> {
        let target = EgressGuard::new(self.egress_policy)
            .lock_url_async(&parsed, purpose)
            .await
            .map_err(|error| Error::Protocol(format!("{purpose} target denied: {error}")))?;

        let builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .gzip(false);
        let builder = crate::tls_roots::apply_explicit_tls_roots(builder)?;
        let client = target
            .apply_to_client_builder(builder)
            .build()
            .map_err(|error| {
                Error::Protocol(format!("failed to build pinned {purpose} client: {error}"))
            })?;
        let response = client
            .get(target.url().clone())
            .header(ACCEPT_ENCODING, "identity")
            .header(HEADER_OPERATION, operation.as_str())
            .send()
            .await
            .map_err(crate::client_internals::transport_error)?;
        validate_response_metadata(&response, purpose, max_bytes)?;
        read_body_limited(response, max_bytes).await
    }
}

fn validate_response_metadata(
    response: &reqwest::Response,
    purpose: &str,
    max_bytes: usize,
) -> Result<()> {
    validate_response_shape(
        response.status(),
        response.headers(),
        response.content_length(),
        purpose,
        max_bytes,
    )
}

fn validate_response_shape(
    status: StatusCode,
    headers: &HeaderMap,
    content_length: Option<u64>,
    purpose: &str,
    max_bytes: usize,
) -> Result<()> {
    if status.is_redirection() || !status.is_success() {
        return Err(Error::Protocol(format!(
            "{purpose} fetch returned HTTP {status}"
        )));
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return Err(Error::Protocol(format!(
            "{purpose} response must not carry Content-Encoding"
        )));
    }
    if content_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(Error::Protocol(format!(
            "{purpose} response exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::canonical_service_resolution_path;
    use arkret_wire::ServiceKind;
    use reqwest::header::HeaderValue;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn public_fetcher_rejects_private_target_before_connecting() {
        let service_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let carrier = ServiceResolutionCarrier::ResolutionUrl {
            resolution_url: format!(
                "https://127.0.0.1{}",
                canonical_service_resolution_path(&service_id)
            ),
        };
        let error = ServiceResolutionFetcher::new()
            .materialize(&carrier, &service_id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("target denied"));
    }

    #[test]
    fn transport_limits_are_protocol_hard_bounds() {
        assert_eq!(SERVICE_RESOLUTION_FETCH_MAX_BYTES, 1_048_576);
        assert_eq!(SERVICE_DESCRIBE_FETCH_MAX_BYTES, 1_048_576);
        assert_eq!(SERVICE_RESOLUTION_FETCH_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn response_shape_rejects_redirect_compression_and_oversize() {
        let empty = HeaderMap::new();
        assert!(
            validate_response_shape(
                StatusCode::FOUND,
                &empty,
                Some(0),
                "service resolution",
                SERVICE_RESOLUTION_FETCH_MAX_BYTES,
            )
            .unwrap_err()
            .to_string()
            .contains("HTTP 302")
        );

        let mut compressed = HeaderMap::new();
        compressed.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(
            validate_response_shape(
                StatusCode::OK,
                &compressed,
                Some(32),
                "service resolution",
                SERVICE_RESOLUTION_FETCH_MAX_BYTES,
            )
            .unwrap_err()
            .to_string()
            .contains("Content-Encoding")
        );

        assert!(
            validate_response_shape(
                StatusCode::OK,
                &empty,
                Some(SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64 + 1),
                "service resolution",
                SERVICE_RESOLUTION_FETCH_MAX_BYTES,
            )
            .unwrap_err()
            .to_string()
            .contains("1048576")
        );
        validate_response_shape(
            StatusCode::OK,
            &empty,
            Some(SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64),
            "service resolution",
            SERVICE_RESOLUTION_FETCH_MAX_BYTES,
        )
        .unwrap();
    }

    async fn serve_once(response: String, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4_096];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(response.as_bytes()).await;
        });
        format!("http://{address}/")
    }

    async fn serve_once_and_capture(response: String) -> (reqwest::Url, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4_096];
            let read = stream.read(&mut request).await.unwrap();
            request_tx
                .send(String::from_utf8_lossy(&request[..read]).into_owned())
                .unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (
            reqwest::Url::parse(&format!("http://{address}/")).unwrap(),
            request_rx,
        )
    }

    #[tokio::test]
    async fn bounded_fetch_sends_exact_operation_selector() {
        let fetcher =
            ServiceResolutionFetcher::with_egress_policy(OutboundPolicy::local_development());
        for operation in [
            ServiceOperationId::OpenServiceReadResolutionV1,
            ServiceOperationId::ServerReadDescribeV1,
        ] {
            let (url, request_rx) =
                serve_once_and_capture("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_owned())
                    .await;
            fetcher
                .fetch_bounded(url, Duration::from_secs(1), "test fetch", 2, operation)
                .await
                .unwrap();
            let request = request_rx.await.unwrap().to_ascii_lowercase();
            assert!(request.contains(&format!(
                "{}: {}\r\n",
                HEADER_OPERATION.to_ascii_lowercase(),
                operation.as_str()
            )));
        }
    }

    #[tokio::test]
    async fn describe_fetch_rejects_redirect_and_oversize() {
        let fetcher =
            ServiceResolutionFetcher::with_egress_policy(OutboundPolicy::local_development());
        let redirect = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://elsewhere.invalid/\r\nContent-Length: 0\r\n\r\n"
                .to_owned(),
            Duration::ZERO,
        )
        .await;
        let error = fetcher
            .fetch_describe(&redirect, ServiceKind::Station)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 302"));

        let oversize = serve_once(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                SERVICE_DESCRIBE_FETCH_MAX_BYTES + 1
            ),
            Duration::ZERO,
        )
        .await;
        let error = fetcher
            .fetch_describe(&oversize, ServiceKind::Station)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service describe response exceeds 1048576 bytes")
        );
    }

    #[tokio::test]
    async fn describe_fetch_has_one_total_deadline() {
        let fetcher =
            ServiceResolutionFetcher::with_egress_policy(OutboundPolicy::local_development());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received_tx, received_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0);
            // Headers and a partial body prove the transport has progressed;
            // withholding the final byte requires the same total deadline to
            // terminate the body read, not merely the connection handshake.
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{")
                .await
                .unwrap();
            received_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let request = tokio::spawn(async move {
            fetcher
                .fetch_describe_with_timeout(
                    &format!("http://{address}/"),
                    ServiceKind::Station,
                    Duration::from_secs(5),
                )
                .await
        });
        received_rx.await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(6)).await;
        let error = request.await.unwrap().unwrap_err().to_string();
        assert!(
            error.contains("exceeded 5 seconds") || error.contains("timed out"),
            "{error}"
        );
        server.abort();
    }
}
