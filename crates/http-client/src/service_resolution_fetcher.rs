//! Hardened transport-only materialization of service-resolution carriers.
//!
//! Fetch success never establishes service authority. Callers must still
//! verify the returned record proof, method history, freshness, successor
//! chain and route binding before using its URL.

use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_egress_reqwest::EgressGuard;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionCarrier, ServiceResolutionRecord,
    validate_service_current_record_url,
};
use arkret_wire::{DidCoreId, Hash, ServiceKind};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap};

use crate::client_internals::read_body_limited;
use crate::{Error, Result};

pub const SERVICE_RESOLUTION_FETCH_MAX_BYTES: usize = 1024 * 1024;
pub const SERVICE_DESCRIBE_FETCH_MAX_BYTES: usize = 1024 * 1024;
pub const SERVICE_RESOLUTION_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// A bounded canonical record whose transport locator was checked, but whose
/// cryptographic and method-native authority has not yet been verified.
#[derive(Clone, Debug)]
pub enum MaterializedServiceResolution {
    InlineRecord {
        record: Box<ServiceResolutionRecord>,
        canonical_bytes: Vec<u8>,
    },
    AuthenticatedResolution {
        resolution: Box<AuthenticatedServiceResolution>,
        canonical_bytes: Vec<u8>,
    },
}

impl MaterializedServiceResolution {
    #[must_use]
    pub fn record(&self) -> &ServiceResolutionRecord {
        match self {
            Self::InlineRecord { record, .. } => record,
            Self::AuthenticatedResolution { resolution, .. } => {
                &resolution.service_resolution_record
            }
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::InlineRecord {
                canonical_bytes, ..
            }
            | Self::AuthenticatedResolution {
                canonical_bytes, ..
            } => canonical_bytes,
        }
    }

    #[must_use]
    pub fn authenticated_resolution(&self) -> Option<&AuthenticatedServiceResolution> {
        match self {
            Self::InlineRecord { .. } => None,
            Self::AuthenticatedResolution { resolution, .. } => Some(resolution),
        }
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
                Ok(MaterializedServiceResolution::InlineRecord {
                    record: Box::new(inline.clone()),
                    canonical_bytes,
                })
            }
            ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url,
                pinned_record_digest,
            } => tokio::time::timeout(
                SERVICE_RESOLUTION_FETCH_TIMEOUT,
                self.fetch_url(
                    current_record_url,
                    pinned_record_digest.as_ref(),
                    expected_service_id,
                ),
            )
            .await
            .map_err(|_| {
                Error::Protocol("service resolution fetch exceeded 5 seconds".to_owned())
            })?,
        }
    }

    /// Fetch the role-scoped endpoint confirmation from a base URL that the
    /// caller has already authenticated through a signed
    /// `ServiceResolutionRecord`.
    ///
    /// Transport success is not authority. Callers must validate the typed
    /// description and compare its stable route-binding projection with the
    /// signed record before using any dynamic metadata.
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
            ),
        )
        .await
        .map_err(|_| Error::Protocol("service describe fetch exceeded 5 seconds".to_owned()))??;
        serde_json::from_slice(&bytes)
            .map_err(|error| Error::Protocol(format!("invalid ServiceDescribe JSON: {error}")))
    }

    async fn fetch_url(
        &self,
        current_record_url: &str,
        pinned_record_digest: Option<&Hash>,
        expected_service_id: &DidCoreId,
    ) -> Result<MaterializedServiceResolution> {
        let parsed = reqwest::Url::parse(current_record_url)
            .map_err(|error| Error::Protocol(format!("invalid service resolution URL: {error}")))?;
        let canonical_bytes = self
            .fetch_bounded(
                parsed,
                SERVICE_RESOLUTION_FETCH_TIMEOUT,
                "service resolution",
                SERVICE_RESOLUTION_FETCH_MAX_BYTES,
            )
            .await?;
        let resolution: AuthenticatedServiceResolution =
            arkret_canonical::canonical::from_canonical_json_slice(&canonical_bytes)
                .map_err(|error| Error::Protocol(error.to_string()))?;
        let record = &resolution.service_resolution_record;
        if &record.record.service_id != expected_service_id {
            return Err(Error::Protocol(
                "fetched service resolution targets a different service".to_owned(),
            ));
        }
        validate_service_current_record_url(&record.record.current_record_url, expected_service_id)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if let Some(expected_digest) = pinned_record_digest {
            let actual = Hash::new(arkret_canonical::canonical_sha256(&record)?)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            if &actual != expected_digest {
                return Err(Error::Protocol(
                    "fetched service resolution does not match its pinned digest".to_owned(),
                ));
            }
        }
        Ok(MaterializedServiceResolution::AuthenticatedResolution {
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
        let builder = apply_explicit_tls_roots(builder)?;
        let client = target
            .apply_to_client_builder(builder)
            .build()
            .map_err(|error| {
                Error::Protocol(format!("failed to build pinned {purpose} client: {error}"))
            })?;
        let response = client
            .get(target.url().clone())
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(crate::client_internals::transport_error)?;
        validate_response_metadata(&response, purpose, max_bytes)?;
        read_body_limited(response, max_bytes).await
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "tls-rustls"))]
fn apply_explicit_tls_roots(builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(builder);
    };
    let path = std::path::PathBuf::from(path);
    let pem = std::fs::read(&path).map_err(|error| {
        Error::Protocol(format!(
            "failed to read SSL_CERT_FILE {}: {error}",
            path.display()
        ))
    })?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        Error::Protocol(format!(
            "SSL_CERT_FILE {} contains no valid PEM certificate: {error}",
            path.display()
        ))
    })?;
    // SSL_CERT_FILE is an explicit trust-store override. Keep hostname
    // verification enabled, but avoid the platform verifier so ephemeral and
    // private deployment roots are evaluated consistently by rustls/webpki.
    Ok(builder.tls_backend_rustls().tls_certs_only(certificates))
}

#[cfg(not(all(not(target_arch = "wasm32"), feature = "tls-rustls")))]
fn apply_explicit_tls_roots(builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
    Ok(builder)
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
    use arkret_models_identity::canonical_service_current_record_path;
    use arkret_wire::ServiceKind;
    use reqwest::header::HeaderValue;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn public_fetcher_rejects_private_target_before_connecting() {
        let service_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let carrier = ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: format!(
                "https://127.0.0.1{}",
                canonical_service_current_record_path(&service_id)
            ),
            pinned_record_digest: None,
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
            .fetch_describe(&redirect, ServiceKind::PrincipalServer)
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
            .fetch_describe(&oversize, ServiceKind::PrincipalServer)
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
        let base = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_owned(),
            Duration::from_millis(100),
        )
        .await;
        let started = tokio::time::Instant::now();
        let _error = fetcher
            .fetch_describe_with_timeout(
                &base,
                ServiceKind::PrincipalServer,
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(80));
    }
}
