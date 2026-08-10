//! Hardened transport-only materialization of service-resolution carriers.
//!
//! Fetch success never establishes service authority. Callers must still
//! verify the returned record proof, method history, freshness, successor
//! chain and route binding before using its URL.

use std::net::SocketAddr;
use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_models_identity::{
    ServiceResolutionCarrier, ServiceResolutionRecord, validate_service_current_record_url,
};
use arkret_wire::{Hash, ServiceId};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap};

use crate::client_internals::read_body_limited;
use crate::{Error, Result};

pub const SERVICE_RESOLUTION_FETCH_MAX_BYTES: usize = 64 * 1024;
pub const SERVICE_RESOLUTION_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// A bounded canonical record whose transport locator was checked, but whose
/// cryptographic and method-native authority has not yet been verified.
#[derive(Clone, Debug)]
pub struct UnverifiedServiceResolutionRecord {
    record: ServiceResolutionRecord,
    canonical_bytes: Vec<u8>,
}

impl UnverifiedServiceResolutionRecord {
    #[must_use]
    pub fn record(&self) -> &ServiceResolutionRecord {
        &self.record
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn into_record(self) -> ServiceResolutionRecord {
        self.record
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
        expected_service_id: &ServiceId,
    ) -> Result<UnverifiedServiceResolutionRecord> {
        carrier
            .validate_shape(expected_service_id)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        match carrier {
            ServiceResolutionCarrier::Inline { inline } => {
                let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(inline)
                    .map_err(|error| Error::Protocol(error.to_string()))?;
                Ok(UnverifiedServiceResolutionRecord {
                    record: inline.clone(),
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

    async fn fetch_url(
        &self,
        current_record_url: &str,
        pinned_record_digest: Option<&Hash>,
        expected_service_id: &ServiceId,
    ) -> Result<UnverifiedServiceResolutionRecord> {
        let parsed = reqwest::Url::parse(current_record_url)
            .map_err(|error| Error::Protocol(format!("invalid service resolution URL: {error}")))?;
        self.egress_policy.validate_url(&parsed).map_err(|error| {
            Error::Protocol(format!("service resolution target denied: {error}"))
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::Protocol("service resolution URL has no host".to_owned()))?
            .to_owned();
        let port = parsed.port_or_known_default().ok_or_else(|| {
            Error::Protocol("service resolution URL has no usable port".to_owned())
        })?;
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| Error::Protocol(format!("service resolution DNS failed: {error}")))?
            .collect();
        let target = self
            .egress_policy
            .bind_resolved(parsed, addresses)
            .map_err(|error| {
                Error::Protocol(format!("service resolution target denied: {error}"))
            })?;

        let client = reqwest::Client::builder()
            .timeout(SERVICE_RESOLUTION_FETCH_TIMEOUT)
            .connect_timeout(SERVICE_RESOLUTION_FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .gzip(false)
            .resolve_to_addrs(&host, target.addresses())
            .build()
            .map_err(|error| {
                Error::Protocol(format!("failed to build pinned resolution client: {error}"))
            })?;
        let response = client
            .get(target.url().clone())
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(crate::client_internals::transport_error)?;
        validate_response_metadata(&response)?;
        let canonical_bytes =
            read_body_limited(response, SERVICE_RESOLUTION_FETCH_MAX_BYTES).await?;
        let record: ServiceResolutionRecord =
            arkret_canonical::canonical::from_canonical_json_slice(&canonical_bytes)
                .map_err(|error| Error::Protocol(error.to_string()))?;
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
        Ok(UnverifiedServiceResolutionRecord {
            record,
            canonical_bytes,
        })
    }
}

fn validate_response_metadata(response: &reqwest::Response) -> Result<()> {
    validate_response_shape(
        response.status(),
        response.headers(),
        response.content_length(),
    )
}

fn validate_response_shape(
    status: StatusCode,
    headers: &HeaderMap,
    content_length: Option<u64>,
) -> Result<()> {
    if status.is_redirection() || !status.is_success() {
        return Err(Error::Protocol(format!(
            "service resolution fetch returned HTTP {}",
            status
        )));
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return Err(Error::Protocol(
            "service resolution response must not carry Content-Encoding".to_owned(),
        ));
    }
    if content_length.is_some_and(|length| length > SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64) {
        return Err(Error::Protocol(
            "service resolution response exceeds 65536 bytes".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::canonical_service_current_record_path;
    use reqwest::header::HeaderValue;

    use super::*;

    #[tokio::test]
    async fn public_fetcher_rejects_private_target_before_connecting() {
        let service_id = ServiceId::new("ak:did_core:webvh:z6mkfixture").unwrap();
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
        assert_eq!(SERVICE_RESOLUTION_FETCH_MAX_BYTES, 65_536);
        assert_eq!(SERVICE_RESOLUTION_FETCH_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn response_shape_rejects_redirect_compression_and_oversize() {
        let empty = HeaderMap::new();
        assert!(
            validate_response_shape(StatusCode::FOUND, &empty, Some(0))
                .unwrap_err()
                .to_string()
                .contains("HTTP 302")
        );

        let mut compressed = HeaderMap::new();
        compressed.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(
            validate_response_shape(StatusCode::OK, &compressed, Some(32))
                .unwrap_err()
                .to_string()
                .contains("Content-Encoding")
        );

        assert!(
            validate_response_shape(
                StatusCode::OK,
                &empty,
                Some(SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64 + 1),
            )
            .unwrap_err()
            .to_string()
            .contains("65536")
        );
        validate_response_shape(
            StatusCode::OK,
            &empty,
            Some(SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64),
        )
        .unwrap();
    }
}
