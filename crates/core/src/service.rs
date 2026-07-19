//! Server-side `ErrorEnvelope` constructors for the API conventions
//! (privacy-preserving not-found, rate-limit, quota). The endpoint
//! binding allowlists, describe-verification requirements, and metadata
//! wire shapes migrated to `arkret-models-discovery` (re-exported
//! below).

pub use arkret_models_discovery::service_requirements::{
    ApiConventionMetadata, DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY, HttpTraceMetadata,
    NotFoundPrivacy, QuotaKind, QuotaMetadata, RateLimitMetadata, RateLimitScopeKind,
    ServiceEndpointBinding, ServiceIdAllowlist, ServiceRequirements,
};
use serde_json::Value;

use crate::ErrorEnvelope;

pub fn privacy_preserving_not_found(trace: Option<HttpTraceMetadata>) -> ErrorEnvelope {
    let mut envelope = ErrorEnvelope::new("not_found", "Resource not found").with_detail(
        "not_found_privacy",
        Value::String("hide_nonexistent_and_invisible".to_owned()),
    );
    if let Some(trace) = trace {
        envelope =
            envelope.with_detail("trace", serde_json::to_value(trace).unwrap_or(Value::Null));
    }
    envelope
}

pub fn rate_limited_error(metadata: RateLimitMetadata) -> ErrorEnvelope {
    ErrorEnvelope::new("rate_limited", "Too many requests")
        .with_retry_after_ms(metadata.retry_after_ms)
        .with_detail(
            "rate_limit",
            serde_json::to_value(metadata).unwrap_or(Value::Null),
        )
}

pub fn quota_exceeded_error(metadata: QuotaMetadata) -> ErrorEnvelope {
    ErrorEnvelope::new("quota_exceeded", "Quota exceeded").with_detail(
        "quota",
        serde_json::to_value(metadata).unwrap_or(Value::Null),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Did, RealmId};

    #[test]
    fn api_metadata_errors_carry_privacy_rate_limit_quota_and_trace() {
        let trace = HttpTraceMetadata {
            request_id: Some("req_123".to_owned()),
            actor_id: Some(Did::new("did:webvh:z6mkfixture:alice.example").unwrap()),
            device_id: None,
            realm_id: Some(RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()),
            operation_id: None,
        };
        let not_found = privacy_preserving_not_found(Some(trace));
        assert_eq!(not_found.code(), "not_found");
        assert_eq!(
            not_found.details()["not_found_privacy"],
            "hide_nonexistent_and_invisible"
        );
        assert!(not_found.details()["trace"].is_object());

        let rate_limited = rate_limited_error(RateLimitMetadata {
            scope: RateLimitScopeKind::Actor,
            subject: "did:webvh:z6mkfixture:alice.example".to_owned(),
            limit: 60,
            remaining: 0,
            reset_at: None,
            retry_after_ms: Some(1000),
        });
        assert_eq!(rate_limited.retry_after_ms(), Some(1000));
        assert_eq!(rate_limited.details()["rate_limit"]["scope"], "actor");

        let quota = quota_exceeded_error(QuotaMetadata {
            quota: QuotaKind::BlobBytes,
            subject: "did:webvh:z6mkfixture:alice.example".to_owned(),
            limit: 1024,
            used: 2048,
            unit: "bytes".to_owned(),
        });
        assert_eq!(quota.details()["quota"]["quota"], "blob_bytes");
    }
}
