//! Compatibility re-exports for service discovery metadata.
//!
//! Endpoint binding allowlists, describe-verification requirements, and
//! metadata wire shapes are owned by `arkret-models-discovery`.

pub use arkret_models_discovery::service_requirements::{
    ApiConventionMetadata, DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY, HttpTraceMetadata,
    NotFoundPrivacy, QuotaKind, QuotaMetadata, RateLimitMetadata, RateLimitScopeKind,
    ServiceEndpointBinding, ServiceIdAllowlist, ServiceRequirements,
};
