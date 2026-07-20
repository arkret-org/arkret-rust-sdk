//! Service identity: wire contract + runtime shim.
//!
//! The registration wire contract (canonical URLs, registration keys, DID
//! documents, WebVH inception operations, receipts, ensure request/outcome
//! DTOs) is owned by `arkret_models_identity::service_identity`. The runtime
//! side (local identity state, identity bundles, and their file / KeyStore
//! persistence backends) moved to `arkret_identity::service_identity` in batch
//! 4c. Core re-exports both halves so downstream `arkret_core::` / `arkret_sdk::`
//! paths stay byte-stable until the facade retires.

pub use arkret_identity::service_identity::{
    FileIdentityBundleBackend, IdentityBundleBackend, IdentityBundleBackendAvailability,
    KeyStoreIdentityBundleBackend, LocalServiceIdentity, ResolvedService, ServiceIdentityBundle,
    ServiceIdentityDiagnostic, ServiceIdentityKeyRef, ServiceIdentityProviderRef,
    ServiceIdentityState, StoredServiceIdentity,
};
pub use arkret_models_identity::service_identity::*;
