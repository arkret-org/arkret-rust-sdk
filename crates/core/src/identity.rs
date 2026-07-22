//! Transitional identity model and helper re-exports.

/// Deterministic primary-handle selection and rendering helpers.
pub mod primary_handle;

pub use arkret_models_identity::{
    DID_WEB_MAX_DOCUMENT_BYTES, DID_WEBVH_V1_METHOD, DidDocument, HandleAttestation,
    did_web_document_url, principal_control_realm_id, validate_did_webvh_v1_method,
};
