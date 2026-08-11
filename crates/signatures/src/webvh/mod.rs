//! Shared `did:webvh` builders.
//!
//! Principal builders borrow recovery-derived cold-root material and publish a
//! pre-rotation commitment without returning the secret. Service builders keep
//! their independent operational-key lifecycle. HTTP submission stays with the
//! caller.

pub mod inception;

pub use inception::{
    ManagedAgentBindingUpdateInput, ManagedAgentInceptionInput, PreparedInception,
    PreparedPrincipalInception, PreparedPrincipalRotation, PreparedWebvhRelocation,
    PrincipalInceptionInput, PrincipalRotationInput, ServiceInceptionInput,
    ServiceRegistrationInceptionInput, SubmittedInception, SuppliedPrincipalInceptionInput,
    ValidatedPrincipalInception, ValidatedWebvhHistoryPoint, WebvhInceptionError,
    WebvhRelocationInput, prepare_managed_agent_binding_update, prepare_managed_agent_inception,
    prepare_portable_principal_inception, prepare_principal_inception, prepare_principal_rotation,
    prepare_service_inception, prepare_service_inception_with_did_key_seed,
    prepare_service_registration_inception,
    prepare_service_registration_inception_with_did_key_seed, prepare_supplied_principal_inception,
    prepare_webvh_relocation, sign_identity_creation_control_proof,
    sign_registration_did_evidence_draft, validate_managed_agent_did_document_profile,
    validate_principal_did_document_profile, validate_principal_inception_operation,
    validate_webvh_history_at, verify_identity_creation_control_proof,
    verify_registration_did_evidence_draft, webvh_next_key_hash,
};
