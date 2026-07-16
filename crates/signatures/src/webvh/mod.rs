//! Shared `did:webvh` builders.
//!
//! Principal builders borrow recovery-derived cold-root material and publish a
//! pre-rotation commitment without returning the secret. Service builders keep
//! their independent operational-key lifecycle. HTTP submission stays with the
//! caller.

pub mod inception;

pub use inception::{
    PreparedInception, PreparedPrincipalInception, PreparedPrincipalRotation,
    PrincipalDidDocumentProfile, PrincipalEnrollmentDelegation, PrincipalInceptionInput,
    PrincipalRotationInput, ServiceInceptionInput, ServiceRegistrationInceptionInput,
    SubmittedInception, SuppliedPrincipalInceptionInput, ValidatedPrincipalInception,
    WebvhInceptionError, prepare_principal_inception, prepare_principal_rotation,
    prepare_service_inception, prepare_service_inception_with_did_key_seed,
    prepare_service_registration_inception,
    prepare_service_registration_inception_with_did_key_seed, prepare_supplied_principal_inception,
    sign_identity_creation_control_proof, validate_principal_did_document_profile,
    validate_principal_inception_operation, verify_identity_creation_control_proof,
    webvh_next_key_hash,
};
