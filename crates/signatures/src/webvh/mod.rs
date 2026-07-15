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
    SubmittedInception, SuppliedPrincipalInceptionInput, WebvhInceptionError,
    prepare_principal_inception, prepare_principal_rotation, prepare_service_inception,
    prepare_service_inception_with_did_key_seed, prepare_service_registration_inception,
    prepare_service_registration_inception_with_did_key_seed, prepare_supplied_principal_inception,
    validate_principal_did_document_profile, webvh_next_key_hash,
};
