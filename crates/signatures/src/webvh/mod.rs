//! Shared `did:webvh` builders.
//!
//! [`skeleton`] owns the method-native construction contract — the `{SCID}`
//! placeholder scope, SCID derivation and the entry-hash pre-image — and has no
//! model dependency, so every producer and verifier can use it. [`inception`]
//! builds the typed Arkret DID-operation bodies on top of it.
//!
//! Principal builders borrow recovery-derived cold-root material and publish a
//! pre-rotation commitment without returning the secret. Service builders keep
//! their independent operational-key lifecycle. HTTP submission stays with the
//! caller.

pub mod skeleton;

pub use skeleton::{
    WEBVH_METHOD_VERSION, WEBVH_SCID_PLACEHOLDER, WebvhInceptionSkeletonInput, WebvhSkeletonError,
    build_webvh_inception_skeleton, derive_webvh_scid, finalize_webvh_scid_substitution,
    format_webvh_did, substitute_webvh_scid, webvh_authority_pair, webvh_entry_hash_multibase,
    webvh_entry_hash_preimage, webvh_next_key_hash_value, webvh_placeholder_did,
    webvh_scid_placeholder_present, webvh_scid_preimage,
};

#[cfg(feature = "webvh")]
pub mod inception;

#[cfg(feature = "webvh")]
pub use inception::{
    AgentBindingUpdateInput, AgentInceptionInput, PreparedInception, PreparedPrincipalInception,
    PreparedPrincipalRotation, PreparedWebvhRelocation, PrincipalInceptionInput,
    PrincipalRotationInput, ServiceInceptionInput, ServiceRegistrationInceptionInput,
    SubmittedInception, SuppliedPrincipalInceptionInput, ValidatedPrincipalInception,
    ValidatedWebvhHistoryPoint, WebvhInceptionError, WebvhRelocationInput,
    prepare_agent_binding_update, prepare_agent_inception, prepare_portable_principal_inception,
    prepare_principal_inception, prepare_principal_portability_update, prepare_principal_rotation,
    prepare_service_inception, prepare_service_inception_with_did_key_seed,
    prepare_service_registration_inception,
    prepare_service_registration_inception_with_assertion_keys,
    prepare_service_registration_inception_with_did_key_seed, prepare_supplied_principal_inception,
    prepare_webvh_relocation, sign_did_webvh_witness_proof, sign_identity_creation_control_proof,
    sign_registration_did_evidence_draft, validate_agent_did_document_profile,
    validate_principal_did_document_profile, validate_principal_inception_operation,
    validate_webvh_history_at, verify_identity_creation_control_proof,
    verify_registration_did_evidence_draft, webvh_next_key_hash,
};
