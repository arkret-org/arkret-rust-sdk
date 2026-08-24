//! Canonical signatures, proof binding and HTTP message signature helpers.

mod development_identity;
// The single `eddsa-jcs-2022` Data Integrity cryptosuite. Unconditional: the
// did:webvh builders, the resolver, starid and the joint conformance harness
// all sign or verify with it, and only some of them enable `webvh`.
pub mod eddsa_jcs_2022;
pub mod frozen_notary;
pub mod http_signature;
#[cfg(feature = "collaboration")]
pub mod media;
#[cfg(feature = "service-identity")]
pub mod service_resolution;

// RFC 9421 federation trust-domain transcript fragment. Pure wire-string
// formatting (no crypto/model deps), so it is available without the
// model features alongside the other HTTP message-signature helpers.
pub mod federation;

pub use development_identity::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
};
pub use eddsa_jcs_2022::{
    DATA_INTEGRITY_PROOF_TYPE, DataIntegrityProofPurpose, EDDSA_JCS_2022_CRYPTOSUITE,
    EddsaJcs2022Error, build_eddsa_jcs_2022_proof, eddsa_jcs_2022_proof_config,
    eddsa_jcs_2022_signing_input, verify_eddsa_jcs_2022_proof,
};
pub use frozen_notary::{verify_frozen_notary_detached_jws, verify_frozen_notary_signature};

// Agent key-pairing canonical binding digests. Gated by `collaboration` because
// they validate against the `PublicKey` wire model owned by
// arkret-models-collaboration.
#[cfg(feature = "collaboration")]
pub mod account_status;
#[cfg(feature = "collaboration")]
pub mod agent;
#[cfg(feature = "collaboration")]
pub mod agent_evidence;
#[cfg(feature = "collaboration")]
pub mod contact_receipt;
#[cfg(feature = "collaboration")]
mod device_authorization;
#[cfg(feature = "collaboration")]
pub mod device_pairing;

#[cfg(feature = "keypackages")]
pub mod device_projection;
#[cfg(feature = "keypackages")]
pub mod keypackages;

mod protocol_api;
pub use protocol_api::*;
