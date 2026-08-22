//! Arkret v1 DID identity behavior layer.
//!
//! DID resolution (`did:key` / `did:web` / `did:webvh`, composite + caching),
//! handle-claim challenges, DID key-log records with controller proofs, and the
//! DID-resolver-driven detached-JWS verify pipeline. Depends only on the wire /
//! model / signature data crates and the outbound egress classifier; the
//! umbrella `arkret` crate re-exports this surface under `arkret::identity::*`.

pub mod authority_history;
mod error;
mod handles;
// DID-P0-B01/B02/B03: verified DID binding value object, its store contract and
// the resolver-free / authority verifier split (`did-usage-and-verification.md`
// §4–§6).
pub mod binding;
// The canonical §5 binding contracts (evidence receipt, resolver policy
// snapshot, evidence dependencies), so six services stop each inventing their
// own digest inputs.
pub mod binding_digest;
pub mod binding_store;
pub(crate) mod helpers;
pub mod history_recovery;
pub mod jws;
mod records;
mod resolvers;
pub mod service_identity;
pub mod service_resolution_evidence;
#[cfg(test)]
mod tests;
pub mod verifier;

// Data types the identity behavior operates on, re-exported so the umbrella
// `arkret` crate can surface `arkret::identity::*`. Internal shared names the
// modules reach through `use super::*` / `use crate::*`.
pub(crate) use std::collections::BTreeMap;

pub use arkret_models_identity::primary_handle::{
    DidDocumentSnapshotResolver, HandleIssuerAuthorityClass, HandleIssuerPolicyEntry,
    MentionRender, NoHolderPreferenceResolver, PrimaryHandleSelectInput, SubjectRender,
    claim_digest, render_mention, render_subject, select_primary_handle,
    select_primary_handle_string,
};
pub use arkret_models_identity::{DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, HandleAttestation};
pub(crate) use arkret_wire::{DidUrl, Event, Hash, Proof};
// DID-P0-B: flat re-exports of the verified-binding surface, so downstream
// repos consume one shared model (`arkret_identity::VerifiedDidBinding`, or
// `arkret::identity::*` through the umbrella) instead of inventing parallel
// per-service types.
pub use authority_history::{
    AuthorityDidHistoryResolver, AuthorityHistoryUnavailable, AuthorityHistoryVerificationError,
    VerifiedAccountBindingReceipt, verify_account_binding_receipt_at_issuance,
};
pub use binding::{
    BindingError, DidBindingPurpose, DidBindingStatus, FreshnessProfile, FreshnessRequirement,
    FreshnessRiskTier, LimitedTrust, PinState, StaleBehavior, VerifiedDidBinding,
    VerifiedDidBindingDocumentInput, VerifiedDidBindingInput, VerifiedDidBindingKey,
    document_canonical_digest,
};
pub use binding_digest::{
    BASE_RESOLVER_POLICY_PROFILE, DigestError, EVIDENCE_RECEIPT_KIND, EvidenceDependencies,
    EvidenceReceipt, MethodEvidence, MethodEvidenceProof, RESOLVER_POLICY_SNAPSHOT_KIND,
    ResolverPolicyProfile, ResolverPolicySnapshot, WebvhLogEvidence, WebvhWitnessRow,
    normalize_did_method_prefix, policy_digest,
};
pub use binding_store::{
    AcceptedDidBinding, BindingFreshness, BindingInvalidation, BindingStoreError,
    InMemoryVerifiedDidBindingStore, VerifiedDidBindingStore, binding_freshness_at,
};
pub(crate) use chrono::{DateTime, Utc};
pub(crate) use error::IdentityError as Error;
pub use error::{IdentityError, Result};
pub use handles::*;
pub(crate) use helpers::*;
/// Public re-export of the `did:webvh` splitter + outbound SSRF egress guard so
/// downstream crates (e.g. starid) reuse the low-level classifier instead of
/// re-implementing address tables (STA-05-001).
pub use helpers::{DidWebvhUrlError, did_webvh_parts, host_is_safe_for_outbound, ip_is_public};
pub use records::*;
pub use resolvers::*;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde_json::Value;
pub use service_resolution_evidence::*;
pub use verifier::{
    BindingResolveError, BindingResolveRequest, BindingVerifyError, DidVerificationRelationship,
    public_key_material_from_binding, public_key_material_from_document,
    resolve_and_verify_binding, verify_event_proof_with_binding,
    verify_event_proof_with_binding_for_event, verify_jws_with_binding, verify_jws_with_document,
    verify_jws_with_document_relationship,
};
