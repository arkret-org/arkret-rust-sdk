//! Signature verification and DID authority resolution — deliberately split
//! (`did-usage-and-verification.md` §1, §4 and §6).
//!
//! # Two independent counters
//!
//! **Per-signature verification** and **per-signature DID resolution** are two
//! separate counts, and only the first one scales with traffic:
//!
//! | counter | grows with | who drives it |
//! | --- | --- | --- |
//! | `signature_verify_count` | every signed object ingested | [`verify_jws_with_document`] / [`verify_jws_with_binding`] / [`verify_event_proof_with_binding`] |
//! | `authority_network_call_count` | §4 trigger scenarios only | [`resolve_and_verify_binding`] / [`resolve_and_verify_binding_with_evidence`] |
//!
//! # Picking the right ordinary entry point
//!
//! | signed object | entry point | what the JWS covers |
//! | --- | --- | --- |
//! | Event [`Proof`] | [`verify_event_proof_with_binding`] | the canonical **proof binding object** (`encoding.md` §6) |
//! | anything else (auth data, receipts, handle claims) | [`verify_jws_with_binding`] | the canonical bytes you pass in |
//!
//! Routing an Event proof through [`verify_jws_with_binding`] verifies the wrong
//! transcript *and* silently relaxes two protected-header checks — see
//! [`verify_event_proof_with_binding`] for the comparison table.
//!
//! Verifying N signatures against one accepted binding costs **N** signature
//! verifications and **0** resolver calls. That property is enforced at the type
//! level here, not by convention: [`verify_jws_with_document`] and
//! [`verify_jws_with_binding`] take no
//! [`DidResolver`](crate::DidResolver) parameter at all, so they physically
//! cannot reach the network. `crates/identity/tests/binding_resolver_spy.rs`
//! proves the same thing with a counting resolver.
//!
//! # Choosing a path
//!
//! Use the **ordinary path** ([`verify_jws_with_binding`], or
//! [`verify_jws_with_document`] when the caller already pinned a historical
//! document) when the signed object's key comes from an already-accepted
//! Seal / auth-state, device authorization, agent signer evidence or a pinned
//! historical binding. §3 lists these explicitly as identity-anchor operations:
//! reading and rendering objects, equality / membership / routing, ordinary
//! Event submission under an accepted key epoch, replay and backfill against
//! pinned material, and cached verification badges. Verifying a signature is
//! **not** re-verifying a DID.
//!
//! Use the **authority path** ([`resolve_and_verify_binding`]) only when the
//! call site can name a row of the §4 closed trigger table:
//!
//! 1. a DID crossing this trust domain's boundary for the first time;
//! 2. account registration / claim / recovery / service-account binding;
//! 3. a new `verification_method`, device generation, agent signer epoch, service signing key or
//!    controller;
//! 4. rotation, recovery, deactivation, method continuity, or service endpoint / delegation change;
//! 5. a new service DID entering a federation / media / push / audit / directory / policy
//!    allowlist;
//! 6. membership / MLS admission of a previously unaccepted principal, pairwise DID or delivery
//!    service binding;
//! 7. an explicitly required freshness that has expired, or a received rotation / deactivation /
//!    witness-fork / policy-change invalidation;
//! 8. verifying a third-party claim / receipt / attestation whose issuer key has no accepted
//!    binding here.
//!
//! §4 closes the list: "outside these triggers, business code MUST NOT add a
//! 'resolve once more to be safe' path." If a call site cannot point at a row,
//! it is an identity-anchor path and belongs on the ordinary API.

use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::{Did, DidUrl, Event, Hash, Proof, TypedTrustDomainId};
use chrono::{DateTime, Duration, Utc};

use crate::binding::{
    BindingError, DidBindingPurpose, DidBindingStatus, FreshnessRequirement, LimitedTrustReason,
    VerifiedDidBinding, VerifiedDidBindingDocumentInput, VerifiedDidBindingKey,
    document_canonical_digest,
};
use crate::binding_store::{
    AcceptedDidBinding, BindingFreshness, BindingStoreError, VerifiedDidBindingStore,
};
use crate::{DidDocument, DidResolver};

// ============================================================================
// Ordinary (resolver-free) verification
// ============================================================================

/// Typed failures of the resolver-free verify path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindingVerifyError {
    /// Empty canonical bytes — nothing to bind the signature to.
    #[error("empty canonical bytes")]
    EmptyCanonicalBytes,
    /// The pinned document is not the issuer's document.
    ///
    /// The legacy [`crate::jws::verify_jws_ed25519`] accepted an `issuer`
    /// argument and never compared it; this path compares it.
    #[error("DID document id `{document_id}` does not match issuer `{issuer}`")]
    DocumentIssuerMismatch { document_id: Did, issuer: Did },
    /// The verification method is not controlled by the issuer DID.
    #[error("verification_method `{verification_method}` is not controlled by issuer `{issuer}`")]
    VerificationMethodIssuerMismatch {
        verification_method: String,
        issuer: Did,
    },
    /// The DID document has no matching verification-method entry.
    #[error(
        "verification_method `{verification_method}` not found in DID document for `{did}` (have {available:?})"
    )]
    VerificationMethodNotFound {
        verification_method: String,
        did: Did,
        available: Vec<String>,
    },
    /// The stored verification material is not a usable Ed25519 public key.
    #[error("verification method public key material rejected: {reason}")]
    PublicKeyMaterial { reason: String },
    /// JWS shape / header / signature rejected.
    #[error("detached JWS rejected: {source}")]
    Proof {
        #[source]
        source: arkret_signatures::VerifierError,
    },
    /// The binding's status forbids ordinary verification.
    #[error("binding status `{status}` is not usable for ordinary verification")]
    BindingStatusNotUsable { status: DidBindingStatus },
    /// The presented verification method is not the one the binding accepted.
    #[error(
        "binding accepted verification_method `{accepted}` but the proof presents `{presented}`"
    )]
    BindingVerificationMethodMismatch { accepted: String, presented: String },
    /// The pinned document no longer matches the binding's digest.
    #[error("pinned document digest {actual} does not match the binding digest {expected}")]
    BindingDocumentDigestMismatch { expected: Hash, actual: Hash },
    /// The pinned document could not be digested.
    #[error("pinned document digest could not be computed: {0}")]
    Digest(String),
    /// The Event envelope could not be canonicalized into signing bytes.
    #[error("event envelope canonicalization failed: {0}")]
    EventCanonicalization(String),
}

/// Verify a detached Ed25519 JWS against an **already-pinned** DID document.
///
/// Zero network calls by construction: this function has no
/// [`DidResolver`](crate::DidResolver) parameter, so it cannot resolve anything
/// even by mistake.
///
/// Checks, in order:
///
/// 1. `canonical_bytes` is non-empty;
/// 2. `verification_method`'s DID part equals `issuer`;
/// 3. `document.id == issuer` — the argument the legacy `verify_jws_ed25519` accepted and silently
///    ignored;
/// 4. `verification_method` resolves inside `document` (full DID URL, then fragment-only id, then
///    the `did:key` single-key shortcut — the exact lookup order of
///    [`crate::resolve_verification_method_key_from_document`], because DID Document
///    `verificationMethod[].id` entries are commonly relative `#key-1` references);
/// 5. the material decodes to an Ed25519 key (multibase or JWK);
/// 6. the detached JWS verifies over `canonical_bytes`.
pub fn verify_jws_with_document(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &DidUrl,
    issuer: &Did,
    document: &DidDocument,
) -> Result<(), BindingVerifyError> {
    if canonical_bytes.is_empty() {
        return Err(BindingVerifyError::EmptyCanonicalBytes);
    }

    let method_did = verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method.as_str());
    if method_did != issuer.as_str() {
        return Err(BindingVerifyError::VerificationMethodIssuerMismatch {
            verification_method: verification_method.as_str().to_owned(),
            issuer: issuer.clone(),
        });
    }

    if &document.id != issuer {
        return Err(BindingVerifyError::DocumentIssuerMismatch {
            document_id: document.id.clone(),
            issuer: issuer.clone(),
        });
    }

    let material = lookup_verification_method_material(document, verification_method.as_str())?;
    let verifying_key =
        crate::jws::decode_ed25519_public_key_material(material).map_err(|error| {
            BindingVerifyError::PublicKeyMaterial {
                reason: error.to_string(),
            }
        })?;
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: verifying_key.to_bytes().to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(jws, canonical_bytes, &public_key)
        .map_err(|source| BindingVerifyError::Proof { source })
}

/// Verify a detached Ed25519 JWS against an accepted binding and the DID
/// document that binding pins.
///
/// Also zero network calls by construction. In addition to
/// [`verify_jws_with_document`] this checks that:
///
/// 1. the binding's [`DidBindingStatus`] still permits ordinary verification (a `Deactivated` or
///    `Quarantined` binding stops authorizing signatures without any resolver call);
/// 2. the presented `verification_method` is the one the binding accepted, when the binding is
///    key-specific;
/// 3. the pinned document still hashes to the binding's `document_digest`.
pub fn verify_jws_with_binding(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &DidUrl,
    accepted: &AcceptedDidBinding,
) -> Result<(), BindingVerifyError> {
    let binding = accepted.binding();
    if !binding.is_usable_for_ordinary_verification() {
        return Err(BindingVerifyError::BindingStatusNotUsable {
            status: binding.status(),
        });
    }
    if let Some(bound) = binding.verification_method()
        && bound.as_str() != verification_method.as_str()
    {
        return Err(BindingVerifyError::BindingVerificationMethodMismatch {
            accepted: bound.as_str().to_owned(),
            presented: verification_method.as_str().to_owned(),
        });
    }
    let actual = document_canonical_digest(accepted.document())
        .map_err(|error| BindingVerifyError::Digest(error.to_string()))?;
    if &actual != binding.document_digest() {
        return Err(BindingVerifyError::BindingDocumentDigestMismatch {
            expected: binding.document_digest().clone(),
            actual,
        });
    }

    verify_jws_with_document(
        canonical_bytes,
        jws,
        verification_method,
        binding.did(),
        accepted.document(),
    )
}

// ============================================================================
// Event proof verification against an accepted binding
// ============================================================================

/// Ed25519 material published by the pinned document of an accepted binding.
///
/// Zero network: the document travels inside the binding. The lookup order is
/// [`crate::resolve_verification_method_key_from_document`]'s — absolute DID
/// URL, bare fragment, `#`-prefixed fragment, then the `did:key` single-key
/// shortcut.
///
/// This is a **material lookup only**: it deliberately does not consult
/// [`DidBindingStatus`], because a caller sometimes needs the key of a
/// quarantined binding for diagnostics. Every verification entry point in this
/// module checks the status itself before calling it.
pub fn public_key_material_from_binding(
    accepted: &AcceptedDidBinding,
    verification_method: &DidUrl,
) -> Result<PublicKeyMaterial, BindingVerifyError> {
    let material =
        lookup_verification_method_material(accepted.document(), verification_method.as_str())?;
    let verifying_key =
        crate::jws::decode_ed25519_public_key_material(material).map_err(|error| {
            BindingVerifyError::PublicKeyMaterial {
                reason: error.to_string(),
            }
        })?;
    Ok(PublicKeyMaterial::Ed25519Raw {
        bytes: verifying_key.to_bytes().to_vec(),
    })
}

/// Verify an Event [`Proof`] against an accepted binding's pinned document.
///
/// # Why this is not `verify_jws_with_binding`
///
/// An Event proof's JWS does **not** sign the envelope bytes. Per
/// `encoding.md` §6 it signs the canonical **proof binding object**
/// (`{event_digest, actor_id, verification_method, created_at, domain?,
/// audience?, context}`), and the Event profile's protected header is stricter
/// than the generic one:
///
/// | check | Event profile (used here) | generic detached-JWS profile |
/// | --- | --- | --- |
/// | `kid` header member | **rejected** (`deny_unknown_fields`) | accepted and returned |
/// | `header.alg` vs `proof.alg` | **must be equal** | not compared |
/// | `event_digest` vs canonical bytes | **constant-time compared** | not applicable |
///
/// Routing an Event proof through [`verify_jws_with_binding`] would therefore
/// verify the wrong bytes *and* relax two header checks. This function keeps the
/// Event-specific path
/// ([`arkret_signatures::verify_eddsa_detached_jws_proof`]) and only replaces
/// where the key comes from: the binding's pinned document instead of a live
/// resolver. Zero network calls by construction — there is no
/// [`DidResolver`](crate::DidResolver) parameter.
///
/// Checks, in order:
///
/// 1. the binding's [`DidBindingStatus`] still permits ordinary verification;
/// 2. `proof.verification_method` is controlled by the bound DID;
/// 3. it is the exact method the binding accepted, when the binding is key-specific;
/// 4. the pinned document still hashes to the binding's `document_digest`;
/// 5. the Event proof verifies under the Event profile.
///
/// `actor_id` is the **Event envelope's** `actor_id` — the value folded into the
/// canonical binding object — which may differ from the signing actor
/// (`executed_by`). Callers that need the signer/actor relationship checked
/// should use [`verify_event_proof_with_binding_for_event`], or check
/// `executed_by` themselves.
pub fn verify_event_proof_with_binding(
    proof: &Proof,
    envelope_bytes: &[u8],
    actor_id: &Did,
    accepted: &AcceptedDidBinding,
) -> Result<(), BindingVerifyError> {
    let binding = accepted.binding();
    if !binding.is_usable_for_ordinary_verification() {
        return Err(BindingVerifyError::BindingStatusNotUsable {
            status: binding.status(),
        });
    }

    let presented = &proof.verification_method;
    let method_did = presented
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(presented.as_str());
    if method_did != binding.did().as_str() {
        return Err(BindingVerifyError::VerificationMethodIssuerMismatch {
            verification_method: presented.as_str().to_owned(),
            issuer: binding.did().clone(),
        });
    }

    if let Some(bound) = binding.verification_method()
        && bound.as_str() != presented.as_str()
    {
        return Err(BindingVerifyError::BindingVerificationMethodMismatch {
            accepted: bound.as_str().to_owned(),
            presented: presented.as_str().to_owned(),
        });
    }

    let actual = document_canonical_digest(accepted.document())
        .map_err(|error| BindingVerifyError::Digest(error.to_string()))?;
    if &actual != binding.document_digest() {
        return Err(BindingVerifyError::BindingDocumentDigestMismatch {
            expected: binding.document_digest().clone(),
            actual,
        });
    }

    let public_key = public_key_material_from_binding(accepted, presented)?;
    arkret_signatures::verify_eddsa_detached_jws_proof(proof, envelope_bytes, actor_id, &public_key)
        .map_err(|source| BindingVerifyError::Proof { source })
}

/// [`verify_event_proof_with_binding`] with the envelope bytes and binding
/// `actor_id` derived from the Event itself.
///
/// The canonical bytes come from
/// [`arkret_signatures::EventProofBuilder::envelope_bytes`] (the Event with
/// `proofs` / `unsigned` stripped), and the binding object's `actor_id` is
/// `event.actor_id` — **not** `event.executed_by`, per `encoding.md` §6.
pub fn verify_event_proof_with_binding_for_event(
    event: &Event,
    proof: &Proof,
    accepted: &AcceptedDidBinding,
) -> Result<(), BindingVerifyError> {
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| BindingVerifyError::EventCanonicalization(error.to_string()))?;
    verify_event_proof_with_binding(proof, &envelope_bytes, &event.actor_id, accepted)
}

/// Look up a verification method's key material inside a DID document.
///
/// Mirrors [`crate::resolve_verification_method_key_from_document`] exactly:
/// full DID URL, then the fragment-only id (DID Documents commonly store
/// relative `#key-1` references), then — only for `did:key` documents holding a
/// single method — the single-key shortcut. It is deliberately no stricter,
/// so migrating a call site off the resolver-based verifier cannot change which
/// documents verify.
fn lookup_verification_method_material<'a>(
    document: &'a DidDocument,
    verification_method: &str,
) -> Result<&'a str, BindingVerifyError> {
    if let Some(value) = document.verification_methods.get(verification_method) {
        return Ok(value.as_str());
    }
    if let Some((_, fragment)) = verification_method.split_once('#') {
        let fragment = fragment.split('?').next().unwrap_or(fragment);
        if let Some(value) = document.verification_methods.get(fragment) {
            return Ok(value.as_str());
        }
        // Documents that store `#key-1` verbatim as the map key.
        if let Some(value) = document.verification_methods.get(&format!("#{fragment}")) {
            return Ok(value.as_str());
        }
    }
    if document.id.method() == "key"
        && document.verification_methods.len() == 1
        && let Some(value) = document.verification_methods.values().next()
    {
        return Ok(value.as_str());
    }
    Err(BindingVerifyError::VerificationMethodNotFound {
        verification_method: verification_method.to_owned(),
        did: document.id.clone(),
        available: document.verification_methods.keys().cloned().collect(),
    })
}

// ============================================================================
// Authority path
// ============================================================================

/// How a resolved document is turned into a [`VerifiedDidBinding`].
///
/// The resolver returns only a DID document, so everything the acceptance pins
/// beyond that document is supplied by the caller — including the method
/// evidence digest and the limited-trust declaration. Use
/// [`LimitedTrustReason::for_pins`] to fill `limited_trust` consistently;
/// [`VerifiedDidBinding::new`] validates it either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingAcceptance {
    /// Digest of the method evidence backing the acceptance (webvh log
    /// verification result, witness set, controller proof bundle...).
    pub evidence_digest: Hash,
    /// Method history head, when the method exposes one.
    pub history_head: Option<Hash>,
    /// Method version identifier, when the method exposes one.
    pub version_id: Option<String>,
    /// Limited-trust declaration; MUST be `Some` exactly when a pin is missing.
    pub limited_trust: Option<LimitedTrustReason>,
    /// Offset from acceptance time to the background-refresh point.
    pub refresh_interval: Option<Duration>,
    /// Offset from acceptance time to the hard-expiry point.
    pub hard_expiry: Option<Duration>,
}

/// Everything [`BindingAcceptance`] carries **except** the evidence digest.
///
/// [`BindingAcceptance::evidence_digest`] must be a finished [`Hash`] before
/// [`resolve_and_verify_binding`] is called, which means material that only
/// exists *after* resolution — a service endpoint published by the resolved
/// document, a witness set returned alongside it — cannot enter the evidence.
/// This type is the same acceptance terms with that field removed, so
/// [`resolve_and_verify_binding_with_evidence`] can compute the digest from the
/// resolved document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingAcceptanceTerms {
    /// Method history head, when the method exposes one.
    pub history_head: Option<Hash>,
    /// Method version identifier, when the method exposes one.
    pub version_id: Option<String>,
    /// Limited-trust declaration; MUST be `Some` exactly when a pin is missing.
    pub limited_trust: Option<LimitedTrustReason>,
    /// Offset from acceptance time to the background-refresh point.
    pub refresh_interval: Option<Duration>,
    /// Offset from acceptance time to the hard-expiry point.
    pub hard_expiry: Option<Duration>,
}

impl BindingAcceptanceTerms {
    /// Complete these terms with an already-computed evidence digest.
    pub fn with_evidence_digest(self, evidence_digest: Hash) -> BindingAcceptance {
        BindingAcceptance {
            evidence_digest,
            history_head: self.history_head,
            version_id: self.version_id,
            limited_trust: self.limited_trust,
            refresh_interval: self.refresh_interval,
            hard_expiry: self.hard_expiry,
        }
    }
}

impl BindingAcceptance {
    /// This acceptance's terms with the evidence digest dropped.
    pub fn terms(&self) -> BindingAcceptanceTerms {
        BindingAcceptanceTerms {
            history_head: self.history_head.clone(),
            version_id: self.version_id.clone(),
            limited_trust: self.limited_trust,
            refresh_interval: self.refresh_interval,
            hard_expiry: self.hard_expiry,
        }
    }
}

/// A caller-supplied evidence computation failed.
///
/// Deliberately a single opaque message rather than a closed enum: the closure
/// runs deployment-specific code (endpoint digesting, witness-set assembly) and
/// the SDK cannot enumerate its failure modes. `From` impls exist for the shapes
/// callers actually produce, so `?` works inside the closure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BindingEvidenceError(String);

impl BindingEvidenceError {
    /// Wrap a failure message.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The failure message.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl From<crate::binding_digest::DigestError> for BindingEvidenceError {
    fn from(error: crate::binding_digest::DigestError) -> Self {
        Self(error.to_string())
    }
}

impl From<BindingError> for BindingEvidenceError {
    fn from(error: BindingError) -> Self {
        Self(error.to_string())
    }
}

impl From<String> for BindingEvidenceError {
    fn from(reason: String) -> Self {
        Self(reason)
    }
}

impl From<&str> for BindingEvidenceError {
    fn from(reason: &str) -> Self {
        Self(reason.to_owned())
    }
}

/// An authority-verification request whose `evidence_digest` is computed
/// **after** the document is resolved.
///
/// Identical to [`BindingResolveRequest`] except that `acceptance` is a
/// [`BindingAcceptanceTerms`]. Use it with
/// [`resolve_and_verify_binding_with_evidence`] when the evidence envelope has
/// to see the resolved document — for instance to bind a service endpoint or a
/// method proof set that only the resolution produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredEvidenceResolveRequest {
    /// The bare DID to establish or refresh a binding for.
    pub did: Did,
    /// Local trust domain the acceptance is scoped to.
    pub trust_domain: TypedTrustDomainId,
    /// The single purpose being authorized.
    pub purpose: DidBindingPurpose,
    /// Digest of the resolver / Realm policy in force. Compute it with
    /// [`crate::binding_digest::PolicyDigestInput`].
    pub policy_digest: Hash,
    /// The concrete verification method being accepted, when key-specific.
    pub verification_method: Option<DidUrl>,
    /// Freshness this call site demands of a reusable binding.
    pub freshness: FreshnessRequirement,
    /// How to turn the resolved document into a binding, minus the evidence.
    pub acceptance: BindingAcceptanceTerms,
}

impl DeferredEvidenceResolveRequest {
    /// The store key this request reads and writes.
    ///
    /// Identical to [`BindingResolveRequest::key`]: the evidence digest is not
    /// a key dimension, so deferring it cannot move an entry.
    pub fn key(&self) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: self.did.clone(),
            trust_domain: self.trust_domain.clone(),
            purpose: self.purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method: self.verification_method.clone(),
            version_id: self.acceptance.version_id.clone(),
        }
    }

    /// Drop the precomputed evidence digest from an eager request.
    pub fn from_request(request: &BindingResolveRequest) -> Self {
        Self {
            did: request.did.clone(),
            trust_domain: request.trust_domain.clone(),
            purpose: request.purpose,
            policy_digest: request.policy_digest.clone(),
            verification_method: request.verification_method.clone(),
            freshness: request.freshness,
            acceptance: request.acceptance.terms(),
        }
    }
}

/// A single authority-verification request.
///
/// Every field is required. `did-usage-and-verification.md` §4 permits reusing
/// an earlier result "only when it is bound to the same DID, trust domain,
/// purpose, policy digest and an acceptable freshness", so there is no
/// `Default` and no implicit trust domain, purpose, policy digest or freshness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingResolveRequest {
    /// The bare DID to establish or refresh a binding for.
    pub did: Did,
    /// Local trust domain the acceptance is scoped to.
    pub trust_domain: TypedTrustDomainId,
    /// The single purpose being authorized.
    pub purpose: DidBindingPurpose,
    /// Digest of the resolver / Realm policy in force. This is the caller's
    /// snapshot of its [`ResolverPolicy`](crate::ResolverPolicy) (and any Realm
    /// policy layered on it); a policy revision changes the digest, which
    /// changes the store key, so a stale-policy binding is never reused.
    pub policy_digest: Hash,
    /// The concrete verification method being accepted, when key-specific.
    pub verification_method: Option<DidUrl>,
    /// Freshness this call site demands of a reusable binding.
    pub freshness: FreshnessRequirement,
    /// How to turn the resolved document into a binding.
    pub acceptance: BindingAcceptance,
}

impl BindingResolveRequest {
    /// The store key this request reads and writes.
    pub fn key(&self) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: self.did.clone(),
            trust_domain: self.trust_domain.clone(),
            purpose: self.purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method: self.verification_method.clone(),
            version_id: self.acceptance.version_id.clone(),
        }
    }
}

/// Typed failures of the authority path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindingResolveError {
    /// The resolver chain could not resolve the DID.
    #[error("DID resolve failed for `{did}`: {source}")]
    Resolve {
        did: Did,
        #[source]
        source: Box<crate::IdentityError>,
    },
    /// The resolved document is for a different DID.
    #[error("resolved document id `{document_id}` does not match requested DID `{requested}`")]
    DocumentIssuerMismatch { document_id: Did, requested: Did },
    /// The requested verification method is absent from the resolved document.
    #[error(
        "verification_method `{verification_method}` not found in resolved document for `{did}` (have {available:?})"
    )]
    VerificationMethodNotFound {
        verification_method: String,
        did: Did,
        available: Vec<String>,
    },
    /// The caller's post-resolution evidence computation failed.
    #[error("evidence computation failed for `{did}`: {source}")]
    Evidence {
        did: Did,
        #[source]
        source: BindingEvidenceError,
    },
    /// The binding failed its internal-consistency checks.
    #[error(transparent)]
    Binding(#[from] BindingError),
    /// The binding / document pairing was rejected by the store.
    #[error(transparent)]
    Store(#[from] BindingStoreError),
}

/// Establish or refresh a verified DID binding — **the only API in this module
/// that may touch the network**.
///
/// Order of operations:
///
/// 1. read the binding store under `request.key()`;
/// 2. on a hit that satisfies `request.freshness`, return it **without calling the resolver**;
/// 3. otherwise call `resolver.resolve_did` **exactly once**, verify the document belongs to the
///    requested DID (and carries the requested verification method), build the binding and
///    `accept()` it back into the store.
///
/// A hard-expired or invalidated entry reads as a miss, so the next authority
/// call resolves again — exactly once.
pub fn resolve_and_verify_binding<R>(
    resolver: &R,
    store: &dyn VerifiedDidBindingStore,
    request: &BindingResolveRequest,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, BindingResolveError>
where
    R: DidResolver + ?Sized,
{
    let evidence_digest = request.acceptance.evidence_digest.clone();
    resolve_and_verify_binding_with_evidence(
        resolver,
        store,
        &DeferredEvidenceResolveRequest::from_request(request),
        move |_document| Ok(evidence_digest),
        now,
    )
}

/// [`resolve_and_verify_binding`] with the evidence digest computed from the
/// **resolved document**.
///
/// Same operation order and the same "exactly one upstream resolution"
/// guarantee; the only difference is *when* the evidence digest exists. On a
/// store hit `evidence` is never called at all — the cached acceptance keeps the
/// evidence it was originally accepted with, so a reuse cannot silently
/// re-stamp itself with fresh-looking evidence.
///
/// ```no_run
/// # use arkret_identity::binding_digest::EvidenceEnvelope;
/// # use arkret_identity::verifier::{DeferredEvidenceResolveRequest, resolve_and_verify_binding_with_evidence};
/// # use arkret_identity::{DidResolver, VerifiedDidBindingStore};
/// # fn demo<R: DidResolver>(
/// #     resolver: &R,
/// #     store: &dyn VerifiedDidBindingStore,
/// #     request: &DeferredEvidenceResolveRequest,
/// #     now: chrono::DateTime<chrono::Utc>,
/// # ) {
/// let policy_digest = request.policy_digest.clone();
/// let accepted = resolve_and_verify_binding_with_evidence(
///     resolver,
///     store,
///     request,
///     |document| {
///         // `document` is the freshly resolved, already-verified document, so
///         // post-resolution material can enter the evidence envelope here.
///         Ok(EvidenceEnvelope::for_document(document, policy_digest)?
///             .with_extension("source", "shared_resolver_chain")
///             .digest()?)
///     },
///     now,
/// );
/// # let _ = accepted;
/// # }
/// ```
pub fn resolve_and_verify_binding_with_evidence<R, F>(
    resolver: &R,
    store: &dyn VerifiedDidBindingStore,
    request: &DeferredEvidenceResolveRequest,
    evidence: F,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, BindingResolveError>
where
    R: DidResolver + ?Sized,
    F: FnOnce(&DidDocument) -> Result<Hash, BindingEvidenceError>,
{
    let key = request.key();
    let (hit, freshness) = store.get_with_freshness(&key, now);
    if let Some(accepted) = hit
        && freshness_satisfies(&freshness, &request.freshness)
        && accepted
            .binding()
            .is_usable_for_authority(&request.freshness, now)
    {
        return Ok(accepted);
    }

    // Authority trigger reached: exactly one upstream resolution.
    let document =
        resolver
            .resolve_did(&request.did)
            .map_err(|source| BindingResolveError::Resolve {
                did: request.did.clone(),
                source: Box::new(source),
            })?;

    if document.id != request.did {
        return Err(BindingResolveError::DocumentIssuerMismatch {
            document_id: document.id,
            requested: request.did.clone(),
        });
    }

    if let Some(verification_method) = &request.verification_method
        && lookup_verification_method_material(&document, verification_method.as_str()).is_err()
    {
        return Err(BindingResolveError::VerificationMethodNotFound {
            verification_method: verification_method.as_str().to_owned(),
            did: request.did.clone(),
            available: document.verification_methods.keys().cloned().collect(),
        });
    }

    // The evidence digest is computed here — after the document is resolved and
    // checked — so post-resolution material can enter it.
    let evidence_digest = evidence(&document).map_err(|source| BindingResolveError::Evidence {
        did: request.did.clone(),
        source,
    })?;

    let binding = VerifiedDidBinding::from_verified_document(
        &document,
        VerifiedDidBindingDocumentInput {
            trust_domain: request.trust_domain.clone(),
            purpose: request.purpose,
            verification_method: request.verification_method.clone(),
            history_head: request.acceptance.history_head.clone(),
            version_id: request.acceptance.version_id.clone(),
            limited_trust: request.acceptance.limited_trust,
            evidence_digest,
            policy_digest: request.policy_digest.clone(),
            verified_at: now,
            refresh_after: request
                .acceptance
                .refresh_interval
                .map(|interval| now + interval),
            expires_at: request.acceptance.hard_expiry.map(|expiry| now + expiry),
            status: DidBindingStatus::Active,
        },
    )?;

    let accepted = AcceptedDidBinding::new(binding, document)?;
    store.accept(accepted.clone())?;
    Ok(accepted)
}

/// Whether an observed store freshness satisfies the caller's requirement.
fn freshness_satisfies(observed: &BindingFreshness, required: &FreshnessRequirement) -> bool {
    match observed {
        BindingFreshness::Fresh => true,
        BindingFreshness::Stale { .. } => !required.require_fresh,
        BindingFreshness::Expired | BindingFreshness::Missing => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_signatures::jws::sign_jws_ed25519;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::binding::VerifiedDidBindingDocumentInput;
    use crate::binding_store::InMemoryVerifiedDidBindingStore;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:local".to_owned()).expect("valid trust domain")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:verifier.example".to_owned()).expect("valid did")
    }

    fn document(key_id: &str) -> DidDocument {
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key().verifying_key().as_bytes(),
        );
        DidDocument {
            id: did(),
            verification_methods: BTreeMap::from([(key_id.to_owned(), multibase)]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        }
    }

    fn verification_method() -> DidUrl {
        DidUrl::new(format!("{}#key-1", did())).expect("valid did url")
    }

    fn accepted(document: &DidDocument) -> AcceptedDidBinding {
        let binding = VerifiedDidBinding::from_verified_document(
            document,
            VerifiedDidBindingDocumentInput {
                trust_domain: trust_domain(),
                purpose: DidBindingPurpose::Principal,
                verification_method: Some(verification_method()),
                history_head: Some(hash(0x22)),
                version_id: Some("1-abc".to_owned()),
                limited_trust: None,
                evidence_digest: hash(0x33),
                policy_digest: hash(0x44),
                verified_at: Utc::now(),
                refresh_after: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            },
        )
        .expect("valid binding");
        AcceptedDidBinding::new(binding, document.clone()).expect("consistent pairing")
    }

    #[test]
    fn verify_with_document_round_trips() {
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        verify_jws_with_document(
            canonical,
            &jws,
            &verification_method(),
            &did(),
            &document(&format!("{}#key-1", did())),
        )
        .expect("verify");
    }

    #[test]
    fn verify_with_document_accepts_a_relative_fragment_key_id() {
        // DID Documents commonly store `verificationMethod[].id` relative.
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        verify_jws_with_document(
            canonical,
            &jws,
            &verification_method(),
            &did(),
            &document("key-1"),
        )
        .expect("relative key id must resolve");
        verify_jws_with_document(
            canonical,
            &jws,
            &verification_method(),
            &did(),
            &document("#key-1"),
        )
        .expect("`#key-1` key id must resolve");
    }

    #[test]
    fn verify_with_document_enforces_the_issuer_argument() {
        // The legacy `jws::verify_jws_ed25519` took `issuer` and never used it.
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        let other = Did::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
        let error = verify_jws_with_document(
            canonical,
            &jws,
            &verification_method(),
            &other,
            &document(&format!("{}#key-1", did())),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::VerificationMethodIssuerMismatch { .. }
        ));
    }

    #[test]
    fn verify_with_document_rejects_a_document_for_another_did() {
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        let mut foreign = document(&format!("{}#key-1", did()));
        foreign.id = Did::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
        let error =
            verify_jws_with_document(canonical, &jws, &verification_method(), &did(), &foreign)
                .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::DocumentIssuerMismatch { .. }
        ));
    }

    #[test]
    fn verify_with_document_rejects_a_tampered_payload() {
        let jws = sign_jws_ed25519(b"original", &signing_key()).expect("sign");
        let error = verify_jws_with_document(
            b"tampered",
            &jws,
            &verification_method(),
            &did(),
            &document(&format!("{}#key-1", did())),
        )
        .unwrap_err();
        assert!(matches!(error, BindingVerifyError::Proof { .. }));
    }

    #[test]
    fn verify_with_binding_round_trips() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted)
            .expect("verify");
    }

    #[test]
    fn verify_with_binding_refuses_a_deactivated_binding() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document).with_binding_status(DidBindingStatus::Deactivated);
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        let error = verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted)
            .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::BindingStatusNotUsable {
                status: DidBindingStatus::Deactivated
            }
        ));
    }

    #[test]
    fn verify_with_binding_refuses_a_different_verification_method() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        let other = DidUrl::new(format!("{}#key-2", did())).expect("valid did url");
        let error = verify_jws_with_binding(canonical, &jws, &other, &accepted).unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::BindingVerificationMethodMismatch { .. }
        ));
    }

    #[test]
    fn verify_with_binding_serves_a_stale_binding_without_a_resolver() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document).with_binding_status(DidBindingStatus::Stale);
        let canonical = br#"{"hello":"world"}"#;
        let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
        verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted)
            .expect("stale bindings still verify ordinary signatures");
    }

    #[test]
    fn freshness_requirement_gates_stale_reuse() {
        let stale = BindingFreshness::Stale {
            age: Duration::minutes(1),
        };
        assert!(!freshness_satisfies(
            &stale,
            &FreshnessRequirement::fresh_within(Duration::hours(1))
        ));
        assert!(freshness_satisfies(
            &stale,
            &FreshnessRequirement::any_accepted()
        ));
        assert!(!freshness_satisfies(
            &BindingFreshness::Expired,
            &FreshnessRequirement::any_accepted()
        ));
        assert!(!freshness_satisfies(
            &BindingFreshness::Missing,
            &FreshnessRequirement::any_accepted()
        ));
    }

    // ------------------------------------------------------------------
    // Event proof verification against an accepted binding (DID-P1-B)
    // ------------------------------------------------------------------

    mod event_proof {
        use arkret_canonical::base64url::base64url_encode;
        use arkret_signatures::{
            Ed25519DetachedJwsVerifier, EventProofBuilder, sign_eddsa_detached_jws,
        };
        use arkret_wire::{EventId, EventRequirements, Hlc, RealmId, ScopeRef, proof_kind};
        use chrono::TimeZone;

        use super::*;

        fn realm() -> RealmId {
            RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").expect("valid realm")
        }

        fn event() -> Event {
            Event {
                event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575")
                    .expect("valid event id"),
                kind: "ak.message.create".into(),
                realm_id: realm(),
                scope_ref: ScopeRef::Realm { realm_id: realm() },
                actor_id: did(),
                actor_seq: 1,
                created_at: Utc
                    .with_ymd_and_hms(2026, 4, 26, 0, 0, 0)
                    .single()
                    .expect("valid timestamp"),
                hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").expect("valid hlc")),
                prev_refs: Vec::new(),
                refs: Vec::new(),
                preconditions: Vec::new(),
                seal_ref: None,
                auth_context: None,
                seal_basis: None,
                requirements: EventRequirements::default(),
                redacts: None,
                payload: BTreeMap::from([("body".to_owned(), serde_json::json!("hello"))]),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                actor_kind: None,
                unsigned: BTreeMap::new(),
                causal_refs: Vec::new(),
                proofs: Vec::new(),
            }
        }

        fn envelope_bytes(event: &Event) -> Vec<u8> {
            EventProofBuilder::new()
                .envelope_bytes(event)
                .expect("canonical envelope bytes")
        }

        /// A proof whose `jws` still has to be filled in.
        fn unsigned_proof(event: &Event) -> Proof {
            Proof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: verification_method(),
                event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
                    envelope_bytes(event),
                ))
                .expect("valid digest"),
                created_at: arkret_canonical::canonical::normalize_timestamp_canonical(
                    Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0)
                        .single()
                        .expect("valid timestamp"),
                ),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            }
        }

        /// Sign the canonical proof **binding object** — the bytes an Event
        /// proof actually covers (`encoding.md` §6).
        fn signed_proof(event: &Event) -> Proof {
            let mut proof = unsigned_proof(event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws = sign_eddsa_detached_jws(&signing_key(), &binding_bytes).expect("sign");
            proof
        }

        /// Hand-assemble a detached JWS with an arbitrary protected header, so
        /// the header hygiene of the Event profile can be exercised directly.
        fn detached_jws_with_header(header: serde_json::Value, payload: &[u8]) -> String {
            use ed25519_dalek::Signer;
            let header_b64 = base64url_encode(
                arkret_canonical::canonical::canonical_json_bytes(&header).expect("header bytes"),
            );
            let signing_input = format!("{header_b64}.{}", base64url_encode(payload));
            let signature = signing_key().sign(signing_input.as_bytes());
            format!(
                "{header_b64}..{}",
                base64url_encode(signature.to_bytes().as_slice())
            )
        }

        fn public_key() -> PublicKeyMaterial {
            PublicKeyMaterial::Ed25519Raw {
                bytes: signing_key().verifying_key().to_bytes().to_vec(),
            }
        }

        #[test]
        fn verifies_against_an_accepted_binding_without_a_resolver() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let proof = signed_proof(&event);
            verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .expect("an accepted binding verifies an Event proof");
        }

        #[test]
        fn the_for_event_helper_derives_the_same_inputs() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let mut event = event();
            let proof = signed_proof(&event);
            event.proofs.push(proof.clone());
            verify_event_proof_with_binding_for_event(&event, &proof, &accepted)
                .expect("verify from the event itself");
        }

        #[test]
        fn signature_must_cover_the_binding_object_not_the_envelope() {
            // The single most important reason this cannot route through
            // `verify_jws_with_binding`: that path verifies the JWS over the
            // bytes it is handed, and the Event profile signs a different
            // transcript.
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let bytes = envelope_bytes(&event);
            let mut proof = unsigned_proof(&event);
            proof.jws = sign_eddsa_detached_jws(&signing_key(), &bytes).expect("sign");

            let error = verify_event_proof_with_binding(&proof, &bytes, &event.actor_id, &accepted)
                .unwrap_err();
            assert!(
                matches!(error, BindingVerifyError::Proof { .. }),
                "a signature over the envelope bytes must not satisfy an Event proof, got {error}"
            );
            // ...while the generic detached-JWS primitive happily accepts it,
            // which is exactly the relaxation this API exists to prevent.
            Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&proof.jws, &bytes, &public_key())
                .expect("the generic profile verifies the envelope-bytes signature");
        }

        #[test]
        fn a_kid_bearing_protected_header_is_rejected() {
            // `DetachedJwsProtectedHeader` is `deny_unknown_fields` and has no
            // `kid`; the generic `JwsProtectedHeader` accepts and returns one.
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = unsigned_proof(&event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws = detached_jws_with_header(
                serde_json::json!({"alg": "EdDSA", "kid": verification_method().as_str()}),
                &binding_bytes,
            );

            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(
                matches!(error, BindingVerifyError::Proof { .. }),
                "the Event profile must reject a `kid` header member, got {error}"
            );
            // The generic profile accepts the very same JWS — proving the
            // header hygiene is genuinely stricter here, not incidentally so.
            Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&proof.jws, &binding_bytes, &public_key())
                .expect("the generic profile accepts a `kid` header");
        }

        #[test]
        fn the_protected_header_alg_must_equal_the_proof_alg() {
            // The generic profile only checks `header.alg == "EdDSA"`; it never
            // compares the header against the proof's own declared `alg`.
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = unsigned_proof(&event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws =
                detached_jws_with_header(serde_json::json!({"alg": "EdDSA"}), &binding_bytes);
            proof.alg = "ES256".to_owned();

            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(
                matches!(error, BindingVerifyError::Proof { .. }),
                "a proof alg that disagrees with the header must be rejected, got {error}"
            );
            Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&proof.jws, &binding_bytes, &public_key())
                .expect("the generic profile ignores the proof's declared alg");
        }

        #[test]
        fn a_crit_header_is_rejected() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = unsigned_proof(&event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws = detached_jws_with_header(
                serde_json::json!({"alg": "EdDSA", "crit": ["b64"]}),
                &binding_bytes,
            );
            assert!(
                verify_event_proof_with_binding(
                    &proof,
                    &envelope_bytes(&event),
                    &event.actor_id,
                    &accepted,
                )
                .is_err()
            );
        }

        #[test]
        fn a_tampered_event_breaks_the_digest_binding() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let proof = signed_proof(&event);
            let mut tampered = event.clone();
            tampered
                .payload
                .insert("body".to_owned(), serde_json::json!("goodbye"));

            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&tampered),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(matches!(error, BindingVerifyError::Proof { .. }));
        }

        #[test]
        fn a_deactivated_binding_stops_authorizing_event_proofs() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document).with_binding_status(DidBindingStatus::Deactivated);
            let event = event();
            let proof = signed_proof(&event);
            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                BindingVerifyError::BindingStatusNotUsable {
                    status: DidBindingStatus::Deactivated
                }
            ));
        }

        #[test]
        fn a_stale_binding_still_verifies_ordinary_event_proofs() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document).with_binding_status(DidBindingStatus::Stale);
            let event = event();
            let proof = signed_proof(&event);
            verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .expect("TTL expiry alone must not turn an ordinary Event into a resolution");
        }

        #[test]
        fn a_method_the_binding_did_not_accept_is_refused() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = signed_proof(&event);
            proof.verification_method =
                DidUrl::new(format!("{}#key-2", did())).expect("valid did url");
            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                BindingVerifyError::BindingVerificationMethodMismatch { .. }
            ));
        }

        #[test]
        fn a_method_controlled_by_another_did_is_refused() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = signed_proof(&event);
            proof.verification_method =
                DidUrl::new("did:webvh:z6mkfixture:other.example#key-1".to_owned())
                    .expect("valid did url");
            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                BindingVerifyError::VerificationMethodIssuerMismatch { .. }
            ));
        }

        #[test]
        fn key_material_comes_from_the_pinned_document_for_every_id_spelling() {
            // The `#key-1` spelling is the one that used to need a downstream
            // retry; all three must resolve identically.
            for key_id in [
                format!("{}#key-1", did()),
                "key-1".to_owned(),
                "#key-1".to_owned(),
            ] {
                let document = document(&key_id);
                let accepted = accepted(&document);
                let material = public_key_material_from_binding(&accepted, &verification_method())
                    .unwrap_or_else(|error| panic!("`{key_id}` must resolve: {error}"));
                assert_eq!(material, public_key());
            }
        }
    }

    // ------------------------------------------------------------------
    // Verification-method lookup convergence (DID-P1-B, gap 4)
    // ------------------------------------------------------------------

    #[test]
    fn lookups_agree_on_every_document_shape() {
        // `resolve_verification_method_key_from_document` used to lack the
        // `#key-1` branch that this module's private lookup had, so a document
        // could verify a JWS and still fail key resolution. Both must now
        // accept and reject exactly the same shapes.
        let target = format!("{}#key-1", did());
        for key_id in [target.clone(), "key-1".to_owned(), "#key-1".to_owned()] {
            let document = document(&key_id);
            let resolver_side =
                crate::resolve_verification_method_key_from_document(&document, &target);
            let verifier_side = lookup_verification_method_material(&document, &target);
            assert!(
                resolver_side.is_ok(),
                "resolver-side lookup must accept `{key_id}`"
            );
            assert!(
                verifier_side.is_ok(),
                "verifier-side lookup must accept `{key_id}`"
            );
        }

        let absent = document("key-9");
        assert!(crate::resolve_verification_method_key_from_document(&absent, &target).is_err());
        assert!(lookup_verification_method_material(&absent, &target).is_err());
    }

    // ------------------------------------------------------------------
    // Deferred (post-resolution) evidence
    // ------------------------------------------------------------------

    struct OneShotResolver {
        document: DidDocument,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl OneShotResolver {
        fn new(document: DidDocument) -> Self {
            Self {
                document,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DidResolver for OneShotResolver {
        fn supports(&self, _did: &Did) -> bool {
            true
        }

        fn resolve_did(&self, _did: &Did) -> crate::Result<DidDocument> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.document.clone())
        }
    }

    fn deferred_request() -> DeferredEvidenceResolveRequest {
        DeferredEvidenceResolveRequest {
            did: did(),
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            policy_digest: hash(0x44),
            verification_method: Some(verification_method()),
            freshness: FreshnessRequirement::fresh_within(Duration::hours(1)),
            acceptance: BindingAcceptanceTerms {
                history_head: None,
                version_id: None,
                limited_trust: Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion),
                refresh_interval: Some(Duration::minutes(30)),
                hard_expiry: Some(Duration::hours(24)),
            },
        }
    }

    #[test]
    fn deferred_evidence_sees_the_resolved_document() {
        // The teabay constraint: material that only exists after resolution
        // (an endpoint, a witness set) could not previously enter the evidence.
        let document = document(&format!("{}#key-1", did()));
        let resolver = OneShotResolver::new(document.clone());
        let store = InMemoryVerifiedDidBindingStore::default();
        let request = deferred_request();
        let expected = crate::binding_digest::EvidenceEnvelope::for_document(
            &document,
            request.policy_digest.clone(),
        )
        .expect("envelope")
        .with_extension("method_count", document.verification_methods.len())
        .digest()
        .expect("digest");

        let accepted = resolve_and_verify_binding_with_evidence(
            &resolver,
            &store,
            &request,
            |resolved| {
                Ok(
                    crate::binding_digest::EvidenceEnvelope::for_document(resolved, hash(0x44))?
                        .with_extension("method_count", resolved.verification_methods.len())
                        .digest()?,
                )
            },
            Utc::now(),
        )
        .expect("resolve");

        assert_eq!(accepted.binding().evidence_digest(), &expected);
        assert_ne!(
            accepted.binding().evidence_digest(),
            accepted.binding().document_digest(),
            "a canonical evidence digest is never the bare document digest"
        );
    }

    #[test]
    fn deferred_evidence_is_not_recomputed_on_a_store_hit() {
        // A reuse must keep the evidence it was accepted with, and must not
        // reach the resolver a second time.
        let document = document(&format!("{}#key-1", did()));
        let resolver = OneShotResolver::new(document.clone());
        let store = InMemoryVerifiedDidBindingStore::default();
        let request = deferred_request();
        let now = Utc::now();

        let first = resolve_and_verify_binding_with_evidence(
            &resolver,
            &store,
            &request,
            |_| Ok(hash(0x33)),
            now,
        )
        .expect("first acceptance");
        let second = resolve_and_verify_binding_with_evidence(
            &resolver,
            &store,
            &request,
            |_| panic!("a store hit must not recompute evidence"),
            now + Duration::minutes(1),
        )
        .expect("store hit");

        assert_eq!(resolver.calls(), 1);
        assert_eq!(
            first.binding().evidence_digest(),
            second.binding().evidence_digest()
        );
    }

    #[test]
    fn deferred_evidence_failure_fails_the_acceptance_closed() {
        let document = document(&format!("{}#key-1", did()));
        let resolver = OneShotResolver::new(document);
        let store = InMemoryVerifiedDidBindingStore::default();
        let error = resolve_and_verify_binding_with_evidence(
            &resolver,
            &store,
            &deferred_request(),
            |_| Err(BindingEvidenceError::new("endpoint digest unavailable")),
            Utc::now(),
        )
        .unwrap_err();
        assert!(matches!(error, BindingResolveError::Evidence { .. }));
        assert_eq!(store.len(), 0, "a failed evidence step stores nothing");
    }

    #[test]
    fn the_eager_and_deferred_paths_produce_the_same_binding() {
        // `resolve_and_verify_binding` is implemented on top of the deferred
        // path; this pins that the delegation is behaviour-preserving.
        let document = document(&format!("{}#key-1", did()));
        let now = Utc::now();
        let eager_request = BindingResolveRequest {
            did: did(),
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            policy_digest: hash(0x44),
            verification_method: Some(verification_method()),
            freshness: FreshnessRequirement::fresh_within(Duration::hours(1)),
            acceptance: deferred_request()
                .acceptance
                .with_evidence_digest(hash(0x33)),
        };
        assert_eq!(
            DeferredEvidenceResolveRequest::from_request(&eager_request),
            deferred_request(),
        );
        assert_eq!(eager_request.key(), deferred_request().key());

        let eager_store = InMemoryVerifiedDidBindingStore::default();
        let eager = resolve_and_verify_binding(
            &OneShotResolver::new(document.clone()),
            &eager_store,
            &eager_request,
            now,
        )
        .expect("eager acceptance");

        let deferred_store = InMemoryVerifiedDidBindingStore::default();
        let deferred = resolve_and_verify_binding_with_evidence(
            &OneShotResolver::new(document),
            &deferred_store,
            &deferred_request(),
            |_| Ok(hash(0x33)),
            now,
        )
        .expect("deferred acceptance");

        assert_eq!(eager, deferred);
    }

    #[test]
    fn store_is_written_back_on_acceptance() {
        struct OneShot(DidDocument);
        impl DidResolver for OneShot {
            fn supports(&self, _did: &Did) -> bool {
                true
            }

            fn resolve_did(&self, _did: &Did) -> crate::Result<DidDocument> {
                Ok(self.0.clone())
            }
        }

        let document = document(&format!("{}#key-1", did()));
        let store = InMemoryVerifiedDidBindingStore::default();
        let request = BindingResolveRequest {
            did: did(),
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            policy_digest: hash(0x44),
            verification_method: Some(verification_method()),
            freshness: FreshnessRequirement::fresh_within(Duration::hours(1)),
            acceptance: BindingAcceptance {
                evidence_digest: hash(0x33),
                history_head: Some(hash(0x22)),
                version_id: Some("1-abc".to_owned()),
                limited_trust: None,
                refresh_interval: Some(Duration::minutes(30)),
                hard_expiry: Some(Duration::hours(24)),
            },
        };
        let now = Utc::now();
        let accepted =
            resolve_and_verify_binding(&OneShot(document), &store, &request, now).expect("resolve");
        assert_eq!(store.len(), 1);
        assert_eq!(accepted.binding().verified_at(), now);
        assert_eq!(
            accepted.binding().refresh_after(),
            Some(now + Duration::minutes(30))
        );
        assert!(store.get(&request.key(), now).is_some());
    }
}
