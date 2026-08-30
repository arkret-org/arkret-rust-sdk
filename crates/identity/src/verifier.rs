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
//! | `authority_network_call_count` | §4 trigger scenarios only | [`resolve_and_verify_binding`] |
//!
//! # Picking the right ordinary entry point
//!
//! | signed object | entry point | what the JWS covers |
//! | --- | --- | --- |
//! | Event [`ProducerEventProof`] | [`verify_event_proof_with_binding`] | the canonical **proof binding object** (`encoding.md` §6) |
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
//! [`DidResolver`] parameter at all, so they physically
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
#[cfg(test)]
use arkret_wire::Event;
use arkret_wire::{ActorId, Did, DidUrl, Hash, ProducerEventProof, TrustDomainId};
use chrono::{DateTime, Utc};

use crate::binding::{
    BindingError, DidBindingPurpose, DidBindingStatus, FreshnessProfile, FreshnessRequirement,
    LimitedTrust, VerifiedDidBinding, VerifiedDidBindingDocumentInput, VerifiedDidBindingKey,
    document_canonical_digest,
};
use crate::binding_digest::{DigestError, EvidenceReceipt};
use crate::binding_store::{
    AcceptedDidBinding, BindingFreshness, BindingStoreError, VerifiedDidBindingStore,
};
use crate::{DidDocument, DidResolver, ResolvedDid};

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
    /// The removed resolver-driven verifier accepted an `issuer`
    /// argument and never compared it; this path compares it.
    #[error("DID document DID `{document_did}` does not match issuer `{issuer}`")]
    DocumentIssuerMismatch { document_did: Did, issuer: Did },
    /// The verification method is not controlled by the issuer DID.
    #[error("verification_method `{verification_method}` is not controlled by issuer `{issuer}`")]
    VerificationMethodIssuerMismatch {
        verification_method: String,
        issuer: Did,
    },
    /// The authority document does not declare the required verification
    /// relationship.
    #[error("DID document for `{did}` has no `{relationship}` relationship")]
    VerificationRelationshipMissing {
        did: Did,
        relationship: &'static str,
    },
    /// The presented method is not active in the required relationship.
    #[error(
        "verification_method `{verification_method}` is not authorized by `{relationship}` for `{did}`"
    )]
    VerificationMethodRelationshipMismatch {
        verification_method: String,
        did: Did,
        relationship: &'static str,
    },
    /// An externally-named verification method did not carry an explicit
    /// controller binding back to the authority document.
    #[error(
        "verification_method `{verification_method}` is controlled by `{actual_controller}`, not authority `{authority}`"
    )]
    VerificationMethodControllerMismatch {
        verification_method: String,
        authority: Did,
        actual_controller: String,
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

/// DID Core verification relationship required by a signed object family.
///
/// This is intentionally typed instead of accepting an arbitrary document
/// property name. New relationships must be added here together with their
/// protocol object-family review and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidVerificationRelationship {
    AssertionMethod,
}

impl DidVerificationRelationship {
    fn property_name(self) -> &'static str {
        match self {
            Self::AssertionMethod => "assertionMethod",
        }
    }
}

/// Verify a detached Ed25519 JWS against an **already-pinned** DID document.
///
/// Zero network calls by construction: this function has no
/// [`DidResolver`] parameter, so it cannot resolve anything
/// even by mistake.
///
/// Checks, in order:
///
/// 1. `canonical_bytes` is non-empty;
/// 2. `verification_method`'s DID part equals `issuer`;
/// 3. `document.id == issuer` — the argument the removed resolver-driven verifier accepted and
///    silently ignored;
/// 4. `verification_method` resolves inside `document` (absolute DID URL, then fragment-only id,
///    then the `did:key` single-key shortcut — the exact lookup order of
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
            document_did: document.id.clone(),
            issuer: issuer.clone(),
        });
    }

    verify_jws_against_document_key(canonical_bytes, jws, verification_method, document)
}

/// Verify a detached JWS against a key that is active in a specific DID Core
/// relationship of an already-pinned authority document.
///
/// Unlike [`verify_jws_with_document`], the verification method id may be
/// externally named when the document explicitly declares that method's
/// `controller` as `authority`. The relationship and controller checks happen
/// before any signature work. This supports explicit controller delegation
/// without treating every key that merely appears in a document as an
/// assertion authority.
pub fn verify_jws_with_document_relationship(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &DidUrl,
    authority: &Did,
    document: &DidDocument,
    relationship: DidVerificationRelationship,
) -> Result<(), BindingVerifyError> {
    if canonical_bytes.is_empty() {
        return Err(BindingVerifyError::EmptyCanonicalBytes);
    }
    if &document.id != authority {
        return Err(BindingVerifyError::DocumentIssuerMismatch {
            document_did: document.id.clone(),
            issuer: authority.clone(),
        });
    }
    require_verification_relationship(document, verification_method, authority, relationship)?;
    verify_jws_against_document_key(canonical_bytes, jws, verification_method, document)
}

fn verify_jws_against_document_key(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &DidUrl,
    document: &DidDocument,
) -> Result<(), BindingVerifyError> {
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

fn require_verification_relationship(
    document: &DidDocument,
    verification_method: &DidUrl,
    authority: &Did,
    relationship: DidVerificationRelationship,
) -> Result<(), BindingVerifyError> {
    let property = relationship.property_name();
    let relationship_value = document.raw_properties.get(property).ok_or_else(|| {
        BindingVerifyError::VerificationRelationshipMissing {
            did: document.id.clone(),
            relationship: property,
        }
    })?;
    let entries = match relationship_value {
        serde_json::Value::Array(entries) => entries.as_slice(),
        entry => std::slice::from_ref(entry),
    };
    let presented = verification_method.as_str();
    let authorized = entries.iter().any(|entry| {
        let reference = entry
            .as_str()
            .or_else(|| entry.as_object()?.get("id")?.as_str());
        reference.is_some_and(|reference| {
            absolutize_document_reference(&document.id, reference) == presented
        })
    });
    if !authorized {
        return Err(BindingVerifyError::VerificationMethodRelationshipMismatch {
            verification_method: presented.to_owned(),
            did: document.id.clone(),
            relationship: property,
        });
    }

    let method_did = verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method.as_str());
    let declared_controller = verification_method_controller(document, presented);
    match declared_controller {
        Some(controller) if controller != authority.as_str() => {
            return Err(BindingVerifyError::VerificationMethodControllerMismatch {
                verification_method: presented.to_owned(),
                authority: authority.clone(),
                actual_controller: controller.to_owned(),
            });
        }
        None if method_did != authority.as_str() => {
            return Err(BindingVerifyError::VerificationMethodControllerMismatch {
                verification_method: presented.to_owned(),
                authority: authority.clone(),
                actual_controller: method_did.to_owned(),
            });
        }
        _ => {}
    }
    Ok(())
}

fn absolutize_document_reference<'a>(did: &Did, reference: &'a str) -> std::borrow::Cow<'a, str> {
    if reference.starts_with('#') {
        std::borrow::Cow::Owned(format!("{}{}", did.as_str(), reference))
    } else {
        std::borrow::Cow::Borrowed(reference)
    }
}

fn verification_method_controller<'a>(
    document: &'a DidDocument,
    verification_method: &str,
) -> Option<&'a str> {
    let methods = document.raw_properties.get("verificationMethod")?;
    let entries = methods.as_array()?;
    entries.iter().find_map(|entry| {
        let object = entry.as_object()?;
        let id = object.get("id")?.as_str()?;
        (absolutize_document_reference(&document.id, id) == verification_method)
            .then(|| object.get("controller")?.as_str())
            .flatten()
    })
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

/// Resolve one Ed25519 verification method from an already authenticated DID
/// document. This performs no network lookup and deliberately carries no
/// freshness policy; callers must authenticate and time-bind the document
/// before invoking it.
pub fn public_key_material_from_document(
    document: &DidDocument,
    verification_method: &DidUrl,
) -> Result<PublicKeyMaterial, BindingVerifyError> {
    let material = lookup_verification_method_material(document, verification_method.as_str())?;
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

/// Verify an Event [`ProducerEventProof`] against an accepted binding's pinned document.
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
/// | `header.alg` | **must be `Ed25519`** | **must be `Ed25519`** |
/// | `event_digest` vs canonical bytes | **constant-time compared** | not applicable |
///
/// Routing an Event proof through [`verify_jws_with_binding`] would therefore
/// verify the wrong bytes *and* relax the `kid` header check. This function keeps the
/// Event-specific path
/// ([`arkret_signatures::verify_ed25519_detached_jws_proof`]) and only replaces
/// where the key comes from: the binding's pinned document instead of a live
/// resolver. Zero network calls by construction — there is no
/// [`DidResolver`] parameter.
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
/// should derive the envelope bytes with
/// [`arkret_signatures::EventProofBuilder::envelope_bytes`] and pass
/// `event.actor_id`, or check `executed_by` themselves.
pub fn verify_event_proof_with_binding(
    proof: &ProducerEventProof,
    envelope_bytes: &[u8],
    actor_id: &ActorId,
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
    arkret_signatures::verify_ed25519_detached_jws_proof(
        proof,
        envelope_bytes,
        actor_id,
        &public_key,
    )
    .map_err(|source| BindingVerifyError::Proof { source })
}

/// Look up a verification method's key material inside a DID document.
///
/// Mirrors [`crate::resolve_verification_method_key_from_document`] exactly:
/// absolute DID URL, then the fragment-only id (DID Documents commonly store
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

/// A single authority-verification request.
///
/// Every field is required. `did-usage-and-verification.md` §4 permits reusing
/// an earlier result "only when it is bound to the same DID, trust domain,
/// purpose, policy digest and an acceptable freshness", so there is no
/// `Default` and no implicit trust domain, purpose, policy digest or freshness.
///
/// There is deliberately **no** `evidence_digest`, `history_head`, `version_id`
/// or `limited_trust` member: §5.2 makes all four products of the resolution
/// itself. A request that carried them would be the "caller supplies the
/// evidence" shape the spec judges non-conformant — and is exactly how one
/// deployment shipped `evidence_digest = document_digest` and another a
/// hard-coded constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingResolveRequest {
    /// The bare DID to establish or refresh a binding for.
    pub did: Did,
    /// Local trust domain the acceptance is scoped to.
    pub trust_domain: TrustDomainId,
    /// The single purpose being authorized.
    pub purpose: DidBindingPurpose,
    /// Digest of the resolver policy in force. Compute it with
    /// [`ResolverPolicy::policy_digest`](crate::ResolverPolicy::policy_digest);
    /// a policy revision changes the digest, which changes the store key, so a
    /// stale-policy binding is never reused.
    pub policy_digest: Hash,
    /// The concrete verification method being accepted, when key-specific.
    pub verification_method: Option<DidUrl>,
    /// The registered freshness profile this call site references (§5.4). It is
    /// the single source of the reuse threshold, `refresh_after` and
    /// `expires_at`, so those three can never drift apart.
    pub freshness: FreshnessProfile,
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
    #[error("resolved document DID `{document_did}` does not match requested DID `{requested}`")]
    DocumentIssuerMismatch { document_did: Did, requested: Did },
    /// The requested verification method is absent from the resolved document.
    #[error(
        "verification_method `{verification_method}` not found in resolved document for `{did}` (have {available:?})"
    )]
    VerificationMethodNotFound {
        verification_method: String,
        did: Did,
        available: Vec<String>,
    },
    /// The canonical evidence receipt could not be built or digested.
    #[error("evidence receipt failed for `{did}`: {source}")]
    Evidence {
        did: Did,
        #[source]
        source: DigestError,
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
/// 2. on a hit that satisfies the request's freshness profile, return it **without calling the
///    resolver**;
/// 3. otherwise call `resolver.resolve_did` **exactly once**, verify the document belongs to the
///    requested DID (and carries the requested verification method), build the §5.2 evidence
///    receipt from the resolution, and `accept()` the binding back into the store.
///
/// A hard-expired or invalidated entry reads as a miss, so the next authority
/// call resolves again — exactly once.
///
/// The evidence receipt, its digest, the dependency record and the per-pin
/// limited-trust states are all derived here from what the resolver returned.
/// That is the point: there is no caller-facing seam where a placeholder could
/// be substituted for evidence.
pub fn resolve_and_verify_binding<R>(
    resolver: &R,
    store: &dyn VerifiedDidBindingStore,
    request: &BindingResolveRequest,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, BindingResolveError>
where
    R: DidResolver + ?Sized,
{
    let requirement = request.freshness.requirement();
    let key = request.key();
    let (hit, freshness) = store.get_with_freshness(&key, now);
    if let Some(accepted) = hit
        && freshness_satisfies(&freshness, &requirement)
        && accepted
            .binding()
            .is_usable_for_authority(&requirement, now)
    {
        return Ok(accepted);
    }

    // Authority trigger reached: exactly one upstream resolution.
    let resolved =
        resolver
            .resolve_did(&request.did)
            .map_err(|source| BindingResolveError::Resolve {
                did: request.did.clone(),
                source: Box::new(source),
            })?;
    let ResolvedDid {
        document,
        method_evidence,
    } = resolved;

    if document.id != request.did {
        return Err(BindingResolveError::DocumentIssuerMismatch {
            document_did: document.id,
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

    let evidence = |source| BindingResolveError::Evidence {
        did: request.did.clone(),
        source,
    };
    let document_digest = document_canonical_digest(&document)?;
    let receipt = EvidenceReceipt::new(document.id.method(), document_digest, &method_evidence);
    let evidence_digest = receipt.digest().map_err(evidence)?;
    let evidence_dependencies = receipt.evidence_dependencies().map_err(evidence)?;

    // §5.5: an absent pin is `method_unsupported` only when the method really
    // publishes nothing. For an evidence-bearing method it is `not_surfaced` —
    // a resolver failure that must stay visible rather than be laundered into a
    // terminal method property.
    let pins = (
        method_evidence.history_head.as_deref(),
        method_evidence.version_id.as_deref(),
    );
    let limited_trust = if method_evidence.is_proofless() {
        LimitedTrust::for_proofless_method(pins.0, pins.1)
    } else {
        LimitedTrust::for_evidence_bearing_method(pins.0, pins.1)
    };

    let binding = VerifiedDidBinding::from_verified_document(
        &document,
        VerifiedDidBindingDocumentInput {
            trust_domain: request.trust_domain.clone(),
            purpose: request.purpose,
            verification_method: request.verification_method.clone(),
            history_head: method_evidence.history_head.clone(),
            version_id: method_evidence.version_id.clone(),
            limited_trust: limited_trust.record_for(),
            evidence_digest,
            evidence_dependencies,
            policy_digest: request.policy_digest.clone(),
            verified_at: now,
            refresh_after: request.freshness.refresh_after(now),
            expires_at: request.freshness.expires_at(now),
            status: DidBindingStatus::Active,
        },
    )?;

    let accepted = AcceptedDidBinding::new(binding, document, receipt)?;
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

    /// A protocol instant is millisecond-precision, and
    /// `VerifiedDidBinding::new` floors its freshness window to it. A raw
    /// `Utc::now()` here would leave a fixture holding sub-millisecond digits
    /// the binding cannot carry, so window assertions would compare against a
    /// value no store could return.
    fn protocol_now() -> DateTime<Utc> {
        arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now())
    }
    use std::collections::BTreeMap;

    use arkret_signatures::jws::sign_jws_ed25519;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::binding::{FreshnessProfile, VerifiedDidBindingDocumentInput};
    use crate::binding_digest::{EvidenceReceipt, MethodEvidence};
    use crate::binding_store::InMemoryVerifiedDidBindingStore;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:local".to_owned()).expect("valid trust domain")
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
        let receipt = EvidenceReceipt::new(
            did().method(),
            document_canonical_digest(document).expect("digest"),
            &MethodEvidence::none(),
        );
        let binding = VerifiedDidBinding::from_verified_document(
            document,
            VerifiedDidBindingDocumentInput {
                trust_domain: trust_domain(),
                purpose: DidBindingPurpose::Principal,
                verification_method: Some(verification_method()),
                history_head: None,
                version_id: None,
                limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
                evidence_digest: receipt.digest().expect("digest"),
                evidence_dependencies: receipt.evidence_dependencies().expect("dependencies"),
                policy_digest: hash(0x44),
                verified_at: protocol_now(),
                refresh_after: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            },
        )
        .expect("valid binding");
        AcceptedDidBinding::new(binding, document.clone(), receipt).expect("consistent pairing")
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
        // The removed resolver-driven verifier took `issuer` and never used it.
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
    fn verify_with_document_rejects_a_duplicate_protected_header_key() {
        // A protected header that repeats a member is not canonical JSON, so
        // the detached-JWS verifier refuses it before any signature check.
        let header = arkret_canonical::base64url_encode(br#"{"alg":"Ed25519","alg":"Ed25519"}"#);
        let signature = arkret_canonical::base64url_encode([1u8; 64]);
        let jws = format!("{header}..{signature}");
        let error = verify_jws_with_document(
            br#"{}"#,
            &jws,
            &verification_method(),
            &did(),
            &document(&format!("{}#key-1", did())),
        )
        .expect_err("a duplicate protected-header key must be rejected");
        let rendered = error.to_string();
        assert!(
            rendered.contains("duplicate key") || rendered.contains("canonical JSON"),
            "got `{rendered}`"
        );
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
        let high = FreshnessRequirement {
            max_age: Some(Duration::hours(1)),
            require_fresh: true,
        };
        let accepted_only = FreshnessRequirement {
            max_age: None,
            require_fresh: false,
        };
        assert!(!freshness_satisfies(&stale, &high));
        assert!(freshness_satisfies(&stale, &accepted_only));
        assert!(!freshness_satisfies(
            &BindingFreshness::Expired,
            &accepted_only
        ));
        assert!(!freshness_satisfies(
            &BindingFreshness::Missing,
            &accepted_only
        ));
    }

    // ------------------------------------------------------------------
    // Event proof verification against an accepted binding (DID-P1-B)
    // ------------------------------------------------------------------

    mod event_proof {
        use arkret_canonical::base64url::base64url_encode;
        use arkret_signatures::{
            Ed25519DetachedJwsVerifier, EventProofBuilder, sign_ed25519_detached_jws,
        };
        use arkret_wire::{EventId, EventRequirements, Hlc, RealmId, ScopeRef, proof_kind};
        use chrono::TimeZone;

        use super::*;

        fn realm() -> RealmId {
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .expect("valid realm")
        }

        fn event() -> Event {
            Event {
                event_id: EventId::new("ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6")
                    .expect("valid event id"),
                kind: "ak.message.create".into(),
                realm_id: realm(),
                scope_ref: ScopeRef::Realm { realm_id: realm() },
                actor_id: arkret_wire::project_did_to_core_id(&did())
                    .expect("registered DID adapter"),
                station_id: arkret_wire::project_did_to_core_id(&did())
                    .expect("registered DID adapter"),
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
        fn unsigned_proof(event: &Event) -> ProducerEventProof {
            ProducerEventProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: verification_method(),
                event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
                    envelope_bytes(event),
                ))
                .expect("valid digest"),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
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
        fn signed_proof(event: &Event) -> ProducerEventProof {
            let mut proof = unsigned_proof(event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws = sign_ed25519_detached_jws(&signing_key(), &binding_bytes).expect("sign");
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
            proof.jws = sign_ed25519_detached_jws(&signing_key(), &bytes).expect("sign");

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
                serde_json::json!({"alg": "Ed25519", "kid": verification_method().as_str()}),
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
        fn an_unsupported_protected_header_algorithm_is_rejected() {
            let document = document(&format!("{}#key-1", did()));
            let accepted = accepted(&document);
            let event = event();
            let mut proof = unsigned_proof(&event);
            let binding_bytes = proof
                .canonical_binding_bytes(&event.actor_id)
                .expect("binding bytes");
            proof.jws =
                detached_jws_with_header(serde_json::json!({"alg": "ES256"}), &binding_bytes);

            let error = verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .unwrap_err();
            assert!(
                matches!(error, BindingVerifyError::Proof { .. }),
                "an unsupported protected header algorithm must be rejected, got {error}"
            );
            let generic_error = Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&proof.jws, &binding_bytes, &public_key())
                .unwrap_err();
            assert!(
                matches!(generic_error, arkret_signatures::VerifierError::Backend(_)),
                "the generic Ed25519 verifier must also reject ES256, got {generic_error}"
            );
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
                serde_json::json!({"alg": "Ed25519", "crit": ["b64"]}),
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
    // Authority path: evidence comes out of the resolver, not the caller
    // ------------------------------------------------------------------

    struct OneShotResolver {
        document: DidDocument,
        method_evidence: MethodEvidence,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl OneShotResolver {
        fn new(document: DidDocument) -> Self {
            Self {
                document,
                method_evidence: MethodEvidence::none(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn with_evidence(document: DidDocument, method_evidence: MethodEvidence) -> Self {
            Self {
                document,
                method_evidence,
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

        fn resolve_did(&self, _did: &Did) -> crate::Result<ResolvedDid> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ResolvedDid::new(
                self.document.clone(),
                self.method_evidence.clone(),
            ))
        }
    }

    /// A `high` tier profile: no stale window, one hour of freshness.
    fn high_profile() -> FreshnessProfile {
        FreshnessProfile {
            freshness_profile_id: "ak.did_freshness.test_high.v1".to_owned(),
            risk_tier: crate::binding::FreshnessRiskTier::High,
            did_method_selector: vec!["*".to_owned()],
            fresh_for_seconds: Some(3_600),
            stale_grace_seconds: None,
            hard_expiry_seconds: Some(86_400),
            stale_behavior: crate::binding::StaleBehavior::SynchronousRefreshOrFailClosed,
        }
    }

    fn request() -> BindingResolveRequest {
        BindingResolveRequest {
            did: did(),
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            policy_digest: hash(0x44),
            verification_method: Some(verification_method()),
            freshness: high_profile(),
        }
    }

    fn webvh_evidence() -> MethodEvidence {
        MethodEvidence {
            proofs: vec![crate::MethodEvidenceProof::WebvhLog(
                crate::WebvhLogEvidence {
                    history_head: "3-QmFixtureHead".to_owned(),
                    witnesses: vec![crate::WebvhWitnessRow {
                        witness_did: Did::new("did:webvh:z6mkfixture:witness.example".to_owned())
                            .expect("valid did"),
                        controlling_organization_did: Did::new(
                            "did:webvh:z6mkfixture:witness-org.example".to_owned(),
                        )
                        .expect("valid did"),
                    }],
                    witness_proofs_digest: hash(0x77),
                },
            )],
            history_head: Some("3-QmFixtureHead".to_owned()),
            version_id: Some("3-QmFixtureHead".to_owned()),
        }
    }

    /// The whole point of the resolver channel: the acceptance's evidence digest
    /// is derived from what the resolver returned, and an auditor recomputes it
    /// from the retained receipt.
    #[test]
    fn the_evidence_digest_is_recomputable_from_the_retained_receipt() {
        let resolver =
            OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
        let store = InMemoryVerifiedDidBindingStore::default();
        let accepted = resolve_and_verify_binding(&resolver, &store, &request(), protocol_now())
            .expect("resolve");

        assert_eq!(
            accepted.binding().evidence_digest(),
            &accepted
                .evidence_receipt()
                .digest()
                .expect("recomputed digest")
        );
        assert_ne!(
            accepted.binding().evidence_digest(),
            accepted.binding().document_digest(),
            "a canonical evidence digest is never the bare document digest"
        );
        assert_eq!(
            accepted.evidence_receipt().document_digest,
            *accepted.binding().document_digest()
        );
    }

    /// §5.6: the dependency record is what makes a witness revocation selective.
    #[test]
    fn evidence_dependencies_are_carried_and_index_the_witness() {
        let resolver =
            OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
        let store = InMemoryVerifiedDidBindingStore::default();
        let accepted = resolve_and_verify_binding(&resolver, &store, &request(), protocol_now())
            .expect("resolve");

        let witness =
            Did::new("did:webvh:z6mkfixture:witness.example".to_owned()).expect("valid did");
        assert_eq!(
            accepted.binding().evidence_dependencies().witness_dids,
            vec![witness.clone()]
        );
        assert_eq!(
            store.invalidate(&crate::BindingInvalidation {
                evidence_witness_did: Some(witness),
                ..Default::default()
            }),
            1
        );
    }

    /// §5.5: an evidence-bearing method that surfaced both pins records no
    /// limited trust at all; a proofless one records `method_unsupported`.
    #[test]
    fn limited_trust_follows_what_the_resolver_surfaced() {
        let store = InMemoryVerifiedDidBindingStore::default();
        let pinned = resolve_and_verify_binding(
            &OneShotResolver::with_evidence(
                document(&format!("{}#key-1", did())),
                webvh_evidence(),
            ),
            &store,
            &request(),
            protocol_now(),
        )
        .expect("resolve");
        assert_eq!(pinned.binding().limited_trust(), None);
        assert_eq!(pinned.binding().history_head(), Some("3-QmFixtureHead"));

        let proofless_store = InMemoryVerifiedDidBindingStore::default();
        let proofless = resolve_and_verify_binding(
            &OneShotResolver::new(document(&format!("{}#key-1", did()))),
            &proofless_store,
            &request(),
            protocol_now(),
        )
        .expect("resolve");
        assert_eq!(
            proofless.binding().limited_trust(),
            Some(LimitedTrust {
                history_head_status: crate::PinState::MethodUnsupported,
                version_id_status: crate::PinState::MethodUnsupported,
            })
        );
    }

    #[test]
    fn a_store_hit_keeps_its_evidence_and_never_reaches_the_resolver_again() {
        let resolver =
            OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
        let store = InMemoryVerifiedDidBindingStore::default();
        let now = protocol_now();

        let first = resolve_and_verify_binding(&resolver, &store, &request(), now).expect("first");
        let second =
            resolve_and_verify_binding(&resolver, &store, &request(), now + Duration::minutes(1))
                .expect("store hit");

        assert_eq!(resolver.calls(), 1);
        assert_eq!(
            first.binding().evidence_digest(),
            second.binding().evidence_digest()
        );
    }

    /// The freshness profile is the single source of the reuse threshold,
    /// `refresh_after` and `expires_at`.
    #[test]
    fn the_freshness_profile_drives_every_window() {
        let resolver = OneShotResolver::new(document(&format!("{}#key-1", did())));
        let store = InMemoryVerifiedDidBindingStore::default();
        let now = protocol_now();
        let request = request();
        let accepted =
            resolve_and_verify_binding(&resolver, &store, &request, now).expect("resolve");

        assert_eq!(accepted.binding().verified_at(), now);
        assert_eq!(
            accepted.binding().refresh_after(),
            Some(now + Duration::hours(1)),
            "refresh_after is verified_at + fresh_for_seconds"
        );
        assert_eq!(
            accepted.binding().expires_at(),
            Some(now + Duration::hours(24))
        );
        assert_eq!(
            request.freshness.requirement().max_age,
            Some(Duration::hours(1)),
            "max_age is the same fresh_for_seconds, never a second constant"
        );
        assert_eq!(store.len(), 1);
        assert!(store.get(&request.key(), now).is_some());
    }
}
