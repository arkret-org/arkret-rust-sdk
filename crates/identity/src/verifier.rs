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
//! authority commit, device authorization, agent signer evidence or a pinned
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
    AcceptedDidBinding, BindingFreshness, BindingInvalidation, BindingStoreError,
    VerifiedDidBindingStore,
};
use crate::test_material::{
    FormalTestMaterialPolicyError, PublicKeyFingerprintInput, enforce_formal_test_material_policy,
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
    /// Published signing material or a reserved identifier cannot authorize a claim.
    #[error(transparent)]
    TestMaterial(#[from] FormalTestMaterialPolicyError),
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
///    then the fragment-less `did:key` embedded method — the exact lookup order of
///    [`crate::resolve_verification_method_key_from_document`], because DID Document
///    `verificationMethod[].id` entries are commonly relative `#key-1` references);
/// 5. the material decodes to an Ed25519 key (multibase or JWK);
/// 6. the key fingerprint, DID and key id are not registered test material;
/// 7. the detached JWS verifies over `canonical_bytes`.
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
    validate_verification_method_relationship(
        document,
        verification_method,
        authority,
        relationship,
    )?;
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
    enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(
            verifying_key.as_bytes(),
        )),
        Some(&document.id),
        Some(verification_method),
        None,
    )?;
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: verifying_key.to_bytes().to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(jws, canonical_bytes, &public_key)
        .map_err(|source| BindingVerifyError::Proof { source })
}

/// Validate a method's authority and relationship in an already-verified
/// current DID document without resolving the DID or verifying a signature.
///
/// Callers must separately verify the object-family transcript and resolve the
/// key material. Merely finding a key in `verificationMethod` is not evidence
/// that the authority permits it to issue assertions.
pub fn validate_verification_method_relationship(
    document: &DidDocument,
    verification_method: &DidUrl,
    authority: &Did,
    relationship: DidVerificationRelationship,
) -> Result<(), BindingVerifyError> {
    if &document.id != authority {
        return Err(BindingVerifyError::DocumentIssuerMismatch {
            document_did: document.id.clone(),
            issuer: authority.clone(),
        });
    }
    let property = relationship.property_name();
    let normalized = document.raw_properties.contains_key("did");
    let wire_property = if normalized {
        match relationship {
            DidVerificationRelationship::AssertionMethod => "assertion_methods",
        }
    } else {
        property
    };
    let relationship_value = document.raw_properties.get(wire_property).ok_or_else(|| {
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
        let reference = entry.as_str().or_else(|| {
            entry
                .as_object()?
                .get(if normalized {
                    "verification_method"
                } else {
                    "id"
                })?
                .as_str()
        });
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
    let normalized = document.raw_properties.contains_key("did");
    let methods = document.raw_properties.get(if normalized {
        "verification_methods"
    } else {
        "verificationMethod"
    })?;
    let entries = methods.as_array()?;
    entries.iter().find_map(|entry| {
        let object = entry.as_object()?;
        let id = object
            .get(if normalized {
                "verification_method"
            } else {
                "id"
            })?
            .as_str()?;
        (absolutize_document_reference(&document.id, id) == verification_method)
            .then(|| {
                object
                    .get(if normalized {
                        "controller_did"
                    } else {
                        "controller"
                    })?
                    .as_str()
            })
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
/// URL, bare fragment, `#`-prefixed fragment, then the fragment-less `did:key`
/// embedded method.
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
/// 5. the resolved key and bound identifiers are not registered test material;
/// 6. the Event proof verifies under the Event profile.
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
    let public_key_bytes =
        public_key
            .ed25519_bytes()
            .map_err(|error| BindingVerifyError::PublicKeyMaterial {
                reason: error.to_string(),
            })?;
    enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(
            &public_key_bytes,
        )),
        Some(binding.did()),
        Some(presented),
        Some(binding.trust_domain()),
    )?;
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
/// canonical embedded method. All entry points share the same lookup.
fn lookup_verification_method_material<'a>(
    document: &'a DidDocument,
    verification_method: &str,
) -> Result<&'a str, BindingVerifyError> {
    if let Some((_, value)) = crate::lookup_verification_method_entry(document, verification_method)
    {
        return Ok(value);
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
    /// the single source of the reuse threshold, `refresh_at` and
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

fn evict_binding_key(store: &dyn VerifiedDidBindingStore, key: &VerifiedDidBindingKey) {
    let mut selector = BindingInvalidation::for_did(key.did.clone())
        .with_trust_domain(key.trust_domain.clone())
        .with_purpose(key.purpose)
        .with_policy_digest(key.policy_digest.clone());
    if let Some(method) = &key.verification_method {
        selector = selector.with_verification_method(method.clone());
    }
    store.invalidate(&selector);
}

fn enforce_document_test_material_policy(
    document: &DidDocument,
    trust_domain: &TrustDomainId,
) -> Result<(), BindingResolveError> {
    enforce_formal_test_material_policy(None, Some(&document.id), None, Some(trust_domain))?;
    for (method_id, material) in &document.verification_methods {
        let absolute = if method_id.starts_with("did:") {
            method_id.clone()
        } else {
            format!("{}#{}", document.id, method_id.trim_start_matches('#'))
        };
        let key_id = DidUrl::new(absolute)
            .map_err(|error| BindingResolveError::PublicKeyMaterial(error.to_owned()))?;
        enforce_formal_test_material_policy(
            None,
            Some(&document.id),
            Some(&key_id),
            Some(trust_domain),
        )?;

        let material = material
            .trim()
            .strip_prefix("did:key:")
            .unwrap_or(material.trim());
        if material.starts_with('z') {
            if let Ok(bytes) = arkret_canonical::decode_ed25519_multibase(material) {
                enforce_formal_test_material_policy(
                    Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&bytes)),
                    Some(&document.id),
                    Some(&key_id),
                    Some(trust_domain),
                )?;
            }
            continue;
        }
        if !material.starts_with('{') {
            continue;
        }
        let jwk: serde_json::Value = serde_json::from_str(material)
            .map_err(|error| BindingResolveError::PublicKeyMaterial(error.to_string()))?;
        match (
            jwk.get("kty").and_then(serde_json::Value::as_str),
            jwk.get("crv").and_then(serde_json::Value::as_str),
        ) {
            (Some("OKP"), Some("Ed25519")) => {
                let bytes = PublicKeyMaterial::Jwk { value: jwk }
                    .ed25519_bytes()
                    .map_err(|error| BindingResolveError::PublicKeyMaterial(error.to_string()))?;
                enforce_formal_test_material_policy(
                    Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&bytes)),
                    Some(&document.id),
                    Some(&key_id),
                    Some(trust_domain),
                )?;
            }
            (Some("EC"), Some("P-256")) => {
                let decode = |member: &str| -> Result<Vec<u8>, BindingResolveError> {
                    let value = jwk
                        .get(member)
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            BindingResolveError::PublicKeyMaterial(format!(
                                "P-256 JWK missing {member}"
                            ))
                        })?;
                    arkret_canonical::base64url::base64url_decode(value)
                        .map_err(|error| BindingResolveError::PublicKeyMaterial(error.to_string()))
                };
                let x = decode("x")?;
                let y = decode("y")?;
                if x.len() != 32 || y.len() != 32 {
                    return Err(BindingResolveError::PublicKeyMaterial(
                        "P-256 JWK coordinates must each be 32 bytes".to_owned(),
                    ));
                }
                let mut bytes = Vec::with_capacity(65);
                bytes.push(0x04);
                bytes.extend(x);
                bytes.extend(y);
                enforce_formal_test_material_policy(
                    Some(&PublicKeyFingerprintInput::P256Sec1Uncompressed(&bytes)),
                    Some(&document.id),
                    Some(&key_id),
                    Some(trust_domain),
                )?;
            }
            (Some("AKP"), _)
                if jwk.get("alg").and_then(serde_json::Value::as_str) == Some("ML-DSA-65") =>
            {
                let encoded = jwk
                    .get("pub")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        BindingResolveError::PublicKeyMaterial(
                            "ML-DSA-65 JWK missing pub".to_owned(),
                        )
                    })?;
                let bytes = arkret_canonical::base64url::base64url_decode(encoded)
                    .map_err(|error| BindingResolveError::PublicKeyMaterial(error.to_string()))?;
                enforce_formal_test_material_policy(
                    Some(&PublicKeyFingerprintInput::MlDsa65Fips204(&bytes)),
                    Some(&document.id),
                    Some(&key_id),
                    Some(trust_domain),
                )?;
            }
            _ => {}
        }
    }
    Ok(())
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
    /// The selected DID document contains published test signing material or a reserved identifier.
    #[error(transparent)]
    TestMaterial(#[from] FormalTestMaterialPolicyError),
    /// A recognized public-key encoding cannot be decoded to algorithm-defined bytes.
    #[error("DID verification method public key material rejected: {0}")]
    PublicKeyMaterial(String),
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
/// 2. reject and evict a cached binding whose pinned document contains registered test material;
/// 3. on a remaining hit that satisfies the request's freshness profile, return it **without
///    calling the resolver**;
/// 4. otherwise call `resolver.resolve_did` **exactly once**, verify the document belongs to the
///    requested DID (and carries the requested verification method), reject registered test
///    material before building the §5.2 evidence receipt or calling `accept()`.
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
    if let Some(accepted) = &hit
        && let Err(error) =
            enforce_document_test_material_policy(accepted.document(), &request.trust_domain)
    {
        evict_binding_key(store, &key);
        return Err(error);
    }
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

    if let Err(error) = enforce_document_test_material_policy(&document, &request.trust_domain) {
        evict_binding_key(store, &key);
        return Err(error);
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
            refresh_at: request.freshness.refresh_at(now),
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
#[path = "verifier/tests.rs"]
mod tests;
