use crate::identity::*;

/// Resolve DID documents for one or more DID methods.
pub trait DidResolver {
    /// Return whether this resolver can handle the DID method or concrete DID.
    fn supports(&self, did: &Did) -> bool;

    /// Resolve a DID document.
    fn resolve_did(&self, did: &Did) -> Result<DidDocument>;
}

/// Public key material resolved from a DID document verification method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedVerificationMethodKey {
    pub did: Did,
    pub verification_method: String,
    pub public_key: cokret_signatures::PublicKeyMaterial,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Did>,
}

/// Extract the controller DID portion from a DID URL verification method.
pub fn verification_method_did(verification_method: &str) -> Result<Did> {
    if verification_method.trim().is_empty() {
        return Err(Error::Protocol(
            "verification_method must not be empty".to_owned(),
        ));
    }
    let hash = verification_method.find('#');
    let query = verification_method.find('?');
    let end = match (hash, query) {
        (Some(hash), Some(query)) => hash.min(query),
        (Some(hash), None) => hash,
        (None, Some(query)) => query,
        (None, None) => verification_method.len(),
    };
    Did::new(verification_method[..end].to_owned()).map_err(Error::from)
}

/// Resolve a verification method key from an already-resolved DID document.
pub fn resolve_verification_method_key_from_document(
    document: &DidDocument,
    verification_method: &str,
) -> Result<ResolvedVerificationMethodKey> {
    let (method_id, public_key_value) =
        lookup_verification_method_value(document, verification_method)?;
    Ok(ResolvedVerificationMethodKey {
        did: document.id.clone(),
        verification_method: method_id.to_owned(),
        public_key: public_key_material_from_did_document_value(&public_key_value)?,
        controller: None,
    })
}

/// Resolve a verification method key through any [`DidResolver`].
pub fn resolve_verification_method_key<R>(
    resolver: &R,
    verification_method: &str,
) -> Result<ResolvedVerificationMethodKey>
where
    R: DidResolver + ?Sized,
{
    let did = verification_method_did(verification_method)?;
    let document = resolver.resolve_did(&did)?;
    resolve_verification_method_key_from_document(&document, verification_method)
}

/// Adapter that lets the signatures crate verify proofs through a live DID
/// resolver instead of a static trusted-key map.
#[derive(Clone, Copy, Debug)]
pub struct DidDocumentVerificationMethodResolver<'a, R: DidResolver + ?Sized> {
    resolver: &'a R,
}

impl<'a, R: DidResolver + ?Sized> DidDocumentVerificationMethodResolver<'a, R> {
    pub fn new(resolver: &'a R) -> Self {
        Self { resolver }
    }
}

impl<R> cokret_signatures::DidVerificationMethodResolver
    for DidDocumentVerificationMethodResolver<'_, R>
where
    R: DidResolver + ?Sized,
{
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<cokret_signatures::VerificationMethodDocument> {
        let did = verification_method_did(verification_method)?;
        let document = self.resolver.resolve_did(&did)?;
        let (method_id, public_key_value) =
            lookup_verification_method_value(&document, verification_method)?;
        Ok(cokret_signatures::VerificationMethodDocument {
            did: document.id,
            verification_method: method_id.to_owned(),
            public_key_multibase: public_key_value.to_owned(),
            controller: None,
        })
    }
}

/// Verify a Cokret [`Proof`] over caller-supplied canonical bytes by
/// resolving `proof.verification_method` through a DID document.
///
/// `binding_actor_id` is the `actor_id` folded into the canonical proof
/// binding object (`encoding.md` §6) — for Event proofs this is the Event
/// envelope's `actor_id` field, which may differ from the controller actor
/// (`executed_by`) used for the verification-method binding check.
pub fn verify_canonical_proof_with_did_resolver<R>(
    canonical_bytes: &[u8],
    proof: &crate::Proof,
    binding_actor_id: &Did,
    context: &cokret_signatures::ProofVerificationContext,
    resolver: &R,
) -> Result<cokret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let adapter = DidDocumentVerificationMethodResolver::new(resolver);
    cokret_signatures::verify_proof_with_resolver(proof, context, &adapter, |method, proof| {
        let public_key = public_key_material_from_did_document_value(&method.public_key_multibase)?;
        cokret_signatures::verify_eddsa_detached_jws_proof(
            proof,
            canonical_bytes,
            binding_actor_id,
            &public_key,
        )
        .map_err(Error::from)?;
        Ok(true)
    })
}

/// Verify an Event Envelope proof with DID-document key discovery.
///
/// When `event.executed_by` is present, the proof controller is bound to
/// that DID; otherwise it is bound to `event.actor_id`.
pub fn verify_event_proof_with_did_resolver<R>(
    event: &crate::Event,
    proof: &crate::Proof,
    resolver: &R,
) -> Result<cokret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let context = event_proof_verification_context(event)?;
    verify_event_proof_with_did_resolver_context(event, proof, resolver, context)
}

pub fn verify_event_proof_with_did_resolver_context<R>(
    event: &crate::Event,
    proof: &crate::Proof,
    resolver: &R,
    context: cokret_signatures::ProofVerificationContext,
) -> Result<cokret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let builder = cokret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(event)?;
    // Binding object `actor_id` is the Event envelope's `actor_id` (spec §6
    // L201), independent of the controller actor (`executed_by`) above.
    verify_canonical_proof_with_did_resolver(
        &canonical_bytes,
        proof,
        &event.actor_id,
        &context,
        resolver,
    )
}

pub fn event_proof_verification_context(
    event: &crate::Event,
) -> Result<cokret_signatures::ProofVerificationContext> {
    let builder = cokret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(event)?;
    let expected_digest =
        crate::Hash::new(cokret_core::canonical::sha256_digest(&canonical_bytes))?;
    let signing_actor = event
        .executed_by
        .clone()
        .unwrap_or_else(|| event.actor_id.clone());
    Ok(cokret_signatures::ProofVerificationContext::new(
        signing_actor,
        expected_digest,
    ))
}

fn lookup_verification_method_value(
    document: &DidDocument,
    verification_method: &str,
) -> Result<(String, String)> {
    if let Some(value) = document.verification_methods.get(verification_method) {
        return Ok((verification_method.to_owned(), value.clone()));
    }
    if let Some(fragment) = verification_method_fragment(verification_method)
        && let Some(value) = document.verification_methods.get(fragment)
    {
        return Ok((fragment.to_owned(), value.clone()));
    }
    if document.verification_methods.len() == 1
        && let Some((method_id, value)) = document.verification_methods.iter().next()
    {
        return Ok((method_id.clone(), value.clone()));
    }
    Err(Error::Protocol(format!(
        "verification_method `{verification_method}` not found in DID document for `{}`",
        document.id
    )))
}

fn verification_method_fragment(verification_method: &str) -> Option<&str> {
    let (_, after_hash) = verification_method.split_once('#')?;
    let end = after_hash.find('?').unwrap_or(after_hash.len());
    Some(&after_hash[..end])
}

fn public_key_material_from_did_document_value(
    value: &str,
) -> Result<cokret_signatures::PublicKeyMaterial> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        let jwk: Value = serde_json::from_str(trimmed)?;
        return Ok(cokret_signatures::PublicKeyMaterial::Jwk { value: jwk });
    }
    let multibase = trimmed.strip_prefix("did:key:").unwrap_or(trimmed);
    if multibase.starts_with('z') {
        return Ok(cokret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    Err(Error::Protocol(
        "DID verification method must carry Ed25519 publicKeyMultibase or publicKeyJwk".to_owned(),
    ))
}
