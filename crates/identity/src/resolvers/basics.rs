use arkret_wire::{DidCoreId, DidFullId};

use crate::*;

/// A resolution: the verified document plus the method evidence backing it.
///
/// `did-usage-and-verification.md` §5.2 makes this shape normative. webvh log
/// heads, witness proof sets and consistency material exist only inside the
/// resolver and cannot be derived from a DID Document, so a resolver contract
/// that returns the document alone leaves the caller no way to compute an
/// evidence digest that carries evidence — which is how one deployment ended up
/// with `evidence_digest == document_digest` and another with a hard-coded
/// constant. "The caller supplies the evidence digest afterwards" is explicitly
/// non-conformant; the evidence travels with the resolution or it does not exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDid {
    pub document: DidDocument,
    /// What the method itself proves. [`MethodEvidence::none`] for a proofless
    /// method (`did:key`, bare `did:web`) — the one normative degenerate form.
    #[serde(default)]
    pub method_evidence: MethodEvidence,
}

impl ResolvedDid {
    /// A resolution by a method that publishes no verifiable evidence.
    pub fn proofless(document: DidDocument) -> Self {
        Self {
            document,
            method_evidence: MethodEvidence::none(),
        }
    }

    /// A resolution carrying the evidence its method published.
    pub fn new(document: DidDocument, method_evidence: MethodEvidence) -> Self {
        Self {
            document,
            method_evidence,
        }
    }
}

/// Resolve DID documents for one or more DID methods.
pub trait DidResolver {
    /// Return whether this resolver can handle the DID method or concrete DID.
    fn supports(&self, did: &DidFullId) -> bool;

    /// Resolve a DID, returning the document **and** its method evidence.
    fn resolve_did(&self, did: &DidFullId) -> Result<ResolvedDid>;

    /// Resolve a DID and keep only the document.
    ///
    /// For call sites that legitimately need nothing but the document (rendering
    /// a handle, looking up a public key for an ordinary signature check). An
    /// authority path MUST NOT use it: it drops exactly the material §5.2
    /// requires the evidence receipt to commit to.
    fn resolve_did_document(&self, did: &DidFullId) -> Result<DidDocument> {
        Ok(self.resolve_did(did)?.document)
    }
}

/// Public key material resolved from a DID document verification method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedVerificationMethodKey {
    pub did: DidFullId,
    /// Registered exemption from the `DidUrl` migration
    /// (`did-usage-and-verification.md` §2.2 / §6): this field stays a `String`.
    ///
    /// It carries the DID Document's `verificationMethod[].id` **verbatim**, and
    /// DID Core 1.0 §3.1 explicitly allows that id to be a *relative* DID URL
    /// (`#key-1`). [`DidUrl::new`] begins with `strip_prefix("did:")`, so typing
    /// this field as `DidUrl` would make every did:web / did:webvh document that
    /// publishes relative references hard-fail inside the resolver instead of
    /// being judged at the policy layer.
    ///
    /// The exemption covers **only** values carried verbatim out of a DID
    /// Document. Before this value is compared against anything on the wire — a
    /// `ProducerEventProof.verification_method`, an `auth_data.verification_method`, a
    /// `binding_proof.verification_method` — it MUST be absolutized into a
    /// `DidUrl` via [`ResolvedVerificationMethodKey::absolutize`], which is the
    /// single exit from this exemption.
    pub verification_method: String,
    pub public_key: arkret_signatures::PublicKeyMaterial,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidFullId>,
}

impl ResolvedVerificationMethodKey {
    /// Absolutize the DID Document reference into a wire-comparable [`DidUrl`].
    ///
    /// This is the only sanctioned way to move [`Self::verification_method`] out
    /// of the exemption described on that field. A relative reference
    /// (`#key-1`) is resolved against `did`; an already-absolute reference is
    /// validated as-is and MUST belong to `did`.
    pub fn absolutize(&self, did: &DidFullId) -> Result<DidUrl> {
        let reference = self.verification_method.trim();
        if reference.is_empty() {
            return Err(IdentityError::Protocol(
                "verification method reference must not be empty".to_owned(),
            ));
        }
        if let Some(fragment) = reference.strip_prefix('#') {
            return DidUrl::new(format!("{}#{fragment}", did.as_str()))
                .map_err(|reason| IdentityError::Protocol(reason.to_owned()));
        }
        let absolute =
            DidUrl::new(reference).map_err(|reason| IdentityError::Protocol(reason.to_owned()))?;
        if verification_method_did(absolute.as_str())? != *did {
            return Err(IdentityError::Protocol(format!(
                "verification method '{absolute}' is not controlled by {did}"
            )));
        }
        Ok(absolute)
    }
}

/// Extract the controller DID portion from a DID URL verification method.
pub fn verification_method_did(verification_method: &str) -> Result<DidFullId> {
    if verification_method.trim().is_empty() {
        return Err(IdentityError::Protocol(
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
    DidFullId::new(verification_method[..end].to_owned()).map_err(IdentityError::from)
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
        verification_method: method_id,
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
    let document = resolver.resolve_did_document(&did)?;
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

impl<R> arkret_signatures::DidVerificationMethodResolver
    for DidDocumentVerificationMethodResolver<'_, R>
where
    R: DidResolver + ?Sized,
{
    fn resolve_verification_method(
        &self,
        verification_method: &DidUrl,
    ) -> arkret_signatures::Result<arkret_signatures::VerificationMethodDocument> {
        let did = verification_method_did(verification_method).map_err(to_signature_error)?;
        let document = self
            .resolver
            .resolve_did_document(&did)
            .map_err(to_signature_error)?;
        let (method_id, public_key_value) =
            lookup_verification_method_value(&document, verification_method)
                .map_err(to_signature_error)?;
        // `method_id` is the DID Document's verbatim reference (possibly the
        // DID Core relative form). The signatures crate compares it against
        // wire proofs, so it crosses the exemption boundary here and MUST be
        // absolutized first.
        let resolved = ResolvedVerificationMethodKey {
            did: document.id.clone(),
            verification_method: method_id,
            public_key: public_key_material_from_did_document_value(&public_key_value)
                .map_err(to_signature_error)?,
            controller: None,
        };
        let absolute = resolved
            .absolutize(&document.id)
            .map_err(to_signature_error)?;
        Ok(arkret_signatures::VerificationMethodDocument {
            did: document.id,
            verification_method: absolute,
            public_key_multibase: public_key_value,
            controller: None,
        })
    }
}

/// Downcast the SDK facade error into the signature-layer error for the
/// resolver adapter above. The signatures crate owns its boundary error and
/// (by design) has no `From<IdentityError>`; the facade message is
/// carried verbatim.
fn to_signature_error(error: IdentityError) -> arkret_signatures::Error {
    match error {
        IdentityError::Protocol(message) => arkret_signatures::Error::Protocol(message),
        IdentityError::Crypto(message) => arkret_signatures::Error::Crypto(message),
        other => arkret_signatures::Error::Protocol(other.to_string()),
    }
}

/// Verify an Arkret [`ProducerEventProof`] over caller-supplied canonical bytes by
/// resolving `proof.verification_method` through a DID document.
///
/// `binding_actor_id` is the `actor_id` folded into the canonical proof
/// binding object (`encoding.md` §6) — for Event proofs this is the Event
/// envelope's `actor_id` field, which may differ from the controller actor
/// (`executed_by`) used for the verification-method binding check.
pub fn verify_canonical_proof_with_did_resolver<R>(
    canonical_bytes: &[u8],
    proof: &ProducerEventProof,
    binding_actor_id: &DidCoreId,
    context: &arkret_signatures::ProofVerificationContext,
    resolver: &R,
) -> Result<arkret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let adapter = DidDocumentVerificationMethodResolver::new(resolver);
    Ok(arkret_signatures::verify_proof_with_resolver(
        proof,
        context,
        &adapter,
        |method, proof| {
            let public_key =
                public_key_material_from_did_document_value(&method.public_key_multibase)
                    .map_err(to_signature_error)?;
            arkret_signatures::verify_ed25519_detached_jws_proof(
                proof,
                canonical_bytes,
                binding_actor_id,
                &public_key,
            )?;
            Ok(true)
        },
    )?)
}

/// Verify an Event Envelope proof with DID-document key discovery.
///
/// When `event.executed_by` is present, the proof controller is bound to
/// that DID; otherwise it is bound to `event.actor_id`.
pub fn verify_event_proof_with_did_resolver<R>(
    event: &Event,
    proof: &ProducerEventProof,
    resolver: &R,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<arkret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let context = event_proof_verification_context_with_digest_suite(event, digest_suite)?;
    verify_event_proof_with_did_resolver_context(event, proof, resolver, context)
}

pub fn verify_event_proof_with_did_resolver_context<R>(
    event: &Event,
    proof: &ProducerEventProof,
    resolver: &R,
    context: arkret_signatures::ProofVerificationContext,
) -> Result<arkret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let builder = arkret_signatures::EventProofBuilder::new();
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

/// Build an Event proof context with the active digest suite of its Realm.
pub fn event_proof_verification_context_with_digest_suite(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<arkret_signatures::ProofVerificationContext> {
    let builder = arkret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(event)?;
    let expected_digest = Hash::new(arkret_canonical::canonical::digest(
        digest_suite,
        &canonical_bytes,
    ))?;
    let signing_actor = event
        .executed_by
        .clone()
        .unwrap_or_else(|| event.actor_id.clone());
    Ok(arkret_signatures::ProofVerificationContext::new(
        signing_actor,
        expected_digest,
    ))
}

/// Resolve a verification method reference against a DID document's
/// `verificationMethod` map.
///
/// Lookup order, widest-wins:
///
/// 1. the full DID URL as published;
/// 2. the bare fragment (`key-1`);
/// 3. the `#`-prefixed fragment (`#key-1`);
/// 4. the `did:key` single-method shortcut.
///
/// Steps 2 and 3 both exist because DID Core 1.0 §3.1 allows
/// `verificationMethod[].id` to be a *relative* DID URL, and
/// [`DidDocument`] keeps whatever the wire published verbatim — both spellings
/// occur in practice. Step 3 was previously missing here while
/// `crate::verifier`'s lookup had it, so a document storing `"#key-1"` verified
/// a JWS but failed key resolution; downstream repos papered over the gap with
/// their own retry. The two lookups are now deliberately identical, and
/// `crate::verifier::lookups_agree_on_every_document_shape` pins that.
fn lookup_verification_method_value(
    document: &DidDocument,
    verification_method: &str,
) -> Result<(String, String)> {
    if let Some(value) = document.verification_methods.get(verification_method) {
        return Ok((verification_method.to_owned(), value.clone()));
    }
    if let Some(fragment) = verification_method_fragment(verification_method) {
        if let Some(value) = document.verification_methods.get(fragment) {
            return Ok((fragment.to_owned(), value.clone()));
        }
        let relative = format!("#{fragment}");
        if let Some(value) = document.verification_methods.get(&relative) {
            return Ok((relative, value.clone()));
        }
    }
    if document.id.method() == "key"
        && document.verification_methods.len() == 1
        && let Some((method_id, value)) = document.verification_methods.iter().next()
    {
        return Ok((method_id.clone(), value.clone()));
    }
    Err(IdentityError::Protocol(format!(
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
) -> Result<arkret_signatures::PublicKeyMaterial> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        let jwk: Value = serde_json::from_str(trimmed)?;
        return Ok(arkret_signatures::PublicKeyMaterial::Jwk { value: jwk });
    }
    let multibase = trimmed.strip_prefix("did:key:").unwrap_or(trimmed);
    if multibase.starts_with('z') {
        return Ok(arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    Err(IdentityError::Protocol(
        "DID verification method must carry Ed25519 publicKeyMultibase or publicKeyJwk".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn document(id: &str, method_id: &str) -> DidDocument {
        DidDocument {
            id: DidFullId::new(id).unwrap(),
            verification_methods: BTreeMap::from([(
                method_id.to_owned(),
                "z6MkhWg7i8fV9nqC2jL4sP6tR1xY3aB5dE7gH9kM2pQ4uV6w".to_owned(),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        }
    }

    #[test]
    fn non_did_key_does_not_fall_back_to_an_unrelated_single_method() {
        let document = document(
            "did:webvh:z6mkfixture:example.com",
            "did:webvh:z6mkfixture:example.com#key-1",
        );
        assert!(
            lookup_verification_method_value(
                &document,
                "did:webvh:z6mkfixture:example.com#missing",
            )
            .is_err()
        );
    }

    #[test]
    fn did_key_retains_the_single_method_fallback() {
        let document = document(
            "did:key:z6MkhWg7i8fV9nqC2jL4sP6tR1xY3aB5dE7gH9kM2pQ4uV6w",
            "did:key:z6MkhWg7i8fV9nqC2jL4sP6tR1xY3aB5dE7gH9kM2pQ4uV6w#z6MkhWg7i8fV9nqC2jL4sP6tR1xY3aB5dE7gH9kM2pQ4uV6w",
        );
        assert!(
            lookup_verification_method_value(
                &document,
                "did:key:z6MkhWg7i8fV9nqC2jL4sP6tR1xY3aB5dE7gH9kM2pQ4uV6w",
            )
            .is_ok()
        );
    }
}
