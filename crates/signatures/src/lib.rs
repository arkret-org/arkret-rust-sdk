//! Canonical signatures, proof binding and HTTP message signature helpers.

#[cfg(feature = "signer")]
pub mod signer;

#[cfg(feature = "signer")]
pub use signer::Ed25519MoveSigner;

// Unified Event Envelope proof builder/verifier pipeline. Available without
// the `signer` feature (canonical bytes + traits + dev-proof gating); the
// `signer` feature also exposes the Ed25519 detached-JWS backend.
pub mod proof;

// S-1 (savfox SDK gap): one-shot `sign_event` helper that owns the
// canonical-JSON + detached-JWS pipeline external Applets used to roll
// themselves.
pub mod event_signer;
pub use event_signer::{SignEventOptions, sign_event};

// Single source of truth for RFC 9421 HTTP Message Signatures + RFC 9530
// Content-Digest. floria, teabay, soland, and chime all consume this module;
// the SDK crate re-exports it for compatibility.
pub mod http_signature;
pub mod jwt;

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
pub use cokret_core::Proof as ProtocolProof;
use cokret_core::{
    Audience, Did, Error, Hash, Proof, ProofBindingRequirements, Result, SignatureBindingPayload,
    canonical,
};
pub use jwt::{
    JwtVerificationError, JwtVerificationPolicy, VerifiedJwt, verify_eddsa_jwt_with_jwks,
};
pub use proof::{
    Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventProofBuilder, EventSigner,
    EventVerifier, ProductionVerifier, ProofType, PublicKeyMaterial, SignedPayload, SignerError,
    VerifierError, build_proof_envelope, detached_jws_kind, sign_eddsa_detached_jws,
    verify_detached_ed25519_signature, verify_eddsa_detached_jws_proof,
};
use serde::{Deserialize, Serialize};

/// Production-grade proof algorithms, mirroring the `active` rows of
/// `artifacts/registry/signature-alg-registry.json` (`proof_alg` values) per
/// `encoding.md` §6.1. The v1 active set is `EdDSA` / `ES256` / `ML-DSA-65`;
/// unregistered algorithms (`ES256K` / `RS256` / `PS256`) MUST NOT appear here.
pub const PRODUCTION_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ML-DSA-65"];
pub const HTTP_MESSAGE_SIGNATURE_PROFILE: &str = "ck.http-message-signature.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetachedSignatureBinding {
    pub payload_digest: Hash,
    pub signer: Did,
    pub verification_method: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

impl DetachedSignatureBinding {
    pub fn from_payload<T: Serialize>(
        payload: &T,
        signer: Did,
        verification_method: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            payload_digest: canonical_payload_digest(payload)?,
            signer,
            verification_method: verification_method.into(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
        })
    }

    pub fn proof_binding_payload(&self) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_digest: self.payload_digest.clone(),
            actor_id: self.signer.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

impl DetachedSignature {
    pub fn from_proof(proof: Proof) -> Self {
        Self {
            kind: proof.kind,
            alg: proof.alg,
            verification_method: proof.verification_method,
            payload_digest: proof.event_digest,
            created_at: proof.created_at,
            domain: proof.domain,
            audience: proof.audience,
            jws: proof.jws,
        }
    }

    pub fn into_proof(self) -> Proof {
        Proof {
            kind: self.kind,
            alg: self.alg,
            verification_method: self.verification_method,
            event_digest: self.payload_digest,
            created_at: self.created_at,
            domain: self.domain,
            audience: self.audience,
            jws: self.jws,
        }
    }

    pub fn validate_against(&self, binding: &DetachedSignatureBinding) -> Result<()> {
        self.clone()
            .into_proof()
            .validate_binding(&binding.proof_binding_payload())
    }
}

pub trait DetachedSigner {
    fn sign_detached(&self, binding: &DetachedSignatureBinding) -> Result<DetachedSignature>;
}

pub trait DetachedVerifier {
    fn verify_detached(
        &self,
        binding: &DetachedSignatureBinding,
        signature: &DetachedSignature,
    ) -> Result<SignatureVerification>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethodDocument {
    pub did: Did,
    pub verification_method: String,
    pub public_key_multibase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Did>,
}

pub trait DidVerificationMethodResolver {
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<VerificationMethodDocument>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticDidVerificationMethodResolver {
    methods: BTreeMap<String, VerificationMethodDocument>,
}

impl StaticDidVerificationMethodResolver {
    pub fn insert(&mut self, document: VerificationMethodDocument) {
        self.methods
            .insert(document.verification_method.clone(), document);
    }
}

impl DidVerificationMethodResolver for StaticDidVerificationMethodResolver {
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<VerificationMethodDocument> {
        self.methods
            .get(verification_method)
            .cloned()
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "unknown verification method '{verification_method}'"
                ))
            })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofVerificationContext {
    pub actor_id: Did,
    pub expected_payload_digest: Hash,
    pub now: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    pub replay_window: Duration,
    #[serde(default)]
    pub binding_requirements: ProofBindingRequirements,
}

impl ProofVerificationContext {
    pub fn new(actor_id: Did, expected_payload_digest: Hash) -> Self {
        Self {
            actor_id,
            expected_payload_digest,
            now: Utc::now(),
            domain: None,
            audience: None,
            service_did: None,
            replay_window: Duration::minutes(5),
            binding_requirements: ProofBindingRequirements::local(),
        }
    }

    pub fn cross_domain(mut self, domain: impl Into<String>, audience: Audience) -> Self {
        self.domain = Some(domain.into());
        self.audience = Some(audience);
        self.binding_requirements = ProofBindingRequirements::cross_domain();
        self
    }
}

pub fn verify_proof_with_resolver<R, F>(
    proof: &Proof,
    context: &ProofVerificationContext,
    resolver: &R,
    verify_jws: F,
) -> Result<SignatureVerification>
where
    R: DidVerificationMethodResolver + ?Sized,
    F: Fn(&VerificationMethodDocument, &Proof) -> Result<bool>,
{
    proof.validate_production()?;
    if proof.event_digest != context.expected_payload_digest {
        return Err(Error::Protocol(
            "proof event_digest does not match expected digest".to_owned(),
        ));
    }
    let expected_binding = SignatureBindingPayload {
        payload_digest: context.expected_payload_digest.clone(),
        actor_id: context.actor_id.clone(),
        verification_method: proof.verification_method.clone(),
        created_at: proof.created_at,
        domain: context.domain.clone(),
        audience: context.audience.clone(),
    };
    proof.validate_binding_with_requirements(&expected_binding, context.binding_requirements)?;
    if proof.created_at > context.now + Duration::minutes(5) {
        return Err(Error::Protocol(
            "proof created_at is too far in the future".to_owned(),
        ));
    }
    if context.now - proof.created_at > context.replay_window {
        return Err(Error::Protocol("proof replay window expired".to_owned()));
    }
    if let Some(service_did) = &context.service_did
        && !audience_contains_service(proof.audience.as_ref(), service_did)
    {
        return Err(Error::Protocol(
            "proof audience does not bind service DID".to_owned(),
        ));
    }

    let method = resolver.resolve_verification_method(&proof.verification_method)?;
    let controller = method.controller.as_ref().unwrap_or(&method.did);
    if controller != &context.actor_id {
        return Err(Error::Protocol(
            "proof verification method controller mismatch".to_owned(),
        ));
    }
    // Fail closed: an invalid JWS is an `Err`, never `Ok(valid: false)`.
    // A `verify_proof_with_resolver(...)?` call site therefore cannot
    // silently accept a proof whose signature did not verify.
    if !verify_jws(&method, proof)? {
        return Err(Error::Protocol(
            "proof signature verification failed".to_owned(),
        ));
    }
    Ok(SignatureVerification {
        valid: true,
        warnings: Vec::new(),
    })
}

fn audience_contains_service(audience: Option<&Audience>, service_did: &Did) -> bool {
    match audience {
        Some(Audience::Single(value)) => value == service_did.as_str(),
        Some(Audience::Multiple(values)) => {
            values.iter().any(|value| value == service_did.as_str())
        }
        None => false,
    }
}

/// Success-shaped verification outcome. [`verify_proof_with_resolver`]
/// only ever returns this with `valid == true` — every failed check
/// (binding, replay window, resolver, JWS) surfaces as `Err` so callers
/// cannot fail open by ignoring the `valid` field.
#[must_use = "check `valid` (and `warnings`) — dropping the result silently accepts the proof"]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub valid: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub fn canonical_payload_digest<T: Serialize>(payload: &T) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(payload)?).map_err(Into::into)
}

pub fn validate_production_proof(proof: &Proof) -> Result<()> {
    proof.validate_production()
}

/// Wire-form HTTP Message Signature container.
///
/// The canonical struct now lives in `cokret-core` (`cokret_core::http`) so the
/// federation wire contracts can embed it without depending on this crate. The
/// canonical signature base (the bytes actually signed) is still built by the
/// single RFC 9421 implementation in [`crate::http_signature`].
pub use cokret_core::HttpMessageSignature;

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn canonical_payload_digest_matches_sha256_shape() {
        let hash = canonical_payload_digest(&json!({"b": 2, "a": 1})).unwrap();
        assert!(hash.as_str().starts_with("sha256:"));
    }

    #[test]
    fn detached_signature_validates_core_proof_binding() {
        let binding = DetachedSignatureBinding::from_payload(
            &json!({"hello": "world"}),
            did("alice"),
            "did:web:alice.example#key-1",
        )
        .unwrap();
        let signature = DetachedSignature {
            kind: "did".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: binding.verification_method.clone(),
            payload_digest: binding.payload_digest.clone(),
            created_at: binding.created_at,
            domain: None,
            audience: None,
            jws: "sig".to_owned(),
        };

        signature.validate_against(&binding).unwrap();
    }

    #[test]
    fn proof_verifier_resolves_method_binds_service_and_replay_window() {
        let actor = did("alice");
        let payload_digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let mut resolver = StaticDidVerificationMethodResolver::default();
        resolver.insert(VerificationMethodDocument {
            did: actor.clone(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            public_key_multibase: "zKey".to_owned(),
            controller: None,
        });
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            event_digest: payload_digest.clone(),
            created_at: Utc::now(),
            domain: Some("api.example".to_owned()),
            audience: Some(Audience::Single("did:web:service.example".to_owned())),
            jws: "sig".to_owned(),
        };
        let mut context = ProofVerificationContext::new(actor, payload_digest);
        context.domain = proof.domain.clone();
        context.audience = proof.audience.clone();
        context.service_did = Some(did("service"));

        let verified = verify_proof_with_resolver(&proof, &context, &resolver, |method, proof| {
            Ok(method.public_key_multibase == "zKey" && proof.jws == "sig")
        })
        .unwrap();
        assert!(verified.valid);

        // Fail closed: an invalid JWS surfaces as Err, never Ok(valid: false).
        assert!(matches!(
            verify_proof_with_resolver(&proof, &context, &resolver, |_, _| Ok(false)),
            Err(Error::Protocol(_))
        ));

        let mut stale = context;
        stale.now = proof.created_at + Duration::minutes(10);
        assert!(matches!(
            verify_proof_with_resolver(&proof, &stale, &resolver, |_, _| Ok(true)),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn proof_verifier_cross_domain_context_requires_explicit_binding() {
        let actor = did("alice");
        let payload_digest =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let mut resolver = StaticDidVerificationMethodResolver::default();
        resolver.insert(VerificationMethodDocument {
            did: actor.clone(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            public_key_multibase: "zKey".to_owned(),
            controller: None,
        });
        let mut proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            event_digest: payload_digest.clone(),
            created_at: Utc::now(),
            domain: None,
            audience: Some(Audience::Single("did:web:service.example".to_owned())),
            jws: "sig".to_owned(),
        };
        let context = ProofVerificationContext::new(actor, payload_digest).cross_domain(
            "ck:trust_domain:example.net",
            Audience::Single("did:web:service.example".to_owned()),
        );

        let error = verify_proof_with_resolver(&proof, &context, &resolver, |_, _| Ok(true))
            .unwrap_err();
        assert!(
            error.to_string().contains("proof_binding_missing"),
            "{error}"
        );

        proof.domain = Some("ck:trust_domain:example.net".to_owned());
        assert!(
            verify_proof_with_resolver(&proof, &context, &resolver, |_, _| Ok(true))
                .unwrap()
                .valid
        );
    }
}
