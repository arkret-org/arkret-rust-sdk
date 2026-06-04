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

// 报告 03 #5 / 09 #2 收敛:RFC 9421 HTTP Message Signatures + RFC 9530
// Content-Digest 的**唯一**真源实现。floria(push)、teabay(ingest)、soland
// (federation)、chime 全部消费这一套(此前下沉前位于 `sdk::http_signature`);
// `sdk` 现以 `pub use cokret_signatures::http_signature` re-export。
pub mod http_signature;

pub use proof::{
    EventProofBuilder, EventSigner, EventVerifier, ProductionVerifier, ProofType,
    PublicKeyMaterial, SignedPayload, SignerError, VerifierError, build_proof_envelope,
    detached_jws_kind,
};

#[cfg(feature = "signer")]
pub use proof::{Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier};

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use cokret_core::{Audience, Did, Error, Hash, Proof, Result, SignatureBindingPayload, canonical};
use serde::{Deserialize, Serialize};

pub use cokret_core::Proof as ProtocolProof;

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
            payload_digest: proof.payload_digest,
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
            payload_digest: self.payload_digest,
            created_at: self.created_at,
            domain: self.domain,
            audience: self.audience,
            jws: self.jws,
        }
    }

    pub fn validate_against(&self, binding: &DetachedSignatureBinding) -> Result<()> {
        self.clone().into_proof().validate_binding(&binding.proof_binding_payload())
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
        self.methods.insert(document.verification_method.clone(), document);
    }
}

impl DidVerificationMethodResolver for StaticDidVerificationMethodResolver {
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<VerificationMethodDocument> {
        self.methods.get(verification_method).cloned().ok_or_else(|| {
            Error::Protocol(format!("unknown verification method '{verification_method}'"))
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
        }
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
    if proof.payload_digest != context.expected_payload_digest {
        return Err(Error::Protocol(
            "proof payload_digest does not match expected digest".to_owned(),
        ));
    }
    if proof.domain != context.domain {
        return Err(Error::Protocol("proof domain mismatch".to_owned()));
    }
    if proof.audience != context.audience {
        return Err(Error::Protocol("proof audience mismatch".to_owned()));
    }
    if proof.created_at > context.now + Duration::minutes(5) {
        return Err(Error::Protocol("proof created_at is too far in the future".to_owned()));
    }
    if context.now - proof.created_at > context.replay_window {
        return Err(Error::Protocol("proof replay window expired".to_owned()));
    }
    if let Some(service_did) = &context.service_did
        && !audience_contains_service(proof.audience.as_ref(), service_did)
    {
        return Err(Error::Protocol("proof audience does not bind service DID".to_owned()));
    }

    let method = resolver.resolve_verification_method(&proof.verification_method)?;
    let controller = method.controller.as_ref().unwrap_or(&method.did);
    if controller != &context.actor_id {
        return Err(Error::Protocol("proof verification method controller mismatch".to_owned()));
    }
    Ok(SignatureVerification { valid: verify_jws(&method, proof)?, warnings: Vec::new() })
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
/// `key_id` / `alg` / `signed_fields` / `signature` mirror the RFC 9421
/// `Signature-Input` parameters plus the detached `Signature` value. The
/// **canonical signature base** (the bytes actually signed) is built by the
/// single RFC 9421 implementation in [`crate::http_signature`] — this struct
/// is just the resulting wire envelope, re-exported by `cokret-contracts`
/// and embedded in `FederationTransactionEnvelope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignature {
    pub key_id: String,
    pub alg: String,
    pub signed_fields: Vec<String>,
    pub signature: String,
}

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
            payload_digest: payload_digest.clone(),
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

        let mut stale = context;
        stale.now = proof.created_at + Duration::minutes(10);
        assert!(matches!(
            verify_proof_with_resolver(&proof, &stale, &resolver, |_, _| Ok(true)),
            Err(Error::Protocol(_))
        ));
    }
}
