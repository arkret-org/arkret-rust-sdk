//! Canonical signatures, proof binding and HTTP message signature helpers.

#[cfg(any(feature = "signer", test))]
#[path = "signer.rs"]
pub mod signer;

#[cfg(any(feature = "signer", test))]
pub use signer::Ed25519PayloadSigner;

// Unified Event Envelope proof builder/verifier pipeline. Available without
// the `signer` feature (canonical bytes + traits + dev-proof gating); the
// `signer` feature also exposes the Ed25519 detached-JWS backend.
#[path = "proof.rs"]
pub mod proof;

// S-1 (savfox SDK gap): one-shot `sign_event` helper that owns the
// canonical-JSON + detached-JWS pipeline external Applets used to roll
// themselves.
#[path = "event_signer.rs"]
pub mod event_signer;
pub use event_signer::{SignEventOptions, sign_event};

#[path = "dpop.rs"]
pub mod dpop;
pub use dpop::{
    DPOP_PROOF_ALG, DPOP_PROOF_TYP, DpopProof, DpopProofRequest, build_dpop_proof,
    dpop_access_token_hash, dpop_jwk_thumbprint,
};

#[path = "jwt.rs"]
pub mod jwt;

#[path = "jwk.rs"]
pub mod jwk;

// Shared `did:webvh` inception builder. Pure build + cryptography (keygen, SCID
// derivation, eddsa-jcs-2022 proof) so clients and servers mint identical
// inception entries. HTTP submission lives in the caller.
//
// The module itself is unconditional because its `skeleton` half (the `{SCID}`
// placeholder contract, SCID derivation and the entry-hash pre-image) carries
// no model dependency and is consumed by components that do not enable
// `webvh`; only the `inception` half, which builds typed operation bodies, is
// feature gated.
#[path = "webvh/mod.rs"]
pub mod webvh;

#[cfg(feature = "service-identity")]
#[path = "service_identity.rs"]
pub mod service_identity;

// Organization-side statement signing (A3). Byte-symmetric counterpart to
// soland's `verify_realm_organization_proof_signature`.
#[cfg(feature = "collaboration")]
#[path = "realm_organization.rs"]
pub mod realm_organization;

// RFC 7515 detached Ed25519 JWS signer (resolver-free sign half). The verify /
// DID-resolve / replay-window half lives in `arkret-identity`.
#[path = "jws.rs"]
pub mod jws;

// `challenge_dpop_session_v1` for the WebSocket binding extension. Kept next to
// (never merged into) the HTTP DPoP module: the two validator contexts must
// stay separate, see `websocket_auth`'s module documentation.
#[path = "websocket_auth.rs"]
pub mod websocket_auth;
pub use websocket_auth::{
    VerifiedWebSocketAuth, WebSocketAuthError, WebSocketAuthProof, WebSocketAuthProofRequest,
    WebSocketAuthVerificationRequest, build_websocket_auth_proof, verify_websocket_auth_proof,
    websocket_holder_thumbprint, websocket_session_grant_hash,
};

#[path = "error.rs"]
pub mod error;

/// Production-grade proof algorithms this SDK can actually produce and verify.
///
/// Re-export of the single source of truth in `arkret-wire`
/// ([`arkret_wire::PRODUCTION_ALGORITHMS`]) so the structural gate
/// (`ProducerEventProof::validate_production`) and this crate's verifiers can never
/// diverge again. The v1 set is exactly `["Ed25519"]` — see the wire constant's
/// documentation for why the other registry-active rows are excluded.
pub use arkret_wire::PRODUCTION_ALGORITHMS;
use arkret_wire::{
    ActorId, Audience, Did, DidCoreId, DidUrl, Hash, ProducerEventProof, ProofBindingRequirements,
    SignatureBindingPayload,
};
use chrono::{DateTime, Duration, Utc};
pub use error::{Error, Result};
pub use jwk::{JsonWebKey, JsonWebKeyOperation, JsonWebKeySet, JsonWebKeyUse};
pub use jwt::{
    JsonWebTokenClaims, JsonWebTokenHeader, JwtAlgorithm, JwtAudience, JwtType,
    JwtVerificationError, JwtVerificationPolicy, VerifiedJwt, verify_ed25519_jwt_with_jwks,
};
// `proof` is an unconditional module, so gating its re-export on
// `collaboration` only made the crate root disagree with itself: a dependent
// that did not happen to have that feature unified on saw the items vanish even
// though they were compiled. arkret-identity depends on this crate with
// `["webvh"]` alone and uses four of these, so it built only by accident of
// feature unification.
pub use proof::{
    Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventProofBuilder, EventSigner,
    EventVerifier, PublicKeyMaterial, SignedPayload, SignerError, VerifierError,
    build_proof_envelope, detached_jws_kind, sign_ed25519_detached_jws,
    verify_detached_ed25519_signature, verify_ed25519_detached_jws_payload_proof,
    verify_ed25519_detached_jws_proof, verify_ed25519_detached_jws_proof_with_digest_suite,
    verify_ed25519_signal_proof,
};
#[cfg(feature = "collaboration")]
pub use realm_organization::realm_organization_statement_sign;
use serde::{Deserialize, Serialize};

#[cfg(feature = "collaboration")]
pub use crate::device_authorization::verify_device_authorize_possession;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethodDocument {
    pub did: Did,
    pub verification_method: DidUrl,
    pub public_key_multibase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Did>,
}

pub trait DidVerificationMethodResolver {
    fn resolve_verification_method(
        &self,
        verification_method: &DidUrl,
    ) -> Result<VerificationMethodDocument>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofVerificationContext {
    pub actor_id: ActorId,
    pub expected_payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub now: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    pub replay_window: Duration,
    #[serde(default)]
    pub binding_requirements: ProofBindingRequirements,
}

impl ProofVerificationContext {
    pub fn new(actor_id: ActorId, expected_payload_digest: Hash) -> Self {
        Self {
            actor_id,
            expected_payload_digest,
            now: Utc::now(),
            domain: None,
            audience: None,
            service_id: None,
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
    proof: &ProducerEventProof,
    context: &ProofVerificationContext,
    resolver: &R,
    verify_jws: F,
) -> Result<SignatureVerification>
where
    R: DidVerificationMethodResolver + ?Sized,
    F: Fn(&VerificationMethodDocument, &ProducerEventProof) -> Result<bool>,
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
    if let Some(service_id) = &context.service_id
        && !audience_contains_service(proof.audience.as_ref(), service_id)
    {
        return Err(Error::Protocol(
            "proof audience does not bind service DID".to_owned(),
        ));
    }

    let method = resolver.resolve_verification_method(&proof.verification_method)?;
    let controller = method.controller.as_ref().unwrap_or(&method.did);
    if arkret_wire::project_did_to_core_id(controller)? != *context.actor_id.signing_principal_id()
    {
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

fn audience_contains_service(audience: Option<&Audience>, service_id: &DidCoreId) -> bool {
    match audience {
        Some(Audience::Single(value)) => value == service_id.as_str(),
        Some(Audience::Multiple(values)) => values.iter().any(|value| value == service_id.as_str()),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;

    use super::*;

    #[derive(Default)]
    struct StaticDidVerificationMethodResolver {
        methods: BTreeMap<String, VerificationMethodDocument>,
    }

    impl StaticDidVerificationMethodResolver {
        fn insert(&mut self, document: VerificationMethodDocument) {
            self.methods
                .insert(document.verification_method.as_str().to_owned(), document);
        }
    }

    impl DidVerificationMethodResolver for StaticDidVerificationMethodResolver {
        fn resolve_verification_method(
            &self,
            verification_method: &DidUrl,
        ) -> Result<VerificationMethodDocument> {
            self.methods
                .get(verification_method.as_str())
                .cloned()
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "unknown verification method '{verification_method}'"
                    ))
                })
        }
    }

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture{name}:{name}.example")).unwrap()
    }

    fn actor(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{name}")).unwrap()
    }

    /// SDK-SOTA-01 / SDK-CRY-02: `ES256` and `ML-DSA-65` are wire-reserved
    /// (registered active rows, no client impl) and MUST NOT be advertised as
    /// usable production algorithms while the Ed25519 verifier is the only
    /// signer/verifier shipped.
    #[test]
    fn production_algorithms_exclude_unimplemented_registry_rows() {
        assert!(!PRODUCTION_ALGORITHMS.contains(&"ES256"));
        assert!(!PRODUCTION_ALGORITHMS.contains(&"ML-DSA-65"));
        // The production set is exactly the algorithms with a real
        // signer/verifier: Ed25519 only.
        assert_eq!(PRODUCTION_ALGORITHMS, &["Ed25519"]);
    }

    #[test]
    fn proof_verifier_resolves_method_binds_service_and_replay_window() {
        let actor_did = did("alice");
        let payload_digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let mut resolver = StaticDidVerificationMethodResolver::default();
        resolver.insert(VerificationMethodDocument {
            did: actor_did,
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            public_key_multibase: "zKey".to_owned(),
            controller: None,
        });
        let proof = ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: payload_digest.clone(),
            signer_resolution_evidence_ref: None,
            created_at: Utc::now(),
            domain: Some("api.example".to_owned()),
            audience: Some(Audience::Single(actor("service").to_string())),
            proof_purpose: None,
            jws: arkret_wire::test_support::DETACHED_JWS_FIXTURE.to_owned(),
        };
        let mut context =
            ProofVerificationContext::new(ActorId::service(actor("alice")), payload_digest);
        context.domain = proof.domain.clone();
        context.audience = proof.audience.clone();
        context.service_id = Some(DidCoreId::new("ak:did_core:webvh:z6mkfixtureservice").unwrap());

        let verified = verify_proof_with_resolver(&proof, &context, &resolver, |method, proof| {
            Ok(method.public_key_multibase == "zKey"
                && proof.jws == arkret_wire::test_support::DETACHED_JWS_FIXTURE)
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
        let actor_did = did("alice");
        let payload_digest =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let mut resolver = StaticDidVerificationMethodResolver::default();
        resolver.insert(VerificationMethodDocument {
            did: actor_did,
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            public_key_multibase: "zKey".to_owned(),
            controller: None,
        });
        let mut proof = ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: payload_digest.clone(),
            signer_resolution_evidence_ref: None,
            created_at: Utc::now(),
            domain: None,
            audience: Some(Audience::Single(
                "did:webvh:z6mkfixture:service.example".to_owned(),
            )),
            proof_purpose: None,
            jws: arkret_wire::test_support::DETACHED_JWS_FIXTURE.to_owned(),
        };
        let context =
            ProofVerificationContext::new(ActorId::service(actor("alice")), payload_digest)
                .cross_domain(
                    "ak:trust_domain:example.net",
                    Audience::Single("did:webvh:z6mkfixture:service.example".to_owned()),
                );

        let error =
            verify_proof_with_resolver(&proof, &context, &resolver, |_, _| Ok(true)).unwrap_err();
        assert!(
            error.to_string().contains("proof_binding_missing"),
            "{error}"
        );

        proof.domain = Some("ak:trust_domain:example.net".to_owned());
        assert!(
            verify_proof_with_resolver(&proof, &context, &resolver, |_, _| Ok(true))
                .unwrap()
                .valid
        );
    }
}
