//! Agent key-pairing canonical binding helpers.

use arkret_canonical::{base64url_decode, canonical};
/// The immutable provision ceiling commitment digest is defined with the
/// agent lifecycle models and surfaced by the signature owner.
pub use arkret_models_collaboration::agent_operations::agent_requested_scope_digest;
use arkret_models_collaboration::agent_operations::{
    AgentKeyPairRequestBody, AgentPairingBootstrap, AgentRequestedScopeDisclosure,
    AgentRuntimeApprovalRequestBody, AgentRuntimeKeyAlgorithm, AgentRuntimeKeyPossessionProof,
    AgentRuntimeKeyPossessionProofKind,
    agent_runtime_key_binding_digest as model_agent_runtime_key_binding_digest,
};
use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyAuthorizePayloadRuntimeAttestation,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding;
use arkret_wire::{
    Base64UrlString, DeviceId, DidCoreId, DidFullId, DidUrl, Event, EventInitialSubmission,
    EventKind, Hash, NonEmptyString, project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// A runtime-key request body together with the private request-domain digest
/// of its generated PublicKey DTO. This digest MUST NOT be copied into the
/// controller-side authorize event, which commits the raw-key authorization
/// digest returned by [`ValidatedAgentRuntimePublicKey::authorization_digest`].
#[derive(Clone, Debug)]
pub struct RuntimeKeyRequest<T> {
    pub body: T,
    pub runtime_request_public_key_digest: Hash,
}

/// Build and sign the two runtime-key pairing request shapes from one
/// bootstrap and Ed25519 signing key.
pub struct RuntimeKeyRequestBuilder<'a> {
    signing_key: &'a SigningKey,
    bootstrap: AgentPairingBootstrap,
    verification_method: String,
    proof_created_at: DateTime<Utc>,
    proof_expires_at: DateTime<Utc>,
    runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

impl<'a> RuntimeKeyRequestBuilder<'a> {
    pub fn new(
        signing_key: &'a SigningKey,
        bootstrap: AgentPairingBootstrap,
        agent_full_id: &DidFullId,
        endpoint_device_id: DeviceId,
    ) -> Self {
        let verification_method = format!("{agent_full_id}#{endpoint_device_id}");
        let proof_created_at = Utc::now();
        let proof_expires_at = std::cmp::min(
            bootstrap.pairing_expires_at,
            proof_created_at + chrono::Duration::seconds(300),
        );
        Self {
            signing_key,
            bootstrap,
            verification_method,
            proof_created_at,
            proof_expires_at,
            runtime_attestation: None,
        }
    }

    #[must_use]
    pub fn proof_expires_at(mut self, proof_expires_at: DateTime<Utc>) -> Self {
        self.proof_expires_at = proof_expires_at;
        self
    }

    /// Override the verifier-visible proof creation time, primarily for
    /// deterministic protocol vectors.
    #[must_use]
    pub fn proof_created_at(mut self, proof_created_at: DateTime<Utc>) -> Self {
        self.proof_created_at = proof_created_at;
        self
    }

    #[must_use]
    pub fn runtime_attestation(
        mut self,
        runtime_attestation: AgentKeyAuthorizePayloadRuntimeAttestation,
    ) -> Self {
        self.runtime_attestation = Some(runtime_attestation);
        self
    }

    pub fn public_key(&self) -> Result<Value> {
        self.validate()?;
        Ok(serde_json::json!({
            "kty": "OKP",
            "kid": self.verification_method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(self.signing_key.verifying_key().to_bytes()),
        }))
    }

    pub fn runtime_request_public_key_digest(&self) -> Result<Hash> {
        agent_runtime_public_key_digest(&self.public_key()?)
    }

    pub fn build_approval_request(
        &self,
    ) -> Result<RuntimeKeyRequest<AgentRuntimeApprovalRequestBody>> {
        let (public_key, public_key_digest, proof_of_possession) = self.request_material()?;
        Ok(RuntimeKeyRequest {
            body: AgentRuntimeApprovalRequestBody {
                pairing_code: NonEmptyString::new(self.bootstrap.pairing_code.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                pairing_request_id: self.bootstrap.pairing_request_id.clone(),
                agent_id: self.bootstrap.agent_id.clone(),
                verification_method: DidUrl::new(self.verification_method.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                public_key,
                proof_of_possession,
                runtime_attestation: self.runtime_attestation.clone(),
            },
            runtime_request_public_key_digest: public_key_digest,
        })
    }

    pub fn build_key_pair_request(
        &self,
        requested_scope_disclosure: AgentRequestedScopeDisclosure,
        signing_key_binding: AgentSigningKeyBinding,
        authorize_event: EventInitialSubmission,
    ) -> Result<RuntimeKeyRequest<AgentKeyPairRequestBody>> {
        requested_scope_disclosure
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if requested_scope_disclosure.agent_id != self.bootstrap.agent_id
            || requested_scope_disclosure.verifier_service_id != self.bootstrap.service_id
        {
            return Err(Error::Protocol(
                "agent requested-scope disclosure is not bound to this pairing".to_owned(),
            ));
        }
        let request_uuid = self
            .bootstrap
            .pairing_request_id
            .strip_prefix("agent_pairing_request:")
            .ok_or_else(|| Error::Protocol("pairing request id is invalid".to_owned()))?;
        if requested_scope_disclosure.request_id.as_str() != format!("ak:request:{request_uuid}")
            || requested_scope_disclosure.challenge.as_str()
                != self.bootstrap.pairing_request_id.as_str()
        {
            return Err(Error::Protocol(
                "agent requested-scope disclosure request or challenge does not match this pairing"
                    .to_owned(),
            ));
        }
        validate_pairing_authorize_event(&authorize_event.event, &self.bootstrap.agent_id)?;
        let authorize_event_id = authorize_event.event.event_id.clone();
        if signing_key_binding.agent_key_authorize_event_id != authorize_event_id {
            return Err(Error::Protocol(
                "agent signing-key binding must reference the exact authorize Event identity"
                    .to_owned(),
            ));
        }
        let authorize_payload = AgentKeyAuthorizePayload::try_from(&authorize_event.event)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let binding_core_digest =
            crate::agent_evidence::agent_signing_key_binding_digest(&signing_key_binding)
                .map_err(|reason| Error::Protocol(reason.as_str().to_owned()))?;
        if authorize_payload.signing_key_binding_digest != binding_core_digest {
            return Err(Error::Protocol(
                "authorize Event signing_key_binding_digest must match the binding core".to_owned(),
            ));
        }
        let (public_key, public_key_digest, proof_of_possession) = self.request_material()?;
        Ok(RuntimeKeyRequest {
            body: AgentKeyPairRequestBody {
                pairing_request_id: self.bootstrap.pairing_request_id.clone(),
                agent_id: self.bootstrap.agent_id.clone(),
                verification_method: DidUrl::new(self.verification_method.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                public_key,
                proof_of_possession,
                requested_scope_disclosure,
                signing_key_binding,
                runtime_attestation: self.runtime_attestation.clone(),
                authorize_event,
            },
            runtime_request_public_key_digest: public_key_digest,
        })
    }

    fn request_material(&self) -> Result<(PublicKey, Hash, AgentRuntimeKeyPossessionProof)> {
        let public_key_value = self.public_key()?;
        let public_key: PublicKey = serde_json::from_value(public_key_value.clone())?;
        let public_key_digest = agent_runtime_public_key_digest(&public_key_value)?;
        let proof_created_at =
            DateTime::<Utc>::from_timestamp_millis(self.proof_created_at.timestamp_millis())
                .ok_or_else(|| {
                    Error::Protocol(
                        "agent key proof created_at is outside the wire timestamp range".into(),
                    )
                })?;
        let proof_expires_at =
            DateTime::<Utc>::from_timestamp_millis(self.proof_expires_at.timestamp_millis())
                .ok_or_else(|| {
                    Error::Protocol(
                        "agent key proof expires_at is outside the wire timestamp range".into(),
                    )
                })?;
        if proof_created_at >= proof_expires_at
            || proof_expires_at > proof_created_at + chrono::Duration::seconds(300)
            || proof_expires_at > self.bootstrap.pairing_expires_at
        {
            return Err(Error::Protocol(
                "agent key proof lifetime must be within the live pairing window and at most 300 seconds"
                    .to_owned(),
            ));
        }
        let verification_method = DidUrl::new(self.verification_method.clone())
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let runtime_key_binding_digest = model_agent_runtime_key_binding_digest(
            &self.bootstrap.agent_id,
            &self.bootstrap.pairing_request_id,
            &verification_method,
            &public_key,
            self.runtime_attestation.as_ref(),
        );
        let runtime_key_binding_digest =
            runtime_key_binding_digest.map_err(|error| Error::Protocol(error.to_string()))?;
        let mut proof_of_possession = AgentRuntimeKeyPossessionProof {
            kind: AgentRuntimeKeyPossessionProofKind::AgentRuntimeKeyPossession,
            verification_method,
            signature_algorithm: AgentRuntimeKeyAlgorithm::Ed25519,
            challenge: self.bootstrap.pairing_request_id.clone(),
            audience: self.bootstrap.service_id.clone(),
            expires_at: proof_expires_at,
            created_at: proof_created_at,
            runtime_key_binding_digest,
            transcript_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|reason| Error::Protocol(reason.to_string()))?,
            signature: Base64UrlString::new("AA")
                .map_err(|reason| Error::Protocol(reason.to_owned()))?,
        };
        let transcript = proof_of_possession
            .canonical_transcript_bytes(&self.bootstrap.pairing_code)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        proof_of_possession.transcript_digest = Hash::new(canonical::sha256_digest(&transcript))
            .map_err(|reason| Error::Protocol(reason.to_string()))?;
        let signature = self.signing_key.sign(&transcript);
        proof_of_possession.signature =
            Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
                .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        Ok((public_key, public_key_digest, proof_of_possession))
    }

    fn validate(&self) -> Result<()> {
        if self.bootstrap.pairing_request_id.trim().is_empty()
            || self.bootstrap.pairing_code.trim().is_empty()
        {
            return Err(Error::Protocol(
                "agent pairing bootstrap request id and code must not be empty".to_owned(),
            ));
        }
        if self.verification_method.trim().is_empty()
            || DidUrl::new(self.verification_method.clone())
                .ok()
                .and_then(|method| {
                    method
                        .as_str()
                        .split_once('#')
                        .and_then(|(controller, _)| DidFullId::new(controller).ok())
                })
                .and_then(|full_id| project_full_id_to_core_id(&full_id).ok())
                .is_none_or(|core_id| core_id != self.bootstrap.agent_id)
        {
            return Err(Error::Protocol(
                "agent runtime verification_method must belong to agent_id".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_pairing_authorize_event(authorize_event: &Event, agent_id: &DidCoreId) -> Result<()> {
    if authorize_event.kind != EventKind::AgentKeyAuthorize {
        return Err(Error::Protocol(
            "agent authorize_event.kind must be ak.agent.key.authorize".to_owned(),
        ));
    }
    if authorize_event.actor_id != *agent_id {
        return Err(Error::Protocol(
            "agent authorize_event.actor_id must match agent_id".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct AgentRuntimeKeyBinding<'a> {
    agent_id: &'a str,
    attestation_digest: &'a str,
    kind: &'static str,
    pairing_request_id: &'a str,
    public_key_digest: &'a str,
    verification_method: &'a str,
}

pub fn agent_runtime_public_key_digest(public_key: &impl Serialize) -> Result<Hash> {
    parse_agent_runtime_public_key(public_key, None)
        .map(|validated| validated.runtime_request_digest)
}

/// A closed, canonical Agent runtime signing key. Both digest domains are
/// returned together so callers cannot accidentally compare one domain with
/// the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAgentRuntimePublicKey {
    pub public_key: PublicKey,
    pub raw_public_key: [u8; 32],
    pub runtime_request_digest: Hash,
    pub authorization_digest: Hash,
}

/// Parse and validate the sole v1 Agent runtime key profile.
///
/// The request DTO is closed to `OKP` + `Ed25519`, its `kid` must equal the
/// request verification method, and the key must use the canonical unpadded
/// base64url encoding of exactly 32 bytes.
pub fn validate_agent_runtime_public_key(
    public_key: &impl Serialize,
    expected_verification_method: &DidUrl,
) -> Result<ValidatedAgentRuntimePublicKey> {
    parse_agent_runtime_public_key(public_key, Some(expected_verification_method))
}

fn parse_agent_runtime_public_key(
    public_key: &impl Serialize,
    expected_verification_method: Option<&DidUrl>,
) -> Result<ValidatedAgentRuntimePublicKey> {
    let public_key = serde_json::to_value(public_key).map_err(|error| {
        Error::Protocol(format!(
            "agent runtime public_key must serialize to JSON: {error}"
        ))
    })?;
    let key: PublicKey = serde_json::from_value(public_key.clone()).map_err(|error| {
        Error::Protocol(format!(
            "agent runtime public_key must match public_key schema: {error}"
        ))
    })?;
    if key.kty.as_str() != "OKP" {
        return Err(Error::Protocol(
            "agent runtime public_key.kty must be OKP".to_owned(),
        ));
    }
    if key.algorithm.as_str() != "Ed25519" {
        return Err(Error::Protocol(
            "agent runtime public_key.algorithm must be Ed25519".to_owned(),
        ));
    }
    if key.key_digest.is_some() {
        return Err(Error::Protocol(
            "agent runtime public_key must not contain key_digest".to_owned(),
        ));
    }
    if expected_verification_method.is_some_and(|expected| key.kid.as_str() != expected.as_str()) {
        return Err(Error::Protocol(
            "agent runtime public_key.kid must match verification_method".to_owned(),
        ));
    }
    let raw_public_key = base64url_decode(key.key.as_bytes())?;
    let raw_public_key: [u8; 32] = raw_public_key.try_into().map_err(|_| {
        Error::Protocol("agent runtime public_key.key must be a 32-byte Ed25519 key".to_owned())
    })?;
    if arkret_canonical::base64url_encode(raw_public_key) != key.key.as_str() {
        return Err(Error::Protocol(
            "agent runtime public_key.key must use canonical unpadded base64url".to_owned(),
        ));
    }
    let runtime_request_digest =
        Hash::new(canonical::canonical_sha256(&public_key)?).map_err(Error::from)?;
    let authorization_digest =
        Hash::new(canonical::sha256_digest(raw_public_key)).map_err(Error::from)?;
    Ok(ValidatedAgentRuntimePublicKey {
        public_key: key,
        raw_public_key,
        runtime_request_digest,
        authorization_digest,
    })
}

/// Digest the runtime attestation value used by the stable approval binding.
/// An absent attestation is represented by canonical JSON `null`.
pub fn agent_runtime_attestation_digest(runtime_attestation: Option<&Value>) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        runtime_attestation.unwrap_or(&Value::Null),
    )?)
    .map_err(Error::from)
}

/// Compute the stable runtime-key approval binding from source key material.
pub fn agent_runtime_key_binding_digest(
    agent_id: &DidCoreId,
    pairing_request_id: &str,
    verification_method: &str,
    public_key: &impl Serialize,
    runtime_attestation: Option<&Value>,
) -> Result<Hash> {
    let public_key_digest = agent_runtime_public_key_digest(public_key)?;
    let attestation_digest = agent_runtime_attestation_digest(runtime_attestation)?;
    agent_runtime_key_binding_digest_from_digests(
        agent_id,
        pairing_request_id,
        verification_method,
        &public_key_digest,
        &attestation_digest,
    )
}

/// Compute the stable runtime-key approval binding from persisted digests.
pub fn agent_runtime_key_binding_digest_from_digests(
    agent_id: &DidCoreId,
    pairing_request_id: &str,
    verification_method: &str,
    public_key_digest: &Hash,
    attestation_digest: &Hash,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(&AgentRuntimeKeyBinding {
        agent_id: agent_id.as_str(),
        attestation_digest: attestation_digest.as_str(),
        kind: "ak.agent.runtime_key_binding.v1",
        pairing_request_id,
        public_key_digest: public_key_digest.as_str(),
        verification_method,
    })?)
    .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyScope,
    };
    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, DeviceId, DidCoreId,
        DidFullId, EventId, Hlc, LeaseBasisRef, ProducerEventProof, RealmId, RequestId, RiskTier,
        SchemaId, SealId,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn initial_submission(event: Event, actor_full_id: DidFullId) -> EventInitialSubmission {
        let policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: event.scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: event.event_id.as_str().to_owned(),
                source_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec!["ak.agent.key.authorize".to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(format!("{actor_full_id}#controller"))
                        .unwrap(),
                }],
                threshold: 1,
            }],
        };
        EventInitialSubmission {
            authorization_lease: Some(AuthorizationLease {
                authorization_lease_id: AuthorizationLeaseId::new(
                    "ak:authorization_lease:01904100-0000-7000-8000-0000000000f1",
                )
                .unwrap(),
                basis_ref: LeaseBasisRef::Seal(
                    SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap(),
                ),
                actor_id: event.actor_id.clone(),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                scope_ref: event.scope_ref.clone(),
                action: "ak.agent.key.authorize".to_owned(),
                authorization_rule_id: "realm_admission".to_owned(),
                risk_tier: RiskTier::High,
                issued_at: event.created_at,
                expires_at: event.created_at + chrono::Duration::minutes(5),
                authority_set_ref: AuthoritySetRef {
                    authority_set_id: policy.authority_set_id.clone(),
                    authority_set_digest: policy.digest().unwrap(),
                },
                authority_set_policy: policy,
                proofs: Vec::new(),
            }),
            event,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    #[test]
    fn runtime_key_binding_matches_normative_vector() {
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkagent").unwrap();
        let public_key = json!({
            "algorithm": "Ed25519",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "did:webvh:z6mkagent:agent.example#runtime-1",
            "kty": "OKP"
        });

        let public_key_digest = agent_runtime_public_key_digest(&public_key).unwrap();
        let attestation_digest = agent_runtime_attestation_digest(None).unwrap();
        let binding_digest = agent_runtime_key_binding_digest(
            &agent_id,
            "pairing_request:01964137-0000-7000-8000-000000000000",
            "did:webvh:z6mkagent:agent.example#runtime-1",
            &public_key,
            None,
        )
        .unwrap();

        // The three expected values are copied verbatim from
        // `spec/v1/artifacts/fixtures/agent-vectors-fixture.json`, vector
        // `ak.vector.agent.runtime_key_binding.v1`. The fixture is the truth;
        // this test exists so the SDK cannot drift from it silently.
        assert_eq!(
            public_key_digest.as_str(),
            "sha256:30bde072332c796c2bfa2cca05564e592d49a6dd11719cfdb8a918c0897486a4"
        );
        assert_eq!(
            attestation_digest.as_str(),
            "sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
        );
        assert_eq!(
            binding_digest.as_str(),
            "sha256:d9bfa43d517f962dd5fa8e1a8873dce0de410bffec06b553ea03dd01e330460f"
        );
    }

    #[test]
    fn runtime_key_binding_changes_when_key_material_changes() {
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkagent").unwrap();
        let first = json!({
            "algorithm": "Ed25519",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "did:webvh:z6mkagent:agent.example#runtime-1",
            "kty": "OKP"
        });
        let second = json!({
            "algorithm": "Ed25519",
            "key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "did:webvh:z6mkagent:agent.example#runtime-1",
            "kty": "OKP"
        });
        let digest = |public_key: &Value| {
            agent_runtime_key_binding_digest(
                &agent_id,
                "pairing_request:01964137-0000-7000-8000-000000000000",
                "did:webvh:z6mkagent:agent.example#runtime-1",
                public_key,
                None,
            )
            .unwrap()
        };
        assert_ne!(digest(&first), digest(&second));
    }

    #[test]
    fn runtime_key_request_builder_signs_the_wire_timestamp_precision() {
        use ed25519_dalek::Verifier as _;

        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_full_id =
            DidFullId::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            agent_id,
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at: "2026-07-14T14:43:48.784473Z"
                .parse::<DateTime<Utc>>()
                .unwrap(),
        };
        let proof_created_at = "2026-07-14T14:40:00.123456Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let request = RuntimeKeyRequestBuilder::new(
            &signing_key,
            bootstrap,
            &agent_full_id,
            DeviceId::new("ak:device:01970000-0000-7000-8000-000000000022").unwrap(),
        )
        .proof_created_at(proof_created_at)
        .build_approval_request()
        .unwrap();
        let proof = &request.body.proof_of_possession;
        let transcript = proof.canonical_transcript_bytes("12345678").unwrap();
        let signature = base64url_decode(proof.signature.as_str()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();

        assert_eq!(
            arkret_canonical::format_timestamp_canonical(proof.expires_at),
            "2026-07-14T14:43:48.784Z"
        );
        assert_eq!(
            arkret_canonical::format_timestamp_canonical(proof.created_at),
            "2026-07-14T14:40:00.123Z"
        );
        signing_key
            .verifying_key()
            .verify(&transcript, &signature)
            .expect("signature must bind the timestamp sent on the wire");
    }

    #[test]
    fn runtime_key_request_builder_caps_default_proof_lifetime() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_full_id =
            DidFullId::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let pairing_expires_at = Utc::now() + chrono::Duration::minutes(10);
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            agent_id,
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at,
        };

        let request = RuntimeKeyRequestBuilder::new(
            &signing_key,
            bootstrap,
            &agent_full_id,
            DeviceId::new("ak:device:01970000-0000-7000-8000-000000000022").unwrap(),
        )
        .build_approval_request()
        .unwrap();
        let proof = request.body.proof_of_possession;

        assert_eq!(
            proof.expires_at,
            proof.created_at + chrono::Duration::seconds(300)
        );
        assert!(proof.expires_at <= pairing_expires_at);
    }

    #[test]
    fn runtime_key_request_builder_assembles_both_pairing_shapes() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_full_id =
            DidFullId::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_actor_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let controller_full_id =
            DidFullId::new("did:webvh:z6mkfixture:controller.example").unwrap();
        let controller_actor_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let controller_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let service_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let pairing_request_id = "agent_pairing_request:01970000-0000-7000-8000-000000000021";
        let issued_at = Utc.with_ymd_and_hms(2026, 7, 17, 0, 0, 0).unwrap();
        let requested_scope = AgentKeyScope {
            actions: vec!["ak.message.create".to_owned()],
            resources: vec![],
            constraints: vec![],
        };
        let mut disclosure = AgentRequestedScopeDisclosure {
            schema: SchemaId::AgentRequestedScopeDisclosureV1,
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000021").unwrap(),
            agent_id: agent_actor_id.clone(),
            controller_id: controller_id.clone(),
            requested_scope_digest: agent_requested_scope_digest(
                &agent_actor_id,
                &controller_id,
                &requested_scope,
            )
            .unwrap(),
            requested_scope: requested_scope.clone(),
            verifier_service_id: service_id.clone(),
            audience: NonEmptyString::new(
                arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            )
            .unwrap(),
            challenge: NonEmptyString::new(pairing_request_id).unwrap(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
            proofs: vec![ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(format!("{controller_full_id}#key-1")).unwrap(),
                event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
            }],
        };
        disclosure.proofs[0].event_digest = disclosure.payload_digest().unwrap();
        let mut tampered_disclosure = disclosure.clone();
        tampered_disclosure.requested_scope.actions.clear();
        assert!(tampered_disclosure.validate().is_err());
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id,
            agent_id: agent_actor_id.clone(),
            pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id).unwrap(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at: issued_at + chrono::Duration::minutes(5),
        };
        let endpoint_device_id =
            DeviceId::new("ak:device:01970000-0000-7000-8000-000000000023").unwrap();
        let verification_method =
            DidUrl::new(format!("{agent_full_id}#{endpoint_device_id}")).unwrap();
        let builder = RuntimeKeyRequestBuilder::new(
            &signing_key,
            bootstrap,
            &agent_full_id,
            endpoint_device_id,
        )
        .proof_created_at(issued_at)
        .proof_expires_at(issued_at + chrono::Duration::minutes(5));
        let runtime_public_key: PublicKey =
            serde_json::from_value(builder.public_key().unwrap()).unwrap();
        let agent_key_id = NonEmptyString::new(verification_method.to_string()).unwrap();
        let binding_core = super::super::agent_evidence::prepare_agent_signing_key_binding_core(
            agent_actor_id.clone(),
            agent_key_id.clone(),
            verification_method.clone(),
            &runtime_public_key,
            issued_at,
            None,
            controller_actor_id.clone(),
        )
        .unwrap();
        let binding_core_digest =
            super::super::agent_evidence::agent_signing_key_binding_core_digest(&binding_core)
                .unwrap();
        let authorize_payload = AgentKeyAuthorizePayload {
            agent_id: agent_actor_id.clone(),
            key_id: agent_key_id.clone(),
            verification_method: verification_method.clone(),
            public_key_digest: binding_core.public_key_digest,
            signing_key_binding_digest: binding_core_digest,
            accountable_principal_id: controller_id,
            agent_key_scope: requested_scope,
            audience: vec!["https://arkret.example".to_owned()],
            issued_at,
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: None,
                pairing_request_id: Some(
                    arkret_wire::OpaqueLocalId::new(pairing_request_id).unwrap(),
                ),
                approved_by: Some(controller_actor_id.clone()),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let authorize_event = arkret_wire::test_support::raw_event(
            EventKind::AgentKeyAuthorize.to_string(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x41; 32],
                )),
            },
            agent_actor_id.clone(),
            agent_actor_id.clone(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            serde_json::to_value(authorize_payload).unwrap(),
        )
        .unwrap();
        let authorize_event_id = authorize_event.event_id.clone();

        let approval = builder.build_approval_request().unwrap();
        let pairing = builder
            .build_key_pair_request(
                disclosure,
                super::super::agent_evidence::build_agent_signing_key_binding(
                    agent_actor_id.clone(),
                    agent_key_id,
                    verification_method.clone(),
                    signing_key.verifying_key().to_bytes(),
                    authorize_event_id,
                    issued_at,
                    None,
                    controller_actor_id,
                    DidUrl::new(format!("{controller_full_id}#key-1")).unwrap(),
                    &SigningKey::from_bytes(&[3_u8; 32]),
                )
                .unwrap(),
                initial_submission(authorize_event, agent_full_id.clone()),
            )
            .unwrap();

        assert_eq!(
            approval.runtime_request_public_key_digest,
            pairing.runtime_request_public_key_digest
        );
        assert_eq!(
            serde_json::to_value(approval.body.public_key).unwrap(),
            serde_json::to_value(pairing.body.public_key).unwrap()
        );
        assert_eq!(pairing.body.agent_id, agent_actor_id);
        assert_eq!(approval.body.verification_method, verification_method);
        assert_eq!(pairing.body.verification_method, verification_method);
    }
}
