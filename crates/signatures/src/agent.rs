//! Agent key-pairing canonical binding helpers.

use arkret_canonical::{base64url_decode, canonical};
use arkret_models_collaboration::agent_operations::AgentPairingBootstrap;
/// The immutable provision ceiling commitment digest is defined with the
/// agent lifecycle models and surfaced by the signature owner.
pub use arkret_models_collaboration::agent_scope::agent_requested_scope_digest;
use arkret_models_collaboration::agent_scope::{
    AgentKeyPairRequestBody, AgentRequestedScopeDisclosure, AgentRuntimeApprovalRequestBody,
    AgentRuntimeKeyAlgorithm, AgentRuntimeKeyPossessionProof, AgentRuntimeKeyPossessionProofKind,
    agent_runtime_key_binding_digest as model_agent_runtime_key_binding_digest,
};
use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyAuthorizePayloadRuntimeAttestation,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_wire::{
    ActorId, Base64UrlString, DeviceId, Did, DidCoreId, DidUrl, Event, EventKind, Hash,
    NonEmptyString, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// A runtime-key request body together with the digest of the runtime key it
/// carries. v1 has one Agent runtime key digest domain, the SHA-256 of the
/// decoded 32-byte Ed25519 key, so this is the same value the controller-side
/// authorize event commits.
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

/// Verify that an exact Agent signing method belongs to the stable Agent id.
///
/// This is a projection check, not string prefix comparison: the DID URL
/// carries a resolvable complete DID while `agent_id` remains the stable
/// [`DidCoreId`] used by pairing, sessions, actors, and indexes.
pub fn validate_agent_verification_method(
    agent_id: &DidCoreId,
    verification_method: &DidUrl,
) -> Result<()> {
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .expect("DidUrl always contains a fragment");
    let controller =
        Did::new(controller.to_owned()).map_err(|reason| Error::Protocol(reason.to_string()))?;
    let projected = project_did_to_core_id(&controller)
        .map_err(|reason| Error::Protocol(reason.to_string()))?;
    if &projected != agent_id {
        return Err(Error::Protocol(
            "agent runtime verification_method must belong to agent_id".to_owned(),
        ));
    }
    Ok(())
}

impl<'a> RuntimeKeyRequestBuilder<'a> {
    /// Build a runtime-key request for an already selected Agent verification
    /// method.
    ///
    /// Agent identity references use the stable [`DidCoreId`] carried by the
    /// bootstrap, while the authorized signing key is named by this complete
    /// DID URL. Validation projects the method controller back to the stable
    /// id; callers must not manufacture a DID by treating the core id as one.
    pub fn new_with_verification_method(
        signing_key: &'a SigningKey,
        bootstrap: AgentPairingBootstrap,
        verification_method: &DidUrl,
    ) -> Self {
        let proof_created_at = Utc::now();
        let proof_expires_at = std::cmp::min(
            bootstrap.pairing_expires_at,
            proof_created_at + chrono::Duration::seconds(300),
        );
        Self {
            signing_key,
            bootstrap,
            verification_method: verification_method.to_string(),
            proof_created_at,
            proof_expires_at,
            runtime_attestation: None,
        }
    }

    /// Convenience constructor for device-shaped method fragments.
    ///
    /// Agent runtimes whose accepted key uses another fragment shape should
    /// call [`Self::new_with_verification_method`] with the exact method.
    pub fn new(
        signing_key: &'a SigningKey,
        bootstrap: AgentPairingBootstrap,
        agent_did: &Did,
        endpoint_device_id: DeviceId,
    ) -> Self {
        let verification_method = DidUrl::new(format!("{agent_did}#{endpoint_device_id}"))
            .expect("validated DID and DeviceId form a valid verification method");
        Self::new_with_verification_method(signing_key, bootstrap, &verification_method)
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
        approval_request_id: arkret_wire::OpaqueLocalId,
        requested_scope_disclosure: AgentRequestedScopeDisclosure,
        authorize_event: Event,
    ) -> Result<RuntimeKeyRequest<AgentKeyPairRequestBody>> {
        requested_scope_disclosure
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if requested_scope_disclosure.agent_id != self.bootstrap.agent_id
            || requested_scope_disclosure.verifier_id != self.bootstrap.service_id
        {
            return Err(Error::Protocol(
                "scope disclosure is not bound to this pairing".to_owned(),
            ));
        }
        validate_pairing_authorize_event(
            &authorize_event,
            &self.bootstrap.agent_id,
            &self.bootstrap.service_id,
        )?;
        let payload = AgentKeyAuthorizePayload::try_from(&authorize_event)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let own = self.public_key()?;
        if serde_json::to_value(&payload.public_key)? != own {
            return Err(Error::Protocol(
                "authorize Event does not carry this runtime key".to_owned(),
            ));
        }
        Ok(RuntimeKeyRequest {
            runtime_request_public_key_digest: agent_runtime_public_key_digest(&own)?,
            body: AgentKeyPairRequestBody {
                pairing_request_id: self.bootstrap.pairing_request_id.clone(),
                approval_request_id,
                requested_scope_disclosure,
                authorize_event: arkret_wire::EventAdmissionSubmission::new(authorize_event),
            },
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
            audience_id: self.bootstrap.service_id.clone(),
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
        let verification_method = DidUrl::new(self.verification_method.clone())
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        validate_agent_verification_method(&self.bootstrap.agent_id, &verification_method)
    }
}

fn validate_pairing_authorize_event(
    authorize_event: &Event,
    agent_id: &DidCoreId,
    station_id: &DidCoreId,
) -> Result<()> {
    if authorize_event.kind != EventKind::AgentKeyAuthorize {
        return Err(Error::Protocol(
            "agent authorize_event.kind must be ak.agent.key.authorize".to_owned(),
        ));
    }
    if authorize_event.actor_id
        != ActorId::account(arkret_wire::AccountId::new(
            agent_id.clone(),
            station_id.clone(),
        ))
    {
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
    parse_agent_runtime_public_key(public_key, None).map(|validated| validated.public_key_digest)
}

/// A closed canonical Agent runtime key.
///
/// `identity/key-management.md` §7.9 fixes one digest domain for this key: the
/// SHA-256 of the decoded 32-byte Ed25519 bytes, with no second DTO digest
/// retained. The pairing request and the authorization therefore name the same
/// value through this one field; two same-valued fields only invited
/// cross-domain comparisons that could never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAgentRuntimePublicKey {
    pub public_key: PublicKey,
    pub raw_public_key: [u8; 32],
    pub public_key_digest: Hash,
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
    let key: PublicKey = serde_json::from_value(public_key).map_err(|error| {
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
    ed25519_dalek::VerifyingKey::from_bytes(&raw_public_key).map_err(|_| {
        Error::Protocol("agent runtime public_key.key must be an Ed25519 curve point".to_owned())
    })?;
    let public_key_digest =
        Hash::new(canonical::sha256_digest(raw_public_key)).map_err(Error::from)?;
    Ok(ValidatedAgentRuntimePublicKey {
        public_key: key,
        raw_public_key,
        public_key_digest,
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
        DeviceId, Did, DidCoreId, EventId, PayloadProof, RealmId, RequestId, SchemaId,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn runtime_key_binding_vector() -> Value {
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/agent-vectors-fixture.json")
                .unwrap();
        fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["vector_id"] == "ak.vector.agent.runtime_key_binding.v1")
            .cloned()
            .unwrap()
    }

    /// `spec/v1/artifacts/fixtures/agent-vectors-fixture.json`, vector
    /// `ak.vector.agent.runtime_key_binding.v1`. The fixture is the truth; this
    /// test reads it so the SDK cannot drift from it silently.
    #[test]
    fn runtime_key_binding_matches_normative_vector() {
        let vector = runtime_key_binding_vector();
        let input = &vector["pairing_request_binding_input"];
        let agent_id = DidCoreId::new(input["agent_id"].as_str().unwrap()).unwrap();
        let public_key = vector["source_public_key"].clone();
        assert!(vector["source_runtime_attestation"].is_null());

        let public_key_digest = agent_runtime_public_key_digest(&public_key).unwrap();
        let attestation_digest = agent_runtime_attestation_digest(None).unwrap();
        let binding_digest = agent_runtime_key_binding_digest(
            &agent_id,
            input["pairing_request_id"].as_str().unwrap(),
            input["verification_method"].as_str().unwrap(),
            &public_key,
            None,
        )
        .unwrap();

        assert_eq!(
            public_key_digest.as_str(),
            vector["expected_public_key_digest"].as_str().unwrap()
        );
        assert_eq!(
            attestation_digest.as_str(),
            vector["expected_attestation_digest"].as_str().unwrap()
        );
        assert_eq!(
            binding_digest.as_str(),
            vector["expected_binding_digest"].as_str().unwrap()
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
        let agent_did = Did::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let bootstrap = AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            agent_id,
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "01234567".to_owned(),
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
            &agent_did,
            DeviceId::new("ak:device:01970000-0000-7000-8000-000000000022").unwrap(),
        )
        .proof_created_at(proof_created_at)
        .build_approval_request()
        .unwrap();
        let proof = &request.body.proof_of_possession;
        // The transcript binds the pairing code, so it has to be the one the builder used.
        let transcript = proof.canonical_transcript_bytes("01234567").unwrap();
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
        let agent_did = Did::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let pairing_expires_at = Utc::now() + chrono::Duration::minutes(10);
        let bootstrap = AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            agent_id,
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at,
        };

        let request = RuntimeKeyRequestBuilder::new(
            &signing_key,
            bootstrap,
            &agent_did,
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
    fn runtime_key_request_builder_preserves_exact_agent_verification_method() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_id = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let bootstrap = AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:web:arkret.example").unwrap(),
            agent_id,
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        let verification_method = DidUrl::new("did:web:agent.example#runtime-1").unwrap();

        let request = RuntimeKeyRequestBuilder::new_with_verification_method(
            &signing_key,
            bootstrap,
            &verification_method,
        )
        .build_approval_request()
        .unwrap();

        assert_eq!(request.body.verification_method, verification_method);
        assert_eq!(
            request.body.public_key.kid.as_str(),
            verification_method.as_str()
        );
        assert_eq!(
            request.body.proof_of_possession.verification_method,
            verification_method
        );
    }

    #[test]
    fn runtime_key_request_builder_rejects_method_for_another_agent() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let bootstrap = AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: DidCoreId::new("ak:did_core:web:arkret.example").unwrap(),
            agent_id: DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            pairing_request_id: arkret_wire::OpaqueLocalId::new(
                "01970000-0000-7000-8000-000000000022",
            )
            .unwrap(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        let wrong_method = DidUrl::new("did:web:other.example#runtime-1").unwrap();

        let error = RuntimeKeyRequestBuilder::new_with_verification_method(
            &signing_key,
            bootstrap,
            &wrong_method,
        )
        .build_approval_request()
        .unwrap_err();

        assert!(error.to_string().contains("must belong to agent_id"));
    }

    #[test]
    fn runtime_key_request_builder_assembles_both_pairing_shapes() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_did = Did::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let agent_actor_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let controller_did = Did::new("did:webvh:z6mkfixture:controller.example").unwrap();
        let controller_actor_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let controller_principal_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
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
            controller_principal_id: controller_principal_id.clone(),
            requested_scope: requested_scope.clone(),
            verifier_id: service_id.clone(),
            audience: NonEmptyString::new(
                arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            )
            .unwrap(),
            challenge: NonEmptyString::new(pairing_request_id).unwrap(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(format!("{controller_did}#key-1")).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
            }],
        };
        disclosure.proofs[0].payload_digest = disclosure.payload_digest().unwrap();
        let mut tampered_disclosure = disclosure.clone();
        tampered_disclosure.requested_scope.actions.clear();
        assert!(tampered_disclosure.validate().is_err());
        let bootstrap = AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: service_id.clone(),
            agent_id: agent_actor_id.clone(),
            pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id).unwrap(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at: issued_at + chrono::Duration::minutes(5),
        };
        let endpoint_device_id =
            DeviceId::new("ak:device:01970000-0000-7000-8000-000000000023").unwrap();
        let verification_method = DidUrl::new(format!("{agent_did}#{endpoint_device_id}")).unwrap();
        let builder =
            RuntimeKeyRequestBuilder::new(&signing_key, bootstrap, &agent_did, endpoint_device_id)
                .proof_created_at(issued_at)
                .proof_expires_at(issued_at + chrono::Duration::minutes(5));
        let runtime_public_key: PublicKey =
            serde_json::from_value(builder.public_key().unwrap()).unwrap();
        let agent_key_id = NonEmptyString::new(verification_method.to_string()).unwrap();
        let authorize_payload = AgentKeyAuthorizePayload {
            agent_id: agent_actor_id.clone(),
            key_id: agent_key_id,
            verification_method: verification_method.clone(),
            public_key: runtime_public_key,
            accountable_principal_id: controller_principal_id,
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
                approved_by: Some(controller_actor_id),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let authorize_event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::AgentKeyAuthorize.to_string(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x41; 32],
                )),
            },
            ActorId::account(arkret_wire::AccountId::new(
                agent_actor_id.clone(),
                service_id,
            )),
            serde_json::to_value(authorize_payload).unwrap(),
            issued_at,
        )
        .unwrap();

        let approval = builder.build_approval_request().unwrap();
        let pairing = builder
            .build_key_pair_request(
                arkret_wire::OpaqueLocalId::new("approval-request-1").unwrap(),
                disclosure,
                authorize_event,
            )
            .unwrap();

        assert_eq!(
            approval.runtime_request_public_key_digest,
            pairing.runtime_request_public_key_digest
        );
        assert_eq!(
            serde_json::to_value(approval.body.public_key).unwrap(),
            pairing.body.authorize_event.event.payload["public_key"]
        );
        assert_eq!(
            pairing.body.authorize_event.event.payload["agent_id"],
            serde_json::to_value(agent_actor_id).unwrap()
        );
        assert_eq!(approval.body.verification_method, verification_method);
        assert_eq!(
            pairing.body.authorize_event.event.payload["verification_method"],
            serde_json::to_value(verification_method).unwrap()
        );
    }
}
