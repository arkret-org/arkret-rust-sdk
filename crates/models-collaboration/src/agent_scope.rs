//! Agent runtime pairing and requested-scope DTOs.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, Base64UrlString, Did, DidCoreId, DidUrl, Event, Hash, NonEmptyString, OpaqueLocalId,
    PayloadProof, ProofContextId, RequestId, Result, SchemaId, WireError, canonical,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::agent::{AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyScope};
use crate::governance::agent_artifacts::PublicKey;

pub const AGENT_RUNTIME_KEY_POSSESSION_PROOF_CONTEXT: &str =
    ProofContextId::AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1;
pub const AGENT_RUNTIME_KEY_BINDING_KIND: &str = "ak.agent.runtime_key_binding.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRuntimeKeyPossessionProofKind {
    #[serde(rename = "agent_runtime_key_possession")]
    AgentRuntimeKeyPossession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRuntimeKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeKeyPossessionProof {
    pub kind: AgentRuntimeKeyPossessionProofKind,
    pub verification_method: DidUrl,
    pub signature_algorithm: AgentRuntimeKeyAlgorithm,
    pub challenge: OpaqueLocalId,
    pub audience_id: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub runtime_key_binding_digest: Hash,
    pub transcript_digest: Hash,
    pub signature: Base64UrlString,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AgentRuntimeKeyBinding<'a> {
    kind: &'static str,
    agent_id: &'a DidCoreId,
    pairing_request_id: &'a OpaqueLocalId,
    verification_method: &'a DidUrl,
    public_key_digest: Hash,
    attestation_digest: Hash,
}

pub fn agent_runtime_key_binding_digest(
    agent_id: &DidCoreId,
    pairing_request_id: &OpaqueLocalId,
    verification_method: &DidUrl,
    public_key: &PublicKey,
    runtime_attestation: Option<&AgentKeyAuthorizePayloadRuntimeAttestation>,
) -> Result<Hash> {
    if public_key.kty.as_str() != "OKP"
        || public_key.algorithm.as_str() != "Ed25519"
        || public_key.kid.as_str() != verification_method.as_str()
        || public_key.key_digest.is_some()
    {
        return Err(WireError::Protocol(
            "Agent runtime public key does not match the closed Ed25519 profile".into(),
        ));
    }
    let raw_public_key = arkret_canonical::base64url_decode(public_key.key.as_str())?;
    if raw_public_key.len() != 32
        || arkret_canonical::base64url_encode(&raw_public_key) != public_key.key.as_str()
    {
        return Err(WireError::Protocol(
            "Agent runtime public key is not canonical 32-byte Ed25519 material".into(),
        ));
    }
    let public_key_digest = Hash::new(canonical::sha256_digest(&raw_public_key))?;
    let attestation = runtime_attestation
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
    let attestation_digest = Hash::new(canonical::canonical_sha256(&attestation)?)?;
    Hash::new(canonical::canonical_sha256(&AgentRuntimeKeyBinding {
        kind: AGENT_RUNTIME_KEY_BINDING_KIND,
        agent_id,
        pairing_request_id,
        verification_method,
        public_key_digest,
        attestation_digest,
    })?)
    .map_err(Into::into)
}

impl AgentRuntimeKeyPossessionProof {
    pub fn canonical_transcript_bytes(&self, pairing_code: &str) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": AGENT_RUNTIME_KEY_POSSESSION_PROOF_CONTEXT,
            "kind": "agent_runtime_key_possession",
            "verification_method": self.verification_method,
            "signature_algorithm": self.signature_algorithm,
            "challenge": self.challenge,
            "audience_id": self.audience_id,
            "created_at": canonical::format_timestamp_canonical(self.created_at),
            "expires_at": canonical::format_timestamp_canonical(self.expires_at),
            "pairing_code": pairing_code,
            "runtime_key_binding_digest": self.runtime_key_binding_digest,
        }))
        .map_err(Into::into)
    }

    pub fn wire_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_shape(
        &self,
        agent_id: &DidCoreId,
        pairing_request_id: &OpaqueLocalId,
        verification_method: &DidUrl,
        public_key: &PublicKey,
        expected_binding_digest: &Hash,
        pairing_code: &str,
        pairing_expires_at: DateTime<Utc>,
        verifier_now: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        if public_key.kty.as_str() != "OKP"
            || public_key.algorithm.as_str() != "Ed25519"
            || public_key.key_digest.is_some()
            || public_key.kid.as_str() != verification_method.as_str()
            || &self.verification_method != verification_method
            || &self.challenge != pairing_request_id
            || self.runtime_key_binding_digest != *expected_binding_digest
        {
            return Err(WireError::Protocol(
                "Agent runtime key proof/request binding mismatch".into(),
            ));
        }
        let controller = verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol("Agent runtime verification method is not a DID URL".into())
            })?;
        if project_did_to_core_id(&Did::new(controller.to_owned())?)? != *agent_id {
            return Err(WireError::Protocol(
                "Agent runtime verification method controller mismatch".into(),
            ));
        }
        let public_key_bytes = arkret_canonical::base64url_decode(public_key.key.as_str())?;
        let signature_bytes = arkret_canonical::base64url_decode(self.signature.as_str())?;
        if public_key_bytes.len() != 32
            || signature_bytes.len() != 64
            || arkret_canonical::base64url_encode(&public_key_bytes) != public_key.key.as_str()
            || arkret_canonical::base64url_encode(&signature_bytes) != self.signature.as_str()
        {
            return Err(WireError::Protocol(
                "Agent runtime key or signature is not canonical Ed25519 material".into(),
            ));
        }
        if self.created_at > verifier_now + chrono::Duration::seconds(60)
            || self.created_at >= self.expires_at
            || self.expires_at > self.created_at + chrono::Duration::seconds(300)
            || self.expires_at > pairing_expires_at
            || verifier_now >= self.expires_at
        {
            return Err(WireError::Protocol(
                "Agent runtime key proof freshness window is invalid".into(),
            ));
        }
        let transcript = self.canonical_transcript_bytes(pairing_code)?;
        if Hash::new(canonical::sha256_digest(&transcript))? != self.transcript_digest {
            return Err(WireError::Protocol(
                "Agent runtime key proof transcript digest mismatch".into(),
            ));
        }
        Ok(transcript)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequestedScopeDisclosure {
    pub schema: SchemaId,
    pub request_id: RequestId,
    pub agent_id: DidCoreId,
    pub controller_principal_id: DidCoreId,
    pub requested_scope: AgentKeyScope,
    pub verifier_id: DidCoreId,
    pub audience: NonEmptyString,
    pub challenge: NonEmptyString,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proofs: Vec<PayloadProof>,
}

impl AgentRequestedScopeDisclosure {
    pub const SCHEMA: SchemaId = SchemaId::AgentRequestedScopeDisclosureV1;

    pub fn canonical_bytes_without_proofs(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&canonical::unsigned_value(self, &["proofs"])?)
            .map_err(Into::into)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(
            &self.canonical_bytes_without_proofs()?,
        ))
        .map_err(Into::into)
    }

    pub fn canonical_proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure proof digest mismatch".into(),
            ));
        }
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1,
            "payload_digest": payload_digest,
            "agent_id": self.agent_id,
            "controller_principal_id": self.controller_principal_id,
            "verifier_id": self.verifier_id,
            "audience": self.audience,
            "challenge": self.challenge,
            "verification_method": proof.verification_method,
            "created_at": proof.created_at,
        }))
        .map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure schema is invalid".into(),
            ));
        }
        if self.challenge.as_str().len() < 16 {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure challenge must contain at least 16 bytes".into(),
            ));
        }
        let lifetime = self.expires_at.signed_duration_since(self.issued_at);
        if lifetime <= chrono::Duration::zero() || lifetime > chrono::Duration::seconds(300) {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure lifetime must be within 1..=300 seconds".into(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure requires a controller proof".into(),
            ));
        }
        let digest = self.payload_digest()?;
        for proof in &self.proofs {
            proof.validate_production()?;
            if proof.payload_digest != digest {
                return Err(WireError::Protocol(
                    "agent requested-scope disclosure proof digest mismatch".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub requested_scope_disclosure: AgentRequestedScopeDisclosure,
    pub authorize_event: Event,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalRequestBody {
    pub pairing_code: NonEmptyString,
    pub pairing_request_id: OpaqueLocalId,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    pub proof_of_possession: AgentRuntimeKeyPossessionProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: DidCoreId,
    pub agent_id: DidCoreId,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub pairing_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<AgentPairingRuntimeIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingRuntimeIdentity {
    pub controller_account_id: AccountId,
    pub verification_method: DidUrl,
}

impl AgentPairingBootstrap {
    pub const SCHEMA: &'static str = SchemaId::AGENT_PAIRING_BOOTSTRAP_V1;

    pub fn validated_runtime_identity(
        &self,
    ) -> std::result::Result<&AgentPairingRuntimeIdentity, String> {
        let identity = self.runtime_identity.as_ref().ok_or_else(|| {
            "Pairing service did not provide runtime identity; resolve a new pairing link"
                .to_owned()
        })?;
        identity
            .controller_account_id
            .validate()
            .map_err(|error| error.to_string())?;
        let (controller, _) = identity
            .verification_method
            .as_str()
            .rsplit_once('#')
            .filter(|(_, fragment)| !fragment.is_empty())
            .ok_or_else(|| {
                "Pairing runtime verification method must be a complete DID URL".to_owned()
            })?;
        let did = Did::new(controller.to_owned()).map_err(|error| error.to_string())?;
        if project_did_to_core_id(&did).map_err(|error| error.to_string())? != self.agent_id {
            return Err(
                "Pairing runtime verification method does not belong to the paired Agent"
                    .to_owned(),
            );
        }
        Ok(identity)
    }
}

#[derive(Serialize)]
struct AgentRequestedScopeCommitment<'a> {
    agent_id: &'a str,
    controller_principal_id: &'a str,
    kind: &'static str,
    requested_scope: &'a AgentKeyScope,
}

pub fn agent_requested_scope_digest(
    agent_id: &DidCoreId,
    controller_principal_id: &DidCoreId,
    requested_scope: &AgentKeyScope,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentRequestedScopeCommitment {
            agent_id: agent_id.as_str(),
            controller_principal_id: controller_principal_id.as_str(),
            kind: "ak.agent.requested_scope_commitment.v1",
            requested_scope,
        },
    )?)
    .map_err(Into::into)
}
