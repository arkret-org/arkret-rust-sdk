//! Agent runtime pairing and requested-scope DTOs.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    Base64UrlString, Did, DidCoreId, DidUrl, EventAdmissionSubmission, Hash, NonEmptyString,
    OpaqueLocalId, PayloadProof, ProofContextId, RequestId, Result, SchemaId, WireError, canonical,
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

/// A runtime key may narrow the immutable provision actions and selectors,
/// and must preserve every mandatory provision constraint. Service-only
/// selection does not manufacture a content-resource ceiling.
pub fn agent_key_scope_within_provision(
    ceiling: &AgentKeyScope,
    key_scope: &AgentKeyScope,
) -> bool {
    use crate::events_payloads::agent::AgentKeyScopeResourceKind;
    let content = |kind| {
        !matches!(
            kind,
            AgentKeyScopeResourceKind::Operation | AgentKeyScopeResourceKind::Service
        )
    };
    if key_scope.actions.is_empty()
        || key_scope.resources.is_empty()
        || key_scope
            .actions
            .iter()
            .any(|action| !ceiling.actions.contains(action))
        || ceiling
            .constraints
            .iter()
            .any(|required| !key_scope.constraints.contains(required))
    {
        return false;
    }
    let has_content = ceiling
        .resources
        .iter()
        .any(|resource| content(resource.kind));
    key_scope.resources.iter().all(|child| {
        (content(child.kind) && !has_content)
            || ceiling.resources.iter().any(|parent| {
                (parent.kind == child.kind
                    || (parent.kind == AgentKeyScopeResourceKind::Realm && content(child.kind)))
                    && parent
                        .realm_id
                        .as_ref()
                        .is_none_or(|id| child.realm_id.as_ref() == Some(id))
                    && parent
                        .operation
                        .as_ref()
                        .is_none_or(|op| child.operation.as_ref() == Some(op))
                    && parent
                        .service_id
                        .as_ref()
                        .is_none_or(|id| child.service_id.as_ref() == Some(id))
                    && parent
                        .schema_ref
                        .as_ref()
                        .is_none_or(|schema| child.schema_ref.as_ref() == Some(schema))
                    && parent
                        .resource_ref
                        .as_ref()
                        .is_none_or(|reference| child.resource_ref.as_ref() == Some(reference))
            })
    })
}

/// A durable grant may only narrow the immutable provision actions/resources
/// and must preserve every provision constraint. Service-only selectors do
/// not manufacture a content resource ceiling (capabilities.md section 9.1).
pub fn agent_grant_scope_within_provision(
    ceiling: &AgentKeyScope,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    constraints: &[crate::governance::grant_constraint::GrantConstraint],
) -> Result<bool> {
    if actions
        .iter()
        .any(|action| !ceiling.actions.contains(action))
        || ceiling
            .constraints
            .iter()
            .any(|required| !constraints.contains(required))
    {
        return Ok(false);
    }
    let content = |kind: &str| {
        matches!(
            kind,
            "realm"
                | "space"
                | "circle"
                | "strand"
                | "message"
                | "morph"
                | "object"
                | "relation"
                | "view"
                | "event"
                | "actor"
                | "schema"
                | "policy"
                | "invite"
                | "notification"
                | "read_cursor"
                | "blob"
        )
    };
    let ceilings = ceiling
        .resources
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<Vec<_>>>()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let has_content = ceilings
        .iter()
        .any(|selector| selector["kind"].as_str().is_some_and(content));
    for resource in resources {
        let child = serde_json::to_value(resource)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        let Some(kind) = child["kind"].as_str() else {
            return Ok(false);
        };
        if !content(kind) {
            return Ok(false);
        }
        if content(kind) && !has_content {
            continue;
        }
        let covered = ceilings.iter().any(|parent| {
            let parent_kind = parent["kind"].as_str();
            if parent_kind != Some(kind) && !(parent_kind == Some("realm") && content(kind)) {
                return false;
            }
            if parent
                .get("realm_id")
                .is_some_and(|realm| child.get("realm_id") != Some(realm))
            {
                return false;
            }
            for field in ["operation", "service_id", "schema_ref"] {
                if parent
                    .get(field)
                    .is_some_and(|value| child.get(field) != Some(value))
                {
                    return false;
                }
            }
            let Some(reference) = parent.get("resource_ref") else {
                return true;
            };
            [
                "resource_ref",
                "space_id",
                "circle_id",
                "strand_id",
                "message_id",
                "morph_id",
                "object_ref",
                "relation_id",
                "view_id",
                "event_id",
                "actor_id",
                "policy_id",
                "invite_id",
                "blob_ref",
            ]
            .iter()
            .any(|field| child.get(*field) == Some(reference))
        });
        if !covered {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRuntimeKeyPossessionProofKind {
    #[serde(rename = "agent_runtime_key_possession")]
    AgentRuntimeKeyPossession,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRuntimeKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub requested_scope_disclosure: AgentRequestedScopeDisclosure,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub authorize_event: EventAdmissionSubmission,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

impl AgentRuntimeApprovalRequestBody {
    pub fn validate(&self) -> Result<()> {
        let code = self.pairing_code.as_str();
        if code.len() != 8 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(WireError::Protocol(
                "Agent pairing code must contain exactly eight ASCII decimal digits".to_owned(),
            ));
        }
        Ok(())
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
