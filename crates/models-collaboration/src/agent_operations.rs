//! Personal-Agent lifecycle wire models and the requested-scope commitment
//! digest, relocated from the `arkret` umbrella. These bind agent-key payloads
//! (`events_payloads::agent`), grant / key-state artifacts
//! (`governance::agent_artifacts`), capability grants
//! (`governance::grant_constraint`), and the managed-frontier reference
//! (`arkret-models-crypto`), all reachable within the collaboration layering
//! edge. the `arkret` umbrella re-exports them for path stability.

use std::collections::BTreeSet;

use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use arkret_wire::{
    AuditReasonText, Did, DidCoreId, DidUrl, EventInitialSubmission, IdempotencyKey, SchemaId,
    project_did_to_core_id,
};

use crate::agent_signer_evidence::AgentSigningKeyBinding;
use crate::events_payloads::agent::{AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyScope};
use crate::governance::agent_artifacts::{AgentKeyAuthorizationState, GrantSnapshot, PublicKey};
use crate::internal_prelude::*;

pub const AGENT_RUNTIME_KEY_POSSESSION_PROOF_CONTEXT: &str =
    ProofContextId::AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1;
pub const AGENT_RUNTIME_KEY_BINDING_KIND: &str = "ak.agent.runtime_key_binding.v1";
pub const AGENT_KEY_PAIRING_REQUEST_BINDING_KIND: &str = "ak.agent.key_pairing_request_binding.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentRuntimeKeyPossessionProofKind {
    #[serde(rename = "agent_runtime_key_possession")]
    AgentRuntimeKeyPossession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentRuntimeKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Closed proof that a runtime controls the proposed Agent Ed25519 key and
/// possesses the authoritative one-time pairing secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRuntimeKeyPossessionProof {
    pub kind: AgentRuntimeKeyPossessionProofKind,
    pub verification_method: DidUrl,
    pub signature_algorithm: AgentRuntimeKeyAlgorithm,
    pub challenge: OpaqueLocalId,
    pub audience: DidCoreId,
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

/// Sole SDK helper for the stable identity of a runtime-key request.
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
            "Agent runtime public key does not match the closed Ed25519 profile".to_owned(),
        ));
    }
    let raw_public_key = arkret_canonical::base64url_decode(public_key.key.as_str())?;
    if raw_public_key.len() != 32
        || arkret_canonical::base64url_encode(&raw_public_key) != public_key.key.as_str()
    {
        return Err(WireError::Protocol(
            "Agent runtime public key is not canonical 32-byte Ed25519 material".to_owned(),
        ));
    }
    let public_key_digest = Hash::new(canonical::canonical_sha256(public_key)?)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let attestation = runtime_attestation
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
    let attestation_digest = Hash::new(canonical::canonical_sha256(&attestation)?)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let binding = AgentRuntimeKeyBinding {
        kind: AGENT_RUNTIME_KEY_BINDING_KIND,
        agent_id,
        pairing_request_id,
        verification_method,
        public_key_digest,
        attestation_digest,
    };
    Hash::new(canonical::canonical_sha256(&binding)?)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

impl AgentRuntimeKeyPossessionProof {
    pub fn canonical_transcript_bytes(&self, pairing_code: &str) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(&serde_json::json!({
            "context": AGENT_RUNTIME_KEY_POSSESSION_PROOF_CONTEXT,
            "kind": "agent_runtime_key_possession",
            "verification_method": self.verification_method,
            "signature_algorithm": self.signature_algorithm,
            "challenge": self.challenge,
            "audience": self.audience,
            "created_at": canonical::format_timestamp_canonical(self.created_at),
            "expires_at": canonical::format_timestamp_canonical(self.expires_at),
            "pairing_code": pairing_code,
            "runtime_key_binding_digest": self.runtime_key_binding_digest,
        }))?)
    }

    pub fn wire_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?)
            .map_err(|error| WireError::Protocol(error.to_string()))
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
                "Agent runtime key proof/request binding mismatch".to_owned(),
            ));
        }
        let controller = verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol("Agent runtime verification method is not a DID URL".to_owned())
            })?;
        if project_did_to_core_id(&Did::new(controller.to_owned())?)? != *agent_id {
            return Err(WireError::Protocol(
                "Agent runtime verification method controller mismatch".to_owned(),
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
                "Agent runtime key or signature is not canonical Ed25519 material".to_owned(),
            ));
        }
        if self.created_at > verifier_now + chrono::Duration::seconds(60)
            || self.created_at >= self.expires_at
            || self.expires_at > self.created_at + chrono::Duration::seconds(300)
            || self.expires_at > pairing_expires_at
            || verifier_now >= self.expires_at
        {
            return Err(WireError::Protocol(
                "Agent runtime key proof freshness window is invalid".to_owned(),
            ));
        }
        let transcript = self.canonical_transcript_bytes(pairing_code)?;
        let transcript_digest = Hash::new(canonical::sha256_digest(&transcript))
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if transcript_digest != self.transcript_digest {
            return Err(WireError::Protocol(
                "Agent runtime key proof transcript digest mismatch".to_owned(),
            ));
        }
        Ok(transcript)
    }
}

/// Sole SDK helper for the controller approval digest. It deliberately binds
/// the current PoP wire digest, so refreshing a proof invalidates stale UI
/// approval prompts without changing the stable runtime identity.
#[allow(clippy::too_many_arguments)]
pub fn agent_key_pairing_request_binding_digest(
    operation_id: &str,
    controller_id: &DidCoreId,
    agent_id: &DidCoreId,
    pairing_request_id: &OpaqueLocalId,
    pairing_code: &str,
    pairing_expires_at: DateTime<Utc>,
    audience: &DidCoreId,
    runtime_key_binding_digest: &Hash,
    proof: &AgentRuntimeKeyPossessionProof,
) -> Result<Hash> {
    let value = serde_json::json!({
        "kind": AGENT_KEY_PAIRING_REQUEST_BINDING_KIND,
        "operation_id": operation_id,
        "controller_id": controller_id,
        "agent_id": agent_id,
        "pairing_request_id": pairing_request_id,
        "pairing_code": pairing_code,
        "expires_at": pairing_expires_at,
        "audience": audience,
        "runtime_key_binding_digest": runtime_key_binding_digest,
        "proof_of_possession_digest": proof.wire_digest()?,
    });
    Hash::new(canonical::canonical_sha256(&value)?)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Controller-signed, verifier-bound private disclosure of an Agent's
/// immutable requested scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRequestedScopeDisclosure {
    pub schema: SchemaId,
    pub request_id: RequestId,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub requested_scope: AgentKeyScope,
    pub verifier_id: DidCoreId,
    pub audience: NonEmptyString,
    pub challenge: NonEmptyString,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proofs: Vec<ProducerEventProof>,
}

impl AgentRequestedScopeDisclosure {
    pub const SCHEMA: SchemaId = SchemaId::AgentRequestedScopeDisclosureV1;
    pub fn canonical_bytes_without_proofs(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AgentRequestedScopeDisclosure serializes as an object")
            .remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(
            &self.canonical_bytes_without_proofs()?,
        ))
        .map_err(|reason| WireError::Protocol(reason.to_string()))
    }

    pub fn canonical_proof_binding_bytes(&self, proof: &ProducerEventProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.event_digest != payload_digest {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure proof digest mismatch".to_owned(),
            ));
        }
        Ok(canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1,
            "payload_digest": payload_digest,
            "agent_id": self.agent_id,
            "controller_id": self.controller_id,
            "verifier_id": self.verifier_id,
            "audience": self.audience,
            "challenge": self.challenge,
            "verification_method": proof.verification_method,
            "created_at": proof.created_at,
        }))?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::AgentRequestedScopeDisclosureV1 {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure schema is invalid".to_owned(),
            ));
        }
        if self.challenge.as_str().len() < 16 {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure challenge must contain at least 16 bytes"
                    .to_owned(),
            ));
        }
        let lifetime = self.expires_at.signed_duration_since(self.issued_at);
        if lifetime <= chrono::Duration::zero() || lifetime > chrono::Duration::seconds(300) {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure lifetime must be within 1..=300 seconds"
                    .to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure requires a controller proof".to_owned(),
            ));
        }
        let payload_digest = self.payload_digest()?;
        if self
            .proofs
            .iter()
            .any(|proof| proof.event_digest != payload_digest)
        {
            return Err(WireError::Protocol(
                "agent requested-scope disclosure proof digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: OpaqueLocalId,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    pub proof_of_possession: AgentRuntimeKeyPossessionProof,
    pub requested_scope_disclosure: AgentRequestedScopeDisclosure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    pub signing_key_binding: AgentSigningKeyBinding,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub authorize_event: EventInitialSubmission,
}

/// Whether a submitted runtime-key authorization has merely been stored or is
/// already covered by the accepted, controller-signed Agent-PCR frontier.
///
/// A durable Event is not yet an authorization witness. Callers MUST close the
/// Event into a managed-PCR Seal and retry the same idempotent pairing request
/// before treating the runtime as active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentKeyPairActivationState {
    AwaitingAcceptedFrontier,
    Active,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyPairOutcome {
    pub activation_state: AgentKeyPairActivationState,
    pub authorize_event_ref: EventId,
    pub signing_key_binding: AgentSigningKeyBinding,
}

impl AgentKeyPairOutcome {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.activation_state == AgentKeyPairActivationState::Active
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

/// Authenticated controller-safe projection of a pending runtime-key request.
///
/// This deliberately excludes the pairing secret and all controller-authored
/// approval material. It is a separate closed DTO from both
/// [`AgentRuntimeApprovalRequestBody`] and [`AgentKeyPairRequestBody`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRuntimeApprovalControllerProjection {
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRuntimeApprovalOutcome {
    pub approval_request_id: OpaqueLocalId,
    pub status: AgentLifecycleState,
}

/// Runtime-side poll for the controller decision on a previously submitted
/// runtime key request. The `pairing_request_id` + `pairing_code` +
/// `agent_id` triple is the query credential; a record miss and a
/// mismatch are indistinguishable (both not_found). Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRuntimeApprovalStatusRequestBody {
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    pub agent_id: DidCoreId,
}

/// Controller-decision status for an agent runtime key pairing request.
/// Once approved, `authorized_event_ref` plus the authorized key binding
/// fields are present; the runtime MUST compare
/// `authorized_public_key_digest` against its own key and treat a mismatch
/// as paired-by-another-runtime. Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRuntimeApprovalStatusOutcome {
    pub status: AgentLifecycleState,
    pub runtime_state: AgentRuntimeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_public_key_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_signing_key_binding: Option<AgentSigningKeyBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentProvisionRequestBody {
    Prepare {
        operation_id: ProtocolOperationId,
        idempotency_key: IdempotencyKey,
        /// Controller-authored, already accepted PCR-independent Agent
        /// inception. The Principal Server verifies and pins its exact head.
        did: Did,
        /// Principal Server half of the controller authority selected by this
        /// authenticated operation. The principal half comes from the session.
        controller_principal_server_id: DidCoreId,
        slug: String,
        requested_scope: AgentKeyScope,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_ttl_ms: Option<u64>,
    },
    Commit {
        operation_id: ProtocolOperationId,
        idempotency_key: IdempotencyKey,
        agent_id: DidCoreId,
        did: Did,
        principal_control_realm_id: RealmId,
        allocation_handle: ProtocolOpaqueId,
        slug: String,
        requested_scope: AgentKeyScope,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        provision_event: Box<EventInitialSubmission>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_ttl_ms: Option<u64>,
    },
}

// NOTE: `AgentKeyScope` is the spec object `{actions, resources, constraints?}`
// defined in `models/artifacts/event_payload/agent.rs`
// (`event-payload.schema.json#/$defs/agent_key_scope`, `$ref`'d by
// `agent-operations.schema.json#/$defs/agent_provision_request_body.requested_scope`).
/// Re-open pairing on any non-terminal agent. The service issues a fresh
/// one-time pairing handle and every previously issued handle becomes
/// permanently unresolvable. Agents without an active authorized key
/// (`runtime_state` `pending_runtime_key` / `pairing_expired`) re-open
/// bootstrap pairing; agents that already hold an active authorized key
/// (lifecycle `active` or `paused`) perform runtime replacement re-pairing
/// (existing keys stay valid until the new pairing completes, then are
/// atomically superseded by the single accepted authorization Event, and the
/// lifecycle intent is preserved unchanged — an `active` agent needs no
/// resume). `deactivated` rejects. Mirrors
/// `agent-operations.schema.json#/$defs/agent_renew_pairing_request_body`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRenewPairingRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentPairingMode {
    Bootstrap,
    Replacement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentProvisionOutcome {
    AwaitingControllerEvent {
        agent_id: DidCoreId,
        did: Did,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        controller_realm_id: RealmId,
        allocation_handle: ProtocolOpaqueId,
        controller_authorization_ref: DidUrl,
        requested_scope_digest: Hash,
    },
    AwaitingPcrGenesis {
        agent_id: DidCoreId,
        did: Did,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        principal_control_realm_id: RealmId,
        allocation_handle: ProtocolOpaqueId,
        controller_authorization_ref: DidUrl,
        requested_scope_digest: Hash,
    },
    AwaitingDidBinding {
        agent_id: DidCoreId,
        did: Did,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        principal_control_realm_id: RealmId,
        allocation_handle: ProtocolOpaqueId,
        controller_authorization_ref: DidUrl,
        requested_scope_digest: Hash,
    },
    Complete {
        #[serde(flatten)]
        outcome: AgentProvisionComplete,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentProvisionComplete {
    pub agent_id: DidCoreId,
    pub did: Did,
    pub initial_resolution: arkret_models_identity::ResolutionCommitment,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub requested_scope_digest: Hash,
    pub pairing_request_id: OpaqueLocalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentRenewPairingOutcome {
    pub agent_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub requested_scope_digest: Hash,
    pub pairing_mode: AgentPairingMode,
    pub pairing_request_id: OpaqueLocalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// One-time bootstrap material handed to a personal agent runtime after
/// provisioning. Mirrors `agent-operations.schema.json#/$defs/agent_pairing_bootstrap`
/// and AKP-0008 §4.4: a short-lived, revocable pairing input only. It is not a
/// session grant, capability grant or long-term secret, and it deliberately
/// carries no scope payload (the authoritative ceiling lives in
/// `ak.agent.key.authorize` and the effective-permission intersection).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: DidCoreId,
    pub agent_id: DidCoreId,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub pairing_expires_at: DateTime<Utc>,
}

impl AgentPairingBootstrap {
    pub const SCHEMA: &'static str = SchemaId::AGENT_PAIRING_BOOTSTRAP_V1;
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingResolveRequestBody {
    pub pairing_token: String,
}

/// Derived, read-only runtime key readiness axis, orthogonal to the
/// controller lifecycle intent axis (`AgentLifecycleState`). See
/// `key-management.md` §3.6.1. It is never written directly nor treated as a
/// lifecycle transition target; services and clients MUST derive it from the
/// same key/pairing facts through [`AgentRuntimeState::derive`] and MUST NOT
/// maintain a second writable state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentRuntimeState {
    PendingRuntimeKey,
    Ready,
    Replacing,
    PairingExpired,
}

impl AgentRuntimeState {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::PendingRuntimeKey => "pending_runtime_key",
            Self::Ready => "ready",
            Self::Replacing => "replacing",
            Self::PairingExpired => "pairing_expired",
        }
    }

    /// Sole derivation of the runtime readiness axis from key/pairing facts
    /// (`key-management.md` §3.6.1). `has_active_authorization` is whether the
    /// agent currently holds an active accepted `ak.agent.key.authorize`;
    /// `has_open_pairing_handle` is whether an unconsumed, unexpired pairing
    /// handle exists. The pairing mode is implied by the pair: an open handle
    /// on a keyed agent is a replacement handle (→ `replacing`), on an unkeyed
    /// agent a bootstrap handle (→ `pending_runtime_key`). Replacement handle
    /// expiry is side-effect free and returns the projection to `ready`;
    /// bootstrap handle expiry projects `pairing_expired`.
    pub fn derive(has_active_authorization: bool, has_open_pairing_handle: bool) -> Self {
        match (has_active_authorization, has_open_pairing_handle) {
            (true, true) => Self::Replacing,
            (true, false) => Self::Ready,
            (false, true) => Self::PendingRuntimeKey,
            (false, false) => Self::PairingExpired,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentProjection {
    pub agent_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub lifecycle: AgentLifecycleState,
    pub readiness: AgentReadiness,
    pub presence: AgentPresence,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentReadinessState {
    Ready,
    NotReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentReadinessBlocker {
    RuntimeKeyMissing,
    PairingOpen,
    RecoveryStale,
    SessionMissing,
    KeypackageEmpty,
    ReplyCapabilityMissing,
    MlsRejoinRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentReadiness {
    pub state: AgentReadinessState,
    pub blockers: Vec<AgentReadinessBlocker>,
}

impl AgentReadiness {
    pub fn validate(&self) -> Result<()> {
        let unique = self.blockers.iter().collect::<BTreeSet<_>>();
        let valid_cardinality = match self.state {
            AgentReadinessState::Ready => self.blockers.is_empty(),
            AgentReadinessState::NotReady => !self.blockers.is_empty(),
        };
        if unique.len() != self.blockers.len() || !valid_cardinality {
            return Err(WireError::Protocol(
                "Agent readiness state and blockers are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentPresenceState {
    Online,
    Offline,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentPresence {
    pub state: AgentPresenceState,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub refresh_after: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

impl AgentLifecycleState {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deactivated => "deactivated",
        }
    }

    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "deactivated" => Some(Self::Deactivated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentLifecycleOutcome {
    pub status: AgentLifecycleState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentList {
    pub agents: Vec<AgentProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<cursor::Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentView {
    pub agent: AgentProjection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_state: Option<KeyState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentPauseRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    /// Initial publication of the closed Agent-PCR lifecycle Event authored by
    /// the Agent principal and executed/signed by its controller delegation.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentResumeRequestBody {
    /// Initial publication of the closed Agent-PCR lifecycle Event authored by
    /// the Agent principal and executed/signed by its controller delegation.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivateRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    /// Closed Agent-PCR terminal lifecycle Event authored by the Agent
    /// principal and executed/signed by its controller delegation.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
}

impl AgentDeactivateRequestBody {
    pub fn validate(&self) -> Result<()> {
        let event = &self.lifecycle_event.event;
        if event.kind != EventKind::SelfAgentDeactivate {
            return Err(WireError::Protocol(
                "agent deactivation lifecycle_event must be ak.self.agent.deactivate".to_owned(),
            ));
        }
        let payload_reason = event.payload.get("reason").and_then(Value::as_str);
        if payload_reason != self.reason.as_ref().map(AuditReasonText::as_str) {
            return Err(WireError::Protocol(
                "agent deactivation request reason must equal lifecycle Event payload reason"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentGrantAttachRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub grant_event: EventInitialSubmission,
    pub requested_scope_disclosure: AgentRequestedScopeDisclosure,
}

impl AgentGrantAttachRequestBody {
    pub fn validate(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        self.requested_scope_disclosure.validate()?;
        let event = &self.grant_event.event;
        if event.kind != EventKind::CapabilityGrant {
            return Err(WireError::Protocol(
                "Agent grant attach requires an ak.capability.grant Event".to_owned(),
            ));
        }
        event.validate_proof_bindings_with_digest_suite(digest_suite)?;
        let payload: crate::events_payloads::capability::CapabilityGrantPayload =
            decode_payload_after_kind_validation(event)?;
        let grant = &payload.grant;
        let subject = match &grant.subject {
            CapabilitySubject::CoreDid(subject) => subject,
            CapabilitySubject::Condition(_) => {
                return Err(WireError::Protocol(
                    "Agent grant attach requires the path Agent as grant subject".to_owned(),
                ));
            }
        };
        if grant.issuer != event.actor_id
            || grant.realm_id.as_ref() != Some(&event.realm_id)
            || event.scope_ref.realm_id() != &event.realm_id
            || self.requested_scope_disclosure.agent_id != *subject
            || self.requested_scope_disclosure.controller_id.as_core_id()
                != event.actor_id.as_core_id()
            || grant.actions.iter().any(|action| {
                !self
                    .requested_scope_disclosure
                    .requested_scope
                    .actions
                    .contains(action)
            })
        {
            return Err(WireError::Protocol(
                "Agent grant Event exceeds or does not match requested-scope disclosure".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentGrantAttachOutcome {
    pub grant_id: GrantId,
}

/// Request body for `ak.self.agent.grant.resource.delete.v1`.
///
/// The controller supplies the complete signed revoke Move. The service only
/// checks its path/target bindings and forwards it through ordinary Event
/// admission; it never authors the revoke or adds the CAS guard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentGrantDetachRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_event: EventInitialSubmission,
}

impl AgentGrantDetachRequestBody {
    pub fn validate(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        let event = &self.revoke_event.event;
        if event.kind != EventKind::CapabilityRevoke {
            return Err(WireError::Protocol(
                "Agent grant detach requires an ak.capability.revoke Event".to_owned(),
            ));
        }
        event.validate_proof_bindings_with_digest_suite(digest_suite)?;
        let payload: crate::events_payloads::capability::CapabilityRevokePayload =
            decode_payload_after_kind_validation(event)?;
        if payload
            .grant_ref
            .as_ref()
            .is_some_and(|grant_ref| grant_ref != &payload.grant_id)
        {
            return Err(WireError::Protocol(
                "Agent grant detach payload grant_ref must equal grant_id".to_owned(),
            ));
        }
        let expected_cell = format!(
            "ak:cell:ak.component.capability.grant.v1:{}",
            payload.grant_id
        );
        let [precondition] = event.preconditions.as_slice() else {
            return Err(WireError::Protocol(
                "Agent grant detach requires exactly one signed head_eq precondition".to_owned(),
            ));
        };
        let predicate = &precondition.predicate;
        if precondition.cell.as_str() != expected_cell
            || predicate.op != PredicateOp::HeadEq
            || predicate
                .value
                .as_ref()
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            || predicate.values.is_some()
            || predicate.predicate_id.is_some()
        {
            return Err(WireError::Protocol(
                "Agent grant detach head_eq must name the complete target grant cell head"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn payload(&self) -> Result<crate::events_payloads::capability::CapabilityRevokePayload> {
        decode_payload_after_kind_validation(&self.revoke_event.event)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentGrantDetachOutcome {
    #[serde(with = "canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Service/SDK-local projection recovered from accepted Sidecar context state.
/// It is also reused by the account-private Sidecar view-state schema, but not
/// by the removed native Sidecar operation wire shape.
pub struct AgentSidecarStrandContextRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Service/SDK-local projection recovered from accepted Sidecar context state.
/// This type is never serialized as an Arkret operation or Event wire field.
pub struct AgentSidecarRelationContextRef {
    pub realm_id: RealmId,
    pub relation_id: RelationId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
/// Local recovered locator; there is deliberately no standalone schema `$defs`
/// or OpenAPI component for this enum.
pub enum AgentSidecarContextRef {
    Strand(AgentSidecarStrandContextRef),
    Relation(AgentSidecarRelationContextRef),
}

impl AgentSidecarContextRef {
    pub fn strand(realm_id: RealmId, strand_id: StrandId) -> Self {
        Self::Strand(AgentSidecarStrandContextRef {
            realm_id,
            strand_id,
        })
    }

    pub fn relation(realm_id: RealmId, relation_id: RelationId) -> Self {
        Self::Relation(AgentSidecarRelationContextRef {
            realm_id,
            relation_id,
        })
    }

    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Strand(value) => &value.realm_id,
            Self::Relation(value) => &value.realm_id,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarAccessReadiness {
    Opening,
    KeyMaterialPending,
    EpochUpdateRequired,
    Ready,
    Failed,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingSidecarAccessReconciliationStage {
    MlsWelcome,
    MlsRemove,
    EpochRotation,
    DeviceKeyMaterial,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSidecarAccessReconciliationItem {
    pub agent_id: DidCoreId,
    pub provisioning_phase: PendingSidecarAccessReconciliationStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier: Option<Vec<EventId>>,
}

impl PendingSidecarAccessReconciliationItem {
    pub fn validate(&self) -> Result<()> {
        match (&self.provisioning_phase, &self.membership_frontier) {
            (PendingSidecarAccessReconciliationStage::MlsRemove, Some(frontier))
                if !frontier.is_empty()
                    && frontier.windows(2).all(|pair| pair[0].as_str() < pair[1].as_str()) =>
            {
                Ok(())
            }
            (PendingSidecarAccessReconciliationStage::MlsRemove, _) => Err(WireError::Protocol(
                "Sidecar MLS remove reconciliation requires a non-empty sorted unique membership_frontier"
                    .to_owned(),
            )),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(WireError::Protocol(
                "Sidecar membership_frontier is only valid for MLS remove reconciliation"
                    .to_owned(),
            )),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarSchema {
    #[serde(rename = "ak.schema.agent_sidecar.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarEncryptionProfile {
    #[serde(rename = "mls_rfc9420")]
    MlsRfc9420,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarState {
    Active,
    Suspended,
    Tombstoned,
}

pub const AGENT_SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN: &str = "ak.sidecar.participant_authority.v1";

fn sorted_unique_agent_ids(ids: &[DidCoreId]) -> bool {
    ids.windows(2)
        .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarParticipantAuthorityTranscript {
    pub domain: &'static str,
    pub sidecar_id: SidecarId,
    pub realm_id: RealmId,
    pub controller_id: DidCoreId,
    pub desired_agent_ids: Vec<DidCoreId>,
}

impl AgentSidecarParticipantAuthorityTranscript {
    pub fn new(
        sidecar_id: SidecarId,
        realm_id: RealmId,
        controller_id: DidCoreId,
        desired_agent_ids: &[DidCoreId],
    ) -> Result<Self> {
        if !sorted_unique_agent_ids(desired_agent_ids)
            || desired_agent_ids
                .iter()
                .any(|agent_id| agent_id.as_core_id() == controller_id.as_core_id())
        {
            return Err(WireError::Protocol(
                "Sidecar participant authority requires sorted unique desired Agent ids with the controller excluded"
                    .to_owned(),
            ));
        }
        Ok(Self {
            domain: AGENT_SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN,
            sidecar_id,
            realm_id,
            controller_id,
            desired_agent_ids: desired_agent_ids.to_vec(),
        })
    }

    pub fn digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

pub fn agent_sidecar_participant_authority_digest(
    sidecar_id: SidecarId,
    realm_id: RealmId,
    controller_id: DidCoreId,
    desired_agent_ids: &[DidCoreId],
) -> Result<Hash> {
    AgentSidecarParticipantAuthorityTranscript::new(
        sidecar_id,
        realm_id,
        controller_id,
        desired_agent_ids,
    )?
    .digest()
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarMlsContext {
    pub participant_authority_digest: Hash,
    pub control_frontier: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_event_ref: Option<EventId>,
    pub current_controller_device_ready: bool,
}

impl AgentSidecarMlsContext {
    pub fn validate(&self) -> Result<()> {
        if self.control_frontier.is_empty()
            || self
                .control_frontier
                .windows(2)
                .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
        {
            return Err(WireError::Protocol(
                "Sidecar MLS control_frontier must be non-empty, UTF-8 byte-lexicographically sorted, and unique"
                    .to_owned(),
            ));
        }
        let present = [
            self.mls_group_id.is_some(),
            self.epoch.is_some(),
            self.genesis_event_ref.is_some(),
        ];
        if present.iter().any(|value| *value) && !present.iter().all(|value| *value) {
            return Err(WireError::Protocol(
                "Sidecar MLS group, epoch, and genesis event reference must be all present or all absent"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecar {
    pub id: SidecarId,
    pub schema: AgentSidecarSchema,
    pub realm_id: RealmId,
    pub controller_id: DidCoreId,
    pub encryption_profile: AgentSidecarEncryptionProfile,
    pub state: AgentSidecarState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl AgentSidecar {
    pub fn validate(&self) -> Result<()> {
        if self.state != AgentSidecarState::Active && self.state_changed_at.is_none() {
            return Err(WireError::Protocol(
                "non-active Sidecar requires state_changed_at".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarView {
    pub sidecar: AgentSidecar,
    pub desired_agent_ids: Vec<DidCoreId>,
    pub effective_agent_ids: Vec<DidCoreId>,
    pub mls_context: AgentSidecarMlsContext,
    pub access_readiness: AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<PendingSidecarAccessReconciliationItem>,
}

impl AgentSidecarView {
    pub fn validate(&self) -> Result<()> {
        self.sidecar.validate()?;
        self.mls_context.validate()?;
        for pending in &self.pending_access_reconciliations {
            pending.validate()?;
        }
        let desired = self.desired_agent_ids.iter().collect::<BTreeSet<_>>();
        if !sorted_unique_agent_ids(&self.desired_agent_ids)
            || !sorted_unique_agent_ids(&self.effective_agent_ids)
            || self
                .effective_agent_ids
                .iter()
                .any(|agent_id| !desired.contains(agent_id))
        {
            return Err(WireError::Protocol(
                "Sidecar desired/effective Agent ids must be sorted and unique, with effective a subset of desired"
                    .to_owned(),
            ));
        }
        let expected_digest = agent_sidecar_participant_authority_digest(
            self.sidecar.id.clone(),
            self.sidecar.realm_id.clone(),
            self.sidecar.controller_id.clone(),
            &self.desired_agent_ids,
        )?;
        if self.mls_context.participant_authority_digest != expected_digest {
            return Err(WireError::Protocol(
                "Sidecar MLS participant_authority_digest does not match the canonical Realm-scoped desired roster transcript"
                    .to_owned(),
            ));
        }
        if self.access_readiness == AgentSidecarAccessReadiness::Ready
            && (!self.mls_context.current_controller_device_ready
                || self.effective_agent_ids.len() != self.desired_agent_ids.len()
                || self.mls_context.mls_group_id.is_none())
        {
            return Err(WireError::Protocol(
                "ready Sidecar requires a ready controller device, an accepted MLS group, and every desired Agent effective"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarList {
    pub items: Vec<AgentSidecarView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<NonEmptyString>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarDisplayMode {
    #[default]
    ContextMerged,
    SidecarOnly,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarProjectionProvenance {
    Shared,
    Private,
    PrivateEcho,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarViewStateSchema {
    #[serde(rename = "ak.schema.agent_sidecar_view_state.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarViewState {
    pub schema: AgentSidecarViewStateSchema,
    pub controller_id: DidCoreId,
    pub sidecar_id: SidecarId,
    pub context_ref: AgentSidecarStrandContextRef,
    pub display_mode: AgentSidecarDisplayMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapsed: Option<bool>,
    pub updated_hlc: Hlc,
    pub origin_device_id: DeviceId,
}

impl AgentSidecarViewState {
    pub fn account_data_key(&self) -> String {
        format!(
            "ak.agent.sidecar_view_state.v1:{}:{}:{}",
            self.controller_id, self.context_ref.realm_id, self.context_ref.strand_id
        )
    }

    pub fn validate_account_data_key(&self, account_data_key: &str) -> Result<()> {
        if account_data_key == self.account_data_key() {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "Sidecar view-state account-data key does not match plaintext".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentSidecarExchangeId(String);

impl AgentSidecarExchangeId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if (22..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~=-".contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(WireError::Protocol(
                "invalid Sidecar exchange id".to_owned(),
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentSidecarExchangeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for AgentSidecarExchangeId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentSidecarExchangeId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarSourceTrackRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: String,
}

impl AgentSidecarSourceTrackRef {
    pub fn validate(&self) -> Result<()> {
        let value = self.track_name.as_bytes();
        if value.is_empty()
            || value.len() > 64
            || !value[0].is_ascii_lowercase()
            || value
                .iter()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'))
        {
            return Err(WireError::Protocol("invalid Sidecar Track name".to_owned()));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeOrigin {
    SourceTrackRouted,
    SidecarNative,
}

/// Deterministic fold status of one source-routed exchange. `pending` is a
/// client-local pre-submission intent and never enters the projection: an
/// accepted request folds to `delivered` (see `zh/models/sidecar.md` §8).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeStatus {
    Delivered,
    Responding,
    Complete,
    Failed,
}

pub const AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CLOSED_EMPTY: &str = "controller_closed_empty";
pub const AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CANCELLED: &str = "controller_cancelled";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeCompletionPolicy {
    Coordinator,
}

fn validate_sidecar_order_key(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || bytes
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._~=-".contains(byte)))
    {
        return Err(WireError::Protocol(format!("invalid Sidecar {label}")));
    }
    Ok(())
}

fn validate_sidecar_failure_reason_code(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase()
        || bytes
            .iter()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'))
    {
        return Err(WireError::Protocol(
            "invalid Sidecar failure code".to_owned(),
        ));
    }
    Ok(())
}

fn validate_unique_sorted_event_ids(values: &[EventId], label: &str) -> Result<()> {
    if values.is_empty() {
        return Err(WireError::Protocol(format!(
            "Sidecar {label} must be non-empty"
        )));
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
    {
        return Err(WireError::Protocol(format!(
            "Sidecar {label} must be unique and UTF-8 byte-lexicographically sorted"
        )));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarEventExchangeBindingSchema {
    #[serde(rename = "ak.schema.agent_sidecar_event_exchange_binding.v1")]
    V1,
}

/// Closed producer outcome of one exchange-bound Sidecar Event.
/// Consumers MUST fail closed to non-echo on any unlisted value; serde's
/// closed enum plus the outer `deny_unknown_fields` provide exactly that.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeBindingRole {
    Request,
    UserFacingResponse,
    Internal,
}

/// Write-once exchange identity carried only on `role=request`; the single
/// durable source of every projection write-once field. Counterpart for
/// `agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeRequestContext {
    pub source_track_ref: AgentSidecarSourceTrackRef,
    pub source_hlc: Hlc,
    pub client_order_key: NonEmptyString,
    pub addressed_agent_ids: Vec<DidCoreId>,
    pub completion_policy: AgentSidecarExchangeCompletionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<EventId>,
}

impl AgentSidecarExchangeRequestContext {
    pub fn validate(&self) -> Result<()> {
        self.source_track_ref.validate()?;
        validate_sidecar_order_key(self.client_order_key.as_str(), "client order key")?;
        if self.addressed_agent_ids.is_empty()
            || self
                .addressed_agent_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.addressed_agent_ids.len()
        {
            return Err(WireError::Protocol(
                "Sidecar exchange addressed_agent_ids must be non-empty and unique".to_owned(),
            ));
        }
        match &self.coordinator_agent_id {
            Some(coordinator) => {
                if !self.addressed_agent_ids.contains(coordinator) {
                    return Err(WireError::Protocol(
                        "Sidecar exchange coordinator must be one of addressed_agent_ids"
                            .to_owned(),
                    ));
                }
            }
            None => {
                if self.addressed_agent_ids.len() != 1 {
                    return Err(WireError::Protocol(
                        "Sidecar exchange coordinator_agent_id is required when more than one Agent is addressed"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The initial coordinator: the explicit field, or the sole addressed
    /// Agent when the field is legally omitted.
    pub fn effective_coordinator(&self) -> Result<&DidCoreId> {
        self.validate()?;
        Ok(self
            .coordinator_agent_id
            .as_ref()
            .unwrap_or(&self.addressed_agent_ids[0]))
    }
}

/// Counterpart for `agent-sidecar-event-exchange-binding.schema.json`. Legal
/// only inside `encrypted_metadata` plaintext (`message_metadata.
/// sidecar_exchange_binding`) of an Event whose effective scope is the native
/// Sidecar. Any Event without a valid binding is non-echo by default.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarEventExchangeBinding {
    pub schema: AgentSidecarEventExchangeBindingSchema,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub exchange_id: AgentSidecarExchangeId,
    pub role: AgentSidecarExchangeBindingRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completes_exchange: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_assignment_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_context: Option<AgentSidecarExchangeRequestContext>,
}

impl AgentSidecarEventExchangeBinding {
    /// Controller-authored `role=request` binding.
    pub fn request(
        exchange_id: AgentSidecarExchangeId,
        request_context: AgentSidecarExchangeRequestContext,
    ) -> Result<Self> {
        let binding = Self {
            schema: AgentSidecarEventExchangeBindingSchema::V1,
            exchange_id,
            role: AgentSidecarExchangeBindingRole::Request,
            request_event_id: None,
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: Some(request_context),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Agent-authored `role=user_facing_response` binding.
    pub fn user_facing_response(
        exchange_id: AgentSidecarExchangeId,
        request_event_id: EventId,
    ) -> Result<Self> {
        let binding = Self {
            schema: AgentSidecarEventExchangeBindingSchema::V1,
            exchange_id,
            role: AgentSidecarExchangeBindingRole::UserFacingResponse,
            request_event_id: Some(request_event_id),
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: None,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Agent-authored `role=internal` binding for exchange-scoped
    /// collaboration/tool Events that MUST NOT be echoed.
    pub fn internal(
        exchange_id: AgentSidecarExchangeId,
        request_event_id: EventId,
    ) -> Result<Self> {
        let binding = Self {
            schema: AgentSidecarEventExchangeBindingSchema::V1,
            exchange_id,
            role: AgentSidecarExchangeBindingRole::Internal,
            request_event_id: Some(request_event_id),
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: None,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Attach the coordinator completion request to a `user_facing_response`
    /// binding. `coordinator_assignment_event_id` is the request Event id for
    /// the initial assignment or the accepted reassign control Event id.
    pub fn with_completion(mut self, coordinator_assignment_event_id: EventId) -> Result<Self> {
        self.completes_exchange = Some(true);
        self.coordinator_assignment_event_id = Some(coordinator_assignment_event_id);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        match self.role {
            AgentSidecarExchangeBindingRole::Request => {
                if self.request_event_id.is_some() {
                    return Err(WireError::Protocol(
                        "Sidecar request binding must not carry request_event_id".to_owned(),
                    ));
                }
                match &self.request_context {
                    Some(context) => context.validate()?,
                    None => {
                        return Err(WireError::Protocol(
                            "Sidecar request binding requires request_context".to_owned(),
                        ));
                    }
                }
            }
            AgentSidecarExchangeBindingRole::UserFacingResponse
            | AgentSidecarExchangeBindingRole::Internal => {
                if self.request_event_id.is_none() {
                    return Err(WireError::Protocol(
                        "Sidecar response/internal binding requires request_event_id".to_owned(),
                    ));
                }
                if self.request_context.is_some() {
                    return Err(WireError::Protocol(
                        "request_context is forbidden outside role=request".to_owned(),
                    ));
                }
            }
        }
        match self.completes_exchange {
            None => {
                if self.coordinator_assignment_event_id.is_some() {
                    return Err(WireError::Protocol(
                        "coordinator_assignment_event_id requires completes_exchange=true"
                            .to_owned(),
                    ));
                }
            }
            Some(true) => {
                if self.role != AgentSidecarExchangeBindingRole::UserFacingResponse {
                    return Err(WireError::Protocol(
                        "completes_exchange is legal only on role=user_facing_response".to_owned(),
                    ));
                }
                if self.coordinator_assignment_event_id.is_none() {
                    return Err(WireError::Protocol(
                        "completes_exchange=true requires coordinator_assignment_event_id"
                            .to_owned(),
                    ));
                }
            }
            Some(false) => {
                return Err(WireError::Protocol(
                    "completes_exchange only admits the literal true".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarExchangeControlSchema {
    #[serde(rename = "ak.schema.agent_sidecar_exchange_control.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeControlAction {
    Close,
    Cancel,
    Fail,
    ReassignCoordinator,
}

impl AgentSidecarExchangeControlAction {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::ReassignCoordinator)
    }
}

/// Counterpart for `agent-sidecar-exchange-control.schema.json`: the closed
/// plaintext encrypted inside `ak.agent.sidecar.exchange.control`. Only the
/// Sidecar controller may author it; it is the sole source of coordinator
/// reassignment and terminal exchange state (`zh/models/sidecar.md` §8).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControl {
    pub schema: AgentSidecarExchangeControlSchema,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub exchange_id: AgentSidecarExchangeId,
    pub request_event_id: EventId,
    /// Canonical UTF-8 byte-order sorted maximal causal heads observed at
    /// authoring time. The outer Event refs MUST carry `role=after` for every
    /// entry and the request Event must be causally covered.
    pub basis_event_ids: Vec<EventId>,
    pub action: AgentSidecarExchangeControlAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ids: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_agent_id: Option<DidCoreId>,
}

impl AgentSidecarExchangeControl {
    pub fn validate(&self) -> Result<()> {
        validate_unique_sorted_event_ids(&self.basis_event_ids, "control basis_event_ids")?;
        if self.action.is_terminal() {
            let responses = self.response_event_ids.as_ref().ok_or_else(|| {
                WireError::Protocol(
                    "terminal Sidecar exchange control requires response_event_ids".to_owned(),
                )
            })?;
            if responses.iter().collect::<BTreeSet<_>>().len() != responses.len() {
                return Err(WireError::Protocol(
                    "Sidecar control response_event_ids must be unique".to_owned(),
                ));
            }
            if self.expected_coordinator_agent_id.is_some() || self.coordinator_agent_id.is_some() {
                return Err(WireError::Protocol(
                    "coordinator fields are forbidden on terminal Sidecar exchange control"
                        .to_owned(),
                ));
            }
        } else {
            if self.response_event_ids.is_some() {
                return Err(WireError::Protocol(
                    "response_event_ids is forbidden on reassign_coordinator".to_owned(),
                ));
            }
            let (Some(expected), Some(next)) = (
                &self.expected_coordinator_agent_id,
                &self.coordinator_agent_id,
            ) else {
                return Err(WireError::Protocol(
                    "reassign_coordinator requires expected_coordinator_agent_id and coordinator_agent_id"
                        .to_owned(),
                ));
            };
            if expected == next {
                return Err(WireError::Protocol(
                    "reassign_coordinator must change the coordinator".to_owned(),
                ));
            }
        }
        match (&self.failure_reason_code, self.action) {
            (Some(code), AgentSidecarExchangeControlAction::Fail) => {
                validate_sidecar_failure_reason_code(code.as_str())?;
            }
            (None, AgentSidecarExchangeControlAction::Fail) => {
                return Err(WireError::Protocol(
                    "action=fail requires failure_reason_code".to_owned(),
                ));
            }
            (Some(_), _) => {
                return Err(WireError::Protocol(
                    "failure_reason_code is legal only on action=fail".to_owned(),
                ));
            }
            (None, _) => {}
        }
        Ok(())
    }

    /// Sidecar exchange terminal mapping. Returns `None` for `reassign_coordinator`.
    /// A delivered response set is never a failure: any terminal action with
    /// responses folds to `complete`; empty-response terminals fold to
    /// `failed` with the action-derived failure code.
    pub fn terminal_result(&self) -> Result<Option<AgentSidecarExchangeTerminalOutcome>> {
        self.validate()?;
        if !self.action.is_terminal() {
            return Ok(None);
        }
        let responses = self.response_event_ids.clone().unwrap_or_default();
        Ok(Some(if responses.is_empty() {
            let failure_reason_code = match self.action {
                AgentSidecarExchangeControlAction::Close => {
                    AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CLOSED_EMPTY.to_owned()
                }
                AgentSidecarExchangeControlAction::Cancel => {
                    AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CANCELLED.to_owned()
                }
                AgentSidecarExchangeControlAction::Fail => self
                    .failure_reason_code
                    .as_ref()
                    .expect("validated above")
                    .as_str()
                    .to_owned(),
                AgentSidecarExchangeControlAction::ReassignCoordinator => unreachable!(),
            };
            AgentSidecarExchangeTerminalOutcome {
                status: AgentSidecarExchangeStatus::Failed,
                failure_reason_code: Some(failure_reason_code),
                response_event_ids: Vec::new(),
            }
        } else {
            AgentSidecarExchangeTerminalOutcome {
                status: AgentSidecarExchangeStatus::Complete,
                failure_reason_code: None,
                response_event_ids: responses,
            }
        }))
    }
}

/// Result of folding one terminal control Event: `complete` always carries at
/// least one response, `failed` never carries any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarExchangeTerminalOutcome {
    pub status: AgentSidecarExchangeStatus,
    pub failure_reason_code: Option<String>,
    pub response_event_ids: Vec<EventId>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/
/// $defs/agent_sidecar_exchange_control_payload` — the outer payload of
/// `ak.agent.sidecar.exchange.control`. The service only sees native Sidecar
/// routing plus ciphertext; admission MUST require the effective scope to be
/// the matching Sidecar and the actor to be its controller.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControlPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: crate::sidecar_operations::SidecarContextRef,
    pub encrypted_payload: EncryptedEnvelope,
}

/// Compute `event_set_digest = sha256(canonical_json(sorted unique ids))`
/// over the complete contributing Event-id set (`zh/models/sidecar.md`
/// §8).
pub fn agent_sidecar_exchange_event_set_digest(event_ids: &[EventId]) -> Result<Hash> {
    let mut ids: Vec<&str> = event_ids.iter().map(EventId::as_str).collect();
    ids.sort_unstable();
    ids.dedup();
    Hash::new(canonical::canonical_sha256(&ids)?).map_err(WireError::from)
}

/// Local cache coverage of one folded exchange: canonical sorted maximal
/// causal heads plus the digest committing to the complete contributing
/// Event-id set. `max_hlc` is display/cache metadata only and never proves
/// causal dominance.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeFoldedFrontier {
    pub event_ids: Vec<EventId>,
    pub event_set_digest: Hash,
    pub max_hlc: Hlc,
}

impl AgentSidecarExchangeFoldedFrontier {
    pub fn validate(&self) -> Result<()> {
        validate_unique_sorted_event_ids(&self.event_ids, "folded frontier event_ids")
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSidecarExchangeProjectionSchema {
    #[serde(rename = "ak.schema.agent_sidecar_exchange_projection.v1")]
    V1,
}

/// Counterpart for `agent-sidecar-exchange-projection.schema.json`: a
/// disposable controller-device-local Event-fold cache for one source-routed
/// exchange. It is not wire truth, is not Account Data, is never uploaded,
/// merged across devices, or streamed to Agent runtimes, and may always be
/// deleted and rebuilt from accepted native Sidecar Event history.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeProjection {
    pub schema: AgentSidecarExchangeProjectionSchema,
    pub controller_id: DidCoreId,
    pub sidecar_id: SidecarId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub exchange_id: AgentSidecarExchangeId,
    pub origin: AgentSidecarExchangeOrigin,
    pub source_track_ref: AgentSidecarSourceTrackRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<EventId>,
    pub source_hlc: Hlc,
    pub client_order_key: NonEmptyString,
    pub addressed_agent_ids: Vec<DidCoreId>,
    pub completion_policy: AgentSidecarExchangeCompletionPolicy,
    pub coordinator_agent_id: DidCoreId,
    /// Request Event id for the initial assignment, or the accepted
    /// `reassign_coordinator` control Event id after reassignment.
    pub coordinator_assignment_event_id: EventId,
    /// Bookkeeping union of exchange-bound Agent actors; it never grants echo
    /// eligibility.
    pub participating_agent_ids: Vec<DidCoreId>,
    pub private_request_event_id: EventId,
    /// Validated user-facing response Event ids in `(response HLC, Event id)`
    /// byte order. Appended only through the controller-device validation of
    /// `zh/models/sidecar.md` §8 — never inferred from reply_to, arrival
    /// order, actor kind, or content shape.
    pub user_facing_response_event_ids: Vec<EventId>,
    pub status: AgentSidecarExchangeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<NonEmptyString>,
    /// Controller-authored control Event that produced `complete`/`failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_event_id: Option<EventId>,
    pub folded_frontier: AgentSidecarExchangeFoldedFrontier,
}

impl AgentSidecarExchangeProjection {
    pub fn validate(&self) -> Result<()> {
        self.source_track_ref.validate()?;
        validate_sidecar_order_key(self.client_order_key.as_str(), "client order key")?;
        if self.origin != AgentSidecarExchangeOrigin::SourceTrackRouted {
            return Err(WireError::Protocol(
                "sidecar-native Events must not create source echo projections".to_owned(),
            ));
        }
        if self.addressed_agent_ids.is_empty()
            || self
                .addressed_agent_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.addressed_agent_ids.len()
        {
            return Err(WireError::Protocol(
                "Sidecar exchange addressed_agent_ids must be non-empty and unique".to_owned(),
            ));
        }
        if !self
            .addressed_agent_ids
            .contains(&self.coordinator_agent_id)
        {
            return Err(WireError::Protocol(
                "Sidecar exchange coordinator must be one of addressed_agent_ids".to_owned(),
            ));
        }
        if self
            .participating_agent_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.participating_agent_ids.len()
        {
            return Err(WireError::Protocol(
                "Sidecar Agent id arrays must be unique".to_owned(),
            ));
        }
        if self
            .user_facing_response_event_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.user_facing_response_event_ids.len()
        {
            return Err(WireError::Protocol(
                "Sidecar response Event ids must be unique".to_owned(),
            ));
        }
        if let Some(failure_reason_code) = &self.failure_reason_code {
            validate_sidecar_failure_reason_code(failure_reason_code.as_str())?;
        }
        match self.status {
            AgentSidecarExchangeStatus::Delivered => {
                if !self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_some()
                {
                    return Err(WireError::Protocol(
                        "delivered Sidecar exchange must carry no responses, failure code, or terminal Event"
                            .to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Responding => {
                if self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_some()
                {
                    return Err(WireError::Protocol(
                        "responding Sidecar exchange requires responses and no terminal fields"
                            .to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Complete => {
                if self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_none()
                {
                    return Err(WireError::Protocol(
                        "complete Sidecar exchange requires responses, a terminal Event, and no failure code"
                            .to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Failed => {
                if !self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_none()
                    || self.terminal_event_id.is_none()
                {
                    return Err(WireError::Protocol(
                        "failed Sidecar exchange requires failure_reason_code and terminal Event and no responses"
                            .to_owned(),
                    ));
                }
            }
        }
        self.folded_frontier.validate()
    }
}

#[derive(Serialize)]
struct AgentRequestedScopeCommitment<'a> {
    agent_id: &'a str,
    controller_id: &'a str,
    kind: &'static str,
    requested_scope: &'a AgentKeyScope,
}

/// Compute the immutable provision ceiling commitment fixed in the accepted
/// Agent DID `ArkretPrincipalControlRealm` service entry.
pub fn agent_requested_scope_digest(
    agent_id: &DidCoreId,
    controller_id: &DidCoreId,
    requested_scope: &AgentKeyScope,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentRequestedScopeCommitment {
            agent_id: agent_id.as_str(),
            controller_id: controller_id.as_str(),
            kind: "ak.agent.requested_scope_commitment.v1",
            requested_scope,
        },
    )?)
    .map_err(WireError::from)
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/key_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct KeyState {
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    /// Immutable global Agent ceiling captured by provisioning.
    pub requested_scope: AgentKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    /// Branch of the current unconsumed, unexpired pairing handle. Present
    /// exactly when `pairing_request_id` and `pairing_expires_at` are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_mode: Option<AgentPairingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub pairing_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_runtime_key_request: Option<AgentRuntimeApprovalControllerProjection>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub approval_requested_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_authorizations: Vec<AgentKeyAuthorizationState>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Timelike};

    use super::*;

    const DETACH_GRANT_ID: &str = "ak:grant:AU4F2tD66XxDdxMbkmhDwjv3NLmV3MuNzo4ZaaUG__we";
    const OTHER_GRANT_ID: &str = "ak:grant:AU1_A5a8MMz_OdxEleQlWPFn-ljdJteaJv3ZZ9APkcrZ";

    fn agent_grant_detach_request() -> AgentGrantDetachRequestBody {
        let realm_id =
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let cell = CellRef::new(format!(
            "ak:cell:ak.component.capability.grant.v1:{DETACH_GRANT_ID}"
        ))
        .unwrap();
        let event = Event {
            event_id: EventId::new("ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6")
                .unwrap(),
            kind: EventKind::CapabilityRevoke,
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturecontroller").unwrap(),
            principal_server_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturecontroller").unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: 7,
            created_at: "2026-08-11T00:00:00.000Z".parse().unwrap(),
            hlc: None,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: vec![Precondition {
                cell,
                predicate: Predicate {
                    op: PredicateOp::HeadEq,
                    value: Some(serde_json::json!([{
                        "dot": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6:0",
                        "value": {
                            "grant_id": DETACH_GRANT_ID,
                            "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                            "subject": "ak:did_core:webvh:z6mkfixtureagent"
                        }
                    }])),
                    values: None,
                    predicate_id: None,
                },
            }],
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            payload: BTreeMap::from([("grant_id".to_owned(), serde_json::json!(DETACH_GRANT_ID))]),
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        };
        AgentGrantDetachRequestBody {
            revoke_event: EventInitialSubmission::online(event),
        }
    }

    #[test]
    fn agent_grant_detach_accepts_exact_revoke_cell_guard() {
        agent_grant_detach_request()
            .validate(arkret_canonical::DigestSuite::Sha256)
            .expect("exact signed revoke contract");
    }

    #[test]
    fn agent_grant_detach_rejects_wrong_kind_guard_count_cell_head_and_grant_ref() {
        let mut wrong_kind = agent_grant_detach_request();
        wrong_kind.revoke_event.event.kind = EventKind::MessageCreate;
        assert!(
            wrong_kind
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let mut no_guard = agent_grant_detach_request();
        no_guard.revoke_event.event.preconditions.clear();
        assert!(
            no_guard
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let mut two_guards = agent_grant_detach_request();
        let second_guard = two_guards.revoke_event.event.preconditions[0].clone();
        two_guards
            .revoke_event
            .event
            .preconditions
            .push(second_guard);
        assert!(
            two_guards
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let mut wrong_cell = agent_grant_detach_request();
        wrong_cell.revoke_event.event.preconditions[0].cell = CellRef::new(format!(
            "ak:cell:ak.component.capability.grant.v1:{OTHER_GRANT_ID}"
        ))
        .unwrap();
        assert!(
            wrong_cell
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let mut empty_head = agent_grant_detach_request();
        empty_head.revoke_event.event.preconditions[0]
            .predicate
            .value = Some(serde_json::json!([]));
        assert!(
            empty_head
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let mut mismatched_ref = agent_grant_detach_request();
        mismatched_ref
            .revoke_event
            .event
            .payload
            .insert("grant_ref".to_owned(), serde_json::json!(OTHER_GRANT_ID));
        assert!(
            mismatched_ref
                .validate(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn agent_provision_outcome_serializes_allocated_did() {
        let outcome = AgentProvisionOutcome::AwaitingControllerEvent {
            agent_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent").unwrap(),
            did: Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap(),
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                did: Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap(),
                method_history_head: format!("sha256:{}", "8b".repeat(32)),
                version_id: format!("1-Qm{}", "a".repeat(44)),
            },
            controller_realm_id: RealmId::new(
                "ak:realm:AUf0Zz23_ZBqZYNvzHTY6qhhx-2YyO94WTorNCFnnvvN",
            )
            .unwrap(),
            allocation_handle: ProtocolOpaqueId::new("allocation.fixture.signature").unwrap(),
            controller_authorization_ref: DidUrl::new(
                "did:webvh:z6mkfixtureagent:agent.example#managed-controller",
            )
            .unwrap(),
            requested_scope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };

        let value = serde_json::to_value(outcome).unwrap();
        assert_eq!(value["status"], "awaiting_controller_event");
        assert_eq!(value["did"], "did:webvh:z6mkfixtureagent:agent.example");
    }

    #[test]
    fn agent_provision_prepare_uses_the_spec_controller_server_coordinate() {
        let request = AgentProvisionRequestBody::Prepare {
            operation_id: ProtocolOperationId::new("ak:operation:agent-provision-wire").unwrap(),
            idempotency_key: IdempotencyKey::new("agent-provision-wire").unwrap(),
            did: Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap(),
            controller_principal_server_id: DidCoreId::new("ak:did_core:web:principal.example")
                .unwrap(),
            slug: "summary".to_owned(),
            requested_scope: AgentKeyScope {
                actions: Vec::new(),
                resources: Vec::new(),
                constraints: Vec::new(),
            },
            pairing_ttl_ms: None,
        };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value["controller_principal_server_id"],
            "ak:did_core:web:principal.example"
        );
        assert!(value.get("controller_authority").is_none());

        let mut stale = value;
        stale
            .as_object_mut()
            .unwrap()
            .remove("controller_principal_server_id");
        stale["controller_authority"] = serde_json::json!({
            "principal_id": "ak:did_core:web:alice.example",
            "principal_server_id": "ak:did_core:web:principal.example"
        });
        assert!(serde_json::from_value::<AgentProvisionRequestBody>(stale).is_err());
    }

    #[test]
    fn key_state_uses_stable_core_actor_ids() {
        let value = serde_json::json!({
            "agent_id": "ak:did_core:webvh:z6mkagent",
            "controller_id": "ak:did_core:webvh:z6mkcontroller",
            "principal_control_realm_id": "ak:realm:AUf0Zz23_ZBqZYNvzHTY6qhhx-2YyO94WTorNCFnnvvN",
            "controller_authorization_ref": "did:webvh:z6mkcontroller:controller.example#authorize-1",
            "requested_scope": {"actions": [], "resources": []},
            "active_authorizations": []
        });
        let parsed: KeyState = serde_json::from_value(value.clone()).expect("core ids parse");
        assert_eq!(parsed.agent_id.as_str(), "ak:did_core:webvh:z6mkagent");
        assert_eq!(
            parsed.controller_id.as_str(),
            "ak:did_core:webvh:z6mkcontroller"
        );

        let mut stale_did = value;
        stale_did["agent_id"] = serde_json::json!("did:webvh:z6mkagent:agent.example");
        assert!(serde_json::from_value::<KeyState>(stale_did).is_err());
    }

    fn runtime_approval_request(runtime_attestation: Value) -> Value {
        serde_json::json!({
            "pairing_code": "12345678",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
            "agent_id": "ak:did_core:webvh:z6mkfixture",
            "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
            "public_key": {
                "kty": "OKP",
                "kid": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
                "algorithm": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "proof_of_possession": {
                "kind": "agent_runtime_key_possession",
                "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
                "signature_algorithm": "Ed25519",
                "challenge": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
                "audience": "ak:did_core:webvh:z6mkfixture",
                "created_at": "2026-07-20T00:00:00.000Z",
                "expires_at": "2026-07-20T00:05:00.000Z",
                "runtime_key_binding_digest": format!("sha256:{}", "1".repeat(64)),
                "transcript_digest": format!("sha256:{}", "2".repeat(64)),
                "signature": arkret_canonical::base64url_encode([3_u8; 64])
            },
            "runtime_attestation": runtime_attestation
        })
    }

    fn requested_scope_disclosure_wire() -> Value {
        serde_json::json!({
            "schema": "ak.schema.agent_requested_scope_disclosure.v1",
            "request_id": "ak:request:01970000-0000-7000-8000-000000000021",
            "agent_id": "ak:did_core:webvh:z6mkfixture",
            "controller_id": "ak:did_core:webvh:z6mkfixture",
            "requested_scope": {
                "actions": ["ak.message.create"],
                "resources": []
            },
            "verifier_id": "ak:did_core:webvh:z6mkfixture",
            "audience": "ak.gate.account.command.pair_agent_key.v1",
            "challenge": "0123456789abcdef",
            "issued_at": "2026-08-03T00:00:00.000Z",
            "expires_at": "2026-08-03T00:05:00.000Z",
            "proofs": []
        })
    }

    #[test]
    fn requested_scope_disclosure_is_closed() {
        let valid = requested_scope_disclosure_wire();
        serde_json::from_value::<AgentRequestedScopeDisclosure>(valid.clone()).unwrap();

        let mut unknown = valid;
        unknown["participation_ceiling"] = serde_json::json!({"reply_message": true});
        assert!(serde_json::from_value::<AgentRequestedScopeDisclosure>(unknown).is_err());
    }

    #[test]
    fn runtime_attestation_is_closed_to_the_v1_self_asserted_shape() {
        let accepted: AgentRuntimeApprovalRequestBody =
            serde_json::from_value(runtime_approval_request(serde_json::json!({
                "kind": "self_asserted",
                "software": "arkret-agent"
            })))
            .expect("registered self_asserted attestation accepts");
        assert!(accepted.runtime_attestation.is_some());

        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "tee" })
            ))
            .is_err(),
            "unknown attestation kinds must fail closed"
        );
        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "self_asserted", "unregistered": true })
            ))
            .is_err(),
            "unregistered attestation fields must fail closed"
        );
    }

    #[test]
    fn sidecar_participant_authority_digest_is_stable() {
        let agent = DidCoreId::new("ak:did_core:webvh:z6mkfixtureassistant").unwrap();
        let digest = agent_sidecar_participant_authority_digest(
            SidecarId::new("ak:sidecar:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr").unwrap(),
            RealmId::new("ak:realm:AbXK2aG2XS8Rx4qSoMG86HcFoZFxVGzkCdy-43-p20aY").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            std::slice::from_ref(&agent),
        )
        .unwrap();
        assert_eq!(
            digest.as_str(),
            "sha256:3f24bade45fa7360336368ad15bff69e5279070c12448440451007e3fd14c78f"
        );
    }

    #[test]
    fn sidecar_participant_authority_rejects_controller_in_agent_set() {
        let controller = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap();
        let controller_as_agent = controller.clone();
        assert!(
            agent_sidecar_participant_authority_digest(
                SidecarId::new("ak:sidecar:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr").unwrap(),
                RealmId::new("ak:realm:AbXK2aG2XS8Rx4qSoMG86HcFoZFxVGzkCdy-43-p20aY").unwrap(),
                controller,
                &[controller_as_agent],
            )
            .is_err()
        );
    }

    #[test]
    fn sidecar_remove_reconciliation_requires_only_a_canonical_frontier() {
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixtureassistant").unwrap();
        let event_a =
            EventId::new("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap();
        let event_b =
            EventId::new("ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N").unwrap();
        let mut membership_frontier = vec![event_a, event_b];
        membership_frontier.sort();
        let valid = PendingSidecarAccessReconciliationItem {
            agent_id,
            provisioning_phase: PendingSidecarAccessReconciliationStage::MlsRemove,
            membership_frontier: Some(membership_frontier.clone()),
        };
        valid.validate().unwrap();
        let mut with_legacy_reason = serde_json::to_value(&valid).unwrap();
        with_legacy_reason["reason"] = serde_json::json!("mls_remove_obligation_pending");
        assert!(
            serde_json::from_value::<PendingSidecarAccessReconciliationItem>(with_legacy_reason)
                .is_err()
        );

        let mut missing = valid.clone();
        missing.membership_frontier = None;
        assert!(missing.validate().is_err());

        let mut unsorted = valid.clone();
        membership_frontier.reverse();
        unsorted.membership_frontier = Some(membership_frontier);
        assert!(unsorted.validate().is_err());

        let mut wrong_stage = valid;
        wrong_stage.provisioning_phase = PendingSidecarAccessReconciliationStage::MlsWelcome;
        assert!(wrong_stage.validate().is_err());
    }

    #[test]
    fn sidecar_timestamps_are_canonical_at_the_wire_boundary() {
        let timestamp = Utc
            .with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
            .unwrap()
            .with_nanosecond(987_654_321)
            .unwrap();
        let sidecar = AgentSidecar {
            id: SidecarId::new("ak:sidecar:AUJCoQiXEV11T2wYGgq5vjXcfFcLnKQHPCp3GyzHYTDe").unwrap(),
            schema: AgentSidecarSchema::V1,
            realm_id: RealmId::new("ak:realm:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr")
                .unwrap(),
            controller_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
            state: AgentSidecarState::Active,
            state_changed_at: Some(timestamp),
            created_at: timestamp,
            updated_at: Some(timestamp),
        };

        let value = serde_json::to_value(&sidecar).unwrap();
        for field in ["state_changed_at", "created_at", "updated_at"] {
            assert_eq!(value[field], "2026-07-20T12:34:56.987Z", "{field}");
            canonical::validate_timestamp_canonical(value[field].as_str().unwrap()).unwrap();
        }

        let mut non_canonical = value;
        non_canonical["created_at"] = serde_json::json!("2026-07-20T12:34:56.987654Z");
        assert!(serde_json::from_value::<AgentSidecar>(non_canonical).is_err());
    }

    fn fixture_event_id(suffix: u32) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.to_be_bytes())).unwrap(),
        )
        .unwrap()
    }

    fn fixture_agent() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureassistant").unwrap()
    }

    fn fixture_request_context() -> AgentSidecarExchangeRequestContext {
        AgentSidecarExchangeRequestContext {
            source_track_ref: AgentSidecarSourceTrackRef {
                realm_id: RealmId::new("ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy")
                    .unwrap(),
                strand_id: StrandId::new("ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")
                    .unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![fixture_agent()],
            completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: None,
            source_event_id: None,
        }
    }

    fn fixture_exchange_projection() -> AgentSidecarExchangeProjection {
        AgentSidecarExchangeProjection {
            schema: AgentSidecarExchangeProjectionSchema::V1,
            controller_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            sidecar_id: SidecarId::new("ak:sidecar:ATxk9k3t-DqTNiiB9n8GoSjjar3vZJvO3Dtpd1SzdHZF")
                .unwrap(),
            exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap(),
            origin: AgentSidecarExchangeOrigin::SourceTrackRouted,
            source_track_ref: AgentSidecarSourceTrackRef {
                realm_id: RealmId::new("ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy")
                    .unwrap(),
                strand_id: StrandId::new("ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")
                    .unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_event_id: None,
            source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![fixture_agent()],
            completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: fixture_agent(),
            coordinator_assignment_event_id: fixture_event_id(0x34),
            participating_agent_ids: vec![],
            private_request_event_id: fixture_event_id(0x34),
            user_facing_response_event_ids: vec![],
            status: AgentSidecarExchangeStatus::Delivered,
            failure_reason_code: None,
            terminal_event_id: None,
            folded_frontier: AgentSidecarExchangeFoldedFrontier {
                event_ids: vec![fixture_event_id(0x34)],
                event_set_digest: agent_sidecar_exchange_event_set_digest(&[fixture_event_id(
                    0x34,
                )])
                .unwrap(),
                max_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            },
        }
    }

    #[test]
    fn sidecar_exchange_projection_is_a_local_fold_cache_and_fail_closed() {
        let projection = fixture_exchange_projection();
        projection.validate().unwrap();

        let mut native = projection.clone();
        native.origin = AgentSidecarExchangeOrigin::SidecarNative;
        assert!(native.validate().is_err());

        let mut pending = serde_json::to_value(&projection).unwrap();
        pending["status"] = serde_json::json!("pending");
        assert!(
            serde_json::from_value::<AgentSidecarExchangeProjection>(pending).is_err(),
            "pending is client-local UI intent and never enters the projection"
        );

        let mut foreign_coordinator = projection.clone();
        foreign_coordinator.coordinator_agent_id =
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureother").unwrap();
        assert!(foreign_coordinator.validate().is_err());

        let mut complete_without_terminal = projection.clone();
        complete_without_terminal.status = AgentSidecarExchangeStatus::Complete;
        complete_without_terminal.user_facing_response_event_ids = vec![fixture_event_id(0x35)];
        assert!(complete_without_terminal.validate().is_err());

        let mut failed_with_response = projection.clone();
        failed_with_response.status = AgentSidecarExchangeStatus::Failed;
        failed_with_response.failure_reason_code =
            Some(NonEmptyString::new("agent_deactivated").unwrap());
        failed_with_response.terminal_event_id = Some(fixture_event_id(0x36));
        failed_with_response.user_facing_response_event_ids = vec![fixture_event_id(0x35)];
        assert!(
            failed_with_response.validate().is_err(),
            "failed never carries responses; delivered responses fold to complete"
        );

        let mut unknown = serde_json::to_value(&projection).unwrap();
        unknown["private_circle_id"] =
            serde_json::json!("ak:circle:ARIqxK3jWXYxpb544UphWaZm_ti9wclu9_0-eSuyZ2e_");
        assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(unknown).is_err());

        let mut account_data_key = serde_json::to_value(&projection).unwrap();
        account_data_key["account_data_key"] = serde_json::json!(
            "ak.agent.sidecar_projection.v1:did:webvh:z6mkfixture:example.com:users:alice"
        );
        assert!(
            serde_json::from_value::<AgentSidecarExchangeProjection>(account_data_key).is_err(),
            "the exchange projection is not Account Data and registers no key surface"
        );
    }

    #[test]
    fn sidecar_exchange_binding_roles_are_closed_producer_contracts() {
        let exchange_id = AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap();
        let request = AgentSidecarEventExchangeBinding::request(
            exchange_id.clone(),
            fixture_request_context(),
        )
        .unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value["schema"],
            "ak.schema.agent_sidecar_event_exchange_binding.v1"
        );
        assert_eq!(value["role"], "request");
        assert!(value.get("request_event_id").is_none());

        let mut smuggled_request_event = request;
        smuggled_request_event.request_event_id = Some(fixture_event_id(0x34));
        assert!(smuggled_request_event.validate().is_err());

        let response = AgentSidecarEventExchangeBinding::user_facing_response(
            exchange_id.clone(),
            fixture_event_id(0x34),
        )
        .unwrap();
        assert!(response.completes_exchange.is_none());
        let completing = response
            .clone()
            .with_completion(fixture_event_id(0x34))
            .unwrap();
        assert_eq!(completing.completes_exchange, Some(true));

        let mut orphan_completion = response.clone();
        orphan_completion.completes_exchange = Some(true);
        assert!(
            orphan_completion.validate().is_err(),
            "completes_exchange requires coordinator_assignment_event_id"
        );
        let mut false_completion = response;
        false_completion.completes_exchange = Some(false);
        assert!(false_completion.validate().is_err());

        let internal =
            AgentSidecarEventExchangeBinding::internal(exchange_id.clone(), fixture_event_id(0x34))
                .unwrap();
        let mut internal_completing = internal.clone();
        internal_completing.completes_exchange = Some(true);
        internal_completing.coordinator_assignment_event_id = Some(fixture_event_id(0x34));
        assert!(
            internal_completing.validate().is_err(),
            "only user_facing_response may request completion"
        );
        let mut internal_with_context = internal;
        internal_with_context.request_context = Some(fixture_request_context());
        assert!(internal_with_context.validate().is_err());

        let mut multi = fixture_request_context();
        multi.addressed_agent_ids = vec![
            fixture_agent(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturereviewer").unwrap(),
        ];
        assert!(
            AgentSidecarEventExchangeBinding::request(exchange_id.clone(), multi.clone()).is_err(),
            "multi-agent requests must pick an explicit coordinator"
        );
        multi.coordinator_agent_id = Some(fixture_agent());
        AgentSidecarEventExchangeBinding::request(exchange_id, multi).unwrap();

        let unknown_role = serde_json::json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": "Abcdefghijklmnopqrstuv",
            "role": "coordinator_summary"
        });
        assert!(
            serde_json::from_value::<AgentSidecarEventExchangeBinding>(unknown_role).is_err(),
            "unknown roles fail closed to non-echo"
        );
    }

    #[test]
    fn sidecar_exchange_control_terminal_mapping_matches_spec() {
        let mut basis_event_ids = vec![fixture_event_id(0x34), fixture_event_id(0x35)];
        basis_event_ids.sort();
        let base = AgentSidecarExchangeControl {
            schema: AgentSidecarExchangeControlSchema::V1,
            exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap(),
            request_event_id: fixture_event_id(0x34),
            basis_event_ids,
            action: AgentSidecarExchangeControlAction::Cancel,
            response_event_ids: Some(vec![fixture_event_id(0x35)]),
            failure_reason_code: None,
            expected_coordinator_agent_id: None,
            coordinator_agent_id: None,
        };
        let outcome = base.terminal_result().unwrap().unwrap();
        assert_eq!(outcome.status, AgentSidecarExchangeStatus::Complete);
        assert!(
            outcome.failure_reason_code.is_none(),
            "cancel with delivered responses folds to complete, not failed"
        );

        let mut empty_close = base.clone();
        empty_close.action = AgentSidecarExchangeControlAction::Close;
        empty_close.response_event_ids = Some(vec![]);
        let outcome = empty_close.terminal_result().unwrap().unwrap();
        assert_eq!(outcome.status, AgentSidecarExchangeStatus::Failed);
        assert_eq!(
            outcome.failure_reason_code.as_deref(),
            Some(AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CLOSED_EMPTY)
        );

        let mut empty_cancel = base.clone();
        empty_cancel.response_event_ids = Some(vec![]);
        let outcome = empty_cancel.terminal_result().unwrap().unwrap();
        assert_eq!(
            outcome.failure_reason_code.as_deref(),
            Some(AGENT_SIDECAR_EXCHANGE_FAILURE_CONTROLLER_CANCELLED)
        );

        let mut fail = base.clone();
        fail.action = AgentSidecarExchangeControlAction::Fail;
        fail.response_event_ids = Some(vec![]);
        assert!(
            fail.validate().is_err(),
            "fail requires failure_reason_code"
        );
        fail.failure_reason_code = Some(NonEmptyString::new("agent_deactivated").unwrap());
        let outcome = fail.terminal_result().unwrap().unwrap();
        assert_eq!(
            outcome.failure_reason_code.as_deref(),
            Some("agent_deactivated")
        );

        let mut reassign = base.clone();
        reassign.action = AgentSidecarExchangeControlAction::ReassignCoordinator;
        reassign.response_event_ids = None;
        reassign.expected_coordinator_agent_id = Some(fixture_agent());
        reassign.coordinator_agent_id =
            Some(DidCoreId::new("ak:did_core:webvh:z6mkfixturereviewer").unwrap());
        assert!(reassign.terminal_result().unwrap().is_none());
        let mut identity_reassign = reassign;
        identity_reassign.coordinator_agent_id = Some(fixture_agent());
        assert!(identity_reassign.validate().is_err());

        let mut terminal_with_coordinator = base.clone();
        terminal_with_coordinator.expected_coordinator_agent_id = Some(fixture_agent());
        assert!(terminal_with_coordinator.validate().is_err());

        let mut unsorted_basis = base;
        unsorted_basis.basis_event_ids.reverse();
        assert!(unsorted_basis.validate().is_err());
    }

    #[test]
    fn sidecar_exchange_event_set_digest_is_order_insensitive_and_stable() {
        let forward = agent_sidecar_exchange_event_set_digest(&[
            fixture_event_id(0x34),
            fixture_event_id(0x35),
        ])
        .unwrap();
        let reversed = agent_sidecar_exchange_event_set_digest(&[
            fixture_event_id(0x35),
            fixture_event_id(0x34),
            fixture_event_id(0x34),
        ])
        .unwrap();
        assert_eq!(forward, reversed);

        let mut unsorted_event_ids = vec![fixture_event_id(0x34), fixture_event_id(0x35)];
        unsorted_event_ids.sort();
        unsorted_event_ids.reverse();
        let frontier = AgentSidecarExchangeFoldedFrontier {
            event_ids: unsorted_event_ids,
            event_set_digest: forward,
            max_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        };
        assert!(
            frontier.validate().is_err(),
            "frontier heads must be canonically sorted"
        );
    }

    #[test]
    fn requested_scope_commitment_is_domain_separated_and_stable() {
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkagent").unwrap();
        let controller_id = DidCoreId::new("ak:did_core:webvh:z6mkcontroller").unwrap();
        let requested_scope: AgentKeyScope = serde_json::from_value(serde_json::json!({
            "actions": [
                "ak.event.read",
                "ak.self.events.stream.subscribe.v1"
            ],
            "resources": [
                {
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe.v1"
                }
            ]
        }))
        .unwrap();
        let digest =
            agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope).unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:c9aeb7698bf2ba946fd9b83e60eb6e792d29fa48a7a78922016aca0a9e747bec"
        );
        assert_eq!(
            digest,
            agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope,).unwrap()
        );

        let mut narrower_scope = requested_scope;
        narrower_scope.actions.pop();
        let tightened =
            agent_requested_scope_digest(&agent_id, &controller_id, &narrower_scope).unwrap();
        assert_ne!(digest, tightened);
    }
}
