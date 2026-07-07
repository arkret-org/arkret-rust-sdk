//! Agent runtime and protocol interop helpers.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyAuthorizePayload,
    AgentKeyPairRequestBody, AgentPairingBootstrap, AgentPauseRequestBody,
    AgentProvisionRequestBody, AgentResumeRequestBody, AgentRotateKeyRequestBody,
    AgentRuntimeApprovalRequestBody, AgentSidecarThreadEnsureRequestBody, CapabilityGrant, Did,
    Error, Event, GrantId, Hash, Hlc, OP_ACCOUNT_AGENT_KEY_PAIR, OP_AGENT_DEACTIVATE, OP_AGENT_GET,
    OP_AGENT_GRANT_ATTACH, OP_AGENT_GRANT_DETACH, OP_AGENT_KEY_AUTHORIZE, OP_AGENT_LIST,
    OP_AGENT_PAUSE, OP_AGENT_PROVISION, OP_AGENT_RESUME, OP_AGENT_ROTATE_KEY,
    OP_AGENT_SIDECAR_THREAD_ENSURE, OP_OPEN_AGENT_PAIRING_SUBMIT_RUNTIME_KEY_REQUEST, PublicKey,
    RealmId, Result, SessionGrantDpopBindingProof, SessionGrantProofKind, SessionGrantRequestBody,
    SessionGrantRequestProof,
};

pub const AGENT_KEY_PROOF_KIND: &str = "agent_key_proof";

/// Agent principal profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: Did,
    pub controller: Did,
    pub display_name: String,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

impl AgentPrincipal {
    /// Create a principal controlled by a DID.
    pub fn new(agent_id: Did, controller: Did, display_name: impl Into<String>) -> Self {
        Self {
            agent_id,
            controller,
            display_name: display_name.into(),
            capabilities: BTreeSet::new(),
            metadata: Value::Null,
            created_at: Utc::now(),
        }
    }
}

/// HTTP method used by a Cokret personal-agent operation plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentHttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl AgentHttpMethod {
    /// Return the wire method token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// A transport-neutral plan for one standard `/_cokret/...` personal-agent
/// HTTP operation.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRequestPlan<B> {
    pub operation_id: &'static str,
    pub method: AgentHttpMethod,
    pub path: String,
    pub body: Option<B>,
}

/// Builder for `ck.gate.account.command.pair_agent_key` request bodies.
#[derive(Clone, Debug)]
pub struct AgentKeyPairRequestBuilder {
    pairing_request_id: String,
    agent_principal_id: Did,
    verification_method: String,
    public_key: Value,
    proof_of_possession: Value,
    runtime_attestation: Option<Value>,
    authorize_event: Value,
}

impl AgentKeyPairRequestBuilder {
    pub fn new(
        pairing_request_id: impl Into<String>,
        agent_principal_id: Did,
        verification_method: impl Into<String>,
        public_key: Value,
        proof_of_possession: Value,
        authorize_event: Value,
    ) -> Self {
        Self {
            pairing_request_id: pairing_request_id.into(),
            agent_principal_id,
            verification_method: verification_method.into(),
            public_key,
            proof_of_possession,
            runtime_attestation: None,
            authorize_event,
        }
    }

    pub fn runtime_attestation(mut self, runtime_attestation: Value) -> Self {
        self.runtime_attestation = Some(runtime_attestation);
        self
    }

    pub fn build(self) -> Result<AgentKeyPairRequestBody> {
        if self.pairing_request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "agent key pairing_request_id must not be empty".to_owned(),
            ));
        }
        if self.verification_method.trim().is_empty() {
            return Err(Error::Protocol(
                "agent key verification_method must not be empty".to_owned(),
            ));
        }
        if !self.authorize_event.is_object() {
            return Err(Error::Protocol(
                "agent key authorize_event must be a signed event object".to_owned(),
            ));
        }
        Ok(AgentKeyPairRequestBody {
            pairing_request_id: self.pairing_request_id,
            agent_principal_id: self.agent_principal_id,
            verification_method: self.verification_method,
            public_key: self.public_key,
            proof_of_possession: self.proof_of_possession,
            runtime_attestation: self.runtime_attestation,
            authorize_event: self.authorize_event,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyProofSigningInput {
    pub audience: String,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub request_canonical_digest: Hash,
    pub verification_method: String,
}

/// Canonical transcript signed by the agent runtime when presenting a
/// proof-of-possession for `ck.gate.account.command.pair_agent_key`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyPairProofSigningInput {
    pub audience: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
    pub request_canonical_digest: Hash,
    pub verification_method: String,
}

impl AgentKeyProofSigningInput {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        cokret_core::canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Ok(Hash::new(cokret_core::canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

impl AgentKeyPairProofSigningInput {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        cokret_core::canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Ok(Hash::new(cokret_core::canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

impl<B> AgentRequestPlan<B> {
    fn with_body(
        operation_id: &'static str,
        method: AgentHttpMethod,
        path: impl Into<String>,
        body: B,
    ) -> Self {
        Self {
            operation_id,
            method,
            path: path.into(),
            body: Some(body),
        }
    }

    fn without_body(
        operation_id: &'static str,
        method: AgentHttpMethod,
        path: impl Into<String>,
    ) -> Self {
        Self {
            operation_id,
            method,
            path: path.into(),
            body: None,
        }
    }
}

impl<B: Serialize> AgentRequestPlan<B> {
    /// Serialize the typed body for generic HTTP clients.
    pub fn body_value(&self) -> Result<Option<Value>> {
        self.body
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }
}

pub const AGENT_KEY_PAIR_PATH: &str = "/_cokret/gate/account/agent-key-pair";
pub const AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH: &str =
    "/_cokret/open/agent-pairing/runtime-key-requests";
pub const AGENTS_PATH: &str = "/_cokret/self/agents";
pub const AGENT_SIDECAR_THREAD_ENSURE_PATH: &str = "/_cokret/self/agent-sidecar-threads:ensure";

/// Percent-encode one path component for the personal-agent HTTP surface.
pub fn agent_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// Builder for `ck.self.agent.command.provision` request bodies.
#[derive(Clone, Debug, Default)]
pub struct AgentProvisionRequestBuilder {
    display_name: Option<String>,
    agent_slug: Option<String>,
    requested_scope: Option<crate::AgentKeyScope>,
    accountability: Value,
    pairing_ttl_ms: Option<u64>,
}

impl AgentProvisionRequestBuilder {
    pub fn new() -> Self {
        Self {
            display_name: None,
            agent_slug: None,
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        }
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn agent_slug(mut self, agent_slug: impl Into<String>) -> Self {
        self.agent_slug = Some(agent_slug.into());
        self
    }

    pub fn requested_scope(mut self, requested_scope: crate::AgentKeyScope) -> Self {
        self.requested_scope = Some(requested_scope);
        self
    }

    pub fn accountability(mut self, accountability: Value) -> Self {
        self.accountability = accountability;
        self
    }

    pub fn pairing_ttl_ms(mut self, pairing_ttl_ms: u64) -> Self {
        self.pairing_ttl_ms = Some(pairing_ttl_ms);
        self
    }

    pub fn build(self) -> AgentProvisionRequestBody {
        AgentProvisionRequestBody {
            display_name: self.display_name,
            agent_slug: self.agent_slug,
            requested_scope: self.requested_scope,
            accountability: self.accountability,
            pairing_ttl_ms: self.pairing_ttl_ms,
        }
    }
}

pub fn agent_pairing_bootstrap(
    cokret_base_url: impl Into<String>,
    service_did: Did,
    agent_principal_id: Did,
    pairing_request_id: impl Into<String>,
    pairing_code: impl Into<String>,
    pairing_expires_at: DateTime<Utc>,
) -> AgentPairingBootstrap {
    AgentPairingBootstrap {
        cokret_base_url: cokret_base_url.into(),
        service_did,
        agent_principal_id,
        pairing_request_id: pairing_request_id.into(),
        pairing_code: pairing_code.into(),
        pairing_expires_at,
    }
}

pub fn agent_key_authorize_payload_value(payload: &AgentKeyAuthorizePayload) -> Result<Value> {
    serde_json::to_value(payload).map_err(Into::into)
}

pub fn build_agent_key_authorize_event(
    payload: &AgentKeyAuthorizePayload,
    realm_id: RealmId,
    controller_actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
) -> Result<Event> {
    Event::new(
        OP_AGENT_KEY_AUTHORIZE,
        realm_id,
        controller_actor_id,
        actor_seq,
        hlc,
        agent_key_authorize_payload_value(payload)?,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_agent_key_authorize_event<S: cokret_core::MoveSigner + ?Sized>(
    payload: &AgentKeyAuthorizePayload,
    realm_id: RealmId,
    controller_actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    controller_signer: &S,
    controller_verification_method: &str,
    proof_options: cokret_signatures::SignEventOptions,
) -> Result<Event> {
    let mut event =
        build_agent_key_authorize_event(payload, realm_id, controller_actor_id, actor_seq, hlc)?;
    cokret_signatures::sign_event(
        &mut event,
        controller_signer,
        controller_verification_method,
        proof_options,
    )?;
    Ok(event)
}

#[derive(Serialize)]
struct AgentKeyPairingRequestBinding<'a> {
    kind: &'static str,
    operation_id: &'static str,
    controller_principal_id: &'a str,
    agent_principal_id: &'a str,
    verification_method: &'a str,
    runtime_public_key_digest: &'a str,
    pairing_request_id: &'a str,
    pairing_code: &'a str,
    expires_at: &'a str,
    audience: &'a str,
}

#[derive(Serialize)]
struct AgentKeyPairProofRequestBinding<'a> {
    kind: &'static str,
    operation_id: &'static str,
    pairing_request_id: &'a str,
    agent_principal_id: &'a str,
    verification_method: &'a str,
    public_key: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_attestation: Option<&'a Value>,
}

pub fn agent_runtime_public_key_digest(public_key: &Value) -> Result<Hash> {
    let key: PublicKey = serde_json::from_value(public_key.clone()).map_err(|err| {
        Error::Protocol(format!(
            "agent runtime public_key must match public_key schema: {err}"
        ))
    })?;
    if key.kty != "OKP" {
        return Err(Error::Protocol(
            "agent runtime public_key.kty must be OKP".to_owned(),
        ));
    }
    if key.alg != "Ed25519" && key.alg != "EdDSA" {
        return Err(Error::Protocol(
            "agent runtime public_key.alg must be Ed25519 or EdDSA".to_owned(),
        ));
    }
    if key.kid.trim().is_empty() {
        return Err(Error::Protocol(
            "agent runtime public_key.kid must not be empty".to_owned(),
        ));
    }
    let key_bytes = crate::base64url_decode(key.key.as_bytes())?;
    if key_bytes.len() != 32 {
        return Err(Error::Protocol(
            "agent runtime public_key.key must be a 32-byte Ed25519 key".to_owned(),
        ));
    }
    Ok(Hash::new(cokret_core::canonical::canonical_sha256(
        public_key,
    )?)?)
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_pairing_request_binding_digest(
    controller_principal_id: &Did,
    agent_principal_id: &Did,
    verification_method: &str,
    runtime_public_key_digest: &Hash,
    pairing_request_id: &str,
    pairing_code: &str,
    pairing_expires_at: &str,
    audience: &str,
) -> Result<Hash> {
    Ok(Hash::new(cokret_core::canonical::canonical_sha256(
        &AgentKeyPairingRequestBinding {
            kind: "ck.agent.key_pairing_request_binding.v1",
            operation_id: OP_ACCOUNT_AGENT_KEY_PAIR,
            controller_principal_id: controller_principal_id.as_str(),
            agent_principal_id: agent_principal_id.as_str(),
            verification_method,
            runtime_public_key_digest: runtime_public_key_digest.as_str(),
            pairing_request_id,
            pairing_code,
            expires_at: pairing_expires_at,
            audience,
        },
    )?)?)
}

pub fn agent_key_pair_proof_request_binding_digest(
    pairing_request_id: &str,
    agent_principal_id: &Did,
    verification_method: &str,
    public_key: &Value,
    runtime_attestation: Option<&Value>,
) -> Result<Hash> {
    Ok(Hash::new(cokret_core::canonical::canonical_sha256(
        &AgentKeyPairProofRequestBinding {
            kind: "ck.agent.key_pair_proof_of_possession_request.v1",
            operation_id: OP_ACCOUNT_AGENT_KEY_PAIR,
            pairing_request_id,
            agent_principal_id: agent_principal_id.as_str(),
            verification_method,
            public_key,
            runtime_attestation,
        },
    )?)?)
}

pub fn agent_key_pair_proof_signing_input(
    verification_method: impl Into<String>,
    challenge: impl Into<String>,
    audience: impl Into<String>,
    expires_at: DateTime<Utc>,
    request_canonical_digest: Hash,
) -> AgentKeyPairProofSigningInput {
    AgentKeyPairProofSigningInput {
        audience: audience.into(),
        challenge: challenge.into(),
        expires_at,
        request_canonical_digest,
        verification_method: verification_method.into(),
    }
}

pub fn agent_key_proof_request_binding_digest(body: &SessionGrantRequestBody) -> Result<Hash> {
    let mut value = serde_json::to_value(body)?;
    let proof = value
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::Protocol("session grant proof must be an object".to_owned()))?;
    proof.remove("signature");
    proof.remove("request_canonical_digest");
    Ok(Hash::new(cokret_core::canonical::canonical_sha256(
        &value,
    )?)?)
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_signing_input_for_session_grant(
    principal_id: &Did,
    requested_scope: &[String],
    agent_key_authorization_ref: &str,
    agent_scope_request: &Value,
    dpop_binding_proof: &SessionGrantDpopBindingProof,
    verification_method: impl Into<String>,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> Result<AgentKeyProofSigningInput> {
    let verification_method = verification_method.into();
    let challenge = challenge.into();
    let nonce = nonce.into();
    let audience = audience.into();
    let mut body = agent_key_proof_unsigned_session_grant_request(
        principal_id.clone(),
        requested_scope.to_vec(),
        agent_key_authorization_ref,
        agent_scope_request.clone(),
        dpop_binding_proof.clone(),
        verification_method.clone(),
        challenge.clone(),
        nonce.clone(),
        audience.clone(),
        expires_at,
    )?;
    let request_canonical_digest = agent_key_proof_request_binding_digest(&body)?;
    body.proof.request_canonical_digest = request_canonical_digest.clone();

    Ok(AgentKeyProofSigningInput {
        audience,
        challenge,
        nonce: Some(nonce),
        expires_at,
        request_canonical_digest,
        verification_method,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_session_grant_request(
    principal_id: Did,
    requested_scope: Vec<String>,
    agent_key_authorization_ref: impl Into<String>,
    agent_scope_request: Value,
    dpop_binding_proof: SessionGrantDpopBindingProof,
    verification_method: impl Into<String>,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: impl Into<String>,
    expires_at: DateTime<Utc>,
    signature: impl Into<String>,
) -> Result<SessionGrantRequestBody> {
    let agent_key_authorization_ref = agent_key_authorization_ref.into();
    let verification_method = verification_method.into();
    let challenge = challenge.into();
    let nonce = nonce.into();
    let audience = audience.into();
    let signing_input = agent_key_proof_signing_input_for_session_grant(
        &principal_id,
        &requested_scope,
        &agent_key_authorization_ref,
        &agent_scope_request,
        &dpop_binding_proof,
        verification_method.clone(),
        challenge.clone(),
        nonce.clone(),
        audience.clone(),
        expires_at,
    )?;

    Ok(agent_key_proof_unsigned_session_grant_request(
        principal_id,
        requested_scope,
        agent_key_authorization_ref,
        agent_scope_request,
        dpop_binding_proof,
        verification_method,
        challenge,
        nonce,
        audience,
        expires_at,
    )?
    .with_agent_key_proof_material(signing_input.request_canonical_digest, signature.into()))
}

#[allow(clippy::too_many_arguments)]
fn agent_key_proof_unsigned_session_grant_request(
    principal_id: Did,
    requested_scope: Vec<String>,
    agent_key_authorization_ref: impl Into<String>,
    agent_scope_request: Value,
    dpop_binding_proof: SessionGrantDpopBindingProof,
    verification_method: impl Into<String>,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> Result<SessionGrantRequestBody> {
    let request_canonical_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    Ok(SessionGrantRequestBody {
        principal_id: Some(principal_id),
        device_id: None,
        requested_scope,
        agent_key_authorization_ref: Some(agent_key_authorization_ref.into()),
        agent_scope_request,
        dpop_binding_proof: Some(dpop_binding_proof),
        applet_delegation: None,
        proof: SessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::AgentKeyProof,
            challenge: challenge.into(),
            request_canonical_digest,
            audience: audience.into(),
            expires_at: Some(expires_at),
            signature: String::new(),
            verification_method: Some(verification_method.into()),
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: Some(nonce.into()),
            authorization_code: None,
            code_verifier: None,
        },
    })
}

trait AgentKeyProofMaterial {
    fn with_agent_key_proof_material(
        self,
        request_canonical_digest: Hash,
        signature: String,
    ) -> Self;
}

impl AgentKeyProofMaterial for SessionGrantRequestBody {
    fn with_agent_key_proof_material(
        mut self,
        request_canonical_digest: Hash,
        signature: String,
    ) -> Self {
        self.proof.request_canonical_digest = request_canonical_digest;
        self.proof.signature = signature;
        self
    }
}

pub fn capability_grant_attach_body(
    grant: &CapabilityGrant,
) -> Result<AgentGrantAttachRequestBody> {
    Ok(AgentGrantAttachRequestBody {
        grant: serde_json::to_value(grant)?,
    })
}

pub fn plan_agent_key_pair(
    body: AgentKeyPairRequestBody,
) -> AgentRequestPlan<AgentKeyPairRequestBody> {
    AgentRequestPlan::with_body(
        OP_ACCOUNT_AGENT_KEY_PAIR,
        AgentHttpMethod::Post,
        AGENT_KEY_PAIR_PATH,
        body,
    )
}

pub fn plan_agent_runtime_approval_request(
    body: AgentRuntimeApprovalRequestBody,
) -> AgentRequestPlan<AgentRuntimeApprovalRequestBody> {
    AgentRequestPlan::with_body(
        OP_OPEN_AGENT_PAIRING_SUBMIT_RUNTIME_KEY_REQUEST,
        AgentHttpMethod::Post,
        AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH,
        body,
    )
}

pub fn plan_agent_provision(
    body: AgentProvisionRequestBody,
) -> AgentRequestPlan<AgentProvisionRequestBody> {
    AgentRequestPlan::with_body(OP_AGENT_PROVISION, AgentHttpMethod::Post, AGENTS_PATH, body)
}

pub fn plan_agent_list() -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(OP_AGENT_LIST, AgentHttpMethod::Get, AGENTS_PATH)
}

pub fn plan_agent_get(agent_principal_id: &str) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GET,
        AgentHttpMethod::Get,
        format!(
            "{}/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
    )
}

pub fn plan_agent_pause(
    agent_principal_id: &str,
    body: AgentPauseRequestBody,
) -> AgentRequestPlan<AgentPauseRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_PAUSE,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/pause",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_resume(
    agent_principal_id: &str,
    body: AgentResumeRequestBody,
) -> AgentRequestPlan<AgentResumeRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_RESUME,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/resume",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_deactivate(
    agent_principal_id: &str,
    body: AgentDeactivateRequestBody,
) -> AgentRequestPlan<AgentDeactivateRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_DEACTIVATE,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/deactivate",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_rotate_key(
    agent_principal_id: &str,
    body: AgentRotateKeyRequestBody,
) -> AgentRequestPlan<AgentRotateKeyRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_ROTATE_KEY,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/rotate-key",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_grant_attach(
    agent_principal_id: &str,
    body: AgentGrantAttachRequestBody,
) -> AgentRequestPlan<AgentGrantAttachRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_GRANT_ATTACH,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/grants",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_grant_detach(
    agent_principal_id: &str,
    grant_id: &GrantId,
) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GRANT_DETACH,
        AgentHttpMethod::Delete,
        format!(
            "{}/{}/grants/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id),
            agent_path_component(grant_id.as_str())
        ),
    )
}

pub fn plan_agent_sidecar_thread_ensure(
    body: AgentSidecarThreadEnsureRequestBody,
) -> AgentRequestPlan<AgentSidecarThreadEnsureRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_SIDECAR_THREAD_ENSURE,
        AgentHttpMethod::Post,
        AGENT_SIDECAR_THREAD_ENSURE_PATH,
        body,
    )
}

/// Delegated actor relationship for an agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegatedActor {
    pub delegated_actor_id: Did,
    pub agent_id: Did,
    pub principal_id: Did,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl DelegatedActor {
    /// Check whether the delegation is active.
    pub fn is_active(&self, at: DateTime<Utc>) -> bool {
        self.expires_at
            .map(|expires_at| expires_at > at)
            .unwrap_or(true)
    }
}

/// Agent run lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    Killed,
}

/// Agent run record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRun {
    pub run_id: String,
    pub agent_id: Did,
    pub principal_id: Did,
    pub state: AgentRunState,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// In-memory agent run lifecycle manager.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentRunManager {
    runs: BTreeMap<String, AgentRun>,
}

#[cfg(test)]
impl AgentRunManager {
    /// Create an empty run manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a run.
    pub fn start_run(&mut self, agent_id: Did, principal_id: Did, input: Value) -> AgentRun {
        let now = Utc::now();
        let run = AgentRun {
            run_id: format!("run_{}", uuid::Uuid::now_v7()),
            agent_id,
            principal_id,
            state: AgentRunState::Running,
            input,
            output: Value::Null,
            error: None,
            started_at: now,
            updated_at: now,
            completed_at: None,
        };
        self.runs.insert(run.run_id.clone(), run.clone());
        run
    }

    /// Transition a run to a new state.
    pub fn transition(
        &mut self,
        run_id: &str,
        state: AgentRunState,
        output: Option<Value>,
        error: Option<String>,
    ) -> Result<AgentRun> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Error::Protocol("agent run not found".to_owned()))?;
        run.state = state;
        if let Some(output) = output {
            run.output = output;
        }
        run.error = error;
        run.updated_at = Utc::now();
        if matches!(
            state,
            AgentRunState::Completed
                | AgentRunState::Failed
                | AgentRunState::Cancelled
                | AgentRunState::Killed
        ) {
            run.completed_at = Some(run.updated_at);
        }
        Ok(run.clone())
    }

    /// Activate the kill switch for a run.
    pub fn kill_run(&mut self, run_id: &str, reason: impl Into<String>) -> Result<AgentRun> {
        self.transition(run_id, AgentRunState::Killed, None, Some(reason.into()))
    }
}

/// Tool audit action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentToolAuditAction {
    Requested,
    Allowed,
    Denied,
    Completed,
    Failed,
}

/// Agent tool audit entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentToolAuditEntry {
    pub entry_id: String,
    pub run_id: String,
    pub agent_id: Did,
    pub tool_name: String,
    pub action: AgentToolAuditAction,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// In-memory tool audit log.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentToolAuditLog {
    entries: Vec<AgentToolAuditEntry>,
}

#[cfg(test)]
impl AgentToolAuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an audit entry.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        run_id: impl Into<String>,
        agent_id: Did,
        tool_name: impl Into<String>,
        action: AgentToolAuditAction,
        input: Value,
        output: Value,
        error: Option<String>,
    ) -> AgentToolAuditEntry {
        let entry = AgentToolAuditEntry {
            entry_id: format!("tool_audit_{}", uuid::Uuid::now_v7()),
            run_id: run_id.into(),
            agent_id,
            tool_name: tool_name.into(),
            action,
            input,
            output,
            error,
            created_at: Utc::now(),
        };
        self.entries.push(entry.clone());
        entry
    }

    /// List entries for a run.
    pub fn entries_for_run(&self, run_id: &str) -> Vec<&AgentToolAuditEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.run_id == run_id)
            .collect()
    }
}

/// Agent protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocol {
    A2a,
    Acp,
    Mcp,
}

/// Agent protocol message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentProtocolMessage {
    pub protocol: AgentProtocol,
    pub message_id: String,
    pub sender: Did,
    pub recipient: Did,
    pub payload: Value,
}

/// External agent registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAgent {
    pub agent_id: Did,
    pub endpoint: String,
    pub supported_protocols: Vec<AgentProtocol>,
}

/// Metadata for one agent protocol bridge endpoint.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentProtocolEndpoint {
    pub endpoint: String,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

/// A2A/ACP/MCP bridge metadata for an agent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentBridgeMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a: Option<AgentProtocolEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acp: Option<AgentProtocolEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<AgentProtocolEndpoint>,
}

/// Protocol bridge and registry.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentProtocolBridge {
    external_agents: BTreeMap<Did, ExternalAgent>,
    bridge_metadata: BTreeMap<Did, AgentBridgeMetadata>,
}

#[cfg(test)]
impl AgentProtocolBridge {
    /// Create an empty bridge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an external agent.
    pub fn register_external_agent(&mut self, agent: ExternalAgent) {
        self.external_agents.insert(agent.agent_id.clone(), agent);
    }

    /// Get external agent info.
    pub fn external_agent(&self, agent_id: &Did) -> Option<&ExternalAgent> {
        self.external_agents.get(agent_id)
    }

    /// Set bridge metadata for an external agent.
    pub fn set_bridge_metadata(&mut self, agent_id: Did, metadata: AgentBridgeMetadata) {
        self.bridge_metadata.insert(agent_id, metadata);
    }

    /// Get bridge metadata for an external agent.
    pub fn bridge_metadata(&self, agent_id: &Did) -> Option<&AgentBridgeMetadata> {
        self.bridge_metadata.get(agent_id)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use cokret_core::move_event::Move;
    use cokret_core::{MoveSignature, MoveSigner, UnsignedMove, canonical, proof_kind};
    use serde_json::json;

    use super::*;
    use crate::{
        AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyScope,
        AgentKeyScopeResource, AgentKeyScopeResourceKind,
        SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE,
    };

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    struct StubMoveSigner {
        did: Did,
        kid: String,
    }

    impl StubMoveSigner {
        fn new(did: Did, kid: impl Into<String>) -> Self {
            Self {
                did,
                kid: kid.into(),
            }
        }
    }

    impl MoveSigner for StubMoveSigner {
        fn sign_move(&self, _unsigned: &UnsignedMove) -> Result<Move> {
            unreachable!("agent authorize helper only calls sign_payload");
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature> {
            let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))?;
            Ok(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: self.kid.clone(),
                payload_digest: payload_digest.clone(),
                created_at: Utc::now(),
                jws: format!("stub..{}", payload_digest.as_str()),
            })
        }
    }

    fn test_scope() -> AgentKeyScope {
        AgentKeyScope {
            actions: vec![
                SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE.to_owned(),
                "ck.message.create".to_owned(),
            ],
            resources: vec![AgentKeyScopeResource {
                kind: AgentKeyScopeResourceKind::Realm,
                realm_id: Some(
                    RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                ),
                r#ref: None,
                operation: None,
                service_did: None,
            }],
            constraints: Vec::new(),
        }
    }

    #[test]
    fn personal_agent_request_plans_use_standard_paths() {
        let provision = AgentProvisionRequestBuilder::new()
            .display_name("summary agent")
            .agent_slug("summary")
            .requested_scope(AgentKeyScope {
                actions: vec!["ck.message.create".to_owned()],
                resources: vec![AgentKeyScopeResource {
                    kind: AgentKeyScopeResourceKind::Realm,
                    realm_id: Some(
                        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                    ),
                    r#ref: None,
                    operation: None,
                    service_did: None,
                }],
                constraints: Vec::new(),
            })
            .build();
        let plan = plan_agent_provision(provision);
        assert_eq!(plan.operation_id, OP_AGENT_PROVISION);
        assert_eq!(plan.method.as_str(), "POST");
        assert_eq!(plan.path, "/_cokret/self/agents");
        let body = plan.body_value().unwrap().unwrap();
        assert_eq!(body["display_name"], "summary agent");
        assert_eq!(body["agent_slug"], "summary");
        assert_eq!(body["requested_scope"]["actions"][0], "ck.message.create");
        assert_eq!(body["requested_scope"]["resources"][0]["kind"], "realm");

        let get = plan_agent_get("did:webvh:z6mkfixture:agent.example");
        assert_eq!(get.operation_id, OP_AGENT_GET);
        assert_eq!(get.method.as_str(), "GET");
        assert_eq!(
            get.path,
            "/_cokret/self/agents/did%3Awebvh%3Az6mkfixture%3Aagent.example"
        );

        let grant_id =
            GrantId::new("ck:grant:01964137-0000-7000-8000-000000000010".to_owned()).unwrap();
        let detach = plan_agent_grant_detach("did:webvh:z6mkfixture:agent.example", &grant_id);
        assert_eq!(detach.operation_id, OP_AGENT_GRANT_DETACH);
        assert_eq!(detach.method.as_str(), "DELETE");
        assert_eq!(
            detach.path,
            "/_cokret/self/agents/did%3Awebvh%3Az6mkfixture%3Aagent.example/grants/ck%3Agrant%3A01964137-0000-7000-8000-000000000010"
        );
    }

    #[test]
    fn agent_key_pair_builder_requires_authorize_event() {
        let agent_id = did("agent");
        let body = AgentKeyPairRequestBuilder::new(
            "01970000-0000-7000-8000-000000000020",
            agent_id.clone(),
            format!("{}#runtime-key-1", agent_id.as_str()),
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }),
            json!({"challenge": "pairing", "signature": "sig"}),
            json!({"kind": OP_AGENT_KEY_AUTHORIZE}),
        )
        .runtime_attestation(json!({"kind": "self_asserted"}))
        .build()
        .unwrap();

        assert_eq!(
            body.pairing_request_id,
            "01970000-0000-7000-8000-000000000020"
        );
        assert_eq!(body.agent_principal_id, agent_id);
        assert_eq!(body.authorize_event["kind"], OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(
            body.runtime_attestation.as_ref().unwrap()["kind"],
            "self_asserted"
        );

        let err = AgentKeyPairRequestBuilder::new(
            "01970000-0000-7000-8000-000000000020",
            did("agent2"),
            "did:webvh:z6mkfixture:agent2.example#runtime-key-1",
            json!({}),
            json!({}),
            Value::Null,
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn agent_pairing_bootstrap_serializes_spec_shape() {
        let bootstrap = agent_pairing_bootstrap(
            "https://cokret.example",
            did("service"),
            did("agent"),
            "01970000-0000-7000-8000-000000000020",
            "R7K9-2M4P",
            Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap(),
        );
        let value = serde_json::to_value(bootstrap).unwrap();

        // CKP-0008 §4.4: exactly six fields, no scope payload.
        assert_eq!(value["cokret_base_url"], "https://cokret.example");
        assert_eq!(value["pairing_code"], "R7K9-2M4P");
        assert_eq!(
            value["pairing_request_id"],
            "01970000-0000-7000-8000-000000000020"
        );
        assert!(value.get("schema").is_none());
        assert!(value.get("requested_scope").is_none());
        assert!(value.get("service_scope").is_none());
        assert!(value.get("content_grant_summary").is_none());
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 6);
    }

    #[test]
    fn agent_key_authorize_event_builder_uses_payload_event_kind() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let payload = AgentKeyAuthorizePayload {
            agent_principal_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{}#runtime-key-1", agent_id.as_str()),
            public_key_digest: None,
            accountable_principal_id: controller_id.clone(),
            agent_key_scope: test_scope(),
            audience: vec!["https://cokret.example".to_owned()],
            issued_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 15, 0).unwrap(),
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::ApprovalEvent,
                r#ref: "ck:event:01970000-0000-7000-8000-000000000021".to_owned(),
                request_canonical_digest: None,
                approved_by: Some(controller_id.clone()),
            },
            revocation_check_ref: None,
            runtime_attestation: None,
        };

        let event = build_agent_key_authorize_event(
            &payload,
            RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            controller_id.clone(),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        )
        .unwrap();

        assert_eq!(event.kind.as_str(), OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(event.actor_id, controller_id);
        assert_eq!(event.actor_seq, 7);
        assert_eq!(event.content["agent_principal_id"], agent_id.as_str());
        assert_eq!(
            event.content["agent_key_scope"]["actions"][0],
            SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE
        );
        assert_eq!(
            event.content["verification_method"],
            "did:webvh:z6mkfixture:agent.example#runtime-key-1"
        );
        let canonical_content =
            String::from_utf8(canonical::canonical_json_bytes(&event.content).unwrap()).unwrap();
        assert_eq!(
            canonical_content,
            r#"{"accountable_principal_id":"did:webvh:z6mkfixture:controller.example","agent_key_scope":{"actions":["ck.self.events.stream.subscribe","ck.message.create"],"resources":[{"kind":"realm","realm_id":"ck:realm:01904100-0000-7000-8000-000000000001"}]},"agent_principal_id":"did:webvh:z6mkfixture:agent.example","approval_evidence":{"approved_by":"did:webvh:z6mkfixture:controller.example","kind":"approval_event","ref":"ck:event:01970000-0000-7000-8000-000000000021"},"audience":["https://cokret.example"],"expires_at":"2026-05-26T10:15:00Z","issued_at":"2026-05-26T10:00:00Z","key_id":"runtime-key-1","verification_method":"did:webvh:z6mkfixture:agent.example#runtime-key-1"}"#
        );
    }

    #[test]
    fn signed_agent_key_authorize_event_builder_attaches_controller_proof() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let payload = AgentKeyAuthorizePayload {
            agent_principal_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{}#runtime-key-1", agent_id.as_str()),
            public_key_digest: None,
            accountable_principal_id: controller_id.clone(),
            agent_key_scope: test_scope(),
            audience: vec!["https://cokret.example".to_owned()],
            issued_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 15, 0).unwrap(),
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::ApprovalEvent,
                r#ref: "ck:event:01970000-0000-7000-8000-000000000021".to_owned(),
                request_canonical_digest: None,
                approved_by: Some(controller_id.clone()),
            },
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let controller_vm = format!("{}#controller-key-1", controller_id.as_str());
        let signer = StubMoveSigner::new(controller_id.clone(), controller_vm.clone());
        let event = build_signed_agent_key_authorize_event(
            &payload,
            RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            controller_id.clone(),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            &signer,
            &controller_vm,
            cokret_signatures::SignEventOptions::new()
                .with_created_at(Utc.with_ymd_and_hms(2026, 5, 26, 10, 1, 0).unwrap()),
        )
        .unwrap();

        assert_eq!(event.kind.as_str(), OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(event.actor_id, controller_id);
        assert_eq!(event.proofs.len(), 1);
        assert_eq!(event.proofs[0].kind, proof_kind::DETACHED_JWS);
        assert_eq!(event.proofs[0].verification_method, controller_vm);
        assert_eq!(
            event.proofs[0].event_digest.as_str(),
            event.event_digest().unwrap()
        );
        assert_eq!(
            event.proofs[0].created_at,
            Utc.with_ymd_and_hms(2026, 5, 26, 10, 1, 0).unwrap()
        );
        event.validate_proof_bindings().unwrap();
    }

    #[test]
    fn agent_key_proof_request_binds_scope_and_dpop_proof() {
        let principal_id = did("agent");
        let requested_scope = vec![
            SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE.to_owned(),
            "ck.message.create".to_owned(),
        ];
        let agent_scope_request = json!({
            "realm_ids": ["ck:realm:01904100-0000-7000-8000-000000000001"],
            "track_names": ["summary"],
        });
        let dpop_binding_proof = SessionGrantDpopBindingProof {
            proof_jwt: "dpop.jwt.value".to_owned(),
        };
        let expires_at = Utc.with_ymd_and_hms(2026, 5, 26, 10, 5, 0).unwrap();
        let authorization_ref = "ck:event:01970000-0000-7000-8000-000000000021";
        let nonce = "nonce-abc";
        let signing_input = agent_key_proof_signing_input_for_session_grant(
            &principal_id,
            &requested_scope,
            authorization_ref,
            &agent_scope_request,
            &dpop_binding_proof,
            format!("{}#runtime-key-1", principal_id.as_str()),
            "challenge",
            nonce,
            "https://cokret.example",
            expires_at,
        )
        .unwrap();
        let signing_json = String::from_utf8(signing_input.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            signing_json,
            r#"{"audience":"https://cokret.example","challenge":"challenge","expires_at":"2026-05-26T10:05:00Z","nonce":"nonce-abc","request_canonical_digest":"sha256:36b158c5b5ceafe211d21558731991459d80ebc7b6ddd8749d99360f116d9e3b","verification_method":"did:webvh:z6mkfixture:agent.example#runtime-key-1"}"#
        );
        assert!(!signing_json.contains(AGENT_KEY_PROOF_KIND));

        let request = agent_key_proof_session_grant_request(
            principal_id.clone(),
            requested_scope.clone(),
            authorization_ref,
            agent_scope_request.clone(),
            dpop_binding_proof.clone(),
            format!("{}#runtime-key-1", principal_id.as_str()),
            "challenge",
            nonce,
            "https://cokret.example",
            expires_at,
            "agent-key-signature",
        )
        .unwrap();
        let digest = agent_key_proof_request_binding_digest(&request).unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:36b158c5b5ceafe211d21558731991459d80ebc7b6ddd8749d99360f116d9e3b"
        );
        assert_eq!(request.principal_id.as_ref(), Some(&principal_id));
        assert_eq!(request.device_id, None);
        assert_eq!(request.requested_scope, requested_scope);
        assert_eq!(
            request.agent_key_authorization_ref.as_deref(),
            Some(authorization_ref)
        );
        assert_eq!(request.agent_scope_request, agent_scope_request);
        assert_eq!(
            request.dpop_binding_proof.as_ref().unwrap().proof_jwt,
            dpop_binding_proof.proof_jwt
        );
        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::AgentKeyProof
        );
        assert_eq!(request.proof.request_canonical_digest, digest);
        assert_eq!(request.proof.nonce.as_deref(), Some(nonce));
        assert_eq!(request.proof.expires_at, Some(expires_at));
        assert_eq!(
            request.proof.verification_method.as_deref(),
            Some("did:webvh:z6mkfixture:agent.example#runtime-key-1")
        );
        assert!(crate::is_personal_agent_runtime_event_service_scope(
            SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE
        ));
        assert!(!crate::is_personal_agent_runtime_event_service_scope(
            "ck.message.create"
        ));
    }

    #[test]
    fn agent_key_pair_binding_helpers_match_wire_contract() {
        let controller_id = did("controller");
        let agent_id = did("agent");
        let verification_method = format!("{}#runtime-key-1", agent_id.as_str());
        let public_key = json!({
            "kty": "OKP",
            "kid": verification_method,
            "alg": "Ed25519",
            "key": crate::base64url_encode([7u8; 32]),
        });
        let runtime_digest = agent_runtime_public_key_digest(&public_key).unwrap();
        let pairing_digest = agent_key_pairing_request_binding_digest(
            &controller_id,
            &agent_id,
            &verification_method,
            &runtime_digest,
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "12345678",
            "2026-07-06T00:15:00.000Z",
            "did:web:soland.local",
        )
        .unwrap();
        let pop_digest = agent_key_pair_proof_request_binding_digest(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            &agent_id,
            &verification_method,
            &public_key,
            None,
        )
        .unwrap();
        let signing_input = agent_key_pair_proof_signing_input(
            verification_method,
            "pairing-pop",
            "did:web:soland.local",
            Utc.with_ymd_and_hms(2026, 7, 6, 0, 15, 0).unwrap(),
            pop_digest.clone(),
        );

        assert!(runtime_digest.as_str().starts_with("sha256:"));
        assert!(pairing_digest.as_str().starts_with("sha256:"));
        assert_eq!(signing_input.request_canonical_digest, pop_digest);
        assert!(
            String::from_utf8(signing_input.canonical_bytes().unwrap())
                .unwrap()
                .contains("pairing-pop")
        );
    }

    #[test]
    fn agent_protocol_registers_external_agents() {
        let agent_id = did("external");
        let mut bridge = AgentProtocolBridge::new();
        bridge.register_external_agent(ExternalAgent {
            agent_id: agent_id.clone(),
            endpoint: "https://agent.example/a2a".to_owned(),
            supported_protocols: vec![AgentProtocol::A2a],
        });

        assert!(bridge.external_agent(&agent_id).is_some());
    }

    #[test]
    fn agent_runs_support_lifecycle_kill_switch_and_tool_audit() {
        let agent = did("agent");
        let principal = did("principal");
        let mut runs = AgentRunManager::new();
        let run = runs.start_run(agent.clone(), principal, json!({"task": "answer"}));
        assert_eq!(run.state, AgentRunState::Running);

        let killed = runs.kill_run(&run.run_id, "operator stop").unwrap();
        assert_eq!(killed.state, AgentRunState::Killed);
        assert!(killed.completed_at.is_some());

        let mut audit = AgentToolAuditLog::new();
        audit.record(
            run.run_id.clone(),
            agent,
            "search",
            AgentToolAuditAction::Denied,
            json!({"q": "secret"}),
            Value::Null,
            Some("policy".to_owned()),
        );
        assert_eq!(audit.entries_for_run(&run.run_id).len(), 1);
    }

    #[test]
    fn agent_protocol_bridge_stores_a2a_acp_mcp_metadata() {
        let agent_id = did("external");
        let mut bridge = AgentProtocolBridge::new();
        bridge.set_bridge_metadata(
            agent_id.clone(),
            AgentBridgeMetadata {
                a2a: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/a2a".to_owned(),
                    capabilities: BTreeSet::from(["tasks".to_owned()]),
                    metadata: Value::Null,
                }),
                acp: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/acp".to_owned(),
                    capabilities: BTreeSet::new(),
                    metadata: json!({"version": "1"}),
                }),
                mcp: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/mcp".to_owned(),
                    capabilities: BTreeSet::from(["tools".to_owned()]),
                    metadata: Value::Null,
                }),
            },
        );

        let metadata = bridge.bridge_metadata(&agent_id).unwrap();
        assert!(metadata.a2a.is_some());
        assert!(metadata.acp.is_some());
        assert!(metadata.mcp.is_some());
    }
}
