//! Agent runtime and protocol interop helpers.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Duration;

pub use arkret_core::agent::{
    agent_key_pair_proof_request_binding_digest, agent_key_pairing_request_binding_digest,
    agent_runtime_attestation_digest, agent_runtime_key_binding_digest,
    agent_runtime_key_binding_digest_from_digests, agent_runtime_public_key_digest,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::AgentKeyRuntimeAttestationKind;
use crate::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyAuthorizePayload,
    AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyPairRequestBody, AgentPairingBootstrap,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentRenewPairingRequestBody,
    AgentResumeRequestBody, AgentRuntimeApprovalRequestBody, AgentRuntimeApprovalStatusRequestBody,
    AgentSidecarThreadEnsureRequestBody, CapabilityGrant, Did, DidUrl, Error, Event, GrantId, Hash,
    Hlc, NonEmptyJsonObject, NonEmptyString, OP_ACCOUNT_AGENT_KEY_PAIR, OP_AGENT_DEACTIVATE,
    OP_AGENT_GET, OP_AGENT_GRANT_ATTACH, OP_AGENT_GRANT_DETACH, OP_AGENT_KEY_AUTHORIZE,
    OP_AGENT_LIST, OP_AGENT_PAUSE, OP_AGENT_PROVISION, OP_AGENT_RENEW_PAIRING, OP_AGENT_RESUME,
    OP_AGENT_SIDECAR_THREAD_ENSURE, OP_OPEN_AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS,
    OP_OPEN_AGENT_PAIRING_SUBMIT_RUNTIME_KEY_REQUEST, PublicKey, RealmId, Result,
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof, SessionGrantProofKind,
    SessionGrantRequestBody, SessionGrantRequestProof,
};

pub const AGENT_KEY_PROOF_KIND: &str = "agent_key_proof";

#[derive(Clone, Debug, Default)]
pub struct AgentRuntimeApprovalPollSchedule {
    attempt: usize,
}

impl AgentRuntimeApprovalPollSchedule {
    const DELAYS: [Duration; 5] = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(30),
    ];

    pub fn next_delay(&mut self, retry_after: Option<Duration>) -> Duration {
        let fallback = Self::DELAYS[self.attempt.min(Self::DELAYS.len() - 1)];
        self.attempt = self.attempt.saturating_add(1);
        retry_after.unwrap_or(fallback)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// A runtime-key request body together with the digest of the generated
/// public key. The digest is reused by the controller-side authorize event.
#[derive(Clone, Debug)]
pub struct RuntimeKeyRequest<T> {
    pub body: T,
    pub public_key_digest: Hash,
}

/// Builds the two runtime-key pairing request shapes from one bootstrap and
/// Ed25519 signing key, keeping JWK and proof-of-possession assembly in the SDK.
pub struct RuntimeKeyRequestBuilder<'a> {
    signing_key: &'a SigningKey,
    bootstrap: AgentPairingBootstrap,
    verification_method: String,
    proof_expires_at: DateTime<Utc>,
    runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

impl<'a> RuntimeKeyRequestBuilder<'a> {
    pub fn new(signing_key: &'a SigningKey, bootstrap: AgentPairingBootstrap) -> Self {
        let key_digest = arkret_canonical::sha256_digest(&signing_key.verifying_key().to_bytes());
        let key_suffix = key_digest
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(key_digest.as_str());
        let verification_method = format!(
            "{}#runtime-key-{}",
            bootstrap.agent_id,
            &key_suffix[..16.min(key_suffix.len())]
        );
        let proof_expires_at = bootstrap.pairing_expires_at;
        Self {
            signing_key,
            bootstrap,
            verification_method,
            proof_expires_at,
            runtime_attestation: None,
        }
    }

    #[must_use]
    pub fn verification_method(mut self, verification_method: impl Into<String>) -> Self {
        self.verification_method = verification_method.into();
        self
    }

    #[must_use]
    pub fn proof_expires_at(mut self, proof_expires_at: DateTime<Utc>) -> Self {
        self.proof_expires_at = proof_expires_at;
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
            "alg": "Ed25519",
            "key": arkret_canonical::base64url_encode(self.signing_key.verifying_key().to_bytes()),
        }))
    }

    pub fn public_key_digest(&self) -> Result<Hash> {
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
                pairing_request_id: NonEmptyString::new(self.bootstrap.pairing_request_id.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                agent_id: self.bootstrap.agent_id.clone(),
                verification_method: DidUrl::new(self.verification_method.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                public_key,
                proof_of_possession,
                runtime_attestation: self.runtime_attestation.clone(),
            },
            public_key_digest,
        })
    }

    pub fn build_key_pair_request(
        &self,
        authorize_event: Event,
    ) -> Result<RuntimeKeyRequest<AgentKeyPairRequestBody>> {
        validate_pairing_authorize_event(&authorize_event, &self.bootstrap.agent_id)?;
        let (public_key, public_key_digest, proof_of_possession) = self.request_material()?;
        Ok(RuntimeKeyRequest {
            body: AgentKeyPairRequestBody {
                pairing_request_id: NonEmptyString::new(self.bootstrap.pairing_request_id.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                agent_id: self.bootstrap.agent_id.clone(),
                verification_method: DidUrl::new(self.verification_method.clone())
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?,
                public_key,
                proof_of_possession,
                runtime_attestation: self.runtime_attestation.clone(),
                authorize_event,
            },
            public_key_digest,
        })
    }

    fn request_material(&self) -> Result<(PublicKey, Hash, NonEmptyJsonObject)> {
        let public_key_value = self.public_key()?;
        let public_key: PublicKey = serde_json::from_value(public_key_value.clone())?;
        let public_key_digest = agent_runtime_public_key_digest(&public_key_value)?;
        // This builder emits millisecond RFC 3339 timestamps. Sign the normalized
        // value so verifier reconstruction cannot lose submilliseconds.
        let proof_expires_at =
            DateTime::<Utc>::from_timestamp_millis(self.proof_expires_at.timestamp_millis())
                .ok_or_else(|| {
                    Error::Protocol(
                        "agent key proof expires_at is outside the wire timestamp range".into(),
                    )
                })?;
        let request_digest = agent_key_pair_proof_request_binding_digest(
            &self.bootstrap.pairing_request_id,
            &self.bootstrap.agent_id,
            &self.verification_method,
            &public_key_value,
            self.runtime_attestation
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .as_ref(),
        )?;
        let signing_input = agent_key_pair_proof_signing_input(
            self.verification_method.clone(),
            self.bootstrap.pairing_request_id.clone(),
            self.bootstrap.service_id.to_string(),
            proof_expires_at,
            request_digest.clone(),
        );
        let signature = self.signing_key.sign(&signing_input.canonical_bytes()?);
        let proof_of_possession = serde_json::from_value(serde_json::json!({
            "challenge": self.bootstrap.pairing_request_id,
            "audience": self.bootstrap.service_id,
            "request_canonical_digest": request_digest,
            "expires_at": proof_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "signature": arkret_canonical::base64url_encode(signature.to_bytes()),
        }))?;
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
            || !self
                .verification_method
                .starts_with(&format!("{}#", self.bootstrap.agent_id))
        {
            return Err(Error::Protocol(
                "agent runtime verification_method must belong to agent_id".to_owned(),
            ));
        }
        Ok(())
    }
}

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

/// HTTP method used by a Arkret personal-agent operation plan.
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

/// A transport-neutral plan for one standard `/_arkret/...` personal-agent
/// HTTP operation.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRequestPlan<B> {
    pub operation_id: &'static str,
    pub method: AgentHttpMethod,
    pub path: String,
    pub body: Option<B>,
}

/// Builder for `ak.gate.account.command.pair_agent_key` request bodies.
#[derive(Clone, Debug)]
pub struct AgentKeyPairRequestBuilder {
    pairing_request_id: String,
    agent_id: Did,
    verification_method: String,
    public_key: Value,
    proof_of_possession: Value,
    runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    authorize_event: Event,
}

impl AgentKeyPairRequestBuilder {
    pub fn new(
        pairing_request_id: impl Into<String>,
        agent_id: Did,
        verification_method: impl Into<String>,
        public_key: Value,
        proof_of_possession: Value,
        authorize_event: Event,
    ) -> Self {
        Self {
            pairing_request_id: pairing_request_id.into(),
            agent_id,
            verification_method: verification_method.into(),
            public_key,
            proof_of_possession,
            runtime_attestation: None,
            authorize_event,
        }
    }

    pub fn runtime_attestation(
        mut self,
        runtime_attestation: AgentKeyAuthorizePayloadRuntimeAttestation,
    ) -> Self {
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
        validate_pairing_authorize_event(&self.authorize_event, &self.agent_id)?;
        Ok(AgentKeyPairRequestBody {
            pairing_request_id: NonEmptyString::new(self.pairing_request_id)
                .map_err(|reason| Error::Protocol(reason.to_owned()))?,
            agent_id: self.agent_id,
            verification_method: DidUrl::new(self.verification_method)
                .map_err(|reason| Error::Protocol(reason.to_owned()))?,
            public_key: serde_json::from_value(self.public_key)?,
            proof_of_possession: serde_json::from_value(self.proof_of_possession)?,
            runtime_attestation: self.runtime_attestation,
            authorize_event: self.authorize_event,
        })
    }
}

fn validate_pairing_authorize_event(authorize_event: &Event, agent_id: &Did) -> Result<()> {
    if authorize_event.kind.as_str() != OP_AGENT_KEY_AUTHORIZE {
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
/// proof-of-possession for `ak.gate.account.command.pair_agent_key`.
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
        arkret_canonical::canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

impl AgentKeyPairProofSigningInput {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        arkret_canonical::canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
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

pub const AGENT_KEY_PAIR_PATH: &str = "/_arkret/gate/account/agent-key-pair";
pub const AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH: &str =
    "/_arkret/open/agent-pairing/runtime-key-requests";
pub const AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS_PATH: &str =
    "/_arkret/open/agent-pairing/runtime-key-requests/status";
pub const AGENTS_PATH: &str = "/_arkret/self/agents";
pub const AGENT_SIDECAR_THREAD_ENSURE_PATH: &str = "/_arkret/self/agent-sidecar-threads:ensure";

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

/// Builder for `ak.self.agent.command.provision` request bodies.
#[derive(Clone, Debug)]
pub struct AgentProvisionRequestBuilder {
    display_name: Option<String>,
    slug: String,
    avatar_blob_ref: Option<crate::BlobRef>,
    requested_scope: crate::AgentKeyScope,
    accountability: Value,
    pairing_ttl_ms: Option<u64>,
}

impl AgentProvisionRequestBuilder {
    pub fn new(slug: impl Into<String>, requested_scope: crate::AgentKeyScope) -> Self {
        Self {
            display_name: None,
            slug: slug.into(),
            avatar_blob_ref: None,
            requested_scope,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        }
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn avatar_blob_ref(mut self, avatar_blob_ref: crate::BlobRef) -> Self {
        self.avatar_blob_ref = Some(avatar_blob_ref);
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
            slug: self.slug,
            avatar_blob_ref: self.avatar_blob_ref,
            requested_scope: self.requested_scope,
            accountability: self.accountability,
            pairing_ttl_ms: self.pairing_ttl_ms,
        }
    }
}

pub fn agent_pairing_bootstrap(
    arkret_base_url: impl Into<String>,
    service_id: Did,
    agent_id: Did,
    pairing_request_id: impl Into<String>,
    pairing_code: impl Into<String>,
    pairing_expires_at: DateTime<Utc>,
) -> AgentPairingBootstrap {
    AgentPairingBootstrap {
        arkret_base_url: arkret_base_url.into(),
        service_id,
        agent_id,
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
    agent_actor_id: Did,
    controller_id: Did,
    controller_authorization_ref: impl Into<String>,
    actor_seq: u64,
    hlc: Hlc,
) -> Result<Event> {
    let mut event = Event::new(
        OP_AGENT_KEY_AUTHORIZE,
        realm_id,
        agent_actor_id,
        actor_seq,
        hlc,
        agent_key_authorize_payload_value(payload)?,
    )?;
    event.executed_by = Some(controller_id);
    event.authorization_ref = Some(controller_authorization_ref.into());
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_agent_key_authorize_event<S: arkret_core::MoveSigner + ?Sized>(
    payload: &AgentKeyAuthorizePayload,
    realm_id: RealmId,
    agent_actor_id: Did,
    controller_id: Did,
    controller_authorization_ref: impl Into<String>,
    actor_seq: u64,
    hlc: Hlc,
    controller_signer: &S,
    controller_verification_method: &str,
    proof_options: arkret_signatures::SignEventOptions,
) -> Result<Event> {
    let mut event = build_agent_key_authorize_event(
        payload,
        realm_id,
        agent_actor_id,
        controller_id,
        controller_authorization_ref,
        actor_seq,
        hlc,
    )?;
    arkret_signatures::sign_event(
        &mut event,
        controller_signer,
        controller_verification_method,
        proof_options,
    )?;
    Ok(event)
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
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        &value,
    )?)?)
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_signing_input_for_session_grant(
    principal_id: &Did,
    requested_scope: &[String],
    agent_key_authorization_ref: &str,
    agent_scope_request: &SessionGrantAgentScopeRequest,
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
    agent_scope_request: SessionGrantAgentScopeRequest,
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
    agent_scope_request: SessionGrantAgentScopeRequest,
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
        agent_scope_request: Some(agent_scope_request),
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
        grant: grant.clone(),
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

pub fn plan_agent_runtime_approval_status(
    body: AgentRuntimeApprovalStatusRequestBody,
) -> AgentRequestPlan<AgentRuntimeApprovalStatusRequestBody> {
    AgentRequestPlan::with_body(
        OP_OPEN_AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS,
        AgentHttpMethod::Post,
        AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS_PATH,
        body,
    )
}

pub fn plan_agent_provision(
    body: AgentProvisionRequestBody,
) -> AgentRequestPlan<AgentProvisionRequestBody> {
    AgentRequestPlan::with_body(OP_AGENT_PROVISION, AgentHttpMethod::Post, AGENTS_PATH, body)
}

pub fn plan_agent_renew_pairing(
    agent_id: &str,
    body: AgentRenewPairingRequestBody,
) -> AgentRequestPlan<AgentRenewPairingRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_RENEW_PAIRING,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/renew-pairing",
            AGENTS_PATH,
            agent_path_component(agent_id)
        ),
        body,
    )
}

pub fn plan_agent_list() -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(OP_AGENT_LIST, AgentHttpMethod::Get, AGENTS_PATH)
}

pub fn plan_agent_get(agent_id: &str) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GET,
        AgentHttpMethod::Get,
        format!("{}/{}", AGENTS_PATH, agent_path_component(agent_id)),
    )
}

pub fn plan_agent_pause(
    agent_id: &str,
    body: AgentPauseRequestBody,
) -> AgentRequestPlan<AgentPauseRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_PAUSE,
        AgentHttpMethod::Post,
        format!("{}/{}/pause", AGENTS_PATH, agent_path_component(agent_id)),
        body,
    )
}

pub fn plan_agent_resume(
    agent_id: &str,
    body: AgentResumeRequestBody,
) -> AgentRequestPlan<AgentResumeRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_RESUME,
        AgentHttpMethod::Post,
        format!("{}/{}/resume", AGENTS_PATH, agent_path_component(agent_id)),
        body,
    )
}

pub fn plan_agent_deactivate(
    agent_id: &str,
    body: AgentDeactivateRequestBody,
) -> AgentRequestPlan<AgentDeactivateRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_DEACTIVATE,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/deactivate",
            AGENTS_PATH,
            agent_path_component(agent_id)
        ),
        body,
    )
}

pub fn plan_agent_grant_attach(
    agent_id: &str,
    body: AgentGrantAttachRequestBody,
) -> AgentRequestPlan<AgentGrantAttachRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_GRANT_ATTACH,
        AgentHttpMethod::Post,
        format!("{}/{}/grants", AGENTS_PATH, agent_path_component(agent_id)),
        body,
    )
}

pub fn plan_agent_grant_detach(agent_id: &str, grant_id: &GrantId) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GRANT_DETACH,
        AgentHttpMethod::Delete,
        format!(
            "{}/{}/grants/{}",
            AGENTS_PATH,
            agent_path_component(agent_id),
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

#[cfg(test)]
mod tests {
    use arkret_canonical::canonical;
    use arkret_core::move_event::Move;
    use arkret_core::{MoveSignature, MoveSigner, UnsignedMove, proof_kind};
    use arkret_wire_base::Result as WireResult;
    use chrono::TimeZone;
    use ed25519_dalek::Verifier as _;
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

    fn event(kind: &str, actor_id: Did) -> Event {
        Event::new(
            kind,
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor_id,
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({}),
        )
        .unwrap()
    }

    fn authorize_event(actor_id: Did) -> Event {
        event(OP_AGENT_KEY_AUTHORIZE, actor_id)
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
        fn sign_move(&self, _unsigned: &UnsignedMove) -> WireResult<Move> {
            unreachable!("agent authorize helper only calls sign_payload");
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<MoveSignature> {
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
                "ak.message.create".to_owned(),
            ],
            resources: vec![AgentKeyScopeResource {
                kind: AgentKeyScopeResourceKind::Operation,
                realm_id: None,
                resource_ref: None,
                schema_ref: None,
                operation: Some(SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE.to_owned()),
                service_id: None,
            }],
            constraints: Vec::new(),
        }
    }

    #[test]
    fn personal_agent_request_plans_use_standard_paths() {
        let provision = AgentProvisionRequestBuilder::new("summary", test_scope())
            .display_name("summary agent")
            .avatar_blob_ref(
                crate::BlobRef::new(concat!(
                    "ak:blob:sha256:",
                    "01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
                ))
                .unwrap(),
            )
            .build();
        let plan = plan_agent_provision(provision);
        assert_eq!(plan.operation_id, OP_AGENT_PROVISION);
        assert_eq!(plan.method.as_str(), "POST");
        assert_eq!(plan.path, "/_arkret/self/agents");
        let body = plan.body_value().unwrap().unwrap();
        assert_eq!(body["display_name"], "summary agent");
        assert_eq!(body["slug"], "summary");
        assert_eq!(
            body["avatar_blob_ref"],
            concat!(
                "ak:blob:sha256:",
                "01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
            )
        );
        assert_eq!(
            body["requested_scope"]["actions"][0],
            SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE
        );
        assert_eq!(body["requested_scope"]["resources"][0]["kind"], "operation");

        let get = plan_agent_get("did:webvh:z6mkfixture:agent.example");
        assert_eq!(get.operation_id, OP_AGENT_GET);
        assert_eq!(get.method.as_str(), "GET");
        assert_eq!(
            get.path,
            "/_arkret/self/agents/did%3Awebvh%3Az6mkfixture%3Aagent.example"
        );

        let grant_id =
            GrantId::new("ak:grant:01964137-0000-7000-8000-000000000010".to_owned()).unwrap();
        let detach = plan_agent_grant_detach("did:webvh:z6mkfixture:agent.example", &grant_id);
        assert_eq!(detach.operation_id, OP_AGENT_GRANT_DETACH);
        assert_eq!(detach.method.as_str(), "DELETE");
        assert_eq!(
            detach.path,
            "/_arkret/self/agents/did%3Awebvh%3Az6mkfixture%3Aagent.example/grants/ak%3Agrant%3A01964137-0000-7000-8000-000000000010"
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
                "kid": format!("{}#runtime-key-1", agent_id.as_str()),
                "alg": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }),
            json!({"challenge": "pairing", "signature": "sig"}),
            authorize_event(agent_id.clone()),
        )
        .runtime_attestation(AgentKeyAuthorizePayloadRuntimeAttestation {
            kind: AgentKeyRuntimeAttestationKind::SelfAsserted,
            software: None,
            version: None,
            attestation_digest: None,
            evidence_ref: None,
        })
        .build()
        .unwrap();

        assert_eq!(
            body.pairing_request_id.as_str(),
            "01970000-0000-7000-8000-000000000020"
        );
        assert_eq!(body.agent_id, agent_id);
        assert_eq!(body.authorize_event.kind.as_str(), OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(
            body.runtime_attestation.as_ref().unwrap().kind,
            AgentKeyRuntimeAttestationKind::SelfAsserted
        );

        let err = AgentKeyPairRequestBuilder::new(
            "01970000-0000-7000-8000-000000000020",
            did("agent2"),
            "did:webvh:z6mkfixture:agent2.example#runtime-key-1",
            json!({}),
            json!({}),
            event("ak.message.create", did("agent2")),
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn runtime_key_request_builder_assembles_both_wire_shapes() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_id = did("runtime-builder");
        let expires_at = "2026-05-26T10:05:00Z".parse::<DateTime<Utc>>().unwrap();
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: Did::new("did:webvh:z6mkfixture:service.example".to_owned()).unwrap(),
            agent_id: agent_id.clone(),
            pairing_request_id: "01970000-0000-7000-8000-000000000021".to_owned(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at: expires_at,
        };
        let builder = RuntimeKeyRequestBuilder::new(&signing_key, bootstrap);
        let approval = builder.build_approval_request().unwrap();
        let pairing = builder
            .build_key_pair_request(authorize_event(agent_id.clone()))
            .unwrap();

        assert_eq!(approval.public_key_digest, pairing.public_key_digest);
        assert_eq!(
            serde_json::to_value(&approval.body.public_key).unwrap(),
            serde_json::to_value(&pairing.body.public_key).unwrap()
        );
        assert_eq!(
            approval.body.proof_of_possession.as_map()["request_canonical_digest"],
            pairing.body.proof_of_possession.as_map()["request_canonical_digest"]
        );
        assert_eq!(approval.body.pairing_code.as_str(), "12345678");
        assert_eq!(pairing.body.agent_id, agent_id);
        assert!(
            !approval.body.proof_of_possession.as_map()["signature"]
                .as_str()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn runtime_key_request_builder_signs_the_wire_timestamp_precision() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_id = did("runtime-builder-submillisecond");
        let expires_at = "2026-07-14T14:43:48.784473Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: Did::new("did:webvh:z6mkfixture:service.example".to_owned()).unwrap(),
            agent_id,
            pairing_request_id: "01970000-0000-7000-8000-000000000022".to_owned(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at: expires_at,
        };
        let request = RuntimeKeyRequestBuilder::new(&signing_key, bootstrap)
            .build_approval_request()
            .unwrap();
        let proof = request.body.proof_of_possession.as_map();
        let proof_expires_at = proof["expires_at"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap();
        let request_digest = Hash::new(
            proof["request_canonical_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let signing_input = agent_key_pair_proof_signing_input(
            request.body.verification_method.to_string(),
            proof["challenge"].as_str().unwrap(),
            proof["audience"].as_str().unwrap(),
            proof_expires_at,
            request_digest,
        );
        let signature =
            arkret_canonical::base64url_decode(proof["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();

        assert_eq!(proof["expires_at"], "2026-07-14T14:43:48.784Z");
        signing_key
            .verifying_key()
            .verify(&signing_input.canonical_bytes().unwrap(), &signature)
            .expect("signature must bind the timestamp sent on the wire");
    }

    #[test]
    fn agent_pairing_bootstrap_serializes_spec_shape() {
        let bootstrap = agent_pairing_bootstrap(
            "https://arkret.example",
            did("service"),
            did("agent"),
            "01970000-0000-7000-8000-000000000020",
            "R7K9-2M4P",
            Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap(),
        );
        let value = serde_json::to_value(bootstrap).unwrap();

        // AKP-0008 §4.4: exactly six fields, no scope payload.
        assert_eq!(value["arkret_base_url"], "https://arkret.example");
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
            agent_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{}#runtime-key-1", agent_id.as_str()),
            public_key_digest: None,
            accountable_principal_id: controller_id.clone(),
            agent_key_scope: test_scope(),
            audience: vec!["https://arkret.example".to_owned()],
            issued_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 0, 0).unwrap(),
            expires_at: Some(Utc.with_ymd_and_hms(2026, 5, 26, 10, 15, 0).unwrap()),
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::ApprovalEvent,
                evidence_ref: Some("ak:event:01970000-0000-7000-8000-000000000021".to_owned()),
                request_canonical_digest: None,
                pairing_request_id: None,
                approved_by: Some(controller_id.clone()),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };

        let event = build_agent_key_authorize_event(
            &payload,
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            agent_id.clone(),
            controller_id.clone(),
            format!("{}#managed-controller", agent_id.as_str()),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        )
        .unwrap();

        assert_eq!(event.kind.as_str(), OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(event.actor_id, agent_id);
        assert_eq!(event.executed_by, Some(controller_id));
        assert_eq!(
            event.authorization_ref.as_deref(),
            Some("did:webvh:z6mkfixture:agent.example#managed-controller")
        );
        assert_eq!(event.actor_seq, 7);
        assert_eq!(event.payload["agent_id"], agent_id.as_str());
        assert_eq!(
            event.payload["agent_key_scope"]["actions"][0],
            SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE
        );
        assert_eq!(
            event.payload["verification_method"],
            "did:webvh:z6mkfixture:agent.example#runtime-key-1"
        );
        let canonical_content =
            String::from_utf8(canonical::canonical_json_bytes(&event.payload).unwrap()).unwrap();
        assert_eq!(
            canonical_content,
            r#"{"accountable_principal_id":"did:webvh:z6mkfixture:controller.example","agent_id":"did:webvh:z6mkfixture:agent.example","agent_key_scope":{"actions":["ak.self.events.stream.subscribe","ak.message.create"],"resources":[{"kind":"operation","operation":"ak.self.events.stream.subscribe"}]},"approval_evidence":{"approved_by":"did:webvh:z6mkfixture:controller.example","evidence_ref":"ak:event:01970000-0000-7000-8000-000000000021","kind":"approval_event"},"audience":["https://arkret.example"],"expires_at":"2026-05-26T10:15:00Z","issued_at":"2026-05-26T10:00:00Z","key_id":"runtime-key-1","verification_method":"did:webvh:z6mkfixture:agent.example#runtime-key-1"}"#
        );
    }

    #[test]
    fn signed_agent_key_authorize_event_builder_attaches_controller_proof() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let payload = AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{}#runtime-key-1", agent_id.as_str()),
            public_key_digest: None,
            accountable_principal_id: controller_id.clone(),
            agent_key_scope: test_scope(),
            audience: vec!["https://arkret.example".to_owned()],
            issued_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 0, 0).unwrap(),
            expires_at: Some(Utc.with_ymd_and_hms(2026, 5, 26, 10, 15, 0).unwrap()),
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::ApprovalEvent,
                evidence_ref: Some("ak:event:01970000-0000-7000-8000-000000000021".to_owned()),
                request_canonical_digest: None,
                pairing_request_id: None,
                approved_by: Some(controller_id.clone()),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let controller_vm = format!("{}#controller-key-1", controller_id.as_str());
        let signer = StubMoveSigner::new(controller_id.clone(), controller_vm.clone());
        let event = build_signed_agent_key_authorize_event(
            &payload,
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            agent_id.clone(),
            controller_id.clone(),
            format!("{}#managed-controller", agent_id.as_str()),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            &signer,
            &controller_vm,
            arkret_signatures::SignEventOptions::new()
                .with_created_at(Utc.with_ymd_and_hms(2026, 5, 26, 10, 1, 0).unwrap()),
        )
        .unwrap();

        assert_eq!(event.kind.as_str(), OP_AGENT_KEY_AUTHORIZE);
        assert_eq!(event.actor_id, agent_id);
        assert_eq!(event.executed_by, Some(controller_id));
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
            "ak.message.create".to_owned(),
        ];
        let agent_scope_request = SessionGrantAgentScopeRequest {
            realm_ids: vec![RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()],
            strand_ids: Vec::new(),
            track_names: vec![NonEmptyString::new("summary").unwrap()],
        };
        let dpop_binding_proof = SessionGrantDpopBindingProof {
            proof_jwt: "dpop.jwt.value".to_owned(),
        };
        let expires_at = Utc.with_ymd_and_hms(2026, 5, 26, 10, 5, 0).unwrap();
        let authorization_ref = "ak:event:01970000-0000-7000-8000-000000000021";
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
            "https://arkret.example",
            expires_at,
        )
        .unwrap();
        let signing_json = String::from_utf8(signing_input.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            signing_json,
            r#"{"audience":"https://arkret.example","challenge":"challenge","expires_at":"2026-05-26T10:05:00Z","nonce":"nonce-abc","request_canonical_digest":"sha256:989eefe3158e7cc381de4f12283b08217e3db5c3717c4669f665c7b9f26b7cd4","verification_method":"did:webvh:z6mkfixture:agent.example#runtime-key-1"}"#
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
            "https://arkret.example",
            expires_at,
            "agent-key-signature",
        )
        .unwrap();
        let digest = agent_key_proof_request_binding_digest(&request).unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:989eefe3158e7cc381de4f12283b08217e3db5c3717c4669f665c7b9f26b7cd4"
        );
        assert_eq!(request.principal_id.as_ref(), Some(&principal_id));
        assert_eq!(request.device_id, None);
        assert_eq!(request.requested_scope, requested_scope);
        assert_eq!(
            request.agent_key_authorization_ref.as_deref(),
            Some(authorization_ref)
        );
        assert_eq!(
            serde_json::to_value(request.agent_scope_request.as_ref().unwrap()).unwrap(),
            serde_json::to_value(&agent_scope_request).unwrap()
        );
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
            "ak.message.create"
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
    fn runtime_approval_poll_schedule_honors_server_delay_and_caps_fallback() {
        let mut schedule = AgentRuntimeApprovalPollSchedule::default();
        let expected = [1, 2, 5, 10, 30, 30];
        for seconds in expected {
            assert_eq!(schedule.next_delay(None), Duration::from_secs(seconds));
        }
        assert_eq!(
            schedule.next_delay(Some(Duration::from_secs(17))),
            Duration::from_secs(17)
        );
        schedule.reset();
        assert_eq!(schedule.next_delay(None), Duration::from_secs(1));
    }
}
