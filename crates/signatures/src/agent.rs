//! Agent key-pairing canonical binding helpers.

use arkret_canonical::{base64url_decode, canonical};
/// The immutable provision ceiling commitment digest is defined with the
/// agent lifecycle models and surfaced by the signature owner.
pub use arkret_models_collaboration::agent_operations::agent_requested_scope_digest;
use arkret_models_collaboration::agent_operations::{
    AgentKeyPairRequestBody, AgentPairingBootstrap, AgentRequestedScopeDisclosure,
    AgentRuntimeApprovalRequestBody,
};
use arkret_models_collaboration::agent_signer_evidence::AgentSigningKeyBinding;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation;
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_wire::{
    Did, DidUrl, Event, EventInitialSubmission, EventKind, Hash, NonEmptyJsonObject,
    NonEmptyString, ServiceOperationId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Canonical transcript signed by an agent runtime when pairing its key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyPairProofSigningInput {
    pub audience: String,
    pub challenge: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub request_canonical_digest: Hash,
    pub verification_method: DidUrl,
}

impl AgentKeyPairProofSigningInput {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

pub fn agent_key_pair_proof_signing_input(
    verification_method: DidUrl,
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
        verification_method,
    }
}

/// A runtime-key request body together with the digest of its generated
/// public key. The digest is reused by the controller-side authorize event.
#[derive(Clone, Debug)]
pub struct RuntimeKeyRequest<T> {
    pub body: T,
    pub public_key_digest: Hash,
}

/// Build and sign the two runtime-key pairing request shapes from one
/// bootstrap and Ed25519 signing key.
pub struct RuntimeKeyRequestBuilder<'a> {
    signing_key: &'a SigningKey,
    bootstrap: AgentPairingBootstrap,
    verification_method: String,
    proof_expires_at: DateTime<Utc>,
    runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

impl<'a> RuntimeKeyRequestBuilder<'a> {
    pub fn new(signing_key: &'a SigningKey, bootstrap: AgentPairingBootstrap) -> Self {
        let key_digest = arkret_canonical::sha256_digest(signing_key.verifying_key().to_bytes());
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
                pairing_request_id: self.bootstrap.pairing_request_id.clone(),
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
        requested_scope_disclosure: AgentRequestedScopeDisclosure,
        signing_key_binding: AgentSigningKeyBinding,
        authorize_event: EventInitialSubmission,
    ) -> Result<RuntimeKeyRequest<AgentKeyPairRequestBody>> {
        requested_scope_disclosure
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if requested_scope_disclosure.agent_id != self.bootstrap.agent_id
            || requested_scope_disclosure.verifier_did != self.bootstrap.service_id
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
            public_key_digest,
        })
    }

    fn request_material(&self) -> Result<(PublicKey, Hash, NonEmptyJsonObject)> {
        let public_key_value = self.public_key()?;
        let public_key: PublicKey = serde_json::from_value(public_key_value.clone())?;
        let public_key_digest = agent_runtime_public_key_digest(&public_key_value)?;
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
            DidUrl::new(self.verification_method.clone())
                .map_err(|reason| Error::Protocol(reason.to_owned()))?,
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
            "expires_at": arkret_canonical::format_timestamp_canonical(proof_expires_at),
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

fn validate_pairing_authorize_event(authorize_event: &Event, agent_id: &Did) -> Result<()> {
    if authorize_event.kind.as_str() != EventKind::AGENT_KEY_AUTHORIZE {
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
struct AgentKeyPairingRequestBinding<'a> {
    kind: &'static str,
    operation_id: &'static str,
    controller_id: &'a str,
    agent_id: &'a str,
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
    agent_id: &'a str,
    verification_method: &'a str,
    public_key: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_attestation: Option<&'a Value>,
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
    if key.alg.as_str() != "Ed25519" && key.alg.as_str() != "EdDSA" {
        return Err(Error::Protocol(
            "agent runtime public_key.alg must be Ed25519 or EdDSA".to_owned(),
        ));
    }
    if key.kid.trim().is_empty() {
        return Err(Error::Protocol(
            "agent runtime public_key.kid must not be empty".to_owned(),
        ));
    }
    if base64url_decode(key.key.as_bytes())?.len() != 32 {
        return Err(Error::Protocol(
            "agent runtime public_key.key must be a 32-byte Ed25519 key".to_owned(),
        ));
    }
    Hash::new(canonical::canonical_sha256(&public_key)?).map_err(Error::from)
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
    agent_id: &Did,
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
    agent_id: &Did,
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

#[allow(clippy::too_many_arguments)]
pub fn agent_key_pairing_request_binding_digest(
    controller_id: &Did,
    agent_id: &Did,
    verification_method: &str,
    runtime_public_key_digest: &Hash,
    pairing_request_id: &str,
    pairing_code: &str,
    pairing_expires_at: &str,
    audience: &str,
) -> Result<Hash> {
    // The pairing binding has a protocol-specific timestamp spelling.  Do not
    // let database precision or an equivalent RFC 3339 offset change a signed
    // digest for the same millisecond.
    let parsed_expires_at = DateTime::parse_from_rfc3339(pairing_expires_at).map_err(|error| {
        Error::Protocol(format!(
            "agent pairing_expires_at must be RFC 3339: {error}"
        ))
    })?;
    let pairing_expires_at =
        canonical::format_timestamp_canonical(parsed_expires_at.with_timezone(&Utc));
    Hash::new(canonical::canonical_sha256(
        &AgentKeyPairingRequestBinding {
            kind: "ak.agent.key_pairing_request_binding.v1",
            operation_id: ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            controller_id: controller_id.as_str(),
            agent_id: agent_id.as_str(),
            verification_method,
            runtime_public_key_digest: runtime_public_key_digest.as_str(),
            pairing_request_id,
            pairing_code,
            expires_at: &pairing_expires_at,
            audience,
        },
    )?)
    .map_err(Error::from)
}

pub fn agent_key_pair_proof_request_binding_digest(
    pairing_request_id: &str,
    agent_id: &Did,
    verification_method: &str,
    public_key: &Value,
    runtime_attestation: Option<&Value>,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentKeyPairProofRequestBinding {
            kind: "ak.agent.key_pair_proof_of_possession_request.v1",
            operation_id: ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            pairing_request_id,
            agent_id: agent_id.as_str(),
            verification_method,
            public_key,
            runtime_attestation,
        },
    )?)
    .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, DeviceId, EventId, Hlc,
        LeaseBasisRef, Proof, RealmId, RequestId, RiskTier, SchemaId, SealId,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn initial_submission(event: Event) -> EventInitialSubmission {
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
                    verification_method: DidUrl::new(format!("{}#controller", event.actor_id))
                        .unwrap(),
                }],
                threshold: 1,
            }],
        };
        EventInitialSubmission {
            authorization_lease: AuthorizationLease {
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
            },
            event,
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: None,
        }
    }

    #[test]
    fn runtime_key_binding_matches_normative_vector() {
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let public_key = json!({
            "alg": "EdDSA",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
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

        assert_eq!(
            public_key_digest.as_str(),
            "sha256:7bfcb9251367ab71fd32c19fc23c11b46ddbc371b52fcb5a75eaa1a79f5f463b"
        );
        assert_eq!(
            attestation_digest.as_str(),
            "sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
        );
        assert_eq!(
            binding_digest.as_str(),
            "sha256:1dd1a4f03dfc6086a43ae3f0e1eca877c9040c25fd95fc48d1b278568306fb06"
        );
    }

    #[test]
    fn runtime_key_binding_changes_when_key_material_changes() {
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let first = json!({
            "alg": "EdDSA",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
            "kty": "OKP"
        });
        let second = json!({
            "alg": "EdDSA",
            "key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
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
    fn pairing_request_binding_normalizes_expiry_to_utc_milliseconds() {
        let controller_id = Did::new("did:webvh:z6mkcontroller:controller.example").unwrap();
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let public_key_digest =
            Hash::new("sha256:7bfcb9251367ab71fd32c19fc23c11b46ddbc371b52fcb5a75eaa1a79f5f463b")
                .unwrap();
        let digest = |expires_at: &str| {
            agent_key_pairing_request_binding_digest(
                &controller_id,
                &agent_id,
                "did:webvh:z6mkagent:agent.example#runtime-1",
                &public_key_digest,
                "pairing_request:01964137-0000-7000-8000-000000000000",
                "fixture-pairing-code",
                expires_at,
                "https://pair.example/_arkret/gate/account/agent-key-pair",
            )
            .unwrap()
        };

        let canonical = digest("2026-07-17T13:50:07.734Z");
        assert_eq!(
            canonical.as_str(),
            "sha256:efa5a4362f7e9da83f03aaa986faeac77140d8b15e8e62c8842d4a78c5eb6661"
        );
        assert_eq!(canonical, digest("2026-07-17T13:50:07.734997Z"));
        assert_eq!(canonical, digest("2026-07-17T21:50:07.734+08:00"));
    }

    #[test]
    fn pairing_request_binding_rejects_invalid_expiry() {
        let controller_id = Did::new("did:webvh:z6mkcontroller:controller.example").unwrap();
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let public_key_digest =
            Hash::new("sha256:7bfcb9251367ab71fd32c19fc23c11b46ddbc371b52fcb5a75eaa1a79f5f463b")
                .unwrap();

        assert!(
            agent_key_pairing_request_binding_digest(
                &controller_id,
                &agent_id,
                "did:webvh:z6mkagent:agent.example#runtime-1",
                &public_key_digest,
                "pairing_request:01964137-0000-7000-8000-000000000000",
                "fixture-pairing-code",
                "2026-07-17 13:50:07.734",
                "https://pair.example/_arkret/gate/account/agent-key-pair",
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_key_request_builder_signs_the_wire_timestamp_precision() {
        use ed25519_dalek::Verifier as _;

        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_id = Did::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id: Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
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
        let request = RuntimeKeyRequestBuilder::new(&signing_key, bootstrap)
            .build_approval_request()
            .unwrap();
        let proof = request.body.proof_of_possession.as_map();
        let proof_expires_at = proof["expires_at"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap();
        let request_digest =
            Hash::new(proof["request_canonical_digest"].as_str().unwrap()).unwrap();
        let signing_input = agent_key_pair_proof_signing_input(
            request.body.verification_method.clone(),
            proof["challenge"].as_str().unwrap(),
            proof["audience"].as_str().unwrap(),
            proof_expires_at,
            request_digest,
        );
        let signature = base64url_decode(proof["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();

        assert_eq!(proof["expires_at"], "2026-07-14T14:43:48.784Z");
        signing_key
            .verifying_key()
            .verify(&signing_input.canonical_bytes().unwrap(), &signature)
            .expect("signature must bind the timestamp sent on the wire");
    }

    #[test]
    fn runtime_key_request_builder_assembles_both_pairing_shapes() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let agent_id = Did::new("did:webvh:z6mkfixture:runtime-builder.agent.example").unwrap();
        let controller_id = Did::new("did:webvh:z6mkfixture:controller.example").unwrap();
        let service_id = Did::new("did:webvh:z6mkfixture:service.example").unwrap();
        let pairing_request_id = "agent_pairing_request:01970000-0000-7000-8000-000000000021";
        let issued_at = Utc.with_ymd_and_hms(2026, 7, 17, 0, 0, 0).unwrap();
        let requested_scope = AgentKeyScope {
            actions: vec!["ak.message.create".to_owned()],
            resources: vec![],
            constraints: vec![],
        };
        let mut disclosure = AgentRequestedScopeDisclosure {
            schema: SchemaId::AGENT_REQUESTED_SCOPE_DISCLOSURE_V1.to_owned(),
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000021").unwrap(),
            agent_id: agent_id.clone(),
            controller_id: controller_id.clone(),
            requested_scope_digest: agent_requested_scope_digest(
                &agent_id,
                &controller_id,
                &requested_scope,
            )
            .unwrap(),
            requested_scope,
            verifier_did: service_id.clone(),
            audience: NonEmptyString::new(ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY)
                .unwrap(),
            challenge: NonEmptyString::new(pairing_request_id).unwrap(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
            proofs: vec![Proof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: DidUrl::new(format!("{controller_id}#key-1")).unwrap(),
                event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
            }],
        };
        disclosure.proofs[0].event_digest = disclosure.payload_digest().unwrap();
        let authorize_event = Event::new(
            EventKind::AGENT_KEY_AUTHORIZE,
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            },
            agent_id.clone(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({}),
        )
        .unwrap();
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://arkret.example".to_owned(),
            service_id,
            agent_id: agent_id.clone(),
            pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id).unwrap(),
            pairing_code: "12345678".to_owned(),
            pairing_expires_at: issued_at + chrono::Duration::minutes(5),
        };
        let builder = RuntimeKeyRequestBuilder::new(&signing_key, bootstrap);

        let approval = builder.build_approval_request().unwrap();
        let pairing = builder
            .build_key_pair_request(
                disclosure,
                super::super::agent_evidence::build_agent_signing_key_binding(
                    agent_id.clone(),
                    NonEmptyString::new(format!("{agent_id}#runtime-key-1")).unwrap(),
                    DidUrl::new(format!("{agent_id}#runtime-key-1")).unwrap(),
                    signing_key.verifying_key().to_bytes(),
                    EventId::new("ak:event:01970000-0000-7000-8000-000000000099").unwrap(),
                    issued_at,
                    None,
                    controller_id.clone(),
                    DidUrl::new(format!("{controller_id}#key-1")).unwrap(),
                    &SigningKey::from_bytes(&[3_u8; 32]),
                )
                .unwrap(),
                initial_submission(authorize_event),
            )
            .unwrap();

        assert_eq!(approval.public_key_digest, pairing.public_key_digest);
        assert_eq!(
            serde_json::to_value(approval.body.public_key).unwrap(),
            serde_json::to_value(pairing.body.public_key).unwrap()
        );
        assert_eq!(pairing.body.agent_id, agent_id);
    }
}
