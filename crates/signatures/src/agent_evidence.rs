//! Native Agent signer-binding, evidence, and ordinary-MLS verification.

use arkret_canonical::{base64url_decode, canonical};
use arkret_models_collaboration::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_SIGNER_EVIDENCE_SCHEMA, AGENT_SIGNING_KEY_BINDING_CONTEXT,
    AGENT_SIGNING_KEY_BINDING_SCHEMA, AgentAuthorizationStatus, AgentControllerProof,
    AgentSignerEvidence, AgentSigningKeyBinding, AgentSigningPublicKey, KEY_TRANSPARENCY_PROFILE,
};
use arkret_wire::{Did, DidUrl, Event, EventId, Hash, NonEmptyString};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::agent::agent_runtime_public_key_digest;
use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_eddsa_detached_jws};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentSigningKey {
    pub signer: Did,
    pub key: [u8; 32],
    pub authorization_ref: EventId,
    pub accepted_frontier: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentEvidenceUnresolvedReason {
    Missing,
    Stale,
}

impl AgentEvidenceUnresolvedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "agent_signer_evidence_missing",
            Self::Stale => "agent_signer_evidence_stale",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentEvidenceRejectedReason {
    AuthorizationInactive,
    AuthorizationConflicted,
    SigningKeyMismatch,
    MlsLeafBindingMismatch,
}

impl AgentEvidenceRejectedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationInactive => "agent_authorization_inactive",
            Self::AuthorizationConflicted => "agent_authorization_conflicted",
            Self::SigningKeyMismatch => "agent_signing_key_mismatch",
            Self::MlsLeafBindingMismatch => "agent_mls_leaf_binding_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentSignerEvidenceVerdict {
    Verified(VerifiedAgentSigningKey),
    Unresolved(AgentEvidenceUnresolvedReason),
    Rejected(AgentEvidenceRejectedReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierRelation {
    Covers,
    Behind,
    Conflict,
}

pub struct AgentSignerEvidenceValidationContext<'a> {
    pub signer_id: &'a Did,
    pub controller_id: &'a Did,
    pub verification_method: &'a DidUrl,
    pub agent_key_authorize_event_id: &'a EventId,
    pub authorize_public_key_digest: &'a Hash,
    pub authorize_signing_key_binding_digest: &'a Hash,
    pub event_accepted_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub controller_public_key: &'a PublicKeyMaterial,
    pub state_witness_verified: bool,
    pub freshness_signature_verified: bool,
    pub freshness_relation_to_event: FrontierRelation,
    pub require_transparency: bool,
    pub transparency_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerPrincipalKind {
    Device,
    NativeAgent,
    Applet,
    Service,
    Integration,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRegime {
    MinimalMetadata,
    OrdinaryDevice,
    OrdinaryNativeAgent,
    AppletOrService,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSignerBinding {
    pub binding_actor_id: Did,
    pub signer_id: Did,
}

pub fn event_signer_binding(event: &Event) -> EventSignerBinding {
    EventSignerBinding {
        binding_actor_id: event.actor_id.clone(),
        signer_id: event
            .executed_by
            .clone()
            .unwrap_or_else(|| event.actor_id.clone()),
    }
}

pub fn dispatch_signer_regime(
    minimal_metadata_realm: bool,
    principal_kind: SignerPrincipalKind,
) -> Result<SignerRegime, AgentEvidenceRejectedReason> {
    if minimal_metadata_realm {
        return Ok(SignerRegime::MinimalMetadata);
    }
    match principal_kind {
        SignerPrincipalKind::Device => Ok(SignerRegime::OrdinaryDevice),
        SignerPrincipalKind::NativeAgent => Ok(SignerRegime::OrdinaryNativeAgent),
        SignerPrincipalKind::Applet
        | SignerPrincipalKind::Service
        | SignerPrincipalKind::Integration => Ok(SignerRegime::AppletOrService),
        SignerPrincipalKind::Unknown => Err(AgentEvidenceRejectedReason::SigningKeyMismatch),
    }
}

pub fn verify_event_signer_controller(
    event: &Event,
    verification_method: &DidUrl,
) -> Result<EventSignerBinding, AgentEvidenceRejectedReason> {
    let binding = event_signer_binding(event);
    if did_url_controller(verification_method) != binding.signer_id.as_str() {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ok(binding)
}

pub fn agent_signing_key_binding_signing_bytes(
    binding: &AgentSigningKeyBinding,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    let mut value = serde_json::to_value(binding)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let proof = value
        .get_mut("controller_proof")
        .and_then(Value::as_object_mut)
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    proof
        .remove("jws")
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let canonical = canonical::canonical_json_bytes(&value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let mut bytes = Vec::with_capacity(AGENT_SIGNING_KEY_BINDING_CONTEXT.len() + canonical.len());
    bytes.extend_from_slice(AGENT_SIGNING_KEY_BINDING_CONTEXT.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn agent_signing_key_binding_digest(
    binding: &AgentSigningKeyBinding,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    Hash::new(
        canonical::canonical_sha256(binding)
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
    )
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

#[allow(clippy::too_many_arguments)]
pub fn build_agent_signing_key_binding(
    agent_id: Did,
    verification_method: DidUrl,
    agent_public_key: [u8; 32],
    agent_key_authorize_event_id: EventId,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    controller_id: Did,
    controller_verification_method: DidUrl,
    controller_signing_key: &SigningKey,
) -> Result<AgentSigningKeyBinding, AgentEvidenceRejectedReason> {
    let public_key = AgentSigningPublicKey {
        kty: NonEmptyString::new("OKP".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        alg: NonEmptyString::new("Ed25519".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            agent_public_key,
        ))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
    };
    let public_key_digest = binding_public_key_digest(&verification_method, &public_key)?;
    let mut binding = AgentSigningKeyBinding {
        schema: NonEmptyString::new(AGENT_SIGNING_KEY_BINDING_SCHEMA.to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        agent_id,
        verification_method,
        public_key,
        public_key_digest,
        agent_key_authorize_event_id,
        issued_at,
        expires_at,
        controller_id,
        controller_proof: AgentControllerProof {
            kind: NonEmptyString::new("detached_jws".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
            verification_method: controller_verification_method,
            jws: NonEmptyString::new("pending".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        },
    };
    let signing_bytes = agent_signing_key_binding_signing_bytes(&binding)?;
    let jws = sign_eddsa_detached_jws(controller_signing_key, &signing_bytes)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    binding.controller_proof.jws =
        NonEmptyString::new(jws).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(binding)
}

pub fn verify_agent_signing_key_binding(
    binding: &AgentSigningKeyBinding,
    expected_agent_id: &Did,
    expected_controller_id: &Did,
    expected_verification_method: &DidUrl,
    expected_authorize_event_id: &EventId,
    expected_public_key_digest: &Hash,
    expected_binding_digest: &Hash,
    controller_public_key: &PublicKeyMaterial,
) -> Result<[u8; 32], AgentEvidenceRejectedReason> {
    if binding.schema.as_str() != AGENT_SIGNING_KEY_BINDING_SCHEMA
        || &binding.agent_id != expected_agent_id
        || &binding.controller_id != expected_controller_id
        || &binding.verification_method != expected_verification_method
        || &binding.agent_key_authorize_event_id != expected_authorize_event_id
        || did_url_controller(&binding.verification_method) != binding.agent_id.as_str()
        || did_url_controller(&binding.controller_proof.verification_method)
            != binding.controller_id.as_str()
        || binding.controller_proof.kind.as_str() != "detached_jws"
        || binding.public_key.kty.as_str() != "OKP"
        || binding.public_key.alg.as_str() != "Ed25519"
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let raw = base64url_decode(binding.public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let public_key_digest =
        binding_public_key_digest(&binding.verification_method, &binding.public_key)?;
    if public_key_digest != binding.public_key_digest
        || &public_key_digest != expected_public_key_digest
        || agent_signing_key_binding_digest(binding)? != *expected_binding_digest
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            binding.controller_proof.jws.as_str(),
            &agent_signing_key_binding_signing_bytes(binding)?,
            controller_public_key,
        )
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(key)
}

pub fn validate_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &AgentSignerEvidenceValidationContext<'_>,
) -> AgentSignerEvidenceVerdict {
    let Some(evidence) = evidence else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
    };
    if evidence.schema.as_str() != AGENT_SIGNER_EVIDENCE_SCHEMA {
        return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let binding = &evidence.signing_key_binding;
    let key = match verify_agent_signing_key_binding(
        binding,
        context.signer_id,
        context.controller_id,
        context.verification_method,
        context.agent_key_authorize_event_id,
        context.authorize_public_key_digest,
        context.authorize_signing_key_binding_digest,
        context.controller_public_key,
    ) {
        Ok(key) => key,
        Err(reason) => return rejected(reason),
    };
    let authorization = &evidence.authorization;
    let witness = &evidence.state_witness;
    if authorization.authorized_event_id != *context.agent_key_authorize_event_id
        || witness.component.as_str() != AGENT_KEY_COMPONENT
        || witness.agent_id != *context.signer_id
        || witness.authorization_event_id != *context.agent_key_authorize_event_id
        || witness.accepted_frontier != authorization.accepted_frontier
        || !context.state_witness_verified
        || !context.freshness_signature_verified
    {
        return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    if authorization.status == AgentAuthorizationStatus::Conflicted
        || context.freshness_relation_to_event == FrontierRelation::Conflict
    {
        return rejected(AgentEvidenceRejectedReason::AuthorizationConflicted);
    }
    if context.event_accepted_at < authorization.not_before
        || authorization
            .expires_at
            .is_some_and(|expires_at| context.event_accepted_at >= expires_at)
    {
        return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
    }
    match authorization.status {
        AgentAuthorizationStatus::Revoked | AgentAuthorizationStatus::Superseded
            if authorization.valid_until_frontier.is_none()
                || authorization.transition_event_id.is_none() =>
        {
            return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
        }
        AgentAuthorizationStatus::Expired if authorization.expires_at.is_none() => {
            return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
        }
        _ => {}
    }
    let freshness = &evidence.freshness_attestation;
    if freshness.expires_at <= context.now
        || context.freshness_relation_to_event == FrontierRelation::Behind
    {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale);
    }
    if context.require_transparency {
        let Some(transparency) = evidence.transparency.as_ref() else {
            return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
        };
        if transparency.profile.as_str() != KEY_TRANSPARENCY_PROFILE
            || !context.transparency_verified
        {
            return rejected(AgentEvidenceRejectedReason::AuthorizationConflicted);
        }
    }
    AgentSignerEvidenceVerdict::Verified(VerifiedAgentSigningKey {
        signer: context.signer_id.clone(),
        key,
        authorization_ref: context.agent_key_authorize_event_id.clone(),
        accepted_frontier: authorization.accepted_frontier.clone(),
    })
}

fn binding_public_key_digest(
    verification_method: &DidUrl,
    public_key: &AgentSigningPublicKey,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    agent_runtime_public_key_digest(&serde_json::json!({
        "kty": public_key.kty,
        "kid": verification_method,
        "alg": public_key.alg,
        "key": public_key.key,
    }))
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn rejected(reason: AgentEvidenceRejectedReason) -> AgentSignerEvidenceVerdict {
    AgentSignerEvidenceVerdict::Rejected(reason)
}

fn did_url_controller(method: &DidUrl) -> &str {
    method.as_str().split_once('#').map_or("", |(did, _)| did)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_decode;
    use arkret_models_collaboration::agent_signer_evidence::{
        AgentAuthorizationEvidence, AgentAuthorizationStateWitness,
        AgentEvidenceFreshnessAttestation,
    };
    use arkret_wire::{RealmId, SealId};
    use chrono::TimeZone;

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn fixture_binding() -> AgentSigningKeyBinding {
        serde_json::from_value(serde_json::json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": "did:webvh:z6mkagent:agent.example",
            "verification_method": "did:webvh:z6mkagent:agent.example#runtime-1",
            "public_key": {
                "kty": "OKP",
                "alg": "Ed25519",
                "key": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
            },
            "public_key_digest": "sha256:bbeb7e8a892586b86114ab88cc60807dc588f3f5f29a428e69b46808f573bfa3",
            "agent_key_authorize_event_id": "ak:event:01964137-0000-7000-8000-000000000001",
            "issued_at": "2026-07-25T00:00:00.000Z",
            "controller_id": "did:webvh:z6mkcontroller:controller.example",
            "controller_proof": {
                "kind": "detached_jws",
                "verification_method": "did:webvh:z6mkcontroller:controller.example#ak:device:01964137-0000-7000-8000-000000000002",
                "jws": "eyJhbGciOiJFZERTQSJ9..DXRrooFsRtGE_A6m3IGglWVK8-YI9PUi96fMbZ3DvObUwAHzWS74LCuJlPKNKFSJBA_PZfZikQsDsDMA8_5XCg"
            }
        }))
        .unwrap()
    }

    #[test]
    fn binding_matches_byte_exact_spec_vector() {
        let binding = fixture_binding();
        let expected = base64url_decode("YWsuYWdlbnQtc2lnbmluZy1rZXktYmluZGluZy12MQp7ImFnZW50X2lkIjoiZGlkOndlYnZoOno2bWthZ2VudDphZ2VudC5leGFtcGxlIiwiYWdlbnRfa2V5X2F1dGhvcml6ZV9ldmVudF9pZCI6ImFrOmV2ZW50OjAxOTY0MTM3LTAwMDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMSIsImNvbnRyb2xsZXJfaWQiOiJkaWQ6d2Vidmg6ejZta2NvbnRyb2xsZXI6Y29udHJvbGxlci5leGFtcGxlIiwiY29udHJvbGxlcl9wcm9vZiI6eyJraW5kIjoiZGV0YWNoZWRfandzIiwidmVyaWZpY2F0aW9uX21ldGhvZCI6ImRpZDp3ZWJ2aDp6Nm1rY29udHJvbGxlcjpjb250cm9sbGVyLmV4YW1wbGUjYWs6ZGV2aWNlOjAxOTY0MTM3LTAwMDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMiJ9LCJpc3N1ZWRfYXQiOiIyMDI2LTA3LTI1VDAwOjAwOjAwLjAwMFoiLCJwdWJsaWNfa2V5Ijp7ImFsZyI6IkVkMjU1MTkiLCJrZXkiOiI2a3BzWS1LY1VncS05VkI3RXk3Ri1aVkhkcTYtdm51U1FoN3FhUlJHMGl3Iiwia3R5IjoiT0tQIn0sInB1YmxpY19rZXlfZGlnZXN0Ijoic2hhMjU2OmJiZWI3ZThhODkyNTg2Yjg2MTE0YWI4OGNjNjA4MDdkYzU4OGYzZjVmMjlhNDI4ZTY5YjQ2ODA4ZjU3M2JmYTMiLCJzY2hlbWEiOiJhay5zY2hlbWEuYWdlbnRfc2lnbmluZ19rZXlfYmluZGluZy52MSIsInZlcmlmaWNhdGlvbl9tZXRob2QiOiJkaWQ6d2Vidmg6ejZta2FnZW50OmFnZW50LmV4YW1wbGUjcnVudGltZS0xIn0").unwrap();
        assert_eq!(
            agent_signing_key_binding_signing_bytes(&binding).unwrap(),
            expected
        );
        assert_eq!(
            agent_signing_key_binding_digest(&binding).unwrap().as_str(),
            "sha256:2bf3cb25763e2c50c42b4a5b71978fa79b17cc97162ca540d1fbc3e6ca05e724"
        );
        let controller_key: [u8; 32] =
            base64url_decode("7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E")
                .unwrap()
                .try_into()
                .unwrap();
        let verified = verify_agent_signing_key_binding(
            &binding,
            &binding.agent_id,
            &binding.controller_id,
            &binding.verification_method,
            &binding.agent_key_authorize_event_id,
            &binding.public_key_digest,
            &agent_signing_key_binding_digest(&binding).unwrap(),
            &PublicKeyMaterial::Ed25519Raw {
                bytes: controller_key.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            arkret_canonical::base64url_encode(verified),
            binding.public_key.key.as_str()
        );
    }

    #[test]
    fn delegated_signer_keeps_actor_binding_separate() {
        let actor = did("did:webvh:z6mkcontroller:controller.example");
        let signer = did("did:webvh:z6mkagent:agent.example");
        let mut event = Event::new(
            arkret_wire::EventKind::MESSAGE_CREATE,
            RealmId::new("ak:realm:01964137-0000-7000-8000-000000000009").unwrap(),
            actor.clone(),
            1,
            arkret_wire::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.executed_by = Some(signer.clone());
        let binding = verify_event_signer_controller(
            &event,
            &DidUrl::new(format!("{signer}#runtime-1")).unwrap(),
        )
        .unwrap();
        assert_eq!(binding.binding_actor_id, actor);
        assert_eq!(binding.signer_id, signer);
    }

    #[test]
    fn stale_evidence_never_verifies() {
        let binding = fixture_binding();
        let mut evidence = AgentSignerEvidence {
            schema: NonEmptyString::new(AGENT_SIGNER_EVIDENCE_SCHEMA.to_owned()).unwrap(),
            authorization: AgentAuthorizationEvidence {
                status: AgentAuthorizationStatus::Active,
                authorized_event_id: binding.agent_key_authorize_event_id.clone(),
                accepted_frontier: NonEmptyString::new("frontier:7".to_owned()).unwrap(),
                accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
                valid_from_frontier: NonEmptyString::new("frontier:7".to_owned()).unwrap(),
                not_before: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
                valid_until_frontier: None,
                expires_at: None,
                transition_event_id: None,
            },
            state_witness: AgentAuthorizationStateWitness {
                component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned()).unwrap(),
                agent_id: binding.agent_id.clone(),
                authorization_event_id: binding.agent_key_authorize_event_id.clone(),
                accepted_frontier: NonEmptyString::new("frontier:7".to_owned()).unwrap(),
                seal_id: SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap(),
                state_root: hash('2'),
                leaf_digest: hash('3'),
                inclusion_proof: vec![],
            },
            freshness_attestation: AgentEvidenceFreshnessAttestation {
                source_service_id: did("did:webvh:z6mkservice:service.example"),
                observed_frontier: NonEmptyString::new("frontier:8".to_owned()).unwrap(),
                issued_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
                expires_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap(),
                http_message_signature: NonEmptyString::new("sig".to_owned()).unwrap(),
            },
            signing_key_binding: binding.clone(),
            transparency: None,
        };
        let controller_key = PublicKeyMaterial::Ed25519Raw {
            bytes: base64url_decode("7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E").unwrap(),
        };
        let verdict = validate_agent_signer_evidence(
            Some(&evidence),
            &AgentSignerEvidenceValidationContext {
                signer_id: &binding.agent_id,
                controller_id: &binding.controller_id,
                verification_method: &binding.verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &binding.public_key_digest,
                authorize_signing_key_binding_digest: &agent_signing_key_binding_digest(&binding)
                    .unwrap(),
                event_accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
                now: Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap(),
                controller_public_key: &controller_key,
                state_witness_verified: true,
                freshness_signature_verified: true,
                freshness_relation_to_event: FrontierRelation::Covers,
                require_transparency: false,
                transparency_verified: false,
            },
        );
        assert_eq!(
            verdict,
            AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale)
        );

        evidence.authorization.status = AgentAuthorizationStatus::Superseded;
        evidence.authorization.valid_until_frontier =
            Some(NonEmptyString::new("frontier:9".to_owned()).unwrap());
        evidence.authorization.transition_event_id =
            Some(EventId::new("ak:event:01964137-0000-7000-8000-000000000009").unwrap());
        evidence.freshness_attestation.expires_at =
            Utc.with_ymd_and_hms(2026, 7, 25, 0, 4, 0).unwrap();
        let historical = validate_agent_signer_evidence(
            Some(&evidence),
            &AgentSignerEvidenceValidationContext {
                signer_id: &binding.agent_id,
                controller_id: &binding.controller_id,
                verification_method: &binding.verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &binding.public_key_digest,
                authorize_signing_key_binding_digest: &agent_signing_key_binding_digest(&binding)
                    .unwrap(),
                event_accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
                now: Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap(),
                controller_public_key: &controller_key,
                state_witness_verified: true,
                freshness_signature_verified: true,
                freshness_relation_to_event: FrontierRelation::Covers,
                require_transparency: false,
                transparency_verified: false,
            },
        );
        assert!(matches!(
            historical,
            AgentSignerEvidenceVerdict::Verified(_)
        ));
    }
}
