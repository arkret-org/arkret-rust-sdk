//! Content-addressed historical signer-resolution evidence.

use arkret_wire::{
    ActorId, DidCoreId, DidUrl, Hash, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor,
    Result, SignerEvidenceRef, WireError,
};
use serde::{Deserialize, Serialize};

use crate::{
    AgentSignerEvidence, AuthenticatedServiceResolution, DidDocument, PublicPrincipalResolution,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticatedSignerResolutionEvidence {
    Service {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        authenticated_resolution: AuthenticatedServiceResolution,
    },
    Principal {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        public_resolution: PublicPrincipalResolution,
        normalized_did_document: DidDocument,
        attester_signer_evidence_ref: SignerEvidenceRef,
    },
    Agent {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        agent_signer_evidence: Box<AgentSignerEvidence>,
        attester_signer_evidence_ref: SignerEvidenceRef,
        controller_signer_evidence_ref: SignerEvidenceRef,
        account_authority_signer_evidence_ref: SignerEvidenceRef,
        receiver_signer_evidence_ref: SignerEvidenceRef,
    },
}

impl Eq for AuthenticatedSignerResolutionEvidence {}

impl AuthenticatedSignerResolutionEvidence {
    pub fn canonical_sha256_digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    pub fn evidence_ref(&self) -> Result<SignerEvidenceRef> {
        let digest = self.canonical_sha256_digest()?;
        SignerEvidenceRef::new(format!("ak:signer_evidence:{}", digest.as_ref()))
    }

    pub fn signer_id(&self) -> &DidCoreId {
        match self {
            Self::Service { signer_id, .. }
            | Self::Principal { signer_id, .. }
            | Self::Agent { signer_id, .. } => signer_id,
        }
    }

    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::Service {
                verification_method,
                ..
            }
            | Self::Principal {
                verification_method,
                ..
            }
            | Self::Agent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    pub fn validate_attester_binding(&self) -> Result<()> {
        if arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024 {
            return Err(WireError::Protocol(
                "authenticated signer resolution evidence exceeds 1 MiB".to_owned(),
            ));
        }
        match self {
            Self::Service {
                signer_id,
                verification_method,
                authenticated_resolution,
            } => {
                let record = &authenticated_resolution.service_resolution_record.record;
                let method_controller = verification_method
                    .as_str()
                    .split_once('#')
                    .map(|(controller, _)| controller);
                if &record.service_id != signer_id
                    || !(record.did.as_str().starts_with("did:key:")
                        || record.did.as_str().starts_with("did:webvh:"))
                    || method_controller != Some(record.did.as_str())
                {
                    return Err(WireError::Protocol(
                        "service signer evidence does not authorize its signer or method"
                            .to_owned(),
                    ));
                }
            }
            Self::Principal {
                signer_id,
                verification_method,
                public_resolution,
                normalized_did_document,
                ..
            } => {
                if &public_resolution.account_id.principal_id != signer_id
                    || !normalized_did_document
                        .verification_methods
                        .contains_key(verification_method.as_str())
                {
                    return Err(WireError::Protocol(
                        "principal signer evidence does not authorize its signer or method"
                            .to_owned(),
                    ));
                }
                public_resolution.validate_attestation_binding()?;
            }
            Self::Agent {
                signer_id,
                verification_method,
                agent_signer_evidence,
                ..
            } => {
                let matches_signer = match agent_signer_evidence.as_ref() {
                    AgentSignerEvidence::HistoricalEvent {
                        event_admission_receipt,
                        ..
                    } => {
                        &event_admission_receipt.agent_id == signer_id
                            && &event_admission_receipt.verification_method == verification_method
                    }
                    AgentSignerEvidence::CurrentAdmission {
                        admission_evidence, ..
                    } => {
                        let binding = &admission_evidence
                            .agent_authority_state_evidence
                            .state
                            .signing_key_binding;
                        &binding.agent_id == signer_id
                            && &binding.verification_method == verification_method
                    }
                };
                if !matches_signer {
                    return Err(WireError::Protocol(
                        "Agent signer evidence does not authorize its signer or method".to_owned(),
                    ));
                }
            }
        }
        let references = match self {
            Self::Service { .. } => return Ok(()),
            Self::Principal {
                attester_signer_evidence_ref,
                ..
            } => vec![attester_signer_evidence_ref],
            Self::Agent {
                attester_signer_evidence_ref,
                controller_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                receiver_signer_evidence_ref,
                ..
            } => vec![
                attester_signer_evidence_ref,
                controller_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                receiver_signer_evidence_ref,
            ],
        };
        for evidence_ref in references {
            evidence_ref.content_digest()?;
        }
        Ok(())
    }
}

/// Freeze the Ed25519 verification method authenticated by retained signer
/// evidence into the exact Realm notary descriptor used at Realm creation.
///
/// Callers must pass historical/authenticated evidence, never a current
/// unauthenticated DID lookup. Unsupported key families fail closed instead
/// of guessing a JOSE algorithm or wire encoding.
pub fn ed25519_notary_signer_descriptor_from_evidence(
    evidence: &AuthenticatedSignerResolutionEvidence,
) -> Result<NotarySignerDescriptor> {
    evidence.validate_attester_binding()?;
    let document = match evidence {
        AuthenticatedSignerResolutionEvidence::Service {
            authenticated_resolution,
            ..
        } => &authenticated_resolution.normalized_did_document,
        AuthenticatedSignerResolutionEvidence::Principal {
            normalized_did_document,
            ..
        } => normalized_did_document,
        AuthenticatedSignerResolutionEvidence::Agent { .. } => {
            return Err(WireError::Protocol(
                "Agent signer evidence does not carry a normalized DID document for Realm notary bootstrap"
                    .to_owned(),
            ));
        }
    };
    let verification_method = evidence.verification_method();
    let material = document
        .verification_methods
        .get(verification_method.as_str())
        .ok_or_else(|| {
            WireError::Protocol(
                "authenticated signer evidence omits the selected notary verification method"
                    .to_owned(),
            )
        })?;
    let public_key = decode_ed25519_material(material)?;
    let frozen_public_key_b64u = arkret_wire::base64url::base64url_encode(public_key);
    let actor_id = match evidence {
        AuthenticatedSignerResolutionEvidence::Service { signer_id, .. } => {
            ActorId::service(signer_id.clone())
        }
        AuthenticatedSignerResolutionEvidence::Principal {
            public_resolution, ..
        } => ActorId::account(public_resolution.authority()),
        AuthenticatedSignerResolutionEvidence::Agent { .. } => {
            unreachable!("Agent signer evidence returned before descriptor construction")
        }
    };
    let descriptor = NotarySignerDescriptor {
        actor_id,
        verification_method: verification_method.clone(),
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u,
        frozen_public_key_digest: Hash::new(arkret_canonical::sha256_digest(public_key))?,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

fn decode_ed25519_material(material: &str) -> Result<[u8; 32]> {
    let material = material.trim();
    if material.starts_with('z') {
        return arkret_canonical::decode_ed25519_multibase(material).map_err(Into::into);
    }
    let value: serde_json::Value = serde_json::from_str(material).map_err(|error| {
        WireError::Protocol(format!(
            "invalid authenticated notary key material: {error}"
        ))
    })?;
    if let serde_json::Value::String(inner) = value {
        return decode_ed25519_material(&inner);
    }
    let object = value.as_object().ok_or_else(|| {
        WireError::Protocol("authenticated notary key material must be multibase or JWK".to_owned())
    })?;
    if object.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || object.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
    {
        return Err(WireError::Protocol(
            "authenticated notary JWK must be an Ed25519 OKP key".to_owned(),
        ));
    }
    let encoded = object
        .get("x")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WireError::Protocol("authenticated notary JWK omits x".to_owned()))?;
    let decoded = arkret_wire::base64url::base64url_decode(encoded).map_err(|error| {
        WireError::Protocol(format!("invalid authenticated notary JWK x: {error}"))
    })?;
    if decoded.len() != 32 || arkret_wire::base64url::base64url_encode(&decoded) != encoded {
        return Err(WireError::Protocol(
            "authenticated notary JWK x is not canonical Ed25519 key material".to_owned(),
        ));
    }
    decoded
        .try_into()
        .map_err(|_| WireError::Protocol("authenticated notary key length mismatch".to_owned()))
}
