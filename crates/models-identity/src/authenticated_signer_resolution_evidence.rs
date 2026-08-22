//! Content-addressed historical signer-resolution evidence.

use arkret_wire::{
    DidCoreId, DidUrl, Error, Hash, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor,
    Result, SignerEvidenceRef,
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
        attester_signer_evidence_digest: Hash,
    },
    NativeAgent {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        agent_signer_evidence: AgentSignerEvidence,
        attester_signer_evidence_ref: SignerEvidenceRef,
        attester_signer_evidence_digest: Hash,
        controller_signer_evidence_ref: SignerEvidenceRef,
        controller_signer_evidence_digest: Hash,
        account_authority_signer_evidence_ref: SignerEvidenceRef,
        account_authority_signer_evidence_digest: Hash,
        receiver_signer_evidence_ref: SignerEvidenceRef,
        receiver_signer_evidence_digest: Hash,
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
            | Self::NativeAgent { signer_id, .. } => signer_id,
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
            | Self::NativeAgent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    pub fn validate_attester_binding(&self) -> Result<()> {
        if arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024 {
            return Err(Error::Protocol(
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
                    || !(record.full_id.as_str().starts_with("did:key:")
                        || record.full_id.as_str().starts_with("did:webvh:"))
                    || method_controller != Some(record.full_id.as_str())
                {
                    return Err(Error::Protocol(
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
                if &public_resolution.principal_id != signer_id
                    || !normalized_did_document
                        .verification_methods
                        .contains_key(verification_method.as_str())
                {
                    return Err(Error::Protocol(
                        "principal signer evidence does not authorize its signer or method"
                            .to_owned(),
                    ));
                }
                public_resolution.validate_attestation_binding()?;
            }
            Self::NativeAgent {
                signer_id,
                verification_method,
                agent_signer_evidence,
                ..
            } => {
                let matches_signer = match agent_signer_evidence {
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
                            .agent_authority_snapshot
                            .core
                            .signing_key_binding;
                        &binding.agent_id == signer_id
                            && &binding.verification_method == verification_method
                    }
                };
                if !matches_signer {
                    return Err(Error::Protocol(
                        "native-agent signer evidence does not authorize its signer or method"
                            .to_owned(),
                    ));
                }
            }
        }
        let pairs = match self {
            Self::Service { .. } => return Ok(()),
            Self::Principal {
                attester_signer_evidence_ref,
                attester_signer_evidence_digest,
                ..
            } => vec![(
                attester_signer_evidence_ref,
                attester_signer_evidence_digest,
            )],
            Self::NativeAgent {
                attester_signer_evidence_ref,
                attester_signer_evidence_digest,
                controller_signer_evidence_ref,
                controller_signer_evidence_digest,
                account_authority_signer_evidence_ref,
                account_authority_signer_evidence_digest,
                receiver_signer_evidence_ref,
                receiver_signer_evidence_digest,
                ..
            } => vec![
                (
                    attester_signer_evidence_ref,
                    attester_signer_evidence_digest,
                ),
                (
                    controller_signer_evidence_ref,
                    controller_signer_evidence_digest,
                ),
                (
                    account_authority_signer_evidence_ref,
                    account_authority_signer_evidence_digest,
                ),
                (
                    receiver_signer_evidence_ref,
                    receiver_signer_evidence_digest,
                ),
            ],
        };
        for (evidence_ref, digest) in pairs {
            if evidence_ref.content_digest()? != *digest || !digest.as_ref().starts_with("sha256:")
            {
                return Err(Error::Protocol(
                    "signer evidence ref and digest do not match".to_owned(),
                ));
            }
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
        AuthenticatedSignerResolutionEvidence::NativeAgent { .. } => {
            return Err(Error::Protocol(
                "native-agent signer evidence does not carry a normalized DID document for Realm notary bootstrap"
                    .to_owned(),
            ));
        }
    };
    let verification_method = evidence.verification_method();
    let material = document
        .verification_methods
        .get(verification_method.as_str())
        .ok_or_else(|| {
            Error::Protocol(
                "authenticated signer evidence omits the selected notary verification method"
                    .to_owned(),
            )
        })?;
    let public_key = decode_ed25519_material(material)?;
    let frozen_public_key_b64u = arkret_wire::base64url::base64url_encode(&public_key);
    let descriptor = NotarySignerDescriptor {
        actor_id: evidence.signer_id().clone(),
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
        Error::Protocol(format!(
            "invalid authenticated notary key material: {error}"
        ))
    })?;
    if let serde_json::Value::String(inner) = value {
        return decode_ed25519_material(&inner);
    }
    let object = value.as_object().ok_or_else(|| {
        Error::Protocol("authenticated notary key material must be multibase or JWK".to_owned())
    })?;
    if object.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || object.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
    {
        return Err(Error::Protocol(
            "authenticated notary JWK must be an Ed25519 OKP key".to_owned(),
        ));
    }
    let encoded = object
        .get("x")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Protocol("authenticated notary JWK omits x".to_owned()))?;
    let decoded = arkret_wire::base64url::base64url_decode(encoded)
        .map_err(|error| Error::Protocol(format!("invalid authenticated notary JWK x: {error}")))?;
    if decoded.len() != 32 || arkret_wire::base64url::base64url_encode(&decoded) != encoded {
        return Err(Error::Protocol(
            "authenticated notary JWK x is not canonical Ed25519 key material".to_owned(),
        ));
    }
    decoded
        .try_into()
        .map_err(|_| Error::Protocol("authenticated notary key length mismatch".to_owned()))
}
