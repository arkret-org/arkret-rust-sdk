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
    /// Historical device authorization for ordinary-human history responses.
    /// This is not DID-document authority or a Control Event proof regime.
    AccountDevice {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        device_projection_attestation: arkret_models_crypto::DeviceProjectionAttestation,
        attester_signer_evidence_ref: SignerEvidenceRef,
    },
    Agent {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        agent_signer_evidence: Box<AgentSignerEvidence>,
        attester_signer_evidence_ref: SignerEvidenceRef,
        account_authority_signer_evidence_ref: SignerEvidenceRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver_signer_evidence_ref: Option<SignerEvidenceRef>,
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
            | Self::AccountDevice { signer_id, .. }
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
            | Self::AccountDevice {
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
                let did = &authenticated_resolution.normalized_did_document.id;
                let method_controller = verification_method
                    .as_str()
                    .split_once('#')
                    .map(|(controller, _)| controller);
                if &authenticated_resolution.service_id != signer_id
                    || !(did.as_str().starts_with("did:key:")
                        || did.as_str().starts_with("did:webvh:"))
                    || method_controller != Some(did.as_str())
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
                    || verification_method
                        .as_str()
                        .split_once('#')
                        .map(|(did, _)| did)
                        != Some(normalized_did_document.id.as_str())
                {
                    return Err(WireError::Protocol(
                        "principal signer evidence does not authorize its signer or method"
                            .to_owned(),
                    ));
                }
                public_resolution.validate_attestation_binding()?;
            }
            Self::AccountDevice {
                signer_id,
                verification_method,
                device_projection_attestation,
                ..
            } => {
                let core = &device_projection_attestation.attestation;
                let (controller, fragment) = verification_method
                    .as_str()
                    .split_once('#')
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "account device evidence requires an exact device method".to_owned(),
                        )
                    })?;
                let controller =
                    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(controller)?)?;
                if &core.account_id.principal_id != signer_id
                    || controller != *signer_id
                    || fragment != core.device_id.as_str()
                    || core.device_status != arkret_models_crypto::DeviceStatus::Active
                    || core.attested_at >= core.expires_at
                    || device_projection_attestation.proof.created_at != core.attested_at
                {
                    return Err(WireError::Protocol(
                        "account device signer evidence binding is invalid".to_owned(),
                    ));
                }
            }
            Self::Agent {
                signer_id,
                verification_method,
                agent_signer_evidence,
                ..
            } => {
                let admission = match agent_signer_evidence.as_ref() {
                    AgentSignerEvidence::HistoricalEvent {
                        admission_evidence, ..
                    }
                    | AgentSignerEvidence::CurrentAdmission {
                        admission_evidence, ..
                    } => admission_evidence,
                };
                let binding = &admission
                    .agent_authority_state_evidence
                    .state
                    .signing_key_binding;
                let matches_signer = &binding.agent_id == signer_id
                    && &binding.verification_method == verification_method;
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
            }
            | Self::AccountDevice {
                attester_signer_evidence_ref,
                ..
            } => vec![attester_signer_evidence_ref],
            Self::Agent {
                attester_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                receiver_signer_evidence_ref,
                ..
            } => {
                if matches!(self, Self::Agent { agent_signer_evidence, .. } if matches!(agent_signer_evidence.as_ref(), AgentSignerEvidence::CurrentAdmission { .. }))
                    == receiver_signer_evidence_ref.is_some()
                {
                    return Err(WireError::Protocol(
                        "Agent receiver evidence must occur only for historical acceptance"
                            .to_owned(),
                    ));
                }
                let mut refs = vec![
                    attester_signer_evidence_ref,
                    account_authority_signer_evidence_ref,
                ];
                refs.extend(receiver_signer_evidence_ref.iter());
                refs
            }
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
        AuthenticatedSignerResolutionEvidence::Agent { .. }
        | AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => {
            return Err(WireError::Protocol(
                "this signer evidence kind cannot authorize Realm notary bootstrap".to_owned(),
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
        AuthenticatedSignerResolutionEvidence::Agent { .. }
        | AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => {
            unreachable!("non-document signer evidence returned before descriptor construction")
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

#[cfg(test)]
mod account_device_tests {
    use super::*;

    fn evidence() -> AuthenticatedSignerResolutionEvidence {
        serde_json::from_value(serde_json::json!({
            "kind": "account_device",
            "signer_id": "ak:did_core:webvh:z6mkfixture",
            "verification_method": "did:webvh:z6mkfixture:account.example#ak:device:0196419b-0000-7000-8000-000000000001",
            "attester_signer_evidence_ref": format!("ak:signer_evidence:sha256:{}", "a".repeat(64)),
            "device_projection_attestation": {
                "attestation": {
                    "account_id": {"principal_id":"ak:did_core:webvh:z6mkfixture", "station_id":"ak:did_core:webvh:z6mkfixtureps"},
                    "device_id":"ak:device:0196419b-0000-7000-8000-000000000001",
                    "device_signing_key_did":"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
                    "hpke_key":"hpke-1",
                    "device_authorize_event_id":"ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                    "authorized_generation_ref":7, "device_status":"active",
                    "attested_at":"2026-09-08T00:00:00.000Z", "expires_at":"2026-09-08T00:05:00.000Z"
                },
                "proof":{"verification_method":"did:webvh:z6mkfixtureps:station.example#signing-1", "created_at":"2026-09-08T00:00:00.000Z", "jws":"AA"}
            }
        })).unwrap()
    }

    #[test]
    fn historical_device_evidence_is_closed_and_not_notary_authority() {
        let evidence = evidence();
        evidence.validate_attester_binding().unwrap();
        assert!(ed25519_notary_signer_descriptor_from_evidence(&evidence).is_err());
        let mut wire = serde_json::to_value(&evidence).unwrap();
        wire["normalized_did_document"] = serde_json::json!({});
        assert!(serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(wire).is_err());
    }

    #[test]
    fn historical_device_evidence_binds_exact_device_and_authorization() {
        let evidence = evidence();
        let digest = evidence.evidence_ref().unwrap();
        for (pointer, value) in [
            (
                "/signer_id",
                serde_json::json!("ak:did_core:webvh:z6mkother"),
            ),
            (
                "/verification_method",
                serde_json::json!("did:webvh:z6mkfixture:account.example#root"),
            ),
            (
                "/device_projection_attestation/attestation/device_status",
                serde_json::json!("revoked"),
            ),
            (
                "/device_projection_attestation/attestation/expires_at",
                serde_json::json!("2026-09-08T00:00:00.000Z"),
            ),
        ] {
            let mut wire = serde_json::to_value(&evidence).unwrap();
            *wire.pointer_mut(pointer).unwrap() = value;
            let changed: AuthenticatedSignerResolutionEvidence =
                serde_json::from_value(wire).unwrap();
            assert_ne!(changed.evidence_ref().unwrap(), digest);
            assert!(changed.validate_attester_binding().is_err(), "{pointer}");
        }
    }
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
