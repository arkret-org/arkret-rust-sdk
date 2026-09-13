//! Historical ordinary producer authentication (`device-lifecycle.md` §8.2).
//!
//! Retained bytes are untrusted inputs. Only a complete method-native source
//! closure can create this cache entry. Fixed signed source observations bind
//! historical keys; original authorization windows and Event proofs are checked
//! for every use. Neither result grants current or ordinary business admission.

use arkret_canonical::DigestSuite;
use arkret_event_draft::EventPayloadExt as _;
use arkret_models_identity::{AuthenticatedSignerResolutionEvidence as Evidence, DidDocument};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{ActorId, DidUrl, Event, EventId, SignerEvidenceRef, WireError};
use chrono::{DateTime, Utc};

type Result<T> = std::result::Result<T, WireError>;

#[derive(Clone, Debug)]
pub struct AuthenticatedHistoricalProducerSource {
    evidence: Evidence,
    signer: ActorId,
    control_device_key: Option<[u8; 32]>,
    control_not_before: Option<DateTime<Utc>>,
    control_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct VerifiedHistoricalEventProducer {
    event: Event,
    actor: ActorId,
    source: AuthenticatedHistoricalProducerSource,
    key: [u8; 32],
}

impl VerifiedHistoricalEventProducer {
    pub fn event_id(&self) -> &EventId {
        &self.event.event_id
    }
    pub fn event(&self) -> &Event {
        &self.event
    }
    pub fn matches_event(&self, event: &Event) -> bool {
        &self.event == event
    }
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }
    pub fn signer(&self) -> &ActorId {
        &self.source.signer
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn source(&self) -> &AuthenticatedHistoricalProducerSource {
        &self.source
    }
    pub fn verification_method(&self) -> &DidUrl {
        self.source.evidence.verification_method()
    }
    pub fn device_authorization(
        &self,
    ) -> Option<&arkret_models_crypto::DeviceProjectionAttestationCore> {
        match &self.source.evidence {
            Evidence::AccountDevice {
                device_projection_attestation,
                ..
            } => Some(&device_projection_attestation.attestation),
            _ => None,
        }
    }
}

impl AuthenticatedHistoricalProducerSource {
    pub fn evidence_ref(&self) -> Result<SignerEvidenceRef> {
        self.evidence.evidence_ref()
    }
    pub fn signer(&self) -> &ActorId {
        &self.signer
    }

    /// Authenticate source facts at their signed historical coordinates.
    /// `publication_time` is the original Event time used to select a Service
    /// method, never a receiver arrival time or a claim of current authority.
    pub fn authenticate(
        root_ref: &SignerEvidenceRef,
        signer: &ActorId,
        evidence: &Evidence,
        dependencies: &[Evidence],
        publication_time: DateTime<Utc>,
    ) -> Result<Self> {
        if &evidence.evidence_ref()? != root_ref
            || evidence.signer_id() != signer.signing_principal_id()
        {
            return invalid(
                "historical producer source does not bind its exact reference and signer",
            );
        }
        evidence.validate_attester_binding()?;
        if dependencies.len() > 64 {
            return invalid("historical producer source exceeds dependency budget");
        }
        let mut refs = std::collections::BTreeSet::new();
        for item in dependencies {
            if !refs.insert(item.evidence_ref()?) {
                return invalid("duplicate historical source dependency");
            }
        }
        match evidence {
            Evidence::Service {
                signer_id,
                authenticated_resolution,
                ..
            } => {
                if !matches!(signer, ActorId::Service { .. }) || !dependencies.is_empty() {
                    return invalid(
                        "service evidence requires an exact Service actor and no surplus dependencies",
                    );
                }
                arkret_identity::verify_authenticated_service_resolution_history(
                    authenticated_resolution,
                    signer_id,
                    publication_time,
                )
                .map_err(wire)?;
            }
            Evidence::Principal {
                public_resolution,
                normalized_did_document,
                attester_signer_evidence_ref,
                ..
            } => {
                if signer.as_account_id() != Some(&public_resolution.account_id) {
                    return invalid(
                        "principal producer evidence belongs to a different complete Account",
                    );
                }
                let attestation = &public_resolution.projection_attestation;
                let resolution = service_attester(
                    dependencies,
                    attester_signer_evidence_ref,
                    &public_resolution.account_id.station_id,
                    &attestation.proof.verification_method,
                )?;
                if matches!(
                    public_resolution.method_history_evidence,
                    arkret_models_identity::ResolutionMethodHistoryEvidence::DidWebDocument { .. }
                ) {
                    return invalid(
                        "mutable did:web cannot authenticate historical principal identity",
                    );
                }
                arkret_identity::verify_public_principal_resolution_history(
                    public_resolution,
                    resolution,
                    normalized_did_document,
                    attestation.attestation.issued_at,
                )
                .map_err(wire)?;
            }
            Evidence::AccountDevice {
                device_projection_attestation,
                attester_signer_evidence_ref,
                ..
            } => {
                let core = &device_projection_attestation.attestation;
                if signer.as_account_id() != Some(&core.account_id) {
                    return invalid("device source belongs to a different complete Account");
                }
                let resolution = service_attester(
                    dependencies,
                    attester_signer_evidence_ref,
                    &core.account_id.station_id,
                    &device_projection_attestation.proof.verification_method,
                )?;
                let document = arkret_identity::authenticated_service_document_at(
                    resolution,
                    &core.account_id.station_id,
                    core.attested_at,
                )
                .map_err(wire)?;
                let key = document_key(
                    &document,
                    &device_projection_attestation.proof.verification_method,
                )?;
                arkret_signatures::device_projection::verify_device_projection_with_key_material(
                    device_projection_attestation,
                    &key,
                    core.attested_at,
                )?;
            }
            Evidence::AccountDeviceControl { .. } => {
                return invalid(
                    "account-device Control evidence requires the complete PCR source verifier",
                );
            }
            Evidence::Agent { .. } => {
                return invalid("Agent evidence requires the complete historical Agent verifier");
            }
        }
        Ok(Self {
            evidence: evidence.clone(),
            signer: signer.clone(),
            control_device_key: None,
            control_not_before: None,
            control_expires_at: None,
        })
    }

    /// Authenticate a portable ordinary-human Control source from the exact
    /// referenced PCR prefix. The caller must resolve every Event and Seal
    /// named by the root before invoking this constructor.
    pub fn authenticate_account_device_control(
        root_ref: &SignerEvidenceRef,
        signer: &ActorId,
        evidence: &Evidence,
        events: &[Event],
        seals: &[arkret_wire::Seal],
        publication_time: DateTime<Utc>,
    ) -> Result<Self> {
        if &evidence.evidence_ref()? != root_ref {
            return invalid("account-device Control evidence ref does not match its bytes");
        }
        evidence.validate_attester_binding()?;
        let Evidence::AccountDeviceControl {
            account_id,
            device_id,
            authorization_event_ref,
            authorized_generation_ref,
            generation_event_ref,
            confirmation_seal_ref,
            pcr_genesis_event_ref,
            principal_inception,
            history_event_refs,
            history_seal_refs,
            ..
        } = evidence
        else {
            return invalid("portable Control verifier requires account_device_control evidence");
        };
        if signer.as_account_id() != Some(account_id) {
            return invalid("account-device Control evidence belongs to another complete Account");
        }
        let mut actual_event_refs = events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        actual_event_refs.sort();
        if actual_event_refs != *history_event_refs {
            return invalid("account-device Control Event closure is missing or has surplus bytes");
        }
        let mut actual_seal_refs = seals.iter().map(|seal| seal.id.clone()).collect::<Vec<_>>();
        actual_seal_refs.sort();
        if actual_seal_refs != *history_seal_refs {
            return invalid("account-device Control Seal closure is missing or has surplus bytes");
        }
        let genesis = events
            .iter()
            .find(|event| &event.event_id == pcr_genesis_event_ref)
            .ok_or_else(|| error("account-device Control PCR genesis is missing"))?;
        let create: crate::RealmCreatePayload = genesis
            .typed_payload::<arkret_wire::event_spec::RealmCreate>()
            .map_err(wire)?;
        let mut ordered_seals = seals.to_vec();
        ordered_seals.sort_by_key(|seal| seal.notary_seq);
        if ordered_seals.last().map(|seal| &seal.id) != Some(confirmation_seal_ref) {
            return invalid("account-device Control closure does not end at its confirmation Seal");
        }
        let history = crate::DeviceAuthorizationHistory::verify(
            account_id,
            pcr_genesis_event_ref,
            &create.object.notary,
            principal_inception,
            confirmation_seal_ref,
            &ordered_seals,
            events,
            create.object.digest_algorithm,
        )
        .map_err(wire)?;
        let authorization = history
            .authorization(authorization_event_ref)
            .ok_or_else(|| error("account-device Control authorization is not confirmed"))?;
        if authorization.device_id() != device_id
            || authorization.authorized_generation_ref() != *authorized_generation_ref
            || authorization.generation_event_id() != generation_event_ref
            || authorization.confirmed_seal() != confirmation_seal_ref
        {
            return invalid("account-device Control root differs from the verified authorization");
        }
        let authorization_payload = authorization.payload();
        if publication_time < authorization_payload.not_before
            || authorization_payload
                .expires_at
                .flatten()
                .is_some_and(|expires_at| publication_time >= expires_at)
        {
            return invalid(
                "Control publication is outside the original device authorization window",
            );
        }
        Ok(Self {
            evidence: evidence.clone(),
            signer: signer.clone(),
            control_device_key: Some(*authorization.public_key()),
            control_not_before: Some(authorization_payload.not_before),
            control_expires_at: authorization_payload.expires_at.flatten(),
        })
    }

    /// Verify original publication bytes, not a current authorization decision.
    pub fn verify_event(
        &self,
        event: &Event,
        digest_suite: DigestSuite,
    ) -> Result<VerifiedHistoricalEventProducer> {
        event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
        event.validate_proof_bindings_with_digest_suite(digest_suite)?;
        let [proof] = event.proofs.as_slice() else {
            return invalid("historical Event requires exactly one producer proof");
        };
        if event.executed_by.as_ref().unwrap_or(&event.actor_id) != &self.signer
            || proof.signer_resolution_evidence_ref.as_ref() != Some(&self.evidence_ref()?)
            || &proof.verification_method != self.evidence.verification_method()
        {
            return invalid("historical Event differs from its authenticated producer source");
        }
        let at = event.created_at;
        let material = match &self.evidence {
            Evidence::Service {
                signer_id,
                authenticated_resolution,
                ..
            } => {
                let document = arkret_identity::authenticated_service_document_at(
                    authenticated_resolution,
                    signer_id,
                    at,
                )
                .map_err(wire)?;
                document_key(&document, &proof.verification_method)?
            }
            Evidence::Principal {
                public_resolution,
                normalized_did_document,
                ..
            } => {
                let document = match &public_resolution.method_history_evidence {
                    arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
                        log_entries,
                        ..
                    } => {
                        let point = arkret_signatures::webvh::validate_webvh_history_at(
                            &normalized_did_document.id,
                            log_entries,
                            at,
                        )
                        .map_err(wire)?;
                        serde_json::from_value(point.document)?
                    }
                    arkret_models_identity::ResolutionMethodHistoryEvidence::DidKeyExpansion {
                        ..
                    } => normalized_did_document.clone(),
                    _ => {
                        return invalid(
                            "historical principal document has no authenticated history",
                        );
                    }
                };
                document_key(&document, &proof.verification_method)?
            }
            Evidence::AccountDevice {
                device_projection_attestation,
                ..
            } => {
                if arkret_schema::classify_event_execution(event).map_err(wire)?
                    != Some(arkret_wire::CbsEffectPlane::Data)
                {
                    return invalid(
                        "account-device projection does not authorize generic Control Events",
                    );
                }
                let core = &device_projection_attestation.attestation;
                if at < core.authorization_window.not_before
                    || core
                        .authorization_window
                        .expires_at
                        .is_some_and(|expiry| at >= expiry)
                {
                    return invalid(
                        "historical publication is outside the original device authorization window",
                    );
                }
                PublicKeyMaterial::Ed25519Multibase {
                    value: core
                        .device_signing_key_did
                        .as_str()
                        .strip_prefix("did:key:")
                        .ok_or_else(|| error("device projection key must be did:key"))?
                        .to_owned(),
                }
            }
            Evidence::AccountDeviceControl { .. } => {
                if arkret_schema::classify_event_execution(event).map_err(wire)?
                    != Some(arkret_wire::CbsEffectPlane::Control)
                {
                    return invalid(
                        "account-device Control evidence authorizes generic Control Events only",
                    );
                }
                if self
                    .control_not_before
                    .is_none_or(|not_before| at < not_before)
                    || self
                        .control_expires_at
                        .is_some_and(|expires_at| at >= expires_at)
                {
                    return invalid(
                        "Control publication is outside the original device authorization window",
                    );
                }
                PublicKeyMaterial::Ed25519Raw {
                    bytes: self
                        .control_device_key
                        .ok_or_else(|| error("verified Control device key is unavailable"))?
                        .to_vec(),
                }
            }
            Evidence::Agent { .. } => {
                return invalid("Agent evidence cannot enter the document/device verifier");
            }
        };
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(wire)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            &material,
            digest_suite,
        )
        .map_err(wire)?;
        Ok(VerifiedHistoricalEventProducer {
            event: event.clone(),
            actor: event.actor_id.clone(),
            source: self.clone(),
            key: material.ed25519_bytes().map_err(wire)?,
        })
    }
}

fn service_attester<'a>(
    dependencies: &'a [Evidence],
    reference: &SignerEvidenceRef,
    station: &arkret_wire::DidCoreId,
    method: &DidUrl,
) -> Result<&'a arkret_models_identity::AuthenticatedServiceResolution> {
    let [dependency] = dependencies else {
        return invalid("missing or surplus exact Service attester dependency");
    };
    if &dependency.evidence_ref()? != reference
        || dependency.signer_id() != station
        || dependency.verification_method() != method
    {
        return invalid("attester reference, complete Account Station or proof method differs");
    }
    dependency.validate_attester_binding()?;
    let Evidence::Service {
        authenticated_resolution,
        ..
    } = dependency
    else {
        return invalid("projection attester must be its exact Station Service");
    };
    Ok(authenticated_resolution)
}

fn document_key(document: &DidDocument, method: &DidUrl) -> Result<PublicKeyMaterial> {
    arkret_identity::validate_verification_method_relationship(
        document,
        method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(wire)?;
    arkret_identity::public_key_material_from_document(document, method).map_err(wire)
}
fn error(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}
fn invalid<T>(message: &str) -> Result<T> {
    Err(error(message))
}
fn wire(error: impl std::fmt::Display) -> WireError {
    WireError::Protocol(error.to_string())
}

#[cfg(test)]
mod tests;
