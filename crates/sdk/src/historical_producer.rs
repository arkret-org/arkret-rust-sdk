//! Historical ordinary producer authentication (`device-lifecycle.md` §8.2).
//!
//! Retained bytes are untrusted inputs. Only a complete method-native source
//! closure can create this cache entry. Fixed signed source observations bind
//! historical keys; original authorization windows and Event proofs are checked
//! for every use. Neither result grants current or ordinary business admission.

use arkret_canonical::DigestSuite;
use arkret_event_draft::EventPayloadExt;
use arkret_models_identity::{AuthenticatedSignerResolutionEvidence as Evidence, DidDocument};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{ActorId, DidUrl, Event, EventId, SignerEvidenceRef, WireError};
use chrono::{DateTime, Utc};

type Result<T> = std::result::Result<T, WireError>;

#[derive(Clone, Debug)]
pub struct AuthenticatedHistoricalProducerSource {
    evidence: Evidence,
    signer: ActorId,
    account_device_control:
        Option<crate::device_authorization_history::VerifiedAccountDeviceControlEvidence>,
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

    pub fn account_device_control_authorization(
        &self,
    ) -> Option<&crate::device_authorization_history::VerifiedAccountDeviceControlEvidence> {
        self.source.account_device_control.as_ref()
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
                    "account device Control evidence requires its complete PCR Event/Seal closure",
                );
            }
            Evidence::Agent { .. } => {
                return invalid("Agent evidence requires the complete historical Agent verifier");
            }
        }
        Ok(Self {
            evidence: evidence.clone(),
            signer: signer.clone(),
            account_device_control: None,
        })
    }

    /// Authenticate a portable ordinary-human Control source by replaying the
    /// complete exact PCR prefix named by the evidence. This is deliberately a
    /// separate constructor from projection/document authentication so callers
    /// cannot accidentally treat the root as a bare key assertion.
    pub fn authenticate_account_device_control(
        root_ref: &SignerEvidenceRef,
        signer: &ActorId,
        evidence: &Evidence,
        seals: &[arkret_wire::Seal],
        events: &[Event],
        digest_suite: DigestSuite,
    ) -> Result<Self> {
        if &evidence.evidence_ref()? != root_ref
            || evidence.signer_id() != signer.signing_principal_id()
        {
            return invalid(
                "historical Control producer source does not bind its exact reference and signer",
            );
        }
        let Evidence::AccountDeviceControl { account_id, .. } = evidence else {
            return invalid(
                "historical human Control source requires account_device_control evidence",
            );
        };
        if signer.as_account_id() != Some(account_id) {
            return invalid(
                "account device Control source belongs to a different complete Account",
            );
        }
        let verified = crate::DeviceAuthorizationHistory::verify_account_device_control(
            evidence,
            seals,
            events,
            digest_suite,
        )
        .map_err(wire)?;
        Ok(Self {
            evidence: evidence.clone(),
            signer: signer.clone(),
            account_device_control: Some(verified),
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
                validate_principal_event_scope(
                    &self.signer,
                    self.evidence.verification_method(),
                    event,
                )?;
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
                let execution = arkret_schema::classify_event_execution(event).map_err(wire)?;
                if execution != Some(arkret_wire::CbsEffectPlane::Data)
                    && event.kind.wire_scope() != arkret_wire::EventWireScope::ActorPrivateEvent
                {
                    return invalid(
                        "account-device projection authorizes only Data or actor-private Events",
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
                if is_account_device_control_prohibited_event(event)? {
                    return invalid(
                        "account device Control evidence cannot authorize a native unit or DID authority action",
                    );
                }
                if arkret_schema::classify_event_execution(event).map_err(wire)?
                    != Some(arkret_wire::CbsEffectPlane::Control)
                {
                    return invalid(
                        "account device Control evidence does not authorize non-Control Events",
                    );
                }
                let source = self.account_device_control.as_ref().ok_or_else(|| {
                    error("account device Control source has no authenticated PCR history")
                })?;
                if !source.authorization_contains(at) {
                    return invalid(
                        "Control publication is outside the original device authorization window",
                    );
                }
                PublicKeyMaterial::Ed25519Raw {
                    bytes: source.public_key().to_vec(),
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

fn is_account_device_control_prohibited_event(event: &Event) -> Result<bool> {
    match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            let payload: crate::RealmCreatePayload = event
                .typed_payload::<arkret_wire::event_spec::RealmCreate>()
                .map_err(wire)?;
            Ok(payload.object.purpose == crate::RealmPurpose::PrincipalControl)
        }
        arkret_wire::EventKind::DeviceReanchor
        | arkret_wire::EventKind::IdentityResolutionUpdate => Ok(true),
        arkret_wire::EventKind::DeviceAuthorize => {
            let payload: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                .map_err(wire)?;
            // `applet_managed_delegation` joins the two unit-bound bindings
            // here because `device-lifecycle.md` §5.3 requires its
            // `proof.verification_method` to be a DID Document verification
            // method fragment and MUST NOT be `ak:device:<uuid>`: an account
            // device signing key can never be its producer.
            Ok(matches!(
                payload.authorization_binding_kind,
                arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RegistrationAnchor
                    | arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::PcrRecovery
                    | arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::AppletManagedDelegation
            ))
        }
        _ => Ok(false),
    }
}

fn signer_uses_device_method(signer: &ActorId, method: &DidUrl) -> bool {
    signer.as_account_id().is_some()
        && method
            .as_str()
            .split_once('#')
            .is_some_and(|(_, fragment)| arkret_wire::DeviceId::new(fragment).is_ok())
}

fn validate_principal_event_scope(signer: &ActorId, method: &DidUrl, event: &Event) -> Result<()> {
    if signer_uses_device_method(signer, method)
        && arkret_schema::classify_event_execution(event).map_err(wire)?
            == Some(arkret_wire::CbsEffectPlane::Control)
    {
        return invalid(
            "principal evidence does not authorize ordinary human generic Control Events",
        );
    }
    Ok(())
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
