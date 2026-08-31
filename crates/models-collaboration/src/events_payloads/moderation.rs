//! Moderation schema artifact counterparts and event payloads.

use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_wire::{ActorId, Did, DidCoreId, DidUrl, Event, Seal, project_did_to_core_id};

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-evidence.schema.json#/$defs/evidence_package`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationEvidencePackage {
    pub target_refs: Vec<ObjectRef>,
    pub encryption: String,
    pub recipient_public_key_ref: DidUrl,
    pub encrypted_to_kid: DidUrl,
    pub ciphertext: String,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<Hash>,
    pub reporter_signature: String,
}

impl ModerationEvidencePackage {
    pub fn validate_for_target(&self, target_ref: &str) -> Result<()> {
        if self.target_refs.len() != 1
            || self.target_refs[0] != target_ref
            || self.encryption.trim().is_empty()
            || self.ciphertext.is_empty()
            || self.reporter_signature.trim().is_empty()
            || self.recipient_public_key_ref != self.encrypted_to_kid
        {
            return Err(WireError::Protocol(
                "moderation evidence package does not bind the exact target and recipient key"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-evidence.schema.json#/$defs/franking_proof`.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingProof {
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub received_by: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub replay_nonce: String,
    pub signature: String,
}

/// Request for the first accepted Seal observation of one durable franking
/// proof Event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingSealObservationRequest {
    pub realm_id: RealmId,
    pub proof_event_id: EventId,
    pub target_event_id: EventId,
}

/// RFC 6962 path proving that the durable proof Event digest is present in
/// `covering_seal.data_event_set_root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingDataEventInclusionProof {
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub audit_path: Vec<Hash>,
}

/// Complete, independently verifiable observation material for one durable
/// franking proof Event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingSealObservationOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub target_event: Event,
    pub covering_seal: Seal,
    pub data_event_inclusion_proof: FrankingDataEventInclusionProof,
    pub service_signer_evidence: AuthenticatedSignerResolutionEvidence,
}

impl FrankingSealObservationOutcome {
    /// Validate all non-Merkle cross-object bindings. Transport clients should
    /// additionally verify `data_event_inclusion_proof` against the signed
    /// `covering_seal.data_event_set_root`.
    pub fn validate_binding(
        &self,
        request: &FrankingSealObservationRequest,
    ) -> Result<FrankingProof> {
        if self.proof_event.event_id != request.proof_event_id
            || self.target_event.event_id != request.target_event_id
            || self.proof_event.realm_id != request.realm_id
            || self.target_event.realm_id != request.realm_id
            || self.covering_seal.realm_id != request.realm_id
            || self.proof_event.kind != EventKind::ModerationFrankingProof
            || self.data_event_inclusion_proof.leaf_count == 0
            || self.data_event_inclusion_proof.leaf_index
                >= self.data_event_inclusion_proof.leaf_count
            || self.data_event_inclusion_proof.audit_path.len() > 64
        {
            return Err(WireError::Protocol(
                "franking Seal observation does not match the requested Event binding".to_owned(),
            ));
        }
        let proof: FrankingProof = serde_json::from_value(
            serde_json::to_value(&self.proof_event.payload).map_err(|error| {
                WireError::Protocol(format!("franking proof Event payload is invalid: {error}"))
            })?,
        )
        .map_err(|error| {
            WireError::Protocol(format!("franking proof Event payload is invalid: {error}"))
        })?;
        if proof.realm_id != request.realm_id
            || proof.event_id != request.target_event_id
            || self.proof_event.actor_id != ActorId::service(proof.received_by.clone())
        {
            return Err(WireError::Protocol(
                "franking proof payload does not bind the requested target".to_owned(),
            ));
        }
        match &self.service_signer_evidence {
            AuthenticatedSignerResolutionEvidence::Service {
                signer_id,
                verification_method,
                ..
            } if signer_id == &proof.received_by
                && verification_method == &proof.verification_method => {}
            _ => {
                return Err(WireError::Protocol(
                    "franking signer evidence does not bind the proof service method".to_owned(),
                ));
            }
        }
        let proof_created_at = self.proof_event.created_at;
        proof.validate_event_time_anchor(&FrankingProofEventTimeAnchor::new(
            request.target_event_id.clone(),
            request.realm_id.clone(),
            proof.received_by.clone(),
            proof_created_at,
            self.covering_seal.sealed_at,
        ))?;
        Ok(proof)
    }
}

/// Accepted-event anchor used to constrain a franking proof `received_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrankingProofEventTimeAnchor {
    pub target_event_id: EventId,
    pub realm_id: RealmId,
    pub received_by: DidCoreId,
    pub proof_event_created_at: DateTime<Utc>,
    pub covering_seal_sealed_at: DateTime<Utc>,
}

impl FrankingProofEventTimeAnchor {
    pub fn new(
        target_event_id: EventId,
        realm_id: RealmId,
        received_by: DidCoreId,
        proof_event_created_at: DateTime<Utc>,
        covering_seal_sealed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            target_event_id,
            realm_id,
            received_by,
            proof_event_created_at,
            covering_seal_sealed_at,
        }
    }
}

impl FrankingProof {
    pub const SIGNATURE_DOMAIN: &'static str = "ak.franking_proof.signature.v1";

    /// Construct the sole v1 franking-proof wire shape and sign its canonical
    /// transcript. The callback returns an unpadded-base64url Ed25519
    /// signature; it is deliberately crypto-backend agnostic so HSM-backed
    /// services do not need to export key material.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        realm_id: RealmId,
        event_id: EventId,
        received_by: DidCoreId,
        verification_method: DidUrl,
        received_at: DateTime<Utc>,
        replay_nonce: String,
        sign: impl FnOnce(&[u8]) -> Result<String>,
    ) -> Result<Self> {
        let mut proof = Self {
            realm_id,
            event_id,
            received_by,
            verification_method,
            received_at,
            replay_nonce,
            signature: String::new(),
        };
        proof.signature = sign(&proof.canonical_signing_bytes()?)?;
        if proof.signature.is_empty() {
            return Err(WireError::Protocol(
                "franking proof signer returned an empty signature".to_owned(),
            ));
        }
        Ok(proof)
    }

    /// Verify the exact canonical transcript through a caller-provided key
    /// resolver/backend. No digest mirror or alternate transcript is exposed.
    pub fn verify_signature(
        &self,
        verify: impl FnOnce(&DidUrl, &[u8], &str) -> Result<()>,
    ) -> Result<()> {
        if self.signature.is_empty() {
            return Err(WireError::Protocol(
                "franking proof signature is empty".to_owned(),
            ));
        }
        let bytes = self.canonical_signing_bytes()?;
        verify(&self.verification_method, &bytes, &self.signature)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningInput<'a> {
            domain: &'static str,
            realm_id: &'a RealmId,
            event_id: &'a EventId,
            received_by: &'a DidCoreId,
            verification_method: &'a DidUrl,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            received_at: DateTime<Utc>,
            replay_nonce: &'a str,
        }

        arkret_canonical::canonical_json_bytes(&SigningInput {
            domain: Self::SIGNATURE_DOMAIN,
            realm_id: &self.realm_id,
            event_id: &self.event_id,
            received_by: &self.received_by,
            verification_method: &self.verification_method,
            received_at: self.received_at,
            replay_nonce: &self.replay_nonce,
        })
        .map_err(Into::into)
    }

    pub fn validate_event_time_anchor(&self, anchor: &FrankingProofEventTimeAnchor) -> Result<()> {
        if self.event_id != anchor.target_event_id {
            return Err(WireError::Protocol(
                "franking proof event_id does not match accepted event anchor".to_owned(),
            ));
        }
        if self.realm_id != anchor.realm_id {
            return Err(WireError::Protocol(
                "franking proof realm_id does not match accepted event anchor".to_owned(),
            ));
        }
        if self.received_by != anchor.received_by {
            return Err(WireError::Protocol(
                "franking proof received_by does not match time anchor issuer".to_owned(),
            ));
        }
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol("franking proof verification_method has no fragment".to_owned())
            })?;
        if project_did_to_core_id(&Did::new(controller.to_owned())?)? != self.received_by {
            return Err(WireError::Protocol(
                "franking proof verification_method does not belong to received_by".to_owned(),
            ));
        }
        if self.received_at > anchor.proof_event_created_at
            || anchor.proof_event_created_at > anchor.covering_seal_sealed_at
        {
            return Err(WireError::Protocol(
                "franking proof time anchor must satisfy received_at <= proof Event created_at <= covering Seal sealed_at"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, project_did_to_core_id};
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    use super::*;

    fn core_id(value: &str) -> DidCoreId {
        project_did_to_core_id(&Did::new(value).unwrap()).unwrap()
    }

    fn event_id(value: &str) -> EventId {
        EventId::new(value).unwrap()
    }

    fn timestamp(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AZwRzb5tUHWAszNd7Hs0ysmMGesGCd3-p9zFZ_JKoo6q").unwrap()
    }

    fn proof() -> FrankingProof {
        FrankingProof {
            realm_id: realm_id(),
            event_id: event_id("ak:event:AY3aEHEku45kFksenyEUUeJDYGC8pcxJwaT9PypXoEZw"),
            received_by: core_id("did:webvh:z6mkfixturesoland:soland.local"),
            verification_method: DidUrl::new(
                "did:webvh:z6mkfixturesoland:soland.local#moderation-1",
            )
            .unwrap(),
            received_at: timestamp("2026-04-30T00:00:00.000Z"),
            replay_nonce: "nonce_0123456789".to_owned(),
            signature: "sig".to_owned(),
        }
    }

    fn anchor(
        proof_event_created_at: DateTime<Utc>,
        covering_seal_sealed_at: DateTime<Utc>,
    ) -> FrankingProofEventTimeAnchor {
        FrankingProofEventTimeAnchor::new(
            event_id("ak:event:AY3aEHEku45kFksenyEUUeJDYGC8pcxJwaT9PypXoEZw"),
            realm_id(),
            core_id("did:webvh:z6mkfixturesoland:soland.local"),
            proof_event_created_at,
            covering_seal_sealed_at,
        )
    }

    #[test]
    fn franking_time_anchor_accepts_matching_event_record() {
        let proof = proof();
        proof
            .validate_event_time_anchor(&anchor(
                timestamp("2026-04-30T00:00:01.000Z"),
                timestamp("2026-04-30T00:00:02.000Z"),
            ))
            .unwrap();
        assert!(
            String::from_utf8(proof.canonical_signing_bytes().unwrap())
                .unwrap()
                .contains(FrankingProof::SIGNATURE_DOMAIN)
        );
    }

    #[test]
    fn franking_time_anchor_rejects_backdated_received_at() {
        let proof = proof();
        let err = proof
            .validate_event_time_anchor(&anchor(
                timestamp("2026-04-29T23:59:59.000Z"),
                timestamp("2026-04-30T00:00:02.000Z"),
            ))
            .unwrap_err();
        assert!(err.to_string().contains("time anchor"));
    }

    #[test]
    fn franking_transcript_fixture_matches_byte_for_byte_and_rejects_mutations() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/franking-proof-transcript-fixture.json",
        )
        .unwrap();
        let case = &fixture["case"];
        let proof: FrankingProof = serde_json::from_value(case["source_payload"].clone()).unwrap();
        let signing_bytes = proof.canonical_signing_bytes().unwrap();
        assert_eq!(
            signing_bytes,
            case["transcript_jcs"].as_str().unwrap().as_bytes()
        );

        let seed = arkret_canonical::base64url_decode(
            fixture["test_key"]["private_key_seed"].as_str().unwrap(),
        )
        .unwrap();
        let seed: [u8; 32] = seed.try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        proof
            .verify_signature(|_, bytes, signature| {
                let signature = arkret_canonical::base64url_decode(signature)
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                let signature = ed25519_dalek::Signature::from_slice(&signature)
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                key.verifying_key()
                    .verify(bytes, &signature)
                    .map_err(|error| WireError::Protocol(error.to_string()))
            })
            .unwrap();

        let produced = FrankingProof::signed(
            proof.realm_id.clone(),
            proof.event_id.clone(),
            proof.received_by.clone(),
            proof.verification_method.clone(),
            proof.received_at,
            proof.replay_nonce.clone(),
            |bytes| {
                Ok(arkret_canonical::base64url_encode(
                    key.sign(bytes).to_bytes(),
                ))
            },
        )
        .unwrap();
        assert_eq!(produced, proof);

        for mutation in case["bound_field_mutations"].as_array().unwrap() {
            let bytes = arkret_canonical::canonical_json_bytes(&mutation["transcript"]).unwrap();
            let signature = arkret_canonical::base64url_decode(&proof.signature).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
            assert!(key.verifying_key().verify(&bytes, &signature).is_err());
        }
    }
}
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_lift_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionLiftPayload {
    pub target_ref: ObjectRef,
    pub decision_ref: EventId,
    /// Exact registered add dots from the observed decision Event. Required by
    /// event-payload.schema.json; partial lift never expands to every cell add.
    pub observed_dot_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod decision_lift_wire_tests {
    use super::*;

    #[test]
    fn moderation_lift_requires_and_preserves_observed_dots() {
        let decision = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-";
        let mut wire = serde_json::json!({
            "target_ref": "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8",
            "decision_ref": decision,
            "observed_dot_ids": [format!("{decision}:0")],
        });
        let payload: ModerationDecisionLiftPayload = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), wire);
        wire.as_object_mut().unwrap().remove("observed_dot_ids");
        assert!(serde_json::from_value::<ModerationDecisionLiftPayload>(wire).is_err());
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionPayload {
    pub target_ref: ObjectRef,
    pub decision: String,
    pub issuer_id: DidCoreId,
    pub request_canonical_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_report_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationReportPayload {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub target_ref: ObjectRef,
    pub report_reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModerationReportProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provider_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<ModerationEvidencePackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<FrankingProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationReportProvenance {
    #[serde(rename = "self")]
    SelfAuthored,
    MimiFacade,
}

impl ModerationReportPayload {
    pub fn validate_provenance(
        &self,
        actor_id: &DidCoreId,
    ) -> std::result::Result<(), &'static str> {
        match self.provenance {
            None | Some(ModerationReportProvenance::SelfAuthored) => {
                if self.source_provider_id.is_some() || actor_id != &self.reporter_id {
                    return Err(
                        "self-authored moderation report must be authored by reporter and omit source_provider_id",
                    );
                }
            }
            Some(ModerationReportProvenance::MimiFacade) => {
                if self.source_provider_id.is_none() || actor_id == &self.reporter_id {
                    return Err(
                        "MIMI facade moderation report requires source_provider_id and service authorship",
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate the stricter self-service moderation-report operation face.
    pub fn validate_self_endpoint(
        &self,
        actor_id: &DidCoreId,
    ) -> std::result::Result<(), &'static str> {
        self.validate_provenance(actor_id)?;
        if self.provenance == Some(ModerationReportProvenance::MimiFacade)
            || self.source_provider_id.is_some()
        {
            return Err("self moderation report forbids MIMI facade provenance");
        }
        if !matches!(
            self.report_reason_code.as_str(),
            "spam" | "harassment" | "hate_speech" | "nsfw" | "illegal" | "misinformation" | "other"
        ) {
            return Err("moderation report_reason_code is not registered");
        }
        if self.report_reason_code == "other"
            && self
                .description
                .as_deref()
                .is_none_or(|description| description.trim().is_empty())
        {
            return Err("moderation report reason other requires a non-empty description");
        }
        if self.target_ref.trim().is_empty() {
            return Err("moderation report target_ref must not be empty");
        }
        if self.evidence_refs.as_ref().is_some_and(|refs| {
            refs.iter()
                .enumerate()
                .any(|(index, value)| refs[..index].contains(value))
        }) {
            return Err("moderation report evidence_refs must be unique");
        }
        if self
            .evidence_package
            .as_ref()
            .is_some_and(|package| package.validate_for_target(&self.target_ref).is_err())
        {
            return Err("moderation evidence package does not bind the report target");
        }
        if self
            .franking_proof
            .as_ref()
            .is_some_and(|proof| proof.realm_id != self.realm_id)
        {
            return Err("moderation franking proof does not match the report Realm");
        }
        Ok(())
    }
}
