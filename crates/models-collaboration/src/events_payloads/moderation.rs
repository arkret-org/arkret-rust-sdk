//! Moderation schema artifact counterparts and event payloads.

use arkret_wire::{DidCoreId, DidFullId, DidUrl, project_full_id_to_core_id};

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
    pub encrypted_to: DidUrl,
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
            || self.recipient_public_key_ref != self.encrypted_to
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
        if project_full_id_to_core_id(&DidFullId::new(controller.to_owned())?)? != self.received_by
        {
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
    use arkret_wire::{DidFullId, project_full_id_to_core_id};

    use super::*;

    fn did(value: &str) -> DidCoreId {
        project_full_id_to_core_id(&DidFullId::new(value).unwrap()).unwrap()
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
            received_by: did("did:webvh:z6mkfixturesoland:soland.local"),
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
            did("did:webvh:z6mkfixturesoland:soland.local"),
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
}
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_lift_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionLiftPayload {
    pub target_ref: ObjectRef,
    pub decision_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionPayload {
    pub target_ref: ObjectRef,
    pub decision: String,
    pub issuer: DidCoreId,
    pub request_canonical_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision_ref: Option<EventId>,
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
    pub reporter: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModerationReportProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provider: Option<DidCoreId>,
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
                if self.source_provider.is_some() || actor_id != &self.reporter {
                    return Err(
                        "self-authored moderation report must be authored by reporter and omit source_provider",
                    );
                }
            }
            Some(ModerationReportProvenance::MimiFacade) => {
                if self.source_provider.is_none() || actor_id == &self.reporter {
                    return Err(
                        "MIMI facade moderation report requires source_provider and service authorship",
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
            || self.source_provider.is_some()
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
