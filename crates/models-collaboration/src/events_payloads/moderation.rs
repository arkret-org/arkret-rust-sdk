//! Moderation schema artifact counterparts and event payloads.

use arkret_wire::EventKind;

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json`.
pub type ModerationAppeal = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/actor_ref`.
pub type ActorRef = Did;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/appeal_id`.
pub type AppealId = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/close_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosePayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub closer: ActorRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub closed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_closed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub reviewer: ActorRef,
    pub verdict: String,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_ref`.
pub type DecisionRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/evidence_visibility`.
pub type EvidenceVisibility = AppealEvidenceVisibility;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/review_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub reviewer: ActorRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_ref: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/submit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub decision_ref: DecisionRef,
    pub target_ref: TargetRef,
    pub appellant: ActorRef,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_visibility: Option<EvidenceVisibility>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/target_ref`.
pub type TargetRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-report.schema.json#/$defs/franking_proof`.

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingProofSenderClaim {
    pub actor_id: Did,
    pub device_id: String,
    pub mls_group_id_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingProof {
    pub kind: String,
    pub franking_proof_id: String,
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub routing_metadata_digest: Hash,
    pub ciphertext_digest: Hash,
    pub aad_digest: Hash,
    pub sender_claim: FrankingProofSenderClaim,
    pub received_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub replay_nonce: String,
    pub signature: String,
}

/// Accepted-event anchor used to constrain a franking proof `received_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrankingProofEventTimeAnchor {
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub received_by: Did,
    pub received_at: DateTime<Utc>,
    pub ciphertext_digest: Hash,
}

impl FrankingProofEventTimeAnchor {
    pub fn new(
        event_id: EventId,
        realm_id: RealmId,
        received_by: Did,
        received_at: DateTime<Utc>,
        ciphertext_digest: Hash,
    ) -> Self {
        Self {
            event_id,
            realm_id,
            received_by,
            received_at,
            ciphertext_digest,
        }
    }
}

impl FrankingProof {
    pub const TIME_ANCHOR_MAX_SKEW_SECS: i64 = 300;

    pub fn validate_event_time_anchor(&self, anchor: &FrankingProofEventTimeAnchor) -> Result<()> {
        if self.kind != EventKind::MODERATION_FRANKING_PROOF {
            return Err(Error::Protocol(
                "franking proof kind must be ak.moderation.franking_proof".to_owned(),
            ));
        }
        if self.event_id != anchor.event_id {
            return Err(Error::Protocol(
                "franking proof event_id does not match accepted event anchor".to_owned(),
            ));
        }
        if self.realm_id != anchor.realm_id {
            return Err(Error::Protocol(
                "franking proof realm_id does not match accepted event anchor".to_owned(),
            ));
        }
        if self.received_by != anchor.received_by {
            return Err(Error::Protocol(
                "franking proof received_by does not match time anchor issuer".to_owned(),
            ));
        }
        if self.ciphertext_digest != anchor.ciphertext_digest {
            return Err(Error::Protocol(
                "franking proof ciphertext_digest does not match accepted encrypted event"
                    .to_owned(),
            ));
        }
        let skew_secs = self
            .received_at
            .signed_duration_since(anchor.received_at)
            .num_seconds()
            .abs();
        if skew_secs > Self::TIME_ANCHOR_MAX_SKEW_SECS {
            return Err(Error::Protocol(format!(
                "franking proof received_at is not constrained by the accepted event time anchor: skew {skew_secs}s"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn event_id(value: &str) -> EventId {
        EventId::new(value).unwrap()
    }

    fn hash(ch: char) -> Hash {
        Hash::new(format!("sha256:{}", ch.to_string().repeat(64))).unwrap()
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
            kind: EventKind::MODERATION_FRANKING_PROOF.to_owned(),
            franking_proof_id: "ak:franking_proof:01904100-0000-7000-8000-000000000111".to_owned(),
            realm_id: realm_id(),
            event_id: event_id("ak:event:AY3aEHEku45kFksenyEUUeJDYGC8pcxJwaT9PypXoEZw"),
            routing_metadata_digest: hash('c'),
            ciphertext_digest: hash('d'),
            aad_digest: hash('e'),
            sender_claim: FrankingProofSenderClaim {
                actor_id: did("did:webvh:z6mkfixture:alice.example"),
                device_id: "ak:device:01904100-0000-7000-8000-000000000333".to_owned(),
                mls_group_id_digest: hash('f'),
            },
            received_by: did("did:webvh:z6mkfixture:soland.local"),
            received_at: timestamp("2026-04-30T00:00:00.000Z"),
            replay_nonce: "nonce_0123456789".to_owned(),
            signature: "sig".to_owned(),
        }
    }

    fn anchor(received_at: DateTime<Utc>) -> FrankingProofEventTimeAnchor {
        FrankingProofEventTimeAnchor::new(
            event_id("ak:event:AY3aEHEku45kFksenyEUUeJDYGC8pcxJwaT9PypXoEZw"),
            realm_id(),
            did("did:webvh:z6mkfixture:soland.local"),
            received_at,
            hash('d'),
        )
    }

    #[test]
    fn franking_time_anchor_accepts_matching_event_record() {
        let proof = proof();
        proof
            .validate_event_time_anchor(&anchor(timestamp("2026-04-30T00:00:01.000Z")))
            .unwrap();
    }

    #[test]
    fn franking_time_anchor_rejects_backdated_received_at() {
        let proof = proof();
        let err = proof
            .validate_event_time_anchor(&anchor(timestamp("2026-04-30T00:10:01.000Z")))
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
    pub issuer: Did,
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
    pub expires_at: Option<NullableTimestamp>,
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
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModerationReportProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provider: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationReportProvenance {
    #[serde(rename = "self")]
    SelfAuthored,
    MimiFacade,
}

impl ModerationReportPayload {
    pub fn validate_provenance(&self, actor_id: &Did) -> std::result::Result<(), &'static str> {
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
}
