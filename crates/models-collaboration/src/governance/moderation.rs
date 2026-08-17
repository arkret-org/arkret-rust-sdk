//! Moderation report wire DTOs.

use arkret_wire::{
    DidCoreId, DidFullId, EventInitialSubmission, EventKind, RealmId, ReportId, Result, SchemaId,
    ScopeRef, project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn now_utc_canonical() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportOutcome {
    pub report_id: ReportId,
    pub status: ModerationReportStatus,
    /// DIDs the report was routed to. Per
    /// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`
    /// this is an array of DID strings (the schema is closed), matching the
    /// `routed_to | did[]` shape in `content-moderation.md` /
    /// `service-http-binding.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to: Vec<DidCoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ModerationReportStatus {
    Submitted,
}

/// Moderation action (moderation.md §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    DenyJoin,
    DenyInvite,
    DenyWrite,
    QuarantineMessage,
    RequireReview,
    RedactOnAccept,
    ShadowCollapse,
}

/// `ak.self.moderation.command.report` request body.
///
/// The service forwards this exact caller-authored and caller-signed DataEvent
/// through ordinary Event admission. It never constructs a report Event from
/// an unsigned report projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub report_event: EventInitialSubmission,
}

/// Accepted target facts used only at the report-authoring boundary.
///
/// This basis is intentionally absent from the wire request. It must come from
/// an accepted target projection that is visible to the authenticated caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModerationReportAcceptedTargetBasis {
    pub target_ref: String,
    pub effective_scope: ScopeRef,
}

impl ModerationReportRequestBody {
    /// Validate constraints carried entirely inside the signed request.
    pub fn validate(&self) -> Result<()> {
        self.report_event.validate_structural()?;
        let event = &self.report_event.event;
        if event.kind != EventKind::SelfModerationReport {
            return Err(arkret_wire::Error::Protocol(
                "moderation report request requires ak.self.moderation.report".to_owned(),
            ));
        }
        if event.executed_by.is_some()
            || event.authorization_ref.is_some()
            || event.applet_id.is_some()
        {
            return Err(arkret_wire::Error::Protocol(
                "self moderation report requires a direct holder-authored Event".to_owned(),
            ));
        }
        if event.seal_basis.is_some() || !event.preconditions.is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "self moderation report must be a DataEvent without seal_basis or preconditions"
                    .to_owned(),
            ));
        }

        let payload: crate::events_payloads::ModerationReportPayload =
            crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
        payload
            .validate_self_endpoint(&event.actor_id)
            .map_err(|reason| arkret_wire::Error::Protocol(reason.to_owned()))?;
        if payload.realm_id != event.realm_id {
            return Err(arkret_wire::Error::Protocol(
                "moderation report payload realm_id does not match the Event realm_id".to_owned(),
            ));
        }
        let expected_scope = payload
            .effective_scope
            .as_ref()
            .cloned()
            .unwrap_or_else(|| ScopeRef::Realm {
                realm_id: payload.realm_id.clone(),
            });
        if event.scope_ref != expected_scope
            || !matches!(
                expected_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            )
        {
            return Err(arkret_wire::Error::Protocol(
                "moderation report signed scope does not match its effective scope".to_owned(),
            ));
        }

        let auth_context = event.auth_context.as_ref().ok_or_else(|| {
            arkret_wire::Error::Protocol(
                "moderation report DataEvent requires auth_context".to_owned(),
            )
        })?;
        if auth_context.key_id.is_empty()
            || auth_context.key_id.len() > 128
            || !auth_context.key_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
            })
            || auth_context.actor_id != event.actor_id
            || !event.proofs.iter().any(|proof| {
                proof.as_producer().is_some_and(|proof| {
                    proof_controller_matches_actor(
                        proof.verification_method.as_str(),
                        &event.actor_id,
                    )
                    .unwrap_or(false)
                })
            })
        {
            return Err(arkret_wire::Error::Protocol(
                "moderation report proof and auth_context must bind the holder actor".to_owned(),
            ));
        }
        Ok(())
    }

    /// Bind a structurally valid request to the authenticated principal and a
    /// visible accepted target projection.
    pub fn validate_authoring_context(
        &self,
        session_principal_id: &DidCoreId,
        accepted_target: &ModerationReportAcceptedTargetBasis,
    ) -> Result<()> {
        self.validate()?;
        let event = &self.report_event.event;
        let payload: crate::events_payloads::ModerationReportPayload =
            crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
        if &event.actor_id != session_principal_id
            || &payload.reporter != session_principal_id
            || payload.target_ref != accepted_target.target_ref
            || event.scope_ref != accepted_target.effective_scope
        {
            return Err(arkret_wire::Error::Protocol(
                "moderation report does not match its authenticated authoring context".to_owned(),
            ));
        }
        Ok(())
    }

    /// The durable report identity is the accepted Event identity with only
    /// its typed prefix changed.
    pub fn report_id(&self) -> Result<ReportId> {
        self.validate()?;
        Ok(ReportId::from_event_id(&self.report_event.event.event_id))
    }
}

fn proof_controller_matches_actor(verification_method: &str, actor_id: &DidCoreId) -> Result<bool> {
    let controller = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .ok_or_else(|| {
            arkret_wire::Error::Protocol(
                "moderation report proof verification_method has no fragment".to_owned(),
            )
        })?;
    let full_id = DidFullId::new(controller.to_owned())?;
    Ok(project_full_id_to_core_id(&full_id)? == *actor_id)
}

/// Moderation report (moderation.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub report_id: String,
    pub realm_id: RealmId,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: DidCoreId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<ModerationFrankingProof>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl ModerationReport {
    pub const SCHEMA: &'static str = SchemaId::MODERATION_REPORT_V1;
    pub fn new(
        id: impl Into<String>,
        realm_id: RealmId,
        target_ref: impl Into<String>,
        report_reason_code: impl Into<String>,
        reporter: DidCoreId,
    ) -> Self {
        Self {
            schema: Some(SchemaId::MODERATION_REPORT_V1.to_owned()),
            report_id: id.into(),
            realm_id,
            target_ref: target_ref.into(),
            report_reason_code: report_reason_code.into(),
            description: None,
            reporter,
            evidence_refs: Vec::new(),
            franking_proof: None,
            created_at: now_utc_canonical(),
        }
    }
}

/// Moderation franking proof for E2EE content (moderation.md §3.4).
///
/// `franking_tag` MUST be a key-bound MAC of the reported ciphertext that
/// only the reporter could have produced; spec leaves the algorithm open
/// per profile — this struct just carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationFrankingProof {
    pub algorithm: String,
    pub franking_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

#[cfg(test)]
mod signed_request_tests {
    use arkret_wire::{
        AuthContext, DidCoreId, DidUrl, EventInitialSubmission, Hash, Hlc, Precondition, Proof,
        RealmId, ReportId, ScopeRef, SealId, proof_kind,
    };
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::{
        ModerationReportAcceptedTargetBasis, ModerationReportOutcome, ModerationReportRequestBody,
        ModerationReportStatus,
    };

    const ACTOR: &str = "ak:did_core:webvh:z6mkfixture";
    const OTHER_ACTOR: &str = "ak:did_core:webvh:z6mkother";
    const REALM: &str = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
    const CIRCLE: &str = "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
    const TARGET: &str = "ak:event:AYe0UROSIqIZGD1cBkkPMK8WhKaAJfv7SpPwNrYjFPOD";
    const VM: &str = "did:webvh:z6mkfixture:fixture.example#device-1";

    fn actor() -> DidCoreId {
        DidCoreId::new(ACTOR).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new(REALM).unwrap()
    }

    fn signed_request(effective_scope: Option<ScopeRef>) -> ModerationReportRequestBody {
        let created_at: DateTime<Utc> = "2026-08-11T00:00:00.000Z".parse().unwrap();
        let scope_ref = effective_scope
            .clone()
            .unwrap_or_else(|| ScopeRef::Realm { realm_id: realm() });
        let mut payload = json!({
            "realm_id": REALM,
            "target_ref": TARGET,
            "report_reason_code": "spam",
            "reporter": ACTOR,
            "provenance": "self"
        });
        if let Some(scope) = effective_scope {
            payload["effective_scope"] = serde_json::to_value(scope).unwrap();
        }
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.self.moderation.report",
            scope_ref,
            actor(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
            created_at,
        )
        .unwrap();
        event.seal_ref = Some(SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap());
        event.auth_context = Some(AuthContext {
            actor_id: actor(),
            key_id: arkret_wire::OpaqueLocalId::new("device-1").unwrap(),
            key_epoch: 1,
            credential_epoch: None,
        });
        event.refresh_content_bound_identity().unwrap();
        let event_digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![
            Proof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(VM).unwrap(),
                event_digest,
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }
            .into(),
        ];
        ModerationReportRequestBody {
            report_event: EventInitialSubmission::online(event),
        }
    }

    fn realm_basis() -> ModerationReportAcceptedTargetBasis {
        ModerationReportAcceptedTargetBasis {
            target_ref: TARGET.to_owned(),
            effective_scope: ScopeRef::Realm { realm_id: realm() },
        }
    }

    #[test]
    fn valid_realm_and_circle_reports_bind_signed_authoring_context() {
        let realm_request = signed_request(None);
        realm_request.validate().unwrap();
        realm_request
            .validate_authoring_context(&actor(), &realm_basis())
            .unwrap();
        assert_eq!(
            realm_request.report_id().unwrap(),
            ReportId::from_event_id(&realm_request.report_event.event.event_id)
        );

        let circle_scope = ScopeRef::Circle {
            realm_id: realm(),
            circle_id: arkret_wire::CircleId::new(CIRCLE).unwrap(),
        };
        let circle_request = signed_request(Some(circle_scope.clone()));
        circle_request
            .validate_authoring_context(
                &actor(),
                &ModerationReportAcceptedTargetBasis {
                    target_ref: TARGET.to_owned(),
                    effective_scope: circle_scope,
                },
            )
            .unwrap();
    }

    #[test]
    fn request_rejects_wrong_kind_scope_actor_and_target() {
        let mut wrong_kind = signed_request(None);
        wrong_kind.report_event.event.kind = arkret_wire::EventKind::MessageCreate;
        assert!(wrong_kind.validate().is_err());

        let mut wrong_scope = signed_request(None);
        wrong_scope.report_event.event.scope_ref = ScopeRef::Circle {
            realm_id: realm(),
            circle_id: arkret_wire::CircleId::new(CIRCLE).unwrap(),
        };
        assert!(wrong_scope.validate().is_err());

        let request = signed_request(None);
        assert!(
            request
                .validate_authoring_context(&DidCoreId::new(OTHER_ACTOR).unwrap(), &realm_basis())
                .is_err()
        );
        let mut wrong_target = realm_basis();
        wrong_target.target_ref =
            "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6".to_owned();
        assert!(
            request
                .validate_authoring_context(&actor(), &wrong_target)
                .is_err()
        );
    }

    #[test]
    fn request_rejects_delegated_mimi_and_control_move_fields() {
        let mut delegated = signed_request(None);
        delegated.report_event.event.executed_by = Some(actor());
        assert!(delegated.validate().is_err());

        let mut mimi = signed_request(None);
        mimi.report_event.event.payload.insert(
            "provenance".to_owned(),
            serde_json::Value::String("mimi_facade".to_owned()),
        );
        mimi.report_event.event.payload.insert(
            "source_provider".to_owned(),
            serde_json::Value::String(OTHER_ACTOR.to_owned()),
        );
        assert!(mimi.validate().is_err());

        let mut guarded = signed_request(None);
        guarded.report_event.event.preconditions = vec![Precondition {
            cell: arkret_wire::CellRef::new("ak:cell:ak.component.realm.authority_root.v1:null")
                .unwrap(),
            predicate: arkret_wire::Predicate {
                op: arkret_wire::PredicateOp::HeadEq,
                value: Some(json!(null)),
                values: None,
                predicate_id: None,
            },
        }];
        assert!(guarded.validate().is_err());
    }

    #[test]
    fn request_rejects_wrong_reporter_proof_and_other_without_description() {
        let mut wrong_reporter = signed_request(None);
        wrong_reporter.report_event.event.payload.insert(
            "reporter".to_owned(),
            serde_json::Value::String(OTHER_ACTOR.to_owned()),
        );
        assert!(wrong_reporter.validate().is_err());

        let mut wrong_proof = signed_request(None);
        wrong_proof.report_event.event.proofs[0]
            .as_producer_mut()
            .unwrap()
            .verification_method =
            DidUrl::new("did:webvh:z6mkother:other.example#device-1").unwrap();
        assert!(wrong_proof.validate().is_err());

        let mut other = signed_request(None);
        other.report_event.event.payload.insert(
            "report_reason_code".to_owned(),
            serde_json::Value::String("other".to_owned()),
        );
        assert!(other.validate().is_err());
    }

    #[test]
    fn submission_outcome_is_closed_and_submitted() {
        let request = signed_request(None);
        let outcome = ModerationReportOutcome {
            report_id: request.report_id().unwrap(),
            status: ModerationReportStatus::Submitted,
            routed_to: Vec::new(),
        };
        assert_eq!(outcome.status, ModerationReportStatus::Submitted);
        assert!(
            serde_json::from_value::<ModerationReportOutcome>(json!({
                "report_id": request.report_id().unwrap(),
                "status": "resolved"
            }))
            .is_err()
        );
    }
}
