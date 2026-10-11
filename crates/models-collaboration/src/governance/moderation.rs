//! Moderation report wire DTOs.

use arkret_wire::{
    AccountId, Did, DidCoreId, EventAdmissionSubmission, EventKind, ReportId, Result, ScopeRef,
    project_did_to_core_id,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportOutcome {
    pub report_id: ReportId,
    pub status: ModerationReportStatus,
    /// DIDs the report was routed to. Per
    /// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`
    /// this is an array of DID strings (the schema is closed), matching the
    /// `routed_to_ids | did[]` shape in `content-moderation.md` /
    /// `service-http-binding.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to_ids: Vec<DidCoreId>,
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

/// `ak.self.moderation.command.report.v1` request body.
///
/// The service forwards this exact caller-authored and caller-signed ordinary Event
/// through ordinary Event admission. It never constructs a report Event from
/// an unsigned report projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub report_event: EventAdmissionSubmission,
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
        let event = &self.report_event.event;
        if event.kind != EventKind::SelfModerationReport {
            return Err(arkret_wire::WireError::Protocol(
                "moderation report request requires ak.self.moderation.report".to_owned(),
            ));
        }
        if event.executed_by.is_some()
            || event.authorization_ref.is_some()
            || event.applet_id.is_some()
        {
            return Err(arkret_wire::WireError::Protocol(
                "self moderation report requires a direct holder-authored Event".to_owned(),
            ));
        }
        let payload: crate::events_payloads::ModerationReportPayload =
            crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
        payload
            .validate_self_endpoint(event.actor_id.signing_principal_id())
            .map_err(|reason| arkret_wire::WireError::Protocol(reason.to_owned()))?;
        if payload.realm_id != event.realm_id {
            return Err(arkret_wire::WireError::Protocol(
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
            return Err(arkret_wire::WireError::Protocol(
                "moderation report signed scope does not match its effective scope".to_owned(),
            ));
        }

        if !event.producer_proof.as_ref().is_some_and(|proof| {
            proof_controller_matches_actor(
                proof.verification_method.as_str(),
                event.actor_id.signing_principal_id(),
            )
            .unwrap_or(false)
        }) {
            return Err(arkret_wire::WireError::Protocol(
                "moderation report proof must bind the holder actor".to_owned(),
            ));
        }
        Ok(())
    }

    /// Bind a structurally valid request to the authenticated principal and a
    /// visible accepted target projection.
    pub fn validate_authoring_context(
        &self,
        session_account_id: &AccountId,
        accepted_target: &ModerationReportAcceptedTargetBasis,
    ) -> Result<()> {
        self.validate()?;
        let event = &self.report_event.event;
        let payload: crate::events_payloads::ModerationReportPayload =
            crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
        if event.actor_id.as_account_id() != Some(session_account_id)
            || payload.reporter_id != session_account_id.principal_id
            || payload.target_ref != accepted_target.target_ref
            || event.scope_ref != accepted_target.effective_scope
        {
            return Err(arkret_wire::WireError::Protocol(
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
            arkret_wire::WireError::Protocol("verification_method has no fragment".into())
        })?;
    Ok(project_did_to_core_id(&Did::new(controller.to_owned())?)? == *actor_id)
}
