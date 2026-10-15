//! Private durable management review carriers. Pending review grants no authority.
use arkret_wire::{
    ActorId, AppletId, ApprovalSignature, Event, Hash, ManagementOperation, ScopeRef,
    event_kind_str,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AppletBotProvisionRequestBody, GhostActorProvisionRequestBody};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementReviewTarget {
    Event {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        event: Box<Event>,
    },
    BotCreation {
        applet_id: AppletId,
        request_body: Box<AppletBotProvisionRequestBody>,
    },
    GhostCreation {
        applet_id: AppletId,
        request_body: Box<GhostActorProvisionRequestBody>,
    },
}

impl ManagementReviewTarget {
    /// The actual business target, independent of the private request envelope.
    /// Creation removes only the final body's outer approval evidence; nested
    /// data and all original producer proofs remain in the signed target.
    pub fn canonical_target_digest(&self) -> arkret_wire::Result<Hash> {
        match self {
            Self::Event { event } => Ok(Hash::new(arkret_canonical::canonical_sha256(event)?)?),
            Self::BotCreation { request_body, .. } => {
                arkret_wire::management_creation_request_digest(request_body)
            }
            Self::GhostCreation { request_body, .. } => {
                arkret_wire::management_creation_request_digest(request_body)
            }
        }
    }
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewRequestBody {
    pub request_id: String,
    pub effective_scope: ScopeRef,
    pub management_operation: ManagementOperation,
    pub requester_actor_id: ActorId,
    pub target: ManagementReviewTarget,
}
impl ManagementReviewRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let valid = match (&self.management_operation, &self.target) {
            (
                ManagementOperation::CreateBot,
                ManagementReviewTarget::BotCreation {
                    applet_id,
                    request_body,
                },
            ) => {
                request_body.authoring_request.purpose
                    == crate::AppletManagedActorPurpose::ProvisionBot
                    && request_body
                        .authoring_request
                        .basis
                        .bot()
                        .is_some_and(|basis| {
                            &basis.applet_id == applet_id
                                && basis.effective_scope == self.effective_scope
                                && self.requester_actor_id
                                    == ActorId::service(basis.service_id.clone())
                        })
            }
            (
                ManagementOperation::MapGhost,
                ManagementReviewTarget::GhostCreation {
                    applet_id,
                    request_body,
                },
            ) => {
                request_body.validate().is_ok()
                    && request_body
                        .authoring_request
                        .basis
                        .ghost()
                        .is_some_and(|basis| {
                            &basis.applet_id == applet_id
                                && basis.effective_scope == self.effective_scope
                                && self.requester_actor_id
                                    == ActorId::service(basis.service_id.clone())
                        })
            }
            (ManagementOperation::Join, ManagementReviewTarget::Event { event }) => {
                event.kind.as_str() == event_kind_str::MEMBER_STATE
            }
            (ManagementOperation::Publish, ManagementReviewTarget::Event { event }) => matches!(
                event.kind.as_str(),
                event_kind_str::AGENT_INTERACTION_SET
                    | event_kind_str::PROFILE_CREATE
                    | event_kind_str::PROFILE_UPDATE
            ),
            _ => false,
        };
        let event_binding = match &self.target {
            ManagementReviewTarget::Event { event } => event.scope_ref == self.effective_scope,
            _ => true,
        };
        if self.request_id.is_empty()
            || !valid
            || !event_binding
            || !matches!(
                self.effective_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            )
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid management review target".into(),
            ));
        }
        Ok(())
    }
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewLookupRequestBody {
    pub request_id: String,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementReviewDecision {
    Approve,
    Reject,
    Cancel,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementReviewStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
    Expired,
    Consumed,
    Superseded,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewDecisionRequestBody {
    pub request_id: String,
    pub expected_status: ManagementReviewStatus,
    pub decision: ManagementReviewDecision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub approval_signatures: Vec<ApprovalSignature>,
}
impl ManagementReviewDecisionRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.expected_status != ManagementReviewStatus::Pending
            || (self.decision == ManagementReviewDecision::Approve)
                == self.approval_signatures.is_empty()
            || self.request_id.is_empty()
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid management review decision".into(),
            ));
        }
        Ok(())
    }
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewOutcome {
    pub request_id: String,
    pub status: ManagementReviewStatus,
    pub target_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub approval_signatures: Vec<ApprovalSignature>,
}
