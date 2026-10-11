//! Private durable management review carriers. Pending review grants no authority.
use arkret_wire::{
    ActorId, AppletId, ApprovalSignature, Event, Hash, ManagementOperation, ScopeRef,
    event_kind_str,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AppletBotProvisionRequestBody, GhostActorProvisionRequestBody};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementReviewTarget {
    Event {
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
                ManagementReviewTarget::BotCreation { request_body, .. },
            ) => {
                request_body.authoring_request.purpose
                    == crate::AppletManagedActorPurpose::ProvisionBot
            }
            (
                ManagementOperation::MapGhost,
                ManagementReviewTarget::GhostCreation { request_body, .. },
            ) => request_body.validate().is_ok(),
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
        if self.request_id.is_empty() || !valid {
            return Err(arkret_wire::WireError::Protocol(
                "invalid management review target".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewLookupRequestBody {
    pub request_id: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementReviewDecision {
    Approve,
    Reject,
    Cancel,
}
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewDecisionRequestBody {
    pub request_id: String,
    pub expected_status: ManagementReviewStatus,
    pub decision: ManagementReviewDecision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementReviewOutcome {
    pub request_id: String,
    pub status: ManagementReviewStatus,
    pub target_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_signatures: Vec<ApprovalSignature>,
}
