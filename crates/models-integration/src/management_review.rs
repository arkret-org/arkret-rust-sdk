//! Private durable management review carriers. Pending review grants no authority.
use arkret_wire::{
    ActorId, ApprovalSignature, Event, Hash, ManagementOperation, ScopeRef, event_kind_str,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementReviewTarget {
    Event {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        event: Box<Event>,
    },
}

impl ManagementReviewTarget {
    /// The actual business target, independent of the private request envelope.
    /// Creation removes only the final body's outer approval evidence; nested
    /// data and all original producer proofs remain in the signed target.
    pub fn canonical_target_digest(&self) -> arkret_wire::Result<Hash> {
        match self {
            Self::Event { event } => Ok(Hash::new(arkret_canonical::canonical_sha256(event)?)?),
        }
    }
}
/// An exact private administrator configuration intent; never an approval.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationRef {
    pub request_id: arkret_wire::RequestId,
    pub intent_digest: Hash,
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub configuration_ref: Option<AppletConfigurationRef>,
}
impl ManagementReviewRequestBody {
    /// Immutable private intent uses the actual target digest, so attaching
    /// outer creation votes cannot change or circularly redefine the request.
    pub fn canonical_intent_digest(&self) -> arkret_wire::Result<Hash> {
        self.validate()?;
        let mut intent = serde_json::json!({
            "request_id":self.request_id,"effective_scope":self.effective_scope,
            "management_operation":self.management_operation,"requester_actor_id":self.requester_actor_id,
            "target_digest":self.target.canonical_target_digest()?
        });
        if let Some(reference) = &self.configuration_ref {
            intent["configuration_ref"] = serde_json::to_value(reference)?;
        }
        Ok(Hash::new(arkret_canonical::canonical_sha256(&intent)?)?)
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        let valid = match (&self.management_operation, &self.target) {
            (ManagementOperation::CreateBot | ManagementOperation::MapGhost, ManagementReviewTarget::Event { event }) => {
                serde_json::from_value::<crate::RealmActorCreatePayload>(serde_json::json!(&event.payload))
                    .is_ok_and(|candidate| candidate.validate().is_ok()
                        && event.kind == arkret_wire::EventKind::RealmActorCreate
                        && event.actor_id == ActorId::service(candidate.service_id.clone())
                        && event.realm_id == candidate.actor_id.as_realm_actor_id().unwrap().realm_id
                        && event.scope_ref == (ScopeRef::RealmControl { realm_id: event.realm_id.clone() })
                        && event.executed_by.is_none()
                        && event.applet_id.as_ref() == Some(&candidate.applet_id)
                        && event.authorization_ref.as_deref() == Some(candidate.creation_authorization_ref.as_str())
                        && self.requester_actor_id == event.actor_id
                        && candidate.creation_scope == self.effective_scope
                        && matches!((&self.management_operation, candidate.actor_role),
                            (ManagementOperation::CreateBot, crate::RealmActorCreatePayloadActorRole::Bot)
                            | (ManagementOperation::MapGhost, crate::RealmActorCreatePayloadActorRole::Ghost)))
            }
            (ManagementOperation::Join, ManagementReviewTarget::Event { event }) => {
                event.kind.as_str() == event_kind_str::MEMBER_STATE
                    || (event.kind.as_str() == event_kind_str::CIRCLE_MEMBER_STATE
                        && event.applet_id.is_some()
                        && event.executed_by.is_none()
                        && matches!(event.actor_id, ActorId::Realm { .. })
                        && serde_json::from_value::<arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload>(serde_json::json!(&event.payload))
                            .is_ok_and(|payload| payload.member_id == event.actor_id
                                && payload.membership == arkret_models_collaboration::governance::circle::CircleMembership::Join
                                && matches!(&event.scope_ref, ScopeRef::Circle { realm_id, circle_id }
                                    if realm_id == &event.realm_id && circle_id == &payload.circle_id)))
            }
            (ManagementOperation::Publish, ManagementReviewTarget::Event { event }) => matches!(
                event.kind.as_str(),
                event_kind_str::AGENT_INTERACTION_SET
                    | event_kind_str::PROFILE_CREATE
                    | event_kind_str::PROFILE_UPDATE
            ),
        };
        let event_binding = match &self.target {
            ManagementReviewTarget::Event { event } => {
                event.kind == arkret_wire::EventKind::RealmActorCreate
                    || (self.management_operation == ManagementOperation::Publish
                        && matches!(
                            event.kind,
                            arkret_wire::EventKind::ProfileCreate
                                | arkret_wire::EventKind::ProfileUpdate
                        )
                        && event
                            .actor_id
                            .as_realm_actor_id()
                            .is_some_and(|actor| actor.realm_id == event.realm_id)
                        && event.scope_ref
                            == (ScopeRef::RealmControl {
                                realm_id: event.realm_id.clone(),
                            })
                        && event.realm_id == *self.effective_scope.realm_id()
                        && event.applet_id.is_some()
                        && event.executed_by.is_none()
                        && event.authorization_ref.is_none()
                        && matches!(self.requester_actor_id, ActorId::Service { .. }))
                    || event.scope_ref == self.effective_scope
            }
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
pub struct ManagementReviewResponseBody {
    pub request_id: String,
    pub status: ManagementReviewStatus,
    pub target_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub approval_signatures: Vec<ApprovalSignature>,
}
