//! Personal-agent Event materialization.

use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::events_payloads::agent::{
    AgentDeactivatePayload, AgentKeyAuthorizePayload, AgentKeyRevokePayload, AgentPausePayload,
    AgentResumePayload,
};
use arkret_wire::{DidCoreId, DidUrl, ScopeRef, event_spec};
use chrono::{DateTime, Utc};

use crate::{EventIntent, EventSpec, Result, TypedEventDraft};

/// Draft a controller-executed `ak.agent.key.authorize`.
///
/// An [`EventIntent`], not an authored Event: the agent signing-key binding
/// commits to this Event's `event_id`, so the caller has to author it through
/// its submit path — with a real actor frontier and HLC — before it can bind
/// anything to that identity.
// Every parameter is a distinct protocol-required binding on the authorize
// Event; collapsing them into one input struct would hide which of them the
// caller may omit.
pub fn build_agent_key_authorize_intent(
    payload: &AgentKeyAuthorizePayload,
    scope_ref: ScopeRef,
    agent_actor_id: DidCoreId,
    controller_id: DidCoreId,
    controller_authorization_ref: DidUrl,
    created_at: DateTime<Utc>,
) -> Result<EventIntent> {
    TypedEventDraft::<event_spec::AgentKeyAuthorize>::new(
        scope_ref,
        agent_actor_id,
        controller_id.clone(),
        payload.clone(),
    )?
    .with_executed_by(controller_id)
    .with_authorization_ref(controller_authorization_ref.into())
    .into_intent(created_at)
}

/// Build the controller-executed `ak.agent.key.revoke` write.
pub fn build_agent_key_revoke_intent(
    payload: &AgentKeyRevokePayload,
    scope_ref: ScopeRef,
    agent_actor_id: DidCoreId,
    controller_id: DidCoreId,
    controller_authorization_ref: DidUrl,
    created_at: DateTime<Utc>,
) -> Result<EventIntent> {
    TypedEventDraft::<event_spec::AgentKeyRevoke>::new(
        scope_ref,
        agent_actor_id,
        controller_id.clone(),
        payload.clone(),
    )?
    .with_executed_by(controller_id)
    .with_authorization_ref(controller_authorization_ref.into())
    .into_intent(created_at)
}

struct AgentLifecycleEventInput<P> {
    payload: P,
    agent_id: DidCoreId,
    controller_id: DidCoreId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    status_changed_at: DateTime<Utc>,
}

fn build_agent_lifecycle_intent<K: EventSpec>(
    input: AgentLifecycleEventInput<K::Payload>,
) -> Result<EventIntent> {
    TypedEventDraft::<K>::new(
        input.principal_control_scope_ref,
        input.agent_id.clone(),
        input.controller_id.clone(),
        input.payload,
    )?
    .with_executed_by(input.controller_id)
    .with_authorization_ref(input.controller_authorization_ref.into())
    .into_intent(input.status_changed_at)
}

/// Build the controller-executed `ak.self.agent.pause` write.
pub fn build_agent_pause_intent(
    agent_id: DidCoreId,
    controller_id: DidCoreId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    reason: Option<arkret_wire::AuditReasonText>,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let payload = AgentPausePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "pause".to_owned(),
        previous_status: "active".to_owned(),
        status_changed_at,
        reason,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentPause>(AgentLifecycleEventInput {
        payload,
        agent_id,
        controller_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}

/// Build the controller-executed `ak.self.agent.resume` write.
pub fn build_agent_resume_intent(
    agent_id: DidCoreId,
    controller_id: DidCoreId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let payload = AgentResumePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "resume".to_owned(),
        previous_status: "paused".to_owned(),
        status_changed_at,
        reason: None,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentResume>(AgentLifecycleEventInput {
        payload,
        agent_id,
        controller_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}

/// Build the controller-executed `ak.self.agent.deactivate` write.
/// Deactivation may start from either active or paused and is terminal.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_deactivate_intent(
    agent_id: DidCoreId,
    controller_id: DidCoreId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    previous_status: AgentLifecycleState,
    reason: Option<arkret_wire::AuditReasonText>,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let previous_status = match previous_status {
        AgentLifecycleState::Active => "active",
        AgentLifecycleState::Paused => "paused",
        AgentLifecycleState::Deactivated => {
            return Err(crate::EventDraftError::Protocol(
                "cannot author an Agent deactivation from terminal deactivated state".to_owned(),
            ));
        }
    };
    let payload = AgentDeactivatePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "deactivate".to_owned(),
        previous_status: previous_status.to_owned(),
        status_changed_at,
        reason,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentDeactivate>(AgentLifecycleEventInput {
        payload,
        agent_id,
        controller_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DidFullId, project_full_id_to_core_id};
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyScope,
    };
    use arkret_schema::{or_set_dot, project_registered_cell_writes};
    use arkret_wire::cell::composite_subject;
    use arkret_wire::{
        AuthoredEvent, CellRef, Event, EventId, EventKind, Hash, Hlc, LatticeOp, LatticeOpType,
        ProjectedCellWrite, ProjectedOp, RealmId,
    };
    use chrono::TimeZone;
    use serde_json::{Value, json};

    use super::*;

    fn did(name: &str) -> DidCoreId {
        project_full_id_to_core_id(&full_id(name)).unwrap()
    }

    fn full_id(name: &str) -> DidFullId {
        DidFullId::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x41; 32],
        ))
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    /// Every cell write the registry derives for `event`.
    ///
    /// A v1 producer stamps no reducer instruction on the wire, so this
    /// projection — not an `effects[]` array — is what the assertions below are
    /// about.
    fn project(event: &Event) -> Vec<ProjectedCellWrite> {
        project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .expect("the registered contract must be evaluable")
    }

    fn agent_key_cell(agent_id: &DidCoreId, key_id: &str) -> CellRef {
        let subject = composite_subject(&[agent_id.as_str(), key_id]).unwrap();
        CellRef::new(format!("ak:cell:ak.component.agent.key.v1:{subject}")).unwrap()
    }

    fn agent_status_cell(agent_id: &DidCoreId) -> CellRef {
        CellRef::new(format!("ak:cell:ak.component.agent.status.v1:{agent_id}")).unwrap()
    }

    fn payload_object(event: &Event) -> Value {
        Value::Object(event.payload.clone().into_iter().collect())
    }

    /// Finalize an intent at a pinned chain position.
    ///
    /// The projections below are keyed by the Event's own dot, which exists only
    /// after the identity is derived. Production positions the write from the
    /// accepted actor frontier and the durable signing stamp; a unit test has
    /// neither, so it pins both.
    fn authored(intent: EventIntent, actor_seq: u64) -> AuthoredEvent {
        intent
            .author_with_digest_suite(
                actor_seq,
                Hlc::new(format!("01970e589d21-{actor_seq:04}-a13f9c2e")).unwrap(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .expect("a test intent finalizes")
    }

    fn transition_write(cell: CellRef, from: Value, to: Value) -> ProjectedCellWrite {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        op.from = Some(from);
        op.to = Some(to);
        ProjectedCellWrite {
            cell,
            op: ProjectedOp::Direct(op),
        }
    }

    fn key_authorize_payload(
        agent_id: DidCoreId,
        agent_full_id: &DidFullId,
        controller_id: DidCoreId,
    ) -> AgentKeyAuthorizePayload {
        AgentKeyAuthorizePayload {
            agent_id,
            key_id: arkret_wire::NonEmptyString::new("runtime-key-1").unwrap(),
            verification_method: DidUrl::new(format!("{agent_full_id}#runtime-key-1")).unwrap(),
            public_key_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            signing_key_binding_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            accountable_principal_id: controller_id.clone(),
            agent_key_scope: AgentKeyScope {
                actions: vec!["ak.message.create".to_owned()],
                resources: vec![],
                constraints: vec![],
            },
            audience: vec!["https://arkret.example".to_owned()],
            issued_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 0, 0).unwrap(),
            expires_at: Some(Utc.with_ymd_and_hms(2026, 5, 26, 10, 15, 0).unwrap()),
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::ApprovalEvent,
                evidence_ref: Some(
                    "ak:event:AV97PI2Y6Qum1pZ62jB1P6M_I7KjPy5KVQxs3bDBUkws".to_owned(),
                ),
                request_canonical_digest: None,
                pairing_request_id: None,
                approved_by: Some(controller_id),
            },
            supersedes: vec![],
            revocation_check_ref: None,
            runtime_attestation: None,
        }
    }

    #[test]
    fn key_authorize_event_binds_controller_execution() {
        let agent_id = did("agent");
        let agent_full_id = full_id("agent");
        let controller_id = did("controller");
        let controller_principal_id = DidCoreId::new(controller_id.as_str()).unwrap();
        let event = authored(
            build_agent_key_authorize_intent(
                &key_authorize_payload(agent_id.clone(), &agent_full_id, controller_principal_id),
                scope(),
                agent_id.clone(),
                controller_id.clone(),
                DidUrl::new(format!("{agent_full_id}#managed-controller")).unwrap(),
                Utc.with_ymd_and_hms(2026, 5, 26, 10, 30, 0).unwrap(),
            )
            .unwrap(),
            7,
        );

        assert_eq!(event.kind, EventKind::AgentKeyAuthorize);
        assert_eq!(event.actor_id, agent_id);
        assert_eq!(event.executed_by, Some(controller_id));
        assert_eq!(event.payload["key_id"], "runtime-key-1");
    }

    /// A `(agent_id, key_id)` authorization is replaced, never overwritten:
    /// `zh/identity/key-management.md` §3.6.1 requires the same Control Move to
    /// observe-remove every active authorize dot on
    /// `ak.component.agent.key.v1` and atomically add the replacement dot. The
    /// registry encodes that as two `cell_writes[]` entries deriving the same
    /// cell, so the add's dot is at `write_index` 1.
    #[test]
    fn key_authorize_projects_atomic_replacement_pair() {
        let agent_id = did("agent");
        let agent_full_id = full_id("agent");
        let controller_id = did("controller");
        let controller_principal_id = DidCoreId::new(controller_id.as_str()).unwrap();
        let event = authored(
            build_agent_key_authorize_intent(
                &key_authorize_payload(agent_id.clone(), &agent_full_id, controller_principal_id),
                scope(),
                agent_id.clone(),
                controller_id,
                DidUrl::new(format!("{agent_full_id}#managed-controller")).unwrap(),
                Utc.with_ymd_and_hms(2026, 5, 26, 10, 30, 0).unwrap(),
            )
            .unwrap(),
            7,
        );

        let cell = agent_key_cell(&agent_id, "runtime-key-1");
        let mut add = LatticeOp::empty();
        add.op_type = LatticeOpType::Add;
        // `event-and-patch.md` §2.4.2: the tag is the canonical dot
        // `"ak:event:" + event_id + ":" + write_index`, never a bare event_id.
        add.tag = Some(or_set_dot(event.event_id.as_str(), 1));
        add.value = Some(payload_object(&event));
        assert_eq!(
            project(&event),
            vec![
                ProjectedCellWrite {
                    cell: cell.clone(),
                    op: ProjectedOp::RemoveObserved {
                        element_match: None
                    },
                },
                ProjectedCellWrite {
                    cell,
                    op: ProjectedOp::Direct(add),
                },
            ]
        );
    }

    #[test]
    fn key_revoke_projects_remove_and_revocation_fact() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let event = authored(
            build_agent_key_revoke_intent(
                &AgentKeyRevokePayload {
                    agent_id: agent_id.clone(),
                    key_id: arkret_wire::NonEmptyString::new("runtime-key-1").unwrap(),
                    revoked_by: controller_id.clone(),
                    revoked_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 30, 0).unwrap(),
                    reason: Some(
                        arkret_wire::AuditReasonText::new("controller_deactivated").unwrap(),
                    ),
                },
                scope(),
                agent_id.clone(),
                controller_id,
                DidUrl::new("did:webvh:z6mkfixture:agent.example#managed-controller").unwrap(),
                Utc.with_ymd_and_hms(2026, 5, 26, 10, 30, 0).unwrap(),
            )
            .unwrap(),
            8,
        );

        // The first write clears every active authorization dot observed in the
        // frozen pre-state. The second records the revocation payload under the
        // canonical write-index dot so the accepted reason and cutoff remain
        // auditable without reviving the removed authorization.
        let cell = agent_key_cell(&agent_id, "runtime-key-1");
        let mut add = LatticeOp::empty();
        add.op_type = LatticeOpType::Add;
        add.tag = Some(or_set_dot(event.event_id.as_str(), 1));
        add.value = Some(payload_object(&event));
        assert_eq!(
            project(&event),
            vec![
                ProjectedCellWrite {
                    cell: cell.clone(),
                    op: ProjectedOp::RemoveObserved {
                        element_match: None
                    },
                },
                ProjectedCellWrite {
                    cell,
                    op: ProjectedOp::Direct(add),
                },
            ]
        );
    }

    #[test]
    fn lifecycle_events_bind_payload_and_status_transition() {
        let agent_id = did("agent");
        let agent_full_id = full_id("agent");
        let controller_id = did("controller");
        let changed_at = Utc.with_ymd_and_hms(2026, 7, 19, 8, 0, 0).unwrap();
        let authorization_ref = DidUrl::new(format!("{agent_full_id}#managed-controller")).unwrap();

        let status_cell = agent_status_cell(&agent_id);

        let pause = authored(
            build_agent_pause_intent(
                agent_id.clone(),
                controller_id.clone(),
                scope(),
                authorization_ref.clone(),
                Some(arkret_wire::AuditReasonText::new("user_requested").unwrap()),
                changed_at,
            )
            .unwrap(),
            8,
        );
        assert_eq!(pause.kind, EventKind::SelfAgentPause);
        assert_eq!(
            project(&pause),
            vec![transition_write(
                status_cell.clone(),
                json!("active"),
                json!("paused")
            )]
        );
        // The registered `transition` projection declares only `from` and `to`,
        // so the lattice op carries no `reason` (`event-and-patch.md` §2.4.2:
        // members the projection does not declare MUST stay absent). The
        // operator's reason survives as a signed payload field instead.
        assert_eq!(pause.payload["reason"], "user_requested");

        let resume = authored(
            build_agent_resume_intent(
                agent_id,
                controller_id,
                scope(),
                authorization_ref,
                changed_at,
            )
            .unwrap(),
            9,
        );
        assert_eq!(resume.kind, EventKind::SelfAgentResume);
        assert_eq!(
            project(&resume),
            vec![transition_write(
                status_cell.clone(),
                json!("paused"),
                json!("active")
            )]
        );

        let deactivate = authored(
            build_agent_deactivate_intent(
                resume.actor_id.clone(),
                resume.executed_by.clone().unwrap(),
                scope(),
                DidUrl::new(resume.authorization_ref.clone().unwrap()).unwrap(),
                AgentLifecycleState::Paused,
                Some(arkret_wire::AuditReasonText::new("user_requested").unwrap()),
                changed_at,
            )
            .unwrap(),
            10,
        );
        assert_eq!(deactivate.kind, EventKind::SelfAgentDeactivate);
        assert_eq!(
            project(&deactivate),
            vec![transition_write(
                status_cell,
                json!("paused"),
                json!("deactivated")
            )]
        );
        assert_eq!(deactivate.payload["reason"], "user_requested");
    }
}
