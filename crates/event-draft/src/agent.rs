//! Personal-agent Event materialization.

use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::events_payloads::agent::{
    AgentDeactivatePayload, AgentKeyAuthorizePayload, AgentKeyRevokePayload, AgentPausePayload,
    AgentResumePayload, AgentSidecarExposureAck,
};
use arkret_wire::{
    CellRef, Did, Effect, Event, EventId, EventKind, Hlc, LatticeOp, LatticeOpType, RealmId,
    composite_subject,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::Result;

/// Build an unsigned controller-executed `ak.agent.key.authorize` Event draft.
pub fn build_agent_key_authorize_event(
    payload: &AgentKeyAuthorizePayload,
    event_id: EventId,
    realm_id: RealmId,
    agent_actor_id: Did,
    controller_id: Did,
    controller_authorization_ref: impl Into<String>,
    actor_seq: u64,
    hlc: Hlc,
) -> Result<Event> {
    let mut event = Event::new(
        EventKind::AGENT_KEY_AUTHORIZE,
        realm_id,
        agent_actor_id,
        actor_seq,
        hlc,
        serde_json::to_value(payload)?,
    )?;
    event.event_id = event_id;
    event.executed_by = Some(controller_id);
    event.authorization_ref = Some(controller_authorization_ref.into());
    event.effects = agent_key_authorize_effects(payload, &event.event_id)?;
    Ok(event)
}

/// Build the canonical observed-remove effects for one Agent key
/// authorization. Authorization Event ids are the OR-set dot tags, so
/// replacement can remove the exact accepted dots named by `supersedes`.
pub fn agent_key_authorize_effects(
    payload: &AgentKeyAuthorizePayload,
    event_id: &EventId,
) -> Result<Vec<Effect>> {
    let mut effects = Vec::with_capacity(payload.supersedes.len() + 1);
    for superseded in &payload.supersedes {
        effects.push(agent_key_effect(
            &payload.agent_id,
            &superseded.key_id,
            LatticeOpType::Remove,
            superseded.authorized_event_ref.as_str(),
            None,
        )?);
    }
    effects.push(agent_key_effect(
        &payload.agent_id,
        &payload.key_id,
        LatticeOpType::Add,
        event_id.as_str(),
        Some(serde_json::to_value(payload)?),
    )?);
    Ok(effects)
}

/// Build an unsigned controller-executed `ak.agent.key.revoke` Event draft.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_key_revoke_event(
    payload: &AgentKeyRevokePayload,
    authorized_event_refs: &[EventId],
    event_id: EventId,
    realm_id: RealmId,
    agent_actor_id: Did,
    controller_id: Did,
    controller_authorization_ref: impl Into<String>,
    actor_seq: u64,
    hlc: Hlc,
) -> Result<Event> {
    let mut event = Event::new(
        EventKind::AGENT_KEY_REVOKE,
        realm_id,
        agent_actor_id,
        actor_seq,
        hlc,
        serde_json::to_value(payload)?,
    )?;
    event.event_id = event_id;
    event.executed_by = Some(controller_id);
    event.authorization_ref = Some(controller_authorization_ref.into());
    event.effects = agent_key_revoke_effects(payload, authorized_event_refs, &event.event_id)?;
    Ok(event)
}

/// Build the canonical revocation effects for every authorization dot
/// observed for a key, followed by a durable transition marker.
pub fn agent_key_revoke_effects(
    payload: &AgentKeyRevokePayload,
    authorized_event_refs: &[EventId],
    event_id: &EventId,
) -> Result<Vec<Effect>> {
    let mut effects = Vec::with_capacity(authorized_event_refs.len() + 1);
    for authorized_event_ref in authorized_event_refs {
        effects.push(agent_key_effect(
            &payload.agent_id,
            &payload.key_id,
            LatticeOpType::Remove,
            authorized_event_ref.as_str(),
            None,
        )?);
    }
    effects.push(agent_key_effect(
        &payload.agent_id,
        &payload.key_id,
        LatticeOpType::Add,
        event_id.as_str(),
        Some(serde_json::to_value(payload)?),
    )?);
    Ok(effects)
}

fn agent_key_effect(
    agent_id: &Did,
    key_id: &str,
    op_type: LatticeOpType,
    tag: &str,
    value: Option<Value>,
) -> Result<Effect> {
    let subject = composite_subject(&[agent_id.as_str(), key_id])?;
    Ok(Effect {
        cell: CellRef::new(format!("ak:cell:ak.component.agent.key.v1:{subject}"))?,
        op: LatticeOp {
            op_type,
            tag: Some(tag.to_owned()),
            value,
            from: None,
            to: None,
            reason: None,
            // `issuer_seq` belongs exclusively to `ordered_log`; this family
            // is an OR-set whose causal identity is the observed dot in `tag`.
            issuer_seq: None,
        },
    })
}

struct AgentLifecycleEventInput {
    kind: &'static str,
    payload: Value,
    agent_id: Did,
    controller_id: Did,
    principal_control_realm_id: RealmId,
    controller_authorization_ref: String,
    previous_status: &'static str,
    next_status: &'static str,
    reason: Option<String>,
    actor_seq: u64,
    hlc: Hlc,
    status_changed_at: DateTime<Utc>,
}

fn build_agent_lifecycle_event(input: AgentLifecycleEventInput) -> Result<Event> {
    let mut event = Event::new_at(
        input.kind,
        input.principal_control_realm_id,
        input.agent_id.clone(),
        input.actor_seq,
        input.hlc,
        input.payload,
        input.status_changed_at,
    )?;
    event.executed_by = Some(input.controller_id);
    event.authorization_ref = Some(input.controller_authorization_ref);
    event.effects = vec![Effect {
        cell: CellRef::new(format!(
            "ak:cell:ak.component.agent.status.v1:{}",
            input.agent_id.as_str()
        ))?,
        op: LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(Value::String(input.previous_status.to_owned())),
            to: Some(Value::String(input.next_status.to_owned())),
            reason: input.reason,
            issuer_seq: None,
        },
    }];
    Ok(event)
}

/// Build an unsigned controller-executed `ak.self.agent.pause` Event draft.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_pause_event(
    agent_id: Did,
    controller_id: Did,
    principal_control_realm_id: RealmId,
    controller_authorization_ref: impl Into<String>,
    reason: Option<String>,
    actor_seq: u64,
    hlc: Hlc,
    status_changed_at: DateTime<Utc>,
) -> Result<Event> {
    let payload = serde_json::to_value(AgentPausePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "pause".to_owned(),
        previous_status: "active".to_owned(),
        status_changed_at,
        reason: reason.clone(),
    })?;
    build_agent_lifecycle_event(AgentLifecycleEventInput {
        kind: EventKind::SELF_AGENT_PAUSE,
        payload,
        agent_id,
        controller_id,
        principal_control_realm_id,
        controller_authorization_ref: controller_authorization_ref.into(),
        previous_status: "active",
        next_status: "paused",
        reason,
        actor_seq,
        hlc,
        status_changed_at,
    })
}

/// Build an unsigned controller-executed `ak.self.agent.resume` Event draft.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_resume_event(
    agent_id: Did,
    controller_id: Did,
    principal_control_realm_id: RealmId,
    controller_authorization_ref: impl Into<String>,
    sidecar_exposure_ack: Option<AgentSidecarExposureAck>,
    actor_seq: u64,
    hlc: Hlc,
    status_changed_at: DateTime<Utc>,
) -> Result<Event> {
    let payload = serde_json::to_value(AgentResumePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "resume".to_owned(),
        previous_status: "paused".to_owned(),
        status_changed_at,
        sidecar_exposure_ack,
        reason: None,
    })?;
    build_agent_lifecycle_event(AgentLifecycleEventInput {
        kind: EventKind::SELF_AGENT_RESUME,
        payload,
        agent_id,
        controller_id,
        principal_control_realm_id,
        controller_authorization_ref: controller_authorization_ref.into(),
        previous_status: "paused",
        next_status: "active",
        reason: None,
        actor_seq,
        hlc,
        status_changed_at,
    })
}

/// Build an unsigned controller-executed `ak.self.agent.deactivate` Event
/// draft. Deactivation may start from either active or paused and is terminal.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_deactivate_event(
    agent_id: Did,
    controller_id: Did,
    principal_control_realm_id: RealmId,
    controller_authorization_ref: impl Into<String>,
    previous_status: AgentLifecycleState,
    reason: Option<String>,
    actor_seq: u64,
    hlc: Hlc,
    status_changed_at: DateTime<Utc>,
) -> Result<Event> {
    let previous_status = match previous_status {
        AgentLifecycleState::Active => "active",
        AgentLifecycleState::Paused => "paused",
        AgentLifecycleState::Deactivated => {
            return Err(crate::EventDraftError::Protocol(
                "cannot author an Agent deactivation from terminal deactivated state".to_owned(),
            ));
        }
    };
    let payload = serde_json::to_value(AgentDeactivatePayload {
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        transition: "deactivate".to_owned(),
        previous_status: previous_status.to_owned(),
        status_changed_at,
        reason: reason.clone(),
    })?;
    build_agent_lifecycle_event(AgentLifecycleEventInput {
        kind: EventKind::SELF_AGENT_DEACTIVATE,
        payload,
        agent_id,
        controller_id,
        principal_control_realm_id,
        controller_authorization_ref: controller_authorization_ref.into(),
        previous_status,
        next_status: "deactivated",
        reason,
        actor_seq,
        hlc,
        status_changed_at,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyScope,
    };
    use arkret_wire::Hash;
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn key_authorize_payload(agent_id: Did, controller_id: Did) -> AgentKeyAuthorizePayload {
        AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{agent_id}#runtime-key-1"),
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
                evidence_ref: Some("ak:event:01970000-0000-7000-8000-000000000021".to_owned()),
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
        let controller_id = did("controller");
        let event = build_agent_key_authorize_event(
            &key_authorize_payload(agent_id.clone(), controller_id.clone()),
            EventId::new("ak:event:01970000-0000-7000-8000-000000000022".to_owned()).unwrap(),
            realm(),
            agent_id.clone(),
            controller_id.clone(),
            format!("{agent_id}#managed-controller"),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        )
        .unwrap();

        assert_eq!(event.kind.as_str(), EventKind::AGENT_KEY_AUTHORIZE);
        assert_eq!(event.actor_id, agent_id);
        assert_eq!(event.executed_by, Some(controller_id));
        assert_eq!(event.payload["key_id"], "runtime-key-1");
        assert_eq!(event.effects.len(), 1);
        assert_eq!(event.effects[0].op.op_type, LatticeOpType::Add);
        assert_eq!(event.effects[0].op.issuer_seq, None);
        assert_eq!(
            event.effects[0].op.tag.as_deref(),
            Some("ak:event:01970000-0000-7000-8000-000000000022")
        );
        let expected_subject =
            composite_subject(&[event.actor_id.as_str(), "runtime-key-1"]).unwrap();
        assert_eq!(
            event.effects[0].cell.as_str(),
            format!("ak:cell:ak.component.agent.key.v1:{expected_subject}")
        );
    }

    #[test]
    fn key_revoke_event_removes_authorization_dot_and_adds_transition_marker() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let authorized_event_id =
            EventId::new("ak:event:01970000-0000-7000-8000-000000000022".to_owned()).unwrap();
        let revoke_event_id =
            EventId::new("ak:event:01970000-0000-7000-8000-000000000023".to_owned()).unwrap();
        let event = build_agent_key_revoke_event(
            &AgentKeyRevokePayload {
                agent_id: agent_id.clone(),
                key_id: "runtime-key-1".to_owned(),
                revoked_by: controller_id.clone(),
                revoked_at: Utc.with_ymd_and_hms(2026, 5, 26, 10, 30, 0).unwrap(),
                reason: Some("controller_deactivated".to_owned()),
            },
            std::slice::from_ref(&authorized_event_id),
            revoke_event_id.clone(),
            realm(),
            agent_id,
            controller_id,
            "did:webvh:z6mkfixture:agent.example#managed-controller",
            8,
            Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        )
        .unwrap();

        assert_eq!(event.effects.len(), 2);
        assert_eq!(event.effects[0].op.op_type, LatticeOpType::Remove);
        assert_eq!(
            event.effects[0].op.tag.as_deref(),
            Some(authorized_event_id.as_str())
        );
        assert_eq!(event.effects[1].op.op_type, LatticeOpType::Add);
        assert!(
            event
                .effects
                .iter()
                .all(|effect| effect.op.issuer_seq.is_none())
        );
        assert_eq!(
            event.effects[1].op.tag.as_deref(),
            Some(revoke_event_id.as_str())
        );
        assert_eq!(event.effects[0].cell, event.effects[1].cell);
    }

    #[test]
    fn lifecycle_events_bind_payload_and_status_transition() {
        let agent_id = did("agent");
        let controller_id = did("controller");
        let changed_at = Utc.with_ymd_and_hms(2026, 7, 19, 8, 0, 0).unwrap();
        let authorization_ref = format!("{agent_id}#managed-controller");

        let pause = build_agent_pause_event(
            agent_id.clone(),
            controller_id.clone(),
            realm(),
            authorization_ref.clone(),
            Some("user_requested".to_owned()),
            8,
            Hlc::new("01970e589d21-0008-a13f9c2e").unwrap(),
            changed_at,
        )
        .unwrap();
        assert_eq!(pause.kind.as_str(), EventKind::SELF_AGENT_PAUSE);
        assert_eq!(pause.effects[0].op.from, Some(json!("active")));
        assert_eq!(pause.effects[0].op.to, Some(json!("paused")));
        assert_eq!(
            pause.effects[0].op.reason.as_deref(),
            Some("user_requested")
        );

        let resume = build_agent_resume_event(
            agent_id,
            controller_id,
            realm(),
            authorization_ref,
            None,
            9,
            Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
            changed_at,
        )
        .unwrap();
        assert_eq!(resume.kind.as_str(), EventKind::SELF_AGENT_RESUME);
        assert_eq!(resume.effects[0].op.from, Some(json!("paused")));
        assert_eq!(resume.effects[0].op.to, Some(json!("active")));

        let deactivate = build_agent_deactivate_event(
            resume.actor_id.clone(),
            resume.executed_by.clone().unwrap(),
            realm(),
            resume.authorization_ref.clone().unwrap(),
            AgentLifecycleState::Paused,
            Some("user_requested".to_owned()),
            10,
            Hlc::new("01970e589d21-000a-a13f9c2e").unwrap(),
            changed_at,
        )
        .unwrap();
        assert_eq!(deactivate.kind.as_str(), EventKind::SELF_AGENT_DEACTIVATE);
        assert_eq!(deactivate.effects[0].op.from, Some(json!("paused")));
        assert_eq!(deactivate.effects[0].op.to, Some(json!("deactivated")));
        assert_eq!(
            deactivate.effects[0].op.reason.as_deref(),
            Some("user_requested")
        );
    }
}
