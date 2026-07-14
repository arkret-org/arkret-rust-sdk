//! End-to-end personal-agent provisioning demo against the soland agent-runtime
//! surface. Wires every operation from the `agent_runtime` group of
//! `operation-registry.json` (spec head 37ce729):
//!
//! 1. `ak.self.agent.command.provision`               — create the agent principal
//! 2. `ak.gate.account.command.pair_agent_key`        — pair a fresh runtime key
//! 3. `ak.self.agent.query.list`                    — confirm registry membership
//! 4. `ak.self.agent.resource.get`                     — fetch the principal record
//! 5. `ak.self.agent.command.pause`                   — quiesce the runtime
//! 6. `ak.self.agent.command.resume`                  — un-quiesce
//! 7. `ak.self.agent.command.renew_pairing`           — runtime replacement re-pairing (supersedes
//!    old keys on completion)
//! 8. `ak.self.agent.grant.command.attach`            — bind a delegation grant
//! 9. `ak.self.agent.grant.resource.delete`            — release the grant
//! 10. `ak.self.agent.sidecar_thread.command.ensure`  — pin a sidecar thread for tool calls
//! 11. `ak.self.agent.command.deactivate`             — terminate the principal
//!
//! The example does NOT require a live soland deployment. Each step is built
//! from `arkret::agent::*` request-plan helpers so a reader can audit the exact
//! standard `/_arkret/...` path and typed request body a real transport would
//! send.
//!
//! Build with the high-level SDK surface:
//!
//! ```sh
//! cargo run --example personal_agent_provision --features full-surface
//! ```

use arkret::agent::{
    AgentProvisionRequestBuilder, AgentRequestPlan, agent_key_pair_proof_request_binding_digest,
    agent_key_pairing_request_binding_digest, agent_runtime_public_key_digest,
    build_agent_key_authorize_event, plan_agent_deactivate, plan_agent_get,
    plan_agent_grant_attach, plan_agent_grant_detach, plan_agent_key_pair, plan_agent_list,
    plan_agent_pause, plan_agent_provision, plan_agent_renew_pairing, plan_agent_resume,
    plan_agent_sidecar_thread_ensure,
};
use arkret::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyApprovalEvidence,
    AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload, AgentKeyPairRequestBody, AgentKeyScope,
    AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentPauseRequestBody,
    AgentRenewPairingRequestBody, AgentResumeRequestBody, AgentSidecarContextRef,
    AgentSidecarThreadEnsureRequestBody, CapabilityGrant, CapabilitySubject, Did, GrantId, Hash,
    Hlc, PayloadProof, PayloadProofPurpose, RealmId, StrandId,
};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

/// Stand-in for a wire send. Returns the mock response a real soland would
/// produce for each operation so the example stays self-contained.
fn mock_send(op_id: &str, method: &str, path: &str, body: &Value) -> Value {
    println!("→ {method} {path}  ({op_id})");
    println!("  request: {body}");
    match op_id {
        "ak.self.agent.command.provision" => json!({
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000100",
            "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
            "pairing_code": "12345678",
            "expires_at": "2026-06-18T12:15:00Z",
            "pcr_recovery": { "status": "pending" },
        }),
        "ak.gate.account.command.pair_agent_key" => json!({
            "ok": true,
            "authorized_event_ref": "ak:event:01964137-0000-7000-8000-000000000101",
        }),
        "ak.self.agent.query.list" => {
            json!({ "agents": [], "next_cursor": null, "has_more": false })
        }
        "ak.self.agent.resource.get" => {
            json!({ "agent_id": body["agent_id"], "status": "active" })
        }
        "ak.self.agent.command.pause" => json!({ "ok": true, "status": "paused" }),
        "ak.self.agent.command.resume" => json!({ "ok": true, "status": "active" }),
        "ak.self.agent.command.renew_pairing" => json!({
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000002",
            "pairing_code": "87654321",
            "expires_at": "2026-06-18T13:15:00Z",
        }),
        "ak.self.agent.grant.command.attach" => json!({
            "ok": true,
            "grant_id": "ak:grant:01964137-0000-7000-8000-000000000010",
        }),
        "ak.self.agent.grant.resource.delete" => json!({
            "ok": true,
            "revoked_at": "2026-06-18T12:05:00Z",
        }),
        "ak.self.agent.sidecar_thread.command.ensure" => json!({
            "ok": true,
            "private_circle_id": "ak:circle:01964137-0000-7000-8000-000000000020",
            "private_strand_id": "ak:strand:01964137-0000-7000-8000-000000000021",
            "private_relation_id": "ak:relation:01964137-0000-7000-8000-000000000022",
            "pending_member_reconciliations": [],
        }),
        "ak.self.agent.command.deactivate" => json!({ "ok": true, "status": "deactivated" }),
        _ => Value::Null,
    }
}

fn send_plan<B: Serialize>(plan: AgentRequestPlan<B>) -> arkret::Result<Value> {
    let body = plan.body_value()?.unwrap_or(Value::Null);
    Ok(mock_send(
        plan.operation_id,
        plan.method.as_str(),
        &plan.path,
        &body,
    ))
}

fn main() -> arkret::Result<()> {
    let controller: Did = Did::new("did:webvh:z6mkfixture:alice.example")?;

    let provision_body = AgentProvisionRequestBuilder::new(
        "summary",
        AgentKeyScope {
            actions: vec![
                "ak.message.create".to_owned(),
                "ak.self.events.command.submit".to_owned(),
            ],
            resources: vec![AgentKeyScopeResource {
                kind: AgentKeyScopeResourceKind::Operation,
                realm_id: None,
                resource_ref: None,
                operation: Some("ak.self.events.command.submit".to_owned()),
                service_id: None,
            }],
            constraints: Vec::new(),
        },
    )
    .display_name("alice-personal-agent")
    .pairing_ttl_ms(15 * 60 * 1000)
    .build();

    let provisioned = send_plan(plan_agent_provision(provision_body))?;
    let agent_id = provisioned["agent_id"].as_str().unwrap().to_owned();

    let agent_id = Did::new(agent_id)?;
    let pairing_request_id = provisioned["pairing_request_id"].as_str().unwrap();
    let verification_method = format!("{agent_id}#runtime-key-1");
    let public_key = json!({
        "kty": "OKP",
        "kid": verification_method,
        "alg": "Ed25519",
        "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let pop_digest = agent_key_pair_proof_request_binding_digest(
        pairing_request_id,
        &agent_id,
        &verification_method,
        &public_key,
        None,
    )?;
    let pairing_digest = agent_key_pairing_request_binding_digest(
        &controller,
        &agent_id,
        &verification_method,
        &agent_runtime_public_key_digest(&public_key)?,
        pairing_request_id,
        provisioned["pairing_code"].as_str().unwrap(),
        provisioned["expires_at"].as_str().unwrap(),
        "did:web:soland.local",
    )?;
    let authorize_event = build_agent_key_authorize_event(
        &AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: verification_method.clone(),
            public_key_digest: Some(agent_runtime_public_key_digest(&public_key)?),
            accountable_principal_id: controller.clone(),
            agent_key_scope: AgentKeyScope {
                actions: vec![
                    "ak.message.create".to_owned(),
                    "ak.self.events.command.submit".to_owned(),
                ],
                resources: vec![AgentKeyScopeResource {
                    kind: AgentKeyScopeResourceKind::Operation,
                    realm_id: None,
                    resource_ref: None,
                    operation: Some("ak.self.events.command.submit".to_owned()),
                    service_id: None,
                }],
                constraints: vec![],
            },
            audience: vec!["did:web:soland.local".to_owned()],
            issued_at: Utc::now(),
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(pairing_digest),
                pairing_request_id: Some(pairing_request_id.to_owned()),
                approved_by: Some(controller.clone()),
            },
            supersedes: vec![],
            revocation_check_ref: None,
            runtime_attestation: None,
        },
        RealmId::new(provisioned["principal_control_realm_id"].as_str().unwrap())?,
        agent_id.clone(),
        controller.clone(),
        provisioned["controller_authorization_ref"]
            .as_str()
            .unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e")?,
    )?;
    let key_pair_body = AgentKeyPairRequestBody {
        pairing_request_id: pairing_request_id.to_owned(),
        agent_id: agent_id.clone(),
        verification_method,
        public_key,
        proof_of_possession: json!({
            "challenge": pairing_request_id,
            "audience": "did:web:soland.local",
            "request_canonical_digest": pop_digest,
            "expires_at": provisioned["expires_at"],
            "signature": "ed25519-pop-signature",
        }),
        runtime_attestation: None,
        // A real client signs this Event with the controller/device key before
        // submitting it. The mock transport below only demonstrates the
        // strongly typed wire shape.
        authorize_event,
    };
    let _key = send_plan(plan_agent_key_pair(key_pair_body))?;

    // 3. ak.self.agent.query.list
    let _list = send_plan(plan_agent_list())?;

    // 4. ak.self.agent.resource.get
    let _get = send_plan(plan_agent_get(agent_id.as_str()))?;

    // 5-6. pause + resume
    let _paused = send_plan(plan_agent_pause(
        agent_id.as_str(),
        AgentPauseRequestBody {
            reason: Some("user_requested".to_owned()),
        },
    ))?;
    let _resumed = send_plan(plan_agent_resume(
        agent_id.as_str(),
        AgentResumeRequestBody {
            sidecar_exposure_ack: None,
        },
    ))?;

    // 7. renew-pairing (runtime replacement re-pairing: the old key keeps
    // working until the new pairing completes, at which point every prior
    // active key is revoked with reason=superseded_by_repairing).
    let _replacement_pairing = send_plan(plan_agent_renew_pairing(
        agent_id.as_str(),
        AgentRenewPairingRequestBody {
            pairing_ttl_ms: Some(15 * 60 * 1000),
        },
    ))?;

    // 8. grant.attach
    let grant = send_plan(plan_agent_grant_attach(
        agent_id.as_str(),
        AgentGrantAttachRequestBody {
            grant: CapabilityGrant {
                id: GrantId::new("ak:grant:01964137-0000-7000-8000-000000000010")?,
                schema: "ak.schema.capability.v1".to_owned(),
                realm_id: Some(RealmId::new(
                    "ak:realm:01964137-0000-7000-8000-000000000030",
                )?),
                issuer: controller.clone(),
                subject: CapabilitySubject::Did(agent_id.clone()),
                actions: vec!["ak.message.create".to_owned()],
                resources: vec![json!({
                    "kind": "realm",
                    "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030"
                })],
                constraints: Vec::new(),
                parent_grant_id: None,
                issued_at: chrono::DateTime::parse_from_rfc3339("2026-06-18T12:00:00Z")
                    .expect("static grant timestamp must be valid")
                    .with_timezone(&Utc),
                not_before: None,
                expires_at: None,
                updated_by: None,
                updated_at: None,
                revoked_by: None,
                revoked_at: None,
                proofs: vec![PayloadProof {
                    kind: "detached_jws".to_owned(),
                    alg: "EdDSA".to_owned(),
                    verification_method: format!("{controller}#key-1"),
                    payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
                    created_at: chrono::DateTime::parse_from_rfc3339("2026-06-18T12:00:00Z")
                        .expect("static proof timestamp must be valid")
                        .with_timezone(&Utc),
                    domain: None,
                    audience: None,
                    proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                    jws: "header..signature".to_owned(),
                }],
            },
        },
    ))?;
    let grant_id = GrantId::new(grant["grant_id"].as_str().unwrap().to_owned())?;

    // 9. grant.detach
    let _detached = send_plan(plan_agent_grant_detach(agent_id.as_str(), &grant_id))?;

    // 10. sidecar_thread.ensure
    let realm_id = RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030")?;
    let context_strand_id = StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031")?;
    let _sidecar = send_plan(plan_agent_sidecar_thread_ensure(
        AgentSidecarThreadEnsureRequestBody {
            controller_id: controller,
            addressed_agent_ids: vec![agent_id.clone()],
            context_ref: AgentSidecarContextRef::strand(realm_id, context_strand_id),
        },
    ))?;

    // 11. deactivate
    let _deactivated = send_plan(plan_agent_deactivate(
        agent_id.as_str(),
        AgentDeactivateRequestBody {
            reason: Some("demo_complete".to_owned()),
        },
    ))?;

    println!("personal-agent provisioning demo complete");
    Ok(())
}
