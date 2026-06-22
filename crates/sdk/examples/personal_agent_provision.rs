//! End-to-end personal-agent provisioning demo against the soland agent-runtime
//! surface. Wires every operation from the `agent_runtime` group of
//! `operation-registry.json` (spec head 37ce729):
//!
//! 1. `ck.self.agent.command.provision`               — create the agent principal
//! 2. `ck.gate.account.command.pair_agent_key`        — pair a fresh runtime key
//! 3. `ck.self.agent.query.list`                    — confirm registry membership
//! 4. `ck.self.agent.resource.get`                     — fetch the principal record
//! 5. `ck.self.agent.command.pause`                   — quiesce the runtime
//! 6. `ck.self.agent.command.resume`                  — un-quiesce
//! 7. `ck.self.agent.command.rotate_key`              — roll the signing key
//! 8. `ck.self.agent.grant.command.attach`            — bind a delegation grant
//! 9. `ck.self.agent.grant.resource.delete`            — release the grant
//! 10. `ck.self.agent.sidecar_thread.command.ensure`  — pin a sidecar thread for tool calls
//! 11. `ck.self.agent.command.deactivate`             — terminate the principal
//!
//! The example does NOT require a live soland deployment. Each step is built
//! from `cokret::agent::*` request-plan helpers so a reader can audit the exact
//! standard `/_cokret/...` path and typed request body a real transport would
//! send.
//!
//! Build with the default feature set:
//!
//! ```sh
//! cargo run --example personal_agent_provision
//! ```

use cokret::agent::{
    AgentProvisionRequestBuilder, AgentRequestPlan, plan_agent_deactivate, plan_agent_get,
    plan_agent_grant_attach, plan_agent_grant_detach, plan_agent_key_pair, plan_agent_list,
    plan_agent_pause, plan_agent_provision, plan_agent_resume, plan_agent_rotate_key,
    plan_agent_sidecar_thread_ensure,
};
use cokret::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyPairRequestBody,
    AgentKeyScope, AgentPauseRequestBody, AgentResumeRequestBody, AgentRotateKeyRequestBody,
    AgentSidecarContextRef, AgentSidecarThreadEnsureRequestBody, Did, GrantId, RealmId, StrandId,
};
use serde::Serialize;
use serde_json::{Value, json};

/// Stand-in for a wire send. Returns the mock response a real soland would
/// produce for each operation so the example stays self-contained.
fn mock_send(op_id: &str, method: &str, path: &str, body: &Value) -> Value {
    println!("→ {method} {path}  ({op_id})");
    println!("  request: {body}");
    match op_id {
        "ck.self.agent.command.provision" => json!({
            "agent_principal_id": "did:web:agent.example",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
            "pairing_code": "12345678",
            "expires_at": "2026-06-18T12:15:00Z",
        }),
        "ck.gate.account.command.pair_agent_key" => json!({
            "ok": true,
            "authorized_event_ref": "ck:event:01964137-0000-7000-8000-000000000101",
        }),
        "ck.self.agent.query.list" => {
            json!({ "agents": [], "next_cursor": null, "has_more": false })
        }
        "ck.self.agent.resource.get" => {
            json!({ "agent_principal_id": body["agent_principal_id"], "status": "active" })
        }
        "ck.self.agent.command.pause" => json!({ "ok": true, "status": "paused" }),
        "ck.self.agent.command.resume" => json!({ "ok": true, "status": "active" }),
        "ck.self.agent.command.rotate_key" => json!({
            "ok": true,
            "authorized_event_ref": "ck:event:01964137-0000-7000-8000-000000000102",
        }),
        "ck.self.agent.grant.command.attach" => json!({
            "ok": true,
            "grant_id": "ck:grant:01964137-0000-7000-8000-000000000010",
        }),
        "ck.self.agent.grant.resource.delete" => json!({
            "ok": true,
            "revoked_at": "2026-06-18T12:05:00Z",
        }),
        "ck.self.agent.sidecar_thread.command.ensure" => json!({
            "ok": true,
            "private_circle_id": "ck:circle:01964137-0000-7000-8000-000000000020",
            "private_strand_id": "ck:strand:01964137-0000-7000-8000-000000000021",
            "private_relation_id": "ck:relation:01964137-0000-7000-8000-000000000022",
            "pending_member_reconciliations": [],
        }),
        "ck.self.agent.command.deactivate" => json!({ "ok": true, "status": "deactivated" }),
        _ => Value::Null,
    }
}

fn send_plan<B: Serialize>(plan: AgentRequestPlan<B>) -> cokret::Result<Value> {
    let body = plan.body_value()?.unwrap_or(Value::Null);
    Ok(mock_send(
        plan.operation_id,
        plan.method.as_str(),
        &plan.path,
        &body,
    ))
}

fn main() -> cokret::Result<()> {
    let controller: Did = Did::new("did:web:alice.example")?;

    let provision_body = AgentProvisionRequestBuilder::new()
        .display_name("alice-personal-agent")
        .agent_slug("summary")
        .requested_scope(AgentKeyScope::Limited)
        .pairing_ttl_ms(15 * 60 * 1000)
        .build();

    let provisioned = send_plan(plan_agent_provision(provision_body))?;
    let agent_principal_id = provisioned["agent_principal_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let key_pair_body = AgentKeyPairRequestBody {
        agent_principal_id: Did::new(agent_principal_id.clone())?,
        verification_method: format!("{agent_principal_id}#runtime-key-1"),
        public_key: json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }),
        proof_of_possession: json!({
            "challenge": provisioned["pairing_request_id"],
            "signature": "ed25519-pop-signature",
        }),
        runtime_attestation: None,
        authorize_event: None,
    };
    let _key = send_plan(plan_agent_key_pair(key_pair_body))?;

    // 3. ck.self.agent.query.list
    let _list = send_plan(plan_agent_list())?;

    // 4. ck.self.agent.resource.get
    let _get = send_plan(plan_agent_get(&agent_principal_id))?;

    // 5-6. pause + resume
    let _paused = send_plan(plan_agent_pause(
        &agent_principal_id,
        AgentPauseRequestBody {
            reason: Some("user_requested".to_owned()),
        },
    ))?;
    let _resumed = send_plan(plan_agent_resume(
        &agent_principal_id,
        AgentResumeRequestBody {
            sidecar_exposure_ack: None,
        },
    ))?;

    // 7. rotate-key
    let _rotated = send_plan(plan_agent_rotate_key(
        &agent_principal_id,
        AgentRotateKeyRequestBody {
            replacement_key: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            }),
            proof_of_possession: json!({
                "challenge": "rotate-key-challenge",
                "signature": "ed25519-pop-signature",
            }),
        },
    ))?;

    // 8. grant.attach
    let grant = send_plan(plan_agent_grant_attach(
        &agent_principal_id,
        AgentGrantAttachRequestBody {
            grant: json!({
                "actions": ["ck.message.create"],
                "resources": [{ "kind": "realm", "realm_id": "ck:realm:01964137-0000-7000-8000-000000000030" }],
            }),
        },
    ))?;
    let grant_id = GrantId::new(grant["grant_id"].as_str().unwrap().to_owned())?;

    // 9. grant.detach
    let _detached = send_plan(plan_agent_grant_detach(&agent_principal_id, &grant_id))?;

    // 10. sidecar_thread.ensure
    let realm_id = RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030")?;
    let context_strand_id = StrandId::new("ck:strand:01964137-0000-7000-8000-000000000031")?;
    let _sidecar = send_plan(plan_agent_sidecar_thread_ensure(
        AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: controller,
            addressed_agent_principal_ids: vec![Did::new(agent_principal_id.clone())?],
            context_ref: AgentSidecarContextRef::strand(realm_id, context_strand_id),
        },
    ))?;

    // 11. deactivate
    let _deactivated = send_plan(plan_agent_deactivate(
        &agent_principal_id,
        AgentDeactivateRequestBody {
            reason: Some("demo_complete".to_owned()),
        },
    ))?;

    println!("personal-agent provisioning demo complete");
    Ok(())
}
