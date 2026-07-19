//! End-to-end personal-agent provisioning demo against the soland agent-runtime
//! surface. Wires every operation from the `agent_runtime` group of
//! `operation-registry.json` (spec head 37ce729):
//!
//! 1. `ak.self.agent.command.provision`               — create the agent principal
//! 2. `ak.gate.account.command.pair_agent_key`        — pair a fresh runtime key
//! 3. `ak.self.agent.query.list`                    — confirm registry membership
//! 4. `ak.self.agent.resource.get`                     — fetch the principal record
//! 5. `ak.self.agent.command.pause`                   — quiesce the runtime
//! 6. `ak.self.agent.command.renew_pairing`           — open paused-only runtime replacement
//! 7. `ak.gate.account.command.pair_agent_key`        — atomically supersede the old runtime key
//! 8. `ak.self.agent.command.resume`                  — resume only after replacement completes
//! 9. `ak.self.agent.grant.command.attach`            — bind a delegation grant
//! 10. `ak.self.agent.grant.resource.delete`          — release the grant
//! 11. `ak.self.agent.sidecar_thread.command.ensure`  — pin a sidecar thread for tool calls
//! 12. `ak.self.agent.command.deactivate`              — terminate the principal
//!
//! The example does NOT require a live soland deployment. Each step is built
//! from `arkret::agent::*` request-plan helpers so a reader can audit the exact
//! standard `/_arkret/...` path and typed request body a real transport would
//! send.
//!
//! Build with the high-level SDK surface:
//!
//! ```sh
//! cargo run --example personal_agent_provision --features full-surface,signer
//! ```

use arkret::agent::{
    AgentProvisionRequestBuilder, AgentRequestPlan, agent_key_pair_proof_request_binding_digest,
    agent_key_pairing_request_binding_digest, agent_runtime_public_key_digest,
    build_agent_key_authorize_event, build_agent_pause_event, build_agent_resume_event,
    plan_agent_deactivate, plan_agent_get, plan_agent_grant_attach, plan_agent_grant_detach,
    plan_agent_key_pair, plan_agent_list, plan_agent_pause, plan_agent_provision,
    plan_agent_renew_pairing, plan_agent_resume, plan_agent_sidecar_thread_ensure,
};
use arkret::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyApprovalEvidence,
    AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload, AgentKeyPairRequestBody, AgentKeyScope,
    AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentKeySupersession, AgentPauseRequestBody,
    AgentRenewPairingRequestBody, AgentRequestedScopeDisclosure, AgentResumeRequestBody,
    AgentSidecarContextRef, AgentSidecarThreadEnsureRequestBody, CapabilityGrant,
    CapabilitySubject, Did, EventId, GrantId, Hash, Hlc, NonEmptyString, PayloadProof,
    PayloadProofPurpose, Proof, RealmId, RequestId, SealBasis, SealId, StrandId,
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
        "ak.self.agent.command.provision" => {
            let agent_id = Did::new("did:webvh:z6mkfixture:agent.example").unwrap();
            let controller_id = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
            let requested_scope: AgentKeyScope =
                serde_json::from_value(body["requested_scope"].clone()).unwrap();
            let requested_scope_digest =
                arkret::agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope)
                    .unwrap();
            if body["phase"] == "prepare" {
                json!({
                    "status": "awaiting_controller_events",
                    "agent_id": agent_id,
                    "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000100",
                    "controller_realm_id": "ak:realm:01964137-0000-7000-8000-000000000099",
                    "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
                    "requested_scope_digest": requested_scope_digest,
                })
            } else {
                json!({
                    "status": "complete",
                    "agent_id": agent_id,
                    "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000100",
                    "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
                    "requested_scope_digest": requested_scope_digest,
                    "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
                    "pairing_code": "12345678",
                    "expires_at": "2026-06-18T12:15:00Z",
                    "pcr_recovery": { "status": "pending" },
                })
            }
        }
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
            "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000100",
            "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
            "requested_scope_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pcr_recovery": { "status": "ready", "backup_id": "ak:backup:01964137-0000-7000-8000-000000000020", "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000021", "series_seq": 1, "managed_frontier_ref": { "frontier_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "seal_ref": "ak:seal:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "mls_epoch": 1 } },
            "pairing_mode": "replacement",
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

    let requested_scope = AgentKeyScope {
        actions: vec![
            "ak.message.create".to_owned(),
            "ak.self.events.command.submit".to_owned(),
        ],
        resources: vec![AgentKeyScopeResource {
            kind: AgentKeyScopeResourceKind::Operation,
            realm_id: None,
            resource_ref: None,
            schema_ref: None,
            operation: Some("ak.self.events.command.submit".to_owned()),
            service_id: None,
        }],
        constraints: Vec::new(),
    };
    let prepared = send_plan(plan_agent_provision(
        arkret::agent::prepare_agent_provision_request("summary", requested_scope.clone()),
    ))?;
    let agent_id = Did::new(prepared["agent_id"].as_str().unwrap().to_owned())?;
    let principal_control_realm_id =
        RealmId::new(prepared["principal_control_realm_id"].as_str().unwrap())?;
    let controller_realm_id = RealmId::new(prepared["controller_realm_id"].as_str().unwrap())?;
    let created_at = Utc::now();
    let signer = arkret::Ed25519MoveSigner::from_did_key_seed(
        [7_u8; 32],
        controller.clone(),
        format!("{controller}#key-1"),
    );
    let mut provision_events = arkret::agent::build_agent_provision_event_drafts(
        &controller,
        &controller_realm_id,
        &agent_id,
        "summary",
        arkret::agent::AgentProvisionEventDraftOptions {
            created_at,
            accountability_actor_seq: 1,
            accountability_hlc: Hlc::new("01970e589d21-0001-a13f9c2e")?,
            selector_actor_seq: 2,
            selector_hlc: Hlc::new("01970e589d21-0002-a13f9c2e")?,
        },
        &signer,
    )?;
    let seal_basis = SealBasis {
        leaves: vec![SealId::new("ak:seal:01964137-0000-7000-8000-000000000098")?],
        control_event_set_root: Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        state_root: Hash::new(format!("sha256:{}", "2".repeat(64)))?,
    };
    for event in [
        &mut provision_events.accountability_grant,
        &mut provision_events.selector_claim,
    ] {
        event.seal_basis = Some(seal_basis.clone());
        arkret::signatures::sign_event(
            event,
            &signer,
            &format!("{controller}#key-1"),
            arkret::signatures::SignEventOptions::new().with_created_at(created_at),
        )?;
    }
    let provision_body = AgentProvisionRequestBuilder::new(
        agent_id.clone(),
        principal_control_realm_id.clone(),
        "summary",
        requested_scope.clone(),
        provision_events,
    )
    .display_name("alice-personal-agent")
    .pairing_ttl_ms(15 * 60 * 1000)
    .build();
    let provisioned = send_plan(plan_agent_provision(provision_body))?;

    let expected_scope_digest =
        arkret::agent_requested_scope_digest(&agent_id, &controller, &requested_scope)?;
    assert_eq!(
        provisioned["requested_scope_digest"].as_str(),
        Some(expected_scope_digest.as_str())
    );
    let pairing_request_id = provisioned["pairing_request_id"].as_str().unwrap();
    let verification_method = format!("{agent_id}#runtime-key-1");
    let public_key_value = json!({
        "kty": "OKP",
        "kid": verification_method,
        "alg": "Ed25519",
        "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let pop_digest = agent_key_pair_proof_request_binding_digest(
        pairing_request_id,
        &agent_id,
        &verification_method,
        &public_key_value,
        None,
    )?;
    let pairing_digest = agent_key_pairing_request_binding_digest(
        &controller,
        &agent_id,
        &verification_method,
        &agent_runtime_public_key_digest(&public_key_value)?,
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
            public_key_digest: Some(agent_runtime_public_key_digest(&public_key_value)?),
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
                    schema_ref: None,
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
    let disclosure_issued_at = Utc::now();
    let pairing_request_uuid = pairing_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| {
            arkret::Error::Protocol("pairing_request_id has an invalid prefix".to_owned())
        })?;
    let mut requested_scope_disclosure = AgentRequestedScopeDisclosure {
        schema: arkret::AGENT_REQUESTED_SCOPE_DISCLOSURE_SCHEMA.to_owned(),
        request_id: RequestId::new(format!("ak:request:{pairing_request_uuid}"))?,
        agent_id: agent_id.clone(),
        controller_id: controller.clone(),
        requested_scope: requested_scope.clone(),
        requested_scope_digest: expected_scope_digest,
        verifier_did: Did::new("did:web:soland.local".to_owned())?,
        audience: NonEmptyString::new("ak.gate.account.command.pair_agent_key")
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        challenge: NonEmptyString::new(pairing_request_id)
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        issued_at: disclosure_issued_at,
        expires_at: disclosure_issued_at + chrono::Duration::minutes(5),
        proofs: vec![Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: format!("{controller}#key-1"),
            event_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: disclosure_issued_at,
            domain: None,
            audience: None,
            jws: "eyJhbGciOiJFZERTQSJ9..AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        }],
    };
    requested_scope_disclosure.proofs[0].event_digest =
        requested_scope_disclosure.payload_digest()?;
    let replacement_disclosure_template = requested_scope_disclosure.clone();
    let key_pair_body = AgentKeyPairRequestBody {
        pairing_request_id: NonEmptyString::new(pairing_request_id)
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        agent_id: agent_id.clone(),
        verification_method: arkret::DidUrl::new(verification_method)
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        public_key: serde_json::from_value(public_key_value)?,
        proof_of_possession: serde_json::from_value(json!({
            "challenge": pairing_request_id,
            "audience": "did:web:soland.local",
            "request_canonical_digest": pop_digest,
            "expires_at": provisioned["expires_at"],
            "signature": "ed25519-pop-signature",
        }))?,
        requested_scope_disclosure,
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

    // 5. Pause before runtime replacement. Lifecycle commands carry the exact delegated
    // Agent Event; the service never synthesizes an Agent-authored Event.
    let lifecycle_authorization_ref = provisioned["controller_authorization_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let pause_created_at = Utc::now();
    let mut pause_event = build_agent_pause_event(
        agent_id.clone(),
        controller.clone(),
        principal_control_realm_id.clone(),
        lifecycle_authorization_ref.clone(),
        Some("user_requested".to_owned()),
        2,
        Hlc::new("01970e589d21-0005-a13f9c2e")?,
        pause_created_at,
    )?;
    pause_event.seal_basis = Some(seal_basis.clone());
    arkret::signatures::sign_event(
        &mut pause_event,
        &signer,
        &format!("{controller}#key-1"),
        arkret::signatures::SignEventOptions::new().with_created_at(pause_created_at),
    )?;
    let _paused = send_plan(plan_agent_pause(
        agent_id.as_str(),
        AgentPauseRequestBody {
            reason: Some("user_requested".to_owned()),
            lifecycle_event: pause_event,
        },
    ))?;

    // 6. Open a paused-only replacement handle.
    let replacement_pairing = send_plan(plan_agent_renew_pairing(
        agent_id.as_str(),
        AgentRenewPairingRequestBody {
            pairing_ttl_ms: Some(15 * 60 * 1000),
        },
    ))?;

    // 7. The replacement runtime generates K2. Its single controller-signed
    // authorize Event names every old authorization it atomically supersedes.
    let replacement_request_id = replacement_pairing["pairing_request_id"].as_str().unwrap();
    let replacement_code = replacement_pairing["pairing_code"].as_str().unwrap();
    let replacement_expires_at = replacement_pairing["expires_at"].as_str().unwrap();
    let replacement_verification_method = format!("{agent_id}#runtime-key-2");
    let replacement_public_key_value = json!({
        "kind": "ed25519",
        "key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    });
    let replacement_pop_digest = agent_key_pair_proof_request_binding_digest(
        replacement_request_id,
        &agent_id,
        &replacement_verification_method,
        &replacement_public_key_value,
        None,
    )?;
    let replacement_pairing_digest = agent_key_pairing_request_binding_digest(
        &controller,
        &agent_id,
        &replacement_verification_method,
        &agent_runtime_public_key_digest(&replacement_public_key_value)?,
        replacement_request_id,
        replacement_code,
        replacement_expires_at,
        "did:web:soland.local",
    )?;
    let mut replacement_authorize_event = build_agent_key_authorize_event(
        &AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: "runtime-key-2".to_owned(),
            verification_method: replacement_verification_method.clone(),
            public_key_digest: Some(agent_runtime_public_key_digest(
                &replacement_public_key_value,
            )?),
            accountable_principal_id: controller.clone(),
            agent_key_scope: requested_scope.clone(),
            audience: vec!["did:web:soland.local".to_owned()],
            issued_at: Utc::now(),
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(replacement_pairing_digest),
                pairing_request_id: Some(replacement_request_id.to_owned()),
                approved_by: Some(controller.clone()),
            },
            supersedes: vec![AgentKeySupersession {
                key_id: "runtime-key-1".to_owned(),
                authorized_event_ref: EventId::new(
                    "ak:event:01964137-0000-7000-8000-000000000101",
                )?,
            }],
            revocation_check_ref: None,
            runtime_attestation: None,
        },
        principal_control_realm_id.clone(),
        agent_id.clone(),
        controller.clone(),
        lifecycle_authorization_ref.clone(),
        3,
        Hlc::new("01970e589d21-0006-a13f9c2e")?,
    )?;
    replacement_authorize_event.seal_basis = Some(seal_basis.clone());
    let mut replacement_disclosure = replacement_disclosure_template;
    let replacement_uuid = replacement_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| {
            arkret::Error::Protocol("replacement pairing id has invalid prefix".into())
        })?;
    replacement_disclosure.request_id = RequestId::new(format!("ak:request:{replacement_uuid}"))?;
    replacement_disclosure.challenge = NonEmptyString::new(replacement_request_id.to_owned())
        .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?;
    replacement_disclosure.proofs[0].event_digest = replacement_disclosure.payload_digest()?;
    let replacement_body = AgentKeyPairRequestBody {
        pairing_request_id: NonEmptyString::new(replacement_request_id.to_owned())
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        agent_id: agent_id.clone(),
        verification_method: arkret::DidUrl::new(replacement_verification_method)
            .map_err(|reason| arkret::Error::Protocol(reason.to_owned()))?,
        public_key: serde_json::from_value(replacement_public_key_value)?,
        proof_of_possession: serde_json::from_value(json!({
            "challenge": replacement_request_id,
            "audience": "did:web:soland.local",
            "request_canonical_digest": replacement_pop_digest,
            "expires_at": replacement_expires_at,
            "signature": "ed25519-replacement-pop-signature",
        }))?,
        requested_scope_disclosure: replacement_disclosure,
        runtime_attestation: None,
        authorize_event: replacement_authorize_event,
    };
    let _replacement_key = send_plan(plan_agent_key_pair(replacement_body))?;

    // 8. Resume only after the replacement pair commit has consumed the open handle.
    let resume_created_at = Utc::now();
    let mut resume_event = build_agent_resume_event(
        agent_id.clone(),
        controller.clone(),
        principal_control_realm_id,
        lifecycle_authorization_ref,
        None,
        4,
        Hlc::new("01970e589d21-0007-a13f9c2e")?,
        resume_created_at,
    )?;
    resume_event.seal_basis = Some(seal_basis.clone());
    arkret::signatures::sign_event(
        &mut resume_event,
        &signer,
        &format!("{controller}#key-1"),
        arkret::signatures::SignEventOptions::new().with_created_at(resume_created_at),
    )?;
    let _resumed = send_plan(plan_agent_resume(
        agent_id.as_str(),
        AgentResumeRequestBody {
            sidecar_exposure_ack: None,
            lifecycle_event: resume_event,
        },
    ))?;

    // 9. grant.attach
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
                resources: vec![
                    serde_json::from_value(json!({
                        "kind": "realm",
                        "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030"
                    }))
                    .unwrap(),
                ],
                capability_action_registry_digest: None,
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
