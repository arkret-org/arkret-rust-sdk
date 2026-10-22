//! Real detached signatures bind native control, the producer and the private ledger.
use arkret_identity::principal_control::{
    DirectIdentityControlPurpose, NativeIdentityControlKey,
    native_identity_control_key_from_verified_selection,
    verify_native_control_management_event_approval,
    verify_native_control_management_operation_approval,
};
use arkret_signatures::Ed25519DetachedJwsSigner;
use arkret_signatures::approval_signature::{
    ApprovalEventVerificationError, ManagementApprovalBinding, approval_signature_signing_bytes,
    management_creation_request_digest,
};
use arkret_wire::*;
use chrono::{TimeDelta, TimeZone, Utc};
use serde_json::json;

fn native_approver() -> (Ed25519DetachedJwsSigner, Did, NativeIdentityControlKey) {
    let seed = [71; 32];
    let key_signer = Ed25519DetachedJwsSigner::from_seed(seed, "fixture");
    let public = key_signer.verifying_key();
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(public.as_bytes());
    let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
    let identity =
        Did::new("did:webvh:QmPa2Sq5krCJFV3c8hmoCxbV4C7XS3zzXV6EBYREriEkm9:principal.example")
            .unwrap();
    let control = native_identity_control_key_from_verified_selection(
        &identity,
        &project_did_to_core_id(&identity).unwrap(),
        &[multibase],
        &method,
        DirectIdentityControlPurpose::ApprovalSignature,
    )
    .unwrap();
    (
        Ed25519DetachedJwsSigner::from_seed(seed, method.as_str()),
        identity,
        control,
    )
}

fn sign(signature: &mut ApprovalSignature, signer: &Ed25519DetachedJwsSigner) {
    signature.proof.jws =
        signer.sign_detached_jws(&approval_signature_signing_bytes(signature).unwrap());
}

#[test]
fn native_management_event_binds_actual_producer_and_never_borrows_controller() {
    let (signer, did, control) = native_approver();
    let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [3; 32],
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let controller = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        station.clone(),
    ));
    let producer = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        station,
    ));
    let mut event = test_support::raw_event_for_actor_at(
        "ak.member.state",
        scope.clone(),
        controller.clone(),
        json!({"member_id":producer,"membership":"join"}),
        at,
    )
    .unwrap();
    event.executed_by = Some(producer.clone());
    event.event_id = event
        .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let request = "ak:request:01904100-0000-7000-8000-000000000019";
    let binding = ManagementApprovalBinding {
        request_id: request,
        management_operation: ManagementOperation::Join,
        effective_scope: &scope,
        created_at: at - TimeDelta::seconds(1),
        expires_at: at + TimeDelta::seconds(60),
        requester_actor_id: &controller,
        target_actor_id: Some(&producer),
    };
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                management_operation: ManagementOperation::Join,
                effective_scope: scope.clone(),
                request_id: request.into(),
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(
                arkret_canonical::canonical_sha256(&event).unwrap(),
            )
            .unwrap(),
            operation: "ak.self.events.command.submit.v1".into(),
            action: CapabilityActionId::AgentJoin,
            realm_id: realm,
            initiating_actor_id: producer.clone(),
            approver_did: did,
            approved_at: at,
            nonce: "ABCDEFGHIJKLMNOPQRSTUV".into(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: control.method().clone(),
            jws: String::new(),
        },
    };
    sign(&mut signature, &signer);
    let verify = |candidate: &ApprovalSignature, ledger: &ManagementApprovalBinding<'_>| {
        verify_native_control_management_event_approval(
            &control,
            candidate,
            &event,
            "ak.self.events.command.submit.v1",
            CapabilityActionId::AgentJoin,
            at,
            ledger,
        )
    };
    verify(&signature, &binding).unwrap();
    let mut wrong = signature.clone();
    wrong.input.initiating_actor_id = controller.clone();
    sign(&mut wrong, &signer);
    assert!(matches!(
        verify(&wrong, &binding),
        Err(ApprovalEventVerificationError::Binding)
    ));
    wrong = signature.clone();
    wrong.proof.jws.push('X');
    assert!(matches!(
        verify(&wrong, &binding),
        Err(ApprovalEventVerificationError::Signature)
    ));
    let wrong_request = ManagementApprovalBinding {
        request_id: "ak:request:01904100-0000-7000-8000-000000000020",
        ..binding
    };
    assert!(matches!(
        verify(&signature, &wrong_request),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let approver = ActorId::account(AccountId::new(
        control.principal().clone(),
        DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap(),
    ));
    let self_review = ManagementApprovalBinding {
        requester_actor_id: &approver,
        ..binding
    };
    assert!(matches!(
        verify(&signature, &self_review),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let self_target = ManagementApprovalBinding {
        target_actor_id: Some(&approver),
        ..binding
    };
    assert!(matches!(
        verify(&signature, &self_target),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let early_ledger = ManagementApprovalBinding {
        created_at: at + TimeDelta::seconds(1),
        ..binding
    };
    assert!(matches!(
        verify(&signature, &early_ledger),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let mut substituted = signature.clone();
    substituted.input.approver_did = Did::new("did:web:substituted.example").unwrap();
    sign(&mut substituted, &signer);
    assert!(matches!(
        verify(&substituted, &binding),
        Err(ApprovalEventVerificationError::Binding)
    ));
}

#[test]
fn native_management_creation_omits_only_outer_evidence_and_binds_ledger() {
    let (signer, did, control) = native_approver();
    let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [4; 32],
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let service = ActorId::service(DidCoreId::new("ak:did_core:web:service.example").unwrap());
    let body = json!({"authoring_request":{"digest":"candidate"},"managed_actor_bundle":{"public_key":"immutable","approval_signatures":"nested signed data"},"approval_signatures":[]});
    let digest = management_creation_request_digest(&body).unwrap();
    let request = "ak:request:01904100-0000-7000-8000-000000000021";
    let binding = ManagementApprovalBinding {
        request_id: request,
        management_operation: ManagementOperation::CreateBot,
        effective_scope: &scope,
        created_at: at - TimeDelta::seconds(1),
        expires_at: at + TimeDelta::seconds(60),
        requester_actor_id: &service,
        target_actor_id: None,
    };
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                management_operation: ManagementOperation::CreateBot,
                effective_scope: scope.clone(),
                request_id: request.into(),
            },
            approval_target: ApprovalTarget::Operation,
            request_canonical_digest: digest.clone(),
            operation: ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1.into(),
            action: CapabilityActionId::AppletBotProvision,
            realm_id: realm,
            initiating_actor_id: service.clone(),
            approver_did: did,
            approved_at: at,
            nonce: "ABCDEFGHIJKLMNOPQRSTUW".into(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: control.method().clone(),
            jws: String::new(),
        },
    };
    sign(&mut signature, &signer);
    let verify =
        |candidate: &ApprovalSignature, target: &Hash, ledger: &ManagementApprovalBinding<'_>| {
            verify_native_control_management_operation_approval(
                &control,
                candidate,
                target,
                ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
                CapabilityActionId::AppletBotProvision,
                &service,
                at,
                ledger,
            )
        };
    signature.validate().unwrap();
    verify(&signature, &digest, &binding).unwrap();
    let mut attached = body;
    attached["approval_signatures"] = json!([signature]);
    assert_eq!(
        management_creation_request_digest(&attached).unwrap(),
        digest
    );
    attached["managed_actor_bundle"]["approval_signatures"] = json!("changed nested data");
    let changed = management_creation_request_digest(&attached).unwrap();
    assert!(matches!(
        verify(&signature, &changed, &binding),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let expired = ManagementApprovalBinding {
        expires_at: at,
        ..binding
    };
    assert!(matches!(
        verify(&signature, &digest, &expired),
        Err(ApprovalEventVerificationError::Binding)
    ));
    let mut wrong = signature.clone();
    wrong.input.operation = "ak.self.applet.ghost.command.provision.v1".into();
    sign(&mut wrong, &signer);
    assert!(matches!(
        verify(&wrong, &digest, &binding),
        Err(ApprovalEventVerificationError::Binding)
    ));
    wrong = signature.clone();
    wrong.proof.verification_method =
        DidUrl::new(format!("{}#wrong", did_to_key(&control))).unwrap();
    assert!(matches!(
        verify(&wrong, &digest, &binding),
        Err(ApprovalEventVerificationError::Binding)
    ));
}

fn did_to_key(control: &NativeIdentityControlKey) -> &str {
    control.method().as_str().split_once('#').unwrap().0
}
