//! Real OpenMLS/group-context and local fence tests. Synthetic ordering receipts
//! here are shape inputs, not evidence of native authority admission.

use arkret_canonical::base64url_encode;
use arkret_canonical::canonical::sha256_digest;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, BlobRef, DeviceId, DidCoreId, Event, RealmId,
};
use serde_json::json;

use super::*;

fn event_id(seed: u8) -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [seed; 32])
}
fn realm() -> RealmId {
    RealmId::from_event_id(&event_id(1))
}
fn scope() -> ScopeRef {
    ScopeRef::Realm { realm_id: realm() }
}
fn blob(bytes: &[u8]) -> BlobRef {
    BlobRef::new(format!("ak:blob:{}", sha256_digest(bytes))).unwrap()
}
fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn shape_receipt(
    kind: EventKind,
    id: EventId,
    payload: serde_json::Value,
    position: u64,
) -> CommittedEventFullView {
    let event: Event = serde_json::from_value(json!({
        "event_id":id,"kind":kind,"realm_id":realm(),"scope_ref":scope(),"actor_id":actor(),
        "created_at":"2026-11-15T00:00:00.000Z","payload":payload
    }))
    .unwrap();
    let commit = serde_json::from_value(json!({
        "commit_id":arkret_wire::RealmCommitId::from_digest([0x33;32]),
        "realm_id":realm(),"stream_ref":{"kind":"realm","realm_id":realm()},
        "stream_position":position,"previous_commit_ref":if position == 0 { serde_json::Value::Null } else { json!(arkret_wire::RealmCommitId::from_digest([0x22;32])) },
        "event_ref":event.event_id,"governance_generation":"0","authority_ref":event_id(9),
        "committed_at":"2026-11-15T00:00:00.000Z",
        "signature":{"context":"ak.realm_commit_signature.v1","signature_algorithm":"Ed25519",
            "verification_method":"did:web:station.example#authority","signed_digest":format!("sha256:{}", "33".repeat(32)),
            "created_at":"2026-11-15T00:00:00.000Z","signature":base64url_encode([0u8;64])}
    })).unwrap();
    CommittedEventFullView { event, commit }
}

fn material(
    group: &ArkretMlsGroup,
    id: EventId,
    info: Vec<u8>,
    tree: Vec<u8>,
) -> (
    MlsGroupStateMaterialRequestBody,
    MlsGroupStateMaterialResponseBody,
) {
    let request = MlsGroupStateMaterialRequestBody {
        realm_id: realm(),
        effective_scope: scope(),
        mls_group_id: group.group_id(),
        epoch: group.epoch(),
        group_state_event_id: id.clone(),
        caller_actor_id: None,
        target_commit_event_ref: None,
        target_epoch: None,
        group_info_ref: blob(&info),
        ratchet_tree_ref: blob(&tree),
        max_response_bytes: None,
    };
    let response = MlsGroupStateMaterialResponseBody {
        realm_id: realm(),
        effective_scope: scope(),
        mls_group_id: group.group_id(),
        epoch: group.epoch(),
        group_state_event_id: id,
        group_info_ref: request.group_info_ref.clone(),
        group_info_base64url: Base64UrlString::new(base64url_encode(info)).unwrap(),
        ratchet_tree_ref: request.ratchet_tree_ref.clone(),
        ratchet_tree_base64url: Base64UrlString::new(base64url_encode(tree)).unwrap(),
    };
    (request, response)
}

fn fixture() -> (
    ArkretMlsGroup,
    MlsGroupValue,
    CommittedEventFullView,
    MlsGroupStateMaterialRequestBody,
    MlsGroupStateMaterialResponseBody,
) {
    let binding = MlsGovernanceBindingPayload::new(scope(), None, 0, 0, 0).unwrap();
    let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let group = crate::ArkretMlsIdentity::new_test_human_device(actor(), device.clone())
        .unwrap()
        .create_group_with_governance_binding(&scope(), &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let (request, response) = material(&group, event_id(2), info, tree);
    let leaf = group.active_author_leaves().into_iter().next().unwrap();
    let genesis = shape_receipt(
        EventKind::MlsGenesis,
        event_id(2),
        json!({
            "cipher_suite":group.group_ciphersuite_canonical_id().unwrap(),
            "group_info_ref":request.group_info_ref,"ratchet_tree_ref":request.ratchet_tree_ref,
            "creator_leaf_authority":{"leaf_signature_key_base64url":base64url_encode(leaf.signature_key),
                "endpoint":{"kind":"device","device_id":device},"authorization_event_ref":event_id(8)},
            "governance_binding":binding,"created_at":"2026-11-15T00:00:00.000Z"
        }),
        0,
    );
    let current = MlsGroupValue {
        effective_scope: scope(),
        genesis_event_ref: event_id(2),
        cipher_suite: arkret_wire::NonEmptyString::new(
            group.group_ciphersuite_canonical_id().unwrap(),
        )
        .unwrap(),
        current_mls_commit_event_ref: event_id(2),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: request.ratchet_tree_ref.clone(),
    };
    (group, current, genesis, request, response)
}

fn start(q: &EventId) -> (Event, CallRecordingStartPayload) {
    let payload: CallRecordingStartPayload = serde_json::from_value(json!({
        "call_id":arkret_wire::CallId::from_event_id(&event_id(4)),"recording_id":"segment-1",
        "recording_agent_id":"ak:did_core:web:media.example","capture_kind":"recording","mode":"audio","visible_notice":true,
        "capture_metadata":{"key_ref":{"algorithm":"MLS","group_state_ref":q},
            "retention":{"consent_confirmed":true,"retention_expires_at":"2027-11-15T00:00:00.000Z"}}
    })).unwrap();
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::CallRecordingStart.as_str(),
        scope(),
        actor(),
        serde_json::to_value(&payload).unwrap(),
        "2026-11-15T00:00:00.000Z".parse().unwrap(),
    )
    .unwrap();
    (event, payload)
}

fn parameters() -> RecordingStreamParameters {
    RecordingStreamParameters {
        segment_bytes: 1024,
        media_type: "audio/ogg".into(),
        digest_suite: DigestSuite::Sha256,
    }
}

fn artifact(
    output: &RecordingStreamOutput,
    start: &CallRecordingStartPayload,
) -> CallRecordingArtifact {
    CallRecordingArtifact {
        schema: CallRecordingArtifact::SCHEMA.to_owned(),
        realm_id: realm(),
        call_id: start.call_id.clone(),
        recording_id: start.recording_id.clone(),
        recording_start_event_id: output.encryption().context.recording_start_event_id.clone(),
        blob_ref: output.blob_ref().clone(),
        size_bytes: output.size_bytes(),
        duration_ms: 1,
        media_type: output.media_type().to_owned(),
        encryption: output.encryption().clone(),
        retention_policy_id: None,
        retention: start.capture_metadata.retention.clone(),
        produced_by: start.recording_agent_id.clone(),
        recording_initiator_capability_ref: arkret_wire::GrantId::from_event_id(&event_id(8)),
        created_at: "2026-11-15T00:00:00.000Z".parse().unwrap(),
        deletion_audit: None,
    }
}

#[test]
fn real_group_context_material_and_current_coordinates_must_all_match() {
    let (group, current, genesis, request, response) = fixture();
    let source = InstalledRecordingEpoch::verify_installed_material(
        &group, &current, &genesis, &genesis, &request, &response,
    )
    .unwrap();
    source.require_installed(&group).unwrap();
    for axis in 0..5 {
        let mut wrong = current.clone();
        match axis {
            0 => wrong.genesis_event_ref = event_id(7),
            1 => wrong.current_mls_commit_event_ref = event_id(7),
            2 => wrong.epoch = 1,
            3 => wrong.current_key_access_revision = 1,
            4 => wrong.public_tree_ref = blob(b"wrong tree"),
            _ => unreachable!(),
        }
        assert!(
            InstalledRecordingEpoch::verify_installed_material(
                &group, &wrong, &genesis, &genesis, &request, &response
            )
            .is_err(),
            "axis {axis}"
        );
    }
    let mut wrong = response;
    wrong.group_info_base64url = Base64UrlString::new(base64url_encode(b"not RFC 9420")).unwrap();
    assert!(
        InstalledRecordingEpoch::verify_installed_material(
            &group, &current, &genesis, &genesis, &request, &wrong
        )
        .is_err()
    );
    // Same scope and epoch with a different real tree/secret is still not Q.
    let (other, ..) = fixture();
    assert!(source.require_installed(&other).is_err());
}

#[test]
fn actual_epoch_install_fences_old_writer_and_old_tail_can_finish_afterwards() {
    let (mut group, current, genesis, request, response) = fixture();
    let source = InstalledRecordingEpoch::verify_installed_material(
        &group, &current, &genesis, &genesis, &request, &response,
    )
    .unwrap();
    let fence = RecordingEpochFence::new(&source);
    let original_group =
        ArkretMlsGroup::restore_from_state_record(&group.export_state_record().unwrap()).unwrap();
    let (initial_start_event, initial_start) = start(&genesis.event.event_id);
    let mut old = fence
        .begin_recording(
            &group,
            &source,
            &initial_start_event,
            "focus-1".into(),
            parameters(),
        )
        .unwrap();
    old.push_to(b"old epoch tail", |_| Ok(())).unwrap();
    let next_binding =
        MlsGovernanceBindingPayload::new(scope(), Some(genesis.event.event_id.clone()), 0, 1, 0)
            .unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&next_binding)
        .unwrap();
    let (info, tree) = group
        .pending_public_group_state_bytes(&envelope, &next_binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        genesis.event.event_id.clone(),
        0,
        &envelope,
        next_binding,
        blob(&info),
        blob(&tree),
    )
    .unwrap();
    let next = shape_receipt(
        EventKind::MlsCommit,
        event_id(6),
        serde_json::to_value(payload).unwrap(),
        1,
    );
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        ready_rx.recv().unwrap();
        attempt_tx.send(()).unwrap();
        assert!(
            old.push_to(b"new epoch plaintext must never enter old writer", |_| Ok(
                ()
            ))
            .is_err()
        );
        let mut frozen = Vec::new();
        let output = old
            .finish(|bytes| {
                frozen.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            output
                .encryption()
                .key_ref
                .group_state_ref
                .event_id()
                .unwrap(),
            event_id(2)
        );
        assert_eq!(output.size_bytes(), 14 + 16);
        (output, frozen)
    });
    // The worker attempts to write while the real install holds the same fence.
    fence
        .with_epoch_install(|| {
            ready_tx.send(()).unwrap();
            attempt_rx.recv().unwrap();
            group.install_accepted_commit(&next, &current)
        })
        .unwrap();
    let (output, frozen) = worker.join().unwrap();
    assert!(!frozen.is_empty());
    let artifact = artifact(&output, &initial_start);
    assert!(
        source
            .decrypt_recording(
                &group,
                &initial_start_event.event_id,
                &initial_start,
                &artifact,
                &frozen
            )
            .is_err()
    );
    assert_ne!(
        crate::exporter_kdf::derive_rtc_recording_key(
            &original_group,
            &artifact.encryption.context
        )
        .unwrap(),
        crate::exporter_kdf::derive_rtc_recording_key(&group, &artifact.encryption.context)
            .unwrap(),
    );
    assert_eq!(
        &**source
            .decrypt_recording(
                &original_group,
                &initial_start_event.event_id,
                &initial_start,
                &artifact,
                &frozen
            )
            .unwrap(),
        b"old epoch tail"
    );
    assert!(
        fence
            .with_media_delivery(&group, &source, || Ok(()))
            .is_err()
    );
    let mut wrong_context = artifact;
    wrong_context.encryption.context.recording_id = "another-segment".parse().unwrap();
    assert!(
        source
            .decrypt_recording(
                &original_group,
                &initial_start_event.event_id,
                &initial_start,
                &wrong_context,
                &frozen,
            )
            .is_err()
    );
    let (next_request, next_response) = material(&group, event_id(6), info, tree);
    let mut next_current = current;
    next_current.current_mls_commit_event_ref = event_id(6);
    next_current.epoch = 1;
    next_current.public_tree_ref = next_request.ratchet_tree_ref.clone();
    let new_source = InstalledRecordingEpoch::verify_installed_material(
        &group,
        &next_current,
        &genesis,
        &next,
        &next_request,
        &next_response,
    )
    .unwrap();
    fence.adopt_installed_epoch(&group, &new_source).unwrap();
    fence
        .with_media_delivery(&group, &new_source, || Ok(()))
        .unwrap();
    let (next_start, _) = start(&event_id(6));
    let mut writer = fence
        .begin_recording(
            &group,
            &new_source,
            &next_start,
            "focus-1".into(),
            parameters(),
        )
        .unwrap();
    writer.push_to(b"new segment", |_| Ok(())).unwrap();
    assert!(fence.adopt_installed_epoch(&group, &source).is_err());
    fence.stop_capture().unwrap();
    assert!(
        writer
            .push_to(b"after qualification loss", |_| Ok(()))
            .is_err()
    );
}

#[test]
fn failed_install_does_not_reenable_old_writer_or_accept_a_different_start_q() {
    let (group, current, genesis, request, response) = fixture();
    let source = InstalledRecordingEpoch::verify_installed_material(
        &group, &current, &genesis, &genesis, &request, &response,
    )
    .unwrap();
    let fence = RecordingEpochFence::new(&source);
    let (start, _) = start(&event_id(7));
    assert!(
        fence
            .begin_recording(&group, &source, &start, "focus-1".into(), parameters(),)
            .is_err()
    );
    let (valid_start, _) = self::start(&genesis.event.event_id);
    for axis in 0..3 {
        let mut wrong = valid_start.clone();
        match axis {
            0 => wrong.kind = EventKind::CallCreate,
            1 => {
                wrong.scope_ref = ScopeRef::Realm {
                    realm_id: RealmId::from_event_id(&event_id(10)),
                }
            }
            2 => wrong.event_id = event_id(11),
            _ => unreachable!(),
        }
        assert!(
            fence
                .begin_recording(&group, &source, &wrong, "focus-1".into(), parameters())
                .is_err(),
            "original Start axis {axis}"
        );
    }
    assert!(
        fence
            .with_epoch_install::<()>(|| Err(protocol("actual install failed")))
            .is_err()
    );
    assert!(
        fence
            .with_media_delivery(&group, &source, || Ok(()))
            .is_err()
    );
}
