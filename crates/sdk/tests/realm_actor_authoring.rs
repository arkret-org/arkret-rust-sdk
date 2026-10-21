use arkret_canonical::{DigestSuite, canonical_sha256};
use arkret_models_identity::*;
use arkret_models_integration::*;
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_signatures::webvh::{RealmActorInceptionInput, prepare_realm_actor_inception};
use arkret_wire::*;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

#[test]
fn control_http_metadata_is_closed_canonical_and_bound_to_private_realm() {
    let (candidate, _) = candidate();
    let realm = candidate
        .actor_id
        .as_realm_actor_id()
        .unwrap()
        .realm_id
        .clone();
    let metadata = RealmActorControlHttpMetadata {
        actor_id: candidate.actor_id,
        control_ref: CommittedEventRef {
            event_id: EventId::from_digest(DigestSuite::Sha256, [80; 32]),
            commit_id: RealmCommitId::from_digest([81; 32]),
            stream_ref: CommitStreamRef::RealmControl {
                realm_id: realm.clone(),
            },
            stream_position: 0,
        },
        nonce: arkret_canonical::base64url_encode([82; 16]),
    };
    let header = metadata.to_header_value().unwrap();
    assert_eq!(
        RealmActorControlHttpMetadata::from_header_value(&header).unwrap(),
        metadata
    );
    assert!(RealmActorControlHttpMetadata::from_header_value(&(header + "=")).is_err());
    let mut wire = json!(metadata);
    wire["account_id"] = serde_json::Value::Null;
    assert!(
        RealmActorControlHttpMetadata::from_header_value(&arkret_canonical::base64url_encode(
            arkret_canonical::canonical_json_bytes(&wire).unwrap()
        ))
        .is_err()
    );
    let mut wrong = metadata.clone();
    wrong.control_ref.stream_ref = CommitStreamRef::Realm { realm_id: realm };
    assert!(wrong.to_header_value().is_err());
    wrong = metadata.clone();
    wrong.control_ref.stream_ref = CommitStreamRef::RealmControl {
        realm_id: RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [83; 32])),
    };
    assert!(wrong.to_header_value().is_err());
    wrong = metadata;
    wrong.nonce = "short".into();
    assert!(wrong.to_header_value().is_err());
}

fn candidate() -> (RealmActorCreatePayload, Ed25519PayloadSigner) {
    let at: DateTime<Utc> = "2026-10-20T00:00:00.000Z".parse().unwrap();
    let endpoint = "https://applet.example/".parse().unwrap();
    let root = [31; 32];
    let next = SigningKey::from_bytes(&[32; 32]);
    let control = SigningKey::from_bytes(&[33; 32]);
    let next_key =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(next.verifying_key().as_bytes());
    let inception = prepare_realm_actor_inception(&RealmActorInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "ghost-1",
        version_time: at,
        root_seed: &root,
        next_root_public_key_multibase: &next_key,
        controller_public_key: control.verifying_key().as_bytes(),
    })
    .unwrap();
    let document: DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
    let head = canonical_sha256(&inception.log_entry).unwrap();
    let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: head.clone(),
            from_version_id: inception.version_id.clone(),
            to_method_history_head: head.clone(),
            to_version_id: inception.version_id.clone(),
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".into(),
            document_digest: normalized_did_document_digest(&document).unwrap(),
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: head.clone(),
                witnesses: vec![],
                witness_proofs_digest: Hash::new(
                    canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
                )
                .unwrap(),
            }],
        },
        log_entries: vec![inception.log_entry],
        witness_records: vec![],
    };
    let service_did = Did::new("did:web:applet.example").unwrap();
    let service = project_did_to_core_id(&service_did).unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[34; 32]),
        service_did,
        DidUrl::new("did:web:applet.example#service").unwrap(),
    );
    let realm = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [35; 32]));
    let method = DidUrl::new(format!("{}#managed-controller", inception.did)).unwrap();
    let mut value = json!({
        "schema": RealmActorCreatePayload::SCHEMA,
        "actor_id": {"kind":"realm", "realm_actor_id": {"realm_id":realm,"principal_id":project_did_to_core_id(&document.id).unwrap()}},
        "applet_id":"ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb", "service_id":service,
        "actor_role":"ghost", "request_id":"0123456789012345678901",
        "creation_scope":{"kind":"realm","realm_id":realm},
        "registration_ref":EventId::from_digest(DigestSuite::Sha256,[36;32]),
        "creation_authorization_ref":GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256,[37;32])),
        "initial_resolution":{"did":document.id,"method_history_head":head,"version_id":inception.version_id},
        "method_history_evidence":evidence,"control_method_kid":method,
        "expires_at":"2026-10-20T00:05:00.000Z",
        "external_ref":{"protocol":"matrix","instance_id":"chat.example","external_id":"external-user"},
        "recovery":{"kind":"manager_native","enabled":true}
    });
    let transcript: RealmActorCreationTranscript = serde_json::from_value(value.clone()).unwrap();
    value["control_signature"] = serde_json::to_value(
        sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorCreation,
            method,
            at,
            &control,
        )
        .unwrap(),
    )
    .unwrap();
    (serde_json::from_value(value).unwrap(), signer)
}

#[test]
fn manager_handover_requires_two_native_rotations_new_control_and_service_acceptance() {
    let (creation, _) = candidate();
    let start = creation.control_signature.created_at;
    let did = creation.initial_resolution.did.clone();
    let method = DidUrl::new(format!("{did}#receiving-controller")).unwrap();
    let multibase = |seed: u8| {
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    };
    let mut entries = creation.method_history_evidence.webvh_material().1.to_vec();
    let mut state = entries[0]["state"].clone();
    let next_method = json!({"id":method,"type":"Multikey","controller":did,
        "publicKeyMultibase":multibase(55)});
    state["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(next_method.clone());
    state["assertionMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!(method));
    state["authentication"]
        .as_array_mut()
        .unwrap()
        .push(json!(method));
    let append = |entries: &mut Vec<serde_json::Value>,
                  state: &serde_json::Value,
                  seed: u8,
                  next: u8,
                  seconds: i64| {
        let update = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: did.as_str(),
                previous_entries: entries,
                state,
                current_update_seed: &[seed; 32],
                next_update_public_key_multibase: &multibase(next),
                version_time: start + chrono::Duration::seconds(seconds),
            },
        )
        .unwrap();
        entries.push(update.log_entry);
    };
    append(&mut entries, &state, 32, 46, 1);
    let control = |entry: &serde_json::Value, method: DidUrl| RealmActorControlValue {
        resolution: PrincipalResolutionProjection {
            did: did.clone(),
            method_history_head: canonical_sha256(entry).unwrap(),
            version_id: entry["versionId"].as_str().unwrap().into(),
            resolution_event_ref: EventId::from_digest(DigestSuite::Sha256, [93; 32]).to_string(),
            updated_at: start,
        },
        control_method_kid: method,
    };
    let binding = control(&entries[0], creation.control_method_kid.clone());
    let current = control(entries.last().unwrap(), method.clone());
    append(&mut entries, &state, 46, 47, 2);
    let transition = entries.clone();
    state["verificationMethod"] = json!([next_method]);
    state["assertionMethod"] = json!([method]);
    state["authentication"] = json!([method]);
    append(&mut entries, &state, 47, 48, 3);
    let service_did = Did::new("did:web:receiving.example").unwrap();
    let service_method = DidUrl::new(format!("{service_did}#service")).unwrap();
    let service: DidDocument = serde_json::from_value(json!({
        "id":service_did,"verificationMethod":[{"id":service_method,"type":"Multikey",
        "controller":service_did,"publicKeyMultibase":multibase(56)}],
        "assertionMethod":[service_method],
    }))
    .unwrap();
    let payload_for = |entries: &[serde_json::Value]| {
        let terminal = entries.last().unwrap();
        let document: DidDocument = serde_json::from_value(terminal["state"].clone()).unwrap();
        let head = canonical_sha256(terminal).unwrap();
        let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: creation.initial_resolution.method_history_head.clone(),
                from_version_id: creation.initial_resolution.version_id.clone(),
                to_method_history_head: head.clone(),
                to_version_id: terminal["versionId"].as_str().unwrap().into(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head.clone(),
                    witnesses: vec![],
                    witness_proofs_digest: Hash::new(
                        canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
                    )
                    .unwrap(),
                }],
            },
            log_entries: entries.to_vec(),
            witness_records: vec![],
        };
        let rev = CurrentRevision {
            commit_id: RealmCommitId::from_digest([94; 32]),
            stream_position: 4,
        };
        let unsigned = json!({
            "expected_manager_revision":rev,"expected_control_revision":rev,
            "expected_device_generation_revision":rev,"expected_generation":1,"new_generation":2,
            "new_service_id":project_did_to_core_id(&service_did).unwrap(),
            "new_registration_ref":creation.registration_ref,
            "management_authorization_ref":creation.creation_authorization_ref,
            "next_resolution":{"did":did,"version_id":terminal["versionId"],"method_history_head":head},
            "method_history_evidence":evidence,
        });
        let mut transcript = unsigned.clone();
        transcript["actor_id"] = json!(creation.actor_id);
        transcript["applet_id"] = json!(creation.applet_id);
        let transcript: RealmActorManagerAcceptanceTranscript =
            serde_json::from_value(transcript).unwrap();
        let mut signed = unsigned;
        signed["new_service_signature"] = json!(
            sign_detached_object(
                &transcript,
                DetachedSignatureContext::RealmActorManagerAcceptance,
                service_method.clone(),
                start + chrono::Duration::seconds(4),
                &SigningKey::from_bytes(&[56; 32]),
            )
            .unwrap()
        );
        serde_json::from_value::<RealmActorManagerChangePayload>(signed).unwrap()
    };
    let payload = payload_for(&entries);
    let verify = |payload: &RealmActorManagerChangePayload| {
        arkret_identity::verify_realm_actor_manager_successor(
            &creation.actor_id,
            &creation.applet_id,
            &binding,
            &current,
            &creation.control_method_kid,
            payload,
            &service,
            start + chrono::Duration::seconds(5),
        )
    };
    verify(&payload).unwrap();
    assert!(
        verify(&payload_for(&transition)).is_err(),
        "old holder transition alone is insufficient"
    );
    let mut bad = payload.clone();
    bad.management_authorization_ref =
        GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [95; 32]));
    assert!(
        verify(&bad).is_err(),
        "Service acceptance binds the exact governance permission"
    );
    bad = payload.clone();
    bad.new_generation = 3;
    assert!(verify(&bad).is_err());
    bad = payload.clone();
    bad.new_service_id = creation.service_id.clone();
    assert!(verify(&bad).is_err());
    let mut old_retained = state;
    old_retained["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":format!("{did}#old-key-alias"),"type":"Multikey","controller":did,
            "publicKeyMultibase":multibase(33)}),
        );
    append(&mut entries, &old_retained, 48, 49, 4);
    assert!(
        verify(&payload_for(&entries)).is_err(),
        "old key aliases must also be removed"
    );
}

#[test]
fn creation_uses_real_independent_webvh_history_and_control_proof() {
    let (candidate, signer) = candidate();
    let at = candidate.control_signature.created_at;
    let event =
        arkret::author_realm_actor_create(candidate.clone(), DigestSuite::Sha256, at, &signer)
            .unwrap();
    assert_eq!(event.kind, EventKind::RealmActorCreate);
    assert_eq!(event.actor_id, ActorId::service(candidate.service_id));
    assert!(matches!(event.scope_ref, ScopeRef::RealmControl { .. }));
    assert!(event.executed_by.is_none());
    assert_eq!(event.applet_id, Some(candidate.applet_id));
    assert!(event.authorization_ref.is_some());
}

#[test]
fn creation_rejects_changed_actor_scope_proof_and_native_history() {
    let (candidate, signer) = candidate();
    let at = candidate.control_signature.created_at;
    let mut altered = candidate.clone();
    altered.request_id.push('a');
    assert!(arkret::author_realm_actor_create(altered, DigestSuite::Sha256, at, &signer).is_err());
    let mut altered = candidate.clone();
    altered.creation_scope = ScopeRef::Realm {
        realm_id: RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [98; 32])),
    };
    assert!(arkret::author_realm_actor_create(altered, DigestSuite::Sha256, at, &signer).is_err());
    let mut altered = candidate.clone();
    altered.control_signature.context = DetachedSignatureContext::RealmActorControlAcceptance;
    assert!(arkret::author_realm_actor_create(altered, DigestSuite::Sha256, at, &signer).is_err());
    assert!(
        arkret::author_realm_actor_create(
            candidate.clone(),
            DigestSuite::Sha256,
            candidate.expires_at,
            &signer
        )
        .is_err()
    );
    let mut value = serde_json::to_value(candidate).unwrap();
    value["method_history_evidence"]["log_entries"][0]["state"]["id"] =
        json!("did:web:other.example");
    let altered = serde_json::from_value(value).unwrap();
    assert!(arkret::author_realm_actor_create(altered, DigestSuite::Sha256, at, &signer).is_err());
}

#[test]
fn management_review_is_bound_to_the_exact_service_candidate_and_business_scope() {
    use arkret_models_integration::{ManagementReviewRequestBody, ManagementReviewTarget};
    let (candidate, signer) = candidate();
    let event = arkret::author_realm_actor_create(
        candidate.clone(),
        DigestSuite::Sha256,
        candidate.control_signature.created_at,
        &signer,
    )
    .unwrap();
    let mut review = ManagementReviewRequestBody {
        configuration_ref: None,
        request_id: "0123456789012345678901".into(),
        effective_scope: candidate.creation_scope.clone(),
        management_operation: ManagementOperation::MapGhost,
        requester_actor_id: event.actor_id.clone(),
        target: ManagementReviewTarget::Event {
            event: Box::new(event),
        },
    };
    review.validate().unwrap();
    let without_configuration = review.canonical_intent_digest().unwrap();
    review.configuration_ref = Some(AppletConfigurationRef {
        request_id: "ak:request:01904100-0000-7000-8000-bbbbbbbbbbbb"
            .parse()
            .unwrap(),
        intent_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
    });
    assert_ne!(
        without_configuration,
        review.canonical_intent_digest().unwrap()
    );
    let bound = review.canonical_intent_digest().unwrap();
    let mut wire = serde_json::to_value(&review).unwrap();
    assert_eq!(
        serde_json::from_value::<ManagementReviewRequestBody>(wire.clone())
            .unwrap()
            .canonical_intent_digest()
            .unwrap(),
        bound
    );
    wire["configuration_ref"]["login_token"] = json!("forbidden");
    assert!(serde_json::from_value::<ManagementReviewRequestBody>(wire).is_err());
    let mut wire = serde_json::to_value(&review).unwrap();
    wire["configuration_ref"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ManagementReviewRequestBody>(wire).is_err());
    let original = review.target.canonical_target_digest().unwrap();
    let ManagementReviewTarget::Event { event } = &mut review.target;
    event.authorization_ref =
        Some(GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [90; 32])).into());
    assert!(review.validate().is_err());
    assert_ne!(original, review.target.canonical_target_digest().unwrap());
}
#[test]
fn recovery_service_originals_verify_without_business_grants_and_bind_all_sources() {
    use arkret_event_draft::TypedEventDraft;
    use arkret_models_collaboration::authority_commit::{
        HistoricalProducerSignerFact, RealmRecoveryServiceHistoricalSignerFact,
    };
    use arkret_signatures::{SignEventOptions, sign_event};
    let fixture: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-signature-kat-fixture.json")
    ).unwrap()).unwrap();
    let case = &fixture["cases"][4];
    let mut begin = case["unsigned_projection"]["payload_without_control_signature"].clone();
    begin["control_signature"] = case["signature"].clone();
    let begin: RealmActorRecoveryBeginPayload = serde_json::from_value(begin).unwrap();
    let (creation, signer) = candidate();
    let actor = ActorId::service(creation.service_id.clone());
    let realm_id = begin
        .target_actor_id
        .as_realm_actor_id()
        .unwrap()
        .realm_id
        .clone();
    let scope = ScopeRef::RealmControl { realm_id };
    let revision = |r: &CommittedEventRef| CurrentRevision {
        commit_id: r.commit_id.clone(),
        stream_position: r.stream_position,
    };
    for reset in [false, true] {
        let intent = if reset {
            TypedEventDraft::<event_spec::RealmActorControlReset>::new(
                scope.clone(),
                actor.clone(),
                RealmActorControlResetPayload {
                    target_actor_id: begin.target_actor_id.clone(),
                    recovery_begin_ref: begin.recovery_ref.clone(),
                    expected_recovery_revision: revision(&begin.recovery_ref),
                    expected_manager_revision: revision(&begin.manager_ref),
                    expected_control_revision: begin.expected_control_revision.clone(),
                    expected_device_generation_revision: begin
                        .expected_device_generation_revision
                        .clone(),
                    published_method_history_evidence: creation.method_history_evidence.clone(),
                },
            )
            .unwrap()
            .with_applet_id(creation.applet_id.clone())
            .into_intent(creation.control_signature.created_at)
            .unwrap()
        } else {
            TypedEventDraft::<event_spec::RealmActorRecoveryBegin>::new(
                scope.clone(),
                actor.clone(),
                begin.clone(),
            )
            .unwrap()
            .with_applet_id(creation.applet_id.clone())
            .into_intent(creation.control_signature.created_at)
            .unwrap()
        };
        let mut authored = intent
            .author_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        sign_event(
            &mut authored,
            &signer,
            SignEventOptions::new().with_created_at(creation.control_signature.created_at),
        )
        .unwrap();
        let event = authored.into_event();
        assert!(event.authorization_ref.is_none());
        let original:RealmRecoveryServiceHistoricalSignerFact=serde_json::from_value(json!({
            "kind":"realm_recovery_service", "event_id":event.event_id, "actor_id":actor,
            "target_actor_id":begin.target_actor_id,"verification_method":event.producer_proof.as_ref().unwrap().verification_method,
            "public_key_b64u":arkret_canonical::base64url_encode(SigningKey::from_bytes(&[34;32]).verifying_key().as_bytes()),
            "accepted_at":creation.control_signature.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),"applet_id":creation.applet_id,
            "registration_epoch":Hash::new(canonical_sha256(&"registration").unwrap()).unwrap(),
            "registration_ref":begin.manager_ref,"manager_ref":begin.manager_ref,"recovery_ref":begin.recovery_ref
        })).unwrap();
        let verify = |f: RealmRecoveryServiceHistoricalSignerFact| {
            arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
                &event,
                &HistoricalProducerSignerFact::RealmRecoveryService(f),
                DigestSuite::Sha256,
            )
        };
        verify(original.clone()).unwrap();
        let mut bad = original.clone();
        bad.recovery_ref.stream_position += 1;
        assert!(verify(bad).is_err());
        let mut bad = original.clone();
        bad.manager_ref.stream_position += 1;
        assert!(verify(bad).is_err());
        let mut bad = original.clone();
        bad.actor_id = begin.target_actor_id.clone();
        assert!(verify(bad).is_err());
        let mut bad = original.clone();
        bad.public_key_b64u = Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[35; 32]).verifying_key().as_bytes(),
        ))
        .unwrap();
        assert!(verify(bad).is_err());
        let original_digest = original.digest().unwrap();
        let mut changed_registration = original;
        changed_registration.registration_ref.stream_position += 1;
        assert_ne!(original_digest, changed_registration.digest().unwrap());
    }
}
fn recovery_plan() -> (
    RealmActorCreatePayload,
    RealmActorRecoveryBeginPayload,
    AppletManagedActorMethodHistoryEvidence,
) {
    let (creation, _) = candidate();
    let at = creation.control_signature.created_at + chrono::Duration::seconds(1);
    let (_, previous, _) = creation.method_history_evidence.webvh_material();
    let next_control = SigningKey::from_bytes(&[44; 32]);
    let next_update = SigningKey::from_bytes(&[45; 32]);
    let next_method = DidUrl::new(format!(
        "{}#recovered-controller",
        creation.initial_resolution.did
    ))
    .unwrap();
    let state = json!({
        "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],
        "id":creation.initial_resolution.did,
        "verificationMethod":[{"id":next_method,"type":"Multikey","controller":creation.initial_resolution.did,
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(next_control.verifying_key().as_bytes())}],
        "assertionMethod":[next_method], "authentication":[next_method]
    });
    let update = arkret_signatures::webvh::prepare_service_rotation(
        &arkret_signatures::webvh::ServiceRotationInput {
            did: creation.initial_resolution.did.as_str(),
            previous_entries: previous,
            state: &state,
            current_update_seed: &[32; 32],
            next_update_public_key_multibase:
                &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    next_update.verifying_key().as_bytes(),
                ),
            version_time: at,
        },
    )
    .unwrap();
    let mut entries = previous.to_vec();
    entries.push(update.log_entry);
    let head = canonical_sha256(entries.last().unwrap()).unwrap();
    let resolution = ResolutionCommitment {
        did: creation.initial_resolution.did.clone(),
        method_history_head: head.clone(),
        version_id: update.version_id.clone(),
    };
    let realm = creation
        .actor_id
        .as_realm_actor_id()
        .unwrap()
        .realm_id
        .clone();
    let source = CommittedEventRef {
        event_id: EventId::from_digest(DigestSuite::Sha256, [70; 32]),
        commit_id: RealmCommitId::from_digest([71; 32]),
        stream_ref: CommitStreamRef::RealmControl { realm_id: realm },
        stream_position: 0,
    };
    let revision = CurrentRevision {
        commit_id: source.commit_id.clone(),
        stream_position: 0,
    };
    let mut value = json!({
        "target_actor_id":creation.actor_id,"request_id":"0123456789012345678901",
        "manager_ref":source,"recovery_ref":source,"expected_control_revision":revision,
        "expected_owner_status_revision":revision,"expected_governance_status_revision":revision,
        "expected_device_generation_revision":revision,"expected_generation":1,"new_generation":2,
        "replaces_recovery_ref":null,"next_resolution":resolution,
        "method_history_evidence":{"log_entries":entries,"witness_records":[]},
        "next_control_method_kid":next_method,"expires_at":"2026-10-20T00:10:00.000Z"
    });
    let transcript:RealmActorRecoveryAcceptanceTranscript=serde_json::from_value(json!({"applet_id":creation.applet_id,"service_id":creation.service_id,"payload_without_control_signature":value})).unwrap();
    value["control_signature"] = json!(
        sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorRecoveryAcceptance,
            next_method,
            at,
            &next_control
        )
        .unwrap()
    );
    let document: DidDocument = serde_json::from_value(state).unwrap();
    let published = ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: creation.initial_resolution.method_history_head.clone(),
            from_version_id: creation.initial_resolution.version_id.clone(),
            to_method_history_head: head.clone(),
            to_version_id: update.version_id,
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".into(),
            document_digest: normalized_did_document_digest(&document).unwrap(),
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: head,
                witnesses: vec![],
                witness_proofs_digest: Hash::new(
                    canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
                )
                .unwrap(),
            }],
        },
        log_entries: entries,
        witness_records: vec![],
    };
    let published: AppletManagedActorMethodHistoryEvidence =
        serde_json::from_value(json!(published)).unwrap();
    (creation, serde_json::from_value(value).unwrap(), published)
}

#[test]
fn recovery_verifies_native_successor_without_old_control_signature_and_finishes_after_intent_expiry()
 {
    let (creation, plan, published) = recovery_plan();
    let current = PrincipalResolutionProjection {
        did: creation.initial_resolution.did.clone(),
        method_history_head: creation.initial_resolution.method_history_head.clone(),
        version_id: creation.initial_resolution.version_id.clone(),
        resolution_event_ref: EventId::from_digest(DigestSuite::Sha256, [70; 32]).to_string(),
        updated_at: creation.control_signature.created_at,
    };
    let at = plan.control_signature.created_at;
    arkret_identity::verify_realm_actor_recovery_plan(
        &creation.applet_id,
        &creation.service_id,
        &current,
        &creation.control_method_kid,
        &plan,
        at,
        at,
    )
    .unwrap();
    arkret_identity::verify_realm_actor_recovery_publication(
        &plan,
        &published,
        plan.expires_at + chrono::Duration::days(2),
    )
    .unwrap();
    let mut wrong = plan.clone();
    wrong.request_id.push('x');
    assert!(
        arkret_identity::verify_realm_actor_recovery_plan(
            &creation.applet_id,
            &creation.service_id,
            &current,
            &creation.control_method_kid,
            &wrong,
            at,
            at
        )
        .is_err()
    );
    let mut wrong = plan.clone();
    wrong.method_history_evidence.log_entries[1]["state"]["authentication"] = json!([]);
    assert!(
        arkret_identity::verify_realm_actor_recovery_plan(
            &creation.applet_id,
            &creation.service_id,
            &current,
            &creation.control_method_kid,
            &wrong,
            at,
            at
        )
        .is_err()
    );
    let mut wrong = current.clone();
    wrong.method_history_head = canonical_sha256(&"fork").unwrap();
    assert!(
        arkret_identity::verify_realm_actor_recovery_plan(
            &creation.applet_id,
            &creation.service_id,
            &wrong,
            &creation.control_method_kid,
            &plan,
            at,
            at
        )
        .is_err()
    );
    assert!(
        arkret_identity::verify_realm_actor_recovery_publication(
            &plan,
            &creation.method_history_evidence,
            at
        )
        .is_err()
    );
}

#[test]
fn private_current_material_requires_exact_original_source_coordinates() {
    let fixture: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-signature-kat-fixture.json")
    ).unwrap()).unwrap();
    let case = &fixture["cases"][3];
    let mut value = case["unsigned_projection"].clone();
    value["signature"] = case["signature"].clone();
    let material: RealmActorMaterialOutcome = serde_json::from_value(value.clone()).unwrap();
    material.validate().unwrap();
    let mut missing = value.clone();
    missing["result"]["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_ref");
    assert!(serde_json::from_value::<RealmActorMaterialOutcome>(missing).is_err());
    for field in ["commit_id", "stream_position", "stream_ref"] {
        let mut wrong = value.clone();
        let source = &mut wrong["result"]["entries"][0]["source_ref"];
        match field {
            "commit_id" => {
                source[field] = json!(format!(
                    "ak:realm_commit:A{}",
                    arkret_canonical::base64url_encode([91u8; 32])
                ))
            }
            "stream_position" => source[field] = json!(99),
            _ => {
                source[field]["realm_id"] = json!(format!(
                    "ak:realm:A{}",
                    arkret_canonical::base64url_encode([91u8; 32])
                ))
            }
        }
        let wrong: RealmActorMaterialOutcome = serde_json::from_value(wrong).unwrap();
        assert!(wrong.validate().is_err(), "{field}");
    }
}
