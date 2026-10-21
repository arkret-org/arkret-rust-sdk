use arkret_wire::{AccountId, DidCoreId, Hash, ProducerEventProof};
use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;

const DEVICE: &str = "ak:device:0198ff00-0000-7000-8000-000000000001";

fn fixture_intent(circle: bool) -> MlsCreatorBootstrapIntent {
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let parent = if circle {
        scope_create_event(fixture_intent(false).signed_scope_create_unit())
            .unwrap()
            .realm_id
            .clone()
    } else {
        arkret_wire::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
    };
    let timestamp = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let payload = if circle {
        json!({})
    } else {
        let genesis = crate::events_payloads::RealmGenesis::new(
            crate::events_payloads::RealmPurpose::Collaboration,
            arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode([5; 32])).unwrap(),
            arkret_wire::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            arkret_wire::SecurityClass::Standard,
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            arkret_wire::JoinRule::Closed,
            arkret_wire::HistoryAccess::SinceJoin,
            arkret_wire::Discoverability::InviteOnly,
            None,
            None,
        )
        .unwrap();
        serde_json::to_value(crate::events_payloads::RealmCreatePayload::new(genesis)).unwrap()
    };
    let mut create = arkret_wire::test_support::raw_event_for_actor_at(
        if circle {
            "ak.circle.create"
        } else {
            "ak.realm.create"
        },
        if circle {
            ScopeRef::Realm {
                realm_id: parent.clone(),
            }
        } else {
            ScopeRef::RealmGenesis
        },
        actor.clone(),
        payload,
        timestamp,
    )
    .unwrap();
    let method = DidUrl::new(format!("did:web:alice.example#{DEVICE}")).unwrap();
    let digest = Hash::new(
        create
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    // This fixture checks durable DTO bindings, not signature verification.
    create.producer_proof = Some(ProducerEventProof {
        kind: "detached_jws".into(),
        verification_method: method.clone(),
        event_digest: digest.clone(),
        created_at: timestamp,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    let scope = if circle {
        ScopeRef::Circle {
            realm_id: parent,
            circle_id: arkret_wire::CircleId::from_event_id(&create.event_id),
        }
    } else {
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        }
    };
    MlsCreatorBootstrapIntent::new(
        actor,
        scope.clone(),
        DeviceId::new(DEVICE).unwrap(),
        method,
        MlsGovernanceBindingPayload::new(scope, None, 0, 0, 0).unwrap(),
        SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(create)),
    )
    .unwrap()
}

#[test]
fn realm_and_circle_intents_retain_exact_create_bytes_and_derived_group() {
    for circle in [false, true] {
        let original = fixture_intent(circle);
        let bytes = arkret_canonical::canonical_json_bytes(&original).unwrap();
        let restored: MlsCreatorBootstrapIntent = serde_json::from_slice(&bytes).unwrap();
        restored.validate().unwrap();
        assert_eq!(original, restored);
        assert_eq!(
            restored.mls_group_id(),
            &restored.effective_scope().canonical_mls_group_id().unwrap()
        );
    }
}

#[test]
fn creator_intent_rejects_foreign_station_device_signer_and_create_identity() {
    let original = fixture_intent(false);
    let mut altered = original.clone();
    altered.owner_actor_id = ActorId::account(AccountId::new(
        original
            .owner_actor_id
            .as_account_id()
            .unwrap()
            .principal_id
            .clone(),
        DidCoreId::new("ak:did_core:web:other.example").unwrap(),
    ));
    assert!(altered.validate().is_err());
    altered = original.clone();
    altered.creator_device_id =
        DeviceId::new("ak:device:0198ff00-0000-7000-8000-000000000002").unwrap();
    assert!(altered.validate().is_err());
    altered = original.clone();
    altered.creator_signer_method = DidUrl::new("did:web:other.example#key").unwrap();
    assert!(altered.validate().is_err());
    altered = original;
    altered.scope_create_event_id = fixture_intent(true).scope_create_event_id;
    assert!(altered.validate().is_err());
}

#[test]
fn intent_cannot_borrow_another_scope_or_serialize_an_open_or_partial_record() {
    let original = fixture_intent(false);
    let mut altered = original.clone();
    altered.effective_scope = fixture_intent(true).effective_scope;
    assert!(altered.validate().is_err());
    let value = serde_json::to_value(original).unwrap();
    for field in value.as_object().unwrap().keys() {
        let mut partial = value.clone();
        partial.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<MlsCreatorBootstrapIntent>(partial).is_err(),
            "missing {field}"
        );
    }
    let mut open = value;
    open["proof_outcome"] = json!({});
    assert!(serde_json::from_value::<MlsCreatorBootstrapIntent>(open).is_err());
}

#[test]
fn deserialized_intent_cannot_rebind_genesis_coordinates_or_its_derived_group() {
    let original = fixture_intent(false);
    for field in ["previous_epoch", "next_epoch", "key_access_revision"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["proposed_group_genesis_binding"]["proposed_group_genesis_binding"][field] = json!(1);
        let altered: MlsCreatorBootstrapIntent = serde_json::from_value(value).unwrap();
        assert!(altered.validate().is_err(), "changed {field}");
    }
    let mut altered = original;
    altered.mls_group_id = fixture_intent(true).mls_group_id;
    assert!(altered.validate().is_err());
}

#[test]
fn human_creator_cannot_replace_the_device_proof_with_a_generic_account_key() {
    let mut altered = fixture_intent(false);
    let method = DidUrl::new("did:web:alice.example#key").unwrap();
    altered.creator_signer_method = method.clone();
    let SelfAuthoritySubmitRequest::Event(event) = &mut altered.signed_scope_create_unit else {
        panic!("fixture must be an Event");
    };
    event
        .event
        .producer_proof
        .as_mut()
        .unwrap()
        .verification_method = method;
    assert!(altered.validate().is_err());
}

#[test]
fn runtime_endpoint_does_not_classify_an_agent_account_as_a_human_device() {
    let mut original = fixture_intent(false);
    let method = DidUrl::new("did:web:alice.example#agent-key").unwrap();
    let SelfAuthoritySubmitRequest::Event(event) = &mut original.signed_scope_create_unit else {
        panic!("fixture must be an Event");
    };
    event
        .event
        .producer_proof
        .as_mut()
        .unwrap()
        .verification_method = method.clone();
    let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method: method.clone(),
    };
    let mut runtime = MlsCreatorBootstrapIntent::new_with_endpoint(
        original.owner_actor_id.clone(),
        original.effective_scope.clone(),
        original.creator_device_id.clone(),
        method,
        endpoint,
        original.proposal().proposed_group_genesis_binding().clone(),
        original.signed_scope_create_unit.clone(),
    )
    .unwrap();
    runtime.validate().unwrap();
    runtime.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
        device_id: runtime.creator_device_id.clone(),
    };
    assert!(runtime.validate().is_err());
    let mut device = fixture_intent(false);
    device.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method: device.creator_signer_method.clone(),
    };
    assert!(device.validate().is_err());
}

fn current_cut(
    circle: bool,
) -> (
    ScopeRef,
    arkret_wire::CommitStreamHead,
    MlsCreatorBootstrapCurrentCut,
) {
    use arkret_wire::{CommitStreamHead, CommitStreamRef, RealmCommitId};

    use crate::sync_frames::current_results::AccountCurrentCoverage;

    let scope = fixture_intent(circle).effective_scope;
    let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
    let realm_id = stream.realm_id().clone();
    let realm_head = CommitStreamHead {
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: 7,
        commit_id: RealmCommitId::new(
            "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        )
        .unwrap(),
    };
    let mut heads = vec![realm_head.clone()];
    if circle {
        heads.push(CommitStreamHead {
            stream_ref: stream,
            stream_position: 2,
            commit_id: RealmCommitId::new(
                "ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        });
    }
    let cut = MlsCreatorBootstrapCurrentCut::new(
        RealmDetailBaseline {
            snapshot_cursor: "ak:cursor:creator_cut".into(),
            cut_revision: 11,
            coverage: AccountCurrentCoverage {
                realm_id: realm_id.clone(),
                stream_heads: heads.clone(),
                complete_for_authorized_streams: true,
            },
            complete: true,
        },
        AccountCurrentView {
            realm_id,
            governance_generation: 3,
            stream_heads: heads,
            entries: vec![],
        },
    );
    (scope, realm_head, cut)
}

#[test]
fn complete_realm_and_circle_cuts_preserve_independent_heads_across_reload() {
    for circle in [false, true] {
        let (scope, head, cut) = current_cut(circle);
        let bytes = arkret_canonical::canonical_json_bytes(&cut).unwrap();
        let mut restored: MlsCreatorBootstrapCurrentCut = serde_json::from_slice(&bytes).unwrap();
        restored.current.stream_heads.reverse();
        restored.validate_absence_binding(&scope, 3, &head).unwrap();
    }
}

#[test]
fn empty_incomplete_or_uncovered_cuts_never_prove_genesis_absence() {
    let (scope, head, cut) = current_cut(true);
    let mut altered = cut.clone();
    altered.baseline.complete = false;
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    altered = cut.clone();
    altered.baseline.coverage.complete_for_authorized_streams = false;
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    altered = cut.clone();
    altered.baseline.coverage.stream_heads.pop();
    altered.current.stream_heads.pop();
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    altered = cut;
    altered.baseline.coverage.stream_heads.clear();
    altered.current.stream_heads.clear();
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
}

#[test]
fn creator_cut_cannot_mix_generations_heads_realms_or_duplicate_coverage() {
    let (scope, head, cut) = current_cut(true);
    assert!(cut.validate_absence_binding(&scope, 4, &head).is_err());
    let mut altered = cut.clone();
    altered.current.stream_heads[1].stream_position += 1;
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    altered = cut.clone();
    altered.baseline.coverage.stream_heads.push(head.clone());
    altered.current.stream_heads.push(head.clone());
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    altered = cut.clone();
    let mut other = current_cut(false).1;
    other.stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::new(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        )
        .unwrap(),
    };
    altered.baseline.coverage.stream_heads.push(other.clone());
    altered.current.stream_heads.push(other);
    assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    let mut advanced_head = head;
    advanced_head.stream_position += 1;
    assert!(
        cut.validate_absence_binding(&scope, 3, &advanced_head)
            .is_err()
    );
}

#[test]
fn an_exact_scope_mls_current_entry_is_a_winner_even_if_its_value_is_empty() {
    let (scope, head, mut cut) = current_cut(true);
    let entry = arkret_wire::TypedCurrentRow::Value {
        selector: arkret_wire::CurrentSelector::MlsGroup {
            scope_ref: scope.clone(),
        },
        source_stream_ref: cut.current.stream_heads[1].stream_ref.clone(),
        revision: arkret_wire::CurrentRevision {
            commit_id: cut.current.stream_heads[1].commit_id.clone(),
            stream_position: 2,
        },
        value: json!({}),
    };
    cut.current.entries.push(entry);
    assert!(cut.validate_absence_binding(&scope, 3, &head).is_err());
}

fn accepted_create(circle: bool) -> (MlsCreatorBootstrapIntent, MlsCreatorBootstrapAcceptedCreate) {
    use arkret_wire::{
        Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
        DetachedSignatureAlgorithm, DetachedSignatureContext, RealmAuthorityBundle,
        RealmAuthorityCurrentAssertion, RealmCommit, RealmCommitAuthorityRef, RealmCommitId,
    };

    let intent = fixture_intent(circle);
    let root_event = scope_create_event(fixture_intent(false).signed_scope_create_unit())
        .unwrap()
        .clone();
    let realm_id = root_event.realm_id.clone();
    let service = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let timestamp = root_event.created_at;
    // These detached signatures exercise shape bindings only. No test
    // claims independently verified acceptance from this synthetic bundle.
    let signature = |context| DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:station.example#key").unwrap(),
        signed_digest: Hash::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        created_at: timestamp,
        sig: Base64UrlString::new("AA").unwrap(),
    };
    let root_commit = RealmCommit {
        commit_id: RealmCommitId::new(
            "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        )
        .unwrap(),
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: root_event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(root_event.event_id.clone()),
        committed_at: timestamp,
        producer_signer_fact_digest: None,
        signature: signature(DetachedSignatureContext::RealmCommit),
    };
    let head = CommitStreamHead {
        stream_ref: root_commit.stream_ref.clone(),
        stream_position: 0,
        commit_id: root_commit.commit_id.clone(),
    };
    let root = RealmAuthorityBundle {
        realm_id: realm_id.clone(),
        genesis_event: root_event,
        genesis_commit: root_commit.clone(),
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: service.clone(),
        current_route_record: json!({}),
        realm_stream_head: head.clone(),
        bundle_issued_at: timestamp,
        current_assertion: RealmAuthorityCurrentAssertion {
            realm_id,
            current_generation: 0,
            current_service_id: service,
            last_handoff_ref: None,
            realm_stream_head: head,
            nonce: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            expires_at: timestamp + chrono::TimeDelta::minutes(5),
            signature: signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
        },
    };
    let event = scope_create_event(intent.signed_scope_create_unit())
        .unwrap()
        .clone();
    let mut commit = root_commit;
    if circle {
        commit.previous_commit_ref = Some(commit.commit_id.clone());
        commit.commit_id =
            RealmCommitId::new("ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        commit.stream_position = 1;
        commit.event_ref = event.event_id.clone();
    }
    let accepted = MlsCreatorBootstrapAcceptedCreate::new(
        &intent,
        event,
        commit,
        arkret_canonical::DigestSuite::Sha256,
        root,
    )
    .unwrap();
    (intent, accepted)
}

fn absence_snapshot(
    accepted: &MlsCreatorBootstrapAcceptedCreate,
) -> arkret_wire::RealmStateSnapshot {
    let root = accepted.authority_root().unwrap();
    let head = root.realm_stream_head.clone();
    let mut signature = root.current_assertion.signature.clone();
    signature.context = arkret_wire::DetachedSignatureContext::RealmSnapshot;
    // Structural fixture only; the host must authenticate this carrier.
    arkret_wire::RealmStateSnapshot {
        purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
        history_basis: None,
        snapshot_id: arkret_wire::RealmSnapshotId::from_digest([3; 32]),
        realm_id: root.realm_id.clone(),
        governance_generation: root.current_generation,
        visible_stream_heads: vec![head.clone()],
        current_state_entries: vec![],
        retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
            history_access: arkret_wire::HistoryAccess::SinceJoin,
            stream_floors: vec![arkret_wire::StreamHistoryFloor {
                stream_ref: head.stream_ref,
                oldest_position: 0,
            }],
        },
        created_at: root.bundle_issued_at,
        signature,
    }
}

fn device_query_fixture(
    intent: &MlsCreatorBootstrapIntent,
) -> arkret_models_crypto::KeysQueryOutcome {
    let now = scope_create_event(intent.signed_scope_create_unit())
        .unwrap()
        .created_at;
    // Shape-only local evidence fixture, never an authenticated Station response.
    serde_json::from_value(json!({
        "device_keys": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(), "device_keys": {
            intent.creator_device_id().as_str(): {
                "signer_evidence_ref": "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "algorithms": {}, "trust_algorithms": [],
                "device_projection": {
                    "device_signing_key_did": "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
                    "hpke_key": "hpke-test", "device_authorize_event_id": intent.scope_create_event_id(),
                    "authorized_generation_ref": 7, "device_status": "active",
                    "attested_at": arkret_canonical::format_timestamp_canonical(now), "expires_at": arkret_canonical::format_timestamp_canonical(now + chrono::TimeDelta::minutes(5)),
                    "authorization_window": {"not_before": arkret_canonical::format_timestamp_canonical(now), "expires_at": null}
                }
            }
        }}],
        "failures": [],
        "device_generations": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(),
            "generation_state": {"current_device_generation_ref": 7}}]
    })).unwrap()
}

fn pinned_fixture(
    intent: &MlsCreatorBootstrapIntent,
    accepted: &MlsCreatorBootstrapAcceptedCreate,
) -> MlsCreatorBootstrapGovernanceEvidence {
    let device = MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
        intent,
        &device_query_fixture(intent),
        accepted.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    MlsCreatorBootstrapGovernanceEvidence::new_device(
        intent,
        accepted.clone(),
        absence_snapshot(accepted),
        device,
    )
    .unwrap()
}

fn agent_creator_fixture() -> (
    MlsCreatorBootstrapIntent,
    MlsCreatorBootstrapAcceptedCreate,
    MlsCreatorBootstrapGovernanceEvidence,
) {
    use arkret_models_identity::signer_key_operations::{
        CurrentSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQueryOutcome,
        SignerKeyQuerySelector,
    };
    let (mut intent, mut create) = accepted_create(false);
    let method = DidUrl::new("did:web:alice.example#runtime").unwrap();
    intent.creator_signer_method = method.clone();
    intent.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method: method.clone(),
    };
    let SelfAuthoritySubmitRequest::Event(original) = &mut intent.signed_scope_create_unit else {
        unreachable!()
    };
    original
        .event
        .producer_proof
        .as_mut()
        .unwrap()
        .verification_method = method.clone();
    create.accepted_event = original.event.clone();
    create.authority_root.native_bundle_mut().genesis_event = original.event.clone();
    create.accepted_bytes_digest = Hash::new(arkret_canonical::canonical::digest(
        create.digest_suite,
        arkret_canonical::canonical_json_bytes(&original.event).unwrap(),
    ))
    .unwrap();
    create.validate_binding(&intent).unwrap();
    let outcome = SignerKeyQueryOutcome::CurrentResolved {
        selector: SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::Agent {
                actor: intent.owner_actor_id().clone(),
                verification_method: method,
            },
        },
        key: ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                [11; 32],
            ))
            .unwrap(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: create.accepted_event.event_id.clone(),
                commit_id: create.covering_commit.commit_id.clone(),
                stream_ref: create.covering_commit.stream_ref.clone(),
                stream_position: 0,
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: create.covering_commit.commit_id.clone(),
                stream_position: 0,
            },
            governance_generation: 0,
        },
    };
    let authority = MlsCreatorBootstrapAgentAuthority::from_current_signer_query(
        &intent,
        outcome,
        create.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    let evidence = MlsCreatorBootstrapGovernanceEvidence::new_with_endpoint_authority(
        &intent,
        create.clone(),
        absence_snapshot(&create),
        MlsCreatorBootstrapEndpointAuthority::Agent(authority),
    )
    .unwrap();
    (intent, create, evidence)
}

#[test]
fn agent_creator_pin_rejects_device_historical_foreign_actor_and_method_substitution() {
    use arkret_models_identity::signer_key_operations::{
        CurrentSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    };
    let (intent, _, evidence) = agent_creator_fixture();
    evidence.validate_binding(&intent).unwrap();
    assert!(evidence.creator_device_authority().is_err());
    let MlsCreatorBootstrapEndpointAuthority::Agent(authority) = evidence.creator_authority()
    else {
        unreachable!()
    };
    let mut other = intent.clone();
    other.owner_actor_id = ActorId::account(AccountId::new(
        intent
            .owner_actor_id()
            .as_account_id()
            .unwrap()
            .principal_id
            .clone(),
        DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
    ));
    assert!(authority.validate_binding(&other).is_err());
    let outcome = SignerKeyQueryOutcome::Unavailable {
        selector: SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::Agent {
                actor: intent.owner_actor_id().clone(),
                verification_method: intent.creator_signer_method().clone(),
            },
        },
    };
    assert!(
        MlsCreatorBootstrapAgentAuthority::from_current_signer_query(&intent, outcome, Utc::now())
            .is_err()
    );
    let mut changed = serde_json::to_value(authority).unwrap();
    changed["outcome"]["selector"]["verification_method"] =
        json!("did:web:alice.example#replacement");
    assert!(
        serde_json::from_value::<MlsCreatorBootstrapAgentAuthority>(changed)
            .unwrap()
            .validate_binding(&intent)
            .is_err()
    );
    let device = fixture_intent(false);
    assert!(authority.validate_binding(&device).is_err());
    let mut changed = serde_json::to_value(authority).unwrap();
    changed["outcome"]["selector"]["verification_mode"] = json!("historical_event");
    assert!(serde_json::from_value::<MlsCreatorBootstrapAgentAuthority>(changed).is_err());
}

#[test]
fn agent_creator_reloads_all_progress_steps_and_preserves_the_original_signed_bytes() {
    // Structural local FSM test, not a claim of authenticated Station acceptance.
    let (intent, create, evidence) = agent_creator_fixture();
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let original_bytes = arkret_canonical::canonical_json_bytes(signed.event()).unwrap();
    let reload = |record: &MlsCreatorBootstrapRecord| {
        let restored: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(record).unwrap()).unwrap();
        restored.validate().unwrap();
        restored
    };
    let mut record = reload(&MlsCreatorBootstrapRecord::new(intent.clone()).unwrap());
    record
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    record = reload(&record);
    record.pin_governance(evidence).unwrap();
    record = reload(&record);
    record.persist_epoch_zero(unit.clone()).unwrap();
    record = reload(&record);
    record.queue_genesis(signed.clone()).unwrap();
    record = reload(&record);
    assert_eq!(
        record.queued_genesis().unwrap().canonical_signed_bytes,
        original_bytes
    );
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(commit.commit_id.clone());
    commit.event_ref = signed.event_id().clone();
    let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
        &intent,
        record.queued_genesis().unwrap(),
        arkret_wire::CommittedEventFullView {
            event: signed.event().clone(),
            commit,
        },
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    record.accept_genesis(accepted).unwrap();
    record = reload(&record);
    let payload = unit.payload().unwrap();
    let checks = MlsCreatorBootstrapArtifactChecks {
        effective_scope: intent.effective_scope().clone(),
        mls_group_id: intent.mls_group_id().clone(),
        epoch: 0,
        cipher_suite: payload.cipher_suite.to_string(),
        creator_leaf_authority: payload.creator_leaf_authority,
        group_info_bytes: unit.group_info_bytes().to_vec(),
        ratchet_tree_bytes: unit.ratchet_tree_bytes().to_vec(),
    };
    record
        .converge_artifacts(MlsCreatorBootstrapArtifacts::new(&record, checks).unwrap())
        .unwrap();
    record = reload(&record);
    record
        .publish_ready(MlsCreatorBootstrapReadyReceipt::new(&record, 7).unwrap())
        .unwrap();
    record = reload(&record);
    assert_eq!(
        record.ready_receipt().unwrap().accepted_genesis_event_id(),
        signed.event_id()
    );
    assert_eq!(
        record.queued_genesis().unwrap().canonical_signed_bytes,
        original_bytes
    );
}

#[test]
fn accepted_winner_before_the_local_create_checkpoint_terminates_without_fabricating_absence() {
    let (intent, create, evidence) = agent_creator_fixture();
    let external_unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &external_unit);
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(commit.commit_id.clone());
    commit.event_ref = signed.event_id().clone();
    let winner = MlsCreatorBootstrapWinner::from_accepted(
        &intent,
        create.clone(),
        arkret_wire::CommittedEventFullView {
            event: signed.event().clone(),
            commit,
        },
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let before = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    let mut after = before.clone();
    after.supersede(winner.clone()).unwrap();
    let after: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&after).unwrap()).unwrap();
    after.validate().unwrap();
    assert_eq!(after.intent(), &intent);
    assert!(
        after.epoch_zero().is_none()
            && after.queued_genesis().is_none()
            && after.ready_receipt().is_none()
    );
    assert_eq!(after.accepted_create(), Some(&create));
    assert_eq!(
        before.state(),
        arkret_wire::MlsCreatorBootstrapState::GenesisIntentPersisted
    );
    let MlsCreatorBootstrapRecord::Superseded { loser_record, .. } = &after else {
        unreachable!()
    };
    assert_eq!(loser_record.as_ref(), &before);
    let mut exact_replay = after.clone();
    exact_replay.supersede(winner).unwrap();
    assert_eq!(exact_replay, after);
}

fn epoch_zero_fixture(
    intent: &MlsCreatorBootstrapIntent,
    evidence: &MlsCreatorBootstrapGovernanceEvidence,
) -> MlsCreatorBootstrapEpochZero {
    let public = b"shape-only-group-info".to_vec();
    let tree = b"shape-only-tree".to_vec();
    let blob = |bytes: &[u8]| {
        arkret_wire::BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::canonical::digest(arkret_canonical::DigestSuite::Sha256, bytes)
        ))
        .unwrap()
    };
    let at = evidence.creator_authority.verified_at();
    let payload = crate::events_payloads::MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(
            arkret_wire::generated::security_strings::MLS_CIPHERSUITES
                .iter()
                .find(|suite| suite.status == "active" && suite.profile_gate.is_none())
                .unwrap()
                .canonical_id,
        )
        .unwrap(),
        group_info_ref: blob(&public),
        ratchet_tree_ref: blob(&tree),
        creator_leaf_authority: crate::events_payloads::MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url::base64url_encode([3; 32]),
            )
            .unwrap(),
            endpoint: intent.creator_endpoint().clone(),
            authorization_event_ref: evidence.creator_authority.authorization_event_ref().clone(),
        },
        governance_binding: evidence.governance_binding.clone(),
        created_at: at,
    };
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.mls.genesis",
        intent.effective_scope().clone(),
        intent.owner_actor_id().clone(),
        serde_json::to_value(payload).unwrap(),
        at,
    )
    .unwrap();
    MlsCreatorBootstrapEpochZero::new(
        intent,
        evidence,
        b"opaque-device-envelope-fixture".to_vec(),
        public,
        tree,
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    )
    .unwrap()
}
fn sign_epoch_zero_fixture(
    intent: &MlsCreatorBootstrapIntent,
    unit: &MlsCreatorBootstrapEpochZero,
) -> arkret_wire::AuthoredEvent {
    let mut event = unit.unsigned_genesis().clone();
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(event.digest_suite())
            .unwrap(),
    )
    .unwrap();
    // Structural proof only. These tests do not authenticate acceptance.
    event.attach_proof(ProducerEventProof {
        kind: "detached_jws".into(),
        verification_method: intent.creator_signer_method().clone(),
        event_digest: digest.clone(),
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

#[test]
fn creator_epoch_zero_and_signed_original_roundtrip_without_replacement() {
    let (intent, accepted) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &accepted);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    assert!(record.persist_epoch_zero(unit.clone()).is_err());
    record
        .accept_realm(accepted.clone(), absence_snapshot(&accepted))
        .unwrap();
    record.pin_governance(evidence).unwrap();
    record.persist_epoch_zero(unit.clone()).unwrap();
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::Epoch0StatePersisted
    );
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    record.persist_epoch_zero(unit.clone()).unwrap();
    let mut different = unit.clone();
    different.encrypted_private_state.push(1);
    assert!(record.persist_epoch_zero(different).is_err());
    assert_eq!(record, reopened);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    record.queue_genesis(signed.clone()).unwrap();
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::GenesisQueued
    );
    record.queue_genesis(signed.clone()).unwrap();
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    let mut changed = signed;
    let mut proof = changed.producer_proof.clone().unwrap();
    proof.created_at += chrono::TimeDelta::milliseconds(1);
    changed.attach_proof(proof);
    assert!(record.queue_genesis(changed).is_err());
    assert_eq!(record, reopened);
}

#[test]
fn creator_new_query_cut_keeps_the_original_governance_pin_immutable() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    record
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    record.pin_governance(evidence.clone()).unwrap();
    let frozen = record.clone();
    // Shape-only later cut. Its real signatures are verified by the host.
    let mut root = create.authority_root().unwrap().clone();
    root.realm_stream_head.stream_position += 1;
    root.realm_stream_head.commit_id = arkret_wire::RealmCommitId::from_digest([23; 32]);
    root.current_assertion.realm_stream_head = root.realm_stream_head.clone();
    let current = MlsCreatorBootstrapAcceptedCreate::new(
        &intent,
        create.accepted_event().clone(),
        create.covering_commit().clone(),
        create.digest_suite(),
        root,
    )
    .unwrap();
    let later = absence_snapshot(&current);
    assert!(validate_creator_genesis_absence_snapshot(&intent, &create, &later).is_err());
    validate_creator_genesis_absence_snapshot(&intent, &current, &later).unwrap();
    assert_eq!(record, frozen);
    assert_eq!(record.governance_evidence(), Some(&evidence));
}

fn own_creator_cut(
    intent: &MlsCreatorBootstrapIntent,
    native: &MlsCreatorBootstrapAcceptedCreate,
    sequence: u64,
) -> (
    MlsCreatorBootstrapAuthority,
    arkret_wire::RealmStateSnapshot,
) {
    let mut snapshot = absence_snapshot(native);
    let payload: crate::events_payloads::RealmCreatePayload = serde_json::from_value(
        serde_json::to_value(&native.authority_root().unwrap().genesis_event.payload).unwrap(),
    )
    .unwrap();
    snapshot
        .current_state_entries
        .push(arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::RealmGenesis,
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: snapshot.realm_id.clone(),
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: native.covering_commit.commit_id.clone(),
                stream_position: 0,
            },
            value: serde_json::to_value(&payload.object).unwrap(),
        });
    let mut unsigned = serde_json::to_value(&snapshot).unwrap();
    unsigned.as_object_mut().unwrap().remove("snapshot_id");
    unsigned.as_object_mut().unwrap().remove("signature");
    snapshot.snapshot_id = arkret_wire::RealmSnapshotId::from_digest(
        arkret_canonical::sha256_bytes(arkret_canonical::canonical_json_bytes(&unsigned).unwrap()),
    );
    let cut = MlsCreatorBootstrapAuthority::own_station(
        snapshot.clone(),
        payload.object,
        intent.owner_actor_id().as_account_id().unwrap().clone(),
        arkret_wire::SessionGrantId::from_issuance_digest([7; 32]),
        3,
        sequence,
    )
    .unwrap();
    (cut, snapshot)
}

#[test]
fn own_station_creator_original_pin_queue_acceptance_roundtrip_without_native_bundle() {
    let (intent, native) = accepted_create(false);
    let (cut, snapshot) = own_creator_cut(&intent, &native, 1);
    let create = MlsCreatorBootstrapAcceptedCreate::new(
        &intent,
        native.accepted_event().clone(),
        native.covering_commit().clone(),
        native.digest_suite(),
        cut.clone(),
    )
    .unwrap();
    assert!(create.authority_root().is_err());
    let device = MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
        &intent,
        &device_query_fixture(&intent),
        snapshot.created_at,
    )
    .unwrap();
    let evidence = MlsCreatorBootstrapGovernanceEvidence::new_device(
        &intent,
        create.clone(),
        snapshot.clone(),
        device,
    )
    .unwrap();
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let queued = MlsCreatorBootstrapQueuedGenesis::new(&intent, &unit, signed.clone()).unwrap();
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
    commit.event_ref = signed.event_id().clone();
    let full = arkret_wire::CommittedEventFullView {
        event: signed.event().clone(),
        commit,
    };
    let mut accepted_snapshot = snapshot.clone();
    accepted_snapshot.visible_stream_heads[0].stream_position = full.commit.stream_position;
    accepted_snapshot.visible_stream_heads[0].commit_id = full.commit.commit_id.clone();
    let mut unsigned = serde_json::to_value(&accepted_snapshot).unwrap();
    unsigned.as_object_mut().unwrap().remove("snapshot_id");
    unsigned.as_object_mut().unwrap().remove("signature");
    accepted_snapshot.snapshot_id = arkret_wire::RealmSnapshotId::from_digest(
        arkret_canonical::sha256_bytes(arkret_canonical::canonical_json_bytes(&unsigned).unwrap()),
    );
    let MlsCreatorBootstrapAuthority::OwnStation(original) = &cut else {
        unreachable!()
    };
    let accepted_cut = MlsCreatorBootstrapAuthority::own_station(
        accepted_snapshot,
        original.realm_genesis.clone(),
        original.account_id.clone(),
        original.session_grant_id.clone(),
        original.session_epoch,
        2,
    )
    .unwrap();
    assert!(
        MlsCreatorBootstrapAcceptedGenesis::new(&intent, &queued, full.clone(), cut.clone())
            .is_err()
    );
    let acceptance = MlsCreatorBootstrapAcceptedGenesis::new(
        &intent,
        &queued,
        full.clone(),
        accepted_cut.clone(),
    )
    .unwrap();
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    record
        .accept_realm(create.clone(), snapshot.clone())
        .unwrap();
    record.pin_governance(evidence).unwrap();
    record.persist_epoch_zero(unit).unwrap();
    record.queue_genesis(signed).unwrap();
    record.accept_genesis(acceptance).unwrap();
    let restored: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored, record);
    assert_eq!(restored.accepted_genesis().unwrap().accepted(), &full);
    let known =
        MlsCreatorBootstrapKnownGenesis::authenticated_winner(&record, full.clone(), accepted_cut)
            .unwrap();
    assert!(matches!(
        known,
        MlsCreatorBootstrapKnownGenesis::Winner { .. }
    ));
    let mut wrong = cut.clone();
    if let MlsCreatorBootstrapAuthority::OwnStation(cut) = &mut wrong {
        cut.account_id.station_id =
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    }
    assert!(
        MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            create.accepted_event().clone(),
            create.covering_commit().clone(),
            create.digest_suite(),
            wrong.clone()
        )
        .is_err()
    );
    assert!(MlsCreatorBootstrapAcceptedGenesis::new(&intent, &queued, full, wrong).is_err());
    let mut changed_snapshot = snapshot;
    changed_snapshot.current_state_entries.clear();
    assert!(
        validate_creator_genesis_absence_snapshot(&intent, &create, &changed_snapshot).is_err()
    );
    let (fresh, _) = own_creator_cut(&intent, &native, 2);
    assert!(cut.same_read(&cut));
    assert!(!cut.same_read(&fresh));
    // This tests local structural records only. The host's real Bound
    // source/session lifecycle is mandatory before either constructor.
}

#[test]
fn creator_exact_accepted_genesis_retains_bytes_commit_and_original_unit() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let queued = MlsCreatorBootstrapQueuedGenesis::new(&intent, &unit, signed.clone()).unwrap();
    // Synthetic Commit exercises structure only, not authority signatures.
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
    commit.event_ref = signed.event_id().clone();
    let row = arkret_wire::CommittedEventFullView {
        event: signed.event().clone(),
        commit,
    };
    let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
        &intent,
        &queued,
        row.clone(),
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    assert!(record.accept_genesis(accepted.clone()).is_err());
    record
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    record.pin_governance(evidence).unwrap();
    record.persist_epoch_zero(unit.clone()).unwrap();
    assert!(record.accept_genesis(accepted.clone()).is_err());
    record.queue_genesis(signed).unwrap();
    record.accept_genesis(accepted.clone()).unwrap();
    record.accept_genesis(accepted.clone()).unwrap();
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::GenesisAccepted
    );
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened.epoch_zero(), Some(&unit));
    let mut changed = accepted.clone();
    changed.accepted.commit.committed_at += chrono::TimeDelta::milliseconds(1);
    assert!(record.accept_genesis(changed).is_err());
    assert_eq!(record, reopened);
    let mut changed = row.clone();
    changed.event.producer_proof.as_mut().unwrap().created_at += chrono::TimeDelta::milliseconds(1);
    assert!(
        MlsCreatorBootstrapAcceptedGenesis::new(
            &intent,
            &queued,
            changed,
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
    let mut changed = row;
    changed.commit.event_ref = intent.scope_create_event_id().clone();
    assert!(
        MlsCreatorBootstrapAcceptedGenesis::new(
            &intent,
            &queued,
            changed,
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
    let mut changed = accepted;
    changed.canonical_accepted_bytes.push(0);
    assert!(changed.validate_binding(&intent, &queued).is_err());
}

#[test]
fn creator_terminal_rejection_reopens_only_from_a_new_verified_absence_and_keeps_tombstones() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    original
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    original.pin_governance(evidence).unwrap();
    original.persist_epoch_zero(unit.clone()).unwrap();
    original.queue_genesis(signed.clone()).unwrap();
    let last_verified =
        MlsCreatorBootstrapVerifiedAbsence::new(&intent, create.clone(), absence_snapshot(&create))
            .unwrap();
    assert!(
        MlsCreatorBootstrapRejection::new(&original, String::new(), last_verified.clone()).is_err()
    );
    for (code, status) in [
        ("failed_precondition", 412),
        ("unauthorized", 401),
        ("not_found", 404),
        ("rate_limited", 429),
        ("internal_error", 500),
        ("failed_precondition", 503),
    ] {
        assert!(
            MlsCreatorBootstrapRejection::from_problem(
                &original,
                arkret_wire::Problem::new(code, status, "not a definite admission decision"),
                last_verified.clone()
            )
            .is_err()
        );
    }
    let problem = arkret_wire::Problem::new("failed_precondition", 409, "admission refused")
        .with_extension(
            "reason_code",
            serde_json::json!("governance_binding_mismatch"),
        );
    let rejection = MlsCreatorBootstrapRejection::from_problem(
        &original,
        problem.clone(),
        last_verified.clone(),
    )
    .unwrap();
    assert_eq!(rejection.reason_code(), "governance_binding_mismatch");
    assert_eq!(rejection.authority_problem(), Some(&problem));
    let irreversible = arkret_wire::Problem::new("failed_precondition", 409, "already accepted")
        .with_extension(
            "reason_code",
            serde_json::json!("mls_activation_irreversible"),
        );
    assert_eq!(
        MlsCreatorBootstrapRejection::terminal_problem_reason(&irreversible),
        Some("mls_activation_irreversible")
    );
    assert_eq!(
        MlsCreatorBootstrapRejection::terminal_problem_reason(&arkret_wire::Problem::new(
            "digest_mismatch",
            400,
            "Genesis public material digest mismatch"
        )),
        Some("digest_mismatch")
    );
    let rejection = MlsCreatorBootstrapRejection::new(
        &original,
        "capability_denied".into(),
        last_verified.clone(),
    )
    .unwrap();
    let mut record = original.clone();
    record.reject(rejection.clone()).unwrap();
    record.reject(rejection.clone()).unwrap();
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::Rejected
    );
    assert_eq!(record.rejection().unwrap().event_id(), signed.event_id());
    assert_eq!(
        record.rejection().unwrap().reason_code(),
        "capability_denied"
    );
    assert!(record.epoch_zero().is_none());
    assert!(record.queued_genesis().is_none());
    let mut contradiction_commit = create.covering_commit().clone();
    contradiction_commit.stream_position += 1;
    contradiction_commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
    contradiction_commit.event_ref = signed.event_id().clone();
    let contradiction = arkret_wire::CommittedEventFullView {
        event: signed.event().clone(),
        commit: contradiction_commit,
    };
    assert!(
        MlsCreatorBootstrapWinner::new(
            &record,
            contradiction.clone(),
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
    let known = MlsCreatorBootstrapKnownGenesis::authenticated_winner(
        &record,
        contradiction.clone(),
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
        serde_json::to_value(&record).unwrap(),
        vec![],
        MlsCreatorBootstrapInvariant::AcceptedResult,
        "definitely rejected original is independently proved accepted".into(),
        Some(known.clone()),
        create.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    assert_eq!(
        quarantined.quarantine_diagnostic().unwrap().last_state(),
        arkret_wire::MlsCreatorBootstrapState::Rejected
    );
    assert_eq!(
        quarantined
            .quarantine_diagnostic()
            .unwrap()
            .accepted_winner(),
        Some(&known)
    );
    assert!(quarantined.epoch_zero().is_none());
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert!(record.reopen_rejected(last_verified).is_err());
    assert_eq!(record, reopened);
    let mut changed = rejection.clone();
    changed.reason_code = "different_reason".into();
    assert!(record.reject(changed).is_err());
    assert_eq!(record, reopened);
    let mut fresh_create = create.clone();
    fresh_create
        .authority_root
        .native_bundle_mut()
        .current_assertion
        .nonce = arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
    let fresh = MlsCreatorBootstrapVerifiedAbsence::new(
        &intent,
        fresh_create.clone(),
        absence_snapshot(&fresh_create),
    )
    .unwrap();
    let mut incomplete = fresh.clone();
    incomplete.current_snapshot.visible_stream_heads.clear();
    assert!(record.reopen_rejected(incomplete).is_err());
    assert_eq!(record, reopened);
    record.reopen_rejected(fresh).unwrap();
    assert!(
        MlsCreatorBootstrapWinner::new(
            &record,
            contradiction.clone(),
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
    let known = MlsCreatorBootstrapKnownGenesis::authenticated_winner(
        &record,
        contradiction,
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
        serde_json::to_value(&record).unwrap(),
        vec![],
        MlsCreatorBootstrapInvariant::AcceptedResult,
        "closed original is independently proved accepted".into(),
        Some(known),
        create.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    assert_eq!(
        quarantined.quarantine_diagnostic().unwrap().last_state(),
        arkret_wire::MlsCreatorBootstrapState::RealmAccepted
    );
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::RealmAccepted
    );
    assert_eq!(record.intent(), &intent);
    assert_eq!(record.closed_attempts(), &[rejection]);
    assert!(
        record.closed_attempts()[0]
            .matches_epoch_zero_public_material(unit.group_info_bytes(), unit.ratchet_tree_bytes())
            .unwrap()
    );
    assert!(
        !record.closed_attempts()[0]
            .matches_epoch_zero_public_material(
                b"unrelated public bytes",
                unit.ratchet_tree_bytes()
            )
            .unwrap()
    );
    assert!(record.epoch_zero().is_none());
    assert!(record.queued_genesis().is_none());
    record
        .pin_governance(pinned_fixture(&intent, &fresh_create))
        .unwrap();
    record.persist_epoch_zero(unit).unwrap();
    let before = record.clone();
    assert!(record.queue_genesis(signed).is_err());
    assert_eq!(record, before);
    assert_eq!(record.closed_attempts().len(), 1);
}

#[test]
fn creator_distinct_winner_stops_the_original_attempt_without_adopting_its_private_unit() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    original
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    original.pin_governance(evidence).unwrap();
    original.persist_epoch_zero(unit.clone()).unwrap();
    original.queue_genesis(signed.clone()).unwrap();
    // A distinct structural winner, not an authenticated Station fixture.
    let mut foreign_unit = unit.clone();
    let mut event = unit.unsigned_genesis().event().clone();
    event.created_at += chrono::TimeDelta::milliseconds(1);
    event.payload.insert(
        "created_at".into(),
        serde_json::Value::String(arkret_canonical::format_timestamp_canonical(
            event.created_at,
        )),
    );
    foreign_unit.unsigned_genesis =
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(event, signed.digest_suite())
            .unwrap();
    let foreign = sign_epoch_zero_fixture(&intent, &foreign_unit);
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
    commit.event_ref = foreign.event_id().clone();
    let row = arkret_wire::CommittedEventFullView {
        event: foreign.event().clone(),
        commit,
    };
    let winner = MlsCreatorBootstrapWinner::new(
        &original,
        row.clone(),
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    // The accepted slot is scope-wide, not restricted to the loser's Actor.
    // Producer authentication and roster validation remain host obligations.
    let mut other_event = row.event.clone();
    other_event.actor_id = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    other_event.producer_proof = None;
    let mut other_signed =
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(other_event, signed.digest_suite())
            .unwrap();
    let digest = Hash::new(
        other_signed
            .event_digest_with_digest_suite(signed.digest_suite())
            .unwrap(),
    )
    .unwrap();
    other_signed.attach_proof(ProducerEventProof {
        kind: "detached_jws".into(),
        verification_method: DidUrl::new(format!("did:web:bob.example#{DEVICE}")).unwrap(),
        event_digest: digest.clone(),
        created_at: other_signed.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    let mut other_row = row.clone();
    other_row.event = other_signed.event().clone();
    other_row.commit.event_ref = other_signed.event_id().clone();
    let other_winner = MlsCreatorBootstrapWinner::new(
        &original,
        other_row,
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let mut other_terminal = original.clone();
    other_terminal.supersede(other_winner).unwrap();
    assert_eq!(other_terminal.intent(), &intent);
    let mut terminal = original.clone();
    terminal.supersede(winner.clone()).unwrap();
    terminal.supersede(winner.clone()).unwrap();
    assert_eq!(
        terminal.state(),
        arkret_wire::MlsCreatorBootstrapState::Superseded
    );
    assert_eq!(terminal.intent(), &intent);
    assert!(terminal.epoch_zero().is_none());
    assert!(terminal.queued_genesis().is_none());
    assert!(terminal.accepted_genesis().is_none());
    assert!(terminal.ready_receipt().is_none());
    assert!(terminal.persist_epoch_zero(unit.clone()).is_err());
    assert!(terminal.queue_genesis(signed.clone()).is_err());
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&terminal).unwrap()).unwrap();
    reopened.validate().unwrap();
    let saved_record = &reopened;
    if let MlsCreatorBootstrapRecord::Superseded {
        loser_genesis,
        loser_record,
        ..
    } = saved_record
    {
        assert_eq!(loser_record.as_ref(), &original);
        assert_eq!(loser_record.epoch_zero(), Some(&unit));
        assert_eq!(loser_genesis.as_ref().unwrap().0, *signed.event_id());
    } else {
        panic!("terminal state lost");
    }
    let mut different = winner.clone();
    different
        .authority_root
        .native_bundle_mut()
        .bundle_issued_at += chrono::TimeDelta::milliseconds(1);
    assert!(terminal.supersede(different).is_err());
    assert_eq!(terminal, reopened);
    let mut original_row = row.clone();
    original_row.event = signed.event().clone();
    original_row.commit.event_ref = signed.event_id().clone();
    assert!(
        MlsCreatorBootstrapWinner::new(
            &original,
            original_row.clone(),
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
    let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
        &intent,
        original.queued_genesis().unwrap(),
        original_row,
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    original.accept_genesis(accepted).unwrap();
    assert!(original.supersede(winner).is_err());
    let mut changed = row;
    changed.commit.event_ref = intent.scope_create_event_id().clone();
    assert!(
        MlsCreatorBootstrapWinner::new(
            &reopened,
            changed,
            create.authority_root().unwrap().clone()
        )
        .is_err()
    );
}

#[test]
fn creator_quarantine_retains_undecodable_recovery_material_without_an_active_exit() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    original
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    original.pin_governance(evidence).unwrap();
    original.persist_epoch_zero(unit).unwrap();
    original.queue_genesis(signed.clone()).unwrap();
    let mut raw = serde_json::to_value(&original).unwrap();
    raw["epoch_zero"]["encrypted_private_state"] = serde_json::json!({"damaged_bytes": [1, 2, 3]});
    assert!(serde_json::from_value::<MlsCreatorBootstrapRecord>(raw.clone()).is_err());
    // Opaque local queue corruption is retained, never accepted as sendable.
    let queues = vec![serde_json::json!({"undecodable_queue_bytes": [7, 8, 9]})];
    let mut quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
        raw.clone(),
        queues.clone(),
        MlsCreatorBootstrapInvariant::PrivateMaterial,
        "undecodable encrypted_private_state".into(),
        None,
        create.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    quarantined.validate().unwrap();
    let diagnostic = quarantined.quarantine_diagnostic().unwrap();
    let diagnostic_json = serde_json::to_value(diagnostic).unwrap();
    assert_eq!(
        diagnostic_json["detected_at"],
        arkret_canonical::format_timestamp_canonical(
            create.authority_root().unwrap().bundle_issued_at
        )
    );
    for timestamp in [
        "2026-09-01T00:00:00Z",
        "2026-09-01T00:00:00.000+00:00",
        "2026-09-01T00:00:00.000000Z",
    ] {
        let mut noncanonical = diagnostic_json.clone();
        noncanonical["detected_at"] = serde_json::json!(timestamp);
        assert!(
            serde_json::from_value::<MlsCreatorBootstrapQuarantine>(noncanonical).is_err(),
            "{timestamp}"
        );
    }
    assert_eq!(
        diagnostic.last_state(),
        arkret_wire::MlsCreatorBootstrapState::GenesisQueued
    );
    assert_eq!(diagnostic.event_id(), Some(signed.event_id()));
    assert_eq!(diagnostic.outbound_queue_item_id(), Some(signed.event_id()));
    assert_eq!(diagnostic.recovery_record(), &raw);
    assert_eq!(diagnostic.recovery_queue_items(), queues);
    assert!(quarantined.epoch_zero().is_none());
    assert!(quarantined.queued_genesis().is_none());
    assert!(quarantined.accepted_genesis().is_none());
    assert!(quarantined.ready_receipt().is_none());
    assert!(quarantined.queue_genesis(signed).is_err());
    assert!(
        quarantined
            .accept_realm(create.clone(), absence_snapshot(&create))
            .is_err()
    );
    let mut next_root = create.authority_root().unwrap().clone();
    next_root.current_assertion.nonce =
        arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
    let next_create = MlsCreatorBootstrapAcceptedCreate::new(
        &intent,
        create.accepted_event().clone(),
        create.covering_commit().clone(),
        create.digest_suite(),
        next_root,
    )
    .unwrap();
    let absence =
        MlsCreatorBootstrapVerifiedAbsence::new(&intent, next_create, absence_snapshot(&create))
            .unwrap();
    assert!(quarantined.reopen_rejected(absence).is_err());
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&quarantined).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened, quarantined);
    for field in ["reason_code", "event_id", "last_state"] {
        let mut bad = serde_json::to_value(&quarantined).unwrap();
        bad["diagnostic"][field] = match field {
            "last_state" => serde_json::json!("realm_accepted"),
            "event_id" => serde_json::json!(EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [91; 32]
            )),
            _ => serde_json::json!("cleared"),
        };
        let bad: MlsCreatorBootstrapRecord = serde_json::from_value(bad).unwrap();
        assert!(bad.validate().is_err(), "{field}");
    }
    for state in ["superseded", "quarantined", "unknown"] {
        let mut forbidden = raw.clone();
        forbidden["state"] = serde_json::json!(state);
        assert!(
            MlsCreatorBootstrapRecord::quarantine_authenticated_record(
                forbidden,
                vec![],
                MlsCreatorBootstrapInvariant::RecordBinding,
                "forbidden original state".into(),
                None,
                create.authority_root().unwrap().bundle_issued_at
            )
            .is_err()
        );
    }
    let mut untrusted = raw;
    untrusted.as_object_mut().unwrap().remove("intent");
    assert!(
        MlsCreatorBootstrapRecord::quarantine_authenticated_record(
            untrusted,
            vec![],
            MlsCreatorBootstrapInvariant::RecordBinding,
            "original record binding mismatch".into(),
            None,
            create.authority_root().unwrap().bundle_issued_at
        )
        .is_err()
    );
}

#[test]
fn creator_ready_and_rejected_failure_dispositions_come_from_the_registry() {
    use arkret_wire::{
        MlsCreatorBootstrapFailureDisposition as Disposition, MlsCreatorBootstrapState as State,
    };
    assert_eq!(State::ALL.len(), 11);
    for state in State::ALL {
        assert_eq!(
            state.failure_disposition(),
            if matches!(state, State::Superseded | State::Quarantined) {
                Disposition::Terminal
            } else {
                Disposition::Quarantined
            }
        );
    }
    assert!(State::Ready.allowed_exits().is_empty());
    assert!(
        !State::Rejected
            .allowed_exits()
            .contains(&State::Quarantined)
    );
    assert_eq!(State::Ready.failure_disposition(), Disposition::Quarantined);
    assert_eq!(
        State::Rejected.failure_disposition(),
        Disposition::Quarantined
    );
}

#[test]
fn creator_artifact_and_ready_receipt_bind_the_whole_original_winning_epoch() {
    let (intent, create) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &create);
    let unit = epoch_zero_fixture(&intent, &evidence);
    let signed = sign_epoch_zero_fixture(&intent, &unit);
    let queued = MlsCreatorBootstrapQueuedGenesis::new(&intent, &unit, signed.clone()).unwrap();
    let mut commit = create.covering_commit().clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
    commit.event_ref = signed.event_id().clone();
    let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
        &intent,
        &queued,
        arkret_wire::CommittedEventFullView {
            event: signed.event().clone(),
            commit,
        },
        create.authority_root().unwrap().clone(),
    )
    .unwrap();
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    record
        .accept_realm(create.clone(), absence_snapshot(&create))
        .unwrap();
    record.pin_governance(evidence).unwrap();
    record.persist_epoch_zero(unit.clone()).unwrap();
    record.queue_genesis(signed).unwrap();
    let payload = unit.payload().unwrap();
    let checks = MlsCreatorBootstrapArtifactChecks {
        effective_scope: intent.effective_scope().clone(),
        mls_group_id: intent.mls_group_id().clone(),
        epoch: 0,
        cipher_suite: payload.cipher_suite.to_string(),
        creator_leaf_authority: payload.creator_leaf_authority,
        group_info_bytes: unit.group_info_bytes().to_vec(),
        ratchet_tree_bytes: unit.ratchet_tree_bytes().to_vec(),
    };
    assert!(MlsCreatorBootstrapArtifacts::new(&record, checks.clone()).is_err());
    record.accept_genesis(accepted).unwrap();
    assert!(MlsCreatorBootstrapReadyReceipt::new(&record, 1).is_err());
    let artifacts = MlsCreatorBootstrapArtifacts::new(&record, checks.clone()).unwrap();
    for field in ["epoch", "scope", "suite", "leaf", "info", "tree"] {
        let mut bad = checks.clone();
        match field {
            "epoch" => bad.epoch = 1,
            "scope" => {
                bad.effective_scope = ScopeRef::Realm {
                    realm_id: arkret_wire::RealmId::from_event_id(intent.scope_create_event_id()),
                }
            }
            "suite" => bad.cipher_suite.push('x'),
            "leaf" => {
                bad.creator_leaf_authority.authorization_event_ref =
                    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32])
            }
            "info" => bad.group_info_bytes.push(0),
            _ => bad.ratchet_tree_bytes.clear(),
        }
        if field == "scope" {
            bad.effective_scope = ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [42; 32],
                )),
            };
        }
        assert!(
            MlsCreatorBootstrapArtifacts::new(&record, bad).is_err(),
            "{field}"
        );
    }
    record.converge_artifacts(artifacts.clone()).unwrap();
    record.converge_artifacts(artifacts.clone()).unwrap();
    assert!(MlsCreatorBootstrapReadyReceipt::new(&record, 0).is_err());
    let receipt = MlsCreatorBootstrapReadyReceipt::new(&record, 7).unwrap();
    record.publish_ready(receipt.clone()).unwrap();
    let frozen = record.clone();
    let known = MlsCreatorBootstrapKnownGenesis::Original {
        acceptance: Box::new(record.accepted_genesis().unwrap().clone()),
    };
    let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
        serde_json::to_value(&record).unwrap(),
        vec![],
        MlsCreatorBootstrapInvariant::PrivateMaterial,
        "restored private state disagrees with accepted public bytes".into(),
        Some(known.clone()),
        create.authority_root().unwrap().bundle_issued_at,
    )
    .unwrap();
    assert_eq!(
        quarantined.state(),
        arkret_wire::MlsCreatorBootstrapState::Quarantined
    );
    let diagnostic = quarantined.quarantine_diagnostic().unwrap();
    assert_eq!(
        diagnostic.last_state(),
        arkret_wire::MlsCreatorBootstrapState::Ready
    );
    assert_eq!(diagnostic.accepted_winner(), Some(&known));
    assert_eq!(
        diagnostic.recovery_record(),
        &serde_json::to_value(&record).unwrap()
    );
    assert!(quarantined.ready_receipt().is_none());
    assert!(quarantined.artifacts().is_none());
    assert_eq!(
        serde_json::from_value::<MlsCreatorBootstrapRecord>(
            serde_json::to_value(&quarantined).unwrap()
        )
        .unwrap(),
        quarantined
    );
    record.publish_ready(receipt.clone()).unwrap();
    let mut changed = receipt;
    changed.ready_commit_position += 1;
    assert!(record.publish_ready(changed).is_err());
    assert_eq!(record, frozen);
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert_eq!(
        reopened.state(),
        arkret_wire::MlsCreatorBootstrapState::Ready
    );
    assert_eq!(reopened.epoch_zero(), Some(&unit));
    let mut bad = artifacts;
    bad.private_state_binding = Hash::new(arkret_canonical::canonical::digest(
        arkret_canonical::DigestSuite::Sha256,
        b"different",
    ))
    .unwrap();
    assert!(record.converge_artifacts(bad).is_err());
    let mut changed = serde_json::to_value(&reopened).unwrap();
    changed["artifacts"]["consistency_checks"]["epoch"] = serde_json::json!(1);
    let changed: MlsCreatorBootstrapRecord = serde_json::from_value(changed).unwrap();
    assert!(changed.validate().is_err());
}

#[test]
fn creator_epoch_zero_rejects_public_refs_unsigned_core_leaf_and_private_omissions() {
    let (intent, accepted) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &accepted);
    let original = epoch_zero_fixture(&intent, &evidence);
    let mut bad = vec![];
    let mut unit = original.clone();
    unit.encrypted_private_state.clear();
    bad.push(unit);
    let mut unit = original.clone();
    unit.group_info_bytes.push(0);
    bad.push(unit);
    let mut unit = original.clone();
    unit.ratchet_tree_bytes.clear();
    bad.push(unit);
    let mut unit = original.clone();
    unit.unsigned_genesis = sign_epoch_zero_fixture(&intent, &unit);
    bad.push(unit);
    for change in ["time", "leaf", "scope"] {
        let mut event = original.unsigned_genesis.event().clone();
        match change {
            "time" => event.created_at += chrono::TimeDelta::milliseconds(1),
            "leaf" => {
                event.payload.get_mut("creator_leaf_authority").unwrap()["endpoint"]["device_id"] =
                    json!("ak:device:0198ff00-0000-7000-8000-000000000002");
            }
            _ => event.scope_ref = fixture_intent(true).effective_scope().clone(),
        }
        let mut unit = original.clone();
        unit.unsigned_genesis = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        bad.push(unit);
    }
    for invalid in bad {
        assert!(invalid.validate_binding(&intent, &evidence).is_err());
    }
}

#[test]
fn creator_pin_requires_acceptance_and_retains_the_exact_immutable_evidence() {
    let (intent, accepted) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &accepted);
    let mut record = MlsCreatorBootstrapRecord::new(intent).unwrap();
    let initial = record.clone();
    assert!(record.pin_governance(evidence.clone()).is_err());
    assert_eq!(record, initial);
    record
        .accept_realm(accepted.clone(), absence_snapshot(&accepted))
        .unwrap();
    record.pin_governance(evidence.clone()).unwrap();
    assert_eq!(
        record.state(),
        arkret_wire::MlsCreatorBootstrapState::GovernanceResultPinned
    );
    let reopened: MlsCreatorBootstrapRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened, record);
    record.pin_governance(evidence.clone()).unwrap();
    let mut changed = evidence;
    changed.device_authority_mut().verified_at += chrono::TimeDelta::milliseconds(1);
    assert!(record.pin_governance(changed).is_err());
    assert_eq!(record, reopened);
}

#[test]
fn creator_pin_rejects_wrong_device_station_generation_and_expired_authority() {
    let (intent, accepted) = accepted_create(false);
    let evidence = pinned_fixture(&intent, &accepted);
    let mut bad = Vec::new();
    let mut changed = evidence.clone();
    changed.device_authority_mut().account_id.station_id =
        DidCoreId::new("ak:did_core:web:other.example").unwrap();
    bad.push(changed);
    let mut changed = evidence.clone();
    changed.device_authority_mut().device_id =
        DeviceId::new("ak:device:0198ff00-0000-7000-8000-000000000002").unwrap();
    bad.push(changed);
    let mut changed = evidence.clone();
    changed
        .device_authority_mut()
        .generation
        .current_device_generation_ref += 1;
    bad.push(changed);
    let mut changed = evidence.clone();
    changed.device_authority_mut().verified_at =
        changed.device_authority_mut().projection.expires_at;
    bad.push(changed);
    let mut changed = evidence.clone();
    changed
        .device_authority_mut()
        .projection
        .authorization_window
        .expires_at = Some(changed.device_authority_mut().verified_at);
    bad.push(changed);
    let mut changed = evidence.clone();
    changed.canonical_proposal_bytes.push(0);
    bad.push(changed);
    let mut changed = evidence.clone();
    changed
        .accepted_create
        .authority_root
        .native_bundle_mut()
        .current_assertion
        .expires_at = changed.device_authority_mut().verified_at;
    bad.push(changed);
    let mut changed = evidence.clone();
    changed.genesis_absence.visible_stream_heads.clear();
    bad.push(changed);
    let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
    record
        .accept_realm(accepted.clone(), absence_snapshot(&accepted))
        .unwrap();
    let original = record.clone();
    for invalid in bad {
        assert!(record.pin_governance(invalid).is_err());
        assert_eq!(record, original);
    }
    let mut missing = device_query_fixture(&intent);
    missing.device_keys.clear();
    assert!(
        MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
            &intent,
            &missing,
            evidence.creator_authority.verified_at()
        )
        .is_err()
    );
}

#[test]
fn creator_record_acceptance_roundtrips_without_replacing_its_cut() {
    let (intent, accepted) = accepted_create(false);
    let snapshot = absence_snapshot(&accepted);
    let mut record = MlsCreatorBootstrapRecord::new(intent).unwrap();
    record
        .accept_realm(accepted.clone(), snapshot.clone())
        .unwrap();
    record
        .accept_realm(accepted.clone(), snapshot.clone())
        .unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    let restored: MlsCreatorBootstrapRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored, record);
    restored.validate().unwrap();
    let mut changed = snapshot;
    changed.created_at += chrono::TimeDelta::seconds(1);
    assert!(record.accept_realm(accepted, changed).is_err());
    assert_eq!(record, restored);
}

#[test]
fn creator_record_unknown_or_incomplete_acceptance_keeps_intent_unchanged() {
    let (intent, accepted) = accepted_create(false);
    let snapshot = absence_snapshot(&accepted);
    let original = MlsCreatorBootstrapRecord::new(intent).unwrap();
    let mut missing = snapshot.clone();
    missing.visible_stream_heads.clear();
    let mut stale = snapshot.clone();
    stale.governance_generation += 1;
    let mut duplicate = snapshot;
    duplicate
        .visible_stream_heads
        .push(duplicate.visible_stream_heads[0].clone());
    for invalid in [missing, stale, duplicate] {
        let mut record = original.clone();
        assert!(record.accept_realm(accepted.clone(), invalid).is_err());
        assert_eq!(record, original);
    }
    let mut changed = serde_json::to_value(&original).unwrap();
    changed["state"] = serde_json::json!("ready");
    assert!(serde_json::from_value::<MlsCreatorBootstrapRecord>(changed).is_err());
}

#[test]
fn creator_circle_absence_cannot_borrow_its_parent_realm_head() {
    let (intent, accepted) = accepted_create(true);
    let parent_only = absence_snapshot(&accepted);
    assert!(validate_creator_genesis_absence_snapshot(&intent, &accepted, &parent_only).is_err());
}

#[test]
fn accepted_creation_keeps_its_exact_signed_event_and_parent_authorization_stream() {
    for circle in [false, true] {
        let (intent, accepted) = accepted_create(circle);
        let bytes = arkret_canonical::canonical_json_bytes(&accepted).unwrap();
        let restored: MlsCreatorBootstrapAcceptedCreate = serde_json::from_slice(&bytes).unwrap();
        restored.validate_binding(&intent).unwrap();
        assert_eq!(accepted, restored);
        if circle {
            assert_ne!(
                restored.covering_commit.stream_ref,
                arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None).unwrap()
            );
        }
    }
}

#[test]
fn accepted_creation_cannot_rebind_proof_commit_scope_or_digest_suite() {
    let (intent, accepted) = accepted_create(true);
    assert!(
        MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            accepted.accepted_event.clone(),
            accepted.covering_commit.clone(),
            arkret_canonical::DigestSuite::Blake3,
            accepted.authority_root.clone()
        )
        .is_err()
    );
    let mut altered = accepted.clone();
    altered
        .accepted_event
        .producer_proof
        .as_mut()
        .unwrap()
        .jws
        .push('x');
    assert!(altered.validate_binding(&intent).is_err());
    altered = accepted.clone();
    altered.covering_commit.stream_ref =
        arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None).unwrap();
    assert!(altered.validate_binding(&intent).is_err());
    altered = accepted.clone();
    altered.digest_suite = arkret_canonical::DigestSuite::Blake3;
    assert!(altered.validate_binding(&intent).is_err());
    altered = accepted.clone();
    altered.covering_commit.event_ref = fixture_intent(false).scope_create_event_id;
    assert!(altered.validate_binding(&intent).is_err());
    altered = accepted;
    altered.covering_commit.governance_generation = 1;
    assert!(altered.validate_binding(&intent).is_err());
}
