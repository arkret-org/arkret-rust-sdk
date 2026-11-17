use arkret_models_crypto::{
    ContentRecoveryScopeCleanupAuthorization, ContentRecoveryScopeCleanupAuthorizationUnsigned,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_wire::ServiceKind;
use rand_core::SeedableRng as _;

use super::*;

const SEED: [u8; 32] = [173; 32];

fn original_source() -> ContentRecoveryScopeCleanupSource {
    original_source_at(None)
}

pub(super) fn original_source_at(at: Option<DateTime<Utc>>) -> ContentRecoveryScopeCleanupSource {
    // The protocol fixture supplies only typed coordinates. Native episode or
    // inventory authority is not claimed by this pure cryptographic test.
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let mut attestation: ContentRecoveryScopeCleanupAuthorization =
        serde_json::from_value(fixture["scope_retirement"]["authorization"].clone()).unwrap();
    if let Some(at) = at {
        attestation.attested_at = at;
        attestation.expires_at = at + chrono::Duration::seconds(120);
    }
    let at = attestation.attested_at;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([174; 32]);
    let key = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://cleanup-origin.example/").unwrap(),
    )
    .unwrap();
    let inception =
        arkret_signatures::webvh::prepare_service_registration_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &url::Url::parse("https://identity.cleanup-origin.example/")
                    .unwrap(),
                registration_key: &key,
                also_known_as: &[],
                version_created_at: at - chrono::Duration::seconds(60),
                did_key_fragment: Some("cleanup"),
            },
            &SEED,
        )
        .unwrap();
    let did = arkret_wire::Did::new(inception.did.clone()).unwrap();
    let owner = arkret_wire::project_did_to_core_id(&did).unwrap();
    let account = attestation.replacement.actor_id.as_account_id().unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        account.principal_id.clone(),
        owner.clone(),
    ));
    attestation.replacement.actor_id = actor.clone();
    for leaf in &mut attestation.inventory_entry.old_leaves {
        leaf.endpoint.actor_id = actor.clone();
    }
    attestation.verification_method = DidUrl::new(inception.did_key_id.clone()).unwrap();
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &SEED,
        attestation.verification_method.as_str(),
        &attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    let origin_resolution = crate::build_authenticated_webvh_service_resolution(
        owner,
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        at,
    )
    .unwrap();
    ContentRecoveryScopeCleanupSource {
        attestation,
        origin_resolution,
    }
}

fn verify(source: &ContentRecoveryScopeCleanupSource) -> Result<()> {
    verify_content_recovery_scope_cleanup_source(
        source,
        &source.origin_resolution.service_id,
        &source.attestation.destination_service_id,
        source.attestation.attested_at,
    )
}

#[test]
fn original_station_history_and_scope_source_signature_survive_cold_wire_roundtrip() {
    let source = original_source();
    verify(&source).unwrap();
    let bytes = arkret_canonical::canonical_json_bytes(&source).unwrap();
    let reopened: ContentRecoveryScopeCleanupSource = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&reopened).unwrap(),
        bytes
    );
    verify(&reopened).unwrap();
    let mut optional_algorithm = reopened;
    optional_algorithm.attestation.signature.signature_algorithm = None;
    verify(&optional_algorithm).unwrap();
}

#[test]
fn current_transport_window_history_and_original_signature_are_independent_gates() {
    let source = original_source();
    let now = source.attestation.attested_at;
    let stranger = DidCoreId::new("ak:did_core:web:stranger-cleanup.example").unwrap();
    assert!(
        verify_content_recovery_scope_cleanup_source(
            &source,
            &stranger,
            &source.attestation.destination_service_id,
            now
        )
        .is_err()
    );
    assert!(
        verify_content_recovery_scope_cleanup_source(
            &source,
            &source.origin_resolution.service_id,
            &stranger,
            now
        )
        .is_err()
    );
    assert!(
        verify_content_recovery_scope_cleanup_source(
            &source,
            &source.origin_resolution.service_id,
            &source.attestation.destination_service_id,
            source.attestation.expires_at
        )
        .is_err()
    );
    assert!(
        verify_content_recovery_scope_cleanup_source(
            &source,
            &source.origin_resolution.service_id,
            &source.attestation.destination_service_id,
            now - chrono::Duration::milliseconds(1)
        )
        .is_err()
    );
    let mut wrong = source.clone();
    wrong.attestation.inventory_digest = Hash::new(format!("sha256:{}", "f1".repeat(32))).unwrap();
    assert!(verify(&wrong).is_err());
    let mut wrong = source.clone();
    wrong.origin_resolution.service_kind = "push_gateway".into();
    assert!(verify(&wrong).is_err());
    let mut wrong = source;
    wrong
        .origin_resolution
        .normalized_did_document
        .raw_properties
        .insert("assertionMethod".into(), serde_json::json!([]));
    assert!(verify(&wrong).is_err());
}

#[test]
fn one_entry_validator_is_used_by_the_signed_cleanup_source() {
    let mut source = original_source();
    // The canonical fixture intentionally has no old leaves. This model-only
    // validator case supplies one explicit leaf; it proves no native history.
    let mut endpoint = source.attestation.replacement.clone();
    endpoint.signature_key_base64url = arkret_canonical::base64url_encode(
        ed25519_dalek::SigningKey::from_bytes(&[198; 32])
            .verifying_key()
            .to_bytes(),
    );
    source.attestation.inventory_entry.old_leaves =
        vec![arkret_models_crypto::ContentRecoveryOldLeaf {
            leaf_index: 0,
            endpoint,
        }];
    source.attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &SEED,
        source.attestation.verification_method.as_str(),
        &source.attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    verify(&source).unwrap();
    for mode in [0, 1, 2] {
        let mut wrong = source.clone();
        if mode == 0 {
            let duplicate = wrong.attestation.inventory_entry.old_leaves[0].clone();
            wrong.attestation.inventory_entry.old_leaves.push(duplicate);
        } else if mode == 1 {
            wrong.attestation.inventory_entry.old_leaves[0]
                .endpoint
                .actor_id =
                arkret_wire::ActorId::service(source.origin_resolution.service_id.clone());
        } else {
            wrong.attestation.inventory_entry.old_leaves[0]
                .endpoint
                .signature_key_base64url = wrong
                .attestation
                .replacement
                .signature_key_base64url
                .clone();
        }
        wrong.attestation.signature =
            arkret_signatures::keypackages::sign_keypackage_signing_input(
                &SEED,
                wrong.attestation.verification_method.as_str(),
                &wrong.attestation.signing_bytes().unwrap(),
            )
            .unwrap();
        assert!(
            verify(&wrong).is_err(),
            "a real signature cannot legalize an invalid frozen entry"
        );
    }
}

#[test]
fn stable_intent_projection_before_signing_is_the_original_instance_formula() {
    let source = original_source();
    let a = &source.attestation;
    let digest = ContentRecoveryScopeCleanupAuthorization::intent_digest_for(
        &a.replacement,
        &a.inventory_digest,
        &a.inventory_entry,
        &a.nonce_base64url,
    )
    .unwrap();
    assert_eq!(digest, a.intent_digest().unwrap());
    let mut renewed = a.clone();
    renewed.delivery_challenge_base64url = arkret_canonical::base64url_encode([193; 32]);
    renewed.destination_service_id =
        DidCoreId::new("ak:did_core:web:renewed-cleanup.example").unwrap();
    renewed.attested_at += chrono::Duration::milliseconds(1);
    renewed.expires_at += chrono::Duration::milliseconds(1);
    assert_eq!(renewed.intent_digest().unwrap(), digest);
    renewed.nonce_base64url = arkret_canonical::base64url_encode([194; 32]);
    assert_ne!(renewed.intent_digest().unwrap(), digest);
    // Different digest is not permission to create a second native E intent;
    // first-nonce reservation and conflict remain the owning ledger's duty.
}

#[test]
fn unsigned_source_projection_is_the_original_ten_field_signing_preimage() {
    let original = original_source();
    let source = &original.attestation;
    // This independent expression is the original owner before extraction.
    let unsigned = arkret_canonical::unsigned_value(source, &["signature"]).unwrap();
    let mut expected = b"ak.mls.recovery_scope_cleanup_authorization.v1\n".to_vec();
    expected.extend(arkret_canonical::canonical_json_bytes(&unsigned).unwrap());
    let before_signature = ContentRecoveryScopeCleanupAuthorization::signing_bytes_for(
        &ContentRecoveryScopeCleanupAuthorizationUnsigned {
            replacement: &source.replacement,
            inventory_digest: &source.inventory_digest,
            inventory_entry: &source.inventory_entry,
            destination_service_id: &source.destination_service_id,
            predecessor_authorization_event_refs: &source.predecessor_authorization_event_refs,
            nonce_base64url: &source.nonce_base64url,
            delivery_challenge_base64url: &source.delivery_challenge_base64url,
            verification_method: &source.verification_method,
            attested_at: source.attested_at,
            expires_at: source.expires_at,
        },
    )
    .unwrap();
    assert_eq!(before_signature, expected);
    assert_eq!(source.signing_bytes().unwrap(), expected);
    let signed = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &SEED,
        source.verification_method.as_str(),
        &before_signature,
    )
    .unwrap();
    assert_eq!(signed, source.signature);
    verify(&original).unwrap();

    let mut changed = source.clone();
    changed.attested_at += chrono::Duration::milliseconds(1);
    assert_ne!(changed.signing_bytes().unwrap(), expected);
    changed = source.clone();
    changed.expires_at -= chrono::Duration::milliseconds(1);
    assert_ne!(changed.signing_bytes().unwrap(), expected);
    changed = source.clone();
    changed.delivery_challenge_base64url = arkret_canonical::base64url_encode([191; 32]);
    assert_ne!(changed.signing_bytes().unwrap(), expected);
    // I still excludes the current delivery challenge and renewal windows.
    assert_eq!(
        changed.intent_digest().unwrap(),
        source.intent_digest().unwrap()
    );
}

// These are pure source/producer-byte and real-signature tests. The formal RFC
// byte fixture is not reclassified as native MLS admission or a Prepared H unit.
fn independently_signed_recovery_source() -> (
    arkret_models_collaboration::content_history::ContentRecoverySource,
    arkret_wire::Event,
    arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    DateTime<Utc>,
) {
    use arkret_models_collaboration::authority_commit::{
        AccountDeviceHistoricalSignerFact, HistoricalProducerSignerFact,
    };
    use arkret_models_crypto::{
        ContentRecoveryBinding, ContentRecoverySourceAttestation, MlsCommitEnvelope,
        MlsCommitPayload, MlsGovernanceBindingPayload,
    };
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    use arkret_wire::{
        ActorId, AuthoredEvent, CommitStreamRef, CommittedEventRef, CurrentRevision, Did, EventId,
        RealmCommitId, RealmId,
    };
    let h = original_source();
    let a = &h.attestation;
    let principal = Did::new("did:web:recovery-author.example").unwrap();
    let actor = ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&principal).unwrap(),
        h.origin_resolution.service_id.clone(),
    ));
    let mut replacement = a.replacement.clone();
    replacement.actor_id = actor.clone();
    let arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } = &replacement.endpoint
    else {
        unreachable!()
    };
    let device_id = device_id.clone();
    let device_method = DidUrl::new(format!("{principal}#{device_id}")).unwrap();
    let device_seed = [197; 32];
    let device_key = ed25519_dalek::SigningKey::from_bytes(&device_seed);
    let binding = ContentRecoveryBinding {
        replacement: replacement.clone(),
        authorization_event_ref: replacement.authorization_event_ref.clone(),
        base_group_state_ref: a.inventory_entry.base_group_state_ref.clone(),
        expected_epoch: a.inventory_entry.epoch,
        inventory_digest: a.inventory_digest.clone(),
    };
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let hex = fixture["public_recovery_wire"]["public_message_hex"]
        .as_str()
        .unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let scope = a.inventory_entry.effective_scope.clone();
    let realm = scope.realm_id().clone();
    let governance = MlsGovernanceBindingPayload::realm(
        realm,
        Some(binding.base_group_state_ref.clone()),
        binding.expected_epoch,
        binding.expected_epoch + 1,
        0,
    )
    .unwrap();
    let envelope = MlsCommitEnvelope {
        group_id: scope.canonical_mls_group_id().unwrap(),
        epoch: binding.expected_epoch + 1,
        commit: arkret_canonical::base64url_encode(&bytes),
        commit_digest: Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap(),
        ratchet_tree: None,
    };
    let material_ref = arkret_wire::BlobRef::new(format!(
        "ak:blob:{}",
        arkret_canonical::sha256_digest(b"pure-public-material-reference")
    ))
    .unwrap();
    let payload = MlsCommitPayload::new(
        binding.base_group_state_ref.clone(),
        0,
        &envelope,
        governance,
        material_ref.clone(),
        material_ref,
    )
    .unwrap()
    .with_recovery_binding(binding)
    .unwrap();
    let raw = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.mls.commit",
        scope.clone(),
        actor.clone(),
        serde_json::to_value(payload).unwrap(),
        a.attested_at,
    )
    .unwrap();
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(raw, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(device_seed, device_method.to_string()),
        SignEventOptions::new().with_created_at(a.attested_at),
    )
    .unwrap();
    let event = authored.into_event();
    let committed_at = a.attested_at + chrono::Duration::seconds(1);
    let mut source = arkret_models_collaboration::content_history::ContentRecoverySource {
        attestation: ContentRecoverySourceAttestation {
            event_ref: event.event_id.clone(),
            replacement: replacement.clone(),
            effective_scope: scope,
            base_group_state_ref: a.inventory_entry.base_group_state_ref.clone(),
            previous_epoch: a.inventory_entry.epoch,
            inventory_digest: a.inventory_digest.clone(),
            verification_method: a.verification_method.clone(),
            attested_at: a.attested_at,
            expires_at: a.expires_at,
            signature: a.signature.clone(),
        },
        origin_resolution: h.origin_resolution,
    };
    source.attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &SEED,
        source.attestation.verification_method.as_str(),
        &source.signing_payload_bytes().unwrap(),
    )
    .unwrap();
    let authorization = CommittedEventRef {
        event_id: replacement.authorization_event_ref.clone(),
        commit_id: RealmCommitId::from_digest([201; 32]),
        stream_ref: CommitStreamRef::Realm {
            realm_id: RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [202; 32],
            )),
        },
        stream_position: 2,
    };
    let fact = HistoricalProducerSignerFact::AccountDevice(AccountDeviceHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor,
        device_id,
        verification_method: device_method,
        key: arkret_models_identity::ResolvedSignerKey {
            public_key_base64url: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(device_key.verifying_key().to_bytes()),
            )
            .unwrap(),
            authorization_ref: authorization.clone(),
            revision: CurrentRevision {
                commit_id: authorization.commit_id,
                stream_position: 2,
            },
            governance_generation: 0,
        },
        accepted_at: committed_at,
    });
    (source, event, fact, committed_at)
}

fn verify_independent_recovery_source_signature(
    source: &arkret_models_collaboration::content_history::ContentRecoverySource,
) -> Result<()> {
    let a = &source.attestation;
    verify_signature(
        &source.origin_resolution,
        &a.replacement.actor_id.as_account_id().unwrap().station_id,
        a.attested_at,
        &a.verification_method,
        &a.signature,
        &source.signing_payload_bytes().unwrap(),
    )?;
    Ok(())
}

#[test]
fn origin_station_source_and_original_device_use_independent_methods_and_keys() {
    let (source, event, fact, committed_at) = independently_signed_recovery_source();
    let account = source
        .attestation
        .replacement
        .actor_id
        .as_account_id()
        .unwrap();
    assert_ne!(account.principal_id, account.station_id);
    assert_ne!(
        source.attestation.verification_method,
        event.producer_proof.as_ref().unwrap().verification_method
    );
    let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::AccountDevice(
        device,
    ) = &fact
    else {
        unreachable!()
    };
    assert_ne!(
        device.key.public_key_base64url.as_str(),
        arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&SEED)
                .verifying_key()
                .to_bytes()
        )
    );
    assert_ne!(
        device.key.public_key_base64url.as_str(),
        source.attestation.replacement.signature_key_base64url
    );
    source.validate_submission_binding(&event).unwrap();
    source
        .validate_original_binding(&event, committed_at, &fact)
        .unwrap();
    verify_independent_recovery_source_signature(&source).unwrap();
    crate::account_device_signer_evidence::verify_historical_producer_event_signature(
        &event,
        &fact,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
}

#[test]
fn neither_native_producer_nor_origin_service_can_substitute_its_key_for_the_other() {
    let (mut source, event, mut fact, _) = independently_signed_recovery_source();
    source.attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[197; 32],
        source.attestation.verification_method.as_str(),
        &source.signing_payload_bytes().unwrap(),
    )
    .unwrap();
    assert!(verify_independent_recovery_source_signature(&source).is_err());
    let (source, ..) = independently_signed_recovery_source();
    verify_independent_recovery_source_signature(&source).unwrap();
    let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::AccountDevice(
        device,
    ) = &mut fact
    else {
        unreachable!()
    };
    device.key.public_key_base64url =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&SEED)
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap();
    assert!(
        crate::account_device_signer_evidence::verify_historical_producer_event_signature(
            &event,
            &fact,
            arkret_canonical::DigestSuite::Sha256
        )
        .is_err()
    );
}

#[test]
fn independent_methods_preserve_original_fact_endpoint_authorization_time_and_presence_gates() {
    let (source, event, fact, committed_at) = independently_signed_recovery_source();
    for mode in 0..5 {
        let mut changed = fact.clone();
        let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::AccountDevice(device)=&mut changed else{unreachable!()};
        match mode {
            0 => device.verification_method = source.attestation.verification_method.clone(),
            1 => {
                device.key.authorization_ref.event_id =
                    source.attestation.base_group_state_ref.clone()
            }
            2 => {
                device.device_id =
                    arkret_wire::DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000099")
                        .unwrap()
            }
            3 => device.accepted_at += chrono::Duration::milliseconds(1),
            _ => {
                device.actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    source.origin_resolution.service_id.clone(),
                    source.origin_resolution.service_id.clone(),
                ))
            }
        }
        assert!(
            source
                .validate_original_binding(&event, committed_at, &changed)
                .is_err()
        );
    }
    assert!(
        source
            .validate_original_binding(&event, source.attestation.expires_at, &fact)
            .is_err()
    );
    let mut missing = event;
    missing.producer_proof = None;
    assert!(source.validate_submission_binding(&missing).is_err());
}

#[test]
fn origin_station_source_and_original_agent_runtime_also_keep_independent_methods() {
    use arkret_models_collaboration::authority_commit::{
        AgentRuntimeHistoricalSignerFact, AgentRuntimeHistoricalSignerFactKind,
        HistoricalProducerSignerFact,
    };
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    let (mut source, mut event, _, committed_at) = independently_signed_recovery_source();
    let principal = arkret_wire::Did::new("did:web:recovery-runtime.example").unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&principal).unwrap(),
        source.origin_resolution.service_id.clone(),
    ));
    let vm = DidUrl::new(format!("{principal}#runtime")).unwrap();
    let seed = [198; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    source.attestation.replacement.actor_id = actor.clone();
    source.attestation.replacement.endpoint =
        arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: vm.clone(),
        };
    let mut binding: arkret_models_crypto::ContentRecoveryBinding =
        serde_json::from_value(event.payload["recovery_binding"].clone()).unwrap();
    binding.replacement = source.attestation.replacement.clone();
    event.payload.insert(
        "recovery_binding".into(),
        serde_json::to_value(binding).unwrap(),
    );
    event.actor_id = actor.clone();
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(seed, vm.to_string()),
        SignEventOptions::new().with_created_at(source.attestation.attested_at),
    )
    .unwrap();
    let event = authored.into_event();
    source.attestation.event_ref = event.event_id.clone();
    source.attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &SEED,
        source.attestation.verification_method.as_str(),
        &source.signing_payload_bytes().unwrap(),
    )
    .unwrap();
    let fact = HistoricalProducerSignerFact::AgentRuntime(AgentRuntimeHistoricalSignerFact {
        kind: AgentRuntimeHistoricalSignerFactKind::AgentRuntime,
        event_ref: event.event_id.clone(),
        actor_id: actor,
        verification_method: vm.clone(),
        public_key_base64url: arkret_canonical::base64url_encode(key.verifying_key().to_bytes()),
        authorization_event_ref: source
            .attestation
            .replacement
            .authorization_event_ref
            .clone(),
        accepted_at: committed_at,
    });
    assert_ne!(vm, source.attestation.verification_method);
    assert!(event.account_device_producer().unwrap().is_none());
    source.validate_submission_binding(&event).unwrap();
    source
        .validate_original_binding(&event, committed_at, &fact)
        .unwrap();
    verify_independent_recovery_source_signature(&source).unwrap();
    crate::account_device_signer_evidence::verify_historical_producer_event_signature(
        &event,
        &fact,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let mut wrong = fact;
    let HistoricalProducerSignerFact::AgentRuntime(changed) = &mut wrong else {
        unreachable!()
    };
    changed.verification_method = source.attestation.verification_method.clone();
    assert!(
        source
            .validate_original_binding(&event, committed_at, &wrong)
            .is_err()
    );
}
