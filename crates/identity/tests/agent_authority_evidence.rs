use arkret_canonical::DigestSuite;
use arkret_identity::build_authenticated_webvh_service_resolution;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestation, DeviceProjectionAttestationCore,
    DeviceStatus,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_signatures::{
    Ed25519DetachedJwsSigner, SignEventOptions, sign_ed25519_detached_jws, sign_event,
};
use arkret_wire::{
    AccountId, ActorId, AuthoredEvent, DeviceId, Did, DidCoreId, DidKey, DidUrl, ErrorCode, Event,
    EventId, NonEmptyString, ProtocolSignature, RealmId, ScopeRef, ServiceKind,
};
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
const PRINCIPAL_DID: &str = "did:webvh:z6mkfixture:alice.example";
const DEVICE_SEED: [u8; 32] = [7; 32];

/// One registered Station together with the key that signs its attestations.
struct Station {
    service_id: DidCoreId,
    method: DidUrl,
    signing_key: SigningKey,
    service_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    registered_at: DateTime<Utc>,
}

fn station(seed: u8, host: &str) -> Station {
    let registered_at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new(format!("https://{host}/")).unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_time: registered_at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let service_resolution = build_authenticated_webvh_service_resolution(
        service_id.clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        registered_at + Duration::seconds(10),
    )
    .unwrap();
    Station {
        service_id,
        method: DidUrl::new(inception.did_key_id.clone()).unwrap(),
        signing_key: SigningKey::from_bytes(&inception.did_key_seed),
        service_resolution,
        registered_at,
    }
}

fn device_key_did() -> DidKey {
    let public = SigningKey::from_bytes(&DEVICE_SEED)
        .verifying_key()
        .to_bytes();
    DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
    ))
    .unwrap()
}

fn account(station: &Station) -> AccountId {
    AccountId::new(
        arkret_wire::project_did_to_core_id(&Did::new(PRINCIPAL_DID).unwrap()).unwrap(),
        station.service_id.clone(),
    )
}

fn core(station: &Station) -> DeviceProjectionAttestationCore {
    let attested_at = station.registered_at + Duration::seconds(10);
    DeviceProjectionAttestationCore {
        account_id: account(station),
        device_id: DeviceId::new(DEVICE).unwrap(),
        device_signing_key_did: device_key_did(),
        hpke_key: NonEmptyString::new("hpke-1").unwrap(),
        device_authorize_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .unwrap(),
        authorized_generation_ref: 1,
        device_status: DeviceStatus::Active,
        authorization_window: DeviceAuthorizationWindow {
            not_before: station.registered_at,
            expires_at: None,
        },
        attested_at,
        expires_at: attested_at + Duration::minutes(5),
    }
}

/// Sign any attestation core with the Station key, bypassing the producer-side
/// guards so a verifier can be fed what a compromised or buggy origin emits.
fn sign_raw(
    core: DeviceProjectionAttestationCore,
    method: &DidUrl,
    key: &SigningKey,
) -> DeviceProjectionAttestation {
    let mut attestation = DeviceProjectionAttestation {
        proof: ProtocolSignature {
            verification_method: method.clone(),
            created_at: core.attested_at,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        },
        attestation: core,
    };
    attestation.proof.jws =
        sign_ed25519_detached_jws(key, &attestation.proof_signing_bytes().unwrap()).unwrap();
    attestation
}

fn evidence_with(
    station: &Station,
    edit: impl FnOnce(&mut DeviceProjectionAttestationCore),
) -> AccountDeviceSignerEvidence {
    let mut core = core(station);
    edit(&mut core);
    AccountDeviceSignerEvidence {
        device_projection_attestation: sign_raw(core, &station.method, &station.signing_key),
        service_resolution: station.service_resolution.clone(),
    }
}

use arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer;
use arkret_models_identity::agent_authority_evidence::*;
use arkret_models_identity::agent_signer_evidence::*;
use arkret_models_identity::{AuthenticatedSignerKind, AuthenticatedSignerResolutionEvidence};
use arkret_wire::{
    CurrentRevision, CurrentSelector, DetachedSignatureContext, RealmCommit, RealmCommitId,
    TypedCurrentResult,
};

fn sign(event: Event, method: &str, seed: [u8; 32]) -> Event {
    let at = event.created_at;
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(seed, method),
        SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    event
        .verify_producer_proof_self_consistency(DigestSuite::Sha256)
        .unwrap();
    event
}

fn commit(
    event: &Event,
    genesis: &Event,
    previous: Option<&RealmCommit>,
    station: &Station,
) -> RealmCommit {
    let at = event.created_at + Duration::seconds(1);
    let mut commit: RealmCommit = serde_json::from_value(json!({
        "commit_id": RealmCommitId::from_digest([0;32]), "realm_id": event.realm_id,
        "stream_ref": {"kind":"realm", "realm_id":event.realm_id},
        "stream_position":previous.map_or(0,|p|p.stream_position+1),
        "previous_commit_ref":previous.map(|p|&p.commit_id), "event_ref":event.event_id,
        "governance_generation":0,"authority_ref":genesis.event_id,"committed_at":at,
        "signature":{"context":"ak.realm_commit_signature.v1","signature_algorithm":"Ed25519",
          "verification_method":station.method,"signed_digest":format!("sha256:{}","0".repeat(64)),
          "created_at":at,"sig":"AA"}
    }))
    .unwrap();
    let mut body = serde_json::to_value(&commit).unwrap();
    body.as_object_mut().unwrap().remove("commit_id");
    body.as_object_mut().unwrap().remove("signature");
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&body).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        station.method.clone(),
        at,
        &station.signing_key,
    )
    .unwrap();
    commit
}

fn fixture() -> (Station, Event, AgentProducerEvidence) {
    let station = station(74, "station.example");
    let controller = account(&station);
    let agent = AccountId::new(
        arkret_wire::project_did_to_core_id(
            &Did::new("did:webvh:z6mkfixture:agent.example").unwrap(),
        )
        .unwrap(),
        station.service_id.clone(),
    );
    let at = station.registered_at + Duration::seconds(20);
    let initial = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [1; 32]));
    let mut genesis = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.realm.create",
        ScopeRef::Realm { realm_id: initial },
        ActorId::account(agent.clone()),
        json!({"object": {
          "schema":"ak.schema.realm_genesis.v1","purpose":"agent_control","genesis_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "initial_resolution":{"did":"did:webvh:z6mkfixture:agent.example","method_history_head":format!("sha256:{}","1".repeat(64)),"version_id":"1-fixture"},
          "trust_domain":"ak:trust_domain:station.example","security_class":"high_assurance","governance_station_id":station.service_id,
          "initial_join_rule":"closed","initial_history_access":"since_join","initial_discoverability":"secret"
        }}),
        at,
    )
    .unwrap();
    genesis.executed_by = Some(ActorId::account(controller.clone()));
    genesis.authorization_ref = Some(
        DidUrl::new("did:webvh:z6mkfixture:agent.example#managed-controller")
            .unwrap()
            .into(),
    );
    let method = format!("{PRINCIPAL_DID}#{DEVICE}");
    let genesis = sign(genesis, &method, DEVICE_SEED);
    let raw = SigningKey::from_bytes(&[88; 32]).verifying_key().to_bytes();
    let encoded = arkret_canonical::base64url_encode(&raw);
    let runtime = "did:webvh:z6mkfixture:agent.example#runtime-key";
    let issued = at + Duration::seconds(10);
    let mut key = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.agent.key.authorize",
        ScopeRef::Realm {
            realm_id: genesis.realm_id.clone(),
        },
        ActorId::account(agent.clone()),
        json!({
            "agent_id":agent.principal_id,"key_id":"runtime-key","verification_method":runtime,
            "public_key":{"kty":"OKP","kid":runtime,"algorithm":"Ed25519","key":encoded},
            "accountable_principal_id":controller.principal_id,
            "agent_key_scope":{"actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":genesis.realm_id}]},
            "audience":["station.example"],"approval_evidence":{"kind":"approval_event"},"issued_at":arkret_canonical::format_timestamp_canonical(issued)
        }),
        issued,
    )
    .unwrap();
    key.executed_by = Some(ActorId::account(controller.clone()));
    key.authorization_ref = Some(
        DidUrl::new("did:webvh:z6mkfixture:agent.example#managed-controller")
            .unwrap()
            .into(),
    );
    let key = sign(key, &method, DEVICE_SEED);
    let first = commit(&genesis, &genesis, None, &station);
    let last = commit(&key, &genesis, Some(&first), &station);
    let device = evidence_with(&station, |_| {});
    let reference = device.signer_evidence_ref().unwrap();
    let binding = AgentKeyAuthorization {
        agent_id: agent.principal_id.clone(),
        agent_key_id: NonEmptyString::new("runtime-key").unwrap(),
        verification_method: DidUrl::new(runtime).unwrap(),
        public_key: serde_json::from_value(key.payload["public_key"].clone()).unwrap(),
        public_key_digest: arkret_wire::Hash::new(arkret_canonical::canonical::sha256_digest(raw))
            .unwrap(),
        controller_principal_id: controller.principal_id.clone(),
        accepted_commit_id: last.commit_id.clone(),
        accepted_at: last.committed_at,
        issued_at: issued,
        expires_at: None,
    };
    let current = |commit: &RealmCommit, selector: CurrentSelector, value: serde_json::Value| {
        TypedCurrentResult::Value {
            selector,
            source_stream_ref: commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        }
    };
    let mut bindings = vec![
        AgentProducerBinding {
            event_ref: genesis.event_id.clone(),
            accepted_commit_id: first.commit_id.clone(),
            signer_resolution_evidence_ref: reference.clone(),
        },
        AgentProducerBinding {
            event_ref: key.event_id.clone(),
            accepted_commit_id: last.commit_id.clone(),
            signer_resolution_evidence_ref: reference.clone(),
        },
    ];
    bindings.sort_by(|a, b| a.event_ref.cmp(&b.event_ref));
    let state = AgentAuthorityState {
        authority_id: station.service_id.clone(),
        agent_id: agent.principal_id.clone(),
        source_commit_id: last.commit_id.clone(),
        pcr_genesis_event: genesis.clone(),
        key_authorization_event: key.clone(),
        authorization: binding,
        key_state_witness: AgentKeyStateWitness {
            commit_id: last.commit_id.clone(),
            commit: last.clone(),
            result: current(
                &last,
                CurrentSelector::AgentKey {
                    agent_id: agent.principal_id.clone(),
                    agent_key_id: arkret_wire::AgentKeyId::new("runtime-key").unwrap(),
                },
                json!({"authorizations":[{"tag_id":format!("{}:1",key.event_id),"value":key.payload}]}),
            ),
        },
        agent_lifecycle_witness: AgentLifecycleWitness {
            commit_id: first.commit_id.clone(),
            commit: first.clone(),
            result: current(
                &first,
                CurrentSelector::AgentStatus {
                    agent_id: agent.principal_id.clone(),
                },
                json!("active"),
            ),
            accepted_status_event: genesis.clone(),
            provenance: AgentLifecycleProvenance::Genesis {
                realm_create_event_id: genesis.event_id.clone(),
            },
        },
        commit_lineages: vec![
            AgentCommitLineage {
                witness_commit_id: first.commit_id.clone(),
                predecessor_commit_ids: vec![first.commit_id.clone(), last.commit_id.clone()],
            },
            AgentCommitLineage {
                witness_commit_id: last.commit_id.clone(),
                predecessor_commit_ids: vec![last.commit_id.clone()],
            },
        ],
        commits: vec![first.clone(), last.clone()],
        authority_bundle: AgentAcceptedAuthorityBundle {
            realm_id: genesis.realm_id.clone(),
            genesis_event: genesis.clone(),
            genesis_commit: first,
            authority_transitions: vec![],
            signer_histories: vec![station.service_resolution.clone()],
        },
        signer_dependencies: vec![AgentSignerDependency::AccountDevice {
            signer_resolution_evidence_ref: reference,
            account_device_signer_evidence: device,
        }],
        producer_bindings: bindings,
    };
    let at = station.registered_at + Duration::seconds(60);
    let expires = at + Duration::seconds(120);
    let digest = state.digest().unwrap();
    let mut attestation = AgentAuthorityStateAttestation {
        authority_id: station.service_id.clone(),
        verification_method: station.method.clone(),
        state_digest: digest.clone(),
        issued_at: at,
        expires_at: expires,
        proof: AgentDetachedJws {
            kind: NonEmptyString::new("detached_jws").unwrap(),
            jws: NonEmptyString::new("placeholder").unwrap(),
        },
    };
    attestation.proof.jws = NonEmptyString::new(
        sign_ed25519_detached_jws(&station.signing_key, &attestation.signing_bytes().unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut gate:ControllerAccountGateAttestation=serde_json::from_value(json!({"schema":ControllerAccountGateAttestation::SCHEMA_ID,"principal_id":controller.principal_id,"eligibility":"active","status":"active","basis":{"kind":"account_binding_default","binding_version":1,"binding_receipt_digest":digest},"basis_digest":digest,"authority_id":station.service_id,"verification_method":station.method,"issued_at":arkret_canonical::format_timestamp_canonical(at),"expires_at":arkret_canonical::format_timestamp_canonical(expires),"proof":{"kind":"detached_jws","jws":"placeholder"}})).unwrap();
    gate.basis_digest = gate.expected_basis_digest().unwrap();
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        &mut gate,
        &station.signing_key,
    )
    .unwrap();
    let leaf = AgentProducerEvidence {
        authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence {
            signer_kind: AuthenticatedSignerKind::Agent,
            subject_id: agent.principal_id.clone(),
            verification_method: DidUrl::new(runtime).unwrap(),
            public_key_jwk: serde_json::from_value(
                json!({"kty":"OKP","crv":"Ed25519","x":encoded}),
            )
            .unwrap(),
            authority_commit_id: last.commit_id,
            resolved_at: at,
        },
        agent_authority_state_evidence: AgentAuthorityStateEvidence {
            schema: NonEmptyString::new(arkret_wire::SchemaId::AGENT_AUTHORITY_STATE_EVIDENCE_V1)
                .unwrap(),
            state: Some(state),
            state_digest: digest,
            attestation,
        },
        controller_account_gate_attestation: gate,
        authority_resolution: station.service_resolution.clone(),
    };
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: genesis.realm_id,
        },
        ActorId::account(agent),
        json!({"body":"hello"}),
        at,
    )
    .unwrap();
    (station, sign(event, runtime, [88; 32]), leaf)
}

#[test]
fn cold_full_agent_proof_and_exact_compact_cache() {
    let (station, event, evidence) = fixture();
    let now = station.registered_at + Duration::seconds(61);
    let verified =
        verify_forwarded_agent_producer(&event, &evidence, &station.service_id, now, None).unwrap();
    assert_eq!(
        verified.account(),
        event.actual_signer().as_account_id().unwrap()
    );
    let mut compact = evidence.clone();
    compact.agent_authority_state_evidence.state = None;
    assert_eq!(
        verify_forwarded_agent_producer(&event, &compact, &station.service_id, now, None)
            .unwrap_err()
            .error_code(),
        Some(ErrorCode::DependencyMissing)
    );
    verify_forwarded_agent_producer(
        &event,
        &compact,
        &station.service_id,
        now,
        evidence.agent_authority_state_evidence.state.as_ref(),
    )
    .unwrap();
    let mut bad = evidence.clone();
    bad.agent_authority_state_evidence
        .state
        .as_mut()
        .unwrap()
        .commits
        .remove(0);
    assert!(verify_forwarded_agent_producer(&event, &bad, &station.service_id, now, None).is_err());
    let mut bad = evidence.clone();
    bad.controller_account_gate_attestation.status = ControllerAccountStatus::Locked;
    assert!(verify_forwarded_agent_producer(&event, &bad, &station.service_id, now, None).is_err());
    assert!(
        verify_forwarded_agent_producer(
            &event,
            &evidence,
            &station.service_id,
            now + Duration::seconds(120),
            None
        )
        .is_err()
    );
}
