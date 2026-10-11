use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, RealmCreatePayload, RealmPurpose,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    AccountId, ActorId, AuthorizationRef, DeviceId, Did, DidCoreId, DidUrl, Discoverability,
    EventKind, GenesisSalt, Hash, HistoryAccess, JoinRule, NonEmptyString, ProducerEventProof,
    RealmId, ScopeRef, SemanticRef, TrustDomainId, project_did_to_core_id, proof_kind,
};

use crate::{
    AgentPcrCreateEventInput, AgentPcrCreatePayloadInput, AgentProvisionIntentOptions,
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_agent_pcr_create,
    build_agent_provision_intent, build_pcr_genesis_unit, build_self_principal_pcr_create,
};

fn realm(seed: u8) -> RealmId {
    RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ))
}

fn principal_fixture() -> (Did, DidCoreId, DidCoreId) {
    let did = Did::new("did:webvh:z6mkfixture:users.example:alice").unwrap();
    let principal_id = project_did_to_core_id(&did).unwrap();
    let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    (did, principal_id, station_id)
}

fn resolution(did: Did) -> ResolutionCommitment {
    ResolutionCommitment {
        did,
        method_history_head: format!("sha256:{}", "a".repeat(64)),
        version_id: "1-fixture".to_owned(),
    }
}

fn founding_device_descriptor() -> FoundingDeviceDescriptor {
    FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        device_public_key_did: NonEmptyString::new(
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        )
        .unwrap(),
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key: NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        founding_authorize_payload_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
    }
}

fn self_principal_input() -> SelfPrincipalPcrCreateInput {
    let (principal_did, principal_id, governance_station_id) = principal_fixture();
    SelfPrincipalPcrCreateInput {
        principal_id,
        governance_station_id,
        principal_did: principal_did.clone(),
        genesis_salt: GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        did_inception_ref: SemanticRef::new(
            format!("sha256:{}", "c".repeat(64)),
            DID_INCEPTION_REF_ROLE,
        ),
        initial_resolution: resolution(principal_did),
        founding_device_descriptor: founding_device_descriptor(),
        initial_join_rule: JoinRule::Invite,
        initial_history_access: HistoryAccess::SinceJoin,
        initial_discoverability: Discoverability::InviteOnly,
        created_at: "2026-09-16T00:00:00Z".parse().unwrap(),
    }
}

fn attach_test_proof(event: &mut arkret_wire::AuthoredEvent, verification_method: &str) {
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.attach_proof(ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new(verification_method).unwrap(),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZERTQSJ9..AA".to_owned(),
    });
}

#[test]
fn self_principal_builder_emits_only_producer_content() {
    let authored = build_self_principal_pcr_create(self_principal_input()).unwrap();
    assert_eq!(authored.kind, EventKind::RealmCreate);
    assert_eq!(authored.scope_ref, ScopeRef::RealmGenesis);
    assert_eq!(
        authored.realm_id,
        RealmId::from_event_id(&authored.event_id)
    );
    assert!(authored.producer_proof.is_none());
    assert_eq!(authored.semantic_refs.len(), 1);

    let wire = serde_json::to_value(authored.event()).unwrap();
    let object = wire["payload"]["object"].as_object().unwrap();
    assert_eq!(object["purpose"], "principal_control");
    assert_eq!(
        object["governance_station_id"],
        "ak:did_core:web:station.example"
    );
}

#[test]
fn identity_creation_packaging_requires_producer_proofs() {
    let create = build_self_principal_pcr_create(self_principal_input())
        .unwrap()
        .into_event();
    let authorize = create.clone();
    assert!(build_pcr_genesis_unit(create, authorize).is_err());
}

#[test]
fn identity_creation_packages_two_signed_events_without_event_predecessors() {
    let mut create = build_self_principal_pcr_create(self_principal_input()).unwrap();
    attach_test_proof(
        &mut create,
        "did:webvh:z6mkfixture:users.example:alice#inception",
    );
    let realm_id = create.realm_id.clone();
    let actor_id = create.actor_id.clone();
    let created_at = create.created_at;
    let mut authorize = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        arkret_wire::Event {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0; 32],
            ),
            kind: EventKind::DeviceAuthorize,
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id,
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at,
            semantic_refs: Vec::new(),
            payload: Default::default(),
            producer_proof: None,
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    attach_test_proof(
        &mut authorize,
        "did:webvh:z6mkfixture:users.example:alice#device-1",
    );

    let unit = build_pcr_genesis_unit(create.into_event(), authorize.into_event())
        .expect("two independently signed events form the PCR genesis unit");
    assert_eq!(unit.create().realm_id, realm_id);
    for event in unit.events.iter() {
        let wire = serde_json::to_value(event).unwrap();
        assert!(wire.get("previous_commit_ref").is_none());
        assert!(wire.get("stream_position").is_none());
    }
}

fn agent_create_input(executed_by: ActorId) -> AgentPcrCreateEventInput {
    let agent_did = Did::new("did:webvh:z6mkfixture:agent.example").unwrap();
    AgentPcrCreateEventInput {
        payload: AgentPcrCreatePayloadInput {
            agent_id: project_did_to_core_id(&agent_did).unwrap(),
            governance_station_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            initial_resolution: resolution(agent_did),
            genesis_salt: GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            initial_join_rule: JoinRule::Closed,
            initial_history_access: HistoryAccess::SinceJoin,
            initial_discoverability: Discoverability::Secret,
        },
        executed_by,
        authorization_ref: AuthorizationRef::new("did:web:controller.example#agent-create")
            .unwrap(),
        created_at: "2026-09-16T00:01:00Z".parse().unwrap(),
    }
}

#[test]
fn agent_create_has_no_authority_ordering_fields() {
    let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let controller = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        station.clone(),
    ));
    let input = agent_create_input(controller.clone());
    let agent_id = input.payload.agent_id.clone();
    let authored = build_agent_pcr_create(input).unwrap();
    assert_eq!(authored.scope_ref, ScopeRef::RealmGenesis);
    assert_eq!(
        authored.actor_id,
        ActorId::account(AccountId::new(agent_id, station)),
        "the control facts belong to the Agent's complete account ActorId"
    );
    assert_eq!(authored.executed_by, Some(controller));
    assert!(authored.producer_proof.is_none());
    let payload: RealmCreatePayload = serde_json::from_value(serde_json::Value::Object(
        authored.payload.clone().into_iter().collect(),
    ))
    .unwrap();
    assert_eq!(payload.object.purpose, RealmPurpose::AgentControl);
}

#[test]
fn agent_create_refuses_a_service_executor() {
    let controller =
        ActorId::service(DidCoreId::new("ak:did_core:web:controller.example").unwrap());
    assert!(build_agent_pcr_create(agent_create_input(controller)).is_err());
}

#[test]
fn agent_provision_intent_is_an_unordered_realm_event() {
    let controller = DidCoreId::new("ak:did_core:web:controller.example").unwrap();
    let agent = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
    let intent = build_agent_provision_intent(
        &controller,
        &realm(1),
        &agent,
        &realm(2),
        &DidUrl::new("did:web:controller.example#agent-control").unwrap(),
        "assistant",
        &Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
        HandleVisibility::Private,
        None,
        AgentProvisionIntentOptions {
            controller_station_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            created_at: "2026-09-16T00:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(intent.kind, EventKind::AgentProvision);
    assert!(intent.semantic_refs.is_empty());
    let wire = serde_json::to_value(&intent).unwrap();
    assert!(wire.get("previous_commit_ref").is_none());
    assert!(wire.get("stream_position").is_none());
}
