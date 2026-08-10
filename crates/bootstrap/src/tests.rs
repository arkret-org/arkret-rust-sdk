use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    AuthorizationRef, CellRef, DeviceId, DidCoreId, DidFullId, DidUrl, Event, EventDigestSuiteCode,
    EventId, EventIdentityKey, EventKind, EventRef, Hash, Hlc, NonEmptyString, NotarySig,
    PayloadSignature, PayloadSigner, ProjectedCellWrite, Proof, RealmId, ScopeRef, SealBasis,
    SealId, SemanticRefProof, SemanticRefProofKind, TypedTrustDomainId, WireError,
    composite_subject, project_full_id_to_core_id, proof_kind,
};
use chrono::Utc;
use serde_json::Value;

use crate::projection::direct_projection;
use crate::self_principal::validate_self_principal_pcr_create;
use crate::{
    AgentProvisionEventDraftOptions, DID_INCEPTION_REF_ROLE, ManagedAgentPcrCreatePayloadInput,
    ManagedAgentPcrGenesisAuthority, REALM_AUTHORITY_ROOT_CELL, REALM_CREATE_CELL,
    REALM_GENESIS_CELL, REALM_NOTARY_CELL, REALM_REDUCER_PROFILE_CELL, SelfPrincipalPcrCreateInput,
    build_agent_provision_event_draft, build_managed_agent_pcr_create_payload,
    build_managed_agent_pcr_event_seal, build_self_principal_bootstrap_seal,
    build_self_principal_pcr_create, build_self_principal_pcr_genesis_unit,
    materialize_managed_agent_pcr_control, validate_self_principal_pcr_genesis_unit,
};

struct FixtureSigner {
    did: DidFullId,
    verification_method: DidUrl,
}

/// The real evaluator, wired in through the crate's injected projector.
///
/// Stubbing it would only prove that this crate agrees with itself; the
/// point of these assertions is that the event-kind registry derives the
/// genesis leaf sets the bootstrap branches name.
fn registry_projection(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

fn fixture_event_id(seed: u8) -> EventId {
    let identity = EventIdentityKey::new(EventDigestSuiteCode::Sha256, [seed; 32]);
    identity.event_id()
}

fn fixture_realm(seed: u8) -> RealmId {
    RealmId::from_event_id(&fixture_event_id(seed))
}

impl PayloadSigner for FixtureSigner {
    fn signer_did(&self) -> &DidFullId {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature, WireError> {
        Ok(PayloadSignature {
            verification_method: self.verification_method.clone(),
            payload_digest: Hash::new(arkret_canonical::canonical::sha256_digest(canonical_bytes))?,
            created_at: Utc::now(),
            jws: "fixture.detached-signature".to_owned(),
            extra: Default::default(),
        })
    }
}

fn attach_fixture_proof(event: &mut Event, verification_method: &DidUrl) {
    let digest = Hash::new(event.event_digest().unwrap()).unwrap();
    event.proofs = vec![Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest: digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "fixture.signature".to_owned(),
    }];
}

fn bootstrap_unit() -> (Event, Event) {
    let input = input();
    let principal_id = input.principal_id.clone();
    let principal_full_id = input.principal_full_id.clone();
    let mut create = build_self_principal_pcr_create(input, &registry_projection).unwrap();
    attach_fixture_proof(
        &mut create,
        &DidUrl::new(
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        )
        .unwrap(),
    );

    let payload = founding_authorize_payload(&principal_id, create.created_at);
    let mut authorize = arkret_wire::test_support::raw_event(
        EventKind::DeviceAuthorize.to_string(),
        // The genesis scope belongs to the create alone; the first authorize is
        // an ordinary Control Move inside the Realm the create just named.
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        serde_json::to_value(payload).unwrap(),
    )
    .unwrap();
    authorize.created_at = create.created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.refresh_content_bound_identity().unwrap();
    attach_fixture_proof(
        &mut authorize,
        &DidUrl::new(format!("{}#{}", principal_full_id, founding_device_id())).unwrap(),
    );
    (create, authorize)
}

fn input() -> SelfPrincipalPcrCreateInput {
    let principal_full_id = DidFullId::new("did:webvh:z6mkfixture:users.example:alice").unwrap();
    let principal_id = project_full_id_to_core_id(&principal_full_id).unwrap();
    let created_at = "2026-07-15T00:00:00.000Z".parse().unwrap();
    SelfPrincipalPcrCreateInput {
        principal_id: principal_id.clone(),
        principal_full_id,
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        did_inception_ref: EventRef::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DID_INCEPTION_REF_ROLE,
        ),
        founding_device_descriptor: founding_device_descriptor(&principal_id, created_at),
        capability_action_registry_digest: Hash::new(format!("sha256:{}", "9a".repeat(32)))
            .unwrap(),
        created_at,
        hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    }
}

fn founding_device_public_key() -> &'static str {
    "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ"
}

fn founding_device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
}

fn founding_authorize_payload(
    principal_id: &DidCoreId,
    not_before: chrono::DateTime<Utc>,
) -> DeviceAuthorizePayload {
    DeviceAuthorizePayload {
        principal_id: principal_id.clone(),
        device_id: founding_device_id(),
        device_public_key: NonEmptyString::new(founding_device_public_key()).unwrap(),
        hpke_key: NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Principal(principal_id.clone()),
        scopes: None,
        not_before,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RootAnchored,
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("signature").unwrap(),
        ),
        recovery_session_id: None,
    }
}

fn founding_device_descriptor(
    principal_id: &DidCoreId,
    not_before: chrono::DateTime<Utc>,
) -> FoundingDeviceDescriptor {
    let payload =
        serde_json::to_value(founding_authorize_payload(principal_id, not_before)).unwrap();
    let device_public_key = NonEmptyString::new(founding_device_public_key()).unwrap();
    let hpke_key = NonEmptyString::new("z6LSDeviceHpkeKey").unwrap();
    FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: founding_device_id(),
        device_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
            device_public_key.as_bytes(),
        ))
        .unwrap(),
        device_public_key,
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
            hpke_key.as_bytes(),
        ))
        .unwrap(),
        hpke_key,
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        founding_authorize_payload_digest: device_authorize_payload_digest(
            &payload,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    }
}

#[test]
fn builder_emits_only_the_closed_unsigned_root_shape() {
    let event = build_self_principal_pcr_create(input(), &registry_projection).unwrap();

    assert_eq!(event.kind, EventKind::RealmCreate);
    assert_eq!(event.actor_seq, 0);
    assert!(event.prev_refs.is_empty());
    assert!(event.proofs.is_empty());
    assert_eq!(event.refs.len(), 1);
    assert_eq!(event.refs[0].role, DID_INCEPTION_REF_ROLE);
    event.verify_event_id_matches_content().unwrap();
    // A genesis envelope carries no realm_id and uses the closed genesis
    // scope; the Realm id is derived from this genesis event.
    assert_eq!(event.scope_ref, ScopeRef::RealmGenesis);
    assert!(event.scope_ref.circle_id().is_none());
    // Nothing on the wire says what this Event writes; the registry
    // contract does, and it must land on exactly the genesis leaf set.
    let effects = direct_projection(&event, &registry_projection).unwrap();
    assert_eq!(
        effects
            .iter()
            .map(|effect| effect.cell.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
        [
            REALM_GENESIS_CELL.to_owned(),
            REALM_CREATE_CELL.to_owned(),
            REALM_NOTARY_CELL.to_owned(),
            REALM_REDUCER_PROFILE_CELL.to_owned(),
            REALM_AUTHORITY_ROOT_CELL.to_owned(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    validate_self_principal_pcr_create(&event, false, &registry_projection).unwrap();
}

#[test]
fn validation_rejects_a_non_self_realm_and_builder_rejects_indirect_inception_ref() {
    let mut wrong_realm = build_self_principal_pcr_create(input(), &registry_projection).unwrap();
    wrong_realm.realm_id =
        RealmId::new("ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    assert!(validate_self_principal_pcr_create(&wrong_realm, false, &registry_projection).is_err());

    let mut indirect = input();
    indirect.did_inception_ref.proof = Some(SemanticRefProof {
        kind: SemanticRefProofKind::Rfc6962Merkle,
        leaf_digest: Hash::new(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap(),
        audit_path: Vec::new(),
        leaf_index: 0,
        leaf_count: 1,
    });
    assert!(build_self_principal_pcr_create(indirect, &registry_projection).is_err());
}

#[test]
fn bootstrap_authorize_must_continue_the_genesis_actor_chain_exactly() {
    let (create, authorize) = bootstrap_unit();
    validate_self_principal_pcr_genesis_unit(&create, &authorize, &registry_projection).unwrap();
    let unit = build_self_principal_pcr_genesis_unit(
        create.clone(),
        authorize.clone(),
        &registry_projection,
    )
    .unwrap();
    assert_eq!(unit.events.len(), 2);

    let mut missing = authorize.clone();
    missing.prev_refs.clear();
    assert!(
        validate_self_principal_pcr_genesis_unit(&create, &missing, &registry_projection).is_err()
    );

    let mut unrelated = authorize;
    unrelated.prev_refs = vec![create.event_id.clone(), fixture_event_id(0x99)];
    assert!(
        validate_self_principal_pcr_genesis_unit(&create, &unrelated, &registry_projection)
            .is_err()
    );
}

#[test]
fn first_bootstrap_seal_covers_both_events_and_is_signed_by_device_one() {
    let (create, authorize) = bootstrap_unit();
    let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
    let principal_id = input().principal_full_id;
    let signer = FixtureSigner {
        did: principal_id.clone(),
        verification_method: DidUrl::new(format!("{principal_id}#{device_id}")).unwrap(),
    };
    let seal = build_self_principal_bootstrap_seal(
        &create,
        &authorize,
        Hlc::new("01970e589d21-0006-a13f9c2e").unwrap(),
        &signer,
        &registry_projection,
    )
    .unwrap();

    assert!(seal.predecessor_refs.is_empty());
    assert_eq!(seal.notary_seq, 0);
    assert_eq!(seal.delta.len(), 2);
    assert_eq!(seal.covered_event_digests, seal.delta);
    assert_eq!(
        seal.completeness_root,
        arkret_state::control_event_completeness_root(
            &[create, authorize],
            &seal.delta.iter().cloned().collect(),
        )
        .unwrap()
    );
    assert_eq!(seal.derive_id().unwrap(), seal.id);
    let NotarySig::Single(signature) = seal.notary_signature else {
        panic!("bootstrap Seal must use one device signature")
    };
    assert_eq!(signature.verification_method, signer.verification_method);
}

fn managed_agent_pcr_create() -> Event {
    let realm_id = RealmId::new("ak:realm:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap();
    let agent_full = DidFullId::new("did:webvh:z6mkfixtureagent:agent.example").unwrap();
    let agent = project_full_id_to_core_id(&agent_full).unwrap();
    let controller_full =
        DidFullId::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap();
    let controller = project_full_id_to_core_id(&controller_full).unwrap();
    let payload = build_managed_agent_pcr_create_payload(ManagedAgentPcrCreatePayloadInput {
        agent_id: agent.clone(),
        agent_full_id: agent_full.clone(),
        controller_id: controller.clone(),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        capability_action_registry_digest: Hash::new(format!("sha256:{}", "9a".repeat(32)))
            .unwrap(),
        created_at: Utc::now(),
    })
    .unwrap();
    let mut create = arkret_wire::test_support::raw_event(
        EventKind::RealmCreate.to_string(),
        ScopeRef::Realm { realm_id },
        agent,
        0,
        Hlc::new("01970e589d21-0007-a13f9c2e").unwrap(),
        payload.to_value().unwrap(),
    )
    .unwrap();
    create.event_id =
        EventId::new("ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap();
    create.authorization_ref =
        Some(AuthorizationRef::new(format!("{agent_full}#managed-controller")).unwrap());
    create.executed_by = Some(controller);
    create.refs.clear();
    create
}

#[test]
fn managed_agent_pcr_payload_is_built_from_the_public_realm_type() {
    let payload = build_managed_agent_pcr_create_payload(ManagedAgentPcrCreatePayloadInput {
        agent_id: DidCoreId::new("ak:did_core:web:agent.example".to_owned()).unwrap(),
        agent_full_id: DidFullId::new("did:web:agent.example").unwrap(),
        controller_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturecontroller").unwrap(),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net".to_owned()).unwrap(),
        capability_action_registry_digest: Hash::new(format!("sha256:{}", "9a".repeat(32)))
            .unwrap(),
        created_at: Utc::now(),
    })
    .unwrap();
    let value = payload.to_value().unwrap();

    assert_eq!(
        value
            .pointer("/object/reducer_profile")
            .and_then(Value::as_str),
        Some(arkret_wire::CORE_REDUCER_PROFILE)
    );
    assert_eq!(
        value.pointer("/object/purpose").and_then(Value::as_str),
        Some("managed_agent_control")
    );
}

#[test]
fn managed_agent_material_derives_the_genesis_leaf_set_from_the_registry() {
    let create = managed_agent_pcr_create();
    let material =
        materialize_managed_agent_pcr_control(std::slice::from_ref(&create), &registry_projection)
            .unwrap();

    assert_eq!(material.agent_id, create.actor_id);
    assert_eq!(
        material
            .joined
            .keys()
            .map(CellRef::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>(),
        vec![
            format!(
                "ak:cell:{}:{}",
                arkret_wire::CellFamilyId::AGENT_STATUS_V1,
                create.actor_id
            ),
            REALM_NOTARY_CELL.to_owned(),
            REALM_AUTHORITY_ROOT_CELL.to_owned(),
            REALM_CREATE_CELL.to_owned(),
            REALM_GENESIS_CELL.to_owned(),
            REALM_REDUCER_PROFILE_CELL.to_owned(),
        ]
    );

    // Nothing the producer sends can move a target any more, so the
    // remaining way to break the genesis leaf set is a payload the
    // contract cannot evaluate.
    let mut no_notary = create;
    no_notary
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove("notary");
    assert!(
        materialize_managed_agent_pcr_control(&[no_notary], &registry_projection).is_err(),
        "a Realm create whose notary source is missing must fail closed"
    );
}

/// Genesis authority is a property of the accepted create alone. The type
/// only accepts that Event, so a caller cannot hand over a later
/// pre-state-dependent transition and cannot silently get a current-state
/// answer in its place.
#[test]
fn managed_agent_genesis_authority_covers_the_whole_founding_notary() {
    let create = managed_agent_pcr_create();
    let authority =
        ManagedAgentPcrGenesisAuthority::from_accepted_create(&create, &registry_projection)
            .unwrap();

    assert_eq!(authority.agent_id(), &create.actor_id);
    assert_eq!(
        authority.controller_id(),
        create.executed_by.as_ref().unwrap()
    );
    assert_eq!(
        authority.authority_set_ref(),
        &Hash::new(
            arkret_canonical::canonical_sha256(&create.payload["object"]["notary"]).unwrap()
        )
        .unwrap(),
        "the authority digest must cover the founding notary value verbatim"
    );

    let mut later_transition = arkret_wire::test_support::raw_event(
        EventKind::MlsGenesis.to_string(),
        create.scope_ref.clone(),
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
        serde_json::json!({}),
    )
    .unwrap();
    later_transition.executed_by = create.executed_by.clone();
    later_transition.authorization_ref = create.authorization_ref;
    assert!(
        ManagedAgentPcrGenesisAuthority::from_accepted_create(
            &later_transition,
            &registry_projection
        )
        .is_err(),
        "only the accepted ak.realm.create defines the genesis authority"
    );
}

#[test]
fn covered_event_with_no_derived_writes_moves_only_the_coverage_root() {
    let create = managed_agent_pcr_create();
    let controller_actor = create.executed_by.clone().unwrap();
    let controller = DidFullId::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap();
    let mut anchor = arkret_wire::test_support::raw_event(
        EventKind::MlsGenesis.to_string(),
        create.scope_ref.clone(),
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-0008-a13f9c2e").unwrap(),
        serde_json::json!({}),
    )
    .unwrap();
    anchor.event_id =
        EventId::new("ak:event:Af0cDOgrSK-qWEvQvEo_FnP9vdEMz6mEq0IN2aIOIege").unwrap();
    anchor.executed_by = Some(controller_actor);
    anchor.authorization_ref = create.authorization_ref.clone();

    // The subject here is this crate's Seal arithmetic, not the registry:
    // a covered Event that derives no cell write must still move the
    // coverage root while leaving the state root alone. The projector is
    // the injected boundary, so it is stubbed for the anchor slot -- the
    // real `ak.mls.genesis` contract registers three writes in v1.
    let anchor_id = anchor.event_id.clone();
    let project = |event: &Event| {
        if event.event_id == anchor_id {
            return Ok(Vec::new());
        }
        registry_projection(event)
    };

    let signer = FixtureSigner {
        did: controller.clone(),
        verification_method: DidUrl::new(format!(
            "{controller}#ak:device:01904100-0000-7000-8000-0000000000a1"
        ))
        .unwrap(),
    };
    let first = build_managed_agent_pcr_event_seal(
        std::slice::from_ref(&create),
        None,
        Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
        &signer,
        &project,
    )
    .unwrap();
    let successor = build_managed_agent_pcr_event_seal(
        &[create, anchor.clone()],
        Some(&first),
        Hlc::new("01970e589d21-000a-a13f9c2e").unwrap(),
        &signer,
        &project,
    )
    .unwrap();

    assert_eq!(successor.predecessor_refs, vec![first.id.clone()]);
    assert_eq!(successor.notary_seq, 1);
    assert_eq!(successor.delta.len(), 1);
    assert_eq!(successor.delta[0].as_str(), anchor.event_digest().unwrap());
    assert_eq!(successor.covered_event_digests.len(), 2);
    assert_eq!(successor.state_root, first.state_root);
    assert_ne!(
        successor.control_event_set_root,
        first.control_event_set_root
    );
    let NotarySig::Single(signature) = successor.notary_signature else {
        panic!("managed Agent PCR Seal must use one controller signature")
    };
    assert_eq!(signature.verification_method, signer.verification_method);
}

#[test]
fn managed_agent_provision_event_projects_the_registered_atomic_cells() {
    let controller_full = DidFullId::new("did:webvh:z6mkfixture:controller.example").unwrap();
    let controller = DidCoreId::new("ak:did_core:webvh:z6mkfixture:controller.example").unwrap();
    let agent = DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent.example").unwrap();
    let event = build_agent_provision_event_draft(
        &controller,
        &fixture_realm(1),
        &agent,
        &fixture_realm(2),
        &DidUrl::new(format!("{controller_full}#managed-agent")).unwrap(),
        "summary",
        &Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        HandleVisibility::Private,
        None,
        AgentProvisionEventDraftOptions {
            created_at: "2026-07-18T01:02:03Z".parse().unwrap(),
            actor_seq: 4,
            hlc: Hlc::new("01980a8f3980-0001-a13f9c2e").unwrap(),
            prev_refs: vec![fixture_event_id(3)],
            seal_basis: Some(SealBasis {
                leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap()],
            }),
        },
    )
    .unwrap();

    let payload: AgentProvisionPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    payload.validate().unwrap();
    assert_eq!(payload.agent_id, agent);
    let effects = direct_projection(&event, &registry_projection).unwrap();
    assert_eq!(
        effects
            .iter()
            .map(|effect| effect.cell.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            format!("ak:cell:ak.component.agent.provision.v1:{agent}"),
            format!(
                "ak:cell:{}:{}",
                arkret_wire::CellFamilyId::AGENT_PRINCIPAL_CONTROL_REALM_CLAIM_V1,
                fixture_realm(2)
            ),
            format!(
                "ak:cell:ak.component.identity.accountability.v1:{}",
                composite_subject(&[controller.as_str(), agent.as_str(), "agent_operator"])
                    .unwrap()
            ),
            format!(
                "ak:cell:ak.component.agent.selector_claim.v1:{}",
                composite_subject(&[controller.as_str(), "summary"]).unwrap()
            ),
        ])
    );

    assert_eq!(
        serde_json::to_value(&event).unwrap()["created_at"],
        "2026-07-18T01:02:03.000Z"
    );
}
