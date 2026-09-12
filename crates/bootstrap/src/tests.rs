use std::collections::BTreeSet;

use arkret_event_draft::build_agent_key_authorize_intent;
use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentProvisionPayload,
};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_collaboration::governance_dependencies::{
    SealPrepareOutcome, SealPrepareRequestBody,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    ActorId, AuthorizationRef, Base64UrlString, CellRef, DeviceId, Did, DidCoreId, DidUrl,
    DigestSuiteCode, Event, EventId, EventIdentityKey, EventKind, EventRef, Hash, Hlc, LatticeOp,
    LatticeOpType, NonEmptyString, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor,
    NotaryValue, PayloadSignature, PayloadSigner, ProducerEventProof, ProjectedCellWrite,
    ProjectedOp, RealmId, ScopeRef, SealBasis, SealId, SemanticRefProof, SemanticRefProofKind,
    SemanticRefProofRootField, TrustDomainId, UnsignedSeal, WireError, composite_subject,
    project_did_to_core_id, proof_kind,
};
use chrono::Utc;
use serde_json::Value;

use crate::projection::direct_projection;
use crate::self_principal::validate_self_principal_pcr_create;
use crate::{
    AgentPcrCreatePayloadInput, AgentPcrGenesisAuthority, AgentProvisionIntentOptions,
    DID_INCEPTION_REF_ROLE, REALM_AUTHORITY_ROOT_CELL, REALM_CREATE_CELL, REALM_GENESIS_CELL,
    REALM_NOTARY_CELL, REALM_REDUCER_PROFILE_CELL, SelfPrincipalPcrCreateInput,
    agent_pcr_genesis_control_unit, build_agent_pcr_bootstrap_seal, build_agent_pcr_create_payload,
    build_agent_provision_intent, build_self_principal_bootstrap_seal,
    build_self_principal_pcr_create, build_self_principal_pcr_genesis_unit,
    materialize_agent_pcr_control, validate_self_principal_pcr_genesis_unit,
};

struct FixtureSigner {
    did: Did,
    verification_method: DidUrl,
}

/// The real evaluator, wired in through the crate's injected projector.
///
/// Stubbing it would only prove that this crate agrees with itself; the
/// point of these assertions is that the event-kind registry derives the
/// genesis leaf sets the bootstrap branches name.
fn registry_projection(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    // The Event id losslessly encodes the suite its digest was taken under, and
    // the OR-Set dots the contract derives are keyed by that digest, so the
    // projector must follow the Event rather than assume one suite.
    arkret_schema::project_registered_cell_writes(
        event,
        event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn fixture_event_id(seed: u8) -> EventId {
    let identity = EventIdentityKey::new(DigestSuiteCode::Sha256, [seed; 32]);
    identity.event_id()
}

fn fixture_realm(seed: u8) -> RealmId {
    RealmId::from_event_id(&fixture_event_id(seed))
}

fn ordered_control_unit(
    events: impl IntoIterator<Item = Event>,
    digest_suite: arkret_canonical::DigestSuite,
) -> arkret_state::OrderedControlUnit {
    arkret_state::OrderedControlUnit {
        events: events
            .into_iter()
            .map(|event| arkret_state::OrderedControlUnitEvent {
                digest: Hash::new(event.event_digest_with_digest_suite(digest_suite).unwrap())
                    .unwrap(),
                event,
                digest_suite,
            })
            .collect(),
    }
}

fn fixture_resolution(did: Did) -> ResolutionCommitment {
    ResolutionCommitment {
        did,
        method_history_head: format!("sha256:{}", "8b".repeat(32)),
        version_id: format!("1-{}", "Qm".to_owned() + &"a".repeat(44)),
    }
}

impl PayloadSigner for FixtureSigner {
    fn signer_did(&self) -> &Did {
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
            jws: "eyJhbGciOiJFZERTQSJ9..AA".to_owned(),
        })
    }

    fn sign_notary_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<PayloadSignature, WireError> {
        let mut signature = self.sign_payload(canonical_bytes)?;
        signature.payload_digest =
            Hash::new(arkret_canonical::digest(digest_suite, canonical_bytes))?;
        Ok(signature)
    }
}

fn attach_fixture_proof(event: &mut Event, verification_method: &DidUrl) {
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.proofs = vec![ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest: digest,
        signer_resolution_evidence_ref: None,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZERTQSJ9..AA".to_owned(),
    }];
}

fn bootstrap_unit() -> (Event, Event) {
    let input = input();
    let principal_id = input.principal_id.clone();
    let principal_did = input.principal_did.clone();
    let mut create = build_self_principal_pcr_create(input, &registry_projection)
        .unwrap()
        .into_event();
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
        // a non-anchor Control Move inside the Realm the create just named.
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        create.actor_id.signing_principal_id().clone(),
        create.actor_id.route_service_id().clone(),
        1,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        serde_json::to_value(payload).unwrap(),
    )
    .unwrap();
    authorize.created_at = create.created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    attach_fixture_proof(
        &mut authorize,
        &DidUrl::new(format!("{}#{}", principal_did, founding_device_id())).unwrap(),
    );
    (create, authorize)
}

fn input() -> SelfPrincipalPcrCreateInput {
    let principal_did = Did::new("did:webvh:z6mkfixture:users.example:alice").unwrap();
    let principal_id = project_did_to_core_id(&principal_did).unwrap();
    let created_at = "2026-07-15T00:00:00.000Z".parse().unwrap();
    SelfPrincipalPcrCreateInput {
        principal_id: principal_id.clone(),
        station_id: DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        principal_did: principal_did.clone(),
        notary: fixture_notary(&principal_id, &principal_did, founding_device_id().as_str()),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        did_inception_ref: EventRef::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DID_INCEPTION_REF_ROLE,
        ),
        initial_resolution: ResolutionCommitment {
            did: principal_did.clone(),
            method_history_head: format!("sha256:{}", "a".repeat(64)),
            version_id: "1-fixture".to_owned(),
        },
        founding_device_descriptor: founding_device_descriptor(&principal_id, created_at),
        created_at,
        hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    }
}

fn fixture_notary(actor_id: &DidCoreId, actor_did: &Did, fragment: &str) -> NotaryValue {
    let public_key = arkret_canonical::decode_ed25519_multibase(
        founding_device_public_key()
            .strip_prefix("did:key:")
            .expect("fixture public key is a did:key identifier"),
    )
    .expect("fixture public key is valid");
    NotaryValue::new(
        NotarySignerDescriptor {
            actor_id: ActorId::service(actor_id.clone()),
            verification_method: DidUrl::new(format!("{actor_did}#{fragment}")).unwrap(),
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret_wire::base64url::base64url_encode(public_key),
        },
        0,
    )
    .unwrap()
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
        pairing_challenge_transcript_digest: None,
        device_id: founding_device_id(),
        device_public_key_did: NonEmptyString::new(founding_device_public_key()).unwrap(),
        hpke_key: NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Principal(principal_id.clone()),
        scopes: None,
        not_before,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
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
    let device_public_key_did = NonEmptyString::new(founding_device_public_key()).unwrap();
    let hpke_key = NonEmptyString::new("z6LSDeviceHpkeKey").unwrap();
    FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: founding_device_id(),
        device_public_key_did,
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
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
    assert_eq!(
        event.actor_id.route_service_id().as_str(),
        "ak:did_core:web:principal.example"
    );
    assert_ne!(
        event.actor_id.route_service_id(),
        event.actor_id.signing_principal_id()
    );
    assert_eq!(event.actor_seq, 0);
    assert!(event.prev_refs.is_empty());
    assert!(event.proofs.is_empty());
    assert_eq!(event.refs.len(), 1);
    assert_eq!(event.refs[0].role, DID_INCEPTION_REF_ROLE);
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
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
            .map(|effect| effect.cell_id.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
        [
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::IDENTITY_RESOLUTION_V1
            ),
            REALM_GENESIS_CELL.to_owned(),
            REALM_CREATE_CELL.to_owned(),
            REALM_NOTARY_CELL.to_owned(),
            REALM_REDUCER_PROFILE_CELL.to_owned(),
            REALM_AUTHORITY_ROOT_CELL.to_owned(),
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1
            ),
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::IDENTITY_RESOLUTION_V1
            ),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    validate_self_principal_pcr_create(&event, false, &registry_projection).unwrap();
}

#[test]
fn validation_rejects_a_non_self_realm_and_builder_rejects_indirect_inception_ref() {
    let mut wrong_realm = build_self_principal_pcr_create(input(), &registry_projection)
        .unwrap()
        .into_event();
    wrong_realm.realm_id =
        RealmId::new("ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    assert!(validate_self_principal_pcr_create(&wrong_realm, false, &registry_projection).is_err());

    let mut indirect = input();
    indirect.did_inception_ref.proof = Some(SemanticRefProof {
        kind: SemanticRefProofKind::Rfc6962Merkle,
        root_field: SemanticRefProofRootField::ControlEventSetRoot,
        root_digest: Hash::new(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap(),
        leaf_canonical_preimage_b64u: Base64UrlString::new("Y2NjYw").unwrap(),
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
fn accepted_bootstrap_history_remains_valid_for_successor_seal_replay() {
    let (create, authorize) = bootstrap_unit();

    validate_self_principal_pcr_genesis_unit(&create, &authorize, &registry_projection).unwrap();
    let principal_id = input().principal_did;
    let signer = FixtureSigner {
        did: principal_id.clone(),
        verification_method: DidUrl::new(format!("{principal_id}#{}", founding_device_id()))
            .unwrap(),
    };
    let seal = build_self_principal_bootstrap_seal(
        &create,
        &authorize,
        Hlc::new("01970e589d21-0006-a13f9c2f").unwrap(),
        &signer,
        &registry_projection,
    )
    .unwrap();

    assert_eq!(seal.delta.len(), 2);
}

#[test]
fn bootstrap_authorize_proof_uses_the_exact_initial_resolution_did() {
    let (create, mut authorize) = bootstrap_unit();
    let same_core_different_did = Did::new("did:webvh:z6mkfixture:other.example:bob").unwrap();
    assert_eq!(
        project_did_to_core_id(&same_core_different_did).unwrap(),
        *create.actor_id.signing_principal_id()
    );
    authorize.proofs[0].verification_method = DidUrl::new(format!(
        "{}#{}",
        same_core_different_did,
        founding_device_id()
    ))
    .unwrap();

    assert!(
        validate_self_principal_pcr_genesis_unit(&create, &authorize, &registry_projection)
            .is_err()
    );
}

#[test]
fn first_bootstrap_seal_covers_both_events_and_is_signed_by_device_one() {
    let (create, authorize) = bootstrap_unit();
    let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
    let principal_id = input().principal_did;
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

    assert!(seal.predecessor_ref.is_none());
    assert_eq!(seal.notary_seq, 0);
    assert_eq!(seal.delta.len(), 2);
    assert_eq!(seal.covered_event_digests, seal.delta);
    assert_eq!(
        seal.derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
        seal.id
    );
    let signature = &seal.notary_signature;
    assert_eq!(signature.verification_method, signer.verification_method);
}

fn agent_pcr_create() -> Event {
    let realm_id = RealmId::new("ak:realm:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap();
    let agent_did = Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap();
    let agent = project_did_to_core_id(&agent_did).unwrap();
    let controller_did = Did::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap();
    let controller = project_did_to_core_id(&controller_did).unwrap();
    let payload = build_agent_pcr_create_payload(AgentPcrCreatePayloadInput {
        agent_id: agent.clone(),
        initial_resolution: fixture_resolution(agent_did.clone()),
        controller_principal_id: controller.clone(),
        notary: fixture_notary(&agent, &agent_did, "root"),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        created_at: Utc::now(),
    })
    .unwrap();
    let mut create = arkret_wire::test_support::raw_event(
        EventKind::RealmCreate.to_string(),
        ScopeRef::Realm { realm_id },
        agent.clone(),
        agent,
        0,
        Hlc::new("01970e589d21-0007-a13f9c2e").unwrap(),
        payload.to_value().unwrap(),
    )
    .unwrap();
    create.event_id =
        EventId::new("ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap();
    create.authorization_ref =
        Some(AuthorizationRef::new(format!("{agent_did}#managed-controller")).unwrap());
    create.executed_by = Some(ActorId::service(controller));
    create.refs.clear();
    create
}

#[test]
fn agent_pcr_payload_is_built_from_the_public_realm_type() {
    let did = Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap();
    let payload = build_agent_pcr_create_payload(AgentPcrCreatePayloadInput {
        agent_id: project_did_to_core_id(&did).unwrap(),
        initial_resolution: fixture_resolution(did.clone()),
        controller_principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturecontroller").unwrap(),
        notary: fixture_notary(&project_did_to_core_id(&did).unwrap(), &did, "root"),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:example.net".to_owned()).unwrap(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
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
        Some("agent_control")
    );
}

#[test]
fn agent_material_derives_the_genesis_leaf_set_from_the_registry() {
    let create = agent_pcr_create();
    let canonical_actor = arkret_canonical::canonical_json_string(&create.actor_id).unwrap();
    let agent_status_subject = composite_subject(&[canonical_actor]).unwrap();
    let unit = agent_pcr_genesis_control_unit(&create).unwrap();
    let material =
        materialize_agent_pcr_control(std::slice::from_ref(&unit), &registry_projection).unwrap();

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
                agent_status_subject
            ),
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::IDENTITY_RESOLUTION_V1
            ),
            REALM_NOTARY_CELL.to_owned(),
            REALM_AUTHORITY_ROOT_CELL.to_owned(),
            REALM_CREATE_CELL.to_owned(),
            REALM_GENESIS_CELL.to_owned(),
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1
            ),
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
        agent_pcr_genesis_control_unit(&no_notary)
            .and_then(|unit| materialize_agent_pcr_control(&[unit], &registry_projection))
            .is_err(),
        "a Realm create whose notary source is missing must fail closed"
    );
}

/// Genesis authority is a property of the accepted create alone. The type
/// only accepts that Event, so a caller cannot hand over a later
/// pre-state-dependent transition and cannot silently get a current-state
/// answer in its place.
#[test]
fn agent_genesis_authority_covers_the_whole_founding_notary() {
    let create = agent_pcr_create();
    let authority =
        AgentPcrGenesisAuthority::from_accepted_create(&create, &registry_projection).unwrap();

    assert_eq!(authority.agent_id(), &create.actor_id);
    assert_eq!(
        authority.controller_actor_id(),
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
        create.actor_id.signing_principal_id().clone(),
        create.actor_id.route_service_id().clone(),
        1,
        Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
        serde_json::json!({}),
    )
    .unwrap();
    later_transition.executed_by = create.executed_by.clone();
    later_transition.authorization_ref = create.authorization_ref;
    assert!(
        AgentPcrGenesisAuthority::from_accepted_create(&later_transition, &registry_projection)
            .is_err(),
        "only the accepted ak.realm.create defines the genesis authority"
    );
}

#[test]
fn covered_event_with_no_derived_writes_moves_only_the_coverage_root() {
    let create = agent_pcr_create();
    let controller_actor = create.executed_by.clone().unwrap();
    let controller = Did::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap();
    let mut anchor = arkret_wire::test_support::raw_event(
        EventKind::MlsGenesis.to_string(),
        create.scope_ref.clone(),
        create.actor_id.signing_principal_id().clone(),
        create.actor_id.route_service_id().clone(),
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
    let _first = build_agent_pcr_bootstrap_seal(
        std::slice::from_ref(&create),
        Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
        &signer,
        &project,
    )
    .unwrap();
    let error = build_agent_pcr_bootstrap_seal(
        &[create, anchor],
        Hlc::new("01970e589d21-000a-a13f9c2e").unwrap(),
        &signer,
        &project,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("bootstrap Seal requires exactly its genesis create")
    );
}

const AGENT_CONTROLLER_SEAL_SEED: [u8; 32] = [0x7c; 32];

fn agent_controller_did() -> Did {
    Did::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap()
}

fn agent_controller_seal_signer() -> arkret_signatures::Ed25519PayloadSigner {
    let controller_did = agent_controller_did();
    arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        AGENT_CONTROLLER_SEAL_SEED,
        controller_did.clone(),
        DidUrl::new(format!("{controller_did}#seal-1")).unwrap(),
    )
}

/// The genesis create of an Agent PCR that locks `digest_suite`.
///
/// The id is content-bound rather than assigned, and it is derived under
/// SHA-256 for every suite because section 2.5.0 makes `realm_id` a retype of
/// this Event's own id and fixes the v1 Realm token header at `0x01`.
fn agent_pcr_genesis_with_digest_suite(digest_suite: arkret_canonical::DigestSuite) -> Event {
    let agent_did = Did::new("did:webvh:z6mkfixtureagent:agent.example").unwrap();
    let agent = project_did_to_core_id(&agent_did).unwrap();
    let controller = project_did_to_core_id(&agent_controller_did()).unwrap();
    let payload = build_agent_pcr_create_payload(AgentPcrCreatePayloadInput {
        agent_id: agent.clone(),
        initial_resolution: fixture_resolution(agent_did.clone()),
        controller_principal_id: controller.clone(),
        notary: fixture_notary(&agent, &agent_did, "root"),
        genesis_salt: arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        digest_suite,
        created_at: "2026-07-15T00:00:00.000Z".parse().unwrap(),
    })
    .unwrap();
    let mut create = arkret_wire::test_support::raw_event(
        EventKind::RealmCreate.to_string(),
        ScopeRef::RealmGenesis,
        agent.clone(),
        agent,
        0,
        Hlc::new("01970e589d21-0011-a13f9c2e").unwrap(),
        payload.to_value().unwrap(),
    )
    .unwrap();
    create.created_at = "2026-07-15T00:00:00.000Z".parse().unwrap();
    create.authorization_ref =
        Some(AuthorizationRef::new(format!("{agent_did}#managed-controller")).unwrap());
    create.executed_by = Some(ActorId::service(controller));
    create.refs.clear();
    create
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    create
}

/// A fixture Control Move authored under `digest_suite`.
fn agent_pcr_follow_up_event(
    create: &Event,
    actor_seq: u64,
    hlc: &str,
    digest_suite: arkret_canonical::DigestSuite,
    seal_basis: Option<SealBasis>,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event(
        EventKind::MlsGenesis.to_string(),
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        create.actor_id.signing_principal_id().clone(),
        create.actor_id.route_service_id().clone(),
        actor_seq,
        Hlc::new(hlc).unwrap(),
        serde_json::json!({}),
    )
    .unwrap();
    event.created_at = create.created_at;
    event.executed_by = create.executed_by.clone();
    event.authorization_ref = create.authorization_ref.clone();
    event.seal_basis = seal_basis;
    event
        .refresh_content_bound_identity_with_digest_suite(digest_suite)
        .unwrap();
    event
}

/// Keep this suite-arithmetic fixture independent of the large MLS payload by
/// projecting its successor onto one registered security Cell.
fn fixture_successor_projection(
    successors: &BTreeSet<EventId>,
) -> impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + '_ {
    move |event: &Event| {
        if successors.contains(&event.event_id) {
            return Ok(vec![ProjectedCellWrite {
                cell_id: CellRef::new(REALM_NOTARY_CELL.to_owned()).unwrap(),
                op: ProjectedOp::Direct(LatticeOp {
                    op_type: LatticeOpType::Set,
                    value: Some(serde_json::json!({"revision": event.actor_seq})),
                    ..LatticeOp::empty()
                }),
            }]);
        }
        registry_projection(event)
    }
}

/// The materializer must take its suite from the authenticated genesis object,
/// not from a constant. Only the create's own digest stays SHA-256, and only
/// because the Realm token is a retype of that Event id.
#[test]
fn agent_pcr_material_uses_the_genesis_declared_digest_suite() {
    for digest_suite in [
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::DigestSuite::Blake3,
    ] {
        let create = agent_pcr_genesis_with_digest_suite(digest_suite);
        let unit = agent_pcr_genesis_control_unit(&create).unwrap();
        let material =
            materialize_agent_pcr_control(std::slice::from_ref(&unit), &registry_projection)
                .unwrap();

        assert_eq!(material.digest_suite, digest_suite);
        assert_eq!(material.state_root.digest_suite().unwrap(), digest_suite);
        assert_eq!(
            material.covered_event_digests,
            vec![
                Hash::new(
                    create
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .unwrap()
                )
                .unwrap()
            ]
        );
        assert_eq!(RealmId::from_event_id(&create.event_id), create.realm_id);

        let authority =
            AgentPcrGenesisAuthority::from_accepted_create(&create, &registry_projection).unwrap();
        assert_eq!(authority.digest_suite(), digest_suite);
        assert_eq!(
            authority.authority_set_ref().digest_suite().unwrap(),
            digest_suite
        );
    }
}

/// Every root, the Seal identity and the notary payload digest follow the
/// declared suite, and the signature is a real Ed25519 detached JWS.
#[test]
fn agent_pcr_bootstrap_seal_follows_the_genesis_declared_digest_suite() {
    for digest_suite in [
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::DigestSuite::Blake3,
    ] {
        let create = agent_pcr_genesis_with_digest_suite(digest_suite);
        let signer = agent_controller_seal_signer();
        let seal = build_agent_pcr_bootstrap_seal(
            std::slice::from_ref(&create),
            Hlc::new("01970e589d21-0012-a13f9c2e").unwrap(),
            &signer,
            &registry_projection,
        )
        .unwrap();

        assert!(
            seal.id
                .as_str()
                .starts_with(&format!("ak:seal:{}:", digest_suite.as_str()))
        );
        seal.validate_id(digest_suite).unwrap();
        assert_eq!(seal.state_root.digest_suite().unwrap(), digest_suite);
        assert_eq!(
            seal.control_event_set_root.digest_suite().unwrap(),
            digest_suite
        );
        let signature = &seal.notary_signature;
        assert_eq!(
            signature.payload_digest.digest_suite().unwrap(),
            digest_suite
        );
        let public_key = signer.verifying_key().to_bytes();
        let descriptor = NotarySignerDescriptor {
            actor_id: ActorId::service(project_did_to_core_id(&agent_controller_did()).unwrap()),
            verification_method: signer.verification_method_id().clone(),
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret_wire::base64url::base64url_encode(public_key),
        };
        arkret_signatures::verify_frozen_notary_signature(
            signature,
            &descriptor,
            &seal.commit_transcript_bytes(digest_suite).unwrap(),
            digest_suite,
        )
        .unwrap();
    }
}

/// A real `ak.agent.key.authorize` successor exercises the registered OR-Set
/// write and the same suite all the way through materialization, roots, Seal
/// identity and the controller's Ed25519 notary signature.
#[test]
fn agent_pcr_authorize_successor_follows_the_genesis_declared_digest_suite() {
    for digest_suite in [
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::DigestSuite::Blake3,
    ] {
        let create = agent_pcr_genesis_with_digest_suite(digest_suite);
        let signer = agent_controller_seal_signer();
        let genesis_seal = build_agent_pcr_bootstrap_seal(
            std::slice::from_ref(&create),
            Hlc::new("01970e589d21-0016-a13f9c2e").unwrap(),
            &signer,
            &registry_projection,
        )
        .unwrap();
        let payload: AgentKeyAuthorizePayload = serde_json::from_value(serde_json::json!({
            "agent_id": create.actor_id.signing_principal_id(),
            "key_id": "runtime-key-1",
            "verification_method": "did:webvh:z6mkfixtureagent:agent.example#runtime-key-1",
            "public_key": {
                "kty": "OKP",
                "kid": "did:webvh:z6mkfixtureagent:agent.example#runtime-key-1",
                "algorithm": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "accountable_principal_id": create
                .executed_by
                .as_ref()
                .unwrap()
                .signing_principal_id(),
            "agent_key_scope": {
                "actions": ["ak.message.create"],
                "resources": []
            },
            "audience": ["https://arkret.example"],
            "issued_at": "2026-07-15T00:01:00.000Z",
            "approval_evidence": {
                "kind": "pairing_request",
                "pairing_request_id":
                    "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "request_canonical_digest":
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "approved_by": create
                    .executed_by
                    .as_ref()
                    .unwrap()
                    .signing_principal_id()
            }
        }))
        .unwrap();
        let intent = build_agent_key_authorize_intent(
            &payload,
            ScopeRef::Realm {
                realm_id: create.realm_id.clone(),
            },
            create.actor_id.clone(),
            create.executed_by.clone().unwrap(),
            DidUrl::new(create.authorization_ref.as_ref().unwrap().as_str()).unwrap(),
            "2026-07-15T00:01:00.000Z".parse().unwrap(),
        )
        .unwrap()
        .with_prev_refs(vec![create.event_id.clone()])
        .with_seal_basis(SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        });
        let mut authored = intent
            .author_with_digest_suite(
                1,
                Hlc::new("01970e589d21-0017-a13f9c2e").unwrap(),
                digest_suite,
            )
            .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            signer.verification_method_id(),
            arkret_signatures::SignEventOptions::new(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
            )
            .with_created_at("2026-07-15T00:01:00.000Z".parse().unwrap()),
        )
        .unwrap();
        authored
            .validate_proof_bindings_with_digest_suite(digest_suite)
            .unwrap();
        let authorize = authored.into_event();
        AgentKeyAuthorizePayload::try_from(&authorize).unwrap();

        let units = [
            agent_pcr_genesis_control_unit(&create).unwrap(),
            ordered_control_unit([authorize.clone()], digest_suite),
        ];
        let material = materialize_agent_pcr_control(&units, &registry_projection).unwrap();
        assert_eq!(material.digest_suite, digest_suite);
        assert_eq!(material.state_root.digest_suite().unwrap(), digest_suite);
        assert!(material.event_ops.iter().any(|(cell, _)| {
            cell.as_str()
                .starts_with("ak:cell:ak.component.agent.key.v1:")
        }));

        let authorize_digest = Hash::new(
            authorize
                .event_digest_with_digest_suite(digest_suite)
                .unwrap(),
        )
        .unwrap();
        let covered = material
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let control_event_set_root =
            arkret_state::control_event_set_root(&covered, digest_suite).unwrap();
        let request = SealPrepareRequestBody {
            realm_id: create.realm_id.clone(),
            predecessor_ref: genesis_seal.id,
            event_digests: vec![authorize_digest.clone()],
            hlc: Hlc::new("01970e589d21-0018-a13f9c2e").unwrap(),
        };
        let prepared = SealPrepareOutcome {
            seal_body: UnsignedSeal {
                realm_id: request.realm_id.clone(),
                predecessor_ref: Some(request.predecessor_ref.clone()),
                delta: request.event_digests.clone(),
                control_event_set_root,
                state_root: material.state_root,
                notary_seq: 1,
                availability_receipt_digests: vec![
                    Hash::new(arkret_canonical::digest(
                        digest_suite,
                        b"availability-receipt",
                    ))
                    .unwrap(),
                ],
                covered_event_digests: Vec::new(),
                previous_state_root: None,
                previous_digest_algorithm: None,
                sealed_at: "2026-07-15T00:02:00.000Z".parse().unwrap(),
                hlc: request.hlc.clone(),
                configuration_ref: create.event_id.clone(),
                command_results: vec![material.command_results[1].clone()],
                authorization_closures: Vec::new(),
                existence_anchors: Vec::new(),
            },
            view: 0,
        };
        let seal = prepared.sign(&request, &signer).unwrap();
        seal.validate_id(digest_suite).unwrap();
        assert_eq!(seal.state_root.digest_suite().unwrap(), digest_suite);
        let signature = &seal.notary_signature;
        assert_eq!(
            signature.payload_digest.digest_suite().unwrap(),
            digest_suite
        );
        let public_key = signer.verifying_key().to_bytes();
        let descriptor = NotarySignerDescriptor {
            actor_id: ActorId::service(project_did_to_core_id(&agent_controller_did()).unwrap()),
            verification_method: signer.verification_method_id().clone(),
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret_wire::base64url::base64url_encode(public_key),
        };
        arkret_signatures::verify_frozen_notary_signature(
            signature,
            &descriptor,
            &seal.commit_transcript_bytes(digest_suite).unwrap(),
            digest_suite,
        )
        .unwrap();
    }
}

/// A follow-up Move digested under the declared suite is accepted in both the
/// anchor unit and a later Seal batch; the same Move digested under the other
/// suite is rejected outright rather than silently re-digested.
#[test]
fn agent_pcr_rejects_events_digested_under_an_undeclared_suite() {
    for digest_suite in [
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::DigestSuite::Blake3,
    ] {
        let other = match digest_suite {
            arkret_canonical::DigestSuite::Sha256 => arkret_canonical::DigestSuite::Blake3,
            arkret_canonical::DigestSuite::Blake3 => arkret_canonical::DigestSuite::Sha256,
        };
        let create = agent_pcr_genesis_with_digest_suite(digest_suite);
        let signer = agent_controller_seal_signer();
        let genesis_seal = build_agent_pcr_bootstrap_seal(
            std::slice::from_ref(&create),
            Hlc::new("01970e589d21-0013-a13f9c2e").unwrap(),
            &signer,
            &registry_projection,
        )
        .unwrap();
        let basis = SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        };

        let successor = agent_pcr_follow_up_event(
            &create,
            1,
            "01970e589d21-0015-a13f9c2e",
            digest_suite,
            Some(basis.clone()),
        );
        let projected = [successor.event_id.clone()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let units = [
            agent_pcr_genesis_control_unit(&create).unwrap(),
            ordered_control_unit([successor.clone()], digest_suite),
        ];
        let material =
            materialize_agent_pcr_control(&units, &fixture_successor_projection(&projected))
                .unwrap();
        assert_eq!(material.digest_suite, digest_suite);
        assert_eq!(material.covered_event_digests.len(), 2);
        assert!(
            material.covered_event_digests.contains(
                &Hash::new(
                    successor
                        .event_digest_with_digest_suite(digest_suite)
                        .unwrap()
                )
                .unwrap()
            )
        );

        let mismatched =
            agent_pcr_follow_up_event(&create, 1, "01970e589d21-0014-a13f9c2e", other, Some(basis));
        let projected = [mismatched.event_id.clone()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let units = [
            agent_pcr_genesis_control_unit(&create).unwrap(),
            ordered_control_unit([mismatched], other),
        ];
        let error =
            materialize_agent_pcr_control(&units, &fixture_successor_projection(&projected))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("suite the genesis did not declare"),
            "unexpected rejection: {error}"
        );
    }
}

#[test]
fn agent_provision_event_projects_the_registered_atomic_cells() {
    let controller_did = Did::new("did:webvh:z6mkfixture:controller.example").unwrap();
    let controller = DidCoreId::new("ak:did_core:webvh:z6mkfixture:controller.example").unwrap();
    let agent = DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent.example").unwrap();
    let intent = build_agent_provision_intent(
        &controller,
        &fixture_realm(1),
        &agent,
        &fixture_realm(2),
        &DidUrl::new(format!("{controller_did}#agent")).unwrap(),
        "summary",
        &Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        HandleVisibility::Private,
        None,
        AgentProvisionIntentOptions {
            controller_station_id: DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            created_at: "2026-07-18T01:02:03Z".parse().unwrap(),
            seal_basis: Some(SealBasis {
                leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap()],
            }),
        },
    )
    .unwrap();
    // The registered cells are subject-keyed, but the OR-Set dots are the
    // Event's own, so the projection runs on the finalized envelope.
    let event = intent
        .with_prev_refs(vec![fixture_event_id(3)])
        .author_with_digest_suite(
            4,
            Hlc::new("01980a8f3980-0001-a13f9c2e").unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("the provision intent finalizes");

    let payload: AgentProvisionPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    payload.validate().unwrap();
    assert_eq!(payload.agent_id, agent);
    assert_eq!(
        event.actor_id.route_service_id().as_str(),
        "ak:did_core:web:principal.example"
    );
    assert_ne!(event.actor_id.route_service_id(), &controller);
    let effects = direct_projection(&event, &registry_projection).unwrap();
    assert_eq!(
        effects
            .iter()
            .map(|effect| effect.cell_id.as_str().to_owned())
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
                // The accountability record is keyed by the digested scope set,
                // not by the raw scope string, so a provision and a standalone
                // grant of the same endorsement address one cell.
                composite_subject(&[
                    controller.as_str(),
                    agent.as_str(),
                    &arkret_wire::string_set_digest_component(
                        &["agent_operator".to_owned()],
                        arkret_wire::DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1,
                    )
                    .unwrap(),
                ])
                .unwrap()
            ),
            format!(
                "ak:cell:ak.component.agent.selector_claim.v1:{}",
                composite_subject(&[controller.as_str(), "summary"]).unwrap()
            ),
        ])
    );

    assert_eq!(
        serde_json::to_value(event.as_ref()).unwrap()["created_at"],
        "2026-07-18T01:02:03.000Z"
    );
}
