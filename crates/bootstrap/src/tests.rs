use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::http_bodies::EventsSubmitRequestBody;
use arkret_models_identity::artifacts_device_identity::{
    DeviceEnrollmentAuthorityBinding, DeviceEnrollmentAuthorityBindingKind,
};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    AnchorUnitLeaseBasis, AnchorUnitLeaseBasisRef, AuthoritySetAuthorizationRule,
    AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicyKind,
    AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind, AuthorizationLease,
    AuthorizationLeaseId, AuthorizationRef, CellRef, DeviceId, Did, DidUrl, Event, EventId,
    EventInitialSubmission, EventKind, EventRef, Hash, Hlc, LeaseBasisRef, NonEmptyString,
    NotarySig, PayloadProof, PayloadSignature, PayloadSigner, ProjectedCellWrite, Proof, RealmId,
    RiskTier, SchemaId, ScopeRef, SealBasis, SealId, SemanticRefProof, SemanticRefProofKind,
    TypedTrustDomainId, WireError, composite_subject, proof_kind,
};
use chrono::Utc;
use serde_json::Value;

use crate::projection::direct_projection;
use crate::self_principal::validate_self_principal_pcr_create;
use crate::{
    AgentProvisionEventDraftOptions, DID_INCEPTION_REF_ROLE, ManagedAgentPcrCreatePayloadInput,
    ManagedAgentPcrGenesisAuthority, PRINCIPAL_CONTROL_PURPOSE, REALM_AUTHORITY_ROOT_CELL,
    REALM_CREATE_CELL, REALM_METADATA_CELL, REALM_NOTARY_CELL, REALM_REDUCER_PROFILE_CELL,
    SelfPrincipalPcrCreateInput, build_agent_provision_event_draft,
    build_managed_agent_pcr_create_payload, build_managed_agent_pcr_event_seal,
    build_self_principal_bootstrap_seal, build_self_principal_pcr_create,
    materialize_managed_agent_pcr_control, self_principal_bootstrap_submit_request,
    validate_self_principal_bootstrap_unit,
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
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
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
    let mut create = build_self_principal_pcr_create(input(), &registry_projection).unwrap();
    attach_fixture_proof(
        &mut create,
        &DidUrl::new(
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        )
        .unwrap(),
    );

    let authority = Did::new("did:key:z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh").unwrap();
    let authorization_ref =
        NonEmptyString::new(format!("{}#enrollment-authority", create.actor_id)).unwrap();
    let payload = DeviceAuthorizePayload {
        principal_id: create.actor_id.clone(),
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        device_public_key: NonEmptyString::new("z6MkDeviceKey").unwrap(),
        hpke_key: NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Did(authority.clone()),
        scopes: None,
        not_before: create.created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(DeviceEnrollmentAuthorityBinding {
            kind: DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: authority.clone(),
            authorization_ref: authorization_ref.clone(),
        }),
        recovery_session_id: None,
    };
    let mut authorize = Event::new(
        EventKind::DEVICE_AUTHORIZE,
        // The genesis scope belongs to the create alone; the first authorize is
        // an ordinary Control Move inside the Realm the create just named.
        arkret_wire::ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        serde_json::to_value(payload).unwrap(),
    )
    .unwrap();
    authorize.event_id = EventId::new("ak:event:01904100-0000-8000-8000-000000000002").unwrap();
    authorize.created_at = create.created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.executed_by = Some(authority.clone());
    authorize.authorization_ref =
        Some(AuthorizationRef::new(authorization_ref.to_string()).unwrap());
    attach_fixture_proof(
        &mut authorize,
        &DidUrl::new(format!(
            "{authority}#z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh"
        ))
        .unwrap(),
    );
    (create, authorize)
}

fn input() -> SelfPrincipalPcrCreateInput {
    let principal_id = Did::new("did:webvh:z6mkfixture:users.example:alice").unwrap();
    SelfPrincipalPcrCreateInput {
        realm_id: RealmId::new(principal_control_realm_id(&principal_id)).unwrap(),
        principal_id,
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        did_inception_ref: EventRef::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DID_INCEPTION_REF_ROLE,
        ),
        capability_action_registry_digest: Hash::new(format!("sha256:{}", "9a".repeat(32)))
            .unwrap(),
        event_id: EventId::new("ak:event:01904100-0000-8000-8000-000000000001").unwrap(),
        created_at: "2026-07-15T00:00:00.000Z".parse().unwrap(),
        hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    }
}

#[test]
fn builder_emits_only_the_closed_unsigned_root_shape() {
    let event = build_self_principal_pcr_create(input(), &registry_projection).unwrap();

    assert_eq!(event.kind, EventKind::REALM_CREATE);
    assert_eq!(event.actor_seq, 0);
    assert!(event.prev_refs.is_empty());
    assert!(event.proofs.is_empty());
    assert_eq!(event.refs.len(), 1);
    assert_eq!(event.refs[0].role, DID_INCEPTION_REF_ROLE);
    // A genesis envelope carries no realm_id and uses the closed genesis
    // scope; the Realm id is derived (subject-derived for a PCR).
    assert_eq!(event.scope_ref, arkret_wire::ScopeRef::RealmGenesis);
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
            REALM_METADATA_CELL.to_owned(),
            format!(
                "ak:cell:ak.component.member.state.v1:{}",
                event.actor_id.as_str()
            ),
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
fn builder_rejects_a_non_self_realm_and_indirect_inception_ref() {
    let mut wrong_realm = input();
    wrong_realm.realm_id = RealmId::new("ak:realm:01904100-0000-8000-8000-000000000002").unwrap();
    assert!(build_self_principal_pcr_create(wrong_realm, &registry_projection).is_err());

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
    validate_self_principal_bootstrap_unit(&create, &authorize, &registry_projection).unwrap();
    let [create_submission, authorize_submission] = submissions(create.clone(), authorize.clone());
    let request = self_principal_bootstrap_submit_request(
        create_submission,
        authorize_submission,
        &registry_projection,
    )
    .unwrap();
    let EventsSubmitRequestBody::Batch(batch) = request else {
        panic!("the bootstrap unit is always a two-slot batch")
    };
    assert_eq!(batch.events.len(), 2);

    let [mut lease_free_create, leased_authorize] = submissions(create.clone(), authorize.clone());
    lease_free_create.authorization_lease = None;
    let error = self_principal_bootstrap_submit_request(
        lease_free_create,
        leased_authorize,
        &registry_projection,
    )
    .expect_err("bootstrap must not regress to lease-free online submissions");
    assert!(error.to_string().contains("complete anchor-unit"));

    let mut missing = authorize.clone();
    missing.prev_refs.clear();
    assert!(
        validate_self_principal_bootstrap_unit(&create, &missing, &registry_projection).is_err()
    );

    let mut unrelated = authorize;
    unrelated.prev_refs = vec![
        create.event_id.clone(),
        EventId::new("ak:event:01904100-0000-8000-8000-000000000099").unwrap(),
    ];
    assert!(
        validate_self_principal_bootstrap_unit(&create, &unrelated, &registry_projection).is_err()
    );
}

/// Complete lease-bound wrappers for the ordered genesis unit.
fn submissions(create: Event, authorize: Event) -> [EventInitialSubmission; 2] {
    let event_digests = [&create, &authorize]
        .into_iter()
        .map(|event| Hash::new(event.event_digest().unwrap()).unwrap())
        .collect::<Vec<_>>();
    let mut anchor_unit = AnchorUnitLeaseBasis {
        realm_id: create.realm_id.clone(),
        event_digests,
        unit_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
    };
    anchor_unit.unit_digest = anchor_unit.expected_unit_digest().unwrap();
    [
        submission(create, anchor_unit.clone(), "0000000000f1"),
        submission(authorize, anchor_unit, "0000000000f2"),
    ]
}

fn submission(
    event: Event,
    anchor_unit: AnchorUnitLeaseBasis,
    lease_suffix: &str,
) -> EventInitialSubmission {
    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: event.event_id.as_str().to_owned(),
            source_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec!["ak.realm.admin".to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new(format!("{}#bootstrap-authority", event.actor_id))
                    .unwrap(),
            }],
            threshold: 1,
        }],
    };
    let mut lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(format!(
            "ak:authorization_lease:01904100-0000-7000-8000-{lease_suffix}"
        ))
        .unwrap(),
        basis_ref: LeaseBasisRef::AnchorUnit(AnchorUnitLeaseBasisRef { anchor_unit }),
        actor_id: event.actor_id.clone(),
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        scope_ref: event.scope_ref.clone(),
        action: "ak.realm.admin".to_owned(),
        authorization_rule_id: "realm_admission".to_owned(),
        risk_tier: RiskTier::High,
        issued_at: event.created_at,
        expires_at: event.created_at + chrono::Duration::minutes(5),
        authority_set_ref: AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        },
        authority_set_policy,
        proofs: Vec::new(),
    };
    lease.proofs = vec![PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new(format!("{}#bootstrap-authority", event.actor_id))
            .unwrap(),
        payload_digest: lease.lease_digest().unwrap(),
        created_at: lease.issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "fixture.detached-signature".to_owned(),
    }];
    EventInitialSubmission {
        event,
        authorization_lease: Some(lease),
        cba_proof_bundles: Vec::new(),
        control_proposal_receipt: None,
        membership_compensation_evidence: None,
    }
}

#[test]
fn first_bootstrap_seal_covers_both_events_and_is_signed_by_device_one() {
    let (create, authorize) = bootstrap_unit();
    let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
    let signer = FixtureSigner {
        did: create.actor_id.clone(),
        verification_method: DidUrl::new(format!("{}#{device_id}", create.actor_id)).unwrap(),
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
    let realm_id = RealmId::new("ak:realm:01904100-0000-8000-8000-0000000000a1").unwrap();
    let agent = Did::new("did:web:agent.example").unwrap();
    let controller = Did::new("did:web:controller.example").unwrap();
    let mut create = Event::new(
        EventKind::REALM_CREATE,
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        agent.clone(),
        0,
        Hlc::new("01970e589d21-0007-a13f9c2e").unwrap(),
        serde_json::json!({
            "object": {
                "id": realm_id,
                "created_by": agent,
                "fields": {"purpose": "principal_control"},
                "notary": {"kind": "single_did", "did": agent},
                "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
                "capability_action_registry_digest": format!("sha256:{}", "9a".repeat(32)),
            }
        }),
    )
    .unwrap();
    create.event_id = EventId::new("ak:event:01904100-0000-8000-8000-0000000000a1").unwrap();
    create.authorization_ref =
        Some(AuthorizationRef::new(format!("{agent}#managed-controller")).unwrap());
    create.executed_by = Some(controller);
    create.refs = vec![EventRef::new(
        "ak:event:01904100-0000-8000-8000-0000000000a0",
        "agent_provision",
    )];
    create
}

#[test]
fn managed_agent_pcr_payload_is_built_from_the_public_realm_type() {
    let payload = build_managed_agent_pcr_create_payload(ManagedAgentPcrCreatePayloadInput {
        agent_id: Did::new("did:web:agent.example".to_owned()).unwrap(),
        controller_id: Did::new("did:web:controller.example".to_owned()).unwrap(),
        realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-0000000000a1").unwrap(),
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
        value
            .pointer("/object/fields/purpose")
            .and_then(Value::as_str),
        Some(PRINCIPAL_CONTROL_PURPOSE)
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
            .collect::<Vec<_>>(),
        vec![
            "ak:cell:ak.component.agent.status.v1:did:web:agent.example",
            "ak:cell:ak.component.member.state.v1:did:web:agent.example",
            REALM_NOTARY_CELL,
            REALM_AUTHORITY_ROOT_CELL,
            REALM_CREATE_CELL,
            REALM_METADATA_CELL,
            REALM_REDUCER_PROFILE_CELL,
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

    let mut later_transition = Event::new(
        EventKind::MLS_GENESIS,
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
    let controller = create.executed_by.clone().unwrap();
    let mut anchor = Event::new(
        EventKind::MLS_GENESIS,
        create.scope_ref.clone(),
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-0008-a13f9c2e").unwrap(),
        serde_json::json!({}),
    )
    .unwrap();
    anchor.event_id = EventId::new("ak:event:01904100-0000-8000-8000-0000000000a2").unwrap();
    anchor.executed_by = Some(controller.clone());
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
fn managed_agent_successor_resolves_registered_patch_from_frozen_predecessor() {
    let create = managed_agent_pcr_create();
    let controller = create.executed_by.clone().unwrap();
    let signer = FixtureSigner {
        did: controller.clone(),
        verification_method: DidUrl::new(format!(
            "{controller}#ak:device:01904100-0000-7000-8000-0000000000b1"
        ))
        .unwrap(),
    };
    let first = build_managed_agent_pcr_event_seal(
        std::slice::from_ref(&create),
        None,
        Hlc::new("01970e589d21-000b-a13f9c2e").unwrap(),
        &signer,
        &registry_projection,
    )
    .unwrap();

    let mut update = Event::new(
        EventKind::REALM_UPDATE,
        create.scope_ref.clone(),
        create.actor_id.clone(),
        1,
        Hlc::new("01970e589d21-000c-a13f9c2e").unwrap(),
        serde_json::json!({
            "patch": {
                "fields.name": "renamed managed Agent"
            }
        }),
    )
    .unwrap();
    update.event_id = EventId::new("ak:event:01904100-0000-8000-8000-0000000000b2").unwrap();
    update.executed_by = Some(controller);
    update.authorization_ref = create.authorization_ref.clone();
    update.seal_basis = Some(first.seal_basis());

    let material = materialize_managed_agent_pcr_control(
        &[create.clone(), update.clone()],
        &registry_projection,
    )
    .unwrap();
    let metadata = CellRef::new(REALM_METADATA_CELL).unwrap();
    let arkret_state::CellState::Value(patched) = material.joined.get(&metadata).unwrap() else {
        panic!("managed Agent metadata must remain a live register")
    };
    assert_eq!(patched["fields"]["name"], "renamed managed Agent");
    assert_eq!(patched["fields"]["purpose"], PRINCIPAL_CONTROL_PURPOSE);

    let successor = build_managed_agent_pcr_event_seal(
        &[create, update.clone()],
        Some(&first),
        Hlc::new("01970e589d21-000d-a13f9c2e").unwrap(),
        &signer,
        &registry_projection,
    )
    .unwrap();
    assert_eq!(successor.delta.len(), 1);
    assert_eq!(successor.delta[0].as_str(), update.event_digest().unwrap());
    assert_ne!(successor.state_root, first.state_root);
}

#[test]
fn managed_agent_provision_event_projects_the_registered_atomic_cells() {
    let controller = Did::new("did:webvh:z6mkfixture:controller.example").unwrap();
    let agent = Did::new("did:webvh:z6mkfixture:agent.example").unwrap();
    let event = build_agent_provision_event_draft(
        &controller,
        &RealmId::new("ak:realm:01904100-0000-8000-8000-000000000001").unwrap(),
        &agent,
        &RealmId::new("ak:realm:01904100-0000-8000-8000-000000000002").unwrap(),
        &DidUrl::new(format!("{controller}#managed-agent")).unwrap(),
        "summary",
        &Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        HandleVisibility::Private,
        None,
        AgentProvisionEventDraftOptions {
            created_at: "2026-07-18T01:02:03Z".parse().unwrap(),
            actor_seq: 4,
            hlc: Hlc::new("01980a8f3980-0001-a13f9c2e").unwrap(),
            prev_refs: vec![EventId::new("ak:event:01904100-0000-8000-8000-000000000003").unwrap()],
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
