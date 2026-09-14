use arkret_models_collaboration::events_payloads::*;
use arkret_models_identity::{AuthenticatedSignerResolutionEvidence, ResolutionCommitment};
use arkret_wire::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use super::*;

fn hash(label: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(label.as_bytes())).unwrap()
}
fn device(index: u8) -> DeviceId {
    DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{index:012}")).unwrap()
}
fn at() -> DateTime<Utc> {
    "2026-09-12T00:00:00Z".parse().unwrap()
}
fn hlc(sequence: usize) -> Hlc {
    Hlc::new(format!("0198d35d9800-{sequence:04x}-a13f9c2e")).unwrap()
}
fn project(event: &Event) -> std::result::Result<Vec<ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}
fn possession(
    account: &AccountId,
    index: u8,
    binding: DeviceAuthorizationBindingKind,
) -> DeviceAuthorizePayload {
    let key = SigningKey::from_bytes(&[80 + index; 32]);
    let public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend([index; 32]);
    let mut unsigned = UnsignedDeviceAuthorizePayload::new(
        device(index),
        NonEmptyString::new(format!("did:key:{public}")).unwrap(),
        NonEmptyString::new(arkret_canonical::encode_multibase_base58btc(hpke)).unwrap(),
        vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        Some(NonEmptyString::new("Ed25519").unwrap()),
        if binding == DeviceAuthorizationBindingKind::AcceptedDevice {
            DeviceOrPrincipalRef::DeviceId(device(1))
        } else {
            DeviceOrPrincipalRef::Principal(account.principal_id.clone())
        },
        None,
        at(),
        None,
        binding,
        (binding == DeviceAuthorizationBindingKind::PcrRecovery).then(|| {
            RecoverySessionId::new("ak:recovery_session:01904100-0000-7000-8000-000000000002")
                .unwrap()
        }),
    )
    .unwrap();
    if binding == DeviceAuthorizationBindingKind::AcceptedDevice {
        unsigned = unsigned.with_pairing_challenge_transcript_digest(hash("pairing"));
    }
    let bytes = unsigned.device_possession_signature_input(account).unwrap();
    unsigned
        .attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode(
                key.sign(&bytes).to_bytes(),
            ))
            .unwrap(),
        )
        .unwrap()
}
fn sign_event(event: Event, method: DidUrl, seed: [u8; 32]) -> Event {
    sign_event_with_evidence(event, method, seed, None)
}
fn sign_event_with_evidence(
    mut event: Event,
    method: DidUrl,
    seed: [u8; 32],
    signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
) -> Event {
    event.proofs.clear();
    event
        .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.into(),
        verification_method: method,
        event_digest: event.event_id.event_digest(),
        signer_resolution_evidence_ref,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
        &SigningKey::from_bytes(&seed),
    )
    .unwrap();
    event.proofs.push(proof);
    event
}
struct Fixture {
    account: AccountId,
    did: Did,
    configuration: NotaryValue,
    inception: arkret_models_identity::DidOperationSubmitRequestBody,
    events: Vec<Event>,
    seals: Vec<Seal>,
    state: BTreeMap<CellRef, ResolvedCellState>,
    covered: BTreeSet<Hash>,
}
impl Fixture {
    // The test independently pins this initial configuration. It exercises
    // real Seal/possession signatures and replay, not registration DID trust.
    fn new() -> Self {
        let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
        );
        let prepared = arkret_signatures::webvh::prepare_principal_inception(
            &arkret_signatures::webvh::PrincipalInceptionInput {
                provider_endpoint: &"https://principal.example/".parse().unwrap(),
                principal_endpoint: &"https://principal.example/".parse().unwrap(),
                local_id: "alice",
                also_known_as: &[],
                version_time: at(),
                root_seed: &[70; 32],
                next_root_public_key_multibase: &next_root,
                witness_policy: None,
            },
        )
        .unwrap();
        let verified_root =
            arkret_signatures::webvh::validate_principal_inception_operation(&prepared.submit_body)
                .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let account = AccountId::new(
            project_did_to_core_id(&did).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let payload = possession(
            &account,
            1,
            DeviceAuthorizationBindingKind::RegistrationAnchor,
        );
        let key = SigningKey::from_bytes(&[81; 32]);
        let configuration = NotaryValue::new(
            NotarySignerDescriptor {
                actor_id: ActorId::account(account.clone()),
                verification_method: DidUrl::new(format!("{did}#{}", device(1))).unwrap(),
                key_kind: NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: arkret_canonical::base64url_encode(
                    key.verifying_key().to_bytes(),
                ),
            },
            0,
        )
        .unwrap();
        let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
        );
        let mut inception = EventRef::new(
            verified_root.did_version_id.clone(),
            arkret_bootstrap::DID_INCEPTION_REF_ROLE,
        );
        inception.critical = true;
        let create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: account.principal_id.clone(),
                station_id: account.station_id.clone(),
                principal_did: did.clone(),
                notary: configuration.clone(),
                genesis_salt: GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                did_inception_ref: inception,
                initial_resolution: ResolutionCommitment {
                    did: did.clone(),
                    method_history_head: verified_root.log_head_digest.to_string(),
                    version_id: verified_root.did_version_id.clone(),
                },
                founding_device_descriptor: FoundingDeviceDescriptor {
                    descriptor_version: 1,
                    device_id: payload.device_id.clone(),
                    device_public_key_did: payload.device_public_key_did.clone(),
                    device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
                    device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
                    hpke_key: payload.hpke_key.clone(),
                    hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
                    algorithms: payload.algorithms.clone(),
                    founding_authorize_payload_digest: typed_device_authorize_payload_digest(
                        &payload,
                        DigestSuite::Sha256,
                    )
                    .unwrap(),
                },
                created_at: at(),
                hlc: hlc(0),
            },
            &project,
        )
        .unwrap()
        .into_event();
        let create = sign_event(
            create,
            DidUrl::new(format!("did:key:{root}#{root}")).unwrap(),
            [70; 32],
        );
        let mut fixture = Self {
            account,
            did,
            configuration,
            inception: prepared.submit_body,
            events: Vec::new(),
            seals: Vec::new(),
            state: BTreeMap::new(),
            covered: BTreeSet::new(),
        };
        let mut authorize = fixture.raw_event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).unwrap(),
            &create.realm_id,
            1,
        );
        authorize.prev_refs = vec![create.event_id.clone()];
        authorize = sign_event(
            authorize,
            fixture.configuration.signer.verification_method.clone(),
            [81; 32],
        );
        fixture.append(vec![create, authorize]);
        fixture
    }
    fn raw_event(
        &self,
        kind: EventKind,
        payload: serde_json::Value,
        realm: &RealmId,
        sequence: u64,
    ) -> Event {
        let mut event = test_support::raw_event_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            self.account.principal_id.clone(),
            self.account.station_id.clone(),
            sequence,
            hlc(sequence as usize),
            payload,
            at(),
        )
        .unwrap();
        event.seal_basis = self.seals.last().map(|seal| SealBasis {
            leaves: vec![seal.id.clone()],
        });
        event.auth_context = None;
        event.unsigned.clear();
        event
    }
    fn event(&self, kind: EventKind, payload: serde_json::Value) -> Event {
        let mut event = self.raw_event(
            kind,
            payload,
            &self.events[0].realm_id,
            self.events.len() as u64,
        );
        event.prev_refs = vec![self.events.last().unwrap().event_id.clone()];
        sign_event(
            event,
            self.configuration.signer.verification_method.clone(),
            [81; 32],
        )
    }
    fn append(&mut self, events: Vec<Event>) {
        let registry = arkret_lattice_registry::try_build_sdk_state_registry().unwrap();
        let unit = OrderedControlUnit {
            events: events
                .iter()
                .map(|event| OrderedControlUnitEvent {
                    digest: event.event_id.event_digest(),
                    event: event.clone(),
                    digest_suite: DigestSuite::Sha256,
                })
                .collect(),
        };
        let batch = arkret_state::execute_ordered_control_units(
            &events[0].realm_id,
            &self.state,
            &registry,
            &[unit],
            DigestSuite::Sha256,
            self.seals.is_empty(),
            |member, stage, _| {
                let projection = crate::project_control_writes_at_state(
                    &member.event,
                    DigestSuite::Sha256,
                    stage,
                )
                .unwrap();
                let effects = projection
                    .writes
                    .iter()
                    .flat_map(|write| {
                        arkret_state::resolve_projected_write(
                            write,
                            &member.event.realm_id,
                            stage,
                            &registry,
                        )
                        .unwrap()
                    })
                    .collect();
                Ok(CommandEventResult::Applied(effects))
            },
        )
        .unwrap();
        self.covered
            .extend(batch.committed_event_digests.iter().cloned());
        let body = UnsignedSeal {
            realm_id: events[0].realm_id.clone(),
            predecessor_ref: self.seals.last().map(|seal| seal.id.clone()),
            delta: batch.committed_event_digests,
            control_event_set_root: arkret_state::control_event_set_root(
                &self.covered,
                DigestSuite::Sha256,
            )
            .unwrap(),
            data_delta: vec![],
            data_event_set_root: arkret_wire::empty_data_event_set_root(DigestSuite::Sha256)
                .unwrap(),
            state_root: arkret_state::compute_state_root(
                arkret_state::GovernanceView::new(&batch.post_state),
                DigestSuite::Sha256,
            )
            .unwrap(),
            notary_seq: self.seals.len() as u64,
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: at(),
            hlc: hlc(self.seals.len() + 10),
            configuration_ref: self
                .events
                .first()
                .map(|event| event.event_id.clone())
                .unwrap_or_else(|| events[0].event_id.clone()),
            command_results: batch.command_results,
            authorization_closures: vec![],
            data_closure_announcements: vec![],
            data_closures: vec![],
            existence_anchors: vec![],
        };
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [81; 32],
            self.did.clone(),
            self.configuration.signer.verification_method.clone(),
        );
        let seal = Seal::sign_with_signer(body, DigestSuite::Sha256, &signer).unwrap();
        self.state = batch.post_state;
        self.seals.push(seal);
        self.events.extend(events);
    }
    fn verify(&self) -> super::Result<DeviceAuthorizationHistory> {
        DeviceAuthorizationHistory::verify(
            &self.account,
            &self.events[0].event_id,
            &self.configuration,
            &self.inception,
            &self.seals.last().unwrap().id,
            &self.seals,
            &self.events,
            DigestSuite::Sha256,
        )
    }
    fn control_evidence(
        &self,
        authorization_event_ref: EventId,
    ) -> AuthenticatedSignerResolutionEvidence {
        let history = self.verify().unwrap();
        history
            .account_device_control_evidence(
                &authorization_event_ref,
                &self.inception,
                &self.seals,
                &self.events,
                DigestSuite::Sha256,
            )
            .unwrap()
    }
    fn reanchor(&self, null_basis: bool) -> Vec<Event> {
        let payload = possession(
            &self.account,
            3,
            DeviceAuthorizationBindingKind::PcrRecovery,
        );
        let previous = self.seals.last().unwrap();
        let reanchor=self.event(EventKind::DeviceReanchor,json!({
            "account_id":self.account,"recovery_authority_kind":"pcr_policy","recovery_policy_id":"ak:policy:01904100-0000-7000-8000-000000000001",
            "recovery_policy_version":1,"recovery_session_id":"ak:recovery_session:01904100-0000-7000-8000-000000000002",
            "previous_device_generation":1,"new_device_generation":2,
            "pre_fence_seal_frontier":if null_basis {serde_json::Value::Null} else {json!({"leaves":[previous.id],"state_root":previous.state_root,"control_event_set_root":previous.control_event_set_root})},
            "replacement_authorize_payload_digest":typed_device_authorize_payload_digest(&payload,DigestSuite::Sha256).unwrap(),
        }));
        let reanchor = sign_event(
            reanchor,
            DidUrl::new(format!("{}#{}", self.did, device(3))).unwrap(),
            [83; 32],
        );
        let mut authorize = self.event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).unwrap(),
        );
        authorize.actor_seq = reanchor.actor_seq + 1;
        authorize.prev_refs = vec![reanchor.event_id.clone()];
        authorize = sign_event(
            authorize,
            DidUrl::new(format!("{}#{}", self.did, device(3))).unwrap(),
            [83; 32],
        );
        vec![reanchor, authorize]
    }
}

#[test]
fn device_history_authenticates_genesis_and_exact_authorize_revoke_instances() {
    let mut f = Fixture::new();
    let initial = f.verify().unwrap();
    assert_eq!(initial.current_generation().number(), 1);
    assert_eq!(initial.authorizations().len(), 1);
    let added = f.event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(possession(
            &f.account,
            2,
            DeviceAuthorizationBindingKind::AcceptedDevice,
        ))
        .unwrap(),
    );
    let added_id = added.event_id.clone();
    f.append(vec![added]);
    let revoke=f.event(EventKind::DeviceRevoke,json!({"device_id":device(2),"revoked_by":device(1),"revoked_at":"2026-09-12T00:00:00.000Z","reason":"user_requested"}));
    let revoke_id = revoke.event_id.clone();
    f.append(vec![revoke]);
    let verified = f.verify().unwrap();
    let source = verified.authorization(&added_id).unwrap();
    assert_eq!(source.authorized_generation_ref(), 1);
    assert_eq!(source.revoked_by(), Some(&revoke_id));
    assert!(!verified.is_currently_active(source));
    assert!(verified.is_currently_active(&verified.authorizations()[0]));
}

#[test]
fn device_history_reanchor_fences_old_generation_without_rewriting_authorize_origins() {
    let mut f = Fixture::new();
    let old = f.events[1].event_id.clone();
    let events = f.reanchor(false);
    let generation = events[0].event_id.clone();
    let replacement = events[1].event_id.clone();
    f.append(events);
    let verified = f.verify().unwrap();
    assert_eq!(verified.current_generation().number(), 2);
    assert_eq!(
        verified.current_generation().authorization_event_id(),
        &f.events[0].event_id
    );
    assert_eq!(
        verified.current_generation().generation_event_id(),
        &generation
    );
    assert_eq!(verified.generations()[0].closed_by(), Some(&generation));
    assert_eq!(
        verified
            .authorization(&old)
            .unwrap()
            .authorized_generation_ref(),
        1
    );
    assert!(!verified.is_currently_active(verified.authorization(&old).unwrap()));
    assert!(verified.is_currently_active(verified.authorization(&replacement).unwrap()));
}

#[test]
fn device_history_rejects_missing_member_foreign_account_and_tampered_source_or_result() {
    let mut f = Fixture::new();
    let founding = f.events.pop().unwrap();
    assert!(f.verify().is_err());
    f.events.push(founding);
    let mut foreign = f.account.clone();
    foreign.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(
        DeviceAuthorizationHistory::verify(
            &foreign,
            &f.events[0].event_id,
            &f.configuration,
            &f.inception,
            &f.seals[0].id,
            &f.seals,
            &f.events,
            DigestSuite::Sha256
        )
        .is_err()
    );
    let original = f.seals[0].notary_signature.jws.clone();
    f.seals[0].notary_signature.jws.push('x');
    assert!(f.verify().is_err());
    f.seals[0].notary_signature.jws = original;
    f.events[1]
        .payload
        .insert("device_id".into(), json!(device(9)));
    assert!(f.verify().is_err());
}

#[test]
fn device_history_recovery_first_requires_real_anchor_and_never_guesses_generation() {
    let mut f = Fixture::new();
    let events = f.reanchor(true);
    f.append(events);
    assert!(matches!(
        f.verify(),
        Err(HistoryEvidenceError::Unavailable(_))
    ));
}

#[test]
fn device_history_rejects_changed_producer_proof_without_changing_content_identity() {
    let mut f = Fixture::new();
    for index in 0..2 {
        let before = f.events[index].event_id.clone();
        let proof = f.events[index].proofs[0].clone();
        f.events[index].proofs[0].jws.push('x');
        f.events[index]
            .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        assert_eq!(f.events[index].event_id, before);
        assert!(matches!(f.verify(), Err(HistoryEvidenceError::Invalid(_))));
        f.events[index].proofs[0] = proof;
    }
    let mut replacement = f.reanchor(false);
    replacement[0] = sign_event(
        replacement[0].clone(),
        f.configuration.signer.verification_method.clone(),
        [81; 32],
    );
    f.append(replacement);
    assert!(matches!(f.verify(), Err(HistoryEvidenceError::Invalid(_))));
}

#[test]
fn device_history_rejects_fenced_and_revoked_producers_even_with_valid_event_signatures() {
    let mut fenced = Fixture::new();
    fenced.append(fenced.reanchor(false));
    let stale = fenced.event(EventKind::DeviceRevoke,
        json!({"device_id":device(3),"revoked_by":device(1),"revoked_at":"2026-09-12T00:00:00.000Z","reason":"user_requested"}));
    fenced.append(vec![stale]);
    assert!(matches!(
        fenced.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));

    let mut revoked = Fixture::new();
    let revoke = revoked.event(EventKind::DeviceRevoke,
        json!({"device_id":device(1),"revoked_by":device(1),"revoked_at":"2026-09-12T00:00:00.000Z","reason":"user_requested"}));
    revoked.append(vec![revoke]);
    let stale = revoked.event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(possession(
            &revoked.account,
            2,
            DeviceAuthorizationBindingKind::AcceptedDevice,
        ))
        .unwrap(),
    );
    revoked.append(vec![stale]);
    assert!(matches!(
        revoked.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn device_history_new_authorization_does_not_revive_the_revoked_instance() {
    let mut f = Fixture::new();
    let payload = possession(
        &f.account,
        2,
        DeviceAuthorizationBindingKind::AcceptedDevice,
    );
    let first = f.event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(&payload).unwrap(),
    );
    let first_id = first.event_id.clone();
    f.append(vec![first]);
    let revoke = f.event(EventKind::DeviceRevoke,
        json!({"device_id":device(2),"revoked_by":device(1),"revoked_at":"2026-09-12T00:00:00.000Z","reason":"user_requested"}));
    f.append(vec![revoke]);
    let replacement = f.event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(&payload).unwrap(),
    );
    let replacement_id = replacement.event_id.clone();
    f.append(vec![replacement]);
    let history = f.verify().unwrap();
    assert!(!history.is_currently_active(history.authorization(&first_id).unwrap()));
    assert!(history.is_currently_active(history.authorization(&replacement_id).unwrap()));
    assert_eq!(
        history.authorization(&first_id).unwrap().public_key(),
        history.authorization(&replacement_id).unwrap().public_key()
    );
    assert_ne!(first_id, replacement_id);
}

#[test]
fn account_device_control_replays_exact_prefix_and_authorizes_only_control() {
    let f = Fixture::new();
    let evidence = f.control_evidence(f.events[1].event_id.clone());
    let verified = DeviceAuthorizationHistory::verify_account_device_control(
        &evidence,
        &f.seals,
        &f.events,
        DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(verified.authorization_event_id(), &f.events[1].event_id);
    assert_eq!(
        verified.public_key(),
        &SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes()
    );
    assert!(verified.authorization_contains(at()));

    let source = crate::historical_producer::AuthenticatedHistoricalProducerSource::authenticate_account_device_control(
        &evidence.evidence_ref().unwrap(),
        &ActorId::account(f.account.clone()),
        &evidence,
        &f.seals,
        &f.events,
        DigestSuite::Sha256,
    )
    .unwrap();
    let candidate = f.event(
        EventKind::DeviceRevoke,
        json!({
            "device_id": device(1),
            "revoked_by": device(1),
            "revoked_at": "2026-09-12T00:00:00.000Z",
            "reason": "user_requested"
        }),
    );
    let candidate = sign_event_with_evidence(
        candidate,
        evidence.verification_method().clone(),
        [81; 32],
        Some(evidence.evidence_ref().unwrap()),
    );
    source
        .verify_event(&candidate, DigestSuite::Sha256)
        .unwrap();

    let data = f.raw_event(
        EventKind::MessageCreate,
        json!({"message_id":"m1","content":{"type":"text","body":"hello"}}),
        &f.events[0].realm_id,
        99,
    );
    let data = sign_event_with_evidence(
        data,
        evidence.verification_method().clone(),
        [81; 32],
        Some(evidence.evidence_ref().unwrap()),
    );
    assert!(source.verify_event(&data, DigestSuite::Sha256).is_err());

    assert!(
        arkret_models_identity::ed25519_notary_signer_descriptor_from_evidence(&evidence).is_err()
    );
    let method = evidence.verification_method().clone();
    let reference = evidence.evidence_ref().unwrap();
    let mut native = vec![f.events[0].clone(), f.events[1].clone()];
    native.push(f.reanchor(false).remove(0));
    let mut did_update = f.events[0].clone();
    did_update.kind = EventKind::IdentityResolutionUpdate;
    native.push(did_update);
    for event in native {
        let event =
            sign_event_with_evidence(event, method.clone(), [81; 32], Some(reference.clone()));
        assert!(source.verify_event(&event, DigestSuite::Sha256).is_err());
    }
}

#[test]
fn account_device_control_materialization_freezes_first_confirmation_prefix() {
    let mut f = Fixture::new();
    let authorize = f.event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(possession(
            &f.account,
            2,
            DeviceAuthorizationBindingKind::AcceptedDevice,
        ))
        .unwrap(),
    );
    let authorization_event_id = authorize.event_id.clone();
    f.append(vec![authorize]);
    let first_confirmation = f.seals.last().unwrap().id.clone();
    let revoke = f.event(
        EventKind::DeviceRevoke,
        json!({
            "device_id": device(2),
            "revoked_by": device(1),
            "revoked_at": "2026-09-12T00:00:00.000Z",
            "reason": "user_requested"
        }),
    );
    f.append(vec![revoke]);

    let evidence = f.control_evidence(authorization_event_id);
    let AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
        confirmation_seal_ref,
        history_event_refs,
        history_seal_refs,
        ..
    } = &evidence
    else {
        unreachable!()
    };
    assert_eq!(confirmation_seal_ref, &first_confirmation);
    assert_eq!(history_seal_refs.len(), 2);
    assert_eq!(history_event_refs.len(), 3);
    assert!(!history_seal_refs.contains(&f.seals[2].id));
    assert!(!history_event_refs.contains(&f.events[3].event_id));

    let prefix_seals = f.seals[..2].to_vec();
    let prefix_events = f.events[..3].to_vec();
    DeviceAuthorizationHistory::verify_account_device_control(
        &evidence,
        &prefix_seals,
        &prefix_events,
        DigestSuite::Sha256,
    )
    .unwrap();
    assert!(matches!(
        DeviceAuthorizationHistory::verify_account_device_control(
            &evidence,
            &f.seals,
            &f.events,
            DigestSuite::Sha256,
        ),
        Err(HistoryEvidenceError::Unavailable(_))
    ));
}

#[test]
fn account_device_control_rejects_mismatched_root_and_incomplete_closure() {
    let f = Fixture::new();
    let evidence = f.control_evidence(f.events[1].event_id.clone());
    assert!(matches!(
        DeviceAuthorizationHistory::verify_account_device_control(
            &evidence,
            &f.seals,
            &f.events[..1],
            DigestSuite::Sha256,
        ),
        Err(HistoryEvidenceError::Unavailable(_))
    ));

    let mut wrong_generation = evidence.clone();
    let AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
        authorized_generation_ref,
        ..
    } = &mut wrong_generation
    else {
        unreachable!()
    };
    *authorized_generation_ref += 1;
    assert!(matches!(
        DeviceAuthorizationHistory::verify_account_device_control(
            &wrong_generation,
            &f.seals,
            &f.events,
            DigestSuite::Sha256,
        ),
        Err(HistoryEvidenceError::Invalid(_))
    ));

    let mut unsorted = evidence;
    let AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
        history_event_refs, ..
    } = &mut unsorted
    else {
        unreachable!()
    };
    history_event_refs.reverse();
    assert!(unsorted.validate_attester_binding().is_err());
}

#[test]
fn device_history_materializes_portable_control_evidence_for_initial_and_recovery_devices() {
    let mut fixture = Fixture::new();
    let founding_authorization = fixture.events[1].event_id.clone();
    let initial = fixture
        .verify()
        .unwrap()
        .control_signer_evidence(&founding_authorization)
        .unwrap();
    let AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
        account_id,
        device_id,
        authorization_event_ref,
        generation_event_ref,
        confirmation_seal_ref,
        history_event_refs,
        history_seal_refs,
        ..
    } = initial
    else {
        panic!("expected account-device Control evidence")
    };
    assert_eq!(account_id, fixture.account);
    assert_eq!(device_id, device(1));
    assert_eq!(authorization_event_ref, founding_authorization);
    assert_eq!(generation_event_ref, fixture.events[0].event_id);
    assert_eq!(confirmation_seal_ref, fixture.seals[0].id);
    assert_eq!(history_event_refs.len(), 2);
    assert_eq!(history_seal_refs, vec![fixture.seals[0].id.clone()]);

    let recovery = fixture.reanchor(false);
    let recovery_generation = recovery[0].event_id.clone();
    let recovery_authorization = recovery[1].event_id.clone();
    fixture.append(recovery);
    let recovered = fixture
        .verify()
        .unwrap()
        .control_signer_evidence(&recovery_authorization)
        .unwrap();
    let AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
        authorized_generation_ref,
        generation_event_ref,
        confirmation_seal_ref,
        history_event_refs,
        history_seal_refs,
        ..
    } = recovered
    else {
        panic!("expected recovered account-device Control evidence")
    };
    assert_eq!(authorized_generation_ref, 2);
    assert_eq!(generation_event_ref, recovery_generation);
    assert_eq!(confirmation_seal_ref, fixture.seals[1].id);
    assert_eq!(history_event_refs.len(), 4);
    assert_eq!(history_seal_refs.len(), 2);
}
