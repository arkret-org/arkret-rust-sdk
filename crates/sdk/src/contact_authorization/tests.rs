use arkret_identity::AuthorityHistoryUnavailable;
use arkret_models_collaboration::contact_operations::{ContactLineage, ContactScopeUpdatePayload};
use arkret_models_identity::IdentityLogListOutcome;
use arkret_signatures::webvh::{ServiceInceptionInput, prepare_service_inception};
use arkret_wire::{AccountId, Base64UrlString, Did, DidUrl};
use chrono::{Duration, TimeZone as _};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;

use super::*;

struct Fixture {
    key: SigningKey,
    history: IdentityLogListOutcome,
    signature: ProtocolSignature,
    issuer: ContactPeer,
    peer: ContactPeer,
    round: Hash,
}
impl AuthorityDidHistoryResolver for Fixture {
    fn resolve_complete_history(
        &self,
        _did: &Did,
    ) -> std::result::Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
        Ok(self.history.clone())
    }
}
impl Fixture {
    fn new() -> Self {
        let at = Utc.with_ymd_and_hms(2026, 9, 12, 0, 0, 0).unwrap();
        let endpoint = "https://contact-authority.example/".parse().unwrap();
        let mut rng = ChaChaRng::seed_from_u64(719);
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: at,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let did = Did::new(inception.did.clone()).unwrap();
        let station = arkret_wire::project_did_to_core_id(&did).unwrap();
        Self {
            key: SigningKey::from_bytes(&inception.did_key_seed),
            history: IdentityLogListOutcome {
                did,
                method: DidMethodUri::Webvh,
                native_history: Some(true),
                entries: vec![inception.log_entry.clone()],
                next_cursor: None,
                has_more: false,
            },
            signature: ProtocolSignature {
                verification_method: DidUrl::new(inception.did_key_id.clone()).unwrap(),
                created_at: at,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
            },
            issuer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:zfixturealice").unwrap(),
                    station,
                ),
            },
            peer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:zfixturebob").unwrap(),
                    DidCoreId::new("ak:did_core:webvh:zfixturebobstation").unwrap(),
                ),
            },
            round: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
        }
    }
    fn sign(&self, bytes: &[u8]) -> String {
        arkret_signatures::sign_ed25519_detached_jws(&self.key, bytes).unwrap()
    }
    fn lineage(&self, version: u8, scopes: &[ContactScope], _terminal: bool) -> ContactLineage {
        let mut lineage = ContactLineage {
            trust_domain_id: domain(),
            initial_contact_round_id: if version == 1 {
                None
            } else {
                Some(self.round.clone())
            },
            contact_round_id: Some(self.round.clone()),
            issuer: self.issuer.clone(),
            peer: self.peer.clone(),
            version: u64::from(version),
            predecessor_event_ref: (version > 1).then(|| event_id(version - 1)),
            event_ref: event_id(version),
            producer_signer: ContactProducerSigner::Direct(
                arkret_models_collaboration::contact_operations::ContactDirectProducerSigner {
                    verification_method: self.signature.verification_method.clone(),
                    public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                        self.key.verifying_key().to_bytes(),
                    ))
                    .unwrap(),
                },
            ),
            granted_to_peer_scopes: scopes.to_vec(),
            accepted_at: self.signature.created_at,
            signature: self.signature.clone(),
        };
        self.resign(&mut lineage);
        lineage
    }
    fn resign(&self, lineage: &mut ContactLineage) {
        lineage.signature.jws = self.sign(&lineage.canonical_signing_bytes().unwrap());
    }
    fn current_proof(&self, last: &ContactLineage) -> ContactCurrentProof {
        let mut proof = ContactCurrentProof {
            trust_domain_id: domain(),
            holder: last.issuer.clone(),
            peer: last.peer.clone(),
            initial_contact_round_id: Some(self.round.clone()),
            contact_round_id: Some(self.round.clone()),
            issuer_id: last.issuer.delivery_station_id().clone(),
            head_event_ref: last.event_ref.clone(),
            version: last.version,
            scope_instances: last
                .granted_to_peer_scopes
                .iter()
                .map(|scope| {
                    arkret_models_collaboration::contact_operations::ContactScopeInstance {
                        contact_scope: *scope,
                        grant_event_ref: last.event_ref.clone(),
                    }
                })
                .collect(),
            closed_round: None,
            issued_at: self.signature.created_at,
            fresh_until: self.signature.created_at + Duration::minutes(5),
            signature: self.signature.clone(),
        };
        proof.signature.jws = self.sign(&proof.canonical_signing_bytes().unwrap());
        proof
    }
}
fn event_id(value: u8) -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [value; 32])
}

struct CarrierFixture {
    source: Fixture,
    device_key: SigningKey,
    method: DidUrl,
}
impl CarrierFixture {
    fn new() -> Self {
        let mut source = Fixture::new();
        let ContactPeer::Human { account_id: peer } = &mut source.peer else {
            unreachable!()
        };
        peer.station_id = source.issuer.delivery_station_id().clone();
        let device_key = SigningKey::from_bytes(&[39; 32]);
        let device_id =
            arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let method =
            DidUrl::new(format!("did:webvh:zfixturealice:alice.example#{device_id}")).unwrap();
        Self {
            source,
            device_key,
            method,
        }
    }
    fn producer_signer(&self) -> ContactProducerSigner {
        ContactProducerSigner::Direct(
            arkret_models_collaboration::contact_operations::ContactDirectProducerSigner {
                verification_method: self.method.clone(),
                public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                    self.device_key.verifying_key().to_bytes(),
                ))
                .unwrap(),
            },
        )
    }
    fn event(&self, kind: EventKind, value: serde_json::Value) -> Event {
        let realm =
            arkret_wire::RealmId::new("ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M")
                .unwrap();
        let event = Event {
            event_id: event_id(50),
            kind,
            realm_id: realm.clone(),
            scope_ref: arkret_wire::ScopeRef::Realm { realm_id: realm },
            actor_id: self.source.issuer.contact_actor_id(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: self.source.signature.created_at,
            semantic_refs: Vec::new(),
            payload: serde_json::from_value(value).unwrap(),
            producer_proof: None,
        };
        self.sign_event(event)
    }
    fn sign_event(&self, mut event: Event) -> Event {
        event.producer_proof = None;
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.event_id = EventId::from_event_digest(&digest).unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: self.method.clone(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &self.device_key,
        )
        .unwrap();
        event.producer_proof = Some(proof);
        event
    }
    fn address(&self) -> arkret_models_collaboration::governance::peer_contact::PeerContactAddress {
        serde_json::from_value(serde_json::json!({"recipient":self.source.peer,
            "service_resolution":{"resolution_url":format!("https://contact-authority.example/_arkret/open/services/{}/resolution",self.source.peer.delivery_station_id().as_str().replace(":","%3A"))}})).unwrap()
    }
    fn request(&self) -> PeerContactSubmitRequestBody {
        use arkret_models_collaboration::contact_operations::RequestAcceptanceReceiptCore;
        use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
        let introduction = ContactIntroductionEvidence::SameStation;
        let mut bytes = b"ak.contact.introduction-evidence.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&introduction).unwrap());
        let event = self.event(
            EventKind::ContactRequested,
            serde_json::json!({
                "trust_domain_id":domain(),"version":1,"peer":self.source.peer, "granted_to_peer_scopes":["direct_message"],
                "introduction_evidence_digest":arkret_canonical::sha256_digest(bytes),
            }),
        );
        let mut receipt = RequestAcceptanceReceipt {
            core: RequestAcceptanceReceiptCore {
                holder: self.source.issuer.clone(),
                peer: self.source.peer.clone(),
                trust_domain_id:domain(),version:1,predecessor_event_ref:None,initial_contact_round_id:None,
                request_event_ref: event.event_id.clone(),
                producer_signer: self.producer_signer(),
                source_checkpoint:Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,&serde_json::json!({"event_ref":event.event_id,"event_digest":event.event_id.event_digest()})).unwrap()).unwrap(),
                accepted_at: event.created_at,
                issuer_id: self.source.issuer.delivery_station_id().clone(),
            },
            receipt_digest: self.source.round.clone(),
            signature: self.source.signature.clone(),
        };
        receipt.receipt_digest = receipt.computed_core_digest().unwrap();
        receipt.signature.jws = self
            .source
            .sign(&receipt.canonical_signing_bytes().unwrap());
        PeerContactSubmitRequestBody::Request {
            idempotency_key: arkret_wire::IdempotencyKey::new("contact-request-fixture").unwrap(),
            signed_event: event,
            request_receipt: receipt,
            contact_address: self.address(),
            introduction_evidence: introduction,
            current_proof: None,
        }
    }
    fn authenticate(&self, carrier: &PeerContactSubmitRequestBody) -> Result<VerifiedContactEvent> {
        authenticate_contact_event_carrier(
            carrier,
            &self.source.issuer,
            DigestSuite::Sha256,
            self.source.signature.created_at,
            &self.source,
        )
    }
    fn successor(
        &self,
        previous: &EventId,
        version: u64,
        terminal: bool,
    ) -> PeerContactSubmitRequestBody {
        let payload = if terminal {
            serde_json::json!({"trust_domain_id":domain(),"initial_contact_round_id":self.source.round,"peer":self.source.peer,"contact_round_id":self.source.round,
            "version":version,"predecessor_event_ref":previous})
        } else {
            serde_json::json!({"schema":"ak.schema.contact_scope_update.v1",
            "trust_domain_id":domain(),"initial_contact_round_id":self.source.round,"peer":self.source.peer,"contact_round_id":self.source.round,"version":version,"predecessor_event_ref":previous,"granted_to_peer_scopes":["voice_call"]})
        };
        let event = self.event(
            if terminal {
                EventKind::ContactTombstone
            } else {
                EventKind::ContactScopeUpdate
            },
            payload,
        );
        let mut lineage = self.source.lineage(
            version as u8,
            if terminal {
                &[]
            } else {
                &[ContactScope::VoiceCall]
            },
            terminal,
        );
        lineage.event_ref = event.event_id.clone();
        lineage.producer_signer = self.producer_signer();
        lineage.predecessor_event_ref = Some(previous.clone());
        self.source.resign(&mut lineage);
        let checkpoint = self.source.current_proof(&lineage);
        if terminal {
            PeerContactSubmitRequestBody::Tombstone {
                idempotency_key: arkret_wire::IdempotencyKey::new("terminal-fixture").unwrap(),
                signed_event: event,
                lineage,
                current_proof: checkpoint,
                contact_address: self.address(),
            }
        } else {
            PeerContactSubmitRequestBody::ScopeUpdate {
                idempotency_key: arkret_wire::IdempotencyKey::new("scope-fixture").unwrap(),
                signed_event: event,
                lineage,
                current_proof: checkpoint,
                contact_address: self.address(),
            }
        }
    }
}

#[test]
fn carrier_requires_independent_source_and_exact_device_producer() {
    let fixture = CarrierFixture::new();
    let carrier = fixture.request();
    let verified = fixture.authenticate(&carrier).unwrap();
    assert_eq!(verified.kind(), EventKind::ContactRequested);
    assert!(
        verified.terminal_fence().is_none(),
        "a lone request does not grant a completed round"
    );
    let mut bad_source = carrier.clone();
    if let PeerContactSubmitRequestBody::Request {
        request_receipt, ..
    } = &mut bad_source
    {
        request_receipt.signature.jws = format!(
            "eyJhbGciOiJFZDI1NTE5In0..{}",
            arkret_canonical::base64url_encode([0; 64])
        );
    }
    assert!(fixture.authenticate(&bad_source).is_err());
    let mut bad_holder = carrier.clone();
    if let PeerContactSubmitRequestBody::Request { signed_event, .. } = &mut bad_holder {
        let binding = signed_event
            .producer_proof
            .as_ref()
            .expect("producer proof")
            .canonical_binding_bytes(&signed_event.actor_id)
            .unwrap();
        signed_event
            .producer_proof
            .as_mut()
            .expect("producer proof")
            .jws = arkret_signatures::jws::sign_jws_ed25519(&binding, &fixture.source.key).unwrap();
    }
    assert!(
        fixture.authenticate(&bad_holder).is_err(),
        "Station key cannot stand in for holder key"
    );
    let mut wrong_account = fixture.source.issuer.clone();
    if let ContactPeer::Human { account_id } = &mut wrong_account {
        account_id.station_id = DidCoreId::new("ak:did_core:webvh:zotherstation").unwrap();
    }
    assert!(
        authenticate_contact_event_carrier(
            &carrier,
            &wrong_account,
            DigestSuite::Sha256,
            fixture.source.signature.created_at,
            &fixture.source
        )
        .is_err()
    );
    let mut bad_intro = carrier;
    if let PeerContactSubmitRequestBody::Request {
        introduction_evidence,
        ..
    } = &mut bad_intro
    {
        *introduction_evidence = arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence::ExplicitAddress;
    }
    assert!(fixture.authenticate(&bad_intro).is_err());
}

#[test]
fn ordinary_contact_proof_can_be_signed_after_its_event_authoring_checkpoint() {
    let fixture = CarrierFixture::new();
    let mut carrier = fixture.request();
    let PeerContactSubmitRequestBody::Request {
        signed_event,
        request_receipt,
        ..
    } = &mut carrier
    else {
        unreachable!()
    };
    let event_id = signed_event.event_id.clone();
    let proof = signed_event.producer_proof.as_mut().unwrap();
    proof.created_at += Duration::seconds(1);
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof
            .canonical_binding_bytes(&signed_event.actor_id)
            .unwrap(),
        &fixture.device_key,
    )
    .unwrap();
    let confirmed_at = signed_event.created_at + Duration::seconds(2);
    request_receipt.core.accepted_at = confirmed_at;
    request_receipt.signature.created_at = confirmed_at;
    request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
    request_receipt.signature.jws = fixture
        .source
        .sign(&request_receipt.canonical_signing_bytes().unwrap());
    let verified = authenticate_contact_event_carrier(
        &carrier,
        &fixture.source.issuer,
        DigestSuite::Sha256,
        confirmed_at,
        &fixture.source,
    )
    .unwrap();
    assert_eq!(verified.event_id(), &event_id);
}

#[test]
fn carrier_projection_binds_exact_method_and_key_without_changing_original_event() {
    let fixture = CarrierFixture::new();
    let carrier = fixture.request();
    let PeerContactSubmitRequestBody::Request { signed_event, .. } = &carrier else {
        unreachable!()
    };
    let original = arkret_canonical::canonical_json_bytes(signed_event).unwrap();
    assert!(signed_event.validate_for_submit_structural().is_ok());
    assert!(
        signed_event
            .validate_for_contact_history_structural()
            .is_ok()
    );
    for _ in 0..2 {
        let verified = fixture.authenticate(&carrier).unwrap();
        let PeerContactSubmitRequestBody::Request { signed_event, .. } = verified.carrier() else {
            unreachable!()
        };
        assert_eq!(
            arkret_canonical::canonical_json_bytes(signed_event).unwrap(),
            original
        );
    }
    for change_method in [false, true] {
        let mut tampered = carrier.clone();
        let PeerContactSubmitRequestBody::Request {
            request_receipt, ..
        } = &mut tampered
        else {
            unreachable!()
        };
        let original = &request_receipt.core.producer_signer;
        request_receipt.core.producer_signer = ContactProducerSigner::direct(
            if change_method {
                DidUrl::new("did:webvh:zfixturealice:alice.example#another-device").unwrap()
            } else {
                original.verification_method().clone()
            },
            if change_method {
                original.public_key_b64u().clone()
            } else {
                Base64UrlString::new(arkret_canonical::base64url_encode(
                    fixture.source.key.verifying_key().to_bytes(),
                ))
                .unwrap()
            },
        )
        .unwrap();
        request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
        assert!(
            fixture.authenticate(&tampered).is_err(),
            "descriptor mutation must invalidate the source signature"
        );
    }
    let mut changed_method = carrier;
    let PeerContactSubmitRequestBody::Request { signed_event, .. } = &mut changed_method else {
        unreachable!()
    };
    let event_id = signed_event.event_id.clone();
    signed_event
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .verification_method =
        DidUrl::new("did:webvh:zfixturealice:alice.example#another-device").unwrap();
    let binding = signed_event
        .producer_proof
        .as_ref()
        .expect("producer proof")
        .canonical_binding_bytes(&signed_event.actor_id)
        .unwrap();
    signed_event
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .jws = arkret_signatures::jws::sign_jws_ed25519(&binding, &fixture.device_key).unwrap();
    assert_eq!(
        signed_event.event_id, event_id,
        "proof metadata is outside the Event content ID"
    );
    assert!(
        fixture.authenticate(&changed_method).is_err(),
        "a valid replacement proof must still match the frozen descriptor"
    );
}

#[test]
fn carrier_history_structure_accepts_producer_events_and_rejects_unrelated_kinds() {
    let fixture = CarrierFixture::new();
    let PeerContactSubmitRequestBody::Request {
        signed_event: event,
        ..
    } = fixture.request()
    else {
        unreachable!()
    };
    assert!(event.validate_for_contact_history_structural().is_ok());
    let mut unrelated = event.clone();
    unrelated.kind = EventKind::MessageCreate;
    assert!(unrelated.validate_for_contact_history_structural().is_err());
    let mut development_proof = event;
    development_proof
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .kind = "dev".to_owned();
    let binding = development_proof
        .producer_proof
        .as_ref()
        .expect("producer proof")
        .canonical_binding_bytes(&development_proof.actor_id)
        .unwrap();
    development_proof
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .jws = arkret_signatures::jws::sign_jws_ed25519(&binding, &fixture.device_key).unwrap();
    assert!(
        verify_holder(
            &development_proof,
            &fixture.source.issuer,
            &fixture.producer_signer(),
            DigestSuite::Sha256
        )
        .is_err()
    );
}

#[test]
fn carrier_scope_and_terminal_bind_real_event_not_unsigned_lineage() {
    let fixture = CarrierFixture::new();
    let carrier = fixture.successor(&event_id(1), 2, false);
    let verified = fixture.authenticate(&carrier).unwrap();
    assert!(verified.terminal_fence().is_none());
    let mut forged = carrier;
    if let PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. } = &mut forged {
        lineage.granted_to_peer_scopes = vec![ContactScope::VideoCall];
        fixture.source.resign(lineage);
    }
    assert!(
        fixture.authenticate(&forged).is_err(),
        "even a Station-signed different scope cannot replace the holder Event"
    );
    let terminal = fixture.successor(verified.event_id(), 3, true);
    let fence = fixture
        .authenticate(&terminal)
        .unwrap()
        .terminal_fence()
        .unwrap();
    assert_eq!(fence.contact_round_id(), &fixture.source.round);
}

#[test]
fn carrier_controller_device_requires_accepted_immutable_agent_pcr_delegation() {
    use arkret_signatures::webvh::{
        AgentBindingUpdateInput, AgentInceptionInput, prepare_agent_binding_update,
        prepare_agent_inception,
    };
    let f = CarrierFixture::new();
    let ContactPeer::Human {
        account_id: controller,
    } = f.source.issuer.clone()
    else {
        unreachable!()
    };
    let mut event= f.event(EventKind::ContactTombstone,serde_json::json!({"trust_domain_id":domain(),"initial_contact_round_id":f.source.round,"peer":f.source.peer,"contact_round_id":f.source.round,"version":2,"predecessor_event_ref":event_id(1)}));
    let at = f.source.signature.created_at;
    let endpoint = "https://agents.example/".parse().unwrap();
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
    );
    let future = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
    );
    let inception = prepare_agent_inception(&AgentInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "contact-agent",
        controller_principal_id: &controller.principal_id,
        version_time: at - Duration::seconds(2),
        root_seed: &[41; 32],
        next_root_public_key_multibase: &next,
    })
    .unwrap();
    let binding = prepare_agent_binding_update(&AgentBindingUpdateInput {
        did: &inception.did,
        local_id: &inception.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: at - Duration::seconds(1),
        current_root_seed: &[42; 32],
        next_root_public_key_multibase: &future,
        controller_principal_id: &controller.principal_id,
        principal_control_realm_id: &event.realm_id,
        requested_scope_digest: &f.source.round,
    })
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let actor = arkret_wire::ActorId::account(AccountId::new(
        arkret_wire::project_did_to_core_id(&did).unwrap(),
        controller.station_id.clone(),
    ));
    event.actor_id = actor.clone();
    event.executed_by = Some(arkret_wire::ActorId::account(controller.clone()));
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(format!("{}#managed-controller", inception.did))
            .unwrap(),
    );
    event = f.sign_event(event);
    let holder = ContactPeer::Agent {
        actor_id: actor,
        controller_account_id: controller,
    };
    let mut history = Fixture::new();
    history.history = IdentityLogListOutcome {
        did,
        method: DidMethodUri::Webvh,
        native_history: Some(true),
        entries: vec![inception.log_entry, binding.log_entry],
        next_cursor: None,
        has_more: false,
    };
    verify_agent_holder_binding(&event, &holder, None, &history).unwrap();
    let producer = ContactProducerSigner::delegated(
        f.method.clone(),
        f.producer_signer().public_key_b64u().clone(),
        history.history.did.clone(),
    )
    .unwrap();
    verify_holder(&event, &holder, &producer, DigestSuite::Sha256).unwrap();
    assert!(
        verify_holder(&event, &holder, &f.producer_signer(), DigestSuite::Sha256).is_err(),
        "a delegated Event cannot consume a direct producer projection"
    );
    let identity =
        verify_contact_agent_identity(&event, &holder, &history.history.did, &history).unwrap();
    assert_eq!(identity.event_id(), &event.event_id);
    assert_eq!(identity.did(), &history.history.did);

    struct CombinedHistory<'a> {
        source: &'a Fixture,
        agent: &'a Fixture,
    }
    impl AuthorityDidHistoryResolver for CombinedHistory<'_> {
        fn resolve_complete_history(
            &self,
            did: &Did,
        ) -> std::result::Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
            if did == &self.source.history.did {
                Ok(self.source.history.clone())
            } else if did == &self.agent.history.did {
                Ok(self.agent.history.clone())
            } else {
                Err(AuthorityHistoryUnavailable {
                    message: "unavailable fixture DID".into(),
                })
            }
        }
    }
    let make_carrier = |event: Event, producer: ContactProducerSigner| {
        let mut lineage = f.source.lineage(2, &[], true);
        lineage.issuer = holder.clone();
        lineage.event_ref = event.event_id.clone();
        lineage.producer_signer = producer;
        f.source.resign(&mut lineage);
        let current_proof = f.source.current_proof(&lineage);
        PeerContactSubmitRequestBody::Tombstone {
            idempotency_key: arkret_wire::IdempotencyKey::new("controller-contact").unwrap(),
            signed_event: event,
            lineage,
            current_proof,
            contact_address: f.address(),
        }
    };
    // The grant reference has no public Agent DID. Only the source-signed
    // delegated locator permits the first receiving Station to resolve it.
    let mut grant_event = event.clone();
    grant_event.authorization_ref = Some(event_id(91).into());
    grant_event = f.sign_event(grant_event);
    let carrier = make_carrier(grant_event.clone(), producer);
    let histories = CombinedHistory {
        source: &f.source,
        agent: &history,
    };
    let verified =
        authenticate_contact_event_carrier(&carrier, &holder, DigestSuite::Sha256, at, &histories)
            .unwrap();
    assert_eq!(verified.event_id(), &grant_event.event_id);
    assert!(
        authenticate_contact_event_carrier(&carrier, &holder, DigestSuite::Sha256, at, &f.source)
            .is_err(),
        "the signed locator does not replace independent native history"
    );
    let missing = make_carrier(grant_event, f.producer_signer());
    assert!(
        authenticate_contact_event_carrier(&missing, &holder, DigestSuite::Sha256, at, &histories)
            .is_err(),
        "a newly signed source receipt cannot authorize an omitted mandatory locator"
    );
    let mut removed_binding = history.history.entries[1]["state"].clone();
    removed_binding["service"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes(),
    );
    let later = arkret_signatures::webvh::prepare_principal_rotation(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: history.history.did.as_str(),
            local_id: "contact-agent",
            previous_entries: &history.history.entries,
            version_time: at + Duration::seconds(1),
            current_root_seed: &[43; 32],
            next_root_public_key_multibase: &next_root,
            state: &removed_binding,
        },
    )
    .unwrap();
    history.history.entries.push(later.log_entry);
    verify_agent_holder_binding(&event, &holder, None, &history).unwrap();
    let mut new_event = event.clone();
    new_event.created_at = at + Duration::seconds(2);
    new_event = f.sign_event(new_event);
    assert!(
        verify_agent_holder_binding(&new_event, &holder, None, &history).is_err(),
        "a later binding removal rejects new Agent identity claims without revoking old facts"
    );
    history.history.entries[2]["state"]["unproven"] = serde_json::json!(true);
    assert!(
        verify_agent_holder_binding(&event, &holder, None, &history).is_err(),
        "even later native history must remain fully authentic"
    );
    history.history.entries[2]["state"]
        .as_object_mut()
        .unwrap()
        .remove("unproven");

    let mut wrong = event.clone();
    wrong.realm_id =
        arkret_wire::RealmId::new("ak:realm:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e").unwrap();
    wrong.scope_ref = arkret_wire::ScopeRef::Realm {
        realm_id: wrong.realm_id.clone(),
    };
    wrong = f.sign_event(wrong);
    assert!(verify_agent_holder_binding(&wrong, &holder, None, &history).is_err());
    let mut materialized = event.clone();
    materialized.authorization_ref = Some(event_id(91).into());
    materialized = f.sign_event(materialized);
    assert!(matches!(
        verify_agent_holder_binding(&materialized, &holder, None, &history),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    verify_agent_holder_binding(&materialized, &holder, Some(&history.history.did), &history)
        .unwrap();
    let mut wrong = event;
    wrong.authorization_ref = None;
    wrong = f.sign_event(wrong);
    assert!(
        verify_agent_holder_binding(&wrong, &holder, Some(&history.history.did), &history).is_err()
    );
}

fn domain() -> arkret_wire::TrustDomainId {
    arkret_wire::TrustDomainId::new("ak:trust_domain:contact.test").unwrap()
}

struct Ceremony {
    a: arkret_test_kit::service_identity::ServiceIdentityFixture,
    b: arkret_test_kit::service_identity::ServiceIdentityFixture,
    wire: arkret_test_kit::contact::ContactCeremonyFixture,
    at: DateTime<Utc>,
}
impl AuthorityDidHistoryResolver for Ceremony {
    fn resolve_complete_history(
        &self,
        did: &Did,
    ) -> std::result::Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
        for source in [&self.a, &self.b] {
            if &source.history.did == did {
                return Ok(source.history.clone());
            }
        }
        Err(AuthorityHistoryUnavailable {
            message: "unknown fixture method".into(),
        })
    }
}
impl Ceremony {
    fn new() -> Self {
        use arkret_test_kit::contact::{ContactCeremonyFixture, ContactParticipant};
        use arkret_test_kit::service_identity::ServiceIdentityFixture;
        let at = Utc.with_ymd_and_hms(2026, 9, 12, 1, 0, 0).unwrap();
        let a = ServiceIdentityFixture::webvh(
            &"https://station-a.example/".parse().unwrap(),
            1201,
            [11; 32],
            "source-a",
            at - Duration::minutes(1),
            at,
        )
        .unwrap();
        let b = ServiceIdentityFixture::webvh(
            &"https://station-b.example/".parse().unwrap(),
            1202,
            [12; 32],
            "source-b",
            at - Duration::minutes(1),
            at,
        )
        .unwrap();
        let participant = |seed, station: &ServiceIdentityFixture, realm: u8| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &key.verifying_key().to_bytes(),
            );
            let did = Did::new(format!("did:key:{multibase}")).unwrap();
            (
                AccountId::new(
                    arkret_wire::project_did_to_core_id(&did).unwrap(),
                    station.service_id.clone(),
                ),
                DidUrl::new(format!("{did}#{multibase}")).unwrap(),
                arkret_wire::RealmId::from_event_id(&event_id(realm)),
            )
        };
        let (aa, am, ar) = participant(21, &a, 31);
        let (ba, bm, br) = participant(22, &b, 32);
        let wire = ContactCeremonyFixture::normal(
            &ContactParticipant {
                account_id: aa,
                realm_id: ar,
                verification_method: am,
                signing_seed: [21; 32],
                authority: &a,
            },
            &ContactParticipant {
                account_id: ba,
                realm_id: br,
                verification_method: bm,
                signing_seed: [22; 32],
                authority: &b,
            },
            at,
        )
        .unwrap();
        Self { a, b, wire, at }
    }
    fn material(&self, index: usize) -> ContactCurrentMaterial {
        let bundle = &self.wire.round;
        let head = bundle.current_operations[index].clone();
        ContactCurrentMaterial {
            initial_identity: Some(bundle.initial_identity.clone()),
            round_evidence: Some(bundle.basis()),
            round_events: Some(bundle.round_events.clone()),
            scope_grants: bundle
                .scope_grants
                .iter()
                .filter(|op| op.holder() == head.holder())
                .cloned()
                .collect(),
            historical_intervals: vec![],
            current_proof: bundle
                .current_proofs
                .iter()
                .find(|p| &p.holder == head.holder())
                .unwrap()
                .clone(),
            head_operation: head,
        }
    }
    fn verify(&self, material: &ContactCurrentMaterial) -> Result<VerifiedContactCurrentMaterial> {
        verify_contact_current_material(
            material,
            material.head_operation.holder(),
            material.head_operation.peer(),
            &domain(),
            DigestSuite::Sha256,
            self.at + Duration::seconds(2),
            self,
        )
    }
    fn sign_state(
        &self,
        state: &arkret_models_collaboration::contact_operations::ContactPrivateState,
        holder: &ContactPeer,
        offset: i64,
    ) -> ContactCurrentProof {
        let d = state.direction(holder).unwrap();
        let at = self.at + Duration::seconds(offset);
        let source = if holder.delivery_station_id() == &self.a.service_id {
            &self.a
        } else {
            &self.b
        };
        ContactCurrentProof::sign_with(
            domain(),
            holder.clone(),
            d.head_operation.peer().clone(),
            state
                .initial_identity
                .as_ref()
                .map(|i| i.round.contact_round_id.clone()),
            state
                .round_basis
                .as_ref()
                .map(|r| r.contact_round_id.clone()),
            source.service_id.clone(),
            d.head_operation.event().event_id.clone(),
            d.head_operation.version(),
            d.scope_instances.clone(),
            d.closed_round.clone().map(Box::new),
            at,
            at + Duration::minutes(5),
            |bytes| source.sign(bytes, at),
        )
        .unwrap()
    }
    fn state(&self) -> arkret_models_collaboration::contact_operations::ContactPrivateState {
        let mut state =
            arkret_models_collaboration::contact_operations::ContactPrivateState::default();
        for index in 0..2 {
            state
                .install_authenticated_current(self.material(index))
                .unwrap();
        }
        state
    }
}
#[test]
fn current_recovers_without_prior_mirror_and_authenticates_both_round_intents() {
    let fixture = Ceremony::new();
    for index in 0..2 {
        let material = fixture.material(index);
        let verified = fixture.verify(&material).unwrap();
        assert!(
            verified
                .direction()
                .unwrap()
                .open_interval(ContactScope::DirectMessage)
                .is_some()
        );
        let mut missing = material;
        missing.round_events.as_mut().unwrap().pop();
        assert!(fixture.verify(&missing).is_err());
    }
}
#[test]
fn source_signature_and_original_holder_signature_are_independent() {
    let fixture = Ceremony::new();
    let mut material = fixture.material(0);
    material.current_proof.scope_instances.clear();
    assert!(fixture.verify(&material).is_err());
    let mut material = fixture.material(0);
    let ContactOperationEvidence::Request { signed_event, .. } = &mut material.head_operation
    else {
        unreachable!()
    };
    signed_event.producer_proof.as_mut().unwrap().jws.push('A');
    assert!(fixture.verify(&material).is_err());
}
#[test]
fn current_source_history_must_be_complete_and_historical_assertion_authorized() {
    let mut fixture = Ceremony::new();
    let material = fixture.material(0);
    fixture.a.history.has_more = true;
    assert!(fixture.verify(&material).is_err());
    fixture.a.history.has_more = false;
    fixture.a.history.entries.clear();
    assert!(fixture.verify(&material).is_err());
}
#[test]
fn current_material_binds_full_pair_domain_and_exact_original_head() {
    let fixture = Ceremony::new();
    for field in ["holder", "peer", "trust_domain_id", "head_event_ref"] {
        let mut value = serde_json::to_value(fixture.material(0)).unwrap();
        value["current_proof"][field] = match field {
            "holder" => {
                serde_json::to_value(fixture.wire.round.current_proofs[1].holder.clone()).unwrap()
            }
            "peer" => {
                serde_json::to_value(fixture.wire.round.current_proofs[0].holder.clone()).unwrap()
            }
            "trust_domain_id" => serde_json::json!("ak:trust_domain:other.example"),
            _ => serde_json::to_value(event_id(99)).unwrap(),
        };
        let changed: ContactCurrentMaterial = serde_json::from_value(value).unwrap();
        assert!(fixture.verify(&changed).is_err(), "{field}");
    }
}
#[test]
fn narrowing_retains_an_existing_scope_instance_and_readd_uses_new_original() {
    use arkret_models_collaboration::contact_operations::{
        ContactScopeInstance, ContactScopeUpdateSchema,
    };
    use arkret_test_kit::contact::ContactParticipant;
    let fixture = Ceremony::new();
    let mut state = fixture.state();
    let operation = contact_carrier_operation(&fixture.wire.scope_update).unwrap();
    let holder = operation.holder().clone();
    let old = state.direction(&holder).unwrap().scope_instances.clone();
    state.apply_confirmed(operation.clone()).unwrap();
    let retained = state
        .direction(&holder)
        .unwrap()
        .scope_instances
        .iter()
        .find(|i| i.contact_scope == ContactScope::DirectMessage)
        .unwrap();
    assert_eq!(
        retained,
        old.iter()
            .find(|i| i.contact_scope == ContactScope::DirectMessage)
            .unwrap()
    );
    let participant = ContactParticipant {
        account_id: holder.contact_actor_id().as_account_id().unwrap().clone(),
        realm_id: operation.event().realm_id.clone(),
        verification_method: operation.producer_signer().verification_method().clone(),
        signing_seed: [22; 32],
        authority: &fixture.b,
    };
    let event = participant
        .event::<arkret_wire::event_spec::ContactScopeUpdate>(
            ContactScopeUpdatePayload {
                schema: ContactScopeUpdateSchema::V1,
                trust_domain_id: domain(),
                initial_contact_round_id: fixture.wire.round.contact_round_id.clone(),
                version: 3,
                predecessor_event_ref: operation.event().event_id.clone(),
                peer: operation.peer().clone(),
                contact_round_id: fixture.wire.round.contact_round_id.clone(),
                granted_to_peer_scopes: vec![ContactScope::Invite, ContactScope::DirectMessage],
            },
            fixture.at,
        )
        .unwrap();
    let lineage = ContactLineage::sign_with(
        domain(),
        Some(fixture.wire.round.contact_round_id.clone()),
        Some(fixture.wire.round.contact_round_id.clone()),
        holder.clone(),
        operation.peer().clone(),
        3,
        Some(operation.event().event_id.clone()),
        event.event_id.clone(),
        operation.producer_signer().clone(),
        vec![ContactScope::Invite, ContactScope::DirectMessage],
        fixture.at,
        |bytes| fixture.b.sign(bytes, fixture.at),
    )
    .unwrap();
    state
        .apply_confirmed(ContactOperationEvidence::ScopeUpdate {
            signed_event: event.clone(),
            lineage,
        })
        .unwrap();
    let new = state
        .direction(&holder)
        .unwrap()
        .scope_instances
        .iter()
        .find(|i| i.contact_scope == ContactScope::Invite)
        .unwrap();
    assert_eq!(
        new,
        &ContactScopeInstance {
            contact_scope: ContactScope::Invite,
            grant_event_ref: event.event_id
        }
    );
    assert_ne!(
        new,
        old.iter()
            .find(|i| i.contact_scope == ContactScope::Invite)
            .unwrap()
    );
}
#[test]
fn remote_closure_preserves_own_original_head_and_lifetime_version() {
    let fixture = Ceremony::new();
    let mut state = fixture.state();
    let operation = contact_carrier_operation(&fixture.wire.scope_update).unwrap();
    state.apply_confirmed(operation).unwrap();
    let operation = contact_carrier_operation(&fixture.wire.tombstone).unwrap();
    let ContactOperationEvidence::Tombstone {
        signed_event,
        lineage,
    } = operation
    else {
        unreachable!()
    };
    let own = fixture.material(0).head_operation.holder().clone();
    let head = state
        .direction(&own)
        .unwrap()
        .head_operation
        .event()
        .event_id
        .clone();
    state
        .apply_confirmed(ContactOperationEvidence::Tombstone {
            signed_event: signed_event.clone(),
            lineage: lineage.clone(),
        })
        .unwrap();
    state.close_round(arkret_models_collaboration::contact_operations::ContactRoundClosure{contact_round_id:fixture.wire.round.contact_round_id.clone(),operation:arkret_models_collaboration::contact_operations::ContactTombstoneEvidence{kind:arkret_models_collaboration::contact_operations::ContactTombstoneEvidenceKind::Tombstone,signed_event,lineage}}).unwrap();
    let proof = fixture.sign_state(&state, &own, 1);
    assert_eq!(proof.head_event_ref, head);
    assert_eq!(proof.version, 1);
    assert!(proof.scope_instances.is_empty());
    let mut material = fixture.material(0);
    material.current_proof = proof;
    material.scope_grants.clear();
    let verified = fixture.verify(&material).unwrap();
    assert!(verified.closure().is_some());
    assert!(
        verified
            .direction()
            .unwrap()
            .open_interval(ContactScope::DirectMessage)
            .is_none()
    );
    assert!(
        state
            .install_authenticated_current(fixture.material(0))
            .is_err(),
        "an older lease cannot revive known exact-round closure"
    );
}
#[test]
fn lease_expiry_does_not_revoke_an_already_verified_ordinary_scope() {
    let fixture = Ceremony::new();
    let material = fixture.material(0);
    let verified = fixture.verify(&material).unwrap();
    let direction = verified.direction().unwrap();
    assert!(
        direction
            .require_current_at(material.current_proof.fresh_until)
            .is_err()
    );
    assert!(
        direction
            .open_interval(ContactScope::DirectMessage)
            .is_some()
    );
    assert!(matches!(
        verify_contact_current_material(
            &material,
            material.head_operation.holder(),
            material.head_operation.peer(),
            &domain(),
            DigestSuite::Sha256,
            material.current_proof.fresh_until,
            &fixture
        ),
        Err(ContactAuthorizationError::NotCurrent)
    ));
}
#[test]
fn same_version_refresh_compares_the_immutable_original_instead_of_proof_bytes() {
    let fixture = Ceremony::new();
    let mut state = fixture.state();
    let mut material = fixture.material(0);
    material.current_proof = fixture.sign_state(&state, material.head_operation.holder(), 1);
    state
        .install_authenticated_current(material.clone())
        .unwrap();
    assert_eq!(
        state
            .direction(material.head_operation.holder())
            .unwrap()
            .head_operation
            .version(),
        1
    );
    let mut conflict = material.clone();
    let ContactOperationEvidence::Request { signed_event, .. } = &mut conflict.head_operation
    else {
        unreachable!()
    };
    signed_event.producer_proof.as_mut().unwrap().jws.push('A');
    assert!(state.install_authenticated_current(conflict).is_err());
    assert!(
        state
            .install_authenticated_current(fixture.material(0))
            .is_ok()
    );
    assert_eq!(
        state
            .direction(material.head_operation.holder())
            .unwrap()
            .current_proof
            .as_ref()
            .unwrap()
            .issued_at,
        material.current_proof.issued_at
    );
}
#[test]
fn optional_wire_members_reject_explicit_null_and_retired_continuity_fields() {
    let fixture = Ceremony::new();
    let material = fixture.material(0);
    for field in [
        "closed_round",
        "initial_contact_round_id",
        "contact_round_id",
    ] {
        let mut value = serde_json::to_value(&material.current_proof).unwrap();
        value[field] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<ContactCurrentProof>(value).is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(&material.current_proof).unwrap();
    value["complete_through"] = serde_json::json!(1);
    assert!(serde_json::from_value::<ContactCurrentProof>(value).is_err());
}
#[test]
fn historical_first_close_requires_the_full_signed_control_result() {
    use arkret_models_collaboration::contact_operations::*;
    let fixture = Ceremony::new();
    let mut state = fixture.state();
    let update = contact_carrier_operation(&fixture.wire.scope_update).unwrap();
    let holder = update.holder().clone();
    let peer = update.peer().clone();
    state.apply_confirmed(update.clone()).unwrap();
    let base = fixture.material(1);
    let proof = fixture.sign_state(&state, &holder, 1);
    let direction = state.direction(&holder).unwrap();
    let material = ContactCurrentMaterial {
        initial_identity: base.initial_identity,
        round_evidence: base.round_evidence,
        round_events: base.round_events.clone(),
        head_operation: update.clone(),
        scope_grants: direction.scope_grants.clone(),
        historical_intervals: vec![ContactHistoricalScopeInterval {
            contact_scope: ContactScope::Invite,
            grant: base.head_operation,
            round: fixture.wire.round.basis(),
            round_events: fixture.wire.round.round_events.clone(),
            closed_by: Some(update),
        }],
        current_proof: proof,
    };
    assert!(
        fixture.verify(&material).is_err(),
        "Event signatures alone do not certify the first interval boundary"
    );
    let request = PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key: arkret_wire::IdempotencyKey::new("current-history-kat").unwrap(),
        requester: peer,
        trust_domain_id: domain(),
        initial_contact_round_id: Some(fixture.wire.round.contact_round_id.clone()),
        known_version: 1,
        grant_event_refs: vec![
            material.historical_intervals[0]
                .grant
                .event()
                .event_id
                .clone(),
        ],
        contact_address:
            arkret_models_collaboration::governance::peer_contact::PeerContactAddress::for_recipient(
                holder,
                arkret_models_identity::ServiceResolutionCarrier::Inline {
                    inline: fixture.b.resolution.clone(),
                },
            ),
    };
    let request_digest = Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
    let result_digest = peer_contact_control_result_digest(
        &request_digest,
        PeerContactControlKind::CurrentRefresh,
        None,
        None,
        Some(&material),
    )
    .unwrap();
    let at = fixture.at + Duration::seconds(1);
    let unsigned = serde_json::json!({"domain":"ak.peer_contact.control_receipt.v1","request_kind":"current_refresh","request_digest":request_digest,"outcome":"accepted","result_digest":result_digest,"recipient_id":fixture.b.service_id,"received_at":arkret_canonical::format_timestamp_canonical(at),"issuer_id":fixture.b.service_id});
    let signature = fixture
        .b
        .sign(
            &arkret_canonical::canonical_json_bytes(&unsigned).unwrap(),
            at,
        )
        .unwrap();
    let receipt = PeerContactControlReceipt {
        domain: PeerContactControlReceiptDomain::V1,
        request_kind: PeerContactControlKind::CurrentRefresh,
        request_digest,
        outcome: PeerContactOutcome::Accepted,
        result_digest: Some(result_digest),
        recipient_id: fixture.b.service_id.clone(),
        received_at: at,
        issuer_id: fixture.b.service_id.clone(),
        signature,
    };
    let result =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::CurrentRefresh {
            status: PeerContactOutcome::Accepted,
            control_receipt: receipt,
            material,
        });
    verify_contact_current_refresh_response(
        &request,
        &result,
        DigestSuite::Sha256,
        fixture.at + Duration::seconds(2),
        &fixture,
    )
    .unwrap();
    let mut tampered = result;
    let PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::CurrentRefresh {
        material,
        ..
    }) = &mut tampered
    else {
        unreachable!()
    };
    material.historical_intervals[0].closed_by = None;
    assert!(
        verify_contact_current_refresh_response(
            &request,
            &tampered,
            DigestSuite::Sha256,
            fixture.at + Duration::seconds(2),
            &fixture
        )
        .is_err()
    );
}

#[test]
fn glare_slot_attestation_signs_protocol_timestamp_and_exact_bounded_choice() {
    use arkret_models_collaboration::contact_operations::GlareConcurrencyAttestation;
    let f = Ceremony::new();
    let op = &f.wire.round.current_operations[0];
    let proof = GlareConcurrencyAttestation::sign_with(
        domain(),
        None,
        f.wire.round.contact_round_id.clone(),
        op.version(),
        op.event().event_id.clone(),
        op.holder().contact_actor_id(),
        f.a.service_id.clone(),
        op.peer().contact_actor_id(),
        [event_id(81).event_digest(), event_id(82).event_digest()],
        f.at,
        |bytes| Ok(f.a.sign(bytes, f.at).unwrap()),
    )
    .unwrap();
    proof.validate_slot_commitment().unwrap();
    assert_eq!(
        serde_json::to_value(&proof).unwrap()["observed_at"],
        "2026-09-12T01:00:00.000Z"
    );
    verify_source_signature_at(
        &f.a.service_id,
        &proof.signature,
        &proof.canonical_signing_bytes().unwrap(),
        f.at,
        &f,
    )
    .unwrap();
    let mut changed = proof.clone();
    changed.version += 1;
    assert!(changed.validate_slot_commitment().is_err());
    changed.unconsumed_slot_checkpoint = changed.slot_commitment().unwrap();
    assert!(
        verify_source_signature_at(
            &f.a.service_id,
            &changed.signature,
            &changed.canonical_signing_bytes().unwrap(),
            f.at,
            &f
        )
        .is_err()
    );
    changed = proof;
    changed.observed_at += Duration::milliseconds(1);
    assert!(changed.validate_slot_commitment().is_err());
}

#[test]
fn delayed_lineage_uses_issuance_key_while_receipts_retain_acceptance_key() {
    use arkret_signatures::webvh::{
        ServiceInceptionInput, ServiceRotationInput, prepare_service_inception_with_did_key_seed,
        prepare_service_rotation,
    };
    let mut f = Ceremony::new();
    let later = f.at + Duration::seconds(2);
    let mut rng = ChaChaRng::seed_from_u64(1202);
    let inception = prepare_service_inception_with_did_key_seed(
        &mut rng,
        &ServiceInceptionInput {
            principal_endpoint: &"https://station-b.example/".parse().unwrap(),
            local_id: "service",
            also_known_as: &[],
            version_time: f.at - Duration::minutes(1),
            did_key_fragment: Some("source-b"),
        },
        &[12; 32],
    )
    .unwrap();
    assert_eq!(inception.log_entry, f.b.history.entries[0]);
    let key = SigningKey::from_bytes(&[54; 32]);
    let mut state = f.b.history.entries[0]["state"].clone();
    let method = state["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["id"] == f.b.verification_method.as_str())
        .unwrap();
    method["publicKeyMultibase"] = serde_json::json!(
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    );
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[55; 32]).verifying_key().as_bytes(),
    );
    let rotation = prepare_service_rotation(&ServiceRotationInput {
        did: f.b.history.did.as_str(),
        previous_entries: &f.b.history.entries,
        state: &state,
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &next,
        version_time: f.at + Duration::seconds(1),
    })
    .unwrap();
    f.b.history.entries.push(rotation.log_entry);
    f.b.signing_key = key;
    let mut carrier = f.wire.scope_update.clone();
    let PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. } = &mut carrier else {
        unreachable!()
    };
    assert_eq!(lineage.accepted_at, f.at);
    lineage.signature =
        f.b.sign(&lineage.canonical_signing_bytes().unwrap(), later)
            .unwrap();
    let holder = f.wire.round.current_operations[1].holder().clone();
    authenticate_contact_event_carrier(&carrier, &holder, DigestSuite::Sha256, later, &f).unwrap();
    let PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. } = &mut carrier else {
        unreachable!()
    };
    lineage.signature =
        f.b.sign(&lineage.canonical_signing_bytes().unwrap(), f.at)
            .unwrap();
    assert!(
        authenticate_contact_event_carrier(&carrier, &holder, DigestSuite::Sha256, later, &f)
            .is_err()
    );
    let mut response = f.wire.response.clone();
    let PeerContactSubmitRequestBody::Response {
        response_receipt, ..
    } = &mut response
    else {
        unreachable!()
    };
    response_receipt.signature.created_at = later;
    response_receipt.signature.jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&[12; 32]),
        &response_receipt.canonical_signing_bytes().unwrap(),
    )
    .unwrap();
    authenticate_contact_event_carrier(&response, &holder, DigestSuite::Sha256, later, &f).unwrap();
}

#[test]
fn signed_contact_request_cannot_introduce_a_future_round_or_unknown_wire_member() {
    for member in ["contact_round_id", "retired_continuity"] {
        let f = CarrierFixture::new();
        let mut carrier = f.request();
        let PeerContactSubmitRequestBody::Request {
            signed_event,
            request_receipt,
            ..
        } = &mut carrier
        else {
            unreachable!()
        };
        signed_event
            .payload
            .insert(member.into(), serde_json::json!(f.source.round));
        *signed_event = f.sign_event(signed_event.clone());
        request_receipt.core.request_event_ref = signed_event.event_id.clone();
        request_receipt.core.source_checkpoint=Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,&serde_json::json!({"event_ref":signed_event.event_id,"event_digest":signed_event.event_id.event_digest()})).unwrap()).unwrap();
        request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
        request_receipt.signature.jws = f
            .source
            .sign(&request_receipt.canonical_signing_bytes().unwrap());
        assert!(f.authenticate(&carrier).is_err(), "{member}");
    }
}

#[test]
fn current_tombstone_original_fences_both_directions_without_a_duplicate_hint() {
    let f = Ceremony::new();
    let mut state = f.state();
    let mut material = f.material(1);
    material.head_operation = contact_carrier_operation(&f.wire.tombstone).unwrap();
    material.scope_grants.clear();
    let PeerContactSubmitRequestBody::Tombstone { current_proof, .. } = &f.wire.tombstone else {
        unreachable!()
    };
    material.current_proof = current_proof.clone();
    material.current_proof.closed_round = None;
    material.current_proof.signature =
        f.b.sign(
            &material.current_proof.canonical_signing_bytes().unwrap(),
            f.at,
        )
        .unwrap();
    let verified = f.verify(&material).unwrap();
    assert!(verified.closure().is_some());
    state.install_authenticated_current(material).unwrap();
    assert!(
        state
            .directions
            .iter()
            .all(|d| d.scope_instances.is_empty())
    );
    assert_eq!(
        state
            .directions
            .iter()
            .find(|d| d.head_operation.holder() == f.wire.round.current_operations[0].holder())
            .unwrap()
            .head_operation
            .version(),
        1
    );
    assert!(state.observed_closure.is_some());
}

#[test]
fn recovered_recontact_request_clears_old_round_but_preserves_first_identity_and_cursors() {
    use arkret_models_collaboration::events_payloads::contact::ContactRequestedPayload;
    use arkret_test_kit::contact::ContactParticipant;
    let f = Ceremony::new();
    let mut state = f.state();
    let terminal = contact_carrier_operation(&f.wire.tombstone).unwrap();
    state
        .apply_confirmed(contact_carrier_operation(&f.wire.scope_update).unwrap())
        .unwrap();
    state.apply_confirmed(terminal.clone()).unwrap();
    state
        .close_round(terminal.round_closure().unwrap())
        .unwrap();
    let initial = state.initial_identity.clone();
    let holder = terminal.holder().clone();
    let peer = terminal.peer().clone();
    let p = ContactParticipant {
        account_id: holder.contact_actor_id().as_account_id().unwrap().clone(),
        realm_id: terminal.event().realm_id.clone(),
        verification_method: terminal.producer_signer().verification_method().clone(),
        signing_seed: [22; 32],
        authority: &f.b,
    };
    let event = p
        .event::<arkret_wire::event_spec::ContactRequested>(
            ContactRequestedPayload {
                trust_domain_id: domain(),
                initial_contact_round_id: Some(f.wire.round.contact_round_id.clone()),
                version: 4,
                predecessor_event_ref: Some(terminal.event().event_id.clone()),
                peer: peer.clone(),
                granted_to_peer_scopes: vec![ContactScope::DirectMessage],
                introduction_evidence_digest: event_id(71).event_digest(),
                message: None,
            },
            f.at,
        )
        .unwrap();
    let receipt=RequestAcceptanceReceipt::sign_with(arkret_models_collaboration::contact_operations::RequestAcceptanceReceiptCore{trust_domain_id:domain(),holder:holder.clone(),peer:peer.clone(),version:4,predecessor_event_ref:Some(terminal.event().event_id.clone()),initial_contact_round_id:Some(f.wire.round.contact_round_id.clone()),request_event_ref:event.event_id.clone(),producer_signer:p.producer().unwrap(),source_checkpoint:Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,&serde_json::json!({"event_ref":event.event_id,"event_digest":event.event_id.event_digest()})).unwrap()).unwrap(),accepted_at:f.at,issuer_id:f.b.service_id.clone()},|bytes|f.b.sign(bytes,f.at)).unwrap();
    let proof = ContactCurrentProof::sign_with(
        domain(),
        holder.clone(),
        peer.clone(),
        Some(f.wire.round.contact_round_id.clone()),
        None,
        f.b.service_id.clone(),
        event.event_id.clone(),
        4,
        vec![],
        Some(Box::new(terminal.round_closure().unwrap())),
        f.at,
        f.at + Duration::minutes(5),
        |bytes| f.b.sign(bytes, f.at),
    )
    .unwrap();
    let material = ContactCurrentMaterial {
        initial_identity: initial.clone(),
        round_evidence: None,
        round_events: None,
        head_operation: ContactOperationEvidence::Request {
            signed_event: event,
            request_receipt: receipt,
        },
        scope_grants: vec![],
        historical_intervals: vec![],
        current_proof: proof,
    };
    verify_contact_current_material(
        &material,
        &holder,
        &peer,
        &domain(),
        DigestSuite::Sha256,
        f.at,
        &f,
    )
    .unwrap();
    state.install_authenticated_current(material).unwrap();
    assert_eq!(state.initial_identity, initial);
    assert!(state.round_basis.is_none());
    assert!(state.round_events.is_empty());
    assert_eq!(
        state.direction(&holder).unwrap().head_operation.version(),
        4
    );
    assert_eq!(state.direction(&peer).unwrap().head_operation.version(), 1);
    assert!(
        state
            .directions
            .iter()
            .all(|d| d.scope_instances.is_empty())
    );
}

#[test]
fn independently_observed_gap_narrowing_fences_old_grants_without_inventing_a_head() {
    use arkret_models_collaboration::contact_operations::ContactScopeUpdateSchema;
    use arkret_test_kit::contact::ContactParticipant;
    let f = Ceremony::new();
    let mut state = f.state();
    let prior = contact_carrier_operation(&f.wire.scope_update).unwrap();
    let participant = ContactParticipant {
        account_id: prior
            .holder()
            .contact_actor_id()
            .as_account_id()
            .unwrap()
            .clone(),
        realm_id: prior.event().realm_id.clone(),
        verification_method: prior.producer_signer().verification_method().clone(),
        signing_seed: [22; 32],
        authority: &f.b,
    };
    let event = participant
        .event::<arkret_wire::event_spec::ContactScopeUpdate>(
            ContactScopeUpdatePayload {
                schema: ContactScopeUpdateSchema::V1,
                trust_domain_id: domain(),
                initial_contact_round_id: f.wire.round.contact_round_id.clone(),
                version: 4,
                predecessor_event_ref: event_id(72),
                peer: prior.peer().clone(),
                contact_round_id: f.wire.round.contact_round_id.clone(),
                granted_to_peer_scopes: vec![],
            },
            f.at,
        )
        .unwrap();
    let lineage = ContactLineage::sign_with(
        domain(),
        Some(f.wire.round.contact_round_id.clone()),
        Some(f.wire.round.contact_round_id.clone()),
        prior.holder().clone(),
        prior.peer().clone(),
        4,
        Some(event_id(72)),
        event.event_id.clone(),
        participant.producer().unwrap(),
        vec![],
        f.at,
        |bytes| f.b.sign(bytes, f.at),
    )
    .unwrap();
    let operation = ContactOperationEvidence::ScopeUpdate {
        signed_event: event,
        lineage,
    };
    verify_original_operation(&operation, DigestSuite::Sha256, f.at, &f).unwrap();
    state.observe_authenticated_operation(&operation).unwrap();
    let direction = state.direction(operation.holder()).unwrap();
    assert_eq!(direction.head_operation.version(), 1);
    assert!(direction.scope_instances.is_empty());
    assert!(direction.current_proof.is_none());
    assert!(state.apply_confirmed(operation).is_err());
    assert!(state.install_authenticated_current(f.material(1)).is_err());
    assert_eq!(state.directions.len(), 2);
}

#[test]
fn known_first_root_without_originals_requires_bounded_recovery_before_authoring() {
    use arkret_models_collaboration::contact_operations::ContactPrivateState;
    let f = Ceremony::new();
    let operation = contact_carrier_operation(&f.wire.scope_update).unwrap();
    let mut state = ContactPrivateState::default();
    state.observe_authenticated_operation(&operation).unwrap();
    assert!(state.initial_identity.is_none());
    assert_eq!(
        state.initial_root_floor.as_ref(),
        Some(&f.wire.round.contact_round_id)
    );
    assert!(state.next_operation(operation.holder()).is_err());
    state.install_authenticated_current(f.material(1)).unwrap();
    assert_eq!(state.next_operation(operation.holder()).unwrap().0, 2);
}

#[test]
fn normal_response_nested_request_cannot_change_the_fixed_identity_or_round_commitment() {
    let f = Ceremony::new();
    let mut operation = f.material(1).head_operation;
    let ContactOperationEvidence::Response {
        response_receipt, ..
    } = &mut operation
    else {
        panic!("normal response required");
    };
    response_receipt
        .request_receipt
        .core
        .initial_contact_round_id = Some(event_id(93).event_digest());
    assert!(operation.validate_shape().is_err());
    let mut operation = f.material(1).head_operation;
    let ContactOperationEvidence::Response {
        response_receipt,
        signed_event,
    } = &mut operation
    else {
        unreachable!()
    };
    response_receipt.contact_round_id = event_id(94).event_digest();
    signed_event.payload.insert(
        "contact_round_id".into(),
        serde_json::to_value(&response_receipt.contact_round_id).unwrap(),
    );
    assert!(operation.validate_shape().is_err());
}

#[test]
fn signed_current_cannot_restore_a_scope_removed_by_the_original_holder_head() {
    let f = Ceremony::new();
    let mut state = f.state();
    let operation = contact_carrier_operation(&f.wire.scope_update).unwrap();
    state.apply_confirmed(operation.clone()).unwrap();
    let mut material = f.material(1);
    material.head_operation = operation.clone();
    material.current_proof = f.sign_state(&state, operation.holder(), 1);
    f.verify(&material).unwrap();
    material.current_proof.scope_instances.push(
        arkret_models_collaboration::contact_operations::ContactScopeInstance {
            contact_scope: ContactScope::Invite,
            grant_event_ref: f.material(1).head_operation.event().event_id.clone(),
        },
    );
    material.current_proof.signature =
        f.b.sign(
            &material.current_proof.canonical_signing_bytes().unwrap(),
            material.current_proof.issued_at,
        )
        .unwrap();
    assert!(f.verify(&material).is_err());
    assert!(state.install_authenticated_current(material).is_err());
}

#[test]
fn independent_closure_cannot_be_reestablished_by_an_old_round_or_a_frozen_current() {
    let f = Ceremony::new();
    let mut state = f.state();
    let terminal = contact_carrier_operation(&f.wire.tombstone).unwrap();
    state
        .close_round(terminal.round_closure().unwrap())
        .unwrap();
    assert!(
        state
            .establish(f.wire.round.basis(), f.wire.round.round_events.clone())
            .is_err()
    );
    let mut material = f.material(0);
    material.current_proof = f.sign_state(&state, material.head_operation.holder(), 1);
    material.scope_grants.clear();
    f.verify(&material).unwrap();
    state.round_basis = None;
    state.round_events.clear();
    state
        .install_authenticated_current(material.clone())
        .unwrap();
    assert!(state.round_basis.is_none());
    material.round_evidence = None;
    material.round_events = None;
    f.verify(&material).unwrap();
    assert!(material.current_proof.scope_instances.is_empty());
}
