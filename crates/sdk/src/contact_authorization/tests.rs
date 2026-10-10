use arkret_identity::AuthorityHistoryUnavailable;
use arkret_models_collaboration::contact_operations::ContactLineage;
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
    fn lineage(&self, version: u8, scopes: &[ContactScope], terminal: bool) -> ContactLineage {
        let mut lineage = ContactLineage {
            contact_round_id: self.round.clone(),
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
            terminal: terminal.then_some(true),
            signature: self.signature.clone(),
        };
        self.resign(&mut lineage);
        lineage
    }
    fn resign(&self, lineage: &mut ContactLineage) {
        lineage.signature.jws = self.sign(&lineage.canonical_signing_bytes().unwrap());
    }
    fn checkpoint(&self, last: &ContactLineage) -> ContactCurrentProof {
        let mut proof = ContactCurrentProof {
            contact_round_id: self.round.clone(),
            issuer_id: self.issuer.delivery_station_id().clone(),
            peer: self.peer.clone(),
            terminal: last.terminal == Some(true),
            head_event_ref: last.event_ref.clone(),
            accepted_commit_event_ids: vec![last.event_ref.clone()],
            complete_through: last.version,
            fresh_until: self.signature.created_at + Duration::minutes(5),
            signature: self.signature.clone(),
        };
        proof.signature.jws = self.sign(&proof.canonical_signing_bytes().unwrap());
        proof
    }
    fn verify(&self, chain: &[ContactLineage]) -> Result<VerifiedContactDirection> {
        verify_test_lineage_history(
            &self.issuer,
            &self.peer,
            &self.round,
            chain,
            &self.checkpoint(chain.last().unwrap()),
            self.signature.created_at,
            self,
        )
    }
}
fn event_id(value: u8) -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [value; 32])
}

#[test]
fn scopes_keep_their_generation_until_removed_then_readded() {
    use ContactScope::{DirectMessage, Presence, VoiceCall};
    let fixture = Fixture::new();
    let chain = vec![
        fixture.lineage(1, &[DirectMessage, Presence], false),
        fixture.lineage(2, &[DirectMessage, VoiceCall], false),
        fixture.lineage(3, &[VoiceCall], false),
        fixture.lineage(4, &[DirectMessage, VoiceCall], false),
    ];
    let verified = fixture.verify(&chain).unwrap();
    let retained = verified.open_interval(VoiceCall).unwrap();
    assert_eq!(retained.authorization_event_id(), &event_id(1));
    assert_eq!(retained.generation_event_id(), &event_id(2));
    let readded = verified.open_interval(DirectMessage).unwrap();
    assert_eq!(readded.authorization_event_id(), &event_id(1));
    assert_eq!(readded.generation_event_id(), &event_id(4));
    assert!(
        verified
            .intervals()
            .iter()
            .any(|interval| interval.scope() == DirectMessage
                && interval.generation_event_id() == &event_id(1)
                && interval.closed_by() == Some(&event_id(3)))
    );
    assert!(verified.open_interval(Presence).is_none());
    assert!(matches!(
        verified.require_current_at(fixture.signature.created_at + Duration::hours(1)),
        Err(ContactAuthorizationError::NotCurrent)
    ));
    assert_eq!(
        verified
            .open_interval(DirectMessage)
            .unwrap()
            .generation_event_id(),
        &event_id(4)
    );
}

#[test]
fn terminal_closes_every_scope_and_cannot_reopen_the_round() {
    let fixture = Fixture::new();
    let mut chain = vec![
        fixture.lineage(1, &[ContactScope::DirectMessage], false),
        fixture.lineage(2, &[ContactScope::DirectMessage], true),
    ];
    let verified = fixture.verify(&chain).unwrap();
    assert!(
        verified
            .open_interval(ContactScope::DirectMessage)
            .is_none()
    );
    assert_eq!(verified.intervals()[0].closed_by(), Some(&event_id(2)));
    chain.push(fixture.lineage(3, &[ContactScope::DirectMessage], false));
    assert!(matches!(
        fixture.verify(&chain),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn incomplete_chains_are_pending_but_false_predecessors_are_invalid() {
    let fixture = Fixture::new();
    let first = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    let second = fixture.lineage(2, &[], false);
    let third = fixture.lineage(3, &[ContactScope::DirectMessage], false);
    assert!(matches!(
        fixture.verify(&[second.clone(), third.clone()]),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    assert!(matches!(
        fixture.verify(&[first.clone(), third]),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    let mut bad = second;
    bad.predecessor_event_ref = Some(event_id(9));
    fixture.resign(&mut bad);
    assert!(matches!(
        fixture.verify(&[first, bad]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn rejects_wrong_pair_round_source_and_payload_tampering() {
    let fixture = Fixture::new();
    let original = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    let mut wrong_pair = original.clone();
    wrong_pair.peer = fixture.issuer.clone();
    fixture.resign(&mut wrong_pair);
    assert!(matches!(
        fixture.verify(&[wrong_pair]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut wrong_round = original.clone();
    wrong_round.contact_round_id = Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap();
    fixture.resign(&mut wrong_round);
    assert!(matches!(
        fixture.verify(&[wrong_round]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut wrong_source = original.clone();
    wrong_source.signature.verification_method =
        DidUrl::new("did:webvh:zother:other.example#key").unwrap();
    assert!(matches!(
        fixture.verify(&[wrong_source]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut tampered = original;
    tampered.granted_to_peer_scopes.push(ContactScope::Presence);
    assert!(matches!(
        fixture.verify(&[tampered]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn verifies_method_history_and_historical_assertion_relationship() {
    let mut fixture = Fixture::new();
    let mut lineage = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    lineage.signature.verification_method =
        DidUrl::new(format!("{}#not-an-assertion-key", fixture.history.did)).unwrap();
    assert!(matches!(
        fixture.verify(&[lineage]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let lineage = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    fixture.history.has_more = true;
    assert!(matches!(
        fixture.verify(std::slice::from_ref(&lineage)),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    fixture.history.has_more = false;
    fixture.history.entries[0]["state"]["alsoKnownAs"] =
        serde_json::json!(["https://forged.example/"]);
    assert!(matches!(
        fixture.verify(&[lineage]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn first_observation_requires_current_evidence() {
    let fixture = Fixture::new();
    let chain = vec![fixture.lineage(1, &[ContactScope::DirectMessage], false)];
    let checkpoint = fixture.checkpoint(&chain[0]);
    assert!(matches!(
        verify_test_lineage_history(
            &fixture.issuer,
            &fixture.peer,
            &fixture.round,
            &chain,
            &checkpoint,
            checkpoint.fresh_until,
            &fixture
        ),
        Err(ContactAuthorizationError::NotCurrent)
    ));
}

fn verify_test_lineage_history(
    issuer: &ContactPeer,
    peer: &ContactPeer,
    round: &Hash,
    lineages: &[ContactLineage],
    checkpoint: &ContactCurrentProof,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactDirection> {
    let transitions = lineages
        .iter()
        .map(|lineage| {
            verify_source_signature(
                issuer.delivery_station_id(),
                &lineage.signature,
                &lineage.canonical_signing_bytes().map_err(invalid)?,
                resolver,
            )?;
            Ok(ContactTransition {
                contact_round_id: lineage.contact_round_id.clone(),
                issuer: lineage.issuer.clone(),
                peer: lineage.peer.clone(),
                version: lineage.version,
                predecessor_event_ref: lineage.predecessor_event_ref.clone(),
                event_ref: lineage.event_ref.clone(),
                granted_to_peer_scopes: lineage.granted_to_peer_scopes.clone(),
                terminal: lineage.terminal,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    verify_transition_history(
        issuer,
        peer,
        round,
        &transitions,
        checkpoint,
        observed_at,
        resolver,
        None,
    )
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
                "peer":self.source.peer, "granted_to_peer_scopes":["direct_message"],
                "introduction_evidence_digest":arkret_canonical::sha256_digest(bytes),
            }),
        );
        let mut receipt = RequestAcceptanceReceipt {
            core: RequestAcceptanceReceiptCore {
                holder: self.source.issuer.clone(),
                peer: self.source.peer.clone(),
                slot_version: 1,
                slot_predecessor: None,
                previous_terminal_contact_round_id: None,
                request_event_ref: event.event_id.clone(),
                producer_signer: self.producer_signer(),
                source_checkpoint: self.source.round.clone(),
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
            serde_json::json!({"peer":self.source.peer,"contact_round_id":self.source.round,
            "version":version,"predecessor_event_ref":previous})
        } else {
            serde_json::json!({"schema":"ak.schema.contact_scope_update.v1",
            "peer":self.source.peer,"contact_round_id":self.source.round,"version":version,"predecessor_event_ref":previous,"granted_to_peer_scopes":["voice_call"]})
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
        let checkpoint = self.source.checkpoint(&lineage);
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
        verified.transition.is_none(),
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
fn carrier_later_head_requires_exact_successor_chain_and_remote_terminal_preserves_local_version() {
    let fixture = CarrierFixture::new();
    let initial = ContactTransition {
        contact_round_id: fixture.source.round.clone(),
        issuer: fixture.source.issuer.clone(),
        peer: fixture.source.peer.clone(),
        version: 1,
        predecessor_event_ref: None,
        event_ref: event_id(1),
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        terminal: None,
    };
    let mut other = initial.clone();
    other.issuer = fixture.source.peer.clone();
    other.peer = fixture.source.issuer.clone();
    other.event_ref = event_id(7);
    // This reducer test supplies origins directly; carrier and round-origin
    // authentication have independent cryptographic tests below and above.
    let round = VerifiedContactRound {
        round: fixture.source.round.clone(),
        origins: [initial, other],
        origin_checkpoints: Vec::new(),
    };
    let mut v2 = fixture.successor(&event_id(1), 2, false);
    let id2 = fixture.authenticate(&v2).unwrap().event_id;
    let v3 = fixture.successor(&id2, 3, true);
    let proof3 = match &v3 {
        PeerContactSubmitRequestBody::Tombstone { current_proof, .. } => current_proof.clone(),
        _ => unreachable!(),
    };
    if let PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. } = &mut v2 {
        *current_proof = proof3.clone();
    }
    let e2 = fixture.authenticate(&v2).unwrap();
    let e3 = fixture.authenticate(&v3).unwrap();
    assert!(matches!(
        verify_contact_direction_history(
            &round,
            &fixture.source.issuer,
            std::slice::from_ref(&e2),
            &proof3,
            fixture.source.signature.created_at,
            &fixture.source,
            None
        ),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    let verified = verify_contact_direction_history(
        &round,
        &fixture.source.issuer,
        &[e2, e3.clone()],
        &proof3,
        fixture.source.signature.created_at,
        &fixture.source,
        None,
    )
    .unwrap();
    assert!(verified.open_interval(ContactScope::VoiceCall).is_none());
    let mut opposite = proof3;
    opposite.peer = fixture.source.issuer.clone();
    opposite.complete_through = 1;
    opposite.signature.jws = fixture
        .source
        .sign(&opposite.canonical_signing_bytes().unwrap());
    let verified = verify_contact_direction_history(
        &round,
        &fixture.source.peer,
        &[],
        &opposite,
        fixture.source.signature.created_at,
        &fixture.source,
        e3.terminal_fence().as_ref(),
    )
    .unwrap();
    assert!(
        verified
            .open_interval(ContactScope::DirectMessage)
            .is_none()
    );
    opposite.complete_through = 3;
    opposite.signature.jws = fixture
        .source
        .sign(&opposite.canonical_signing_bytes().unwrap());
    assert!(
        verify_contact_direction_history(
            &round,
            &fixture.source.peer,
            &[],
            &opposite,
            fixture.source.signature.created_at,
            &fixture.source,
            e3.terminal_fence().as_ref()
        )
        .is_err()
    );
}

impl CarrierFixture {
    fn reversed(&self) -> Self {
        let mut reverse = Self::new();
        std::mem::swap(&mut reverse.source.issuer, &mut reverse.source.peer);
        reverse.method = DidUrl::new(
            "did:webvh:zfixturebob:bob.example#ak:device:0196419b-0000-7000-8000-000000000001",
        )
        .unwrap();
        reverse
    }
    fn initial_proof(&self, round: &Hash, event: &EventId) -> ContactCurrentProof {
        let mut proof = self.source.checkpoint(&self.source.lineage(1, &[], false));
        proof.contact_round_id = round.clone();
        proof.head_event_ref = event.clone();
        proof.accepted_commit_event_ids = vec![event.clone()];
        proof.signature.jws = self.source.sign(&proof.canonical_signing_bytes().unwrap());
        proof
    }
}

#[test]
fn carrier_normal_round_uses_exact_request_and_response_origins_and_reject_never_grants() {
    use arkret_models_collaboration::contact_operations::{
        NormalResponseAcceptanceReceipt, RejectAcceptanceReceipt,
    };
    let a = CarrierFixture::new();
    let b = a.reversed();
    let request = a.request();
    let er = a.authenticate(&request).unwrap();
    let PeerContactSubmitRequestBody::Request {
        request_receipt, ..
    } = &request
    else {
        unreachable!()
    };
    let mut pair = [
        a.source.issuer.contact_actor_id(),
        b.source.issuer.contact_actor_id(),
    ];
    pair.sort_by_key(|actor| arkret_canonical::canonical_json_bytes(actor).unwrap());
    let core = ContactRound::Normal {
        sorted_pair_member_ids: pair,
        request_event_ref: er.event_id.clone(),
        request_acceptance_receipt_digest: request_receipt.computed_receipt_digest().unwrap(),
    };
    let round = compute_contact_round_id(&core).unwrap();
    let accept=b.event(EventKind::ContactAccepted,serde_json::json!({"peer":b.source.peer,"contact_round_id":round,"version":1,
        "request_event_ref":er.event_id,"request_acceptance_receipt_digest":request_receipt.computed_receipt_digest().unwrap(),"granted_to_peer_scopes":["voice_call"]}));
    let mut response = NormalResponseAcceptanceReceipt {
        contact_round_id: round.clone(),
        request_receipt: request_receipt.clone(),
        response_event_ref: accept.event_id.clone(),
        producer_signer: b.producer_signer(),
        outgoing_slot_absence_digest: a.source.round.clone(),
        accepted_at: accept.created_at,
        issuer_id: b.source.issuer.delivery_station_id().clone(),
        signature: b.source.signature.clone(),
    };
    response.signature.jws = b.source.sign(&response.canonical_signing_bytes().unwrap());
    let accepted = PeerContactSubmitRequestBody::Response {
        idempotency_key: arkret_wire::IdempotencyKey::new("response-fixture").unwrap(),
        signed_event: accept,
        response_receipt: response.clone(),
        contact_address: b.address(),
        current_proof: None,
    };
    let ea = b.authenticate(&accepted).unwrap();
    let mut bundle = ContactRoundEvidenceBundle {
        contact_round_id: round.clone(),
        previous_terminal_contact_round_id: None,
        contact_round: core,
        request_receipts: vec![request_receipt.clone()],
        normal_response_receipt: Some(response),
        glare_concurrency_attestations: None,
        current_proofs: vec![
            a.initial_proof(&round, &er.event_id),
            b.initial_proof(&round, &ea.event_id),
        ],
        continuity_checkpoint: None,
    };
    let verified = verify_contact_round_origins(
        &bundle,
        &[er.clone(), ea.clone()],
        a.source.signature.created_at,
        &a.source,
    )
    .unwrap();
    let first = verify_contact_direction_history(
        &verified,
        &a.source.issuer,
        &[],
        &bundle.current_proofs[0],
        a.source.signature.created_at,
        &a.source,
        None,
    )
    .unwrap();
    assert_eq!(
        first
            .open_interval(ContactScope::DirectMessage)
            .unwrap()
            .authorization_event_id(),
        &er.event_id
    );
    let second = verify_contact_direction_history(
        &verified,
        &b.source.issuer,
        &[],
        &bundle.current_proofs[1],
        a.source.signature.created_at,
        &a.source,
        None,
    )
    .unwrap();
    assert_eq!(
        second
            .open_interval(ContactScope::VoiceCall)
            .unwrap()
            .generation_event_id(),
        &ea.event_id
    );
    bundle.current_proofs[1] = bundle.current_proofs[0].clone();
    assert!(
        verify_contact_round_origins(
            &bundle,
            &[er.clone(), ea],
            a.source.signature.created_at,
            &a.source
        )
        .is_err(),
        "equal Station ids cannot disguise duplicate directions"
    );
    let reject = b.event(
        EventKind::ContactRejected,
        serde_json::json!({"peer":b.source.peer,"request_event_ref":er.event_id,
        "request_acceptance_receipt_digest":request_receipt.computed_receipt_digest().unwrap()}),
    );
    let mut receipt = RejectAcceptanceReceipt {
        request_receipt: request_receipt.clone(),
        reject_event_ref: reject.event_id.clone(),
        producer_signer: b.producer_signer(),
        accepted_at: reject.created_at,
        issuer_id: b.source.issuer.delivery_station_id().clone(),
        signature: b.source.signature.clone(),
    };
    receipt.signature.jws = b.source.sign(&receipt.canonical_signing_bytes().unwrap());
    let rejected = PeerContactSubmitRequestBody::Reject {
        idempotency_key: arkret_wire::IdempotencyKey::new("reject-fixture").unwrap(),
        signed_event: reject,
        reject_receipt: receipt,
        contact_address: b.address(),
    };
    let rejected = b.authenticate(&rejected).unwrap();
    assert!(rejected.transition.is_none());
    assert!(rejected.terminal_fence().is_none());
}

#[test]
fn carrier_glare_round_authenticates_both_requests_and_both_source_attestations() {
    use arkret_models_collaboration::contact_operations::GlareConcurrencyAttestation;
    let a = CarrierFixture::new();
    let b = a.reversed();
    let ar = a.request();
    let br = b.request();
    let ea = a.authenticate(&ar).unwrap();
    let eb = b.authenticate(&br).unwrap();
    let PeerContactSubmitRequestBody::Request {
        request_receipt: ra,
        ..
    } = ar
    else {
        unreachable!()
    };
    let PeerContactSubmitRequestBody::Request {
        request_receipt: rb,
        ..
    } = br
    else {
        unreachable!()
    };
    let core = ContactRound::glare_from_request_receipts(&[ra.clone(), rb.clone()]).unwrap();
    let round = compute_contact_round_id(&core).unwrap();
    let attestation = |f: &CarrierFixture| {
        let mut proof = GlareConcurrencyAttestation {
            subject_id: f.source.issuer.contact_actor_id(),
            issuer_id: f.source.issuer.delivery_station_id().clone(),
            peer_id: f.source.peer.contact_actor_id(),
            request_receipt_digests: [
                ra.computed_receipt_digest().unwrap(),
                rb.computed_receipt_digest().unwrap(),
            ],
            observed_commit_event_ids: vec![ea.event_id.clone(), eb.event_id.clone()],
            complete_through: 1,
            unconsumed_slot_checkpoint: f.source.round.clone(),
            observed_at: f.source.signature.created_at,
            signature: f.source.signature.clone(),
        };
        proof.signature.jws = f.source.sign(&proof.canonical_signing_bytes().unwrap());
        proof
    };
    let mut bundle = ContactRoundEvidenceBundle {
        contact_round_id: round.clone(),
        previous_terminal_contact_round_id: None,
        contact_round: core,
        request_receipts: vec![ra.clone(), rb.clone()],
        normal_response_receipt: None,
        glare_concurrency_attestations: Some([attestation(&a), attestation(&b)]),
        current_proofs: vec![
            a.initial_proof(&round, &ea.event_id),
            b.initial_proof(&round, &eb.event_id),
        ],
        continuity_checkpoint: None,
    };
    let verified = verify_contact_round_origins(
        &bundle,
        &[ea.clone(), eb.clone()],
        a.source.signature.created_at,
        &a.source,
    )
    .unwrap();
    for (index, event) in [&ea, &eb].into_iter().enumerate() {
        let direction = verify_contact_direction_history(
            &verified,
            event.holder(),
            &[],
            &bundle.current_proofs[index],
            a.source.signature.created_at,
            &a.source,
            None,
        )
        .unwrap();
        assert_eq!(
            direction
                .open_interval(ContactScope::DirectMessage)
                .unwrap()
                .authorization_event_id(),
            event.event_id()
        );
    }
    bundle.glare_concurrency_attestations.as_mut().unwrap()[1].subject_id =
        a.source.issuer.contact_actor_id();
    assert!(
        verify_contact_round_origins(&bundle, &[ea, eb], a.source.signature.created_at, &a.source)
            .is_err()
    );
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
    let mut event= f.event(EventKind::ContactTombstone,serde_json::json!({"peer":f.source.peer,"contact_round_id":f.source.round,"version":2,"predecessor_event_ref":event_id(1)}));
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
        let current_proof = f.source.checkpoint(&lineage);
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

#[test]
fn carrier_current_proof_cannot_precede_its_command_or_skip_remote_terminal_local_history() {
    let f = CarrierFixture::new();
    let initial = ContactTransition {
        contact_round_id: f.source.round.clone(),
        issuer: f.source.issuer.clone(),
        peer: f.source.peer.clone(),
        version: 1,
        predecessor_event_ref: None,
        event_ref: event_id(1),
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        terminal: None,
    };
    let mut other = initial.clone();
    other.issuer = f.source.peer.clone();
    other.peer = f.source.issuer.clone();
    other.event_ref = event_id(7);
    let mut round = VerifiedContactRound {
        round: f.source.round.clone(),
        origins: [initial, other],
        origin_checkpoints: Vec::new(),
    };
    let mut carrier = f.successor(&event_id(1), 2, false);
    let current = match &carrier {
        PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. } => current_proof.clone(),
        _ => unreachable!(),
    };
    if let PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. } = &mut carrier {
        *current_proof = f.initial_proof(&f.source.round, &event_id(1));
    }
    let event = f.authenticate(&carrier).unwrap();
    assert!(matches!(
        verify_contact_direction_history(
            &round,
            &f.source.issuer,
            &[event],
            &current,
            f.source.signature.created_at,
            &f.source,
            None
        ),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let terminal = f.successor(&event_id(1), 2, true);
    let terminal = f.authenticate(&terminal).unwrap();
    let fence = terminal.terminal_fence().unwrap();
    let mut proof = f.initial_proof(&f.source.round, terminal.event_id());
    proof.peer = f.source.issuer.clone();
    proof.terminal = true;
    proof.signature.jws = f.source.sign(&proof.canonical_signing_bytes().unwrap());
    let mut higher = proof.clone();
    higher.complete_through = 9;
    higher.signature.jws = f.source.sign(&higher.canonical_signing_bytes().unwrap());
    round.origin_checkpoints.push(higher);
    assert!(matches!(
        verify_contact_direction_history(
            &round,
            &f.source.peer,
            &[],
            &proof,
            f.source.signature.created_at,
            &f.source,
            Some(&fence)
        ),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
}
