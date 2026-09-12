use arkret_canonical::{base64url_encode, canonical_json_bytes, sha256_digest};
use arkret_wire::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

use super::*;

fn hash(label: &str) -> Hash {
    Hash::new(sha256_digest(label.as_bytes())).unwrap()
}
fn id(label: &str) -> EventId {
    EventId::from_event_digest(&hash(label)).unwrap()
}
fn realm() -> RealmId {
    RealmId::from_event_id(&id("realm"))
}
fn descriptor(seed: u8) -> NotarySignerDescriptor {
    NotarySignerDescriptor {
        actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:authority.example").unwrap()),
        verification_method: DidUrl::new("did:web:authority.example#notary").unwrap(),
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: base64url_encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        ),
    }
}
fn signature(bytes: &[u8], seed: u8) -> SealSignature {
    let method = descriptor(seed).verification_method;
    let protected =
        base64url_encode(canonical_json_bytes(&json!({"alg":"Ed25519","kid":method})).unwrap());
    let input = format!("{protected}.{}", base64url_encode(bytes));
    SealSignature {
        verification_method: method,
        payload_digest: Hash::new(sha256_digest(bytes)).unwrap(),
        jws: format!(
            "{protected}..{}",
            base64url_encode(
                SigningKey::from_bytes(&[seed; 32])
                    .sign(input.as_bytes())
                    .to_bytes()
            )
        ),
    }
}
fn member() -> Event {
    arkret_wire::test_support::raw_event_at(
        "ak.member.state", ScopeRef::Realm { realm_id: realm() },
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station-a.example").unwrap(), 1,
        Hlc::new("0198d35d9800-0000-a13f9c2e").unwrap(),
        json!({"member_id":{"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station-a.example"
        }},"membership":"join"}),
        "2026-09-12T00:00:00Z".parse().unwrap(),
    ).unwrap()
}

struct Fixture {
    configuration: NotaryValue,
    configuration_ref: EventId,
    event: Event,
    seal: Seal,
    certificates: Vec<SealConclusionCertificate>,
}
impl Fixture {
    // These fixtures test signed authority-fact consumption, not admission or
    // executor replay. Producer authorization is deliberately outside this API.
    fn new(event: Event) -> Self {
        let configuration = NotaryValue::new(descriptor(1), 1000).unwrap();
        let genesis = event.kind == EventKind::RealmCreate;
        let configuration_ref = if genesis {
            event.event_id.clone()
        } else {
            id("configuration")
        };
        let writes =
            arkret_schema::project_registered_cell_writes(&event, DigestSuite::Sha256).unwrap();
        let mut effects: Vec<_> = writes
            .iter()
            .filter_map(|write| {
                let value = match &write.op {
                    ProjectedOp::TransitionTo { to } => to.clone(),
                    ProjectedOp::Direct(op) if op.kind == LatticeOpType::Set => {
                        op.value.clone().unwrap()
                    }
                    _ => return None,
                };
                Some(CommandResultEffect {
                    cell_id: write.cell_id.clone(),
                    state: CanonicalCellState::SequencedState(CanonicalSequencedState {
                        revision_event_id: event.event_id.clone(),
                        value,
                    }),
                })
            })
            .collect();
        effects.sort_by(|a, b| a.cell_id.cmp(&b.cell_id));
        let digest = event.event_id.event_digest();
        let command = SealCommandOutcome::committed(
            digest.clone(),
            vec![digest.clone()],
            effects.clone(),
            DigestSuite::Sha256,
        )
        .unwrap();
        let body = UnsignedSeal {
            realm_id: event.realm_id.clone(),
            predecessor_ref: (!genesis)
                .then(|| SealId::new(format!("ak:seal:{}", hash("previous"))).unwrap()),
            delta: vec![digest.clone()],
            control_event_set_root: hash("event-root"),
            state_root: hash("state-root"),
            notary_seq: u64::from(!genesis),
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: "2026-09-12T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("0198d35d9800-0000-a13f9c2e").unwrap(),
            configuration_ref: configuration_ref.clone(),
            command_results: vec![command.clone()],
            authorization_closures: vec![],
            existence_anchors: vec![],
        };
        let body_bytes = canonical_json_bytes(&body).unwrap();
        let transcript = canonical_json_bytes(
            &json!({"context":"ak.seal.commit.v1","seal_digest":sha256_digest(&body_bytes)}),
        )
        .unwrap();
        let seal = Seal::from_canonical_body_and_signature(
            &body_bytes,
            signature(&transcript, 1),
            DigestSuite::Sha256,
        )
        .unwrap();
        let mut results = vec![SealConclusionOutcome::Command(
            SealConclusionCommandOutcome {
                selector: SealConclusionCommandSelector {
                    kind: SealConclusionCommandSelectorKind::Command,
                    event_digest: digest.clone(),
                },
                result: Some(command),
            },
        )];
        results.extend(effects.into_iter().map(|effect| {
            let CanonicalCellState::SequencedState(state) = effect.state else {
                unreachable!()
            };
            SealConclusionOutcome::CommandEffect(SealConclusionCommandEffectOutcome {
                selector: SealConclusionCommandEffectSelector {
                    kind: SealConclusionCommandEffectSelectorKind::CommandEffect,
                    event_digest: digest.clone(),
                    cell_id: effect.cell_id,
                },
                state: Some(SealConclusionCellState {
                    revision_event_id: state.revision_event_id,
                    value: state.value,
                }),
            })
        }));
        results.sort_by_key(|result| canonical_json_bytes(&result.selector()).unwrap());
        let statement = SealConclusionStatement {
            realm_id: event.realm_id.clone(),
            configuration_ref: configuration_ref.clone(),
            authority_seal_ref: seal.id.clone(),
            target_seal_ref: seal.id.clone(),
            results,
        };
        let signed = signature(&statement.signing_payload_bytes().unwrap(), 1);
        Self {
            configuration,
            configuration_ref,
            event,
            seal,
            certificates: vec![SealConclusionCertificate {
                statement,
                signature: signed,
            }],
        }
    }
    fn verify(&self) -> Result<ConfirmedAuthorizationSources, HistoryEvidenceError> {
        ConfirmedAuthorizationSources::verify_at_seal(
            &self.seal.realm_id,
            &self.configuration_ref,
            &self.configuration,
            &self.seal,
            &self.certificates,
            std::slice::from_ref(&self.event),
            DigestSuite::Sha256,
        )
    }
    fn resign_conclusion(&mut self) {
        self.certificates[0].signature = signature(
            &self.certificates[0]
                .statement
                .signing_payload_bytes()
                .unwrap(),
            1,
        );
    }

    fn resign_seal_and_conclusion(&mut self) {
        self.seal.id = Seal::id_from_canonical_bytes(
            &self.seal.canonical_bytes_for_id().unwrap(),
            DigestSuite::Sha256,
        )
        .unwrap();
        self.seal.notary_signature = signature(
            &self
                .seal
                .commit_transcript_bytes(DigestSuite::Sha256)
                .unwrap(),
            1,
        );
        let statement = &mut self.certificates[0].statement;
        statement.authority_seal_ref = self.seal.id.clone();
        statement.target_seal_ref = self.seal.id.clone();
        self.resign_conclusion();
    }
}

#[test]
fn exact_committed_member_origin_preserves_full_account_and_is_not_permission() {
    let fixture = Fixture::new(member());
    let sources = fixture.verify().unwrap();
    let [source] = sources.sources() else {
        panic!("one membership origin")
    };
    assert_eq!(
        source.dependency_kind(),
        AuthorizationDependencyKind::MemberJoin
    );
    assert_eq!(source.authorization_event_id(), &fixture.event.event_id);
    assert_eq!(source.generation_event_id(), &fixture.event.event_id);
    assert_eq!(
        serde_json::to_value(source.subject().unwrap()).unwrap(),
        fixture.event.payload["member_id"]
    );
    assert_eq!(sources.committing_seal(), &fixture.seal.id);
}

#[test]
fn trusted_configuration_cannot_be_replaced_by_same_named_foreign_key() {
    let mut fixture = Fixture::new(member());
    fixture.configuration = NotaryValue::new(descriptor(2), 1000).unwrap();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn seal_and_conclusion_each_require_real_signatures() {
    let mut fixture = Fixture::new(member());
    fixture.certificates[0].signature = signature(
        &fixture.certificates[0]
            .statement
            .signing_payload_bytes()
            .unwrap(),
        2,
    );
    assert!(fixture.verify().is_err());
    let mut fixture = Fixture::new(member());
    fixture.seal.notary_signature = signature(
        &fixture
            .seal
            .commit_transcript_bytes(DigestSuite::Sha256)
            .unwrap(),
        2,
    );
    assert!(fixture.verify().is_err());
}

#[test]
fn missing_effect_stays_pending_and_signed_wrong_effect_does_not_certify_origin() {
    let mut fixture = Fixture::new(member());
    fixture.certificates[0]
        .statement
        .results
        .retain(|result| matches!(result, SealConclusionOutcome::Command(_)));
    fixture.resign_conclusion();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Unavailable(_))
    ));
    let mut fixture = Fixture::new(member());
    for result in &mut fixture.certificates[0].statement.results {
        if let SealConclusionOutcome::CommandEffect(effect) = result {
            effect.state.as_mut().unwrap().revision_event_id = id("other-source");
        }
    }
    fixture.resign_conclusion();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn re_signed_command_result_cannot_replace_exact_seal_unit() {
    let mut fixture = Fixture::new(member());
    for result in &mut fixture.certificates[0].statement.results {
        if let SealConclusionOutcome::Command(command) = result {
            command
                .result
                .as_mut()
                .unwrap()
                .unit_event_digests
                .push(hash("another-member"));
        }
    }
    fixture.resign_conclusion();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn altered_source_bytes_and_uncommitted_source_are_rejected() {
    let mut fixture = Fixture::new(member());
    fixture
        .event
        .payload
        .insert("membership".into(), json!("leave"));
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
    fixture
        .event
        .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Unavailable(_))
    ));
}

#[test]
fn rejected_command_never_authenticates_an_origin_even_with_signed_effect() {
    let mut fixture = Fixture::new(member());
    let command = &mut fixture.seal.command_results[0];
    *command = SealCommandOutcome::rejected(
        command.event_digest.clone(),
        command.unit_event_digests.clone(),
        ReasonCode::InvalidMembershipTransition,
        DigestSuite::Sha256,
    )
    .unwrap();
    fixture.seal.delta.clear();
    for result in &mut fixture.certificates[0].statement.results {
        if let SealConclusionOutcome::Command(conclusion) = result {
            conclusion.result = Some(command.clone());
        }
    }
    fixture.resign_seal_and_conclusion();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn foreign_target_and_configuration_ref_cannot_supply_missing_facts() {
    let mut fixture = Fixture::new(member());
    fixture.certificates[0].statement.target_seal_ref =
        SealId::new(format!("ak:seal:{}", hash("foreign"))).unwrap();
    fixture.resign_conclusion();
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
    let mut fixture = Fixture::new(member());
    fixture.configuration_ref = id("untrusted-candidate-config");
    assert!(matches!(
        fixture.verify(),
        Err(HistoryEvidenceError::Invalid(_))
    ));
}

#[test]
fn circle_membership_origin_is_bound_to_exact_circle_and_member() {
    let mut event = member();
    event.kind = EventKind::CircleMemberState;
    let circle_id = CircleId::from_event_id(&id("circle"));
    event.scope_ref = ScopeRef::Circle {
        realm_id: event.realm_id.clone(),
        circle_id: circle_id.clone(),
    };
    event.payload.insert("circle_id".into(), json!(circle_id));
    event
        .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    let fixture = Fixture::new(event);
    let sources = fixture.verify().unwrap();
    assert_eq!(sources.sources()[0].scope_ref(), &fixture.event.scope_ref);
    assert_eq!(
        sources.sources()[0].dependency_kind(),
        AuthorizationDependencyKind::MemberJoin
    );
}

#[test]
fn genesis_independent_dependencies_share_event_without_sharing_kind() {
    let notary = NotaryValue::new(descriptor(1), 1000).unwrap();
    let payload = crate::RealmCreatePayload::new(
        crate::RealmGenesis::event_derived(
            crate::RealmPurpose::Collaboration,
            GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            vec!["ak.schema.realm.genesis.v1".into()],
            ReducerProfileId::CORE_V1,
            DigestSuite::Sha256,
            SecurityClass::Standard,
            EncryptionProfile::None,
            notary,
        )
        .unwrap(),
    );
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        member().actor_id,
        1,
        Hlc::new("0198d35d9800-0000-a13f9c2e").unwrap(),
        payload.to_value().unwrap(),
        "2026-09-12T00:00:00Z".parse().unwrap(),
    )
    .unwrap();
    let fixture = Fixture::new(event);
    let sources = fixture.verify().unwrap();
    assert_eq!(sources.sources().len(), 5);
    let kinds: std::collections::BTreeSet<_> = sources
        .sources()
        .iter()
        .map(|source| {
            assert_eq!(source.authorization_event_id(), &fixture.event.event_id);
            assert_eq!(source.generation_event_id(), &fixture.event.event_id);
            source.dependency_kind().as_str()
        })
        .collect();
    assert_eq!(kinds.len(), 5);
}
