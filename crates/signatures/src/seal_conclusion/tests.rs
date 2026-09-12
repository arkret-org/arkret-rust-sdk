use arkret_canonical::{base64url_encode, canonical_json_bytes, sha256_digest};
use arkret_wire::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

use super::*;

fn realm() -> RealmId {
    RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
}

fn event() -> EventId {
    EventId::new("ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2").unwrap()
}

fn target() -> SealId {
    SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap()
}

fn cell() -> CellRef {
    CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null").unwrap()
}

fn descriptor(index: u8) -> NotarySignerDescriptor {
    let key = SigningKey::from_bytes(&[index; 32])
        .verifying_key()
        .to_bytes();
    NotarySignerDescriptor {
        actor_id: ActorId::service(
            DidCoreId::new(format!("ak:did_core:web:voter{index}.example")).unwrap(),
        ),
        verification_method: DidUrl::new(format!("did:web:voter{index}.example#notary")).unwrap(),
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: base64url_encode(key),
        frozen_public_key_digest: Hash::new(sha256_digest(key)).unwrap(),
    }
}

fn signature(index: u8, bytes: &[u8]) -> SealSignature {
    let method = descriptor(index).verification_method;
    let protected =
        base64url_encode(canonical_json_bytes(&json!({"alg":"Ed25519","kid":method})).unwrap());
    let input = format!("{protected}.{}", base64url_encode(bytes));
    let signed = SigningKey::from_bytes(&[index; 32]).sign(input.as_bytes());
    SealSignature {
        verification_method: method,
        payload_digest: Hash::new(sha256_digest(bytes)).unwrap(),
        jws: format!("{protected}..{}", base64url_encode(signed.to_bytes())),
    }
}

fn fixture(f: u32) -> (NotaryValue, SealConclusionSet, SealConclusionQuery) {
    let configuration =
        NotaryValue::new((1..=(3 * f + 1) as u8).map(descriptor).collect(), f, 1000).unwrap();
    let statement = SealConclusionStatement {
        realm_id: realm(),
        configuration_ref: event(),
        authority_seal_ref: target(),
        target_seal_ref: target(),
        results: vec![SealConclusionOutcome::Cell(SealConclusionCellOutcome {
            selector: SealConclusionCellSelector {
                kind: SealConclusionCellSelectorKind::Cell,
                cell_id: cell(),
            },
            state: None,
        })],
    };
    let bytes = statement.signing_payload_bytes().unwrap();
    let query = SealConclusionQuery {
        target_seal_ref: target(),
        selectors: statement
            .results
            .iter()
            .map(SealConclusionOutcome::selector)
            .collect(),
        known_configuration_ref: None,
    };
    let set = SealConclusionSet {
        configuration_handoffs: vec![],
        conclusions: vec![SealConclusionCertificate {
            statement,
            signatures: (1..=(2 * f + 1) as u8)
                .map(|index| signature(index, &bytes))
                .collect(),
        }],
    };
    (configuration, set, query)
}

#[test]
fn exact_quorum_consumes_partial_facts_without_seal_history() {
    for f in [0, 1] {
        let (configuration, set, query) = fixture(f);
        let facts = verify_seal_conclusion_facts(
            &set,
            &realm(),
            &event(),
            &configuration,
            &[query],
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(matches!(
            facts.result(&target(), &SealConclusionSelector::Cell { cell_id: cell() }),
            Some(SealConclusionOutcome::Cell(SealConclusionCellOutcome {
                state: None,
                ..
            }))
        ));
        let bundle = CbsProofBundle {
            target_seal_ref: target(),
            seals: vec![],
            control_moves: vec![],
            inclusion_proofs: vec![],
            availability_proofs: vec![],
            conclusion_set: Some(set),
        };
        bundle.validate_structural().unwrap();
    }
}

#[test]
fn configured_signer_alone_cannot_replace_three_votes() {
    let (configuration, mut set, _) = fixture(1);
    set.conclusions[0].signatures.truncate(1);
    assert!(
        verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &configuration).is_err()
    );
}

#[test]
fn extra_or_duplicate_votes_are_not_a_quorum() {
    let (configuration, mut set, _) = fixture(1);
    let bytes = set.conclusions[0]
        .statement
        .signing_payload_bytes()
        .unwrap();
    set.conclusions[0].signatures.push(signature(4, &bytes));
    assert!(
        verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &configuration).is_err()
    );
    set.conclusions[0].signatures.pop();
    set.conclusions[0].signatures[1] = set.conclusions[0].signatures[0].clone();
    assert!(
        verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &configuration).is_err()
    );
}

#[test]
fn wrong_result_and_cross_domain_signatures_fail() {
    let (configuration, mut set, _) = fixture(0);
    set.conclusions[0].statement.authority_seal_ref =
        SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap();
    assert!(
        verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &configuration).is_err()
    );
    let (_, mut set, _) = fixture(0);
    let wrong = canonical_json_bytes(
        &json!({"context":"ak.seal.commit.v1","statement":set.conclusions[0].statement}),
    )
    .unwrap();
    set.conclusions[0].signatures = vec![signature(1, &wrong)];
    assert!(
        verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &configuration).is_err()
    );
}

#[test]
fn missing_fact_or_local_conflict_cannot_be_accepted() {
    let (configuration, set, mut query) = fixture(0);
    assert!(
        verify_seal_conclusion_facts(
            &set,
            &realm(),
            &event(),
            &configuration,
            &[query.clone()],
            |_, _| Err(WireError::Protocol("known conflict".into()))
        )
        .is_err()
    );
    query.selectors = vec![SealConclusionSelector::Command {
        event_digest: event().event_digest(),
    }];
    assert!(
        verify_seal_conclusion_facts(
            &set,
            &realm(),
            &event(),
            &configuration,
            &[query],
            |_, _| Ok(())
        )
        .is_err()
    );
}

#[test]
fn absent_cell_written_null_and_missing_field_are_distinct() {
    let (_, set, _) = fixture(0);
    let absent = &set.conclusions[0].statement.results[0];
    let mut value = serde_json::to_value(absent).unwrap();
    value.as_object_mut().unwrap().remove("state");
    assert!(serde_json::from_value::<SealConclusionOutcome>(value).is_err());
    let written = SealConclusionCellState {
        revision_event_id: event(),
        value: serde_json::Value::Null,
    };
    assert_ne!(
        serde_json::to_value(written).unwrap(),
        serde_json::Value::Null
    );
}

#[test]
fn known_configuration_hint_neither_creates_trust_nor_changes_signed_facts() {
    let (configuration, set, mut query) = fixture(0);
    query.known_configuration_ref = Some(event());
    verify_seal_conclusion_facts(
        &set,
        &realm(),
        &event(),
        &configuration,
        &[query],
        |_, _| Ok(()),
    )
    .unwrap();
    let foreign = NotaryValue::new(vec![descriptor(9)], 0, 1000).unwrap();
    assert!(verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &foreign).is_err());
}

#[test]
fn bundle_requires_exact_certified_target() {
    let (_, set, _) = fixture(0);
    let mut bundle = CbsProofBundle {
        target_seal_ref: target(),
        seals: vec![],
        control_moves: vec![],
        inclusion_proofs: vec![],
        availability_proofs: vec![],
        conclusion_set: Some(set),
    };
    bundle.target_seal_ref = SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap();
    assert!(bundle.validate_structural().is_err());
    bundle.conclusion_set = None;
    assert!(bundle.validate_structural().is_err());
}

#[test]
fn collector_requires_distinct_valid_votes_and_emits_exact_threshold() {
    let (configuration, set, _) = fixture(1);
    let statement = set.conclusions[0].statement.clone();
    let bytes = statement.signing_payload_bytes().unwrap();
    let mut collector = SealConclusionCollector::new(statement, configuration.clone()).unwrap();
    collector.add_signature(signature(1, &bytes)).unwrap();
    collector.add_signature(signature(1, &bytes)).unwrap();
    assert!(collector.certificate().unwrap().is_none());
    assert!(
        collector
            .add_signature(signature(2, b"another statement"))
            .is_err()
    );
    assert!(collector.add_signature(signature(9, &bytes)).is_err());
    collector.add_signature(signature(2, &bytes)).unwrap();
    assert!(collector.certificate().unwrap().is_none());
    collector.add_signature(signature(3, &bytes)).unwrap();
    collector.add_signature(signature(4, &bytes)).unwrap();
    let certificate = collector.certificate().unwrap().unwrap();
    assert_eq!(certificate.signatures.len(), 3);
    verify_seal_conclusion_quorum_signatures(&certificate, &configuration).unwrap();
}

#[test]
fn old_quorum_authenticates_successor_then_successor_authenticates_history() {
    let (old, mut set, query) = fixture(0);
    let next_ref =
        EventId::from_event_digest(&Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap())
            .unwrap();
    let next = NotaryValue::new(vec![descriptor(2)], 0, 1000).unwrap();
    let statement = SealConfigurationHandoffStatement {
        realm_id: realm(),
        configuration_ref: event(),
        handoff_seal_ref: target(),
        next_configuration_ref: next_ref.clone(),
        next_configuration: next,
    };
    let payload = statement.signing_payload_bytes().unwrap();
    set.configuration_handoffs
        .push(SealConfigurationHandoffCertificate {
            statement,
            signatures: vec![signature(1, &payload)],
        });
    set.conclusions[0].statement.configuration_ref = next_ref;
    set.conclusions[0].signatures = vec![signature(
        2,
        &set.conclusions[0]
            .statement
            .signing_payload_bytes()
            .unwrap(),
    )];
    verify_seal_conclusion_facts(&set, &realm(), &event(), &old, &[query], |_, _| Ok(())).unwrap();
    set.configuration_handoffs[0].signatures = vec![signature(2, &payload)];
    assert!(verify_seal_conclusion_set_quorum_chain(&set, &realm(), &event(), &old).is_err());
}
