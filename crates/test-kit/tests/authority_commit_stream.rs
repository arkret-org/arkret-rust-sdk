//! Real signatures do not turn a malformed independent stream into a valid chain.

use arkret_models_collaboration::events_payloads::message::{ContentBlock, MessageCreatePayload};
use arkret_test_kit::authority_objects::signed_commit;
use arkret_test_kit::{SignedEventFixtureBuilder, seeded_signer, subjects};
use arkret_wire::{ActorId, Event, RealmCommitId, ScopeRef};

fn event(scope: ScopeRef, sequence: u64) -> Event {
    SignedEventFixtureBuilder::new(
        "ak.message.create",
        scope,
        ActorId::account(subjects::alice_account_id()),
        serde_json::to_value(MessageCreatePayload::with_content(
            subjects::strand_id(),
            "discussion",
            ContentBlock::text(format!("fixture message {sequence}")),
        ))
        .unwrap(),
    )
    .sign_verifiable(&seeded_signer(
        subjects::alice_did(),
        subjects::alice_verification_method(),
    ))
    .unwrap()
    .expect_verifiable()
}

#[test]
fn signed_authority_material_preserves_independent_streams_and_refuses_bad_successors() {
    let realm = ScopeRef::Realm {
        realm_id: subjects::realm_id(),
    };
    let circle = ScopeRef::Circle {
        realm_id: subjects::realm_id(),
        circle_id: "ak:circle:ATJ_DJ_0dc3yFbBW3UWM7qysprZ6zJPZzhxGzqahfHEA"
            .parse()
            .unwrap(),
    };
    let authority = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
    let method = arkret_wire::DidUrl::new("did:web:station.example#notary-key").unwrap();
    let genesis = event(realm.clone(), 0);
    let first = signed_commit(
        &method,
        &authority,
        &genesis,
        0,
        None,
        genesis.event_id.clone(),
        None,
    )
    .unwrap();
    let private_genesis = event(circle, 0);
    let private_first = signed_commit(
        &method,
        &authority,
        &private_genesis,
        0,
        None,
        genesis.event_id.clone(),
        None,
    )
    .unwrap();
    let next_event = event(realm, 1);
    let next = signed_commit(
        &method,
        &authority,
        &next_event,
        1,
        Some(first.commit_id.clone()),
        genesis.event_id.clone(),
        None,
    )
    .unwrap();
    next.validate_successor_of(&first).unwrap();
    assert!(next.validate_successor_of(&private_first).is_err());
    for (position, previous) in [
        (1, Some(RealmCommitId::from_digest([93; 32]))),
        (2, Some(first.commit_id.clone())),
        (0, None),
    ] {
        let invalid = signed_commit(
            &method,
            &authority,
            &next_event,
            position,
            previous,
            genesis.event_id.clone(),
            None,
        )
        .unwrap();
        invalid.validate_content_address().unwrap();
        assert!(invalid.validate_successor_of(&first).is_err());
    }
    assert!(
        signed_commit(
            &method,
            &authority,
            &next_event,
            0,
            Some(first.commit_id),
            genesis.event_id.clone(),
            None
        )
        .is_err()
    );
    assert!(
        signed_commit(
            &method,
            &authority,
            &next_event,
            1,
            None,
            genesis.event_id,
            None
        )
        .is_err()
    );
    let mut corrupt = next;
    corrupt.previous_commit_ref = Some(private_first.commit_id);
    assert!(corrupt.validate_content_address().is_err());
    assert!(
        arkret_signatures::detached_object::verify_detached_object_signature(
            &corrupt.signature,
            &arkret_canonical::unsigned_value(&corrupt, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: authority.verifying_key().to_bytes().to_vec()
            }
        )
        .is_err()
    );
}
