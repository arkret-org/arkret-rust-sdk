//! Round-trip tests for the Realm authority-chain verifier.
//!
//! The positive case builds a real two-generation chain with real Ed25519
//! keys: genesis under Station A, one planned doubly signed handoff to Station
//! B, and a nonce-bound current assertion whose key comes from the route
//! record's own DID document. Every negative case mutates exactly one thing
//! about that chain, so the assertion is about the mutation and not about a
//! fixture that was never valid in the first place.

use arkret_canonical::canonical;
use arkret_models_identity::DidDocument;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_wire::{
    Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidCoreId, DidUrl, Event, EventId,
    EventKind, Hash, RealmAuthorityBundle, RealmAuthorityCurrentAssertion, RealmAuthorityHandoff,
    RealmAuthorityHandoffId, RealmAuthorityTransition, RealmCommit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, RealmSnapshotId, ScopeRef, StreamRow,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

use super::*;

const STATION_A: &str = "did:web:station-a.example";
const STATION_B: &str = "did:web:station-b.example";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_100, 0).unwrap()
}

fn issued_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_050, 0).unwrap()
}

fn expires_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_400, 0).unwrap()
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    }
}

fn multibase(key: &SigningKey) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
}

fn method(did: &str) -> DidUrl {
    DidUrl::new(format!("{did}#realm-authority")).unwrap()
}

fn core_id(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did.to_owned()).unwrap()).unwrap()
}

fn realm_id() -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x10; 32],
    ))
}

fn realm_stream() -> CommitStreamRef {
    CommitStreamRef::Realm {
        realm_id: realm_id(),
    }
}

fn hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte}{byte}").repeat(32))).unwrap()
}

fn placeholder_signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: method(STATION_A),
        signed_digest: hash('1'),
        created_at: issued_at(),
        sig: Base64UrlString::new("A".repeat(86)).unwrap(),
    }
}

fn event(kind: EventKind, seconds: i64) -> Event {
    arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
        core_id(STATION_A),
        json!({}),
        Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap(),
    )
    .unwrap()
}

/// Seal a commit exactly the way the verifier reconstructs it: the unsigned
/// projection is the object minus its `signature` member.
fn seal_commit(mut commit: RealmCommit, did: &str, key: &SigningKey) -> RealmCommit {
    let unsigned = canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method(did),
        issued_at(),
        key,
    )
    .unwrap();
    commit
}

fn commit(
    seed: u8,
    stream_position: u64,
    previous: Option<u8>,
    event_ref: &EventId,
    generation: u64,
    authority_ref: RealmCommitAuthorityRef,
    did: &str,
    key: &SigningKey,
) -> RealmCommit {
    seal_commit(
        RealmCommit {
            commit_id: RealmCommitId::from_digest([seed; 32]),
            realm_id: realm_id(),
            stream_ref: realm_stream(),
            stream_position,
            previous_commit_ref: previous.map(|byte| RealmCommitId::from_digest([byte; 32])),
            event_ref: event_ref.clone(),
            authority_generation: generation,
            authority_ref,
            committed_at: issued_at(),
            signature: placeholder_signature(DetachedSignatureContext::RealmCommit),
        },
        did,
        key,
    )
}

/// Both handoff signatures seal the same unsigned body under *different*
/// domains, so the sealing helper takes both keys at once and there is no way
/// for a caller of this fixture to accidentally reuse one domain twice.
fn seal_handoff(
    mut handoff: RealmAuthorityHandoff,
    old_context: DetachedSignatureContext,
    new_context: DetachedSignatureContext,
    old_key: &SigningKey,
    new_key: &SigningKey,
) -> RealmAuthorityHandoff {
    let unsigned = canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    handoff.old_authority_signature = sign_detached_object(
        &unsigned,
        old_context,
        method(STATION_A),
        issued_at(),
        old_key,
    )
    .unwrap();
    handoff.new_authority_acceptance_signature = sign_detached_object(
        &unsigned,
        new_context,
        method(STATION_B),
        issued_at(),
        new_key,
    )
    .unwrap();
    handoff
}

fn route_document(did: &str, key: &SigningKey) -> DidDocument {
    serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#realm-authority"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": multibase(key),
        }],
        "authentication": [format!("{did}#realm-authority")],
        "assertionMethod": [format!("{did}#realm-authority")],
        "service": [{
            "id": format!("{did}#station"),
            "type": "ArkretService",
            "serviceEndpoint": "https://station-b.example/",
            "serviceKind": "station",
        }],
    }))
    .unwrap()
}

fn route_record(did: &str, key: &SigningKey) -> serde_json::Value {
    let resolution = crate::build_authenticated_did_web_service_resolution(
        core_id(did),
        "station".to_owned(),
        route_document(did, key),
        now(),
    )
    .unwrap();
    serde_json::to_value(&resolution).unwrap()
}

struct Chain {
    bundle: RealmAuthorityBundle,
    keys: RealmAuthorityKeyMap,
    /// A later ordinary Realm-stream commit made under generation 1.
    item: StreamRow,
}

/// Genesis under Station A, one planned handoff to Station B, and a live
/// assertion from Station B. Every signature is a real Ed25519 signature over
/// the canonical unsigned body.
fn chain() -> Chain {
    let key_a = signing_key(0xA1);
    let key_b = signing_key(0xB2);

    let genesis_event = event(EventKind::RealmCreate, 0);
    let genesis_commit = commit(
        0x01,
        0,
        None,
        &genesis_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &key_a,
    );

    let change_event = event(EventKind::MessageCreate, 1);
    let change_commit = commit(
        0x02,
        1,
        Some(0x01),
        &change_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &key_a,
    );
    let handoff = seal_handoff(
        RealmAuthorityHandoff {
            handoff_id: RealmAuthorityHandoffId::from_digest([0x21; 32]),
            realm_id: realm_id(),
            from_generation: 0,
            to_generation: 1,
            from_service_id: core_id(STATION_A),
            to_service_id: core_id(STATION_B),
            final_stream_heads_digest: hash('a'),
            snapshot_ref: RealmSnapshotId::from_digest([0x44; 32]),
            snapshot_digest: hash('b'),
            change_event_ref: change_event.event_id.clone(),
            change_commit_id: change_commit.commit_id.clone(),
            old_authority_signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityHandoffOld,
            ),
            new_authority_acceptance_signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            ),
        },
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        &key_a,
        &key_b,
    );

    // One ordinary Realm-stream commit made after the handoff, under Station B.
    let item_event = event(EventKind::MessageCreate, 2);
    let item_commit = commit(
        0x03,
        2,
        Some(0x02),
        &item_event.event_id,
        1,
        RealmCommitAuthorityRef::Handoff(handoff.handoff_id.clone()),
        STATION_B,
        &key_b,
    );

    let head = CommitStreamHead {
        stream_ref: realm_stream(),
        stream_position: 2,
        commit_id: item_commit.commit_id.clone(),
    };
    let mut assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm_id(),
        current_generation: 1,
        current_service_id: core_id(STATION_B),
        last_handoff_ref: Some(handoff.handoff_id.clone()),
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new(NONCE.to_owned()).unwrap(),
        expires_at: expires_at(),
        signature: placeholder_signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
    };
    let unsigned = canonical::unsigned_value(&assertion, &["signature"]).unwrap();
    assertion.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method(STATION_B),
        issued_at(),
        &key_b,
    )
    .unwrap();

    let bundle = RealmAuthorityBundle {
        realm_id: realm_id(),
        genesis_event,
        genesis_commit,
        authority_transitions: vec![RealmAuthorityTransition {
            change_event,
            change_commit,
            handoff,
        }],
        current_generation: 1,
        current_service_id: core_id(STATION_B),
        current_route_record: route_record(STATION_B, &key_b),
        realm_stream_head: head,
        bundle_issued_at: issued_at(),
        current_assertion: assertion,
    };

    let keys = RealmAuthorityKeyMap::new()
        .with_key(&method(STATION_A), public(&key_a))
        .with_key(&method(STATION_B), public(&key_b));

    Chain {
        bundle,
        keys,
        item: StreamRow {
            commit: item_commit,
            event: item_event,
        },
    }
}

fn freshness() -> RealmAuthorityFreshness {
    RealmAuthorityFreshness::new(
        now(),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
        Duration::seconds(300),
    )
    .unwrap()
}

fn verify(chain: &Chain) -> ChainResult<VerifiedRealmAuthority> {
    verify_realm_authority_bundle(&chain.bundle, &freshness(), &chain.keys)
}

#[test]
fn a_real_two_generation_chain_verifies_and_authorises_its_own_commits() {
    let chain = chain();
    let verified = verify(&chain).expect("the honest chain must verify");

    assert_eq!(verified.realm_id(), &realm_id());
    assert_eq!(verified.current_generation(), 1);
    assert_eq!(verified.current_service_id(), &core_id(STATION_B));
    assert_eq!(verified.authority_service_at(0), Some(&core_id(STATION_A)));
    assert_eq!(verified.authority_service_at(1), Some(&core_id(STATION_B)));
    assert_eq!(verified.authority_service_at(2), None);

    verified
        .verify_committed_item(&chain.item, &chain.keys)
        .expect("a commit made under generation 1 must verify against generation 1");
}

/// Matching coordinates are not authority. The commit below is structurally
/// perfect and `CommittedEventRef::matches` would accept it; it is signed by
/// the wrong Station, which is the only thing that matters.
#[test]
fn a_structurally_perfect_commit_signed_by_the_wrong_station_is_refused() {
    let chain = chain();
    let verified = verify(&chain).unwrap();
    let rogue_key = signing_key(0xC3);

    let mut item = chain.item.clone();
    item.commit = seal_commit(item.commit.clone(), STATION_A, &rogue_key);
    let keys = RealmAuthorityKeyMap::new()
        .with_key(&method(STATION_A), public(&rogue_key))
        .with_key(&method(STATION_B), public(&signing_key(0xB2)));

    let reference = arkret_wire::CommittedEventRef {
        event_id: item.event.event_id.clone(),
        commit_id: item.commit.commit_id.clone(),
        stream_ref: item.commit.stream_ref.clone(),
        stream_position: item.commit.stream_position,
    };
    assert!(
        reference.matches(&item),
        "the structural match is exactly the check that must not be sufficient"
    );

    let error = verified
        .verify_committed_item(&item, &keys)
        .expect_err("generation 1 is held by Station B, not Station A");
    assert!(
        matches!(error, RealmAuthorityChainError::StationMismatch(_)),
        "{error}"
    );
}

/// Negative 1 — one byte changed inside the signed commit body.
#[test]
fn one_changed_byte_in_a_signed_commit_fails_closed() {
    let mut chain = chain();
    chain.bundle.genesis_commit.stream_position = 0;
    chain.bundle.genesis_commit.committed_at = issued_at() + Duration::seconds(1);

    let error = verify(&chain).expect_err("a re-dated commit body must not verify");
    assert!(
        matches!(error, RealmAuthorityChainError::SignatureInvalid(_)),
        "{error}"
    );
}

/// Negative 2 — one byte changed inside the genesis Event, whose id is a
/// digest of its own content.
#[test]
fn one_changed_byte_in_the_genesis_event_breaks_its_content_binding() {
    let mut chain = chain();
    chain
        .bundle
        .genesis_event
        .payload
        .insert("tampered".to_owned(), json!(1));

    let error = verify(&chain).expect_err("a mutated Event body must not verify");
    assert!(
        matches!(error, RealmAuthorityChainError::ChainBroken(_)),
        "{error}"
    );
    assert!(error.to_string().contains("event_id"), "{error}");
}

/// Negative 3 — the chain is one hop short of the generation it claims.
#[test]
fn a_missing_hop_never_reaches_the_claimed_generation() {
    let mut chain = chain();
    chain.bundle.authority_transitions.clear();

    let error = verify(&chain).expect_err("an empty chain cannot reach generation 1");
    assert!(
        matches!(error, RealmAuthorityChainError::ChainBroken(_)),
        "{error}"
    );
    assert!(
        error.to_string().contains("reaches generation 0"),
        "{error}"
    );
}

/// Negative 4 — a handoff that skips a generation number.
#[test]
fn a_skipped_generation_number_is_refused() {
    let mut chain = chain();
    chain.bundle.authority_transitions[0].handoff.to_generation = 2;
    chain.bundle.current_generation = 2;
    chain.bundle.current_assertion.current_generation = 2;

    let error = verify(&chain).expect_err("generations advance by exactly one");
    assert!(
        matches!(error, RealmAuthorityChainError::GenerationMismatch(_)),
        "{error}"
    );
}

/// Negative 5 — the two handoff signatures put in the *same* domain. A
/// transition signed twice in one domain is one Station's statement, not a
/// handoff, and it must not be able to install a successor.
#[test]
fn signing_both_handoff_positions_in_one_domain_is_refused() {
    let mut chain = chain();
    let transition = &mut chain.bundle.authority_transitions[0];
    transition.handoff = seal_handoff(
        transition.handoff.clone(),
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        &signing_key(0xA1),
        &signing_key(0xB2),
    );

    let error = verify(&chain).expect_err("one domain cannot carry both handoff signatures");
    assert!(
        matches!(error, RealmAuthorityChainError::SignatureInvalid(_)),
        "{error}"
    );
    assert!(error.to_string().contains("domain context"), "{error}");
}

/// Negative 6 — the route record resolves a different DID than the one the
/// online assertion is signed under.
#[test]
fn a_route_record_for_another_did_is_refused() {
    let mut chain = chain();
    chain.bundle.current_route_record = route_record(STATION_A, &signing_key(0xA1));

    let error = verify(&chain).expect_err("the route must resolve the signing Station");
    assert!(
        matches!(error, RealmAuthorityChainError::RouteMismatch(_)),
        "{error}"
    );
}

/// Negative 6b — the route record resolves the right DID but publishes a
/// different key for the assertion's verification method.
#[test]
fn a_route_record_publishing_another_key_is_refused() {
    let mut chain = chain();
    chain.bundle.current_route_record = route_record(STATION_B, &signing_key(0xD4));

    let error = verify(&chain).expect_err("the assertion key must be the published one");
    assert!(
        matches!(error, RealmAuthorityChainError::SignatureInvalid(_)),
        "{error}"
    );
}

/// Negative 7 — material the caller could not resolve is never a pass.
#[test]
fn a_missing_public_key_fails_closed_rather_than_skipping_the_check() {
    let chain = chain();
    let keys = RealmAuthorityKeyMap::new().with_key(&method(STATION_B), public(&signing_key(0xB2)));

    let error = verify_realm_authority_bundle(&chain.bundle, &freshness(), &keys)
        .expect_err("an unresolvable verification method must fail closed");
    assert!(
        matches!(error, RealmAuthorityChainError::MaterialIncomplete(_)),
        "{error}"
    );
}

/// Negative 8 — freshness is the caller's parameter, and every way of being
/// stale is refused.
#[test]
fn stale_replayed_and_foreign_nonce_bundles_are_refused() {
    let chain = chain();

    let wrong_nonce = RealmAuthorityFreshness::new(
        now(),
        Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB".to_owned()).unwrap(),
        Duration::seconds(300),
    )
    .unwrap();
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &wrong_nonce, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));

    let expired = RealmAuthorityFreshness::new(
        expires_at() + Duration::seconds(1),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
        Duration::days(1),
    )
    .unwrap();
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &expired, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));

    let too_old = RealmAuthorityFreshness::new(
        now(),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
        Duration::seconds(1),
    )
    .unwrap();
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &too_old, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));

    let before_issue = RealmAuthorityFreshness::new(
        issued_at() - Duration::seconds(1),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
        Duration::seconds(300),
    )
    .unwrap();
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &before_issue, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));
}

/// Negative 9 — a commit whose generation this bundle does not cover at all.
#[test]
fn a_commit_from_an_uncovered_generation_is_refused() {
    let chain = chain();
    let verified = verify(&chain).unwrap();
    let mut item = chain.item.clone();
    item.commit.authority_generation = 7;
    item.commit = seal_commit(item.commit, STATION_B, &signing_key(0xB2));

    let error = verified
        .verify_committed_item(&item, &chain.keys)
        .expect_err("generation 7 was never installed");
    assert!(
        matches!(error, RealmAuthorityChainError::GenerationMismatch(_)),
        "{error}"
    );
}

/// Negative 10 — a commit that names the wrong installing record for its own
/// generation.
#[test]
fn a_commit_naming_the_wrong_installing_record_is_refused() {
    let chain = chain();
    let verified = verify(&chain).unwrap();
    let mut item = chain.item.clone();
    item.commit.authority_ref =
        RealmCommitAuthorityRef::Handoff(RealmAuthorityHandoffId::from_digest([0x99; 32]));
    item.commit = seal_commit(item.commit, STATION_B, &signing_key(0xB2));

    let error = verified
        .verify_committed_item(&item, &chain.keys)
        .expect_err("the authority_ref must name the record that installed the generation");
    assert!(
        matches!(error, RealmAuthorityChainError::GenerationMismatch(_)),
        "{error}"
    );
}
