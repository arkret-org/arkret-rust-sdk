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
    Base64UrlString, CommitStreamHead, CommitStreamRef, CommittedEventFullView, CommittedEventView,
    DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidCoreId,
    DidUrl, Event, EventId, EventKind, Hash, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityHandoffId, RealmAuthorityTransition, RealmCommit,
    RealmCommitAuthorityRef, RealmCommitId, RealmId, RealmSnapshotId, ScopeRef,
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

#[test]
fn authority_key_map_keeps_rotated_keys_at_their_signed_times() {
    let method = method(STATION_A);
    let earlier = issued_at();
    let later = now();
    let old_key = public(&signing_key(0xA1));
    let new_key = public(&signing_key(0xA2));
    let mut keys = RealmAuthorityKeyMap::new();
    keys.insert(&method, new_key.clone());
    keys.insert_at(&method, earlier, old_key.clone());
    keys.insert_at(&method, later, new_key.clone());

    assert_eq!(keys.public_key_at(&method, earlier), Some(old_key));
    assert_eq!(keys.public_key_at(&method, later), Some(new_key.clone()));
    assert_eq!(
        keys.public_key_at(&method, later + Duration::seconds(1)),
        None
    );
    assert_eq!(keys.public_key(&method), Some(new_key));
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
            governance_generation: generation,
            authority_ref,
            committed_at: issued_at(),
            producer_signer_fact_digest: None,
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
    item: CommittedEventFullView,
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
            historical_signer_facts_digest: None,
            snapshot_ref: RealmSnapshotId::from_digest([0x44; 32]),
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
        item: CommittedEventFullView {
            commit: item_commit,
            event: item_event,
        },
    }
}

fn freshness() -> RealmAuthorityFreshness {
    RealmAuthorityFreshness::new(now(), Base64UrlString::new(NONCE.to_owned()).unwrap())
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

#[test]
fn identical_verified_results_from_multiple_locators_converge() {
    let first_chain = chain();
    let mut second_chain = chain();
    second_chain.bundle.bundle_issued_at += Duration::seconds(1);
    let first = verify(&first_chain).expect("the first locator's chain must verify");
    let second =
        verify(&second_chain).expect("a fresh envelope over the same chain and cut must verify");

    let locator_results = [first, second];
    let converged = converge_verified_realm_authorities(&locator_results)
        .expect("two locators returning the same verified chain must converge");
    assert_eq!(converged.current_service_id(), &core_id(STATION_B));
}

#[test]
fn no_verified_locator_result_fails_closed() {
    assert_eq!(
        converge_verified_realm_authorities(&[]),
        Err(RealmAuthorityConvergenceError::NoVerifiedAuthority)
    );
}

#[test]
fn mutually_exclusive_verified_chains_fail_closed() {
    let first_chain = chain();
    let mut conflicting_chain = chain();
    let transition = &mut conflicting_chain.bundle.authority_transitions[0];
    transition.handoff.historical_signer_facts_digest = Some(hash('c'));
    transition.handoff = seal_handoff(
        transition.handoff.clone(),
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        &signing_key(0xA1),
        &signing_key(0xB2),
    );

    let first = verify(&first_chain).expect("the first chain must verify independently");
    let conflicting = verify(&conflicting_chain)
        .expect("the equivocated handoff is also cryptographically valid on its own");
    assert_eq!(
        converge_verified_realm_authorities(&[first, conflicting]),
        Err(RealmAuthorityConvergenceError::ConflictingVerifiedAuthorities)
    );
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
        reference.matches(&CommittedEventView::Full(item.clone())),
        "the structural match is exactly the check that must not be sufficient"
    );

    let error = verified
        .verify_committed_item(&item, &keys)
        .expect_err("generation 1 is held by Station B, not Station A");
    assert!(
        matches!(error, RealmAuthorityChainError::StationMismatch(_)),
        "{error}"
    );
    assert_eq!(
        error.error_code(),
        Some(arkret_wire::ErrorCode::SignatureInvalid),
        "a Commit from a non-current governance Station is signature_invalid"
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
    );
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &wrong_nonce, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));

    let expired = RealmAuthorityFreshness::new(
        expires_at() + Duration::seconds(1),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
    );
    assert!(matches!(
        verify_realm_authority_bundle(&chain.bundle, &expired, &chain.keys),
        Err(RealmAuthorityChainError::NotFresh(_))
    ));

    // A bundle whose issue instant is far behind the caller's clock is still
    // fresh while its nonce-bound assertion has not expired: no caller-side
    // bundle age limit exists.
    let late_but_unexpired = RealmAuthorityFreshness::new(
        expires_at() - Duration::milliseconds(1),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
    );
    verify_realm_authority_bundle(&chain.bundle, &late_but_unexpired, &chain.keys)
        .expect("an unexpired nonce-bound assertion is the only freshness rule");
}

/// Negative 9 — a commit whose generation this bundle does not cover at all.
#[test]
fn a_commit_from_an_uncovered_generation_is_refused() {
    let chain = chain();
    let verified = verify(&chain).unwrap();
    let mut item = chain.item.clone();
    item.commit.governance_generation = 7;
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

/// Every variant maps to exactly the registered code the spec assigns it, and
/// the variants the spec leaves to the calling operation carry none.
#[test]
fn chain_errors_map_to_registered_protocol_codes() {
    let reason = || "reason".to_owned();
    for (error, expected) in [
        (
            RealmAuthorityChainError::SignatureInvalid(reason()),
            Some(arkret_wire::ErrorCode::SignatureInvalid),
        ),
        (
            RealmAuthorityChainError::StationMismatch(reason()),
            Some(arkret_wire::ErrorCode::SignatureInvalid),
        ),
        (
            RealmAuthorityChainError::GenerationMismatch(reason()),
            Some(arkret_wire::ErrorCode::SignatureInvalid),
        ),
        (RealmAuthorityChainError::MaterialIncomplete(reason()), None),
        (RealmAuthorityChainError::ChainBroken(reason()), None),
        (RealmAuthorityChainError::RouteMismatch(reason()), None),
        (RealmAuthorityChainError::NotFresh(reason()), None),
    ] {
        assert_eq!(error.error_code(), expected, "{error:?}");
    }
}

#[derive(Default)]
struct HistoricalKeys {
    keys: BTreeMap<(DidUrl, DateTime<Utc>), PublicKeyMaterial>,
}

impl RealmAuthorityKeyDirectory for HistoricalKeys {
    fn public_key(&self, _method: &DidUrl) -> Option<PublicKeyMaterial> {
        None
    }

    fn public_key_at(&self, method: &DidUrl, at: DateTime<Utc>) -> Option<PublicKeyMaterial> {
        self.keys.get(&(method.clone(), at)).cloned()
    }
}

fn same_method_rotation() -> (RealmAuthorityBundle, CommittedEventFullView, HistoricalKeys) {
    let old_key = signing_key(0x81);
    let new_key = signing_key(0x82);
    let genesis_event = event(EventKind::RealmCreate, 0);
    let item_event = event(EventKind::MessageCreate, 1);
    let mut genesis_commit = commit(
        0x61,
        0,
        None,
        &genesis_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &old_key,
    );
    let mut item_commit = commit(
        0x62,
        1,
        Some(0x61),
        &item_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &old_key,
    );
    let mut keys = HistoricalKeys::default();
    for (index, commit) in [&mut genesis_commit, &mut item_commit]
        .into_iter()
        .enumerate()
    {
        let at = issued_at() - Duration::seconds(40 - index as i64);
        commit.committed_at = at;
        commit.signature = sign_detached_object(
            &canonical::unsigned_value(commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            method(STATION_A),
            at,
            &old_key,
        )
        .unwrap();
        keys.keys.insert((method(STATION_A), at), public(&old_key));
    }
    let head = CommitStreamHead {
        stream_ref: realm_stream(),
        stream_position: 1,
        commit_id: item_commit.commit_id.clone(),
    };
    let mut assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm_id(),
        current_generation: 0,
        current_service_id: core_id(STATION_A),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new(NONCE.to_owned()).unwrap(),
        expires_at: expires_at(),
        signature: placeholder_signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
    };
    assertion.signature = sign_detached_object(
        &canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method(STATION_A),
        issued_at(),
        &new_key,
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: realm_id(),
        genesis_event,
        genesis_commit,
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: core_id(STATION_A),
        current_route_record: route_record(STATION_A, &new_key),
        realm_stream_head: head,
        bundle_issued_at: issued_at(),
        current_assertion: assertion,
    };
    (
        bundle,
        CommittedEventFullView {
            commit: item_commit,
            event: item_event,
        },
        keys,
    )
}

#[test]
fn same_method_rotation_preserves_historical_genesis_and_receipt_verification() {
    let (bundle, item, keys) = same_method_rotation();
    let verified = verify_realm_authority_bundle(&bundle, &freshness(), &keys).unwrap();
    verified.verify_committed_item(&item, &keys).unwrap();
    assert_eq!(verified.current_generation(), 0);
}

#[test]
fn same_method_rotation_missing_historical_key_fails_closed() {
    let (bundle, item, mut keys) = same_method_rotation();
    let verified = verify_realm_authority_bundle(&bundle, &freshness(), &keys).unwrap();
    keys.keys
        .remove(&(method(STATION_A), item.commit.signature.created_at));
    assert!(matches!(
        verified.verify_committed_item(&item, &keys),
        Err(RealmAuthorityChainError::MaterialIncomplete(_))
    ));
}

#[test]
fn same_method_rotation_current_key_cannot_replace_historical_key() {
    let (bundle, item, mut keys) = same_method_rotation();
    let verified = verify_realm_authority_bundle(&bundle, &freshness(), &keys).unwrap();
    keys.keys.insert(
        (method(STATION_A), item.commit.signature.created_at),
        public(&signing_key(0x82)),
    );
    assert!(matches!(
        verified.verify_committed_item(&item, &keys),
        Err(RealmAuthorityChainError::SignatureInvalid(_))
    ));
    let current_only =
        RealmAuthorityKeyMap::new().with_key(&method(STATION_A), public(&signing_key(0x82)));
    assert!(matches!(
        verify_realm_authority_bundle(&bundle, &freshness(), &current_only),
        Err(RealmAuthorityChainError::SignatureInvalid(_))
    ));
}

#[test]
fn human_original_fact_is_frozen_before_commit_identity_and_governance_signature() {
    use arkret_models_collaboration::authority_commit::{
        HistoricalProducerSignerFactEntry, HumanHistoricalSignerFact,
        historical_signer_facts_digest, validate_new_human_admission_fact,
    };
    use arkret_models_identity::ResolvedSignerKey;
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    let seal_fact = |mut commit: RealmCommit| {
        let unsigned = canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            &canonical::canonical_json_bytes(&unsigned).unwrap(),
        ));
        seal_commit(commit, STATION_B, &signing_key(0xB2))
    };
    let chain = chain();
    let authority = verify(&chain).unwrap();
    let principal = Did::new("did:web:human.example").unwrap();
    let device =
        arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&principal).unwrap(),
        core_id(STATION_A),
    ));
    let raw = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.invite.create",
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        actor.clone(),
        json!({
            "invitee_account_id": arkret_wire::AccountId::new(arkret_wire::project_did_to_core_id(&principal).unwrap(), core_id(STATION_B)),
            "introduction_evidence_digest": arkret_canonical::canonical_sha256(&json!({"kind":"explicit_address"})).unwrap(),
            "expires_at": expires_at(),
        }),
        now(),
    )
    .unwrap();
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        raw,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let device_seed = [77; 32];
    let vm = DidUrl::new(format!("{principal}#{device}")).unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(device_seed, vm.to_string()),
        SignEventOptions::new().with_created_at(now()),
    )
    .unwrap();
    let event = authored.into_event();
    let fact = HumanHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor,
        device_id: device,
        verification_method: vm,
        key: ResolvedSignerKey {
            public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&device_seed)
                    .verifying_key()
                    .as_bytes(),
            ))
            .unwrap(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [71; 32]),
                commit_id: RealmCommitId::from_digest([72; 32]),
                stream_ref: CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [73; 32],
                    )),
                },
                stream_position: 2,
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: RealmCommitId::from_digest([74; 32]),
                stream_position: 3,
            },
            governance_generation: 4,
        },
        accepted_at: issued_at(),
    };
    validate_new_human_admission_fact(&event, Some(&fact), arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    assert!(
        validate_new_human_admission_fact(&event, None, arkret_canonical::DigestSuite::Sha256)
            .is_err()
    );
    use arkret_models_collaboration::authority_commit::validate_new_human_admission_fact_for_purpose;
    use arkret_models_collaboration::events_payloads::RealmPurpose;
    for purpose in [
        RealmPurpose::PrincipalControl,
        RealmPurpose::AgentControl,
        RealmPurpose::AppletManagedControl,
    ] {
        validate_new_human_admission_fact_for_purpose(
            &event,
            purpose,
            None,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(
            validate_new_human_admission_fact_for_purpose(
                &event,
                purpose,
                Some(&fact.clone().into()),
                arkret_canonical::DigestSuite::Sha256
            )
            .is_err()
        );
    }
    for purpose in [
        RealmPurpose::Collaboration,
        RealmPurpose::DirectConversation,
    ] {
        validate_new_human_admission_fact_for_purpose(
            &event,
            purpose,
            Some(&fact.clone().into()),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(
            validate_new_human_admission_fact_for_purpose(
                &event,
                purpose,
                None,
                arkret_canonical::DigestSuite::Sha256
            )
            .is_err()
        );
    }
    let mut accepted = chain.item.clone();
    accepted.event = event;
    accepted.commit.event_ref = accepted.event.event_id.clone();
    accepted.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    accepted.commit = seal_fact(accepted.commit);
    let verified = crate::account_device_signer_evidence::verify_historical_human_committed_event(
        &accepted,
        &fact,
        &authority,
        &chain.keys,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(verified.fact(), &fact);
    let mut alternate = fact.clone();
    alternate.key.revision.stream_position += 1;
    assert!(
        crate::account_device_signer_evidence::verify_historical_human_committed_event(
            &accepted,
            &alternate,
            &authority,
            &chain.keys,
            arkret_canonical::DigestSuite::Sha256
        )
        .is_err()
    );
    let mut altered = accepted.clone();
    altered.commit.producer_signer_fact_digest = Some(alternate.digest().unwrap());
    let unsigned = canonical::unsigned_value(&altered.commit, &["signature"]).unwrap();
    altered.commit.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method(STATION_B),
        issued_at(),
        &signing_key(0xB2),
    )
    .unwrap();
    assert!(altered.commit.verify_commit_id_matches_content().is_err());
    let mut wrong = fact.clone();
    wrong.key.public_key_b64u = Base64UrlString::new(arkret_canonical::base64url_encode(
        signing_key(22).verifying_key().as_bytes(),
    ))
    .unwrap();
    let mut wrong_accepted = accepted.clone();
    wrong_accepted.commit.producer_signer_fact_digest = Some(wrong.digest().unwrap());
    wrong_accepted.commit = seal_fact(wrong_accepted.commit);
    assert!(
        crate::account_device_signer_evidence::verify_historical_human_committed_event(
            &wrong_accepted,
            &wrong,
            &authority,
            &chain.keys,
            arkret_canonical::DigestSuite::Sha256
        )
        .is_err()
    );
    let entry = HistoricalProducerSignerFactEntry {
        target: arkret_wire::CommittedEventRef {
            event_id: accepted.event.event_id.clone(),
            commit_id: accepted.commit.commit_id.clone(),
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
        },
        producer_signer_fact: fact.clone().into(),
    };
    entry.validate_target(&accepted).unwrap();
    assert!(historical_signer_facts_digest(&[entry.clone(), entry.clone()]).is_err());
    assert_ne!(
        historical_signer_facts_digest(&[]).unwrap(),
        historical_signer_facts_digest(&[entry]).unwrap()
    );
    let inventory_entry = HistoricalProducerSignerFactEntry {
        target: arkret_wire::CommittedEventRef {
            event_id: accepted.event.event_id.clone(),
            commit_id: accepted.commit.commit_id.clone(),
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
        },
        producer_signer_fact: fact.clone().into(),
    };
    use arkret_models_collaboration::authority_commit::validate_historical_signer_fact_inventory;
    validate_historical_signer_fact_inventory(&[inventory_entry.clone()], &[accepted.clone()])
        .unwrap();
    assert!(validate_historical_signer_fact_inventory(&[], &[accepted.clone()]).is_err());
    assert!(validate_historical_signer_fact_inventory(&[inventory_entry.clone()], &[]).is_err());
    assert!(
        validate_historical_signer_fact_inventory(
            &[inventory_entry.clone(), inventory_entry],
            &[accepted.clone()]
        )
        .is_err()
    );
    let mut unsupported_digest = accepted.commit.clone();
    unsupported_digest.producer_signer_fact_digest =
        Some(Hash::new(format!("blake3:{}", "00".repeat(32))).unwrap());
    assert!(unsupported_digest.validate_shape().is_err());
    let scan_request = arkret_wire::StreamScanRequest {
        realm_id: accepted.commit.realm_id.clone(),
        stream_ref: accepted.commit.stream_ref.clone(),
        direction: arkret_wire::StreamScanDirection::Before(Some(
            accepted.commit.stream_position + 1,
        )),
        limit: 1,
    };
    let page = arkret_models_collaboration::authority_commit::PeerStreamScanOutcome {
        committed_events: vec![CommittedEventView::Full(accepted.clone())],
        readable_floor: Some(arkret_wire::ReadableFloor {
            oldest_position: accepted.commit.stream_position,
            floor_commit_id: accepted.commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
        }),
        truncated: false,
        producer_signer_facts: vec![HistoricalProducerSignerFactEntry {
            target: arkret_wire::CommittedEventRef {
                event_id: accepted.event.event_id.clone(),
                commit_id: accepted.commit.commit_id.clone(),
                stream_ref: accepted.commit.stream_ref.clone(),
                stream_position: accepted.commit.stream_position,
            },
            producer_signer_fact: fact.clone().into(),
        }],
    };
    page.validate_for_request(&scan_request).unwrap();
    let mut missing = page.clone();
    missing.producer_signer_facts.clear();
    assert!(missing.validate_for_request(&scan_request).is_err());
    let mut duplicate = page.clone();
    duplicate
        .producer_signer_facts
        .push(duplicate.producer_signer_facts[0].clone());
    assert!(duplicate.validate_for_request(&scan_request).is_err());
    let mut withheld = page.clone();
    withheld.committed_events = vec![CommittedEventView::Withheld(
        arkret_wire::CommittedEventWithheldView {
            commit: accepted.commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        },
    )];
    assert!(withheld.validate_for_request(&scan_request).is_err());
    withheld.producer_signer_facts.clear();
    withheld.validate_for_request(&scan_request).unwrap();
    let mut wrong_source = page.clone();
    wrong_source.producer_signer_facts[0].producer_signer_fact = alternate.into();
    assert!(wrong_source.validate_for_request(&scan_request).is_err());
    use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody;
    let delivery = InviteDeliveryRequestBody::new(
        accepted.event.clone(), accepted.commit.clone(), Some(fact.clone()),
        vec![serde_json::from_value(json!({"service_kind":"station", "service_id":core_id(STATION_B), "source":"invite"})).unwrap()],
        serde_json::from_value(json!({
            "account_id": {"principal_id": arkret_wire::project_did_to_core_id(&principal).unwrap(), "station_id":core_id(STATION_B)},
            "service_resolution":{"resolution_url":"https://station-b.example/.well-known/did.json"},
        })).unwrap(),
        serde_json::from_value(json!({"kind":"explicit_address"})).unwrap(),
        "original-invite-delivery",
    ).unwrap();
    let verified_invite =
        crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
            &delivery,
            &authority,
            &chain.keys,
        )
        .unwrap();
    assert_eq!(verified_invite.fact(), &fact);
    let reopened: InviteDeliveryRequestBody =
        serde_json::from_value(serde_json::to_value(&delivery).unwrap()).unwrap();
    reopened.validate_for_submission().unwrap();
    crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
        &reopened,
        &authority,
        &chain.keys,
    )
    .unwrap();
    let mut missing_source = delivery.clone();
    missing_source.producer_signer_fact = None;
    assert!(missing_source.validate_minimal().is_err());
    let mut sibling_target = delivery.clone();
    sibling_target.invite_commit.event_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32]);
    sibling_target.invite_commit = seal_fact(sibling_target.invite_commit);
    assert!(
        crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
            &sibling_target,
            &authority,
            &chain.keys
        )
        .is_err()
    );
    let mut wrong_source = delivery.clone();
    wrong_source
        .producer_signer_fact
        .as_mut()
        .unwrap()
        .key
        .revision
        .stream_position += 1;
    assert!(
        crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
            &wrong_source,
            &authority,
            &chain.keys
        )
        .is_err()
    );
    let mut wrong_invite_key = delivery.clone();
    wrong_invite_key.producer_signer_fact = Some(wrong.clone());
    wrong_invite_key.invite_commit.producer_signer_fact_digest = Some(wrong.digest().unwrap());
    wrong_invite_key.invite_commit = seal_fact(wrong_invite_key.invite_commit);
    wrong_invite_key.validate_minimal().unwrap();
    assert!(
        crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
            &wrong_invite_key,
            &authority,
            &chain.keys
        )
        .is_err()
    );
    let mut wrong_governance = delivery.clone();
    wrong_governance.invite_commit =
        seal_commit(wrong_governance.invite_commit, STATION_B, &signing_key(22));
    wrong_governance.validate_minimal().unwrap();
    assert!(
        crate::account_device_signer_evidence::verify_invite_delivery_human_signer(
            &wrong_governance,
            &authority,
            &chain.keys
        )
        .is_err()
    );
    let mut exact_legacy = delivery.clone();
    exact_legacy.producer_signer_fact = None;
    exact_legacy.invite_commit.producer_signer_fact_digest = None;
    exact_legacy.invite_commit = seal_fact(exact_legacy.invite_commit);
    exact_legacy.validate_minimal().unwrap();
    assert!(exact_legacy.validate_for_submission().is_err());

    let mut legacy = accepted.clone();
    legacy.commit.producer_signer_fact_digest = None;
    legacy.commit = seal_fact(legacy.commit);
    authority
        .verify_committed_item(&legacy, &chain.keys)
        .unwrap();
    let wire = serde_json::to_value(&legacy.commit).unwrap();
    assert!(wire.get("producer_signer_fact_digest").is_none());
    let reopened: RealmCommit = serde_json::from_value(wire).unwrap();
    reopened.verify_commit_id_matches_content().unwrap();
}

#[test]
fn handoff_inventory_digest_is_bound_by_both_real_station_signatures() {
    use arkret_models_collaboration::authority_commit::historical_signer_facts_digest;
    let mut chain = chain();
    let transition = &mut chain.bundle.authority_transitions[0];
    transition.handoff.historical_signer_facts_digest =
        Some(historical_signer_facts_digest(&[]).unwrap());
    transition.handoff = seal_handoff(
        transition.handoff.clone(),
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        &signing_key(0xA1),
        &signing_key(0xB2),
    );
    verify(&chain).unwrap();
    let original = chain.bundle.authority_transitions[0].handoff.clone();
    chain.bundle.authority_transitions[0]
        .handoff
        .historical_signer_facts_digest = Some(hash('d'));
    assert!(verify(&chain).is_err());
    let unsigned = canonical::unsigned_value(
        &chain.bundle.authority_transitions[0].handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    chain.bundle.authority_transitions[0]
        .handoff
        .old_authority_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        method(STATION_A),
        issued_at(),
        &signing_key(0xA1),
    )
    .unwrap();
    assert!(verify(&chain).is_err());
    chain.bundle.authority_transitions[0].handoff = original;
    verify(&chain).unwrap();
}

#[test]
fn new_handoff_submission_requires_signed_inventory_and_exact_snapshot_original() {
    use arkret_models_collaboration::authority_commit::{
        AuthorityHandoffRequest, historical_signer_facts_digest,
    };
    use arkret_wire::{HistoryAccess, RealmStateSnapshot, RetentionAndHistoryFloor};
    let mut chain = chain();
    let finalize_event = |raw: Event| {
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            raw,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
                [5; 32],
                "did:web:founder.example#ak:device:0196419b-0000-7000-8000-000000000001",
            ),
            arkret_signatures::SignEventOptions::new().with_created_at(issued_at()),
        )
        .unwrap();
        authored.into_event()
    };
    // Build a canonical Genesis first: its content address is the Realm identity on every reopen.
    let mut genesis = chain.bundle.genesis_event.clone();
    genesis.scope_ref = ScopeRef::RealmGenesis;
    genesis.producer_proof = None;
    let genesis = finalize_event(genesis);
    let cut_realm = RealmId::from_event_id(&genesis.event_id);
    let cut_stream = CommitStreamRef::Realm {
        realm_id: cut_realm.clone(),
    };
    let seal_original = |mut value: RealmCommit, station: &str, key: &SigningKey| {
        let unsigned = canonical::unsigned_value(&value, &["commit_id", "signature"]).unwrap();
        value.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            &canonical::canonical_json_bytes(&unsigned).unwrap(),
        ));
        seal_commit(value, station, key)
    };
    chain.bundle.realm_id = cut_realm.clone();
    chain.bundle.genesis_event = genesis.clone();
    chain.bundle.genesis_commit.realm_id = cut_realm.clone();
    chain.bundle.genesis_commit.stream_ref = cut_stream.clone();
    chain.bundle.genesis_commit.event_ref = genesis.event_id.clone();
    chain.bundle.genesis_commit.authority_ref =
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
    chain.bundle.genesis_commit =
        seal_original(chain.bundle.genesis_commit, STATION_A, &signing_key(0xA1));
    let transition = &mut chain.bundle.authority_transitions[0];
    transition.change_event.realm_id = cut_realm.clone();
    transition.change_event.scope_ref = ScopeRef::Realm {
        realm_id: cut_realm.clone(),
    };
    transition.change_event.producer_proof = None;
    transition.change_event = finalize_event(transition.change_event.clone());
    transition.change_commit.realm_id = cut_realm.clone();
    transition.change_commit.stream_ref = cut_stream.clone();
    transition.change_commit.event_ref = transition.change_event.event_id.clone();
    transition.change_commit.previous_commit_ref =
        Some(chain.bundle.genesis_commit.commit_id.clone());
    transition.change_commit.authority_ref =
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
    transition.change_commit = seal_original(
        transition.change_commit.clone(),
        STATION_A,
        &signing_key(0xA1),
    );
    transition.handoff.realm_id = cut_realm.clone();
    transition.handoff.change_event_ref = transition.change_event.event_id.clone();
    transition.handoff.change_commit_id = transition.change_commit.commit_id.clone();
    chain.bundle.current_assertion.realm_id = cut_realm.clone();
    // The imported post-cut item is independently valid, but remains outside this frozen cut.
    chain.item.event.realm_id = cut_realm.clone();
    chain.item.event.scope_ref = ScopeRef::Realm {
        realm_id: cut_realm.clone(),
    };
    chain.item.event.producer_proof = None;
    chain.item.event = finalize_event(chain.item.event);
    chain.item.commit.realm_id = cut_realm.clone();
    chain.item.commit.stream_ref = cut_stream.clone();
    chain.item.commit.event_ref = chain.item.event.event_id.clone();
    chain.item.commit.previous_commit_ref = Some(transition.change_commit.commit_id.clone());
    chain.item.commit = seal_original(chain.item.commit, STATION_B, &signing_key(0xB2));
    let transition = &chain.bundle.authority_transitions[0];
    let heads = vec![CommitStreamHead {
        stream_ref: cut_stream.clone(),
        stream_position: transition.change_commit.stream_position,
        commit_id: transition.change_commit.commit_id.clone(),
    }];
    let mut snapshot = RealmStateSnapshot {
        snapshot_id: RealmSnapshotId::from_digest([0; 32]),
        realm_id: cut_realm.clone(),
        governance_generation: 0,
        visible_stream_heads: heads.clone(),
        current_state_entries: vec![],
        retention_and_history_floor: RetentionAndHistoryFloor {
            history_access: HistoryAccess::AllHistoryForCurrentMembers,
            stream_floors: vec![arkret_wire::StreamHistoryFloor {
                stream_ref: cut_stream.clone(),
                oldest_position: 0,
            }],
        },
        created_at: issued_at(),
        signature: placeholder_signature(DetachedSignatureContext::RealmSnapshot),
    };
    let unsigned = canonical::unsigned_value(&snapshot, &["snapshot_id", "signature"]).unwrap();
    snapshot.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        &canonical::canonical_json_bytes(&unsigned).unwrap(),
    ));
    snapshot.signature = sign_detached_object(
        &canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmSnapshot,
        method(STATION_A),
        issued_at(),
        &signing_key(0xA1),
    )
    .unwrap();
    let mut handoff = transition.handoff.clone();
    handoff.snapshot_ref = snapshot.snapshot_id.clone();
    handoff.final_stream_heads_digest =
        Hash::new(arkret_canonical::canonical_sha256(&heads).unwrap()).unwrap();
    handoff.historical_signer_facts_digest = Some(historical_signer_facts_digest(&[]).unwrap());
    handoff = seal_handoff(
        handoff,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        &signing_key(0xA1),
        &signing_key(0xB2),
    );
    chain.bundle.authority_transitions[0].handoff = handoff.clone();
    chain.bundle.realm_stream_head = heads[0].clone();
    chain.bundle.current_assertion.realm_stream_head = heads[0].clone();
    chain.bundle.current_assertion.signature = sign_detached_object(
        &canonical::unsigned_value(&chain.bundle.current_assertion, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method(STATION_B),
        issued_at(),
        &signing_key(0xB2),
    )
    .unwrap();
    verify(&chain).unwrap();
    let request = AuthorityHandoffRequest {
        handoff,
        final_stream_heads: heads,
        snapshot,
        authority_bundle: chain.bundle.clone(),
        historical_signer_facts: Some(vec![]),
    };
    request.validate_new_handoff().unwrap();
    request.validate_imported_signer_facts(&[]).unwrap();
    chain.item.validate_shape().unwrap();
    chain.item.commit.validate_content_address().unwrap();
    assert!(
        request
            .validate_imported_signer_facts(&[chain.item.clone()])
            .is_err()
    );
    let reopened: AuthorityHandoffRequest =
        serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();
    reopened.validate_new_handoff().unwrap();
    let mut missing = request.clone();
    missing.historical_signer_facts = None;
    assert!(missing.validate_new_handoff().is_err());
    let mut legacy = request.clone();
    legacy.historical_signer_facts = None;
    legacy.handoff.historical_signer_facts_digest = None;
    legacy.handoff = seal_handoff(
        legacy.handoff,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        &signing_key(0xA1),
        &signing_key(0xB2),
    );
    legacy.authority_bundle.authority_transitions[0].handoff = legacy.handoff.clone();
    legacy.validate_shape().unwrap();
    assert!(legacy.validate_new_handoff().is_err());
    let mut altered = request;
    altered.snapshot.retention_and_history_floor.history_access = HistoryAccess::SinceJoin;
    assert!(altered.validate_new_handoff().is_err());
}

#[test]
fn service_original_fact_verifies_real_proof_and_rejects_replacement_installation() {
    use arkret_models_collaboration::authority_commit::{
        HistoricalProducerSignerFact, ServiceHistoricalSignerFact,
    };
    use arkret_models_identity::ServiceHistoricalSigningKey;
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    let chain = chain();
    let authority = verify(&chain).unwrap();
    let suite = arkret_canonical::DigestSuite::Sha256;
    let actor = arkret_wire::ActorId::service(core_id("did:web:applet.example"));
    let scope = ScopeRef::Realm {
        realm_id: realm_id(),
    };
    let applet =
        arkret_wire::AppletId::new("ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d").unwrap();
    let mut raw = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.message.create",
        scope.clone(),
        actor.clone(),
        json!({"content":{"kind":"ak.content.text","text":"service original"}}),
        now(),
    )
    .unwrap();
    raw.applet_id = Some(applet.clone());
    raw.authorization_ref =
        Some(arkret_wire::GrantId::from_event_id(&EventId::from_digest(suite, [32; 32])).into());
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(raw, suite).unwrap();
    let seed = [78; 32];
    let vm = DidUrl::new("did:web:applet.example#producer").unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(seed, vm.to_string()),
        SignEventOptions::new().with_created_at(now()),
    )
    .unwrap();
    let event = authored.into_event();
    let coordinate = |byte| arkret_wire::CommittedEventRef {
        event_id: EventId::from_digest(suite, [byte; 32]),
        commit_id: RealmCommitId::from_digest([byte; 32]),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id(),
        },
        stream_position: 0,
    };
    let fact = ServiceHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor,
        verification_method: vm,
        key: ServiceHistoricalSigningKey {
            public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            ))
            .unwrap(),
            applet_id: applet,
            registration_epoch: arkret_wire::Hash::new(format!("sha256:{}", "12".repeat(32)))
                .unwrap(),
            registration_ref: coordinate(31),
            authorization_ref: coordinate(32),
            effective_scope: scope,
        },
        accepted_at: chain.item.commit.committed_at,
    };
    let mut full = chain.item.clone();
    full.event = event;
    full.commit.event_ref = full.event.event_id.clone();
    full.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    let unsigned = canonical::unsigned_value(&full.commit, &["commit_id", "signature"]).unwrap();
    full.commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        canonical::canonical_json_bytes(&unsigned).unwrap(),
    ));
    full.commit = seal_commit(full.commit, STATION_B, &signing_key(0xB2));
    let source: HistoricalProducerSignerFact = fact.clone().into();
    assert!(
        arkret_models_collaboration::authority_commit::validate_new_producer_admission_fact(
            &full.event,
            None,
            suite
        )
        .is_err()
    );
    crate::account_device_signer_evidence::verify_historical_producer_committed_event(
        &full,
        &source,
        &authority,
        &chain.keys,
        suite,
    )
    .unwrap();
    let mut replaced = fact.clone();
    replaced.key.public_key_b64u = Base64UrlString::new(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&[79; 32]).verifying_key().as_bytes(),
    ))
    .unwrap();
    assert!(
        crate::account_device_signer_evidence::verify_historical_producer_event_signature(
            &full.event,
            &replaced.into(),
            suite
        )
        .is_err()
    );
    let mut replaced = fact.clone();
    replaced.key.registration_epoch =
        arkret_wire::Hash::new(format!("sha256:{}", "13".repeat(32))).unwrap();
    assert!(
        crate::account_device_signer_evidence::verify_historical_producer_committed_event(
            &full,
            &replaced.into(),
            &authority,
            &chain.keys,
            suite
        )
        .is_err()
    );
    let mut replaced = fact;
    replaced.key.authorization_ref = coordinate(33);
    assert!(
        crate::account_device_signer_evidence::verify_historical_producer_committed_event(
            &full,
            &replaced.into(),
            &authority,
            &chain.keys,
            suite
        )
        .is_err()
    );
}
