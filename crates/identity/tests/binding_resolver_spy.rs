//! DID-P0-B03 resolver-spy acceptance: prove that "verify a signature" and
//! "resolve a DID" are two independent counters
//! (`did-usage-and-verification.md` §6, last bullet).
//!
//! The spy wraps a real [`DidResolver`] and counts every upstream resolution.
//! The ordinary verify APIs cannot even receive a resolver — that is proven
//! twice over here: at the type level (they have no resolver parameter) and by
//! the counter staying at its previous value across many calls.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_identity::binding::{
    DidBindingPurpose, DidBindingStatus, FreshnessProfile, FreshnessRiskTier, LimitedTrust,
    StaleBehavior, VerifiedDidBinding, VerifiedDidBindingDocumentInput,
};
use arkret_identity::binding_digest::{EvidenceReceipt, MethodEvidence};
use arkret_identity::binding_store::{
    AcceptedDidBinding, BindingInvalidation, InMemoryVerifiedDidBindingStore,
    VerifiedDidBindingStore,
};
use arkret_identity::verifier::{
    BindingResolveRequest, resolve_and_verify_binding, verify_jws_with_binding,
    verify_jws_with_document,
};
use arkret_identity::{DidDocument, DidResolver, ResolvedDid, document_canonical_digest};
use arkret_signatures::jws::sign_jws_ed25519;
use arkret_wire::{DidFullId, DidUrl, Hash, TypedTrustDomainId};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;

// ============================================================================
// Fixtures
// ============================================================================

const CANONICAL: &[u8] = br#"{"kind":"ak.message.create.v1","seq":1}"#;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[17u8; 32])
}

fn did() -> DidFullId {
    DidFullId::new("did:webvh:z6mkfixture:spy.example".to_owned()).expect("valid did")
}

fn verification_method() -> DidUrl {
    DidUrl::new(format!("{}#key-1", did())).expect("valid did url")
}

fn hash(seed: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
}

fn trust_domain() -> TypedTrustDomainId {
    TypedTrustDomainId::new("ak:trust_domain:local".to_owned()).expect("valid trust domain")
}

fn document() -> DidDocument {
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key().verifying_key().as_bytes(),
    );
    DidDocument {
        id: did(),
        verification_methods: BTreeMap::from([(format!("{}#key-1", did()), multibase)]),
        also_known_as: Vec::new(),
        updated_at: None,
        raw_properties: BTreeMap::new(),
    }
}

// ============================================================================
// Counting resolver spy
// ============================================================================

/// Wraps an inner resolver and counts authority network resolutions.
///
/// Only `resolve_did` increments — a local binding-store lookup or a
/// per-signature verification must never reach this type at all.
struct CountingDidResolver<R: DidResolver> {
    inner: R,
    calls: AtomicUsize,
}

impl<R: DidResolver> CountingDidResolver<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl<R: DidResolver> DidResolver for CountingDidResolver<R> {
    fn supports(&self, did: &DidFullId) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &DidFullId) -> arkret_identity::Result<ResolvedDid> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve_did(did)
    }
}

/// Minimal upstream: always returns the fixture document.
struct FixtureResolver;

impl DidResolver for FixtureResolver {
    fn supports(&self, did: &DidFullId) -> bool {
        did == &self::did()
    }

    fn resolve_did(&self, did: &DidFullId) -> arkret_identity::Result<ResolvedDid> {
        if did != &self::did() {
            return Err(arkret_identity::IdentityError::Protocol(format!(
                "fixture resolver does not handle {did}"
            )));
        }
        Ok(ResolvedDid::proofless(document()))
    }
}

fn spy() -> CountingDidResolver<FixtureResolver> {
    CountingDidResolver::new(FixtureResolver)
}

/// A `high` tier profile: 30 minutes fresh, 24 hours hard expiry.
fn freshness_profile() -> FreshnessProfile {
    FreshnessProfile {
        freshness_profile_id: "ak.did_freshness.spy_high.v1".to_owned(),
        risk_tier: FreshnessRiskTier::High,
        did_method_selector: vec!["*".to_owned()],
        fresh_for_seconds: Some(1_800),
        stale_grace_seconds: None,
        hard_expiry_seconds: Some(86_400),
        stale_behavior: StaleBehavior::SynchronousRefreshOrFailClosed,
    }
}

fn request() -> BindingResolveRequest {
    BindingResolveRequest {
        did: did(),
        trust_domain: trust_domain(),
        purpose: DidBindingPurpose::Principal,
        policy_digest: hash(0x44),
        verification_method: Some(verification_method()),
        freshness: freshness_profile(),
    }
}

fn accepted_without_resolver(now: DateTime<Utc>) -> AcceptedDidBinding {
    let document = document();
    let receipt = EvidenceReceipt::new(
        did().method(),
        document_canonical_digest(&document).expect("digest"),
        &MethodEvidence::none(),
    );
    let binding = VerifiedDidBinding::from_verified_document(
        &document,
        VerifiedDidBindingDocumentInput {
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            verification_method: Some(verification_method()),
            history_head: None,
            version_id: None,
            limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
            evidence_digest: receipt.digest().expect("digest"),
            evidence_dependencies: receipt.evidence_dependencies().expect("dependencies"),
            policy_digest: hash(0x44),
            verified_at: now,
            refresh_after: Some(now + Duration::minutes(30)),
            expires_at: Some(now + Duration::hours(24)),
            status: DidBindingStatus::Active,
        },
    )
    .expect("valid binding");
    AcceptedDidBinding::new(binding, document, receipt).expect("consistent pairing")
}

// ============================================================================
// 1. Ordinary verification never reaches a resolver
// ============================================================================

#[test]
fn ordinary_verification_never_calls_the_resolver() {
    // The spy exists for the whole test but is never handed to the verify
    // APIs — they take no resolver parameter, so this is a compile-time
    // guarantee that the counter assertion merely re-confirms.
    let spy = spy();
    let now = Utc::now();
    let accepted = accepted_without_resolver(now);
    let jws = sign_jws_ed25519(CANONICAL, &signing_key()).expect("sign");

    let mut verified = 0usize;
    for _ in 0..5 {
        verify_jws_with_binding(CANONICAL, &jws, &verification_method(), &accepted)
            .expect("binding verify");
        verify_jws_with_document(
            CANONICAL,
            &jws,
            &verification_method(),
            &did(),
            accepted.document(),
        )
        .expect("document verify");
        verified += 2;
    }

    assert_eq!(verified, 10, "every signature was actually verified");
    assert_eq!(
        spy.calls(),
        0,
        "verify_jws_with_binding / verify_jws_with_document must never resolve"
    );
}

// ============================================================================
// 2-4. Authority miss / hit / invalidation counting
// ============================================================================

#[test]
fn authority_miss_resolves_exactly_once_and_a_hit_adds_nothing() {
    let spy = spy();
    let store = InMemoryVerifiedDidBindingStore::default();
    let request = request();
    let now = Utc::now();

    // 2. First call is a store miss: exactly one upstream resolution.
    let first = resolve_and_verify_binding(&spy, &store, &request, now).expect("first resolve");
    assert_eq!(spy.calls(), 1, "authority miss resolves exactly once");
    assert_eq!(store.len(), 1, "the acceptance is written back");

    // 3. Same key, still fresh: the store answers, the resolver is untouched.
    for minute in 1..=5 {
        let hit =
            resolve_and_verify_binding(&spy, &store, &request, now + Duration::minutes(minute))
                .expect("binding hit");
        assert_eq!(
            hit.binding().verified_at(),
            first.binding().verified_at(),
            "a fresh hit returns the stored acceptance, not a new one"
        );
    }
    assert_eq!(spy.calls(), 1, "a fresh binding hit adds no resolver call");

    // 4. After precise invalidation the next authority call resolves again — once, not once per
    //    caller.
    let removed =
        store.invalidate(&BindingInvalidation::for_did(did()).with_trust_domain(trust_domain()));
    assert_eq!(removed, 1);
    resolve_and_verify_binding(&spy, &store, &request, now + Duration::minutes(6))
        .expect("resolve after invalidation");
    assert_eq!(spy.calls(), 2, "invalidation costs exactly one refresh");
}

#[test]
fn hard_expiry_reads_as_a_miss_and_refreshes_once() {
    let spy = spy();
    let store = InMemoryVerifiedDidBindingStore::default();
    let request = request();
    let now = Utc::now();

    resolve_and_verify_binding(&spy, &store, &request, now).expect("first resolve");
    assert_eq!(spy.calls(), 1);

    // Past `hard_expiry` (24h) the entry is invisible: one refresh, no more.
    resolve_and_verify_binding(&spy, &store, &request, now + Duration::hours(25))
        .expect("refresh after hard expiry");
    assert_eq!(spy.calls(), 2);
}

#[test]
fn a_stale_binding_blocks_a_fresh_authority_call_but_not_a_low_risk_one() {
    let store = InMemoryVerifiedDidBindingStore::default();
    let now = Utc::now();
    let after_refresh = now + Duration::minutes(45); // past refresh_after (30m), inside 24h.

    // High-risk caller demands freshness: the stale entry does not satisfy it.
    let strict_spy = spy();
    let strict = request();
    resolve_and_verify_binding(&strict_spy, &store, &strict, now).expect("first resolve");
    assert_eq!(strict_spy.calls(), 1);
    resolve_and_verify_binding(&strict_spy, &store, &strict, after_refresh)
        .expect("explicit refresh");
    assert_eq!(
        strict_spy.calls(),
        2,
        "require_fresh must refresh rather than reuse a stale binding"
    );

    // Low-risk caller accepts a stale binding: no live fallback, no extra call.
    let relaxed_store = InMemoryVerifiedDidBindingStore::default();
    let relaxed_spy = spy();
    let mut relaxed = request();
    relaxed.freshness = FreshnessProfile {
        freshness_profile_id: "ak.did_freshness.spy_low.v1".to_owned(),
        risk_tier: FreshnessRiskTier::Low,
        did_method_selector: vec!["*".to_owned()],
        fresh_for_seconds: Some(1_800),
        stale_grace_seconds: None,
        hard_expiry_seconds: Some(86_400),
        stale_behavior: StaleBehavior::AcceptedWithoutNetwork,
    };
    resolve_and_verify_binding(&relaxed_spy, &relaxed_store, &relaxed, now).expect("first resolve");
    assert_eq!(relaxed_spy.calls(), 1);
    let stale = resolve_and_verify_binding(&relaxed_spy, &relaxed_store, &relaxed, after_refresh)
        .expect("stale reuse");
    assert_eq!(
        relaxed_spy.calls(),
        1,
        "a stale low-risk read must not become an online resolution"
    );
    assert_eq!(stale.binding().status(), DidBindingStatus::Stale);
}

// ============================================================================
// 5. The two counters are genuinely independent
// ============================================================================

#[test]
fn one_authority_resolve_then_five_ordinary_verifications_add_no_resolver_calls() {
    let spy = spy();
    let store = InMemoryVerifiedDidBindingStore::default();
    let request = request();
    let now = Utc::now();

    let accepted = resolve_and_verify_binding(&spy, &store, &request, now).expect("resolve");
    assert_eq!(spy.calls(), 1, "authority_network_call_count = 1");

    let jws = sign_jws_ed25519(CANONICAL, &signing_key()).expect("sign");
    let mut signature_verify_count = 0usize;
    for _ in 0..5 {
        verify_jws_with_binding(CANONICAL, &jws, &verification_method(), &accepted)
            .expect("ordinary verify");
        signature_verify_count += 1;
    }

    assert_eq!(
        signature_verify_count, 5,
        "signature_verify_count grows with traffic"
    );
    assert_eq!(
        spy.calls(),
        1,
        "authority_network_call_count does not: the two counters are independent"
    );
}

#[test]
fn a_tampered_payload_still_fails_without_falling_back_to_the_resolver() {
    let spy = spy();
    let store = InMemoryVerifiedDidBindingStore::default();
    let request = request();
    let now = Utc::now();
    let accepted = resolve_and_verify_binding(&spy, &store, &request, now).expect("resolve");
    assert_eq!(spy.calls(), 1);

    let jws = sign_jws_ed25519(CANONICAL, &signing_key()).expect("sign");
    for _ in 0..3 {
        assert!(
            verify_jws_with_binding(b"tampered", &jws, &verification_method(), &accepted).is_err(),
            "a bad signature must fail closed"
        );
    }
    assert_eq!(
        spy.calls(),
        1,
        "a failed ordinary verification must not trigger a 'resolve to be safe' path"
    );
}
