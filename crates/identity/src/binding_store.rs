//! Verified-binding store contract, precise invalidation and a reference
//! in-memory implementation (`did-usage-and-verification.md` §5).
//!
//! # What the store holds
//!
//! An [`AcceptedDidBinding`] is a [`VerifiedDidBinding`] **plus the pinned DID
//! document it was accepted against**. Carrying the document is what makes
//! `crate::verifier::verify_jws_with_binding` a zero-network operation: the
//! public key comes out of the stored document, not out of a resolver. The
//! pairing is checked — [`AcceptedDidBinding::new`] and
//! [`VerifiedDidBindingStore::accept`] both recompute the document's canonical
//! digest and reject a mismatch.
//!
//! # Stale is not expired
//!
//! `did-usage-and-verification.md` §5: "cache TTL expiry alone MUST NOT turn an
//! ordinary business request into an online DID resolution; it only marks the
//! authority-grade result stale." The store implements exactly that split:
//!
//! - `now > expires_at` (**hard expiry**) — [`VerifiedDidBindingStore::get`] returns `None`; the
//!   entry no longer exists for readers.
//! - `now > refresh_after` (**stale**) — `get` still returns the entry, with its status downgraded
//!   to [`DidBindingStatus::Stale`], and the caller decides by risk level.
//!
//! [`VerifiedDidBindingStore::get_with_freshness`] exposes the distinction
//! directly as a [`BindingFreshness`].

use std::collections::BTreeMap;
use std::sync::Mutex;

use arkret_wire::{DidFullId, DidUrl, Hash, TypedTrustDomainId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::DidDocument;
use crate::binding::{
    DidBindingPurpose, DidBindingStatus, VerifiedDidBinding, VerifiedDidBindingKey,
    document_canonical_digest,
};
use crate::binding_digest::EvidenceReceipt;

// ============================================================================
// Errors
// ============================================================================

/// Reasons a store refuses to accept a binding.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindingStoreError {
    /// The supplied document is not the document the binding was accepted for.
    #[error("pinned document digest {actual} does not match the binding digest {expected}")]
    DocumentDigestMismatch { expected: Hash, actual: Hash },
    /// The supplied document belongs to a different DID than the binding.
    #[error("pinned document id `{document_id}` does not match the bound DID `{did}`")]
    DocumentIdMismatch {
        document_id: DidFullId,
        did: DidFullId,
    },
    /// The retained evidence receipt does not re-digest to the binding's
    /// `evidence_digest`, so the acceptance is not recomputable.
    #[error("retained evidence receipt digests to {actual}, not the binding digest {expected}")]
    EvidenceDigestMismatch { expected: Hash, actual: Hash },
    /// The document or receipt could not be canonicalized / digested.
    #[error("pinned document digest could not be computed: {0}")]
    Digest(String),
}

// ============================================================================
// Accepted binding (binding + pinned document)
// ============================================================================

/// A [`VerifiedDidBinding`] together with the DID document it pins.
///
/// Fields are private and the pairing is validated on construction, so a value
/// of this type is always self-consistent: the document really is the one whose
/// canonical digest the binding recorded.
///
/// `Deserialize` routes through [`AcceptedDidBinding::new`] rather than filling
/// the fields directly, so a persisted pairing is **re-validated on load**: a
/// store row whose document was edited after it was written fails to
/// deserialize instead of coming back as a trusted acceptance. The inner
/// [`VerifiedDidBinding`] independently re-runs its own constructor checks, so
/// both halves and their relationship are checked on every hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AcceptedDidBinding {
    binding: VerifiedDidBinding,
    document: DidDocument,
    evidence_receipt: EvidenceReceipt,
}

/// Wire shape of [`AcceptedDidBinding`]. Kept separate so `Deserialize` is
/// forced through the validating constructor instead of `#[derive]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedDidBindingWire {
    binding: VerifiedDidBinding,
    document: DidDocument,
    evidence_receipt: EvidenceReceipt,
}

impl<'de> Deserialize<'de> for AcceptedDidBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AcceptedDidBindingWire::deserialize(deserializer)?;
        Self::new(wire.binding, wire.document, wire.evidence_receipt)
            .map_err(serde::de::Error::custom)
    }
}

impl AcceptedDidBinding {
    /// Pair a binding with the material it rests on: the pinned document and the
    /// canonical evidence receipt.
    ///
    /// Verifies that the document's canonical digest is exactly
    /// `binding.document_digest()`, that the document belongs to the bound DID,
    /// and that the receipt re-digests to `binding.evidence_digest()`.
    ///
    /// The receipt is retained rather than discarded after digesting because
    /// `did-usage-and-verification.md` §5.2 makes "auditable" mean
    /// "recomputable": a stored acceptance whose evidence digest cannot be
    /// re-derived from retained material is exactly the unfalsifiable claim the
    /// canonical receipt exists to prevent.
    pub fn new(
        binding: VerifiedDidBinding,
        document: DidDocument,
        evidence_receipt: EvidenceReceipt,
    ) -> Result<Self, BindingStoreError> {
        if &document.id != binding.did() {
            return Err(BindingStoreError::DocumentIdMismatch {
                document_id: document.id,
                did: binding.did().clone(),
            });
        }
        let actual = document_canonical_digest(&document)
            .map_err(|error| BindingStoreError::Digest(error.to_string()))?;
        if &actual != binding.document_digest() {
            return Err(BindingStoreError::DocumentDigestMismatch {
                expected: binding.document_digest().clone(),
                actual,
            });
        }
        let recomputed = evidence_receipt
            .digest()
            .map_err(|error| BindingStoreError::Digest(error.to_string()))?;
        if &recomputed != binding.evidence_digest() {
            return Err(BindingStoreError::EvidenceDigestMismatch {
                expected: binding.evidence_digest().clone(),
                actual: recomputed,
            });
        }
        Ok(Self {
            binding,
            document,
            evidence_receipt,
        })
    }

    /// The verified binding.
    pub fn binding(&self) -> &VerifiedDidBinding {
        &self.binding
    }

    /// The pinned DID document the binding was accepted against.
    pub fn document(&self) -> &DidDocument {
        &self.document
    }

    /// The retained canonical evidence receipt an auditor recomputes the
    /// binding's `evidence_digest` from.
    pub fn evidence_receipt(&self) -> &EvidenceReceipt {
        &self.evidence_receipt
    }

    /// Return a copy whose binding carries `status`. The document and receipt
    /// pairings are unchanged, so both digest invariants still hold.
    pub fn with_binding_status(&self, status: DidBindingStatus) -> Self {
        Self {
            binding: self.binding.with_status(status),
            document: self.document.clone(),
            evidence_receipt: self.evidence_receipt.clone(),
        }
    }
}

// ============================================================================
// Freshness
// ============================================================================

/// Freshness of a stored binding at a given instant.
///
/// `Stale` and `Expired` are deliberately distinct: only `Expired` makes the
/// entry disappear for readers, and neither one may trigger an implicit online
/// resolution on an ordinary path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingFreshness {
    /// Inside the refresh window.
    Fresh,
    /// Past `refresh_after` but not hard-expired; `age` is the time since the
    /// refresh point.
    Stale { age: Duration },
    /// Past `expires_at`. Treated as absent by [`VerifiedDidBindingStore::get`].
    Expired,
    /// No entry under this key.
    Missing,
}

// ============================================================================
// Invalidation selector
// ============================================================================

/// Precise invalidation selector (`did-usage-and-verification.md` §5: the
/// invalidation index must locate entries "at least by DID, verification
/// method, history head, trust domain, purpose and policy digest").
///
/// Every populated dimension is a **conjunctive** constraint: an entry is
/// invalidated only when it matches *all* of them. That is what keeps a
/// rotation in one trust domain (or for one purpose) from wiping an independent
/// acceptance in another — invalidating "this DID **in this trust domain**"
/// never touches the same DID in a different trust domain.
///
/// An empty selector matches nothing and invalidates zero entries; use an
/// explicit dimension (or [`VerifiedDidBindingStore::snapshot`] plus targeted
/// calls) rather than relying on a catch-all wipe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingInvalidation {
    /// Match the bound DID.
    pub did: Option<DidFullId>,
    /// Match the accepted concrete verification method (key rotation).
    pub verification_method: Option<DidUrl>,
    /// Match the pinned history head (witness fork).
    pub history_head: Option<String>,
    /// Match a witness this binding's evidence depends on (§5.6).
    ///
    /// This is the selective-invalidation dimension a digest cannot provide: a
    /// witness revocation arrives as a witness DID, and `evidence_digest` is
    /// one-way, so without this the only safe response is the `for_did` sweep
    /// that also invalidates every unaffected binding of that DID.
    pub evidence_witness_did: Option<DidFullId>,
    /// Match a witness controlling organization the evidence depends on (§5.6).
    pub evidence_witness_organization: Option<DidFullId>,
    /// Match the local trust domain.
    pub trust_domain: Option<TypedTrustDomainId>,
    /// Match the acceptance purpose (controller / service delegation change).
    pub purpose: Option<DidBindingPurpose>,
    /// Match the resolver / Realm policy digest (policy revision).
    pub policy_digest: Option<Hash>,
}

impl BindingInvalidation {
    /// Selector constrained to one DID.
    pub fn for_did(did: DidFullId) -> Self {
        Self {
            did: Some(did),
            ..Self::default()
        }
    }

    /// Selector constrained to one verification method (key rotation).
    pub fn for_verification_method(verification_method: DidUrl) -> Self {
        Self {
            verification_method: Some(verification_method),
            ..Self::default()
        }
    }

    /// Selector constrained to one history head (witness fork).
    pub fn for_history_head(history_head: String) -> Self {
        Self {
            history_head: Some(history_head),
            ..Self::default()
        }
    }

    /// Selector constrained to one witness DID (witness revocation).
    ///
    /// Stores that declare evidence-bearing methods MUST support this lookup:
    /// §5.6 makes reverse lookup by witness DID the minimum a selective
    /// invalidation needs.
    pub fn for_evidence_witness(witness_did: DidFullId) -> Self {
        Self {
            evidence_witness_did: Some(witness_did),
            ..Self::default()
        }
    }

    /// Selector constrained to one witness controlling organization (an
    /// organization merge determination collapses several witnesses into one).
    pub fn for_evidence_witness_organization(organization: DidFullId) -> Self {
        Self {
            evidence_witness_organization: Some(organization),
            ..Self::default()
        }
    }

    /// Selector constrained to one policy digest (resolver / Realm policy change).
    pub fn for_policy_digest(policy_digest: Hash) -> Self {
        Self {
            policy_digest: Some(policy_digest),
            ..Self::default()
        }
    }

    /// Narrow the selector to one trust domain.
    pub fn with_trust_domain(mut self, trust_domain: TypedTrustDomainId) -> Self {
        self.trust_domain = Some(trust_domain);
        self
    }

    /// Narrow the selector to one purpose.
    pub fn with_purpose(mut self, purpose: DidBindingPurpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Narrow the selector to one verification method.
    pub fn with_verification_method(mut self, verification_method: DidUrl) -> Self {
        self.verification_method = Some(verification_method);
        self
    }

    /// Narrow the selector to one history head.
    pub fn with_history_head(mut self, history_head: String) -> Self {
        self.history_head = Some(history_head);
        self
    }

    /// Narrow the selector to one policy digest.
    pub fn with_policy_digest(mut self, policy_digest: Hash) -> Self {
        self.policy_digest = Some(policy_digest);
        self
    }

    /// Narrow the selector to one DID.
    pub fn with_did(mut self, did: DidFullId) -> Self {
        self.did = Some(did);
        self
    }

    /// Whether any dimension is constrained. An unconstrained selector matches
    /// nothing.
    pub fn is_empty(&self) -> bool {
        self.did.is_none()
            && self.verification_method.is_none()
            && self.history_head.is_none()
            && self.evidence_witness_did.is_none()
            && self.evidence_witness_organization.is_none()
            && self.trust_domain.is_none()
            && self.purpose.is_none()
            && self.policy_digest.is_none()
    }

    /// Whether `binding` matches every constrained dimension.
    pub fn matches(&self, binding: &VerifiedDidBinding) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(did) = &self.did
            && did != binding.did()
        {
            return false;
        }
        if let Some(verification_method) = &self.verification_method
            && binding.verification_method() != Some(verification_method)
        {
            return false;
        }
        if let Some(history_head) = &self.history_head
            && binding.history_head() != Some(history_head)
        {
            return false;
        }
        if let Some(witness) = &self.evidence_witness_did
            && !binding
                .evidence_dependencies()
                .witness_dids
                .contains(witness)
        {
            return false;
        }
        if let Some(organization) = &self.evidence_witness_organization
            && !binding
                .evidence_dependencies()
                .witness_controlling_organizations
                .contains(organization)
        {
            return false;
        }
        if let Some(trust_domain) = &self.trust_domain
            && trust_domain != binding.trust_domain()
        {
            return false;
        }
        if let Some(purpose) = &self.purpose
            && *purpose != binding.purpose()
        {
            return false;
        }
        if let Some(policy_digest) = &self.policy_digest
            && policy_digest != binding.policy_digest()
        {
            return false;
        }
        true
    }
}

// ============================================================================
// Store contract
// ============================================================================

/// Storage contract for accepted DID bindings.
///
/// Implementations are shared across threads (`Send + Sync`) because a service
/// creates exactly one store at startup and every handler reads it — the
/// opposite of constructing a network resolver per request.
pub trait VerifiedDidBindingStore: Send + Sync {
    /// Look up an entry, honouring hard expiry.
    ///
    /// Returns `None` when the key is unknown **or** when `now` is past the
    /// entry's `expires_at`. A stale-but-not-expired entry is returned with its
    /// status downgraded to [`DidBindingStatus::Stale`].
    fn get(&self, key: &VerifiedDidBindingKey, now: DateTime<Utc>) -> Option<AcceptedDidBinding> {
        self.get_with_freshness(key, now).0
    }

    /// Same as [`Self::get`] but also reports why.
    fn get_with_freshness(
        &self,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> (Option<AcceptedDidBinding>, BindingFreshness);

    /// Store an accepted binding, re-verifying the binding/document pairing.
    fn accept(&self, accepted: AcceptedDidBinding) -> Result<(), BindingStoreError>;

    /// Invalidate every entry matching `selector`; returns the number removed.
    fn invalidate(&self, selector: &BindingInvalidation) -> usize;

    /// Deterministic snapshot of all stored entries, ordered by key.
    fn snapshot(&self) -> Vec<AcceptedDidBinding>;
}

/// Compute an entry's freshness without consulting a store.
pub fn binding_freshness_at(binding: &VerifiedDidBinding, now: DateTime<Utc>) -> BindingFreshness {
    if binding.is_hard_expired(now) {
        return BindingFreshness::Expired;
    }
    match binding.refresh_after() {
        Some(refresh_after) if now > refresh_after => BindingFreshness::Stale {
            age: now - refresh_after,
        },
        _ => BindingFreshness::Fresh,
    }
}

// ============================================================================
// Reference implementation
// ============================================================================

/// Reference in-memory [`VerifiedDidBindingStore`] for SDK tests and service
/// integration.
///
/// Backed by a `Mutex<BTreeMap<..>>`, so iteration order (and therefore
/// [`Self::snapshot`] and eviction) is deterministic. When the capacity bound is
/// reached, the entry with the oldest `verified_at` is evicted, ties broken by
/// key order — never at random.
#[derive(Debug)]
pub struct InMemoryVerifiedDidBindingStore {
    entries: Mutex<BTreeMap<VerifiedDidBindingKey, AcceptedDidBinding>>,
    max_entries: usize,
}

impl InMemoryVerifiedDidBindingStore {
    /// Create a store bounded to `max_entries`. `0` disables storage entirely
    /// (every `get` misses), which is useful for negative tests.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            max_entries,
        }
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove every entry.
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<VerifiedDidBindingKey, AcceptedDidBinding>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for InMemoryVerifiedDidBindingStore {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl VerifiedDidBindingStore for InMemoryVerifiedDidBindingStore {
    fn get_with_freshness(
        &self,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> (Option<AcceptedDidBinding>, BindingFreshness) {
        let entries = self.lock();
        let Some(entry) = entries.get(key) else {
            return (None, BindingFreshness::Missing);
        };
        match binding_freshness_at(entry.binding(), now) {
            BindingFreshness::Fresh => (Some(entry.clone()), BindingFreshness::Fresh),
            BindingFreshness::Stale { age } => {
                // Downgrade `Active` to `Stale` so the caller sees the TTL
                // crossing in the value itself. `Deactivated` / `Quarantined`
                // are terminal and never upgraded back into `Stale`.
                let downgraded = if entry.binding().status() == DidBindingStatus::Active {
                    entry.with_binding_status(DidBindingStatus::Stale)
                } else {
                    entry.clone()
                };
                (Some(downgraded), BindingFreshness::Stale { age })
            }
            // Hard-expired entries are invisible to readers. They are left in
            // place so an explicit `invalidate` still reports them, and so a
            // refresh can overwrite the same key.
            BindingFreshness::Expired => (None, BindingFreshness::Expired),
            BindingFreshness::Missing => (None, BindingFreshness::Missing),
        }
    }

    fn accept(&self, accepted: AcceptedDidBinding) -> Result<(), BindingStoreError> {
        // Re-verify the pairing even though `AcceptedDidBinding::new` already
        // did: `accept` is the trust boundary a service calls, and the value
        // may have crossed a serialization hop since construction.
        let recomputed = document_canonical_digest(accepted.document())
            .map_err(|error| BindingStoreError::Digest(error.to_string()))?;
        if &recomputed != accepted.binding().document_digest() {
            return Err(BindingStoreError::DocumentDigestMismatch {
                expected: accepted.binding().document_digest().clone(),
                actual: recomputed,
            });
        }
        if &accepted.document().id != accepted.binding().did() {
            return Err(BindingStoreError::DocumentIdMismatch {
                document_id: accepted.document().id.clone(),
                did: accepted.binding().did().clone(),
            });
        }

        if self.max_entries == 0 {
            return Ok(());
        }
        let key = accepted.binding().key();
        let mut entries = self.lock();
        if !entries.contains_key(&key) && entries.len() >= self.max_entries {
            // Deterministic eviction: oldest `verified_at`, ties broken by key
            // order (BTreeMap iteration is sorted, and `min_by_key` keeps the
            // first minimum).
            if let Some(victim) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.binding().verified_at())
                .map(|(victim_key, _)| victim_key.clone())
            {
                entries.remove(&victim);
            }
        }
        entries.insert(key, accepted);
        Ok(())
    }

    fn invalidate(&self, selector: &BindingInvalidation) -> usize {
        if selector.is_empty() {
            return 0;
        }
        let mut entries = self.lock();
        let doomed = entries
            .iter()
            .filter(|(_, entry)| selector.matches(entry.binding()))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &doomed {
            entries.remove(key);
        }
        doomed.len()
    }

    fn snapshot(&self) -> Vec<AcceptedDidBinding> {
        self.lock().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidUrl;

    use super::*;
    use crate::binding::{LimitedTrust, VerifiedDidBindingDocumentInput};
    use crate::binding_digest::MethodEvidence;

    const KEY_MATERIAL: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn trust_domain(scope: &str) -> TypedTrustDomainId {
        TypedTrustDomainId::new(format!("ak:trust_domain:{scope}")).expect("valid trust domain")
    }

    fn did() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:store.example".to_owned()).expect("valid did")
    }

    fn document_for(did: &DidFullId, fragment: &str) -> DidDocument {
        DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                format!("{did}#{fragment}"),
                KEY_MATERIAL.to_owned(),
            )]),
            also_known_as: Vec::new(),
            // Fixed timestamp so the canonical digest is reproducible.
            updated_at: None,
            raw_properties: BTreeMap::new(),
        }
    }

    struct Fixture {
        did: DidFullId,
        trust_domain: TypedTrustDomainId,
        purpose: DidBindingPurpose,
        fragment: &'static str,
        history_head: Option<String>,
        policy_digest: Hash,
        verified_at: DateTime<Utc>,
        refresh_after: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        status: DidBindingStatus,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                did: did(),
                trust_domain: trust_domain("local"),
                purpose: DidBindingPurpose::Principal,
                fragment: "key-1",
                history_head: Some("1-abc".to_owned()),
                policy_digest: hash(0x44),
                // A protocol instant is millisecond-precision; taking a raw
                // `Utc::now()` here would give the fixture sub-millisecond
                // digits the constructor floors away.
                verified_at: arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now()),
                refresh_after: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            }
        }

        fn accepted(&self) -> AcceptedDidBinding {
            let document = document_for(&self.did, self.fragment);
            let verification_method =
                DidUrl::new(format!("{}#{}", self.did, self.fragment)).expect("valid did url");
            // The receipt is what the acceptance is built from, so the fixture
            // derives the digest from it rather than picking a literal: a
            // hand-written `evidence_digest` is precisely what the store now
            // refuses.
            let receipt = EvidenceReceipt::new(
                self.did.method(),
                document_canonical_digest(&document).expect("digest"),
                &MethodEvidence::none(),
            );
            let binding = VerifiedDidBinding::from_verified_document(
                &document,
                VerifiedDidBindingDocumentInput {
                    trust_domain: self.trust_domain.clone(),
                    purpose: self.purpose,
                    verification_method: Some(verification_method),
                    history_head: self.history_head.clone(),
                    version_id: Some("1-abc".to_owned()),
                    limited_trust: LimitedTrust::for_proofless_method(
                        self.history_head.as_deref(),
                        Some("1-abc"),
                    )
                    .record_for(),
                    evidence_digest: receipt.digest().expect("digest"),
                    evidence_dependencies: receipt.evidence_dependencies().expect("dependencies"),
                    policy_digest: self.policy_digest.clone(),
                    verified_at: self.verified_at,
                    refresh_after: self.refresh_after,
                    expires_at: self.expires_at,
                    status: self.status,
                },
            )
            .expect("valid binding");
            AcceptedDidBinding::new(binding, document, receipt).expect("consistent pairing")
        }
    }

    fn store_with(fixtures: &[Fixture]) -> InMemoryVerifiedDidBindingStore {
        let store = InMemoryVerifiedDidBindingStore::default();
        for fixture in fixtures {
            store.accept(fixture.accepted()).expect("accept");
        }
        store
    }

    // -- pairing --

    #[test]
    fn accept_rejects_a_document_that_is_not_the_pinned_one() {
        let fixture = Fixture::new();
        let accepted = fixture.accepted();
        // Hand-build a binding whose digest points at a different document.
        let other = document_for(&fixture.did, "key-2");
        let error = AcceptedDidBinding::new(
            accepted.binding().clone(),
            other,
            accepted.evidence_receipt().clone(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingStoreError::DocumentDigestMismatch { .. }
        ));
    }

    #[test]
    fn accept_rejects_a_document_belonging_to_another_did() {
        let fixture = Fixture::new();
        let other_did =
            DidFullId::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
        let accepted = fixture.accepted();
        let error = AcceptedDidBinding::new(
            accepted.binding().clone(),
            document_for(&other_did, "key-1"),
            accepted.evidence_receipt().clone(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingStoreError::DocumentIdMismatch { .. }
        ));
    }

    // -- serde round-trip through the validating constructor --

    #[test]
    fn serde_round_trip_preserves_the_pairing() {
        let accepted = Fixture::new().accepted();
        let json = serde_json::to_string(&accepted).expect("serialize");
        let restored: AcceptedDidBinding = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.binding(), accepted.binding());
        assert_eq!(restored.document().id, accepted.document().id);
        assert_eq!(
            restored.document().verification_methods,
            accepted.document().verification_methods
        );
        // `DidDocument` re-materializes `raw_properties` on the way back in, so
        // the values are not `==`. What matters is that the pairing invariant
        // survives: the restored document still hashes to the pinned digest —
        // which `AcceptedDidBinding::new` just proved by not rejecting it.
        assert_eq!(
            &document_canonical_digest(restored.document()).expect("digest"),
            accepted.binding().document_digest()
        );
    }

    #[test]
    fn deserialization_rejects_a_tampered_document() {
        // The reason persistence previously had to be split into
        // `(binding, document)` and rebuilt through `AcceptedDidBinding::new`:
        // a `Deserialize` that filled the fields directly would let an edited
        // stored document come back as a trusted acceptance. This one runs the
        // same digest check, so the split is no longer necessary.
        let fixture = Fixture::new();
        let accepted = fixture.accepted();
        let mut value = serde_json::to_value(&accepted).expect("serialize");
        value["document"]["verification_methods"] = serde_json::json!({
            format!("{}#key-1", fixture.did): "z6MkAttackerControlledKeyMaterialValue00000000",
        });

        let error = serde_json::from_value::<AcceptedDidBinding>(value).unwrap_err();
        assert!(
            error.to_string().contains("digest"),
            "a tampered document must fail the pairing check, got: {error}"
        );
    }

    #[test]
    fn deserialization_rejects_a_document_for_another_did() {
        let accepted = Fixture::new().accepted();
        let other_did =
            DidFullId::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
        let mut value = serde_json::to_value(&accepted).expect("serialize");
        value["document"]["id"] = serde_json::json!(other_did.as_str());
        assert!(serde_json::from_value::<AcceptedDidBinding>(value).is_err());
    }

    #[test]
    fn deserialization_also_reruns_the_inner_binding_checks() {
        // Both halves are re-validated, not just their relationship.
        let accepted = Fixture::new().accepted();
        let mut value = serde_json::to_value(&accepted).expect("serialize");
        value["binding"]["method"] = serde_json::json!("web");
        assert!(serde_json::from_value::<AcceptedDidBinding>(value).is_err());
    }

    // -- stale vs hard-expired --

    #[test]
    fn hard_expired_entry_is_invisible_to_readers() {
        let mut fixture = Fixture::new();
        fixture.expires_at = Some(fixture.verified_at + Duration::minutes(10));
        let store = store_with(std::slice::from_ref(&fixture));
        let key = fixture.accepted().binding().key();

        let (hit, freshness) =
            store.get_with_freshness(&key, fixture.verified_at + Duration::minutes(5));
        assert!(hit.is_some());
        assert_eq!(freshness, BindingFreshness::Fresh);

        let (hit, freshness) =
            store.get_with_freshness(&key, fixture.verified_at + Duration::minutes(11));
        assert!(hit.is_none(), "hard-expired binding must read as absent");
        assert_eq!(freshness, BindingFreshness::Expired);
    }

    #[test]
    fn past_refresh_point_returns_a_stale_entry_rather_than_nothing() {
        let mut fixture = Fixture::new();
        fixture.refresh_after = Some(fixture.verified_at + Duration::minutes(10));
        fixture.expires_at = Some(fixture.verified_at + Duration::hours(24));
        let store = store_with(std::slice::from_ref(&fixture));
        let key = fixture.accepted().binding().key();

        let (hit, freshness) =
            store.get_with_freshness(&key, fixture.verified_at + Duration::minutes(30));
        let hit = hit.expect("stale binding must still be readable");
        assert_eq!(hit.binding().status(), DidBindingStatus::Stale);
        assert!(
            hit.binding().is_usable_for_ordinary_verification(),
            "a stale binding still serves ordinary verification without a resolver"
        );
        assert!(matches!(freshness, BindingFreshness::Stale { .. }));
    }

    #[test]
    fn deactivated_status_is_not_overwritten_by_the_stale_downgrade() {
        let mut fixture = Fixture::new();
        fixture.status = DidBindingStatus::Deactivated;
        fixture.refresh_after = Some(fixture.verified_at + Duration::minutes(10));
        let store = store_with(std::slice::from_ref(&fixture));
        let key = fixture.accepted().binding().key();
        let hit = store
            .get(&key, fixture.verified_at + Duration::minutes(30))
            .expect("entry present");
        assert_eq!(hit.binding().status(), DidBindingStatus::Deactivated);
        assert!(!hit.binding().is_usable_for_ordinary_verification());
    }

    // -- §5 invalidation triggers, one test each --

    #[test]
    fn rotation_invalidates_only_the_rotated_verification_method() {
        let mut old = Fixture::new();
        old.fragment = "key-1";
        let mut new = Fixture::new();
        new.fragment = "key-2";
        let store = store_with(&[old, new]);
        assert_eq!(store.len(), 2);

        let rotated = DidUrl::new(format!("{}#key-1", did())).expect("valid did url");
        let removed = store.invalidate(&BindingInvalidation::for_verification_method(rotated));
        assert_eq!(removed, 1, "rotation removes exactly the superseded key");
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.snapshot()[0]
                .binding()
                .verification_method()
                .map(DidUrl::as_str),
            Some(format!("{}#key-2", did()).as_str())
        );
    }

    #[test]
    fn deactivation_invalidates_every_purpose_of_that_did_in_the_trust_domain() {
        let mut principal = Fixture::new();
        principal.purpose = DidBindingPurpose::Principal;
        let mut controller = Fixture::new();
        controller.purpose = DidBindingPurpose::Controller;
        let mut other_domain = Fixture::new();
        other_domain.trust_domain = trust_domain("federation.peer");
        let store = store_with(&[principal, controller, other_domain]);
        assert_eq!(store.len(), 3);

        let removed = store.invalidate(
            &BindingInvalidation::for_did(did()).with_trust_domain(trust_domain("local")),
        );
        assert_eq!(removed, 2, "deactivation clears both local purposes");
        assert_eq!(store.len(), 1, "the other trust domain is untouched");
    }

    #[test]
    fn witness_fork_invalidates_by_history_head() {
        let mut forked = Fixture::new();
        forked.history_head = Some("1-abc".to_owned());
        forked.fragment = "key-1";
        let mut sound = Fixture::new();
        sound.history_head = Some("2-def".to_owned());
        sound.fragment = "key-2";
        let store = store_with(&[forked, sound]);

        let removed = store.invalidate(&BindingInvalidation::for_history_head("1-abc".to_owned()));
        assert_eq!(removed, 1);
        assert_eq!(
            store.snapshot()[0].binding().history_head(),
            Some("2-def"),
            "only the forked head is dropped"
        );
    }

    #[test]
    fn controller_delegation_change_invalidates_only_the_controller_purpose() {
        let mut controller = Fixture::new();
        controller.purpose = DidBindingPurpose::Controller;
        let mut principal = Fixture::new();
        principal.purpose = DidBindingPurpose::Principal;
        let store = store_with(&[controller, principal]);

        let removed = store.invalidate(
            &BindingInvalidation::for_did(did()).with_purpose(DidBindingPurpose::Controller),
        );
        assert_eq!(removed, 1);
        assert_eq!(
            store.snapshot()[0].binding().purpose(),
            DidBindingPurpose::Principal
        );
    }

    #[test]
    fn service_delegation_change_invalidates_only_the_service_purpose() {
        let mut service = Fixture::new();
        service.purpose = DidBindingPurpose::Service;
        let mut endpoint = Fixture::new();
        endpoint.purpose = DidBindingPurpose::PrincipalServiceEndpoint;
        let store = store_with(&[service, endpoint]);

        let removed = store.invalidate(
            &BindingInvalidation::for_did(did()).with_purpose(DidBindingPurpose::Service),
        );
        assert_eq!(removed, 1);
        assert_eq!(
            store.snapshot()[0].binding().purpose(),
            DidBindingPurpose::PrincipalServiceEndpoint
        );
    }

    #[test]
    fn policy_digest_change_invalidates_only_the_superseded_policy() {
        let mut old_policy = Fixture::new();
        old_policy.policy_digest = hash(0x44);
        let mut new_policy = Fixture::new();
        new_policy.policy_digest = hash(0x55);
        let store = store_with(&[old_policy, new_policy]);
        assert_eq!(store.len(), 2, "policy digest is part of the store key");

        let removed = store.invalidate(&BindingInvalidation::for_policy_digest(hash(0x44)));
        assert_eq!(removed, 1);
        assert_eq!(store.snapshot()[0].binding().policy_digest(), &hash(0x55));
    }

    // -- negative: no collateral damage --

    #[test]
    fn invalidating_one_trust_domain_does_not_clear_another() {
        let mut local = Fixture::new();
        local.trust_domain = trust_domain("local");
        let mut peer = Fixture::new();
        peer.trust_domain = trust_domain("federation.peer");
        let store = store_with(&[local, peer]);

        let removed = store.invalidate(
            &BindingInvalidation::for_did(did()).with_trust_domain(trust_domain("local")),
        );
        assert_eq!(removed, 1);
        let remaining = store.snapshot();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].binding().trust_domain(),
            &trust_domain("federation.peer"),
            "an unrelated trust domain must survive"
        );
    }

    #[test]
    fn invalidating_one_purpose_does_not_clear_another() {
        let mut issuer = Fixture::new();
        issuer.purpose = DidBindingPurpose::Issuer;
        let mut device = Fixture::new();
        device.purpose = DidBindingPurpose::DeviceSigner;
        let store = store_with(&[issuer, device]);

        let removed = store.invalidate(
            &BindingInvalidation::for_did(did()).with_purpose(DidBindingPurpose::Issuer),
        );
        assert_eq!(removed, 1);
        assert_eq!(
            store.snapshot()[0].binding().purpose(),
            DidBindingPurpose::DeviceSigner,
            "an unrelated purpose must survive"
        );
    }

    #[test]
    fn an_empty_selector_invalidates_nothing() {
        let store = store_with(&[Fixture::new()]);
        assert_eq!(store.invalidate(&BindingInvalidation::default()), 0);
        assert_eq!(store.len(), 1);
    }

    // -- capacity --

    #[test]
    fn capacity_evicts_the_oldest_verification_deterministically() {
        let store = InMemoryVerifiedDidBindingStore::new(2);
        let base = Utc::now();
        let mut first = Fixture::new();
        first.purpose = DidBindingPurpose::Principal;
        first.verified_at = base;
        let mut second = Fixture::new();
        second.purpose = DidBindingPurpose::Service;
        second.verified_at = base + Duration::seconds(1);
        let mut third = Fixture::new();
        third.purpose = DidBindingPurpose::Issuer;
        third.verified_at = base + Duration::seconds(2);

        store.accept(first.accepted()).expect("accept");
        store.accept(second.accepted()).expect("accept");
        store.accept(third.accepted()).expect("accept");

        assert_eq!(store.len(), 2);
        let purposes = store
            .snapshot()
            .iter()
            .map(|entry| entry.binding().purpose())
            .collect::<Vec<_>>();
        assert!(
            !purposes.contains(&DidBindingPurpose::Principal),
            "the oldest verification is evicted, got {purposes:?}"
        );
    }

    #[test]
    fn re_accepting_the_same_key_replaces_the_entry() {
        let fixture = Fixture::new();
        let store = store_with(std::slice::from_ref(&fixture));
        let mut refreshed = Fixture::new();
        refreshed.verified_at = fixture.verified_at + Duration::hours(1);
        store.accept(refreshed.accepted()).expect("accept");
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.snapshot()[0].binding().verified_at(),
            refreshed.verified_at
        );
    }
}
