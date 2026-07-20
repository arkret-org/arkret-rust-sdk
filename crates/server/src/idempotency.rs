//! Applet transaction idempotency window (`applet-integration.md` §7.3 /
//! §7.3.1).
//!
//! The idempotency identity is the spec 5-tuple `(operation_id, direction,
//! source_service_id, destination_service_id, idempotency_key)`
//! (`operation-registry.json` `idempotency_identity_fields`). Each record
//! additionally pins the canonical body digest and the per-delivery
//! `source_signature_anchor` formed at verification time, so a rotated key
//! or a different signer can never replay an old `Idempotency-Key` as a
//! benign duplicate.
//!
//! The API is claim-based: [`IdempotencyWindow::claim`] atomically performs
//! lookup **and** placeholder insertion inside a single lock acquisition, so
//! the idempotency record is persisted *before* the caller runs any external
//! side effect (the ordering `applet-integration.md` §7.3 requires) and two
//! concurrent deliveries of the same identity can never both observe
//! "fresh". After processing, the caller either
//! [`IdempotencyWindow::complete`]s the claim with the outcome to replay to
//! future duplicates, or [`IdempotencyWindow::release`]s it so the peer can
//! retry.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use arkret_wire::{Error, Hash};

/// Delivery direction component of the idempotency identity
/// (`applet-integration.md` §7.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdempotencyDirection {
    /// Arkret node pushing a transaction to an Applet service.
    NodeToApplet,
    /// Installed Applet service / bridge pushing an external-network
    /// transaction to the arkret edge inbound endpoint.
    AppletToArkretInbound,
}

impl IdempotencyDirection {
    /// Canonical wire label used inside `source_signature_anchor` tuples.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NodeToApplet => "node_to_applet",
            Self::AppletToArkretInbound => "applet_to_arkret_inbound",
        }
    }
}

/// Spec 5-tuple idempotency identity
/// (`applet-integration.md` §7.3: "幂等 identity MUST 至少绑定
/// `(operation_id, direction, Source-Service-ID, Destination-Service-ID,
/// Idempotency-Key)`").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IdempotencyIdentity {
    pub operation_id: String,
    pub direction: IdempotencyDirection,
    pub source_service_id: String,
    pub destination_service_id: String,
    pub idempotency_key: String,
}

impl IdempotencyIdentity {
    /// Identity for a `ak.edge.applet.command.transaction` delivery.
    pub fn applet_transaction(
        direction: IdempotencyDirection,
        source_service_id: impl Into<String>,
        destination_service_id: impl Into<String>,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION
                .to_owned(),
            direction,
            source_service_id: source_service_id.into(),
            destination_service_id: destination_service_id.into(),
            idempotency_key: idempotency_key.into(),
        }
    }
}

/// Storage-neutral decision for an Applet transaction idempotency claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionClaim<T> {
    Claimed,
    Pending,
    Duplicate(T),
    Conflict,
}

/// Persistence contract for Applet transaction idempotency.
///
/// Production services should use a durable implementation so claims and
/// completed outcomes survive restarts for the full retention window.
pub trait TransactionIdempotencyStore<T>: Send + Sync + 'static {
    type Error;

    fn claim(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &str,
        source_signature_anchor: &str,
    ) -> Result<TransactionClaim<T>, Self::Error>;

    fn record(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &str,
        source_signature_anchor: &str,
        outcome: &T,
    ) -> Result<(), Self::Error>;

    fn release(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &str,
        source_signature_anchor: &str,
    ) -> Result<(), Self::Error>;
}

/// Decision returned by [`IdempotencyWindow::claim`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyClaim<T> {
    /// First delivery of this identity within the window. The placeholder
    /// record is already persisted; the caller MUST process the request and
    /// then call [`IdempotencyWindow::complete`] (or
    /// [`IdempotencyWindow::release`] on failure).
    Fresh,
    /// The same identity + body digest + anchor is currently being
    /// processed by another caller. The caller MUST NOT execute side
    /// effects; answer with a retryable signal.
    InFlight { first_seen: Instant },
    /// Exact duplicate of a completed delivery (identity, body digest and
    /// anchor all match). The caller MUST return the cached outcome and MUST
    /// NOT re-execute side effects (`applet-integration.md` §7.3).
    Duplicate { outcome: T, first_seen: Instant },
    /// Same identity but a different canonical body digest or a different
    /// `source_signature_anchor`. The caller MUST fail closed with
    /// `duplicate_conflict` (`applet-integration.md` §7.3).
    DuplicateConflict { first_seen: Instant },
}

#[derive(Clone, Debug)]
enum EntryState<T> {
    InFlight,
    Completed(T),
}

#[derive(Clone, Debug)]
struct IdempotencyEntry<T> {
    body_digest: Hash,
    source_signature_anchor: String,
    first_seen: Instant,
    state: EntryState<T>,
}

/// Bounded-time sliding window that dedupes inbound Applet transaction
/// deliveries. `T` is the cached outcome replayed to exact duplicates.
#[derive(Debug)]
pub struct IdempotencyWindow<T> {
    window: Duration,
    inner: Mutex<HashMap<IdempotencyIdentity, IdempotencyEntry<T>>>,
}

impl<T: Clone> IdempotencyWindow<T> {
    /// Construct a window with the given retention duration. Per spec
    /// (`api-conventions.md` §6.1) receivers MUST retain idempotency
    /// records for at least 24 hours from record creation, and the
    /// window MUST be no shorter than the signature replay window plus
    /// the maximum allowed clock skew.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Atomically look up the identity and, when unseen (or aged out),
    /// persist an in-flight placeholder — all under a single lock, so the
    /// record exists before the caller runs any external side effect and no
    /// two concurrent claims of the same identity can both be `Fresh`.
    ///
    /// Aged-out entries are overwritten by the new claim (never a no-op), so
    /// a key that idles past the window becomes dedupable again immediately.
    pub fn claim(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &Hash,
        source_signature_anchor: &str,
    ) -> IdempotencyClaim<T> {
        let now = Instant::now();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = inner.get(identity)
            && now.saturating_duration_since(entry.first_seen) <= self.window
        {
            if &entry.body_digest != body_digest
                || entry.source_signature_anchor != source_signature_anchor
            {
                return IdempotencyClaim::DuplicateConflict {
                    first_seen: entry.first_seen,
                };
            }
            return match &entry.state {
                EntryState::InFlight => IdempotencyClaim::InFlight {
                    first_seen: entry.first_seen,
                },
                EntryState::Completed(outcome) => IdempotencyClaim::Duplicate {
                    outcome: outcome.clone(),
                    first_seen: entry.first_seen,
                },
            };
        }
        // Unseen or aged out: (re)claim by overwriting the slot.
        inner.insert(
            identity.clone(),
            IdempotencyEntry {
                body_digest: body_digest.clone(),
                source_signature_anchor: source_signature_anchor.to_owned(),
                first_seen: now,
                state: EntryState::InFlight,
            },
        );
        IdempotencyClaim::Fresh
    }

    /// Settle an in-flight claim with the outcome future exact duplicates
    /// will be answered with. Returns `false` (no-op) when the claim is
    /// missing or already completed.
    pub fn complete(&self, identity: &IdempotencyIdentity, outcome: T) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.get_mut(identity) {
            Some(entry) if matches!(entry.state, EntryState::InFlight) => {
                entry.state = EntryState::Completed(outcome);
                true
            }
            _ => false,
        }
    }

    /// Drop an in-flight claim after a processing failure so the peer can
    /// retry the delivery. Completed records are never released — a settled
    /// outcome stays replayable for the rest of the window. Returns whether
    /// an in-flight claim was released.
    pub fn release(&self, identity: &IdempotencyIdentity) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.get(identity) {
            Some(entry) if matches!(entry.state, EntryState::InFlight) => {
                inner.remove(identity);
                true
            }
            _ => false,
        }
    }

    /// Drop entries older than `window`. Cheap to call from a background
    /// timer; claims already overwrite aged-out entries, so this only bounds
    /// memory.
    pub fn gc(&self) {
        let now = Instant::now();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.retain(|_, entry| now.saturating_duration_since(entry.first_seen) <= self.window);
    }

    /// Current entry count. Test-only helper.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the window has zero recorded entries. Test-only helper;
    /// paired with [`Self::len`] to satisfy `clippy::len_without_is_empty`.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

impl<T: Clone + Send + 'static> TransactionIdempotencyStore<T> for IdempotencyWindow<T> {
    type Error = Error;

    fn claim(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &str,
        source_signature_anchor: &str,
    ) -> Result<TransactionClaim<T>, Self::Error> {
        let body_digest = Hash::new(body_digest)?;
        Ok(
            match self.claim(identity, &body_digest, source_signature_anchor) {
                IdempotencyClaim::Fresh => TransactionClaim::Claimed,
                IdempotencyClaim::InFlight { .. } => TransactionClaim::Pending,
                IdempotencyClaim::Duplicate { outcome, .. } => TransactionClaim::Duplicate(outcome),
                IdempotencyClaim::DuplicateConflict { .. } => TransactionClaim::Conflict,
            },
        )
    }

    fn record(
        &self,
        identity: &IdempotencyIdentity,
        _body_digest: &str,
        _source_signature_anchor: &str,
        outcome: &T,
    ) -> Result<(), Self::Error> {
        self.complete(identity, outcome.clone());
        Ok(())
    }

    fn release(
        &self,
        identity: &IdempotencyIdentity,
        _body_digest: &str,
        _source_signature_anchor: &str,
    ) -> Result<(), Self::Error> {
        self.release(identity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::canonical;

    use super::*;

    fn hash_of(bytes: &[u8]) -> Hash {
        Hash::new(canonical::sha256_digest(bytes)).unwrap()
    }

    fn identity(key: &str) -> IdempotencyIdentity {
        IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            "did:webvh:QmSrc:source.example",
            "did:webvh:QmDst:applet.example",
            key,
        )
    }

    fn window() -> IdempotencyWindow<u32> {
        IdempotencyWindow::new(Duration::from_secs(5 * 60))
    }

    #[test]
    fn claim_is_fresh_for_unseen_identity_and_persists_placeholder() {
        let win = window();
        let body = hash_of(b"hello");
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        // The placeholder is persisted before any side effect runs: a second
        // concurrent claim observes InFlight, never Fresh.
        assert!(matches!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::InFlight { .. }
        ));
    }

    #[test]
    fn completed_claim_replays_outcome_to_exact_duplicates() {
        let win = window();
        let body = hash_of(b"hello");
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        assert!(win.complete(&identity("key-1"), 7));
        match win.claim(&identity("key-1"), &body, "anchor-a") {
            IdempotencyClaim::Duplicate { outcome, .. } => assert_eq!(outcome, 7),
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_body_digest_or_anchor_is_duplicate_conflict() {
        let win = window();
        let body_a = hash_of(b"hello");
        let body_b = hash_of(b"world");
        assert_eq!(
            win.claim(&identity("key-1"), &body_a, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        win.complete(&identity("key-1"), 7);
        // Different canonical body digest.
        assert!(matches!(
            win.claim(&identity("key-1"), &body_b, "anchor-a"),
            IdempotencyClaim::DuplicateConflict { .. }
        ));
        // Same body, different source_signature_anchor (e.g. rotated key).
        assert!(matches!(
            win.claim(&identity("key-1"), &body_a, "anchor-b"),
            IdempotencyClaim::DuplicateConflict { .. }
        ));
        // Conflicts also apply to in-flight (not yet completed) claims.
        assert_eq!(
            win.claim(&identity("key-2"), &body_a, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        assert!(matches!(
            win.claim(&identity("key-2"), &body_b, "anchor-a"),
            IdempotencyClaim::DuplicateConflict { .. }
        ));
    }

    #[test]
    fn identity_components_are_all_significant() {
        let win = window();
        let body = hash_of(b"hello");
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        // Same key but a different destination service DID is a distinct
        // identity, not a duplicate.
        let other_destination = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            "did:webvh:QmSrc:source.example",
            "did:webvh:QmOther:applet.example",
            "key-1",
        );
        assert_eq!(
            win.claim(&other_destination, &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        // Same key but the opposite direction is also distinct.
        let other_direction = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::AppletToArkretInbound,
            "did:webvh:QmSrc:source.example",
            "did:webvh:QmDst:applet.example",
            "key-1",
        );
        assert_eq!(
            win.claim(&other_direction, &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
    }

    #[test]
    fn aged_out_entry_is_overwritten_and_dedupes_again() {
        let win: IdempotencyWindow<u32> = IdempotencyWindow::new(Duration::from_millis(1));
        let body = hash_of(b"hello");
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        win.complete(&identity("key-1"), 7);
        std::thread::sleep(Duration::from_millis(10));
        // Aged out: the claim overwrites the stale entry (never a no-op)...
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        win.complete(&identity("key-1"), 8);
        // ...so the very next duplicate is served from the NEW record.
        match win.claim(&identity("key-1"), &body, "anchor-a") {
            IdempotencyClaim::Duplicate { outcome, .. } => assert_eq!(outcome, 8),
            other => panic!("expected Duplicate with refreshed outcome, got {other:?}"),
        }
    }

    #[test]
    fn release_drops_in_flight_claim_but_never_completed_records() {
        let win = window();
        let body = hash_of(b"hello");
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        assert!(win.release(&identity("key-1")));
        // Released: the retry claims fresh again.
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        win.complete(&identity("key-1"), 7);
        // Completed records are not releasable.
        assert!(!win.release(&identity("key-1")));
        assert!(matches!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Duplicate { .. }
        ));
    }

    #[test]
    fn complete_is_a_noop_without_an_in_flight_claim() {
        let win = window();
        let body = hash_of(b"hello");
        assert!(!win.complete(&identity("key-1"), 7));
        assert_eq!(
            win.claim(&identity("key-1"), &body, "anchor-a"),
            IdempotencyClaim::Fresh
        );
        assert!(win.complete(&identity("key-1"), 7));
        // Double-complete does not overwrite the settled outcome.
        assert!(!win.complete(&identity("key-1"), 9));
        match win.claim(&identity("key-1"), &body, "anchor-a") {
            IdempotencyClaim::Duplicate { outcome, .. } => assert_eq!(outcome, 7),
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn gc_drops_aged_out_entries() {
        let win: IdempotencyWindow<u32> = IdempotencyWindow::new(Duration::from_millis(1));
        let body = hash_of(b"hello");
        win.claim(&identity("key-1"), &body, "anchor-a");
        std::thread::sleep(Duration::from_millis(10));
        win.gc();
        assert!(win.is_empty());
        assert_eq!(win.len(), 0);
    }

    #[test]
    fn concurrent_claims_of_same_identity_yield_exactly_one_fresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let win = Arc::new(window());
        let body = hash_of(b"hello");
        let fresh = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let win = Arc::clone(&win);
            let body = body.clone();
            let fresh = Arc::clone(&fresh);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                match win.claim(&identity("key-1"), &body, "anchor-a") {
                    IdempotencyClaim::Fresh => {
                        fresh.fetch_add(1, Ordering::SeqCst);
                    }
                    IdempotencyClaim::InFlight { .. } | IdempotencyClaim::Duplicate { .. } => {}
                    IdempotencyClaim::DuplicateConflict { .. } => {
                        panic!("matching body/anchor must never conflict")
                    }
                }
            }));
        }
        for join in joins {
            join.join().unwrap();
        }
        // The claim is atomic (lookup + placeholder under one lock): exactly
        // one thread wins the right to execute side effects.
        assert_eq!(fresh.load(Ordering::SeqCst), 1);
    }
}
