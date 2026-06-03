//! S-5 (savfox SDK gap, 2026-05-27) — `(source_service_did,
//! Idempotency-Key)` deduplication window.
//!
//! Spec `applet-integration.md` §7.3: when an Applet receives the same
//! `Idempotency-Key` from the same `source_service_did` within the
//! window, the receiver MUST return the cached `accepted` response when
//! the canonical body hash matches, or `duplicate_conflict` when the
//! body hash differs.
//!
//! This module owns the bookkeeping (insertion, lookup, body-hash
//! comparison, GC) so every Applet implementation no longer rolls its
//! own `HashMap<(String, String), Instant>` with subtly different
//! semantics.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use cokret_core::Hash;

/// Decision returned by [`IdempotencyWindow::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyDecision {
    /// First time the `(source_service_did, idempotency_key)` tuple
    /// has been seen within the window. Caller SHOULD process the
    /// request, then call [`IdempotencyWindow::record`] with the
    /// canonical body hash.
    Fresh,
    /// Same key + matching canonical body hash. Caller MUST return the
    /// cached `accepted` response (re-execution is forbidden by spec).
    Duplicate { first_seen: Instant },
    /// Same key but **different** body hash. Caller MUST return
    /// `duplicate_conflict` per `applet-integration.md` §7.3.
    Conflict { first_seen: Instant },
}

#[derive(Clone, Debug)]
struct IdempotencyEntry {
    body_hash: Hash,
    first_seen: Instant,
}

/// Bounded-time sliding window that dedupes inbound Applet writes.
#[derive(Debug)]
pub struct IdempotencyWindow {
    window: Duration,
    inner: Mutex<HashMap<(String, String), IdempotencyEntry>>,
}

impl IdempotencyWindow {
    /// Construct a window with the given retention duration. Spec
    /// recommends 5 minutes (`Duration::from_secs(5 * 60)`).
    pub fn new(window: Duration) -> Self {
        Self { window, inner: Mutex::new(HashMap::new()) }
    }

    /// Inspect the window for an existing entry. Does not mutate;
    /// callers stamp the window via [`Self::record`].
    pub fn check(
        &self,
        source_service_did: &str,
        idempotency_key: &str,
        body_canonical_hash: &Hash,
    ) -> IdempotencyDecision {
        let key = (source_service_did.to_owned(), idempotency_key.to_owned());
        let now = Instant::now();
        let inner = self.inner.lock().expect("idempotency window poisoned");
        match inner.get(&key) {
            None => IdempotencyDecision::Fresh,
            Some(entry) if now.saturating_duration_since(entry.first_seen) > self.window => {
                // Entry aged out — treat as fresh (caller MUST re-record).
                IdempotencyDecision::Fresh
            }
            Some(entry) if &entry.body_hash == body_canonical_hash => {
                IdempotencyDecision::Duplicate { first_seen: entry.first_seen }
            }
            Some(entry) => IdempotencyDecision::Conflict { first_seen: entry.first_seen },
        }
    }

    /// Stamp the window with `(source_service_did, idempotency_key) →
    /// body_canonical_hash`. Idempotent: calling twice with the same
    /// hash keeps the original `first_seen`.
    pub fn record(
        &self,
        source_service_did: &str,
        idempotency_key: &str,
        body_canonical_hash: Hash,
    ) {
        let key = (source_service_did.to_owned(), idempotency_key.to_owned());
        let mut inner = self.inner.lock().expect("idempotency window poisoned");
        inner.entry(key).or_insert(IdempotencyEntry {
            body_hash: body_canonical_hash,
            first_seen: Instant::now(),
        });
    }

    /// Drop entries older than `window`. Cheap to call from a
    /// background timer; safe to skip in test scenarios.
    pub fn gc(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("idempotency window poisoned");
        inner.retain(|_, entry| now.saturating_duration_since(entry.first_seen) <= self.window);
    }

    /// Current entry count. Test-only helper.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("idempotency window poisoned").len()
    }

    /// Whether the window has zero recorded entries. Test-only
    /// helper; paired with [`Self::len`] to satisfy
    /// `clippy::len_without_is_empty`.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("idempotency window poisoned").is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cokret_core::canonical;

    fn hash_of(bytes: &[u8]) -> Hash {
        Hash::new(canonical::sha256_digest(bytes)).unwrap()
    }

    fn alice_svc() -> &'static str {
        "did:web:savfox.example"
    }

    #[test]
    fn check_returns_fresh_for_unseen_key() {
        let win = IdempotencyWindow::new(Duration::from_secs(5 * 60));
        let body = hash_of(b"hello");
        assert_eq!(win.check(alice_svc(), "key-1", &body), IdempotencyDecision::Fresh);
    }

    #[test]
    fn check_returns_duplicate_for_matching_body_hash() {
        let win = IdempotencyWindow::new(Duration::from_secs(5 * 60));
        let body = hash_of(b"hello");
        win.record(alice_svc(), "key-1", body.clone());
        let decision = win.check(alice_svc(), "key-1", &body);
        assert!(
            matches!(decision, IdempotencyDecision::Duplicate { .. }),
            "expected Duplicate, got {decision:?}"
        );
    }

    #[test]
    fn check_returns_conflict_for_mismatched_body_hash() {
        let win = IdempotencyWindow::new(Duration::from_secs(5 * 60));
        let body_a = hash_of(b"hello");
        let body_b = hash_of(b"world");
        win.record(alice_svc(), "key-1", body_a);
        let decision = win.check(alice_svc(), "key-1", &body_b);
        assert!(
            matches!(decision, IdempotencyDecision::Conflict { .. }),
            "expected Conflict, got {decision:?}"
        );
    }

    #[test]
    fn gc_drops_aged_out_entries() {
        let win = IdempotencyWindow::new(Duration::from_millis(1));
        let body = hash_of(b"hello");
        win.record(alice_svc(), "key-1", body.clone());
        // Wait past the window. Using std sleep is fine here — the
        // budget is 5ms in practice.
        std::thread::sleep(Duration::from_millis(10));
        win.gc();
        assert_eq!(win.len(), 0);
        // After GC the key reads as Fresh again.
        assert_eq!(win.check(alice_svc(), "key-1", &body), IdempotencyDecision::Fresh);
    }

    #[test]
    fn check_treats_stale_entry_as_fresh_without_explicit_gc() {
        let win = IdempotencyWindow::new(Duration::from_millis(1));
        let body = hash_of(b"hello");
        win.record(alice_svc(), "key-1", body.clone());
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(win.check(alice_svc(), "key-1", &body), IdempotencyDecision::Fresh);
    }
}
