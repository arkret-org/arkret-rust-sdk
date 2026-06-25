mod basics;
mod composite_and_caching;
mod did_web;
mod did_webvh;
mod policy;

pub use basics::*;
pub use composite_and_caching::*;
pub use did_web::*;
pub use did_webvh::*;
pub use policy::*;

// ============================================================================
// Cache freshness tests.
// ============================================================================
#[cfg(test)]
mod caching_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;

    use super::*;
    use crate::identity::Freshness;
    use crate::identity::helpers::did_key_material;
    use crate::{Did, DidDocument, DidResolver, Error, Result};

    /// Controllable resolver stub that tracks upstream calls and can be
    /// switched into a forced-failure mode.
    #[derive(Debug)]
    struct StubResolver {
        calls: AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    impl StubResolver {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            did.method() == "key"
        }

        fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::Protocol("stub resolver forced failure".to_owned()));
            }
            let key = did_key_material(did)
                .ok_or_else(|| Error::Protocol("stub: unsupported did:key".to_owned()))?;
            Ok(DidDocument::new(
                did.clone(),
                format!("{}#{key}", did.as_str()),
                key,
            ))
        }
    }

    fn sample_did(suffix: &str) -> Did {
        // Valid did:key Ed25519 multibase fixtures.
        let base = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        Did::new(format!("{base}{suffix}")).unwrap_or_else(|_| Did::new(base.to_owned()).unwrap())
    }

    fn policy(ttl: Option<chrono::Duration>, fail_mode: ResolverFailMode) -> ResolverPolicy {
        ResolverPolicy {
            allowed_methods: Vec::new(),
            default_principal_method: None,
            trust_roots: Vec::new(),
            ttl,
            fail_mode,
        }
    }

    #[test]
    fn cache_hit_avoids_second_upstream_call() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::FailClosed,
            ),
            128,
        );
        let did = sample_did("");

        let now = Utc::now();
        let (_doc, f1) = resolver
            .resolve_with_freshness(&did, now)
            .expect("first resolve");
        assert_eq!(f1, Freshness::Missing, "first resolve uses upstream");
        assert_eq!(resolver.inner().calls(), 1);

        // A second resolve inside the same TTL window hits the cache.
        let (_doc, f2) = resolver
            .resolve_with_freshness(&did, now + chrono::Duration::minutes(1))
            .expect("second resolve");
        assert_eq!(f2, Freshness::Fresh, "fresh cache hit");
        assert_eq!(resolver.inner().calls(), 1, "upstream called once");

        // The document hash was computed and stored with its prefix.
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn ttl_expiry_triggers_miss() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::FailClosed,
            ),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        resolver.resolve_with_freshness(&did, now).expect("first");
        assert_eq!(resolver.inner().calls(), 1);

        // After TTL expiry, the next resolve misses and returns upstream data.
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) = resolver
            .resolve_with_freshness(&did, later)
            .expect("after expiry");
        assert_eq!(f, Freshness::Missing, "expired entry resolves upstream");
        assert_eq!(resolver.inner().calls(), 2);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let stub = StubResolver::new();
        // Capacity 2: inserting three DIDs evicts the oldest entry.
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::FailClosed,
            ),
            2,
        );

        let base = Utc::now();
        let d1 = sample_did("");
        // Use distinct did:key identifiers to separate cache entries.
        let d2 = Did::new("did:key:z6MkfGFvHcKHd9YEK5sBYqLqHs5GpD3xKCJQyZK7r2pHpkpf".to_owned())
            .expect("valid did:key");
        let d3 = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned())
            .expect("valid did:key");

        resolver.resolve_with_freshness(&d1, base).expect("d1");
        resolver
            .resolve_with_freshness(&d2, base + chrono::Duration::seconds(1))
            .expect("d2");
        assert_eq!(resolver.len(), 2);

        // Inserting the third entry evicts d1 because it has the oldest cached_at.
        resolver
            .resolve_with_freshness(&d3, base + chrono::Duration::seconds(2))
            .expect("d3");
        assert_eq!(resolver.len(), 2, "capacity remains capped at 2");

        // d1 now misses and resolves upstream again; d2/d3 remain cached.
        let calls_before = resolver.inner().calls();
        let (_doc, f1) = resolver
            .resolve_with_freshness(&d1, base + chrono::Duration::seconds(3))
            .expect("d1 re-resolve");
        assert_eq!(f1, Freshness::Missing, "oldest entry was evicted");
        assert_eq!(resolver.inner().calls(), calls_before + 1);

        let (_doc, f2) = resolver
            .resolve_with_freshness(&d3, base + chrono::Duration::seconds(3))
            .expect("d3 still cached");
        assert_eq!(f2, Freshness::Fresh, "d3 remains cached");
    }

    #[test]
    fn max_entries_zero_disables_cache() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::FailClosed,
            ),
            0,
        );
        let did = sample_did("");
        let now = Utc::now();

        resolver.resolve_with_freshness(&did, now).expect("first");
        resolver.resolve_with_freshness(&did, now).expect("second");
        // Disabled cache: every resolve uses upstream and no entry is retained.
        assert_eq!(resolver.len(), 0, "disabled cache stores no entries");
        assert_eq!(resolver.inner().calls(), 2, "each resolve calls upstream");
    }

    #[test]
    fn fail_closed_propagates_error() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::FailClosed,
            ),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        // Warm the cache with one successful lookup.
        resolver
            .resolve_with_freshness(&did, now)
            .expect("warm cache");
        // Force failure and cross the TTL boundary to trigger upstream resolution.
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let result = resolver.resolve_with_freshness(&did, later);
        assert!(result.is_err(), "FailClosed must propagate upstream errors");
    }

    #[test]
    fn allow_cached_on_error_returns_stale() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(
                Some(chrono::Duration::minutes(15)),
                ResolverFailMode::AllowCachedOnError,
            ),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        // Warm the cache with one successful lookup.
        resolver
            .resolve_with_freshness(&did, now)
            .expect("warm cache");
        // Force failure after the TTL boundary.
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) = resolver
            .resolve_with_freshness(&did, later)
            .expect("stale fallback succeeds");
        match f {
            Freshness::Stale { age } => {
                // The age should be positive and roughly one minute.
                assert!(
                    age >= chrono::Duration::seconds(30),
                    "stale age should be positive and plausible"
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }
}
