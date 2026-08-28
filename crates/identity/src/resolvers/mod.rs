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
    use arkret_wire::Did;
    use chrono::Utc;

    use super::*;
    use crate::DidResolver;

    fn sample_did(suffix: &str) -> Did {
        // Valid did:key Ed25519 multibase fixtures.
        let base = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        Did::new(format!("{base}{suffix}")).unwrap_or_else(|_| Did::new(base.to_owned()).unwrap())
    }

    #[test]
    fn reusable_cache_exposes_snapshot_health_and_invalidation() {
        let cache = DidResolutionCache::new(2);
        let did = sample_did("");
        let now = Utc::now();
        let document = DidKeyResolver::new()
            .resolve_did(&did)
            .expect("resolve fixture");

        cache
            .insert(did.clone(), document, now, chrono::Duration::minutes(15))
            .expect("cache fixture");

        assert_eq!(
            cache.health(now + chrono::Duration::minutes(1)),
            DidResolutionCacheHealth {
                entries: 1,
                fresh_entries: 1,
                stale_entries: 0,
            }
        );
        assert!(cache.has_fresh_entry(now));
        assert!(!cache.has_only_stale_entries(now));

        let snapshot = cache.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].did, did.as_str());
        assert!(
            snapshot[0].resolution.document_hash.starts_with("sha256:"),
            "snapshot retains the canonical document digest"
        );

        let after_expiry = now + chrono::Duration::minutes(16);
        assert_eq!(
            cache.health(after_expiry),
            DidResolutionCacheHealth {
                entries: 1,
                fresh_entries: 0,
                stale_entries: 1,
            }
        );
        assert!(cache.has_only_stale_entries(after_expiry));
        assert!(matches!(
            cache
                .peek(&did)
                .expect("stale entry remains observable")
                .freshness_at(after_expiry),
            Freshness::Stale { .. }
        ));

        cache.invalidate(&did);
        assert!(cache.is_empty());

        let document = DidKeyResolver::new()
            .resolve_did(&did)
            .expect("resolve fixture");
        cache
            .insert(did, document, now, chrono::Duration::minutes(15))
            .expect("cache fixture");
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn did_key_resolution_is_deterministic_and_has_no_synthetic_update_time() {
        let did = sample_did("");
        let first = DidKeyResolver::new()
            .resolve_did(&did)
            .expect("first resolution");
        let second = DidKeyResolver::new()
            .resolve_did(&did)
            .expect("second resolution");

        assert_eq!(first.document, second.document);
        assert!(first.document.updated_at.is_none());
        let verification_method = format!(
            "{}#{}",
            did.as_str(),
            did.as_str().strip_prefix("did:key:").unwrap()
        );
        assert_eq!(
            first.document.raw_properties.get("assertionMethod"),
            Some(&serde_json::json!([verification_method]))
        );
    }
}
