use crate::identity::helpers::*;
use crate::identity::*;

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
// 缓存 / 新鲜度单测(S3)
// ============================================================================
#[cfg(test)]
mod caching_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// 可控桩 resolver:记录 `resolve_did` 调用次数,并可被切换为「失败」。
    /// 每次解析成功时返回携带递增计数的文档,便于断言「是否真的走了上游」。
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
        // 一组合法的 did:key Ed25519 multibase 标识。
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
        assert_eq!(f1, Freshness::Missing, "首次解析来自上游");
        assert_eq!(resolver.inner().calls(), 1);

        // 同一 TTL 窗口内再次解析:命中缓存,不再调用上游。
        let (_doc, f2) = resolver
            .resolve_with_freshness(&did, now + chrono::Duration::minutes(1))
            .expect("second resolve");
        assert_eq!(f2, Freshness::Fresh, "命中且新鲜");
        assert_eq!(resolver.inner().calls(), 1, "上游只被调用一次");

        // document_hash 已计算且带前缀。
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

        // 超过 TTL 后再解析:过期 → miss → 重新走上游。
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) = resolver
            .resolve_with_freshness(&did, later)
            .expect("after expiry");
        assert_eq!(f, Freshness::Missing, "过期后重新取自上游");
        assert_eq!(resolver.inner().calls(), 2);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let stub = StubResolver::new();
        // 容量 2:写入三个不同 DID 后,最旧的应被逐出。
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
        // 通过不同的 did:key 标识区分条目。
        let d2 = Did::new("did:key:z6MkfGFvHcKHd9YEK5sBYqLqHs5GpD3xKCJQyZK7r2pHpkpf".to_owned())
            .expect("valid did:key");
        let d3 = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned())
            .expect("valid did:key");

        resolver.resolve_with_freshness(&d1, base).expect("d1");
        resolver
            .resolve_with_freshness(&d2, base + chrono::Duration::seconds(1))
            .expect("d2");
        assert_eq!(resolver.len(), 2);

        // 写入第三个,最旧的 d1(cached_at 最早)应被逐出。
        resolver
            .resolve_with_freshness(&d3, base + chrono::Duration::seconds(2))
            .expect("d3");
        assert_eq!(resolver.len(), 2, "容量上限保持为 2");

        // d1 现在 miss(会再次走上游),d2/d3 仍命中。
        let calls_before = resolver.inner().calls();
        let (_doc, f1) = resolver
            .resolve_with_freshness(&d1, base + chrono::Duration::seconds(3))
            .expect("d1 re-resolve");
        assert_eq!(f1, Freshness::Missing, "最旧条目已被逐出");
        assert_eq!(resolver.inner().calls(), calls_before + 1);

        let (_doc, f2) = resolver
            .resolve_with_freshness(&d3, base + chrono::Duration::seconds(3))
            .expect("d3 still cached");
        assert_eq!(f2, Freshness::Fresh, "d3 仍在缓存中");
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
        // 缓存关闭:每次都走上游,且永远不留存条目。
        assert_eq!(resolver.len(), 0, "缓存关闭,无任何条目");
        assert_eq!(resolver.inner().calls(), 2, "每次都调用上游");
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

        // 先成功填充一条缓存。
        resolver
            .resolve_with_freshness(&did, now)
            .expect("warm cache");
        // 切换为失败,并越过 TTL 触发上游调用。
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let result = resolver.resolve_with_freshness(&did, later);
        assert!(result.is_err(), "FailClosed 模式下底层错误必须上抛");
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

        // 先成功填充缓存。
        resolver
            .resolve_with_freshness(&did, now)
            .expect("warm cache");
        // 切换为失败,越过 TTL。
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) = resolver
            .resolve_with_freshness(&did, later)
            .expect("stale fallback succeeds");
        match f {
            Freshness::Stale { age } => {
                // age 约为超过 expires_at 的 1 分钟(16 - 15)。
                assert!(
                    age >= chrono::Duration::seconds(30),
                    "返回的过期时长应为正且合理"
                );
            }
            other => panic!("期望 Stale,实际为 {other:?}"),
        }
    }
}
