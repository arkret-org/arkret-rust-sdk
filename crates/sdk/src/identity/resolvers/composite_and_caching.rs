use std::collections::HashMap;

use super::basics::*;
use super::policy::*;
use crate::identity::helpers::*;
use crate::identity::*;

/// Limited `did:keri` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidKeriResolver {
    documents: BTreeMap<Did, DidDocument>,
}

impl DidKeriResolver {
    /// Create an empty `did:keri` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:keri` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "keri" {
            return Err(Error::Protocol(
                "did:keri resolver only accepts did:keri".to_owned(),
            ));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidKeriResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "keri"
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol(
                "unsupported DID method for did:keri resolver".to_owned(),
            ));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:keri document not found".to_owned()))
    }
}

/// Resolver for `did:key` identifiers with base58btc multicodec validation.
#[derive(Clone, Debug, Default)]
pub struct DidKeyResolver;

impl DidKeyResolver {
    /// Create a `did:key` resolver.
    pub fn new() -> Self {
        Self
    }
}

impl DidResolver for DidKeyResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "key" && did_key_material(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        let key = did_key_material(did)
            .ok_or_else(|| Error::Protocol("unsupported did:key form".to_owned()))?;
        Ok(DidDocument::new(
            did.clone(),
            format!("{}#{key}", did.as_str()),
            key,
        ))
    }
}

/// Resolver that tries registered adapters in order.
#[derive(Default)]
pub struct CompositeDidResolver {
    resolvers: Vec<Box<dyn DidResolver + Send + Sync>>,
    policy: ResolverPolicy,
}

impl CompositeDidResolver {
    /// Create an empty resolver chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the active [`ResolverPolicy`].
    pub fn with_policy(mut self, policy: ResolverPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Read the active policy.
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// Append a resolver adapter.
    pub fn push<R>(&mut self, resolver: R)
    where
        R: DidResolver + Send + Sync + 'static,
    {
        self.resolvers.push(Box::new(resolver));
    }
}

impl std::fmt::Debug for CompositeDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeDidResolver")
            .field("resolver_count", &self.resolvers.len())
            .field("policy", &self.policy)
            .finish()
    }
}

impl DidResolver for CompositeDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.policy.permits(did) && self.resolvers.iter().any(|resolver| resolver.supports(did))
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        self.policy.validate(did)?;
        self.resolvers
            .iter()
            .find(|resolver| resolver.supports(did))
            .ok_or_else(|| Error::Protocol("unsupported DID method".to_owned()))?
            .resolve_did(did)
    }
}

// ============================================================================
// DID 解析缓存与新鲜度类型(S1 / S2)
//
// `CompositeDidResolver` 上的 `ResolverPolicy.ttl` 此前仅是元数据——
// resolver 不缓存,每次 `resolve_did` 都重走 resolver 链。下面的类型在
// 不改动任何现有 public API 的前提下,以纯粹的「加法」补上缓存层:
//
// - `Freshness` 描述一次取值相对 TTL 的新鲜程度(新鲜 / 过期 / 缺失)。
// - `CachedResolution` 是单条缓存记录,携带文档、缓存/过期时间戳、文档 规范哈希,以及可选的 webvh
//   日志头与版本号。
// - `CachingDidResolver<R>` 包装任意 `R: DidResolver`,内部以 `Mutex<CacheState>` 保存条目并执行 LRU
//   + TTL 逐出。
// ============================================================================

/// 一次缓存取值相对其 TTL 的新鲜程度。
///
/// - `Fresh`:命中且仍在 TTL 窗口内。
/// - `Stale { age }`:命中但已过期(`age` 是相对 `expires_at` 超出的时长); 仅在
///   `ResolverFailMode::AllowCachedOnError` 且底层 resolver 出错时返回。
/// - `Missing`:缓存里没有这个 DID(或缓存被关闭),需要走底层 resolver。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// 命中且未过期。
    Fresh,
    /// 命中但已过期;`age` 为超过 `expires_at` 的时长。
    Stale { age: chrono::Duration },
    /// 缓存里没有该条目。
    Missing,
}

/// 单条 DID 解析缓存记录。
///
/// `document_hash` 用现有 canonical 工具([`cokret_core::canonical`])对
/// 文档做规范化后取 SHA-256(带 `sha256:` 前缀),便于上层做去重 / 变更
/// 检测。`log_head` 与 `version` 是可选的 `did:webvh` 元数据,缓存层本身
/// 不依赖它们,只作透传携带。
#[derive(Clone, Debug)]
pub struct CachedResolution {
    /// 缓存的 DID 文档。
    pub document: DidDocument,
    /// 写入缓存的时刻。
    pub cached_at: DateTime<Utc>,
    /// 过期时刻(`cached_at + ttl`)。
    pub expires_at: DateTime<Utc>,
    /// 文档的规范化 SHA-256 摘要(带 `sha256:` 前缀)。
    pub document_hash: String,
    /// 可选:`did:webvh` 日志头(最新 `versionId`)。
    pub log_head: Option<String>,
    /// 可选:文档版本号。
    pub version: Option<String>,
}

impl CachedResolution {
    /// 用规范化哈希构造一条缓存记录。`log_head` / `version` 默认为 `None`,
    /// 可在构造后按需填充。
    fn new(
        document: DidDocument,
        cached_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let document_hash = document_canonical_hash(&document)?;
        Ok(Self {
            document,
            cached_at,
            expires_at,
            document_hash,
            log_head: None,
            version: None,
        })
    }

    /// 相对 `now` 计算这条记录的新鲜程度。
    fn freshness_at(&self, now: DateTime<Utc>) -> Freshness {
        if now < self.expires_at {
            Freshness::Fresh
        } else {
            Freshness::Stale {
                age: now - self.expires_at,
            }
        }
    }
}

/// 用现有 canonical 工具计算文档的规范化 SHA-256 摘要(带 `sha256:` 前缀)。
fn document_canonical_hash(document: &DidDocument) -> Result<String> {
    let bytes = cokret_core::canonical::canonical_json_bytes(document)
        .map_err(|e| Error::Protocol(format!("DID document canonicalization failed: {e}")))?;
    Ok(cokret_core::canonical::sha256_digest(bytes))
}

/// `CachingDidResolver` 的内部可变状态,由 `Mutex` 保护。
#[derive(Debug)]
struct CacheState {
    entries: HashMap<String, CachedResolution>,
    max_entries: usize,
}

impl CacheState {
    /// LRU 取值:命中且未过期返回克隆;过期则惰性删除并返回 `None`。
    /// 供 [`DidResolver::resolve_did`] 使用——那条路径不需要 stale 回退,
    /// 因此过期即删,保持 `len()` 诚实。
    fn get_fresh(&mut self, key: &str, now: DateTime<Utc>) -> Option<CachedResolution> {
        match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// 仅查看新鲜条目,**不删除**过期项——`resolve_with_freshness` 在
    /// `AllowCachedOnError` 下需要保留过期条目以备 stale 回退。
    fn peek_fresh(&self, key: &str, now: DateTime<Utc>) -> Option<CachedResolution> {
        match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.clone()),
            _ => None,
        }
    }

    /// 写入一条记录,超过容量时按 `cached_at` 逐出最旧(O(n) 扫描)。
    /// `max_entries == 0` 时不接纳任何条目(缓存关闭)。
    fn insert(&mut self, key: String, entry: CachedResolution) {
        if self.max_entries == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.cached_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&victim);
            }
        }
        self.entries.insert(key, entry);
    }
}

/// 给任意 [`DidResolver`] 加上 TTL + LRU 缓存的包装。
///
/// `resolve_did` 实现 [`DidResolver`]:先查缓存(命中且未过期直接返回),
/// miss / 过期才调底层 resolver 并回填。[`Self::resolve_with_freshness`]
/// 在此之上额外返回 [`Freshness`],并遵循 [`ResolverPolicy::fail_mode`]:
/// 仅 `AllowCachedOnError` 时在底层错误下回退到过期缓存。
///
/// 设计上保持对底层 resolver 的通用性(`R: DidResolver`),
/// [`ResolverPolicy`] 由单独字段持有——既可在构造时直接传入,也可从被
/// 包装的 [`CompositeDidResolver`] 复制其 policy。
pub struct CachingDidResolver<R: DidResolver> {
    inner: R,
    policy: ResolverPolicy,
    state: std::sync::Mutex<CacheState>,
}

impl<R: DidResolver> CachingDidResolver<R> {
    /// 用显式 policy 与容量构造缓存包装。`max_entries == 0` 关闭缓存。
    pub fn new(inner: R, policy: ResolverPolicy, max_entries: usize) -> Self {
        Self {
            inner,
            policy,
            state: std::sync::Mutex::new(CacheState {
                entries: HashMap::new(),
                max_entries,
            }),
        }
    }

    /// 读取生效的 policy。
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// 借用底层 resolver。
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// 当前缓存条目数(惰性逐出之外的即时计数)。
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 丢弃某个 DID 的缓存(例如收到吊销 / 轮换事件时)。
    pub fn invalidate(&self, did: &Did) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(did.as_str());
    }

    /// 清空全部缓存。
    pub fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .clear();
    }

    /// 依据 `policy.ttl` 计算 `expires_at`。`ttl == None` 表示禁用缓存,
    /// 此处用零时长(写入即过期),配合 `max_entries` 共同决定是否真正缓存。
    fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self.policy.ttl {
            Some(ttl) => now + ttl,
            None => now,
        }
    }

    /// 解析并返回文档及其 [`Freshness`]。
    ///
    /// 流程:
    /// 1. 命中且未过期 → 返回 `(doc, Fresh)`。
    /// 2. 否则调用底层 resolver:
    ///    - 成功 → 回填缓存,返回 `(doc, Missing)`(本次取自上游,非缓存)。
    ///    - 失败 → 若 `fail_mode == AllowCachedOnError` 且存在过期缓存, 返回 `(stale_doc, Stale {
    ///      age })`;否则向上抛错(fail-closed)。
    pub fn resolve_with_freshness(
        &self,
        did: &Did,
        now: DateTime<Utc>,
    ) -> Result<(DidDocument, Freshness)> {
        let key = did.as_str().to_owned();

        // 1. 命中且新鲜(此处用 peek,不删除过期项,以便步骤 2 的 stale 回退仍能读到过期条目)。
        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peek_fresh(&key, now)
        {
            return Ok((entry.document, Freshness::Fresh));
        }

        // 2. miss / 过期:走底层 resolver。
        match self.inner.resolve_did(did) {
            Ok(document) => {
                let expires_at = self.expires_at(now);
                let entry = CachedResolution::new(document.clone(), now, expires_at)?;
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(key, entry);
                Ok((document, Freshness::Missing))
            }
            Err(err) => {
                // 仅在 AllowCachedOnError 下回退到过期缓存。
                if self.policy.fail_mode == ResolverFailMode::AllowCachedOnError {
                    let stale = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .entries
                        .get(&key)
                        .cloned();
                    if let Some(entry) = stale {
                        let freshness = entry.freshness_at(now);
                        return Ok((entry.document, freshness));
                    }
                }
                Err(err)
            }
        }
    }
}

impl<R: DidResolver> DidResolver for CachingDidResolver<R> {
    fn supports(&self, did: &Did) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        let now = Utc::now();
        let key = did.as_str().to_owned();

        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_fresh(&key, now)
        {
            return Ok(entry.document);
        }

        let document = self.inner.resolve_did(did)?;
        let expires_at = self.expires_at(now);
        let entry = CachedResolution::new(document.clone(), now, expires_at)?;
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, entry);
        Ok(document)
    }
}

impl<R: DidResolver + std::fmt::Debug> std::fmt::Debug for CachingDidResolver<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry_count = self.state.lock().map(|s| s.entries.len()).unwrap_or(0);
        f.debug_struct("CachingDidResolver")
            .field("inner", &self.inner)
            .field("policy", &self.policy)
            .field("entries", &entry_count)
            .finish()
    }
}
