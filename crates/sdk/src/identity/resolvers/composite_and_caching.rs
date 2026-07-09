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
// DID resolution cache and freshness types.
// ============================================================================

/// Freshness of a cached DID resolution relative to its TTL.
///
/// - `Fresh`: cache hit inside the TTL window.
/// - `Stale { age }`: cache hit after expiry; returned only when
///   `ResolverFailMode::AllowCachedOnError` lets a failed upstream resolve fall back to expired
///   cache data.
/// - `Missing`: no usable cache entry exists, so the resolver must query upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Cache hit inside the TTL window.
    Fresh,
    /// Cache hit after expiry; `age` is the duration past `expires_at`.
    Stale { age: chrono::Duration },
    /// No usable cache entry exists.
    Missing,
}

/// Single cached DID resolution.
///
/// `document_hash` is the canonical JSON SHA-256 digest with the `sha256:`
/// prefix. `log_head` and `version` carry optional `did:webvh` metadata without
/// affecting cache behaviour.
#[derive(Clone, Debug)]
pub struct CachedResolution {
    /// Cached DID document.
    pub document: DidDocument,
    /// Time when the entry was stored.
    pub cached_at: DateTime<Utc>,
    /// Expiry time (`cached_at + ttl`).
    pub expires_at: DateTime<Utc>,
    /// Canonical SHA-256 digest of the document, including the `sha256:` prefix.
    pub document_hash: String,
    /// Optional `did:webvh` log head (latest `versionId`).
    pub log_head: Option<String>,
    /// Optional document version.
    pub version: Option<String>,
}

impl CachedResolution {
    /// Build a cache entry and compute its canonical document hash.
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

    /// Return this entry's freshness relative to `now`.
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

/// Compute the document's canonical SHA-256 digest with the `sha256:` prefix.
fn document_canonical_hash(document: &DidDocument) -> Result<String> {
    let bytes = arkret_core::canonical::canonical_json_bytes(document)
        .map_err(|e| Error::Protocol(format!("DID document canonicalization failed: {e}")))?;
    Ok(arkret_core::canonical::sha256_digest(bytes))
}

/// Mutable state for `CachingDidResolver`, protected by a `Mutex`.
#[derive(Debug)]
struct CacheState {
    entries: HashMap<String, CachedResolution>,
    max_entries: usize,
}

impl CacheState {
    /// Return a fresh cloned entry or lazily remove an expired entry.
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

    /// Return a fresh cloned entry without deleting expired entries.
    fn peek_fresh(&self, key: &str, now: DateTime<Utc>) -> Option<CachedResolution> {
        match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.clone()),
            _ => None,
        }
    }

    /// Insert an entry and evict the oldest cached item if capacity is full.
    fn insert(&mut self, key: String, entry: CachedResolution) {
        if self.max_entries == 0 {
            return;
        }
        if !self.entries.contains_key(&key)
            && self.entries.len() >= self.max_entries
            && let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.cached_at)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(key, entry);
    }
}

/// TTL + LRU cache wrapper for any [`DidResolver`].
///
/// [`DidResolver::resolve_did`] returns fresh cache hits directly and resolves
/// upstream only on miss or expiry. [`Self::resolve_with_freshness`] also
/// reports whether data came from cache, and honors
/// [`ResolverPolicy::fail_mode`] by falling back to stale data only for
/// `ResolverFailMode::AllowCachedOnError`.
pub struct CachingDidResolver<R: DidResolver> {
    inner: R,
    policy: ResolverPolicy,
    state: std::sync::Mutex<CacheState>,
}

impl<R: DidResolver> CachingDidResolver<R> {
    /// Build a cache wrapper with an explicit policy and capacity.
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

    /// Return the active resolver policy.
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// Borrow the wrapped resolver.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Current cached entry count, excluding future lazy expiry.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }

    /// Whether the cache currently has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop the cached entry for a DID.
    pub fn invalidate(&self, did: &Did) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(did.as_str());
    }

    /// Drop every cached entry.
    pub fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .clear();
    }

    /// Compute `expires_at` from `policy.ttl`.
    fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self.policy.ttl {
            Some(ttl) => now + ttl,
            None => now,
        }
    }

    /// Resolve a DID and return the document together with its [`Freshness`].
    ///
    /// Fresh cache hits return `(doc, Fresh)`. Misses and expired entries query
    /// the upstream resolver. If that query fails, stale data is returned only
    /// when the active policy is `AllowCachedOnError`.
    pub fn resolve_with_freshness(
        &self,
        did: &Did,
        now: DateTime<Utc>,
    ) -> Result<(DidDocument, Freshness)> {
        let key = did.as_str().to_owned();

        // Keep expired entries around so an upstream failure can still fall back
        // to stale data when policy permits it.
        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peek_fresh(&key, now)
        {
            return Ok((entry.document, Freshness::Fresh));
        }

        // Miss or expired entry: resolve upstream.
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
                // Stale fallback is available only in AllowCachedOnError mode.
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
