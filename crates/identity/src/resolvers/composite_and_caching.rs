use std::collections::HashMap;

use arkret_wire::DidFullId;

use super::basics::*;
use super::policy::*;
use crate::helpers::*;
use crate::*;

/// Limited `did:keri` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidKeriResolver {
    documents: BTreeMap<DidFullId, DidDocument>,
}

impl DidKeriResolver {
    /// Create an empty `did:keri` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:keri` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "keri" {
            return Err(IdentityError::Protocol(
                "did:keri resolver only accepts did:keri".to_owned(),
            ));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidKeriResolver {
    fn supports(&self, did: &DidFullId) -> bool {
        did.method() == "keri"
    }

    fn resolve_did(&self, did: &DidFullId) -> Result<ResolvedDid> {
        if !self.supports(did) {
            return Err(IdentityError::Protocol(
                "unsupported DID method for did:keri resolver".to_owned(),
            ));
        }
        self.documents
            .get(did)
            .cloned()
            .map(ResolvedDid::proofless)
            .ok_or_else(|| IdentityError::Protocol("did:keri document not found".to_owned()))
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
    fn supports(&self, did: &DidFullId) -> bool {
        did.method() == "key" && did_key_material(did).is_some()
    }

    fn resolve_did(&self, did: &DidFullId) -> Result<ResolvedDid> {
        let key = did_key_material(did)
            .ok_or_else(|| IdentityError::Protocol("unsupported did:key form".to_owned()))?;
        // `did:key` is self-describing: there is no log, no witness set and
        // nothing to prove beyond the identifier, so the receipt degrades to an
        // empty proof array rather than to an invented placeholder.
        let verification_method = format!("{}#{key}", did.as_str());
        let mut document = DidDocument::new(did.clone(), &verification_method, key);
        document.raw_properties.insert(
            "assertionMethod".to_owned(),
            serde_json::json!([verification_method]),
        );
        // did:key is self-certifying and immutable. A resolver-local wall-clock
        // timestamp would make the same DID expand to different canonical
        // documents and break retained-history verification.
        document.updated_at = None;
        Ok(ResolvedDid::proofless(document))
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
    fn supports(&self, did: &DidFullId) -> bool {
        self.policy.permits(did) && self.resolvers.iter().any(|resolver| resolver.supports(did))
    }

    fn resolve_did(&self, did: &DidFullId) -> Result<ResolvedDid> {
        self.policy.validate(did)?;
        self.resolvers
            .iter()
            .find(|resolver| resolver.supports(did))
            .ok_or_else(|| IdentityError::Protocol("unsupported DID method".to_owned()))?
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
/// prefix. The method evidence is cached alongside the document because a cache
/// hit must be able to produce the same section 5.2 evidence receipt an upstream
/// resolution would: caching the document alone would silently downgrade every
/// cached authority acceptance into a proofless one.
#[derive(Clone, Debug)]
pub struct CachedResolution {
    /// Cached DID document.
    pub document: DidDocument,
    /// What the method proved about that document.
    pub method_evidence: MethodEvidence,
    /// Time when the entry was stored.
    pub cached_at: DateTime<Utc>,
    /// Expiry time (`cached_at + ttl`).
    pub expires_at: DateTime<Utc>,
    /// Canonical SHA-256 digest of the document, including the `sha256:` prefix.
    pub document_hash: String,
}

impl CachedResolution {
    /// Build a cache entry and compute its canonical document hash.
    pub fn new(
        document: DidDocument,
        cached_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_resolution(ResolvedDid::proofless(document), cached_at, expires_at)
    }

    /// Build a cache entry from a full resolution.
    pub fn for_resolution(
        resolved: ResolvedDid,
        cached_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let document_hash = document_canonical_hash(&resolved.document)?;
        Ok(Self {
            document: resolved.document,
            method_evidence: resolved.method_evidence,
            cached_at,
            expires_at,
            document_hash,
        })
    }

    /// The cached resolution.
    pub fn resolved(&self) -> ResolvedDid {
        ResolvedDid::new(self.document.clone(), self.method_evidence.clone())
    }

    /// Return this entry's freshness relative to `now`.
    pub fn freshness_at(&self, now: DateTime<Utc>) -> Freshness {
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
    let bytes = arkret_canonical::canonical::canonical_json_bytes(document).map_err(|e| {
        IdentityError::Protocol(format!("DID document canonicalization failed: {e}"))
    })?;
    Ok(arkret_canonical::canonical::sha256_digest(bytes))
}

/// Mutable state for [`DidResolutionCache`], protected by a `Mutex`.
#[derive(Clone, Debug)]
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

/// Reusable TTL + LRU store for resolved DID documents.
///
/// Client runtimes may carry a deep-cloned snapshot through UI state and
/// authority adapters without reimplementing expiry, eviction, or invalidation
/// semantics.
#[derive(Debug)]
pub struct DidResolutionCache {
    state: std::sync::Mutex<CacheState>,
}

/// Aggregate read-only cache health for status surfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DidResolutionCacheHealth {
    pub entries: usize,
    pub fresh_entries: usize,
    pub stale_entries: usize,
}

/// Stable read-only snapshot entry returned by [`DidResolutionCache::snapshot`].
#[derive(Clone, Debug)]
pub struct DidResolutionCacheSnapshotEntry {
    pub did: String,
    pub resolution: CachedResolution,
}

impl Clone for DidResolutionCache {
    fn clone(&self) -> Self {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Self {
            state: std::sync::Mutex::new(state),
        }
    }
}

impl DidResolutionCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(CacheState {
                entries: HashMap::new(),
                max_entries,
            }),
        }
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return a fresh resolution and lazily evict an expired entry.
    pub fn get(&self, did: &DidFullId, now: DateTime<Utc>) -> Option<ResolvedDid> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_fresh(did.as_str(), now)
            .map(|entry| entry.resolved())
    }

    /// Insert a resolution with an explicit TTL.
    pub fn insert(
        &self,
        did: DidFullId,
        resolved: ResolvedDid,
        now: DateTime<Utc>,
        ttl: chrono::Duration,
    ) -> Result<()> {
        let entry = CachedResolution::for_resolution(resolved, now, now + ttl)?;
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(did.to_string(), entry);
        Ok(())
    }

    /// Read an entry without evicting it, including stale entries.
    pub fn peek(&self, did: &DidFullId) -> Option<CachedResolution> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .get(did.as_str())
            .cloned()
    }

    /// Return a deterministic read-only snapshot sorted by DID.
    pub fn snapshot(&self) -> Vec<DidResolutionCacheSnapshotEntry> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = state
            .entries
            .iter()
            .map(|(did, resolution)| DidResolutionCacheSnapshotEntry {
                did: did.clone(),
                resolution: resolution.clone(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.did.cmp(&right.did));
        entries
    }

    pub fn health(&self, now: DateTime<Utc>) -> DidResolutionCacheHealth {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh_entries = state
            .entries
            .values()
            .filter(|entry| matches!(entry.freshness_at(now), Freshness::Fresh))
            .count();
        DidResolutionCacheHealth {
            entries: state.entries.len(),
            fresh_entries,
            stale_entries: state.entries.len().saturating_sub(fresh_entries),
        }
    }

    pub fn has_fresh_entry(&self, now: DateTime<Utc>) -> bool {
        self.health(now).fresh_entries > 0
    }

    pub fn has_only_stale_entries(&self, now: DateTime<Utc>) -> bool {
        let health = self.health(now);
        health.entries > 0 && health.fresh_entries == 0
    }

    pub fn invalidate(&self, did: &DidFullId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(did.as_str());
    }

    pub fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .clear();
    }
}

impl Default for DidResolutionCache {
    fn default() -> Self {
        Self::new(128)
    }
}
