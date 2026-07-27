//! Production reqwest-based [`DidResolver`] for `did:web` and `did:webvh`.
//!
//! HTTP fetch + caching layer on top of [`arkret_identity`]'s offline
//! helpers. Per `identity/identity-handles.md` §4 the resolver:
//!
//! - fetches `https://<host>/.well-known/did.json` for `did:web`,
//! - fetches `did.json`, `did.jsonl`, and, when declared, the separate `did-witness.json` for
//!   `did:webvh`, then validates the SCID, chain, controller proofs, and method-native witness
//!   threshold,
//! - caches results behind a configurable TTL (default 7d),
//! - applies the [`ResolverPolicy`] allow-list and fail-mode,
//! - bounds responses by [`DID_WEB_MAX_DOCUMENT_BYTES`] and rejects non-JSON content types.
//!
//! Concurrency: async callers use [`HttpDidResolver::resolve_did_async`]
//! (native awaits, no helper threads). The sync [`DidResolver`] impl drives
//! the same future without deadlocking any runtime flavor (see
//! [`HttpDidResolver::drive`]). Concurrent resolutions of the same DID are
//! single-flighted: one network fetch, every waiter shares the result.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_identity::{
    DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, DidResolver, DidWebDocumentOutcome, DidWebResolver,
    DidWebvhDocumentOutcome, DidWebvhLogOutcome, DidWebvhResolver, ResolverFailMode,
    ResolverPolicy, verify_did_webvh_v1_chain_and_witness_bytes,
};
use arkret_wire::Did;
use chrono::{DateTime, Utc};
use reqwest::Client as HttpClient;
use tokio::sync::OnceCell;

use crate::{Error, Result};

/// Default TTL applied to cached documents when the policy does not
/// override it.
pub const DEFAULT_HTTP_DID_RESOLVER_TTL_SECS: i64 = 60 * 60 * 24 * 7;

/// Maximum additional outage window for returning a previously verified
/// cache entry after live resolution fails.
pub const DEFAULT_HTTP_DID_RESOLVER_OUTAGE_SECS: i64 = 60 * 60 * 24;

/// Default request timeout (2s) per spec recommendation.
pub const DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS: u64 = 2_000;

/// Default maximum number of verified DID documents retained in memory.
pub const DEFAULT_HTTP_DID_RESOLVER_MAX_ENTRIES: usize = 1_024;

/// Cached entry in the HTTP DID resolver.
#[derive(Clone, Debug)]
struct CacheEntry {
    document: DidDocument,
    fetched_at: DateTime<Utc>,
    last_accessed_at: DateTime<Utc>,
}

type InflightResolution<T> = Arc<OnceCell<std::result::Result<T, String>>>;

/// Last externally visible resolver health signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpDidResolverHealthSignal {
    Healthy,
    DegradedHostingUnreachable,
    StaleHistory,
    Untrusted,
}

/// Deduplicates concurrent fetches of the same key: the first caller runs
/// the fetch, every concurrent caller awaits the same [`OnceCell`] and
/// shares the result; the marker is removed once settled so later callers
/// start a fresh fetch (this is fetch-level dedup, not a cache).
///
/// Errors are stored as their display string (the error type is not
/// `Clone`) and rehydrated as [`Error::Protocol`] for the waiters.
struct SingleFlight<T> {
    inflight: Mutex<BTreeMap<Did, InflightResolution<T>>>,
}

impl<T: Clone> SingleFlight<T> {
    fn new() -> Self {
        Self {
            inflight: Mutex::new(BTreeMap::new()),
        }
    }

    async fn run<F, Fut>(&self, key: &Did, fetch: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let cell = {
            let mut inflight = self
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inflight
                .entry(key.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        // `get_or_init` runs at most one initializer at a time; if the
        // leading caller is cancelled mid-fetch, the next waiter's closure
        // takes over (tokio OnceCell semantics), so a cancelled leader never
        // wedges the flight.
        let outcome = cell
            .get_or_init(|| async { fetch().await.map_err(|err| err.to_string()) })
            .await
            .clone();
        // Settled: drop the marker so the next resolution starts a new
        // fetch. Guard on pointer identity — a fresh flight may already have
        // replaced the slot.
        {
            let mut inflight = self
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inflight.get(key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
                inflight.remove(key);
            }
        }
        outcome.map_err(Error::Protocol)
    }
}

/// Reqwest-backed DID resolver covering `did:web` and `did:webvh`.
pub struct HttpDidResolver {
    http: HttpClient,
    egress_policy: Option<OutboundPolicy>,
    policy: ResolverPolicy,
    cache: Mutex<BTreeMap<Did, CacheEntry>>,
    max_cache_entries: usize,
    health_signal: Mutex<HttpDidResolverHealthSignal>,
    runtime: tokio::runtime::Handle,
    single_flight: SingleFlight<DidDocument>,
}

impl std::fmt::Debug for HttpDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDidResolver")
            .field("policy", &self.policy)
            .field(
                "cached_dids",
                &self
                    .cache
                    .lock()
                    .map(|cache| cache.len())
                    .unwrap_or_default(),
            )
            .finish()
    }
}

impl HttpDidResolver {
    /// Build a resolver with default `reqwest` transport and policy.
    ///
    /// MUST be called from inside a Tokio runtime — the resolver caches
    /// the current runtime handle as the fallback driver for the sync
    /// [`DidResolver::resolve_did`] impl. Async callers should prefer
    /// [`Self::resolve_did_async`], which awaits the fetch natively.
    /// The sync path blocks the calling thread for the duration of the
    /// fetch (bounded by the request timeout) but never deadlocks; see
    /// [`Self::drive`] for the runtime-flavor handling.
    pub fn new() -> Result<Self> {
        Self::with_policy(ResolverPolicy::default())
    }

    /// Build a resolver with the supplied [`ResolverPolicy`].
    pub fn with_policy(policy: ResolverPolicy) -> Result<Self> {
        Self::with_policy_and_egress(policy, OutboundPolicy::public_https())
    }

    /// Build a resolver with the supplied resolution and outbound-target
    /// policies. Each request validates the URL before DNS resolution,
    /// validates every resolved address, pins the validated candidates into
    /// the connector, and rejects redirects.
    pub fn with_policy_and_egress(
        policy: ResolverPolicy,
        egress_policy: OutboundPolicy,
    ) -> Result<Self> {
        let http = HttpClient::builder()
            .timeout(Duration::from_millis(DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| Error::Protocol(format!("failed to build reqwest client: {err}")))?;
        Self::build(
            http,
            policy,
            DEFAULT_HTTP_DID_RESOLVER_MAX_ENTRIES,
            Some(egress_policy),
        )
    }

    /// Build a resolver from a pre-configured [`reqwest::Client`].
    ///
    /// The caller owns the transport policy for an injected client. Production
    /// callers should prefer [`Self::with_policy_and_egress`].
    pub fn with_client(http: HttpClient, policy: ResolverPolicy) -> Result<Self> {
        Self::with_client_and_cache_limit(http, policy, DEFAULT_HTTP_DID_RESOLVER_MAX_ENTRIES)
    }

    /// Build a resolver with an explicit in-memory cache bound.
    pub fn with_client_and_cache_limit(
        http: HttpClient,
        policy: ResolverPolicy,
        max_cache_entries: usize,
    ) -> Result<Self> {
        Self::build(http, policy, max_cache_entries, None)
    }

    fn build(
        http: HttpClient,
        policy: ResolverPolicy,
        max_cache_entries: usize,
        egress_policy: Option<OutboundPolicy>,
    ) -> Result<Self> {
        if max_cache_entries == 0 {
            return Err(Error::Protocol(
                "HttpDidResolver cache limit must be greater than zero".to_owned(),
            ));
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|err| {
            Error::Protocol(format!(
                "HttpDidResolver requires an active Tokio runtime: {err}"
            ))
        })?;
        Ok(Self {
            http,
            egress_policy,
            policy,
            cache: Mutex::new(BTreeMap::new()),
            max_cache_entries,
            health_signal: Mutex::new(HttpDidResolverHealthSignal::Healthy),
            runtime,
            single_flight: SingleFlight::new(),
        })
    }

    async fn client_for_url(&self, url: &str) -> Result<HttpClient> {
        let Some(policy) = self.egress_policy else {
            return Ok(self.http.clone());
        };
        let parsed = reqwest::Url::parse(url)
            .map_err(|error| Error::Protocol(format!("did fetch URL is invalid: {error}")))?;
        policy
            .validate_url(&parsed)
            .map_err(|error| Error::Protocol(format!("did fetch target is denied: {error}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::Protocol("did fetch URL has no host".to_owned()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| Error::Protocol("did fetch URL has no usable port".to_owned()))?;
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| Error::Protocol(format!("did fetch DNS resolution failed: {error}")))?
            .collect();
        let target = policy
            .bind_resolved(parsed, addresses)
            .map_err(|error| Error::Protocol(format!("did fetch target is denied: {error}")))?;
        HttpClient::builder()
            .timeout(Duration::from_millis(DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, target.addresses())
            .build()
            .map_err(|error| Error::Protocol(format!("failed to build pinned DID client: {error}")))
    }

    /// Read the active policy.
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// Return the last health signal observed by resolution.
    pub fn health_signal(&self) -> HttpDidResolverHealthSignal {
        self.health_signal
            .lock()
            .map(|signal| *signal)
            .unwrap_or(HttpDidResolverHealthSignal::Untrusted)
    }

    /// Drop every cached entry.
    pub fn invalidate_all(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Drop a single cached entry.
    pub fn invalidate(&self, did: &Did) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(did);
        }
    }

    /// Current verified-document cache size for health/metrics adapters.
    pub fn cached_document_count(&self) -> usize {
        self.cache
            .lock()
            .map(|cache| cache.len())
            .unwrap_or_default()
    }

    fn ttl_secs(&self) -> i64 {
        self.policy
            .ttl
            .map(|d| d.num_seconds())
            .unwrap_or(DEFAULT_HTTP_DID_RESOLVER_TTL_SECS)
    }

    fn max_stale_secs(&self) -> i64 {
        self.ttl_secs()
            .saturating_add(DEFAULT_HTTP_DID_RESOLVER_OUTAGE_SECS)
    }

    fn set_health_signal(&self, signal: HttpDidResolverHealthSignal) {
        if let Ok(mut health_signal) = self.health_signal.lock() {
            *health_signal = signal;
        }
    }

    fn cached(&self, did: &Did) -> Option<DidDocument> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get_mut(did)?;
        let age = Utc::now()
            .signed_duration_since(entry.fetched_at)
            .num_seconds();
        if age >= 0 && age < self.ttl_secs() {
            entry.last_accessed_at = Utc::now();
            Some(entry.document.clone())
        } else {
            None
        }
    }

    fn stale_within_outage(&self, did: &Did) -> Option<DidDocument> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get_mut(did)?;
        let age = Utc::now()
            .signed_duration_since(entry.fetched_at)
            .num_seconds();
        if age >= 0 && age <= self.max_stale_secs() {
            entry.last_accessed_at = Utc::now();
            Some(entry.document.clone())
        } else {
            cache.remove(did);
            None
        }
    }

    fn cache_put(&self, did: &Did, document: &DidDocument) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Utc::now();
            let max_stale_secs = self.max_stale_secs();
            cache.retain(|_, entry| {
                let age = now.signed_duration_since(entry.fetched_at).num_seconds();
                age >= 0 && age <= max_stale_secs
            });
            if !cache.contains_key(did)
                && cache.len() >= self.max_cache_entries
                && let Some(lru_did) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_accessed_at)
                    .map(|(did, _)| did.clone())
            {
                cache.remove(&lru_did);
            }
            cache.insert(
                did.clone(),
                CacheEntry {
                    document: document.clone(),
                    fetched_at: now,
                    last_accessed_at: now,
                },
            );
        }
    }

    /// Fetch `url` with an enforced response-size ceiling.
    ///
    /// The body is read incrementally and the connection is dropped as
    /// soon as the accumulated size exceeds `max_bytes` — DID resolution
    /// is triggered by untrusted input (verifying a stranger's signature
    /// or invite), so a hostile `did:web` host must not be able to force
    /// an unbounded allocation before the size check runs. A declared
    /// `Content-Length` above the ceiling is rejected before any body
    /// byte is read.
    async fn fetch_bytes(&self, url: &str, max_bytes: usize) -> Result<(String, Vec<u8>)> {
        let client = self.client_for_url(url).await?;
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|err| Error::Protocol(format!("did fetch failed: {err}")))?;
        if !response.status().is_success() {
            return Err(Error::Protocol(format!(
                "did fetch returned status {}",
                response.status()
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        if response
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(Error::Protocol(
                "did response exceeds maximum size".to_owned(),
            ));
        }
        let mut body: Vec<u8> = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|err| Error::Protocol(format!("did body read failed: {err}")))?;
            let Some(chunk) = chunk else { break };
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(Error::Protocol(
                    "did response exceeds maximum size".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((content_type, body))
    }

    async fn resolve_did_web(&self, did: &Did) -> Result<DidDocument> {
        let url = DidWebResolver::document_url(did)?;
        let (content_type, body) = self.fetch_bytes(&url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
        let mut resolver = DidWebResolver::new();
        let document = resolver.insert_from_https_response(
            did,
            DidWebDocumentOutcome {
                url,
                content_type,
                body,
            },
        )?;
        Ok(document)
    }

    async fn resolve_did_webvh(&self, did: &Did) -> Result<DidDocument> {
        let doc_url = DidWebvhResolver::document_url(did)?;
        let log_url = DidWebvhResolver::log_url(did)?;
        // Documents are capped at the spec document limit; the jsonl log
        // is deliberately wider (×32, matching `DidWebvhResolver::ingest_log`).
        let (doc_ct, doc_body) = self
            .fetch_bytes(&doc_url, DID_WEB_MAX_DOCUMENT_BYTES)
            .await?;
        let (log_ct, log_body) = self
            .fetch_bytes(&log_url, DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32))
            .await?;
        let witness_declared = log_body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .any(|entry| entry.pointer("/parameters/witness").is_some());
        let witness_body = if witness_declared {
            let witness_url = DidWebvhResolver::witness_url(did)?;
            let (witness_ct, witness_body) = self
                .fetch_bytes(&witness_url, DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32))
                .await?;
            if !is_json_content_type(&witness_ct) {
                return Err(Error::Protocol(format!(
                    "did witness response content type is not JSON: {witness_ct}"
                )));
            }
            Some(witness_body)
        } else {
            None
        };
        verify_did_webvh_v1_chain_and_witness_bytes(did, &log_body, witness_body.as_deref())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let mut resolver = DidWebvhResolver::new();
        let document = resolver.insert_from_https_response(
            did,
            DidWebvhDocumentOutcome {
                url: doc_url,
                content_type: doc_ct,
                body: doc_body,
            },
        )?;
        // Validate the log too — reject the document if the log chain is bad.
        resolver.ingest_log(
            did,
            DidWebvhLogOutcome {
                url: log_url,
                content_type: log_ct,
                body: log_body,
            },
        )?;
        Ok(document)
    }

    /// Fetch (and validate) the document for `did`, without cache or
    /// fail-mode handling.
    async fn fetch_document(&self, did: &Did) -> Result<DidDocument> {
        match did.method() {
            "web" => self.resolve_did_web(did).await,
            "webvh" => self.resolve_did_webvh(did).await,
            other => Err(Error::Protocol(format!(
                "HttpDidResolver does not support did:{other}"
            ))),
        }
    }

    /// Shared post-fetch handling for the sync and async resolution paths:
    /// cache the fresh document, or apply the policy fail-mode (stale cache
    /// within the outage window vs. fail closed) and update the health
    /// signal.
    fn finish_resolution(&self, did: &Did, fetched: Result<DidDocument>) -> Result<DidDocument> {
        match fetched {
            Ok(document) => {
                self.cache_put(did, &document);
                self.set_health_signal(HttpDidResolverHealthSignal::Healthy);
                Ok(document)
            }
            Err(err) => match self.policy.fail_mode {
                ResolverFailMode::AllowCachedOnError => {
                    if let Some(stale) = self.stale_within_outage(did) {
                        self.set_health_signal(HttpDidResolverHealthSignal::StaleHistory);
                        Ok(stale)
                    } else {
                        self.set_health_signal(
                            HttpDidResolverHealthSignal::DegradedHostingUnreachable,
                        );
                        Err(err)
                    }
                }
                ResolverFailMode::FailClosed => {
                    self.set_health_signal(HttpDidResolverHealthSignal::Untrusted);
                    Err(err)
                }
            },
        }
    }

    /// Async-native resolution path: awaits the fetch on the caller's
    /// runtime — no helper threads, no `block_on`, so it is always safe to
    /// call from async contexts (including single-worker runtimes).
    /// Concurrent resolutions of the same DID share one network fetch
    /// (single-flight).
    pub async fn resolve_did_async(&self, did: &Did) -> Result<DidDocument> {
        self.policy.validate(did)?;
        if let Some(cached) = self.cached(did) {
            return Ok(cached);
        }
        let fetched = self
            .single_flight
            .run(did, || self.fetch_document(did))
            .await;
        self.finish_resolution(did, fetched)
    }

    /// Drive `future` to completion from a synchronous context without
    /// deadlocking any Tokio runtime flavor.
    ///
    /// - Caller associated with a **multi-thread** runtime (worker thread, blocking-pool thread, or
    ///   a thread inside `Runtime::block_on`): `tokio::task::block_in_place` + `Handle::block_on`.
    ///   `block_in_place` tells the scheduler this thread is about to block so the worker core is
    ///   handed off to a replacement thread — the IO/timer drivers stay driven even with
    ///   `worker_threads = 1`, which is exactly the deadlock the previous "external thread +
    ///   `Handle::block_on`" shape had (an external thread only polls the future; it never drives
    ///   the runtime's IO driver). Off runtime worker threads `block_in_place` is a pass-through
    ///   and `Handle::block_on` is safe because the runtime's own workers keep driving the drivers.
    /// - Caller associated with a **current-thread** runtime: that runtime's only driver thread is
    ///   the caller itself, so nothing may block on its handle. Drive the fetch on a private
    ///   single-use runtime owned by a scoped helper thread instead (the helper drives its own IO
    ///   driver; the caller only parks in `join()`).
    fn drive<T: Send, F: Future<Output = Result<T>> + Send>(&self, future: F) -> Result<T> {
        // Prefer the runtime the calling thread is currently associated
        // with; fall back to the handle cached at construction time for
        // plain non-runtime threads.
        let handle = tokio::runtime::Handle::try_current().unwrap_or_else(|_| self.runtime.clone());
        match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::CurrentThread => std::thread::scope(|s| {
                s.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|err| {
                            Error::Protocol(format!("failed to build DID resolver runtime: {err}"))
                        })?;
                    runtime.block_on(future)
                })
                .join()
                .expect("did resolver join")
            }),
            _ => tokio::task::block_in_place(|| handle.block_on(future)),
        }
    }
}

fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

impl DidResolver for HttpDidResolver {
    fn supports(&self, did: &Did) -> bool {
        if !self.policy.permits(did) {
            return false;
        }
        matches!(did.method(), "web" | "webvh")
    }

    /// Sync facade over [`Self::resolve_did_async`]. Blocks the calling
    /// thread for the duration of the fetch (bounded by the request
    /// timeout); see [`Self::drive`] for why this is deadlock-free on every
    /// runtime flavor. Async callers should use
    /// [`Self::resolve_did_async`] directly.
    fn resolve_did(&self, did: &Did) -> arkret_identity::Result<DidDocument> {
        // The `DidResolver` trait (owned by arkret-identity) is typed on
        // `IdentityError`; bridge this crate's facade error at the boundary.
        self.drive(self.resolve_did_async(did))
            .map_err(|error| arkret_identity::IdentityError::Protocol(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(did: Did) -> DidDocument {
        DidDocument {
            id: did,
            verification_methods: BTreeMap::new(),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn resolver_rejects_unsupported_method() {
        let resolver = HttpDidResolver::with_policy(ResolverPolicy {
            allowed_methods: vec!["did:web:".to_owned(), "did:webvh:".to_owned()],
            ..ResolverPolicy::default()
        })
        .unwrap();
        let did = Did::new("did:key:z6MkfZ6S2cYbVdXBgnYzQwHgKZ4ApZRzELZ8R6PqQVqzDqXY").unwrap();
        assert!(!resolver.supports(&did));
        assert!(resolver.resolve_did(&did).is_err());
    }

    #[tokio::test]
    async fn default_transport_rejects_private_targets_before_connecting() {
        let resolver = HttpDidResolver::new().unwrap();
        let error = resolver
            .client_for_url("https://127.0.0.1/.well-known/did.json")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("target is denied"));
    }

    #[tokio::test]
    async fn resolver_invalidates_cache() {
        let resolver = HttpDidResolver::new().unwrap();
        // Using `did:web` form with an unreachable host so the failure
        // path is exercised; we only check cache invalidation API works.
        let did = Did::new("did:web:nonexistent.invalid").unwrap();
        resolver.invalidate(&did);
        resolver.invalidate_all();
    }

    #[tokio::test]
    async fn resolver_cache_is_bounded_and_removes_expired_entries() {
        let resolver = HttpDidResolver::with_client_and_cache_limit(
            HttpClient::new(),
            ResolverPolicy::default(),
            2,
        )
        .unwrap();
        let first = Did::new("did:web:first.example").unwrap();
        let second = Did::new("did:web:second.example").unwrap();
        let third = Did::new("did:web:third.example").unwrap();
        resolver.cache_put(&first, &document(first.clone()));
        resolver.cache_put(&second, &document(second.clone()));
        resolver.cache_put(&third, &document(third.clone()));
        assert_eq!(resolver.cached_document_count(), 2);

        let expired = resolver
            .cache
            .lock()
            .unwrap()
            .keys()
            .next()
            .cloned()
            .unwrap();
        resolver
            .cache
            .lock()
            .unwrap()
            .get_mut(&expired)
            .unwrap()
            .fetched_at = Utc::now() - chrono::TimeDelta::days(9);
        assert!(resolver.stale_within_outage(&expired).is_none());
        assert_eq!(resolver.cached_document_count(), 1);
    }

    #[test]
    fn requires_runtime() {
        // Outside a Tokio runtime, `with_policy` must error rather than
        // panic.
        let result = HttpDidResolver::new();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn single_flight_deduplicates_concurrent_fetches() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let flight = SingleFlight::<u32>::new();
        let calls = AtomicUsize::new(0);
        let did = Did::new("did:webvh:QmScid:resolver.invalid").unwrap();
        let fetch = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                // Yield so the concurrent callers below get polled while the
                // leader's fetch is still in flight.
                tokio::task::yield_now().await;
                Ok(7_u32)
            }
        };
        let (a, b, c) = tokio::join!(
            flight.run(&did, fetch),
            flight.run(&did, fetch),
            flight.run(&did, fetch),
        );
        assert_eq!(a.unwrap(), 7);
        assert_eq!(b.unwrap(), 7);
        assert_eq!(c.unwrap(), 7);
        // Three concurrent resolutions, exactly one fetch.
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The flight marker is removed once settled: a later resolution
        // starts a fresh fetch (this is dedup, not a cache).
        assert_eq!(flight.run(&did, fetch).await.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn single_flight_shares_errors_without_caching_them() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let flight = SingleFlight::<u32>::new();
        let calls = AtomicUsize::new(0);
        let did = Did::new("did:webvh:QmScid:resolver.invalid").unwrap();
        let fetch = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                tokio::task::yield_now().await;
                Err::<u32, _>(Error::Protocol("boom".to_owned()))
            }
        };
        let (a, b) = tokio::join!(flight.run(&did, fetch), flight.run(&did, fetch));
        assert!(a.is_err());
        assert!(b.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Errors are not cached: the next resolution retries.
        assert!(flight.run(&did, fetch).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn async_path_fails_closed_for_unreachable_host() {
        let resolver = HttpDidResolver::new().unwrap();
        let did = Did::new("did:web:nonexistent.invalid").unwrap();
        // `.invalid` is reserved (RFC 2606): DNS resolution fails, the
        // fail-closed default policy surfaces the error, and nothing hangs.
        assert!(resolver.resolve_did_async(&did).await.is_err());
        assert_eq!(
            resolver.health_signal(),
            HttpDidResolverHealthSignal::Untrusted
        );
    }

    // Regression for the SDK-ASYNC-05 deadlock: the sync `resolve_did`
    // called from async context on a multi-thread runtime with a single
    // worker. The old shape (external thread + `Handle::block_on`) parked
    // the only worker in `join()` while the helper waited on IO/timer
    // drivers nobody was driving — permanent deadlock. `block_in_place`
    // hands the worker core off, so this now completes (with an error for
    // the unreachable host).
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn sync_resolve_on_single_worker_multi_thread_runtime_does_not_deadlock() {
        let resolver = Arc::new(HttpDidResolver::new().unwrap());

        // Exercise the true worker-thread path via a spawned task.
        let on_worker = {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move {
                let did = Did::new("did:web:nonexistent.invalid").unwrap();
                resolver.resolve_did(&did)
            })
            .await
            .unwrap()
        };
        assert!(on_worker.is_err());

        // And the `Runtime::block_on` (test body) path.
        let did = Did::new("did:web:nonexistent.invalid").unwrap();
        assert!(resolver.resolve_did(&did).is_err());
    }

    #[tokio::test]
    async fn sync_resolve_on_current_thread_runtime_does_not_deadlock() {
        // `#[tokio::test]` default flavor is current-thread: the sync path
        // must detour through the private helper runtime instead of
        // blocking the only driver thread.
        let resolver = HttpDidResolver::new().unwrap();
        let did = Did::new("did:web:nonexistent.invalid").unwrap();
        assert!(resolver.resolve_did(&did).is_err());
    }
}
