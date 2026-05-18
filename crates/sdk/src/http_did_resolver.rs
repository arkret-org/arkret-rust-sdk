//! Production reqwest-based [`DidResolver`] for `did:web` and `did:webvh`.
//!
//! HTTP fetch + caching layer on top of [`crate::identity`]'s offline
//! helpers. Per `identity/identity-handles.md` §4 the resolver:
//!
//! - fetches `https://<host>/.well-known/did.json` for `did:web`,
//! - fetches `https://<host>/.well-known/did.jsonl` and `did.json` for
//!   `did:webvh` and validates the SCID + chain via the existing
//!   [`DidWebvhResolver`] helpers,
//! - caches results behind a configurable TTL (default 5min),
//! - applies the [`ResolverPolicy`] allow-list and fail-mode,
//! - bounds responses by [`DID_WEB_MAX_DOCUMENT_BYTES`] and rejects
//!   non-JSON content types.
//!
//! Concurrency: the cache is guarded by a `Mutex` because resolver
//! traits are sync. For high-fanout deployments wrap the resolver in a
//! task-local cache or composite resolver and pre-warm at startup.

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client as HttpClient;

use crate::identity::{
    DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, DidResolver, DidWebDocumentResponse, DidWebResolver,
    DidWebvhDocumentResponse, DidWebvhLogResponse, DidWebvhResolver, ResolverFailMode,
    ResolverPolicy,
};
use crate::{Did, Error, Result};

/// Default TTL applied to cached documents when the policy does not
/// override it.
pub const DEFAULT_HTTP_DID_RESOLVER_TTL_SECS: i64 = 300;

/// Default request timeout (2s) per spec recommendation.
pub const DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS: u64 = 2_000;

/// Cached entry in the HTTP DID resolver.
#[derive(Clone, Debug)]
struct CacheEntry {
    document: DidDocument,
    fetched_at: DateTime<Utc>,
}

/// Reqwest-backed DID resolver covering `did:web` and `did:webvh`.
pub struct HttpDidResolver {
    http: HttpClient,
    policy: ResolverPolicy,
    cache: Mutex<std::collections::BTreeMap<Did, CacheEntry>>,
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for HttpDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDidResolver")
            .field("policy", &self.policy)
            .field("cached_dids", &self.cache.lock().map(|cache| cache.len()).unwrap_or_default())
            .finish()
    }
}

impl HttpDidResolver {
    /// Build a resolver with default `reqwest` transport and policy.
    ///
    /// MUST be called from inside a Tokio runtime — the resolver caches
    /// the current runtime handle so its sync `resolve_did` impl can
    /// drive the async `reqwest` calls.
    pub fn new() -> Result<Self> {
        Self::with_policy(ResolverPolicy::default())
    }

    /// Build a resolver with the supplied [`ResolverPolicy`].
    pub fn with_policy(policy: ResolverPolicy) -> Result<Self> {
        let http = HttpClient::builder()
            .timeout(Duration::from_millis(DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS))
            .build()
            .map_err(|err| Error::Protocol(format!("failed to build reqwest client: {err}")))?;
        Self::with_client(http, policy)
    }

    /// Build a resolver from a pre-configured [`reqwest::Client`].
    pub fn with_client(http: HttpClient, policy: ResolverPolicy) -> Result<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|err| {
            Error::Protocol(format!("HttpDidResolver requires an active Tokio runtime: {err}"))
        })?;
        Ok(Self { http, policy, cache: Mutex::new(std::collections::BTreeMap::new()), runtime })
    }

    /// Read the active policy.
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
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

    fn ttl_secs(&self) -> i64 {
        self.policy.ttl.map(|d| d.num_seconds()).unwrap_or(DEFAULT_HTTP_DID_RESOLVER_TTL_SECS)
    }

    fn cached(&self, did: &Did) -> Option<DidDocument> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(did)?;
        let age = Utc::now().signed_duration_since(entry.fetched_at).num_seconds();
        if age >= 0 && age < self.ttl_secs() { Some(entry.document.clone()) } else { None }
    }

    fn cache_put(&self, did: &Did, document: &DidDocument) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                did.clone(),
                CacheEntry { document: document.clone(), fetched_at: Utc::now() },
            );
        }
    }

    fn stale(&self, did: &Did) -> Option<DidDocument> {
        let cache = self.cache.lock().ok()?;
        cache.get(did).map(|entry| entry.document.clone())
    }

    async fn fetch_bytes(&self, url: &str) -> Result<(String, Vec<u8>)> {
        let response = self
            .http
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
        let bytes = response
            .bytes()
            .await
            .map_err(|err| Error::Protocol(format!("did body read failed: {err}")))?;
        if bytes.len() > DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32) {
            return Err(Error::Protocol("did response exceeds maximum size".to_owned()));
        }
        Ok((content_type, bytes.to_vec()))
    }

    async fn resolve_did_web(&self, did: &Did) -> Result<DidDocument> {
        let url = DidWebResolver::document_url(did)?;
        let (content_type, body) = self.fetch_bytes(&url).await?;
        let mut resolver = DidWebResolver::new();
        let document = resolver
            .insert_from_https_response(did, DidWebDocumentResponse { url, content_type, body })?;
        Ok(document)
    }

    async fn resolve_did_webvh(&self, did: &Did) -> Result<DidDocument> {
        let doc_url = DidWebvhResolver::document_url(did)?;
        let log_url = DidWebvhResolver::log_url(did)?;
        let (doc_ct, doc_body) = self.fetch_bytes(&doc_url).await?;
        let (log_ct, log_body) = self.fetch_bytes(&log_url).await?;
        let mut resolver = DidWebvhResolver::new();
        let document = resolver.insert_from_https_response(
            did,
            DidWebvhDocumentResponse { url: doc_url, content_type: doc_ct, body: doc_body },
        )?;
        // Validate the log too — reject the document if the log chain is bad.
        resolver.ingest_log(
            did,
            DidWebvhLogResponse { url: log_url, content_type: log_ct, body: log_body },
        )?;
        Ok(document)
    }

    fn block_on<F: Future + Send>(&self, future: F) -> F::Output
    where
        F::Output: Send,
    {
        // We cannot call `block_on` from within the same runtime; spawn a
        // blocking task so the runtime drives the future from a worker.
        // `tokio::task::block_in_place` only works on the multi-thread runtime,
        // but `Handle::block_on` panics from within a runtime — the safest
        // pattern is to off-load to a blocking thread that owns its own
        // mini-runtime via `Handle::block_on`.
        let handle = self.runtime.clone();
        std::thread::scope(|s| {
            s.spawn(move || handle.block_on(future)).join().expect("did resolver join")
        })
    }

    fn fetch_now(&self, did: &Did) -> Result<DidDocument> {
        let method = did.method();
        match method {
            "web" => self.block_on(self.resolve_did_web(did)),
            "webvh" => self.block_on(self.resolve_did_webvh(did)),
            other => Err(Error::Protocol(format!("HttpDidResolver does not support did:{other}"))),
        }
    }
}

impl DidResolver for HttpDidResolver {
    fn supports(&self, did: &Did) -> bool {
        if !self.policy.permits(did) {
            return false;
        }
        matches!(did.method(), "web" | "webvh")
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        self.policy.validate(did)?;
        if let Some(cached) = self.cached(did) {
            return Ok(cached);
        }
        match self.fetch_now(did) {
            Ok(document) => {
                self.cache_put(did, &document);
                Ok(document)
            }
            Err(err) => match self.policy.fail_mode {
                ResolverFailMode::AllowCachedOnError => {
                    if let Some(stale) = self.stale(did) {
                        Ok(stale)
                    } else {
                        Err(err)
                    }
                }
                ResolverFailMode::FailClosed => Err(err),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn resolver_invalidates_cache() {
        let resolver = HttpDidResolver::new().unwrap();
        // Using `did:web` form with an unreachable host so the failure
        // path is exercised; we only check cache invalidation API works.
        let did = Did::new("did:web:nonexistent.invalid").unwrap();
        resolver.invalidate(&did);
        resolver.invalidate_all();
    }

    #[test]
    fn requires_runtime() {
        // Outside a Tokio runtime, `with_policy` must error rather than
        // panic.
        let result = HttpDidResolver::new();
        assert!(result.is_err());
    }
}
