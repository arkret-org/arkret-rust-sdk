//! [`ClientBuilder`] and its native/wasm transport configuration.
//!
//! `RedirectPolicy` and `ClientBuilder` are part of the public API and are
//! re-exported at the crate root from `lib.rs`. `TransportConfig` is an
//! internal helper and stays private to this module.

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use url::Url;

use crate::client_internals::{
    transport_error, validate_auth, validate_base_url, validate_header_value,
};
use crate::{Auth, Client, Error, HttpMessageSigner, Result, RetryConfig};
#[cfg(not(target_arch = "wasm32"))]
use crate::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT};

/// Named redirect policies. `reqwest::redirect::Policy` is not `Clone`, so
/// we model the supported choices as a small enum and materialise a Policy
/// at `build()` time.
///
/// Native-only: `reqwest`'s `redirect` module is not compiled into the
/// wasm32 fetch backend (the browser handles redirects transparently), so
/// this enum and the corresponding [`ClientBuilder::redirect`] method are
/// gated out on wasm32.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub enum RedirectPolicy {
    /// Refuse to follow any redirects (typical service-to-service).
    None,
    /// Follow up to `limit` redirects, then return the last response.
    Limited(usize),
}

#[cfg(not(target_arch = "wasm32"))]
impl RedirectPolicy {
    fn into_reqwest(self) -> reqwest::redirect::Policy {
        match self {
            RedirectPolicy::None => reqwest::redirect::Policy::none(),
            RedirectPolicy::Limited(limit) => reqwest::redirect::Policy::limited(limit),
        }
    }
}

/// Native transport configuration applied to the underlying `reqwest::Client`.
///
/// Every field is optional. `None` means "let `reqwest` keep its default."
/// These options are silently ignored when [`ClientBuilder::http_client`] is
/// used to inject a fully-built `reqwest::Client` — in that mode the caller
/// owns the transport configuration end to end. [`ClientBuilder::build`]
/// returns [`Error::Protocol`] if both a pre-built client and any transport
/// option are set, to avoid silent surprises.
///
/// The wasm32 fetch backend exposes none of these knobs (the browser owns
/// the connection pool, proxy, redirect and timeout policies), so on wasm32
/// `TransportConfig` is a zero-sized stub that is always "default" and
/// applies as a no-op.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, Default)]
struct TransportConfig {
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    tcp_nodelay: Option<bool>,
    tcp_keepalive: Option<Duration>,
    http2_keep_alive_interval: Option<Duration>,
    http2_keep_alive_timeout: Option<Duration>,
    http2_keep_alive_while_idle: Option<bool>,
    proxies: Vec<reqwest::Proxy>,
    no_proxy: bool,
    redirect: Option<RedirectPolicy>,
    gzip: Option<bool>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TransportConfig {
    fn is_default(&self) -> bool {
        self.timeout.is_none()
            && self.connect_timeout.is_none()
            && self.pool_idle_timeout.is_none()
            && self.pool_max_idle_per_host.is_none()
            && self.tcp_nodelay.is_none()
            && self.tcp_keepalive.is_none()
            && self.http2_keep_alive_interval.is_none()
            && self.http2_keep_alive_timeout.is_none()
            && self.http2_keep_alive_while_idle.is_none()
            && self.proxies.is_empty()
            && !self.no_proxy
            && self.redirect.is_none()
            && self.gzip.is_none()
    }

    fn apply(self, mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        // An explicit total timeout applies client-wide (including the
        // subscribe streams — the caller asked for it). When unset, the
        // bounded [`DEFAULT_REQUEST_TIMEOUT`] is applied *per request*
        // in `Client::request` instead, so long-lived streams stay open.
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        // reqwest's own default is *no* connect timeout at all; always
        // bound the connection-establishment phase so a SYN black hole
        // can never suspend a caller forever.
        builder = builder.connect_timeout(self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT));
        if let Some(pool_idle_timeout) = self.pool_idle_timeout {
            builder = builder.pool_idle_timeout(pool_idle_timeout);
        }
        if let Some(pool_max_idle_per_host) = self.pool_max_idle_per_host {
            builder = builder.pool_max_idle_per_host(pool_max_idle_per_host);
        }
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            builder = builder.tcp_nodelay(tcp_nodelay);
        }
        if let Some(tcp_keepalive) = self.tcp_keepalive {
            builder = builder.tcp_keepalive(tcp_keepalive);
        }
        if let Some(http2_keep_alive_interval) = self.http2_keep_alive_interval {
            builder = builder.http2_keep_alive_interval(http2_keep_alive_interval);
        }
        if let Some(http2_keep_alive_timeout) = self.http2_keep_alive_timeout {
            builder = builder.http2_keep_alive_timeout(http2_keep_alive_timeout);
        }
        if let Some(http2_keep_alive_while_idle) = self.http2_keep_alive_while_idle {
            builder = builder.http2_keep_alive_while_idle(http2_keep_alive_while_idle);
        }
        for proxy in self.proxies {
            builder = builder.proxy(proxy);
        }
        if self.no_proxy {
            builder = builder.no_proxy();
        }
        if let Some(redirect) = self.redirect {
            builder = builder.redirect(redirect.into_reqwest());
        }
        if let Some(gzip) = self.gzip {
            builder = builder.gzip(gzip);
        }
        builder
    }
}

/// Wasm32 stub for `TransportConfig`. The fetch backend doesn't expose any
/// of the native transport knobs, so this is a zero-sized type that always
/// reports "default" and applies as a no-op.
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Default)]
struct TransportConfig;

#[cfg(target_arch = "wasm32")]
impl TransportConfig {
    fn is_default(&self) -> bool {
        true
    }

    fn apply(self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
    }
}

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    base_url: Url,
    http: Option<reqwest::Client>,
    auth: Option<Auth>,
    http_message_signer: Option<HttpMessageSigner>,
    allow_insecure_localhost: bool,
    loopback_method_scope: Option<crate::service_method_resolution::LoopbackMethodScope>,
    transport: TransportConfig,
    retry: RetryConfig,
    user_agent: Option<String>,
}

impl ClientBuilder {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            http: None,
            auth: None,
            http_message_signer: None,
            allow_insecure_localhost: false,
            loopback_method_scope: None,
            transport: TransportConfig::default(),
            retry: RetryConfig::default(),
            user_agent: None,
        }
    }

    /// Inject a fully-built `reqwest::Client`. The caller owns transport
    /// configuration in this mode; mixing `http_client(...)` with any
    /// transport-shaping builder method (`timeout`, `proxy`, …) is a
    /// programming error and is rejected by [`Self::build`].
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn http_message_signer(mut self, signer: HttpMessageSigner) -> Self {
        self.http_message_signer = Some(signer);
        self
    }

    pub fn allow_insecure_localhost(mut self) -> Self {
        self.allow_insecure_localhost = true;
        self
    }

    /// Allow credential-free HTTPS DID method discovery in one local development
    /// DNS namespace and port. Only `localhost` and `local.host` are supported.
    /// Native DNS answers must all be loopback. Other targets retain public HTTPS
    /// policy. This scope is retained when the client changes its base URL.
    pub fn loopback_service_discovery(mut self, namespace: &str, port: u16) -> Result<Self> {
        self.loopback_method_scope = Some(
            crate::service_method_resolution::LoopbackMethodScope::new(namespace, port)?,
        );
        Ok(self)
    }

    /// Total timeout for a single request including the connect handshake,
    /// TLS, headers and body. Use [`Self::connect_timeout`] when you want a
    /// separate, shorter cap on the connection establishment phase.
    ///
    /// Native-only: the wasm32 fetch backend has no per-request timeout
    /// hook (the browser owns the timeline).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = Some(timeout);
        self
    }

    /// Cap the connection-establishment phase (TCP + TLS handshake) only.
    /// Independent of the total request timeout set via [`Self::timeout`].
    ///
    /// Native-only: there is no concept of a separate connect phase in the
    /// wasm32 fetch backend.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.transport.connect_timeout = Some(connect_timeout);
        self
    }

    /// Maximum idle time before a pooled connection is reaped. `None` means
    /// `reqwest`'s default. Set a value if your service is behind a proxy or
    /// load balancer with an aggressive idle-connection kill window.
    ///
    /// Native-only: the wasm32 fetch backend has no user-visible connection
    /// pool.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.transport.pool_idle_timeout = Some(pool_idle_timeout);
        self
    }

    /// Cap the number of idle connections kept open per remote host.
    ///
    /// Native-only: see [`Self::pool_idle_timeout`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.transport.pool_max_idle_per_host = Some(pool_max_idle_per_host);
        self
    }

    /// Enable / disable TCP_NODELAY on connections. Defaults to reqwest's
    /// choice (currently enabled).
    ///
    /// Native-only: the wasm32 fetch backend doesn't expose TCP-level knobs.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn tcp_nodelay(mut self, tcp_nodelay: bool) -> Self {
        self.transport.tcp_nodelay = Some(tcp_nodelay);
        self
    }

    /// Enable TCP keepalive with the given interval. Useful when the path
    /// includes long-lived NAT mappings or stateful firewalls that drop
    /// silent connections.
    ///
    /// Native-only: see [`Self::tcp_nodelay`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.transport.tcp_keepalive = Some(interval);
        self
    }

    /// Send an HTTP/2 PING frame at this interval.
    ///
    /// Native-only: HTTP/2 framing is invisible behind the browser fetch
    /// pipeline on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.transport.http2_keep_alive_interval = Some(interval);
        self
    }

    /// Drop the HTTP/2 connection if a PING is unanswered within this window.
    ///
    /// Native-only: see [`Self::http2_keep_alive_interval`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.transport.http2_keep_alive_timeout = Some(timeout);
        self
    }

    /// Whether to keep sending HTTP/2 PINGs while idle.
    ///
    /// Native-only: see [`Self::http2_keep_alive_interval`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.transport.http2_keep_alive_while_idle = Some(enabled);
        self
    }

    /// Route requests through an HTTP / HTTPS proxy. Multiple calls compose:
    /// `reqwest` evaluates proxies in order and falls through to no-proxy if
    /// none match. Pair with [`Self::no_proxy`] to disable system proxy
    /// detection from environment variables.
    ///
    /// Native-only: the browser owns proxy selection on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn proxy(mut self, proxy: reqwest::Proxy) -> Self {
        self.transport.proxies.push(proxy);
        self
    }

    /// Disable proxy auto-detection from environment variables
    /// (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`). Combine with
    /// [`Self::proxy`] for fully explicit routing in production.
    ///
    /// Native-only: see [`Self::proxy`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn no_proxy(mut self) -> Self {
        self.transport.no_proxy = true;
        self
    }

    /// Override the default redirect policy. The default is to follow up
    /// to 10 redirects; pass [`RedirectPolicy::None`] for service-to-service
    /// paths where redirect-following is a bug.
    ///
    /// Native-only: the browser handles redirects transparently on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.transport.redirect = Some(policy);
        self
    }

    /// Toggle gzip response decoding (the `gzip` feature is on by default
    /// in `arkret-http-client`'s `reqwest` profile, so this method exists to
    /// let callers turn it *off* when stricter content negotiation matters).
    ///
    /// Native-only: gzip negotiation is owned by the browser on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn gzip(mut self, enabled: bool) -> Self {
        self.transport.gzip = Some(enabled);
        self
    }

    /// Configure status / transport retry for the native `execute` path.
    ///
    /// # wasm32 behavior
    ///
    /// **Ignored on wasm32.** The browser fetch backend has no in-crate
    /// sleep primitive and no connect-error discrimination, so `execute()`
    /// always sends exactly once there and a configured `RetryConfig` is
    /// ignored. Layer retry above the client (e.g. via
    /// `wasm-bindgen-futures`) when running in the browser.
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    // `mut self` is only used by the native redirect-hardening block below;
    // on wasm32 the browser owns redirect/header-stripping so the binding is
    // intentionally unused there.
    #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
    pub fn build(mut self) -> Result<Client> {
        validate_base_url(&self.base_url, self.allow_insecure_localhost)?;
        if let Some(auth) = &self.auth {
            validate_auth(auth)?;
        }
        if let Some(user_agent) = &self.user_agent {
            validate_header_value("user agent", user_agent)?;
        }
        // DeviceProof / ServiceSignature credentials ride in custom headers
        // (`X-Arkret-Device-Proof`, `Signature` / `X-Arkret-Service-Signature`)
        // that reqwest does NOT strip across a cross-host redirect (its
        // sensitive-header allowlist only covers `Authorization` / `Cookie` /
        // `Proxy-Authorization`). Following a 3xx to an attacker-controlled
        // host would replay these device / service credentials to a third
        // party. Default such clients to never follow redirects unless the
        // caller explicitly chose a policy (Bearer is safe — reqwest strips
        // `Authorization` itself — so it keeps reqwest's default).
        #[cfg(not(target_arch = "wasm32"))]
        if self.http.is_none()
            && self.transport.redirect.is_none()
            && matches!(
                self.auth,
                Some(Auth::DeviceProof(_)) | Some(Auth::ServiceSignature(_)) | Some(Auth::Dpop(_))
            )
        {
            self.transport.redirect = Some(RedirectPolicy::None);
        }
        // Pre-built clients own their transport configuration end to end;
        // the per-request default timeout only kicks in when this builder
        // owns the transport and no explicit timeout was configured.
        #[cfg(not(target_arch = "wasm32"))]
        let default_timeout = if self.http.is_none() && self.transport.timeout.is_none() {
            Some(DEFAULT_REQUEST_TIMEOUT)
        } else {
            None
        };
        let http = match self.http {
            Some(http) => {
                if !self.transport.is_default() {
                    return Err(Error::Protocol(
                        "transport options conflict with a pre-built http_client; configure one or the other"
                            .to_owned(),
                    ));
                }
                http
            }
            None => {
                let builder = self.transport.apply(reqwest::Client::builder());
                #[cfg(not(target_arch = "wasm32"))]
                let builder = crate::tls_roots::apply_explicit_tls_roots(builder)?;
                builder.build().map_err(transport_error)?
            }
        };
        Ok(Client {
            base_url: self.base_url,
            http,
            auth: self.auth,
            own_station_context: None,
            http_message_signer: self.http_message_signer,
            service_signature_identity: None,
            managed_device_signature_identity: None,
            allow_insecure_localhost: self.allow_insecure_localhost,
            loopback_method_scope: self.loopback_method_scope,
            retry: self.retry,
            user_agent: self.user_agent,
            #[cfg(not(target_arch = "wasm32"))]
            default_timeout,
        })
    }
}
