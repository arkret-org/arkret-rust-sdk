//! Arkret v1 outbound egress guard bound to `reqwest`.
//!
//! [`arkret_egress_policy`] is the judgment primitive: it answers whether one
//! scheme, one host, one address or one DNS answer set is admissible. This
//! crate owns the composition that sits on top of it and that every Arkret
//! service otherwise reassembles by hand:
//!
//! 1. parse the target URL,
//! 2. judge its scheme and host before any lookup,
//! 3. resolve the host,
//! 4. judge every answer — one denied answer rejects the target,
//! 5. bind the surviving answers to the `reqwest` client, so a second lookup between validation and
//!    connect cannot rebind the host.
//!
//! [`EgressGuard::apply_to_client_builder`] installs the connect-time resolver
//! for clients that dispatch to many targets; [`LockedEgressUrl`] is the
//! per-target token for callers that pre-resolve one URL. A redirect is a new
//! target and must repeat the whole sequence, so clients are expected to be
//! built with `reqwest::redirect::Policy::none()`.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use arkret_egress_policy::{OutboundPolicy, PolicyError};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{ClientBuilder, Url};
use thiserror::Error;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Port assumed when a URL carries neither an explicit port nor a scheme with a
/// known default.
const FALLBACK_PORT: u16 = 443;

/// Which host names a deployment lets resolve to loopback addresses, beyond
/// what the base [`OutboundPolicy`] already permits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum LoopbackHostScope {
    /// No host-scoped exception; the base policy decides alone.
    #[default]
    PolicyOnly,
    /// The named hosts may resolve *wholly* to loopback. A mixed answer, a
    /// private address, or an unnamed host falls back to the base policy, so
    /// this can never widen the reachable address set for anything else.
    Trusted(Arc<HashSet<String>>),
    /// Only `localhost` and loopback IP literals are reachable at all, and they
    /// must resolve wholly to loopback. Used by debug and test-harness clients
    /// that must not be able to leave the machine.
    LoopbackOnly,
}

/// Structured, auditable egress rejection carrying the caller's purpose.
#[derive(Debug, Error)]
#[error("{purpose}: {kind}")]
pub struct EgressError {
    purpose: String,
    #[source]
    kind: EgressErrorKind,
}

impl EgressError {
    fn new(purpose: &str, kind: EgressErrorKind) -> Self {
        Self {
            purpose: purpose.to_owned(),
            kind,
        }
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn kind(&self) -> &EgressErrorKind {
        &self.kind
    }
}

/// Why an outbound target was rejected.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EgressErrorKind {
    #[error("invalid URL: {0}")]
    InvalidUrl(#[source] url::ParseError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("DNS resolution for {host} failed: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("egress host {host:?} is denied: only loopback destinations are reachable")]
    LoopbackOnlyHost { host: String },
    #[error("egress host {host:?} is denied: it did not resolve wholly to loopback")]
    LoopbackBinding { host: String },
}

/// The parse/judge/resolve/bind sequence for one outbound posture.
#[derive(Clone, Debug, Default)]
pub struct EgressGuard {
    policy: OutboundPolicy,
    loopback_hosts: LoopbackHostScope,
}

impl EgressGuard {
    /// Build a guard around an explicit policy.
    #[must_use]
    pub const fn new(policy: OutboundPolicy) -> Self {
        Self {
            policy,
            loopback_hosts: LoopbackHostScope::PolicyOnly,
        }
    }

    /// Production posture: HTTPS and globally routable addresses only.
    #[must_use]
    pub const fn public_https() -> Self {
        Self::new(OutboundPolicy::public_https())
    }

    /// Local development posture: plain HTTP permitted, loopback added to the
    /// production address set.
    #[must_use]
    pub const fn local_development() -> Self {
        Self::new(OutboundPolicy::local_development())
    }

    /// Name the hosts that may resolve wholly to loopback while every other
    /// host keeps the base posture.
    ///
    /// This is a deployment configuration item, not a per-service exemption: it
    /// exists because an operator-run reverse proxy commonly terminates TLS for
    /// a stable name such as `auth.local.host` on the same machine. An empty
    /// list is exactly [`LoopbackHostScope::PolicyOnly`], so the default
    /// changes nothing.
    #[must_use]
    pub fn with_trusted_loopback_https_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts: HashSet<String> = hosts
            .into_iter()
            .map(|host| normalize_host(host.as_ref()))
            .filter(|host| !host.is_empty())
            .collect();
        self.loopback_hosts = if hosts.is_empty() {
            LoopbackHostScope::PolicyOnly
        } else {
            LoopbackHostScope::Trusted(Arc::new(hosts))
        };
        self
    }

    /// Restrict this guard to loopback destinations only.
    #[must_use]
    pub fn loopback_only(mut self) -> Self {
        self.loopback_hosts = LoopbackHostScope::LoopbackOnly;
        self
    }

    #[must_use]
    pub const fn policy(&self) -> OutboundPolicy {
        self.policy
    }

    #[must_use]
    pub fn loopback_host_scope(&self) -> &LoopbackHostScope {
        &self.loopback_hosts
    }

    /// Judge a URL's scheme and host before any lookup.
    pub fn validate_url(&self, url: &Url, purpose: &str) -> Result<(), EgressError> {
        self.check_url(url)
            .map_err(|kind| EgressError::new(purpose, kind))
    }

    /// Judge a bare host name, as a connect-time DNS resolver sees it.
    pub fn validate_host(&self, host: &str, purpose: &str) -> Result<(), EgressError> {
        self.check_host(host)
            .map_err(|kind| EgressError::new(purpose, kind))
    }

    /// Judge a resolved answer set for `host`. One denied answer rejects the
    /// whole target, so a retry cannot hide a policy hit as DNS churn.
    pub fn validate_addresses(
        &self,
        host: &str,
        addresses: &[SocketAddr],
        purpose: &str,
    ) -> Result<(), EgressError> {
        self.check_addresses(host, addresses)
            .map_err(|kind| EgressError::new(purpose, kind))
    }

    /// Parse, judge, resolve and lock `raw_url` with the blocking system
    /// resolver.
    pub fn lock_str(&self, raw_url: &str, purpose: &str) -> Result<LockedEgressUrl, EgressError> {
        let url = parse_url(raw_url).map_err(|kind| EgressError::new(purpose, kind))?;
        self.lock_url(&url, purpose)
    }

    /// Judge, resolve and lock `url` with the blocking system resolver.
    pub fn lock_url(&self, url: &Url, purpose: &str) -> Result<LockedEgressUrl, EgressError> {
        let plan = self
            .plan(url)
            .map_err(|kind| EgressError::new(purpose, kind))?;
        let (host, port) = match plan {
            Plan::Literal { host, address } => {
                return self.bind(url, &host, None, vec![address], purpose);
            }
            Plan::Lookup { host, port } => (host, port),
        };
        let addresses = blocking_lookup(&host, port).map_err(|source| {
            EgressError::new(
                purpose,
                EgressErrorKind::Dns {
                    host: host.clone(),
                    source,
                },
            )
        })?;
        self.bind(url, &host, Some(host.clone()), addresses, purpose)
    }

    /// Parse, judge, resolve and lock `raw_url` on the async resolver.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn lock_str_async(
        &self,
        raw_url: &str,
        purpose: &str,
    ) -> Result<LockedEgressUrl, EgressError> {
        let url = parse_url(raw_url).map_err(|kind| EgressError::new(purpose, kind))?;
        self.lock_url_async(&url, purpose).await
    }

    /// Judge, resolve and lock `url` on the async resolver.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn lock_url_async(
        &self,
        url: &Url,
        purpose: &str,
    ) -> Result<LockedEgressUrl, EgressError> {
        let plan = self
            .plan(url)
            .map_err(|kind| EgressError::new(purpose, kind))?;
        let (host, port) = match plan {
            Plan::Literal { host, address } => {
                return self.bind(url, &host, None, vec![address], purpose);
            }
            Plan::Lookup { host, port } => (host, port),
        };
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|source| {
                EgressError::new(
                    purpose,
                    EgressErrorKind::Dns {
                        host: host.clone(),
                        source,
                    },
                )
            })?
            .collect();
        self.bind(url, &host, Some(host.clone()), addresses, purpose)
    }

    /// Judge, resolve and lock `url` using a caller-supplied resolver.
    ///
    /// Deployments that resolve through their own stub resolver, or tests that
    /// inject a fixed answer set, still get the full judgment sequence.
    pub fn lock_url_with<F>(
        &self,
        url: &Url,
        purpose: &str,
        resolve: F,
    ) -> Result<LockedEgressUrl, EgressError>
    where
        F: FnOnce(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
    {
        let plan = self
            .plan(url)
            .map_err(|kind| EgressError::new(purpose, kind))?;
        let (host, port) = match plan {
            Plan::Literal { host, address } => {
                return self.bind(url, &host, None, vec![address], purpose);
            }
            Plan::Lookup { host, port } => (host, port),
        };
        let addresses = resolve(&host, port).map_err(|source| {
            EgressError::new(
                purpose,
                EgressErrorKind::Dns {
                    host: host.clone(),
                    source,
                },
            )
        })?;
        self.bind(url, &host, Some(host.clone()), addresses, purpose)
    }

    /// The connect-time DNS resolver enforcing this guard.
    #[must_use]
    pub fn resolver(&self) -> Arc<GuardedDnsResolver> {
        Arc::new(GuardedDnsResolver {
            guard: self.clone(),
        })
    }

    /// Install this guard's scheme restriction and connect-time resolver.
    #[must_use]
    pub fn apply_to_client_builder(&self, builder: ClientBuilder) -> ClientBuilder {
        builder
            .https_only(!self.policy.allows_http())
            .dns_resolver(self.resolver())
    }

    fn check_url(&self, url: &Url) -> Result<(), EgressErrorKind> {
        let host = url
            .host_str()
            .filter(|host| !host.trim().is_empty())
            .ok_or(PolicyError::MissingHost)?;
        if self.loopback_hosts == LoopbackHostScope::LoopbackOnly
            && !is_explicit_loopback_host(host)
        {
            return Err(EgressErrorKind::LoopbackOnlyHost {
                host: host.to_owned(),
            });
        }
        self.policy.validate_url(url)?;
        Ok(())
    }

    fn check_host(&self, host: &str) -> Result<(), EgressErrorKind> {
        if self.loopback_hosts == LoopbackHostScope::LoopbackOnly
            && !is_explicit_loopback_host(host)
        {
            return Err(EgressErrorKind::LoopbackOnlyHost {
                host: host.to_owned(),
            });
        }
        self.policy.validate_host(host)?;
        Ok(())
    }

    fn check_addresses(&self, host: &str, addresses: &[SocketAddr]) -> Result<(), EgressErrorKind> {
        match &self.loopback_hosts {
            LoopbackHostScope::LoopbackOnly => {
                if addresses.is_empty() {
                    return Err(PolicyError::NoAddresses.into());
                }
                if addresses.iter().any(|address| !address.ip().is_loopback()) {
                    return Err(EgressErrorKind::LoopbackBinding {
                        host: host.to_owned(),
                    });
                }
                return Ok(());
            }
            // A named host that resolves wholly to loopback is admitted here.
            // Anything else — an unnamed host, an empty answer, a mixed answer
            // or a private address — falls through to the base policy, which is
            // why this scope can never widen the reachable address set.
            LoopbackHostScope::Trusted(hosts)
                if hosts.contains(&normalize_host(host))
                    && !addresses.is_empty()
                    && addresses.iter().all(|address| address.ip().is_loopback()) =>
            {
                return Ok(());
            }
            _ => {}
        }
        self.policy.validate_resolved_addresses(addresses)?;
        Ok(())
    }

    fn plan(&self, url: &Url) -> Result<Plan, EgressErrorKind> {
        self.check_url(url)?;
        let host = url.host_str().ok_or(PolicyError::MissingHost)?.to_owned();
        let port = url.port_or_known_default().unwrap_or(FALLBACK_PORT);
        match literal_host_ip(url) {
            Some(ip) => Ok(Plan::Literal {
                host,
                address: SocketAddr::new(ip, port),
            }),
            None => Ok(Plan::Lookup { host, port }),
        }
    }

    fn bind(
        &self,
        url: &Url,
        host: &str,
        resolve_host: Option<String>,
        addresses: Vec<SocketAddr>,
        purpose: &str,
    ) -> Result<LockedEgressUrl, EgressError> {
        self.check_addresses(host, &addresses)
            .map_err(|kind| EgressError::new(purpose, kind))?;
        Ok(LockedEgressUrl {
            url: url.clone(),
            resolve_host,
            addresses,
        })
    }
}

enum Plan {
    Literal { host: String, address: SocketAddr },
    Lookup { host: String, port: u16 },
}

/// A judged URL plus the complete validated answer set to pin to a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedEgressUrl {
    url: Url,
    /// `None` for address literals, which need no DNS override.
    resolve_host: Option<String>,
    addresses: Vec<SocketAddr>,
}

impl LockedEgressUrl {
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Every validated address for the target, including the literal address of
    /// an IP-literal URL.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// The host and answer set to pin, or `None` when the URL was an address
    /// literal and no override is needed.
    #[must_use]
    pub fn dns_override(&self) -> Option<(&str, &[SocketAddr])> {
        match self.resolve_host.as_deref() {
            Some(host) if !self.addresses.is_empty() => Some((host, &self.addresses)),
            _ => None,
        }
    }

    /// Pin the validated answer set so a second lookup cannot rebind the host.
    #[must_use]
    pub fn apply_to_client_builder(&self, builder: ClientBuilder) -> ClientBuilder {
        match self.dns_override() {
            Some((host, addresses)) => builder.resolve_to_addrs(host, addresses),
            None => builder,
        }
    }
}

/// Connect-time resolver that judges the host before lookup and every answer
/// after it.
#[derive(Clone, Debug)]
pub struct GuardedDnsResolver {
    guard: EgressGuard,
}

impl GuardedDnsResolver {
    #[must_use]
    pub fn new(guard: EgressGuard) -> Self {
        Self { guard }
    }
}

impl Resolve for GuardedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.guard.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            guard
                .check_host(&host)
                .map_err(|kind| boxed(EgressError::new("egress DNS resolver", kind)))?;
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|source| {
                    boxed(EgressError::new(
                        "egress DNS resolver",
                        EgressErrorKind::Dns {
                            host: host.clone(),
                            source,
                        },
                    ))
                })?
                .collect();
            guard
                .check_addresses(&host, &addresses)
                .map_err(|kind| boxed(EgressError::new("egress DNS resolver", kind)))?;
            let resolved: Addrs = Box::new(addresses.into_iter());
            Ok(resolved)
        })
    }
}

/// The address literal in `url`'s host, if the host is one.
#[must_use]
pub fn literal_host_ip(url: &Url) -> Option<IpAddr> {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        _ => None,
    }
}

/// Lower-case a host and drop its root label so comparisons are stable.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_explicit_loopback_host(host: &str) -> bool {
    let host = normalize_host(host);
    host == "localhost"
        || host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(&host)
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn parse_url(raw_url: &str) -> Result<Url, EgressErrorKind> {
    Url::parse(raw_url).map_err(EgressErrorKind::InvalidUrl)
}

fn blocking_lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(Iterator::collect)
}

fn boxed(error: EgressError) -> BoxError {
    Box::new(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(raw: &str) -> SocketAddr {
        raw.parse().expect("socket address")
    }

    #[test]
    fn production_rejects_http_and_non_public_targets() {
        let guard = EgressGuard::public_https();
        for raw in [
            "http://93.184.216.34/path",
            "https://127.0.0.1:8080/sink",
            "https://10.0.0.2/.well-known/did.json",
            "https://169.254.169.254/latest/meta-data",
            "https://[fd00::1]/sink",
            "https://198.18.0.1/path",
            "https://192.0.2.1/path",
            "https://localhost/sink",
            "https://metadata.google.internal/sink",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(guard.validate_url(&url, "test").is_err(), "{raw}");
        }
    }

    #[test]
    fn production_rejects_all_transition_forms() {
        let guard = EgressGuard::public_https();
        for raw in [
            "https://[64:ff9b::a9fe:a9fe]/latest/meta-data",
            "https://[2002:0a00:0001::]/sink",
            "https://[::ffff:10.0.0.1]/sink",
            "https://[2001:0000:7f00:0001:0000:0000:3f57:fefe]/sink",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(guard.validate_url(&url, "test").is_err(), "{raw}");
        }
    }

    #[test]
    fn development_only_adds_http_loopback() {
        let guard = EgressGuard::local_development();
        assert!(
            guard
                .validate_url(&Url::parse("http://127.0.0.1:8080/sink").unwrap(), "test")
                .is_ok()
        );
        assert!(
            guard
                .validate_url(&Url::parse("http://10.0.0.1:8080/sink").unwrap(), "test")
                .is_err()
        );
    }

    #[test]
    fn error_message_carries_the_caller_purpose() {
        let guard = EgressGuard::public_https();
        let error = guard
            .validate_url(
                &Url::parse("https://127.0.0.1/x").unwrap(),
                "did resolution",
            )
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.starts_with("did resolution: "), "{rendered}");
        assert!(rendered.contains("loopback address"), "{rendered}");
    }

    #[test]
    fn ip_literal_needs_no_dns_override() {
        let guard = EgressGuard::public_https();
        let url = Url::parse("https://93.184.216.34/path").unwrap();
        let target = guard.lock_url(&url, "test").unwrap();

        assert_eq!(target.url().as_str(), "https://93.184.216.34/path");
        assert!(target.dns_override().is_none());
        assert_eq!(target.addresses(), [addr("93.184.216.34:443")]);
    }

    #[test]
    fn injected_resolver_answers_are_judged_individually() {
        let guard = EgressGuard::public_https();
        let url = Url::parse("https://relay.example/federation").unwrap();

        let ok = guard
            .lock_url_with(&url, "test", |_host, port| {
                Ok(vec![SocketAddr::new(
                    "93.184.216.34".parse().unwrap(),
                    port,
                )])
            })
            .unwrap();
        assert_eq!(ok.dns_override().unwrap().0, "relay.example");

        let error = guard
            .lock_url_with(&url, "test", |_host, port| {
                Ok(vec![
                    SocketAddr::new("93.184.216.34".parse().unwrap(), port),
                    SocketAddr::new("127.0.0.1".parse().unwrap(), port),
                ])
            })
            .unwrap_err();
        assert!(error.to_string().contains("loopback"), "{error}");

        let empty = guard
            .lock_url_with(&url, "test", |_host, _port| Ok(Vec::new()))
            .unwrap_err();
        assert!(empty.to_string().contains("no addresses"), "{empty}");
    }

    #[test]
    fn trusted_host_admits_only_exact_name_and_whole_loopback_answer() {
        let guard = EgressGuard::public_https().with_trusted_loopback_https_hosts(["local.host"]);
        let loopback = [addr("127.0.0.1:443")];

        assert!(
            guard
                .validate_addresses("LOCAL.HOST.", &loopback, "test")
                .is_ok()
        );
        assert!(
            guard
                .validate_addresses("other.host", &loopback, "test")
                .is_err()
        );
        assert!(
            guard
                .validate_addresses("local.host", &[addr("192.168.1.10:443")], "test")
                .is_err()
        );
        assert!(
            guard
                .validate_addresses(
                    "local.host",
                    &[addr("127.0.0.1:443"), addr("8.8.8.8:443")],
                    "test",
                )
                .is_err()
        );
        assert!(guard.validate_addresses("local.host", &[], "test").is_err());
    }

    #[test]
    fn trusted_host_that_resolves_publicly_keeps_the_base_posture() {
        let guard = EgressGuard::public_https().with_trusted_loopback_https_hosts(["auth.example"]);
        assert!(
            guard
                .validate_addresses("auth.example", &[addr("93.184.216.34:443")], "test")
                .is_ok()
        );
    }

    #[test]
    fn trusted_hosts_never_admit_a_denied_host_class() {
        let guard = EgressGuard::public_https()
            .with_trusted_loopback_https_hosts(["gateway.internal", "localhost"]);
        assert!(guard.validate_host("gateway.internal", "test").is_err());
        assert!(guard.validate_host("localhost", "test").is_err());
    }

    #[test]
    fn empty_trusted_list_is_the_default_scope() {
        let guard =
            EgressGuard::public_https().with_trusted_loopback_https_hosts(Vec::<String>::new());
        assert_eq!(guard.loopback_host_scope(), &LoopbackHostScope::PolicyOnly);
    }

    #[test]
    fn loopback_only_scope_admits_nothing_off_machine() {
        let guard = EgressGuard::local_development().loopback_only();

        assert!(
            guard
                .validate_url(&Url::parse("http://127.0.0.1:8080/x").unwrap(), "test")
                .is_ok()
        );
        assert!(
            guard
                .validate_url(&Url::parse("http://localhost:8080/x").unwrap(), "test")
                .is_ok()
        );
        assert!(
            guard
                .validate_url(&Url::parse("http://example.com/x").unwrap(), "test")
                .is_err()
        );
        assert!(guard.validate_host("example.com", "test").is_err());
        assert!(
            guard
                .validate_addresses("localhost", &[addr("8.8.8.8:80")], "test")
                .is_err()
        );
        assert!(
            guard
                .validate_addresses("localhost", &[addr("127.0.0.1:80")], "test")
                .is_ok()
        );
    }

    #[tokio::test]
    async fn async_lock_pins_a_loopback_development_target() {
        let guard = EgressGuard::local_development();
        let url = Url::parse("http://localhost:8080/sink").unwrap();
        let target = guard.lock_url_async(&url, "test").await.unwrap();

        let (host, addresses) = target.dns_override().expect("named host is pinned");
        assert_eq!(host, "localhost");
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
        assert!(addresses.iter().any(|address| address.port() == 8080));
    }
}
