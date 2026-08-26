//! Arkret v1 outbound network target policy.
//!
//! The policy is deliberately independent of an HTTP client or async runtime.
//! Callers validate a URL before DNS resolution and validate every A/AAAA
//! answer before connecting.
//! Redirects and other target changes must repeat the complete sequence.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;
use url::Url;

/// A non-public address category rejected by the Arkret v1 default policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AddressClass {
    Unspecified,
    Loopback,
    Private,
    LinkLocal,
    CarrierGradeNat,
    Benchmark,
    ProtocolAssignment,
    Documentation,
    Multicast,
    Reserved,
    Broadcast,
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "unspecified address",
            Self::Loopback => "loopback address",
            Self::Private => "private address",
            Self::LinkLocal => "link-local address",
            Self::CarrierGradeNat => "carrier-grade NAT address",
            Self::Benchmark => "benchmark address",
            Self::ProtocolAssignment => "protocol-assignment address",
            Self::Documentation => "documentation address",
            Self::Multicast => "multicast address",
            Self::Reserved => "reserved address",
            Self::Broadcast => "broadcast address",
        })
    }
}

/// Which classified address exceptions a deployment explicitly grants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AddressExceptions {
    /// Only globally routable public addresses are accepted.
    #[default]
    None,
    /// Local development may connect to loopback only.
    Loopback,
    /// A caller-verified, target-scoped deployment exception admits all
    /// non-public classes except metadata/link-local destinations.
    ControlledNetwork,
}

impl AddressExceptions {
    fn permits(self, class: AddressClass) -> bool {
        match self {
            Self::None => false,
            Self::Loopback => class == AddressClass::Loopback,
            Self::ControlledNetwork => matches!(
                class,
                AddressClass::Loopback | AddressClass::Private | AddressClass::CarrierGradeNat
            ),
        }
    }
}

/// Scheme and address policy applied to one outbound target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutboundPolicy {
    allow_http: bool,
    address_exceptions: AddressExceptions,
}

impl OutboundPolicy {
    /// Default production policy: HTTPS and public addresses only.
    #[must_use]
    pub const fn public_https() -> Self {
        Self {
            allow_http: false,
            address_exceptions: AddressExceptions::None,
        }
    }

    /// Local development policy: HTTP is allowed, but only loopback is added
    /// to the production address set.
    #[must_use]
    pub const fn local_development() -> Self {
        Self {
            allow_http: true,
            address_exceptions: AddressExceptions::Loopback,
        }
    }

    /// Construct a target-scoped controlled-network exception.
    ///
    /// The caller must first match the configured purpose, service identity,
    /// trust domain, host/CIDR, port, expiry, and audit requirements. Link-local
    /// metadata destinations remain impossible to admit through this profile.
    #[must_use]
    pub const fn controlled_network(allow_http: bool) -> Self {
        Self {
            allow_http,
            address_exceptions: AddressExceptions::ControlledNetwork,
        }
    }

    /// Whether plain `http` targets are admissible under this policy.
    #[must_use]
    pub const fn allows_http(self) -> bool {
        self.allow_http
    }

    /// Validate scheme and host before DNS resolution.
    pub fn validate_url(self, url: &Url) -> Result<(), PolicyError> {
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            scheme => return Err(PolicyError::SchemeDenied(scheme.to_owned())),
        }
        let host = url
            .host_str()
            .filter(|host| !host.trim().is_empty())
            .ok_or(PolicyError::MissingHost)?;
        self.validate_host(host)
    }

    /// Validate a host name or address literal on its own.
    ///
    /// This is the host half of [`Self::validate_url`], split out so a
    /// connect-time DNS resolver — which is handed a bare host name and never
    /// sees the URL — judges the name by exactly the same rules.
    pub fn validate_host(self, host: &str) -> Result<(), PolicyError> {
        let host = host.trim();
        if host.is_empty() {
            return Err(PolicyError::MissingHost);
        }
        if let Some(reason) = classify_host(host) {
            let exception_applies = match reason {
                "localhost name" => self.address_exceptions.permits(AddressClass::Loopback),
                "internal-only DNS suffix" => {
                    self.address_exceptions == AddressExceptions::ControlledNetwork
                }
                _ => false,
            };
            if !exception_applies {
                return Err(PolicyError::HostDenied {
                    host: host.to_owned(),
                    reason,
                });
            }
        }
        if let Ok(ip) = strip_ipv6_brackets(host).parse::<IpAddr>() {
            self.validate_ip(ip)?;
        }
        Ok(())
    }

    /// Validate one address selected by a connector.
    pub fn validate_ip(self, ip: IpAddr) -> Result<(), PolicyError> {
        if let Some(class) = classify_ip(ip)
            && !self.address_exceptions.permits(class)
        {
            return Err(PolicyError::AddressDenied { ip, class });
        }
        Ok(())
    }

    /// Validate all addresses produced by a connect-time resolver.
    pub fn validate_resolved_addresses(self, addresses: &[SocketAddr]) -> Result<(), PolicyError> {
        if addresses.is_empty() {
            return Err(PolicyError::NoAddresses);
        }
        for address in addresses {
            self.validate_ip(address.ip())?;
        }
        Ok(())
    }
}

/// Structured, auditable rejection produced by the shared policy.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("URL scheme {0:?} is not allowed")]
    SchemeDenied(String),
    #[error("URL host is required")]
    MissingHost,
    #[error("egress host {host:?} is denied: {reason}")]
    HostDenied { host: String, reason: &'static str },
    #[error("egress address {ip} is denied: {class}")]
    AddressDenied { ip: IpAddr, class: AddressClass },
    #[error("DNS resolution returned no addresses")]
    NoAddresses,
}

/// Return the default-policy class for a non-public address.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> Option<AddressClass> {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

/// Return a blocked well-known DNS-name category.
#[must_use]
pub fn classify_host(host: &str) -> Option<&'static str> {
    let host = strip_ipv6_brackets(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("localhost name");
    }
    if host == "metadata.google.internal" {
        return Some("cloud metadata name");
    }
    if matches!(
        host.rsplit_once('.').map(|(_, suffix)| suffix),
        Some("local" | "internal")
    ) {
        return Some("internal-only DNS suffix");
    }
    None
}

fn classify_ipv4(ip: Ipv4Addr) -> Option<AddressClass> {
    let [a, b, c, d] = ip.octets();
    if a == 0 {
        Some(AddressClass::Unspecified)
    } else if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        Some(AddressClass::Private)
    } else if a == 100 && (64..=127).contains(&b) {
        Some(AddressClass::CarrierGradeNat)
    } else if a == 127 {
        Some(AddressClass::Loopback)
    } else if a == 169 && b == 254 {
        Some(AddressClass::LinkLocal)
    } else if a == 192 && b == 0 && c == 0 {
        Some(AddressClass::ProtocolAssignment)
    } else if (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        Some(AddressClass::Documentation)
    } else if a == 198 && (b == 18 || b == 19) {
        Some(AddressClass::Benchmark)
    } else if (224..=239).contains(&a) {
        Some(AddressClass::Multicast)
    } else if a >= 240 && !(a == 255 && b == 255 && c == 255 && d == 255) {
        Some(AddressClass::Reserved)
    } else if ip == Ipv4Addr::BROADCAST {
        Some(AddressClass::Broadcast)
    } else {
        None
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> Option<AddressClass> {
    let segments = ip.segments();
    if ip.is_unspecified() {
        return Some(AddressClass::Unspecified);
    }
    if ip.is_loopback() {
        return Some(AddressClass::Loopback);
    }
    if ip.is_multicast() {
        return Some(AddressClass::Multicast);
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some(AddressClass::Private);
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some(AddressClass::LinkLocal);
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some(AddressClass::Documentation);
    }
    if let Some(v4) = compatible_ipv4(ip) {
        return classify_ipv4(v4);
    }
    if let Some(v4) = mapped_ipv4(ip) {
        return classify_ipv4(v4);
    }
    if let Some(v4) = nat64_ipv4(ip) {
        return classify_ipv4(v4);
    }
    if let Some(v4) = sixtofour_ipv4(ip) {
        return classify_ipv4(v4);
    }
    if let Some((server, client)) = teredo_ipv4(ip) {
        return classify_ipv4(server).or_else(|| classify_ipv4(client));
    }
    None
}

fn compatible_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    (segments[..6] == [0; 6]).then(|| words_to_ipv4(segments[6], segments[7]))
}

fn mapped_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    ip.to_ipv4_mapped()
}

fn nat64_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    (s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0]).then(|| words_to_ipv4(s[6], s[7]))
}

fn sixtofour_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    (s[0] == 0x2002).then(|| words_to_ipv4(s[1], s[2]))
}

fn teredo_ipv4(ip: Ipv6Addr) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let s = ip.segments();
    (s[0] == 0x2001 && s[1] == 0).then(|| {
        let server = words_to_ipv4(s[2], s[3]);
        let client = words_to_ipv4(!s[6], !s[7]);
        (server, client)
    })
}

fn words_to_ipv4(high: u16, low: u16) -> Ipv4Addr {
    let high = high.to_be_bytes();
    let low = low.to_be_bytes();
    Ipv4Addr::new(high[0], high[1], low[0], low[1])
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_normative_ipv4_category() {
        for raw in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let ip = raw.parse::<IpAddr>().unwrap();
            assert!(classify_ip(ip).is_some(), "{raw} must be denied");
        }
    }

    #[test]
    fn rejects_ipv6_and_transition_categories() {
        for raw in [
            "::",
            "::1",
            "::127.0.0.1",
            "::10.0.0.1",
            "::ffff:10.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
            "64:ff9b::a9fe:a9fe",
            "2002:0a00:0001::",
            "2001:0000:7f00:0001:0000:0000:3f57:fefe",
        ] {
            let ip = raw.parse::<IpAddr>().unwrap();
            assert!(classify_ip(ip).is_some(), "{raw} must be denied");
        }
    }

    #[test]
    fn production_is_https_only_and_fail_closed() {
        let policy = OutboundPolicy::public_https();
        let http = Url::parse("http://93.184.216.34/path").unwrap();
        assert!(matches!(
            policy.validate_url(&http),
            Err(PolicyError::SchemeDenied(_))
        ));

        let https = Url::parse("https://example.com/path").unwrap();
        let addrs = vec!["93.184.216.34:443".parse().unwrap()];
        assert!(policy.validate_url(&https).is_ok());
        assert!(policy.validate_resolved_addresses(&addrs).is_ok());
    }

    #[test]
    fn one_denied_dns_answer_rejects_the_whole_binding() {
        let addrs = vec![
            "93.184.216.34:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(matches!(
            OutboundPolicy::public_https().validate_resolved_addresses(&addrs),
            Err(PolicyError::AddressDenied { .. })
        ));
    }

    #[test]
    fn development_only_adds_http_loopback() {
        let url = Url::parse("http://127.0.0.1:8080/path").unwrap();
        let addrs = vec!["127.0.0.1:8080".parse().unwrap()];
        assert!(
            OutboundPolicy::local_development()
                .validate_url(&url)
                .is_ok()
        );
        assert!(
            OutboundPolicy::local_development()
                .validate_resolved_addresses(&addrs)
                .is_ok()
        );
        assert!(
            OutboundPolicy::local_development()
                .validate_ip("10.0.0.1".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn transition_addresses_with_public_embedded_ips_are_public() {
        for raw in ["::8.8.8.8", "64:ff9b::808:808", "2002:0808:0808::"] {
            assert!(classify_ip(raw.parse().unwrap()).is_none(), "{raw}");
        }
    }

    #[test]
    fn validate_host_matches_the_host_half_of_validate_url() {
        let policy = OutboundPolicy::public_https();
        for host in [
            "localhost",
            "metadata.google.internal",
            "api.internal",
            "::1",
        ] {
            assert!(policy.validate_host(host).is_err(), "{host}");
        }
        assert!(policy.validate_host("example.com").is_ok());
        assert!(policy.validate_host("[::1]").is_err());
        assert!(policy.validate_host("").is_err());
        assert!(
            OutboundPolicy::local_development()
                .validate_host("localhost")
                .is_ok()
        );
    }

    #[test]
    fn controlled_network_exception_does_not_admit_special_ranges() {
        let policy = OutboundPolicy::controlled_network(false);
        assert!(policy.validate_ip("10.0.0.1".parse().unwrap()).is_ok());
        for raw in [
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(policy.validate_ip(raw.parse().unwrap()).is_err(), "{raw}");
        }
    }
}
