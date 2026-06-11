use std::net::{IpAddr, Ipv6Addr};

use super::*;
pub(super) use crate::canonical::sha256_hex;

/// SSRF guard: reject hosts that resolve to non-public address space before
/// the SDK makes an outbound `did:web` / `did:webvh` fetch.
///
/// DIDs may be supplied by untrusted peers (handshakes, invites, directory
/// responses), so a host like `169.254.169.254` (cloud metadata),
/// `127.0.0.1`, or `10.x.x.x` must never trigger an internal request. Bare
/// `localhost` is also blocked. Registered domain names are allowed (DNS
/// rebinding is out of scope for this static check).
pub(super) fn host_is_safe_for_outbound(host: &str) -> bool {
    let candidate = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = candidate.parse::<IpAddr>() {
        return ip_is_public(ip);
    }
    if candidate.eq_ignore_ascii_case("localhost")
        || candidate.to_ascii_lowercase().ends_with(".localhost")
    {
        return false;
    }
    true
}

fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_documentation()
            || v4.is_unspecified()
            || v4.is_multicast()
            // Carrier-grade NAT shared range 100.64.0.0/10.
            || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_public(IpAddr::V4(mapped));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ipv6_unique_local(v6)
                || is_ipv6_unicast_link_local(v6))
        }
    }
}

fn is_ipv6_unique_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

pub(super) fn split_domain_handle(handle: &str) -> Result<(String, String)> {
    let normalized = normalize_handle(handle);
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(Error::Protocol("handle proof requires local@domain form".to_owned()));
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || local.contains('/')
        || domain.contains('/')
        || domain.contains("..")
    {
        return Err(Error::Protocol("invalid domain handle".to_owned()));
    }
    Ok((local.to_owned(), domain.to_owned()))
}

pub(super) fn normalize_handle(handle: &str) -> String {
    handle.trim().trim_start_matches('@').to_lowercase()
}

pub(super) fn did_web_document_url(did: &Did) -> Option<String> {
    if did.method() != "web" {
        return None;
    }
    let method_id = did.as_str().strip_prefix("did:web:")?;
    if method_id.is_empty() || method_id.contains("//") || method_id.contains('?') {
        return None;
    }
    let parts = method_id.split(':').collect::<Vec<_>>();
    let host = parts.first()?;
    if host.is_empty() || !host.contains('.') || host.contains('/') {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return None;
    }
    if !host_is_safe_for_outbound(host) {
        return None;
    }
    if parts.len() == 1 {
        return Some(format!("https://{host}/.well-known/did.json"));
    }
    if parts[1..].iter().any(|part| part.is_empty() || part.contains('/') || part.contains("..")) {
        return None;
    }
    Some(format!("https://{host}/{}/did.json", parts[1..].join("/")))
}

pub(super) fn is_allowed_did_web_content_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(media_type.as_str(), "application/did+json" | "application/json")
}

/// Split a `did:webvh:<scid>:<host>[%3A<port>][:<path>…]` DID into its
/// component parts: `(scid, host, port, path_segments)`.
///
/// Returns `None` for any non-`did:webvh` input or malformed component
/// (empty scid/host, or a path segment containing `/` or `..`). 公开拆分
/// 助手:供 starid 等下游直接解析 did:webvh,无需经过 SDK 内部。
pub fn did_webvh_parts(did: &Did) -> Option<(String, String, Option<u16>, Vec<String>)> {
    let method_id = did.as_str().strip_prefix("did:webvh:")?;
    let mut parts = method_id.split(':');
    let scid = parts.next()?.to_owned();
    if scid.is_empty() {
        return None;
    }
    let host_raw = parts.next()?;
    if host_raw.is_empty() {
        return None;
    }
    let (host, port) = if let Some(idx) = host_raw.find("%3A").or_else(|| host_raw.find("%3a")) {
        let host = host_raw[..idx].to_owned();
        let port_str = &host_raw[idx + 3..];
        let port = port_str.parse::<u16>().ok()?;
        (host, Some(port))
    } else {
        (host_raw.to_owned(), None)
    };
    let path = parts.map(ToOwned::to_owned).collect::<Vec<_>>();
    if path
        .iter()
        .any(|segment| segment.is_empty() || segment.contains('/') || segment.contains(".."))
    {
        return None;
    }
    Some((scid, host, port, path))
}

pub(super) fn did_webvh_scid(did: &Did) -> Option<String> {
    did_webvh_parts(did).map(|(scid, _, _, _)| scid)
}

pub(super) fn did_webvh_document_url(did: &Did) -> Option<String> {
    did_webvh_url(did, "did.json")
}

pub(super) fn did_webvh_log_url(did: &Did) -> Option<String> {
    did_webvh_url(did, "did.jsonl")
}

pub(super) fn did_webvh_url(did: &Did, leaf: &str) -> Option<String> {
    let (_, host, port, path) = did_webvh_parts(did)?;
    if !host.contains('.') {
        return None;
    }
    if !host_is_safe_for_outbound(&host) {
        return None;
    }
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    if path.is_empty() {
        Some(format!("https://{authority}/.well-known/{leaf}"))
    } else {
        Some(format!("https://{authority}/{}/{leaf}", path.join("/")))
    }
}

pub(super) fn did_key_material(did: &Did) -> Option<String> {
    let method_id = did.as_str().strip_prefix("did:key:")?;
    let encoded = method_id.strip_prefix('z')?;
    let decoded = decode_base58btc(encoded)?;
    if !is_supported_did_key_multicodec(&decoded) {
        return None;
    }
    Some(method_id.to_owned())
}

/// Decode a base58btc (Bitcoin alphabet) string, returning `None` on any
/// invalid character. Thin wrapper over the single `core::multibase`
/// primitive (backed by the `bs58` crate) so the `did:key` / `did:webvh`
/// paths share one base58 implementation.
pub(crate) fn decode_base58btc(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    cokret_core::decode_base58btc(input).ok()
}

/// Encode `bytes` as a base58btc string (Bitcoin alphabet, no multibase
/// `z` prefix). Inverse of [`decode_base58btc`]. Used by the `did:webvh`
/// SCID / entry-hash derivation, which wraps a SHA-256 multihash in
/// base58btc. Delegates to the single `core::multibase` encoder.
pub(crate) fn encode_base58btc(bytes: &[u8]) -> String {
    cokret_core::encode_base58btc(bytes)
}

/// Wrap a SHA-256 digest of `canonical_bytes` in a multihash envelope
/// (`0x12 0x20` = sha2-256 + 32-byte length) and return the
/// **multibase** `z`-prefixed base58btc string. This is the form
/// `did:webvh` v1.0 uses for both the SCID and per-entry hashes.
pub(crate) fn webvh_multihash_base58(canonical_bytes: &[u8]) -> String {
    let digest = Sha256::digest(canonical_bytes);
    let mut envelope = Vec::with_capacity(2 + digest.len());
    envelope.push(0x12); // sha2-256 multihash code
    envelope.push(0x20); // 32-byte digest length
    envelope.extend_from_slice(&digest);
    format!("z{}", encode_base58btc(&envelope))
}

pub(super) fn is_supported_did_key_multicodec(bytes: &[u8]) -> bool {
    // multicodec varint parsing reuses the single `core::multibase` helper.
    let Some((code, offset)) = cokret_core::decode_multicodec_varint(bytes) else {
        return false;
    };
    let key = &bytes[offset..];
    match code {
        0xec | 0xed => key.len() == 32,           // X25519-pub / Ed25519-pub
        0xe7 | 0x1200 => key.len() == 33,         // secp256k1-pub / P-256-pub
        0x1201 => key.len() == 49,                // P-384-pub
        0x1202 => (66..=67).contains(&key.len()), // P-521-pub
        0x1205 => key.len() >= 64,                // RSA-pub
        _ => false,
    }
}

