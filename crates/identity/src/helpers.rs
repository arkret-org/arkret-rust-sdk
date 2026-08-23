use std::net::IpAddr;

use arkret_wire::DidFullId;

/// SSRF host classification shared by request-layer egress guards.
///
/// DIDs may be supplied by untrusted peers (handshakes, invites, directory
/// responses), so a host like `169.254.169.254` (cloud metadata),
/// `127.0.0.1`, or `10.x.x.x` must never trigger an internal request. Bare
/// `localhost` is also blocked. Registered domain names are allowed by this
/// static helper; outbound clients must additionally use
/// `arkret_egress_policy::OutboundPolicy` for scheme, DNS-answer, and
/// connection-binding checks.
///
/// This is a request-layer judgment: the `did:web` / `did:webvh` URL
/// derivation helpers are pure syntax-to-URL functions and deliberately do
/// NOT call it. Every network caller applies the shared egress lock —
/// `arkret_egress_reqwest::EgressGuard` with address pinning on native, or
/// this static classification where the platform owns DNS and sockets
/// (wasm browser fetch) — immediately before dispatch instead.
///
/// Public export for downstream crates such as starid, so they reuse the same
/// outbound SSRF classification instead of duplicating private/metadata/CGN/
/// NAT64/link-local deny lists (STA-05-001).
pub fn host_is_safe_for_outbound(host: &str) -> bool {
    let candidate = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    candidate.parse::<IpAddr>().map_or_else(
        |_| arkret_egress_policy::classify_host(candidate).is_none(),
        ip_is_public,
    )
}

/// Returns `true` only if `ip` is in globally-routable public address space.
///
/// Rejects every range an SSRF egress guard must block: loopback, private
/// (RFC 1918 / ULA `fc00::/7`), link-local (incl. `169.254.169.254` cloud
/// metadata), CGN/shared `100.64.0.0/10`, broadcast, documentation,
/// unspecified, and multicast. IPv4-mapped IPv6 (`::ffff:0:0/96`) is folded
/// to its v4 form before classification so a mapped private address is still
/// rejected.
///
/// Public export for downstream crates such as starid; see
/// [`host_is_safe_for_outbound`] and STA-05-001.
pub fn ip_is_public(ip: IpAddr) -> bool {
    arkret_egress_policy::classify_ip(ip).is_none()
}

pub(super) fn did_web_document_url(did: &DidFullId) -> Option<String> {
    // Pure syntax-to-URL derivation. Whether the resulting authority may be
    // connected to is a request-layer decision (shared egress lock with
    // address pinning immediately before dispatch), not a property of the
    // DID, so no egress judgment belongs here.
    arkret_models_identity::did_web_document_url(did).ok()
}

pub(super) fn is_allowed_did_web_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/did+json" | "application/json"
    )
}

pub(super) fn is_allowed_did_webvh_log_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/json" | "application/jsonl" | "application/x-ndjson" | "application/did+json"
    )
}

/// Split a `did:webvh:<scid>:<host>[%3A<port>][:<path>…]` DID into its
/// component parts: `(scid, host, port, path_segments)`.
///
/// Returns `None` for any non-`did:webvh` input or malformed component
/// (empty scid/host, or a path segment containing `/` or `..`). Public helper
/// for downstream crates such as starid to parse did:webvh directly without
/// going through SDK internals.
pub fn did_webvh_parts(did: &DidFullId) -> Option<(String, String, Option<u16>, Vec<String>)> {
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

pub(super) fn did_webvh_scid(did: &DidFullId) -> Option<String> {
    did_webvh_parts(did).map(|(scid, ..)| scid)
}

/// Why a `did:webvh` URL could not be produced.
///
/// Every arm is a property of the DID itself: syntax and authority shape
/// decide whether a value can ever name a `did:webvh` log location. Whether
/// this deployment may connect to the resulting authority is a separate,
/// request-layer decision (the shared egress lock applied immediately before
/// dispatch), so a policy rejection never reaches this enum — folding the two
/// together once sent an investigation down the wrong path, because a
/// loopback authority, which is legal did:webvh syntax, reported itself as a
/// malformed DID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidWebvhUrlError {
    /// Not a `did:webvh` DID at all.
    UnsupportedMethod,
    /// `did:webvh` syntax is malformed: empty scid or host, an unparsable port,
    /// or a path segment containing `/` or `..`.
    InvalidSyntax,
    /// Syntax is well formed but the authority cannot host a `did:webvh` log:
    /// the host is not a registrable domain name.
    InvalidAuthority,
}

impl DidWebvhUrlError {
    pub fn as_message(self) -> &'static str {
        match self {
            Self::UnsupportedMethod => "not a did:webvh DID",
            Self::InvalidSyntax => "malformed did:webvh syntax",
            Self::InvalidAuthority => "did:webvh authority is not a registrable domain name",
        }
    }
}

pub(super) fn did_webvh_document_url(did: &DidFullId) -> Option<String> {
    did_webvh_url(did, "did.json")
}

pub(super) fn did_webvh_url(did: &DidFullId, leaf: &str) -> Option<String> {
    try_did_webvh_url(did, leaf).ok()
}

/// Derive a `did:webvh` artifact URL, reporting *why* on failure.
///
/// This is a pure syntax-to-URL function: it validates the did:webvh shape
/// and derives the deterministic HTTPS location, and nothing more. Whether
/// this deployment may connect to the derived authority is judged by the
/// caller's request layer — the shared `EgressGuard` lock with the validated
/// addresses pinned into the client, applied immediately before dispatch —
/// so deployments with operator-trusted authorities can resolve DIDs that a
/// public-only posture cannot.
pub(super) fn try_did_webvh_url(did: &DidFullId, leaf: &str) -> Result<String, DidWebvhUrlError> {
    if !did.as_str().starts_with("did:webvh:") {
        return Err(DidWebvhUrlError::UnsupportedMethod);
    }
    let (_, host, port, path) = did_webvh_parts(did).ok_or(DidWebvhUrlError::InvalidSyntax)?;
    if !host.contains('.') {
        return Err(DidWebvhUrlError::InvalidAuthority);
    }
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok(if path.is_empty() {
        format!("https://{authority}/.well-known/{leaf}")
    } else {
        format!("https://{authority}/{}/{leaf}", path.join("/"))
    })
}

pub(super) fn did_key_material(did: &DidFullId) -> Option<String> {
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
    arkret_canonical::decode_base58btc(input).ok()
}

/// Encode `bytes` as a base58btc string (Bitcoin alphabet, no multibase
/// `z` prefix). Inverse of [`decode_base58btc`]. Used by the `did:webvh`
/// SCID / entry-hash derivation, which wraps a SHA-256 multihash in
/// base58btc. Delegates to the single `core::multibase` encoder.
#[cfg(test)]
pub(crate) fn encode_base58btc(bytes: &[u8]) -> String {
    arkret_canonical::encode_base58btc(bytes)
}

/// Wrap a SHA-256 digest of `canonical_bytes` in a multihash envelope
/// (`0x12 0x20` = sha2-256 + 32-byte length) and return the **bare**
/// base58btc string — no multibase `z` prefix. This is the form
/// `did:webvh` v1.0 uses for both the SCID and per-entry hashes
/// (46-char `Qm…` strings; multibase `z` applies to keys/signatures only).
pub(crate) fn webvh_multihash_base58(canonical_bytes: &[u8]) -> String {
    arkret_canonical::sha256_multihash_base58btc(canonical_bytes)
}

pub(super) fn is_supported_did_key_multicodec(bytes: &[u8]) -> bool {
    // multicodec varint parsing reuses the single `core::multibase` helper.
    let Some((code, offset)) = arkret_canonical::decode_multicodec_varint(bytes) else {
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
