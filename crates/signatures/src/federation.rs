//! Federation trust-domain message-signature helpers.

use arkret_wire::TrustDomainId;
use arkret_wire::constants::{HEADER_DESTINATION_TRUST_DOMAIN, HEADER_SOURCE_TRUST_DOMAIN};

// ── HTTP message-signature transcript extension ────────────────────────
/// Build the canonical signing-transcript fragment for the
/// two federation trust-domain headers. Callers append this fragment
/// to the existing RFC 9421 signature base produced by
/// the RFC 9421 helpers in `crates/signatures/src/http_signature.rs` and
/// `crates/wire/src/http_signature.rs`.
///
/// Wire shape: two lines, each with the header name in lower-case
/// quoted form per RFC 9421 §2.2.
pub fn federation_trust_domain_transcript_fragment(
    source_trust_domain: &TrustDomainId,
    destination_trust_domain: &TrustDomainId,
) -> String {
    let header_name = |s: &str| s.to_ascii_lowercase();

    format!(
        "\"{src_h}\": {src}\n\"{dst_h}\": {dst}\n",
        src_h = header_name(HEADER_SOURCE_TRUST_DOMAIN),
        dst_h = header_name(HEADER_DESTINATION_TRUST_DOMAIN),
        src = source_trust_domain.as_str(),
        dst = destination_trust_domain.as_str()
    )
}

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;
