//! RFC 9421 HTTP Message Signatures (Ed25519) + RFC 9530 Content-Digest.
//!
//! This module is HTTP-framework agnostic: callers extract method,
//! target-uri, and headers from their own request object (Salvo,
//! reqwest, hyper, etc.) and hand them to the canonicalization
//! helpers. The module owns:
//!
//! 1. Parsing the `Signature-Input` and `Signature` headers.
//! 2. Building the canonical signing string from a typed request description
//!    ([`SignedRequestParts`]).
//! 3. Computing and verifying the RFC 9530 `Content-Digest` for the request body.
//! 4. Ed25519 sign / verify on the canonical message bytes.
//!
//! Wire shape (matches floria's verifier and soland's fanout signer):
//!
//! ```text
//! Signature-Input: sig1=("@method" "@target-uri" "@authority" \
//!     "content-digest" "source-service-id" \
//!     "destination-service-id");\
//!     created=1715990000;expires=1715990300;\
//!     keyid="did:webvh:z6mkfixture:sync.example.com#push";alg="ed25519"
//! Signature: sig1=:BASE64URLSAFE_OR_STANDARD_64B:
//! Content-Digest: sha-256=:BASE64STANDARD_32B:
//! ```
//!
//! The signing string emitted by [`canonical_message`] follows RFC
//! 9421 §2.5 verbatim (one `"name": value` line per covered component,
//! then a trailing `"@signature-params": (...)` line whose value is
//! the original `Signature-Input` after the `label=` prefix is
//! stripped).
//!
//! All signature / public-key fields are base64. The `Signature`
//! header value is base64 *standard* (per RFC 9421 §3.1 Inner List
//! Byte Sequence syntax), so [`encode_signature_b64`] /
//! [`decode_signature_b64`] use the standard alphabet rather than
//! URL-safe.

use std::collections::BTreeSet;

use arkret_canonical::{base64_standard_decode, base64_standard_encode};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

/// Errors emitted by the RFC 9421 helpers.
///
/// Verifiers are expected to map these into their HTTP-framework
/// rejection type (e.g. `401 signature_invalid` in floria). No
/// stringly-typed variants — each variant pinpoints the failure
/// kind precisely so callers can branch on it.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    /// The `Signature-Input` header is empty, missing the `label=`
    /// prefix, or has an unbalanced component list.
    #[error("signature-input header is malformed")]
    MalformedSignatureInput,
    /// The component list inside `(...)` is empty.
    #[error("signature-input must cover at least one component")]
    EmptyCoveredComponents,
    /// A required `;name=value` parameter is missing (created, expires,
    /// keyid, alg).
    #[error("signature-input is missing required parameter `{0}`")]
    MissingSignatureInputParameter(&'static str),
    /// A parameter value (e.g. `created=`) failed to parse as the
    /// expected primitive (i64, bool, string).
    #[error("signature-input parameter `{0}` has an invalid value")]
    InvalidSignatureInputParameter(&'static str),
    /// The configured / declared algorithm is not `ed25519`.
    #[error("unsupported signature algorithm: `{0}`")]
    UnsupportedAlgorithm(String),
    /// The `Signature` header is empty, missing the `label=:...:`
    /// wrapping, or does not contain the label declared in
    /// `Signature-Input`.
    #[error("signature header is malformed or missing label `{0}`")]
    MalformedSignatureHeader(String),
    /// A covered component (e.g. a header) was declared in
    /// `Signature-Input` but the value is missing or empty in the
    /// request.
    #[error("covered component `{0}` is missing from the request")]
    MissingCoveredComponent(String),
    /// A covered component name is not recognized (e.g.
    /// `@request-target` is not implemented).
    #[error("unknown covered component: `{0}`")]
    UnknownCoveredComponent(String),
    /// The `Content-Digest` header value did not parse as RFC 9530
    /// dictionary syntax, or uses an unsupported algorithm.
    #[error("content-digest header is malformed or unsupported")]
    MalformedContentDigest,
    /// The `Content-Digest` value did not match the recomputed hash
    /// of the request body.
    #[error("content-digest does not match request body")]
    ContentDigestMismatch,
    /// The base64-encoded `Signature` value did not decode.
    #[error("signature value is not valid base64")]
    InvalidSignatureBase64,
    /// The decoded `Signature` value is not 64 bytes (Ed25519).
    #[error("ed25519 signature must be 64 bytes")]
    InvalidSignatureLength,
    /// Ed25519 verification failed (math, not transport).
    #[error("ed25519 signature verification failed")]
    SignatureInvalid,
    /// The provided public key bytes are not a valid Ed25519
    /// verifying key.
    #[error("ed25519 public key is invalid")]
    InvalidPublicKey,
}

/// Policy-layer failures after the RFC 9421 headers have parsed.
///
/// [`SignatureError`] covers syntax, canonicalization and Ed25519 math. This
/// error covers deployment/profile policy: the minimum covered components,
/// digest presence and accepted `created` / `expires` window.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignaturePolicyError {
    /// The signature did not cover every component required by the caller.
    #[error("signature input does not cover every required component")]
    MissingRequiredCoveredComponent,
    /// The profile requires a `Content-Digest` header and the caller did not
    /// supply one.
    #[error("content-digest header is required by signature policy")]
    MissingContentDigest,
    /// `expires` is earlier than `created`.
    #[error("signature validity window is invalid")]
    InvalidValidityWindow,
    /// `created` is too far in the future for the accepted clock skew.
    #[error("signature was created in the future")]
    CreatedInFuture,
    /// `created` is too far in the past for the accepted clock skew.
    #[error("signature creation time is too old")]
    CreatedTooOld,
    /// `expires` is older than the accepted clock skew.
    #[error("signature has expired")]
    Expired,
}

/// End-to-end raw HTTP message verification failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpMessageVerificationError {
    /// Signed JSON requests must be transmitted without content codings so the
    /// verified bytes are the exact canonical JSON bytes the application
    /// parses.
    #[error("signed canonical JSON request must not use Content-Encoding")]
    ContentEncodingNotAllowed,
    /// The raw request body was valid JSON but not byte-for-byte canonical
    /// Arkret JSON.
    #[error("signed request body is not canonical JSON: {0}")]
    NonCanonicalJson(String),
    /// A required HTTP header is absent after case-insensitive lookup.
    #[error("required HTTP message signature header `{0}` is missing")]
    MissingHeader(&'static str),
    /// RFC 9421 / RFC 9530 parsing, canonicalization or signature math failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// Arkret profile policy rejected the otherwise parseable signature input.
    #[error(transparent)]
    Policy(#[from] SignaturePolicyError),
}

/// Successful raw HTTP message signature verification result.
///
/// This result proves the RFC 9421 signature, the optional RFC 9530
/// `Content-Digest`, and the configured validity window. It does not prove
/// request freshness by itself: this layer does not maintain replay state.
/// Consumers MUST keep a seen-message cache keyed by deployment policy, for
/// example by `(key_id, created, expires, nonce or canonical_message digest)`,
/// and reject duplicate verified requests within the accepted window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHttpMessageSignature {
    /// Parsed `Signature-Input` parameters that were verified.
    pub signature_input: SignatureInput,
    /// Parsed and body-verified `Content-Digest`, when supplied.
    pub content_digest: Option<ContentDigest>,
    /// Exact RFC 9421 canonical bytes that were verified.
    pub canonical_message: Vec<u8>,
}

// =====================================================================
// SignatureInput — parsed `Signature-Input` header
// =====================================================================

/// A single covered component referenced by a `Signature-Input`
/// header. Distinguishes derived components (`@method`, `@target-uri`,
/// `@authority`) from named headers so canonicalization can branch
/// without re-parsing strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    /// `@method` — the HTTP method exactly as received. RFC 9421
    /// §2.2.1 explicitly forbids case transformation.
    Method,
    /// `@target-uri` — full request URI per RFC 9421 §2.2.2.
    TargetUri,
    /// `@authority` — request authority (host + optional port) per
    /// RFC 9421 §2.2.3.
    Authority,
    /// `@path` — request path per RFC 9421 §2.2.5. Used by soland's
    /// fanout signer.
    Path,
    /// Named lowercase header. Re-emitted as `"name": value` in the
    /// signing string with whitespace trimmed.
    Header(String),
}

impl Component {
    /// The canonical wire form (RFC 9421 §2.1) of this component
    /// name, e.g. `@method` or `content-digest`. Always lowercase.
    pub fn canonical_name(&self) -> String {
        match self {
            Component::Method => "@method".to_owned(),
            Component::TargetUri => "@target-uri".to_owned(),
            Component::Authority => "@authority".to_owned(),
            Component::Path => "@path".to_owned(),
            Component::Header(name) => name.to_ascii_lowercase(),
        }
    }

    /// Parse a component name (already stripped of surrounding
    /// quotes) into its typed form. Lowercases header names.
    pub fn parse(name: &str) -> Component {
        match name {
            "@method" => Component::Method,
            "@target-uri" => Component::TargetUri,
            "@authority" => Component::Authority,
            "@path" => Component::Path,
            other => Component::Header(other.to_ascii_lowercase()),
        }
    }
}

/// Parsed `Signature-Input` header. RFC 9421 §2.5 — the header maps a
/// signature `label` to a covered component list and a `;`-separated
/// parameter list (created, expires, keyid, alg, nonce, …).
///
/// Only the parameters listed below are surfaced; unknown parameters
/// are preserved in [`Self::params_value`] so the original
/// `@signature-params` line can be reconstructed byte-for-byte when
/// building the signing string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInput {
    /// The signature label (e.g. `sig1`).
    pub label: String,
    /// Covered components in declaration order. Order matters — it is
    /// re-emitted verbatim in the signing string.
    pub covered_components: Vec<Component>,
    /// `created` parameter (Unix seconds). Required by the v1
    /// federation / push profile.
    pub created: i64,
    /// `expires` parameter (Unix seconds). Required by the v1
    /// federation / push profile.
    pub expires: i64,
    /// `keyid` parameter — the key fingerprint or DID fragment the
    /// verifier should look up.
    pub key_id: String,
    /// `alg` parameter — must be `ed25519` for this v1 profile.
    pub algorithm: String,
    /// The literal string from the `=` after the label through the
    /// end of the header value, used to reconstruct the
    /// `@signature-params` line byte-for-byte when building the
    /// signing string. (RFC 9421 §2.5 requires bit-exact reuse.)
    pub params_value: String,
}

impl SignatureInput {
    /// Returns true if every component in `required` is covered by
    /// this signature input. Used by verifiers to enforce a minimum
    /// covered-component set (floria requires `@method`,
    /// `@target-uri`, `@authority`, `content-digest`, the two
    /// service-ID headers).
    pub fn covers_all(&self, required: &[Component]) -> bool {
        let covered: BTreeSet<String> = self
            .covered_components
            .iter()
            .map(Component::canonical_name)
            .collect();
        required
            .iter()
            .all(|c| covered.contains(&c.canonical_name()))
    }
}

/// HTTP Message Signature profile policy shared by services such as floria and
/// teabay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerificationPolicy {
    required_components: Vec<Component>,
    require_content_digest: bool,
    max_clock_skew_seconds: i64,
    max_validity_window_seconds: i64,
}

impl SignatureVerificationPolicy {
    /// Build a policy with an explicit required-component set.
    pub fn new(required_components: impl Into<Vec<Component>>) -> Self {
        Self {
            required_components: required_components.into(),
            require_content_digest: true,
            max_clock_skew_seconds: 30,
            max_validity_window_seconds: 300,
        }
    }

    /// Minimal Arkret service-ingest policy: method, absolute target URI,
    /// authority and content digest must all be covered.
    pub fn service_ingest() -> Self {
        Self::new(vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("content-digest".to_owned()),
        ])
    }

    /// Require a `Content-Digest` header independently of whether the signature
    /// declares `content-digest` as a covered component.
    pub fn require_content_digest(mut self, require: bool) -> Self {
        self.require_content_digest = require;
        self
    }

    /// Configure accepted clock skew around `created`.
    pub fn max_clock_skew_seconds(mut self, seconds: i64) -> Self {
        self.max_clock_skew_seconds = seconds.max(0);
        self
    }

    /// Configure the maximum accepted `expires - created` lifetime.
    pub fn max_validity_window_seconds(mut self, seconds: i64) -> Self {
        self.max_validity_window_seconds = seconds.max(0);
        self
    }

    /// Validate the policy against a parsed [`SignatureInput`].
    ///
    /// `content_digest_header` is the raw `Content-Digest` header value, if the
    /// transport supplied one. Callers should still parse and verify the digest
    /// bytes with [`ContentDigest::parse`] and [`verify_content_digest`].
    pub fn validate(
        &self,
        signature_input: &SignatureInput,
        content_digest_header: Option<&str>,
        now_unix_seconds: i64,
    ) -> Result<(), SignaturePolicyError> {
        if !signature_input.covers_all(&self.required_components) {
            return Err(SignaturePolicyError::MissingRequiredCoveredComponent);
        }
        if self.require_content_digest
            && content_digest_header.is_none_or(|value| value.trim().is_empty())
        {
            return Err(SignaturePolicyError::MissingContentDigest);
        }
        if signature_input.expires < signature_input.created {
            return Err(SignaturePolicyError::InvalidValidityWindow);
        }
        if signature_input
            .expires
            .saturating_sub(signature_input.created)
            > self.max_validity_window_seconds
        {
            return Err(SignaturePolicyError::InvalidValidityWindow);
        }
        let skew = self.max_clock_skew_seconds;
        if signature_input.created > now_unix_seconds.saturating_add(skew) {
            return Err(SignaturePolicyError::CreatedInFuture);
        }
        if signature_input.expires < now_unix_seconds {
            return Err(SignaturePolicyError::Expired);
        }
        if signature_input.created < now_unix_seconds.saturating_sub(skew) {
            return Err(SignaturePolicyError::CreatedTooOld);
        }
        Ok(())
    }
}

/// Parse a `Signature-Input` header value. Accepts the format emitted
/// by floria, chime, and soland:
///
/// ```text
/// label=("@method" "@target-uri" ...);created=...;expires=...;keyid="...";alg="ed25519"
/// ```
pub fn parse_signature_input(header: &str) -> Result<SignatureInput, SignatureError> {
    let trimmed = header.trim();
    let (label, remainder) = trimmed
        .split_once('=')
        .ok_or(SignatureError::MalformedSignatureInput)?;
    let label = label.trim().to_owned();
    let remainder = remainder.trim();

    // The signing string re-emits exactly this suffix in the
    // @signature-params line.
    let params_value = remainder.to_owned();

    if !remainder.starts_with('(') {
        return Err(SignatureError::MalformedSignatureInput);
    }
    let end_components = remainder
        .find(')')
        .ok_or(SignatureError::MalformedSignatureInput)?;
    let components_str = &remainder[1..end_components];
    let covered_components: Vec<Component> = components_str
        .split_ascii_whitespace()
        .map(|c| c.trim_matches('"'))
        .filter(|c| !c.is_empty())
        .map(Component::parse)
        .collect();
    if covered_components.is_empty() {
        return Err(SignatureError::EmptyCoveredComponents);
    }

    let mut created: Option<i64> = None;
    let mut expires: Option<i64> = None;
    let mut key_id: Option<String> = None;
    let mut algorithm: Option<String> = None;

    for param in remainder[end_components + 1..]
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let (name, raw_value) = param
            .split_once('=')
            .ok_or(SignatureError::MalformedSignatureInput)?;
        match name.trim() {
            "created" => {
                created = Some(
                    raw_value
                        .parse::<i64>()
                        .map_err(|_| SignatureError::InvalidSignatureInputParameter("created"))?,
                );
            }
            "expires" => {
                expires = Some(
                    raw_value
                        .parse::<i64>()
                        .map_err(|_| SignatureError::InvalidSignatureInputParameter("expires"))?,
                );
            }
            "keyid" => {
                key_id = Some(raw_value.trim_matches('"').to_owned());
            }
            "alg" => {
                algorithm = Some(raw_value.trim_matches('"').to_ascii_lowercase());
            }
            _ => {
                // ignore unknown params; preserved in params_value
            }
        }
    }

    Ok(SignatureInput {
        label,
        covered_components,
        created: created.ok_or(SignatureError::MissingSignatureInputParameter("created"))?,
        expires: expires.ok_or(SignatureError::MissingSignatureInputParameter("expires"))?,
        key_id: key_id.ok_or(SignatureError::MissingSignatureInputParameter("keyid"))?,
        algorithm: algorithm.ok_or(SignatureError::MissingSignatureInputParameter("alg"))?,
        params_value,
    })
}

/// Parse the `Signature` header value and return the raw signature
/// bytes for the requested label. The header may contain multiple
/// signatures (RFC 9421 §4.2) separated by `,` — this helper returns
/// the bytes for `label` only.
pub fn parse_signature_header(header: &str, label: &str) -> Result<Vec<u8>, SignatureError> {
    for part in header.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((candidate, encoded)) = part.split_once("=:") else {
            continue;
        };
        if candidate.trim() != label {
            continue;
        }
        let encoded = encoded
            .strip_suffix(':')
            .ok_or_else(|| SignatureError::MalformedSignatureHeader(label.to_owned()))?;
        return decode_signature_b64(encoded);
    }
    Err(SignatureError::MalformedSignatureHeader(label.to_owned()))
}

/// Format a minimal `Signature-Input` header value from a typed component list.
///
/// This helper intentionally formats only the `label=(...)` component list. Some
/// caller-side contexts, such as Chime device-registration proofs, attach
/// deployment metadata in separate headers and let an external signer decide
/// whether to add RFC 9421 parameters such as `created`, `expires` or `keyid`.
pub fn format_signature_input_component_list(
    label: &str,
    covered_components: &[Component],
) -> Result<String, SignatureError> {
    if !is_valid_signature_label(label) {
        return Err(SignatureError::MalformedSignatureInput);
    }
    if covered_components.is_empty() {
        return Err(SignatureError::EmptyCoveredComponents);
    }

    let covered = covered_components
        .iter()
        .map(|component| format!("\"{}\"", component.canonical_name()))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!("{label}=({covered})"))
}

/// Format a `Signature` header value for an externally computed signature.
///
/// This does not verify the signature bytes. It validates the wire envelope used
/// by RFC 9421 (`label=:...:`) while allowing callers to supply a detached
/// signature from an HSM, browser wallet or DID-proof layer.
pub fn format_signature_header(label: &str, signature: &str) -> Result<String, SignatureError> {
    if !is_valid_signature_label(label)
        || signature.trim().is_empty()
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
    {
        return Err(SignatureError::MalformedSignatureHeader(label.to_owned()));
    }

    Ok(format!("{label}=:{signature}:"))
}

fn is_valid_signature_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

// =====================================================================
// SignedRequestParts — HTTP-framework-agnostic request projection
// =====================================================================

/// HTTP-framework-agnostic projection of the request fields that
/// RFC 9421 needs to canonicalize. Headers are stored as a `Vec` of
/// `(lowercase_name, value)` tuples so the caller controls ordering;
/// duplicate headers are joined with `, ` per RFC 9421 §2.1 when
/// looked up.
///
/// `body_digest` carries the pre-computed `Content-Digest` value —
/// when present, [`canonical_message`] consumes it as the value of
/// the `content-digest` covered component without re-hashing.
/// Verifiers that want to enforce body integrity should call
/// [`verify_content_digest`] separately against the raw body bytes.
#[derive(Debug, Clone)]
pub struct SignedRequestParts {
    /// HTTP method exactly as it appears on the request, e.g. `"POST"`.
    /// RFC 9421 section 2.2.1 treats method names as case-sensitive and
    /// forbids changing their case while constructing the signature base.
    pub method: String,
    /// Absolute target URI of the request, e.g.
    /// `"https://push.example.com/_arkret/edge/push/notify"`.
    pub target_uri: String,
    /// Authority component (host + optional port).
    pub authority: String,
    /// Path component (used by `@path`).
    pub path: String,
    /// Lowercase header name + raw header value pairs. The lookup
    /// helper [`Self::header`] does case-insensitive matching.
    pub headers: Vec<(String, String)>,
    /// Optional pre-computed `Content-Digest` value (e.g.
    /// `"sha-256=:BASE64:"`). When set, it overrides any
    /// `content-digest` entry in `headers`.
    pub body_digest: Option<String>,
}

impl SignedRequestParts {
    /// Case-insensitive header lookup, joining duplicates with `, `
    /// per RFC 9421 §2.1.
    pub fn header(&self, name: &str) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(&lower))
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }
}

// =====================================================================
// Content-Digest (RFC 9530)
// =====================================================================

/// `Content-Digest` algorithms supported by this v1 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentDigestAlgorithm {
    /// `sha-256` — the sole Arkret v1 wire algorithm identifier.
    Sha256,
}

impl ContentDigestAlgorithm {
    /// Wire form (`"sha-256"`) used in the RFC 9530 dictionary key.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ContentDigestAlgorithm::Sha256 => "sha-256",
        }
    }
}

/// Parsed `Content-Digest` header value (RFC 9530 §2). Currently
/// surfaces a single (alg, digest_bytes) tuple — the dictionary
/// syntax supports multiple but the v1 profile commits to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    pub algorithm: ContentDigestAlgorithm,
    /// Raw SHA-256 digest bytes.
    pub digest: Vec<u8>,
    /// The original header value, preserved so it can be re-emitted
    /// byte-for-byte in the signing string.
    pub wire_value: String,
}

impl ContentDigest {
    /// Compute a `Content-Digest` over `body` using the chosen
    /// algorithm and return the wire-ready header value, e.g.
    /// `"sha-256=:BASE64:"`. The standard base64 alphabet is used per
    /// RFC 9530.
    pub fn compute(body: &[u8], algorithm: ContentDigestAlgorithm) -> ContentDigest {
        let digest = match algorithm {
            ContentDigestAlgorithm::Sha256 => {
                arkret_canonical::canonical::sha256_bytes(body).to_vec()
            }
        };
        let wire_value = format!(
            "{}=:{}:",
            algorithm.wire_name(),
            base64_standard_encode(&digest)
        );
        ContentDigest {
            algorithm,
            digest,
            wire_value,
        }
    }

    /// Parse a `Content-Digest` header value. Accepts the simple
    /// `alg=:base64:` form emitted by floria, chime, and soland.
    pub fn parse(value: &str) -> Result<ContentDigest, SignatureError> {
        let trimmed = value.trim();
        // Find the first `=` (algorithm name boundary).
        let (alg_str, rest) = trimmed
            .split_once('=')
            .ok_or(SignatureError::MalformedContentDigest)?;
        let algorithm = match alg_str.trim() {
            "sha-256" => ContentDigestAlgorithm::Sha256,
            _ => return Err(SignatureError::MalformedContentDigest),
        };
        let encoded = rest
            .trim()
            .strip_prefix(':')
            .and_then(|v| v.strip_suffix(':'))
            .ok_or(SignatureError::MalformedContentDigest)?;
        let digest =
            base64_standard_decode(encoded).map_err(|_| SignatureError::MalformedContentDigest)?;
        let expected_len = match algorithm {
            ContentDigestAlgorithm::Sha256 => 32,
        };
        if digest.len() != expected_len {
            return Err(SignatureError::MalformedContentDigest);
        }
        Ok(ContentDigest {
            algorithm,
            digest,
            wire_value: trimmed.to_owned(),
        })
    }
}

/// Recompute the digest over `body` and reject if it does not match
/// the parsed [`ContentDigest`]. Verifiers should call this before
/// trusting any `content-digest` covered component in the signature.
pub fn verify_content_digest(parsed: &ContentDigest, body: &[u8]) -> Result<(), SignatureError> {
    let recomputed = match parsed.algorithm {
        ContentDigestAlgorithm::Sha256 => arkret_canonical::canonical::sha256_bytes(body).to_vec(),
    };
    // Constant-time-ish comparison; the digest bytes are public so a
    // simple eq is sufficient, but we keep the check explicit.
    if recomputed != parsed.digest {
        return Err(SignatureError::ContentDigestMismatch);
    }
    Ok(())
}

/// Verify a raw HTTP message signature from framework-extracted request data.
///
/// This is the high-level verifier downstream services should use when they
/// already have the raw body bytes and request headers. It performs, in order:
///
/// 1. `Signature-Input` / `Signature` header extraction.
/// 2. `Content-Digest` parsing and raw-body verification, when present.
/// 3. Arkret policy validation (`required_components`, digest requirement and created/expires
///    window).
/// 4. RFC 9421 canonical message construction.
/// 5. Ed25519 verification against the supplied public key.
///
/// This helper is intentionally stateless and does not perform replay
/// deduplication. Services that accept signed HTTP messages MUST maintain their
/// own seen-message cache for the accepted validity window, including any
/// `nonce` parameter carried in the preserved [`SignatureInput::params_value`]
/// when their deployment profile requires nonce-based replay protection.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_http_message<I, N, V>(
    method: &str,
    target_uri: &str,
    authority: &str,
    path: &str,
    headers: I,
    body: &[u8],
    public_key: &VerifyingKey,
    policy: &SignatureVerificationPolicy,
    now_unix_seconds: i64,
) -> Result<VerifiedHttpMessageSignature, HttpMessageVerificationError>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let mut request = SignedRequestParts {
        method: method.to_owned(),
        target_uri: target_uri.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        headers: headers
            .into_iter()
            .map(|(name, value)| {
                (
                    name.as_ref().to_ascii_lowercase(),
                    value.as_ref().trim().to_owned(),
                )
            })
            .collect(),
        body_digest: None,
    };

    let signature_input_header =
        request
            .header("signature-input")
            .ok_or(HttpMessageVerificationError::MissingHeader(
                "Signature-Input",
            ))?;
    let signature_header = request
        .header("signature")
        .ok_or(HttpMessageVerificationError::MissingHeader("Signature"))?;

    let signature_input = parse_signature_input(&signature_input_header)?;
    if signature_input.algorithm != "ed25519" {
        return Err(SignatureError::UnsupportedAlgorithm(signature_input.algorithm).into());
    }

    let content_digest = match request.header("content-digest") {
        Some(value) => {
            let parsed = ContentDigest::parse(&value)?;
            verify_content_digest(&parsed, body)?;
            request.body_digest = Some(parsed.wire_value.clone());
            Some(parsed)
        }
        None => None,
    };

    policy.validate(
        &signature_input,
        content_digest
            .as_ref()
            .map(|digest| digest.wire_value.as_str()),
        now_unix_seconds,
    )?;

    let canonical_message = canonical_message(&request, &signature_input)?;
    let signature_bytes = parse_signature_header(&signature_header, &signature_input.label)?;
    if signature_bytes.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength.into());
    }
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&signature_array);
    public_key
        .verify_strict(&canonical_message, &signature)
        .map_err(|_| SignatureError::SignatureInvalid)?;

    Ok(VerifiedHttpMessageSignature {
        signature_input,
        content_digest,
        canonical_message,
    })
}

/// Verify an Arkret signed canonical-JSON HTTP request.
///
/// This is the complete receiver-side preflight required by
/// `service-http-binding.md` §2.5.1: content codings are rejected, the exact
/// body bytes must already be canonical JSON, and the RFC 9421 signature and
/// RFC 9530 content digest are then verified over those same bytes.
///
/// Framework adapters should pass `true` for
/// `content_encoding_present` whenever the request contains a
/// `Content-Encoding` header, regardless of its value.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_canonical_json_message<I, N, V>(
    method: &str,
    target_uri: &str,
    authority: &str,
    path: &str,
    headers: I,
    content_encoding_present: bool,
    body: &[u8],
    public_key: &VerifyingKey,
    policy: &SignatureVerificationPolicy,
    now_unix_seconds: i64,
) -> Result<VerifiedHttpMessageSignature, HttpMessageVerificationError>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    validate_signed_canonical_json_body(content_encoding_present, body)?;
    verify_signed_http_message(
        method,
        target_uri,
        authority,
        path,
        headers,
        body,
        public_key,
        policy,
        now_unix_seconds,
    )
}

/// Validate the representation requirements shared by every signed JSON
/// receiver before signature verification.
pub fn validate_signed_canonical_json_body(
    content_encoding_present: bool,
    body: &[u8],
) -> Result<(), HttpMessageVerificationError> {
    if content_encoding_present {
        return Err(HttpMessageVerificationError::ContentEncodingNotAllowed);
    }
    arkret_canonical::canonical::validate_canonical_bytes(body)
        .map_err(|error| HttpMessageVerificationError::NonCanonicalJson(error.to_string()))
}

// =====================================================================
// Canonical message construction (RFC 9421 §2.5)
// =====================================================================

/// Build the canonical signing string for an HTTP request per RFC
/// 9421 §2.5.
///
/// Emits one `"name": value` line per covered component in the order
/// given by `signature_input.covered_components`, then a trailing
/// `"@signature-params": <params_value>` line whose value is taken
/// verbatim from `signature_input.params_value` (so signer / verifier
/// reuse the exact same bytes — RFC 9421 requires this).
///
/// The output is `Vec<u8>` rather than `String` because the resulting
/// bytes are the input to Ed25519 — never displayed as text.
pub fn canonical_message(
    req: &SignedRequestParts,
    signature_input: &SignatureInput,
) -> Result<Vec<u8>, SignatureError> {
    let mut components = Vec::with_capacity(signature_input.covered_components.len());
    for component in &signature_input.covered_components {
        let value = component_value(req, component)?;
        components.push((component.clone(), value));
    }
    Ok(canonical_message_from_component_values(
        &components,
        &signature_input.params_value,
    ))
}

/// Build canonical RFC 9421 message bytes from already-resolved component
/// values.
///
/// This is the shared lower-level primitive for adapters that obtain request
/// components from framework-specific request types. Callers remain
/// responsible for resolving each value according to RFC 9421.
pub fn canonical_message_from_component_values(
    components: &[(Component, String)],
    signature_params: &str,
) -> Vec<u8> {
    let mut lines = Vec::with_capacity(components.len() + 1);
    for (component, value) in components {
        lines.push(format!("\"{}\": {}", component.canonical_name(), value));
    }
    lines.push(format!("\"@signature-params\": {}", signature_params));
    lines.join("\n").into_bytes()
}

fn component_value(
    req: &SignedRequestParts,
    component: &Component,
) -> Result<String, SignatureError> {
    match component {
        Component::Method => Ok(req.method.clone()),
        Component::TargetUri => Ok(req.target_uri.clone()),
        Component::Authority => Ok(req.authority.clone()),
        Component::Path => Ok(req.path.clone()),
        Component::Header(name) => {
            if name == "content-digest"
                && let Some(digest) = &req.body_digest
            {
                return Ok(digest.clone());
            }
            req.header(name)
                .ok_or_else(|| SignatureError::MissingCoveredComponent(name.clone()))
        }
    }
}

// =====================================================================
// Sign / verify
// =====================================================================

/// Ed25519-sign the canonical message bytes and return a base64
/// (standard alphabet) string suitable for the `Signature` header.
pub fn sign_message(message: &[u8], signing_key: &SigningKey) -> String {
    let signature: Signature = signing_key.sign(message);
    encode_signature_b64(&signature.to_bytes())
}

/// Verify an Ed25519 signature (base64 standard alphabet) against the
/// canonical message bytes. Returns Ok on success; the discriminated
/// [`SignatureError`] tells the caller exactly which check failed
/// (decoding vs. crypto).
pub fn verify_signature(
    message: &[u8],
    signature_b64: &str,
    public_key: &VerifyingKey,
) -> Result<(), SignatureError> {
    let bytes = decode_signature_b64(signature_b64)?;
    if bytes.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    let signature = Signature::from_bytes(&arr);
    public_key
        .verify_strict(message, &signature)
        .map_err(|_| SignatureError::SignatureInvalid)
}

/// Construct an Ed25519 public key from raw 32 bytes. Helper for
/// callers that store keys as hex / base64.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, SignatureError> {
    if bytes.len() != 32 {
        return Err(SignatureError::InvalidPublicKey);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| SignatureError::InvalidPublicKey)
}

/// Construct an Ed25519 signing key from a 32-byte seed.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

// -- base64 helpers --------------------------------------------------

/// Standard-alphabet base64 encode (RFC 9421 §3.1 Inner List Byte
/// Sequence).
pub fn encode_signature_b64(bytes: &[u8]) -> String {
    base64_standard_encode(bytes)
}

/// Standard-alphabet base64 decode. Returns
/// [`SignatureError::InvalidSignatureBase64`] on failure.
pub fn decode_signature_b64(s: &str) -> Result<Vec<u8>, SignatureError> {
    base64_standard_decode(s.trim()).map_err(|_| SignatureError::InvalidSignatureBase64)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the floria test fixture: same seed + same component set
    /// the floria notify test uses (see floria/src/auth.rs::sign_request).
    const TEST_SEED: [u8; 32] = [1u8; 32];

    fn floria_signature_input(created: i64, expires: i64) -> String {
        format!(
            "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
             \"source-service-id\" \"destination-service-id\");\
             created={created};expires={expires};\
             keyid=\"did:webvh:z6mkfixture:sync.example.com#push\";alg=\"ed25519\""
        )
    }

    #[test]
    fn parse_signature_input_handles_floria_fixture() {
        let header = floria_signature_input(1_715_990_000, 1_715_990_300);
        let parsed = parse_signature_input(&header).expect("parses");
        assert_eq!(parsed.label, "sig1");
        assert_eq!(parsed.created, 1_715_990_000);
        assert_eq!(parsed.expires, 1_715_990_300);
        assert_eq!(parsed.key_id, "did:webvh:z6mkfixture:sync.example.com#push");
        assert_eq!(parsed.algorithm, "ed25519");
        assert_eq!(parsed.covered_components.len(), 6);
        assert_eq!(parsed.covered_components[0], Component::Method);
        assert_eq!(parsed.covered_components[1], Component::TargetUri);
        assert_eq!(parsed.covered_components[2], Component::Authority);
        assert_eq!(
            parsed.covered_components[3],
            Component::Header("content-digest".to_owned())
        );
        assert_eq!(
            parsed.covered_components[4],
            Component::Header("source-service-id".to_owned())
        );
        // covers_all check
        assert!(parsed.covers_all(&[
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("content-digest".to_owned()),
        ]));
        assert!(!parsed.covers_all(&[Component::Header("x-nope".to_owned())]));
    }

    #[test]
    fn signature_policy_enforces_digest_components_and_time_window() {
        let policy = SignatureVerificationPolicy::service_ingest();
        let now = 1_715_990_010;
        let valid = parse_signature_input(&floria_signature_input(now - 1, now + 30)).unwrap();
        policy
            .validate(
                &valid,
                Some("sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"),
                now,
            )
            .expect("valid policy input passes");
        let too_old = parse_signature_input(&floria_signature_input(now - 300, now)).unwrap();
        assert_eq!(
            policy.validate(&too_old, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::CreatedTooOld)
        );

        let missing_digest = parse_signature_input(
            "sig1=(\"@method\" \"@target-uri\" \"@authority\");created=1715990000;expires=1715990030;keyid=\"did:webvh:z6mkfixture:sync.example.com#push\";alg=\"ed25519\"",
        )
        .unwrap();
        assert_eq!(
            policy.validate(&missing_digest, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::MissingRequiredCoveredComponent)
        );
        assert_eq!(
            policy.validate(&valid, None, now),
            Err(SignaturePolicyError::MissingContentDigest)
        );

        let future = parse_signature_input(&floria_signature_input(now + 40, now + 70)).unwrap();
        assert_eq!(
            policy.validate(&future, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::CreatedInFuture)
        );
        let expired = parse_signature_input(&floria_signature_input(now - 300, now - 40)).unwrap();
        assert_eq!(
            policy.validate(&expired, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::Expired)
        );
        let just_expired =
            parse_signature_input(&floria_signature_input(now - 30, now - 1)).unwrap();
        assert_eq!(
            policy.validate(&just_expired, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::Expired)
        );
        let too_long = parse_signature_input(&floria_signature_input(now - 1, now + 301)).unwrap();
        assert_eq!(
            policy.validate(&too_long, Some("sha-256=:x=:"), now),
            Err(SignaturePolicyError::InvalidValidityWindow)
        );
    }

    #[test]
    fn formats_minimal_signature_headers_for_external_signers() {
        let input = format_signature_input_component_list(
            "sig1",
            &[
                Component::Method,
                Component::TargetUri,
                Component::Header("Content-Digest".to_owned()),
            ],
        )
        .unwrap();
        assert_eq!(
            input,
            "sig1=(\"@method\" \"@target-uri\" \"content-digest\")"
        );

        let signature = format_signature_header("sig1", "YWJjZA==").unwrap();
        assert_eq!(signature, "sig1=:YWJjZA==:");

        assert_eq!(
            format_signature_input_component_list("bad label", &[Component::Method]),
            Err(SignatureError::MalformedSignatureInput)
        );
        assert_eq!(
            format_signature_input_component_list("sig1", &[]),
            Err(SignatureError::EmptyCoveredComponents)
        );
        assert_eq!(
            format_signature_header("sig1", "bad:sig"),
            Err(SignatureError::MalformedSignatureHeader("sig1".to_owned()))
        );
    }

    #[test]
    fn canonical_message_matches_floria_known_good_vector() {
        // Reconstruct the exact signing string floria's sign_request
        // helper produces for a fixed (method, target-uri, authority,
        // digest, did) tuple. Locking this byte-for-byte is what
        // proves the SDK can verify floria-produced signatures.
        let created = 1_715_990_000_i64;
        let expires = 1_715_990_300_i64;
        let input_header = floria_signature_input(created, expires);
        let signature_input = parse_signature_input(&input_header).unwrap();

        let body = br#"{"hello":"world"}"#;
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);

        let req = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: "http://127.0.0.1/_arkret/edge/push/notify".to_owned(),
            authority: "127.0.0.1".to_owned(),
            path: "/_arkret/edge/push/notify".to_owned(),
            headers: vec![
                (
                    "source-service-id".to_owned(),
                    "did:webvh:z6mkfixture:sync.example.com".to_owned(),
                ),
                (
                    "destination-service-id".to_owned(),
                    "did:webvh:z6mkfixture:push.example.com".to_owned(),
                ),
            ],
            body_digest: Some(digest.wire_value.clone()),
        };

        let message = canonical_message(&req, &signature_input).unwrap();
        let text = String::from_utf8(message).unwrap();
        let expected = format!(
            "\"@method\": POST\n\
             \"@target-uri\": http://127.0.0.1/_arkret/edge/push/notify\n\
             \"@authority\": 127.0.0.1\n\
             \"content-digest\": {digest_val}\n\
             \"source-service-id\": did:webvh:z6mkfixture:sync.example.com\n\
             \"destination-service-id\": did:webvh:z6mkfixture:push.example.com\n\
             \"@signature-params\": ({components});created={created};expires={expires};keyid=\"did:webvh:z6mkfixture:sync.example.com#push\";alg=\"ed25519\"",
            digest_val = digest.wire_value,
            components = "\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"source-service-id\" \"destination-service-id\"",
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn method_component_preserves_extension_method_case() {
        let input = parse_signature_input(
            "sig1=(\"@method\");created=1;expires=2;keyid=\"k\";alg=\"ed25519\"",
        )
        .unwrap();
        let request = SignedRequestParts {
            method: "mIxEd".to_owned(),
            target_uri: "https://example.test/".to_owned(),
            authority: "example.test".to_owned(),
            path: "/".to_owned(),
            headers: Vec::new(),
            body_digest: None,
        };

        assert_eq!(
            canonical_message(&request, &input).unwrap(),
            b"\"@method\": mIxEd\n\"@signature-params\": (\"@method\");created=1;expires=2;keyid=\"k\";alg=\"ed25519\""
        );
    }

    #[test]
    fn sign_then_verify_round_trip_succeeds() {
        let signing_key = signing_key_from_seed(&TEST_SEED);
        let public_key = signing_key.verifying_key();

        let input_header = floria_signature_input(1_700_000_000, 1_700_000_300);
        let signature_input = parse_signature_input(&input_header).unwrap();

        let body = br#"{"op":"ping"}"#;
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        let req = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: "https://push.example/_arkret/edge/push/notify".to_owned(),
            authority: "push.example".to_owned(),
            path: "/_arkret/edge/push/notify".to_owned(),
            headers: vec![
                (
                    "source-service-id".to_owned(),
                    "did:webvh:z6mkfixture:sync.example.com".to_owned(),
                ),
                (
                    "destination-service-id".to_owned(),
                    "did:webvh:z6mkfixture:push.example.com".to_owned(),
                ),
            ],
            body_digest: Some(digest.wire_value.clone()),
        };

        let message = canonical_message(&req, &signature_input).unwrap();
        let signature_b64 = sign_message(&message, &signing_key);

        verify_signature(&message, &signature_b64, &public_key).expect("verifies");

        // And the body digest re-verifies against the body.
        let parsed_digest = ContentDigest::parse(&digest.wire_value).unwrap();
        verify_content_digest(&parsed_digest, body).expect("digest matches");
    }

    #[test]
    fn verify_signed_http_message_checks_headers_body_and_signature() {
        let signing_key = signing_key_from_seed(&TEST_SEED);
        let public_key = signing_key.verifying_key();
        let now = 1_715_990_010;
        let input_header = floria_signature_input(now - 1, now + 30);
        let signature_input = parse_signature_input(&input_header).unwrap();
        let body = br#"{"op":"notify"}"#;
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        let req = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: "https://push.example/_arkret/edge/push/notify".to_owned(),
            authority: "push.example".to_owned(),
            path: "/_arkret/edge/push/notify".to_owned(),
            headers: vec![
                (
                    "source-service-id".to_owned(),
                    "did:webvh:z6mkfixture:sync.example.com".to_owned(),
                ),
                (
                    "destination-service-id".to_owned(),
                    "did:webvh:z6mkfixture:push.example.com".to_owned(),
                ),
            ],
            body_digest: Some(digest.wire_value.clone()),
        };
        let message = canonical_message(&req, &signature_input).unwrap();
        let signature = sign_message(&message, &signing_key);
        let signature_header = format!("sig1=:{signature}:");
        let headers = vec![
            ("Signature-Input", input_header.as_str()),
            ("Signature", signature_header.as_str()),
            ("Content-Digest", digest.wire_value.as_str()),
            (
                "Source-Service-ID",
                "did:webvh:z6mkfixture:sync.example.com",
            ),
            (
                "Destination-Service-ID",
                "did:webvh:z6mkfixture:push.example.com",
            ),
        ];

        let verified = verify_signed_http_message(
            "POST",
            "https://push.example/_arkret/edge/push/notify",
            "push.example",
            "/_arkret/edge/push/notify",
            headers.clone(),
            body,
            &public_key,
            &SignatureVerificationPolicy::service_ingest(),
            now,
        )
        .unwrap();
        assert_eq!(
            verified.signature_input.key_id,
            "did:webvh:z6mkfixture:sync.example.com#push"
        );
        assert_eq!(
            verified.content_digest.unwrap().wire_value,
            digest.wire_value
        );

        let err = verify_signed_http_message(
            "POST",
            "https://push.example/_arkret/edge/push/notify",
            "push.example",
            "/_arkret/edge/push/notify",
            headers,
            br#"{"op":"tampered"}"#,
            &public_key,
            &SignatureVerificationPolicy::service_ingest(),
            now,
        )
        .unwrap_err();
        assert_eq!(
            err,
            HttpMessageVerificationError::Signature(SignatureError::ContentDigestMismatch)
        );
    }

    #[test]
    fn signed_json_preflight_rejects_content_encoding_and_noncanonical_bytes() {
        assert_eq!(
            validate_signed_canonical_json_body(true, br#"{"ok":true}"#).unwrap_err(),
            HttpMessageVerificationError::ContentEncodingNotAllowed
        );
        for body in [
            br#"{ "ok": true }"#.as_slice(),
            br#"{"text":"e\u0301"}"#.as_slice(),
            br#"{"text":"\u0061"}"#.as_slice(),
        ] {
            assert!(matches!(
                validate_signed_canonical_json_body(false, body),
                Err(HttpMessageVerificationError::NonCanonicalJson(_))
            ));
        }
        validate_signed_canonical_json_body(false, "{\"text\":\"é\"}".as_bytes()).unwrap();
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let signing_key = signing_key_from_seed(&TEST_SEED);
        let public_key = signing_key.verifying_key();
        let input =
            parse_signature_input(&floria_signature_input(1_700_000_000, 1_700_000_300)).unwrap();
        let req = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: "https://push.example/".to_owned(),
            authority: "push.example".to_owned(),
            path: "/".to_owned(),
            headers: vec![
                (
                    "source-service-id".to_owned(),
                    "did:webvh:z6mkfixture:sync.example.com".to_owned(),
                ),
                (
                    "destination-service-id".to_owned(),
                    "did:webvh:z6mkfixture:push.example.com".to_owned(),
                ),
            ],
            body_digest: Some(
                ContentDigest::compute(b"{}", ContentDigestAlgorithm::Sha256).wire_value,
            ),
        };
        let message = canonical_message(&req, &input).unwrap();
        let signature_b64 = sign_message(&message, &signing_key);

        // Flip one byte of the signature payload (decode, mutate,
        // re-encode) and confirm verification fails with the precise
        // SignatureInvalid variant rather than InvalidSignatureBase64.
        let mut raw = decode_signature_b64(&signature_b64).unwrap();
        raw[0] ^= 0xff;
        let tampered = encode_signature_b64(&raw);
        assert_eq!(
            verify_signature(&message, &tampered, &public_key),
            Err(SignatureError::SignatureInvalid)
        );

        // Tampering the message body (different digest) also fails.
        let other_req = SignedRequestParts {
            body_digest: Some(
                ContentDigest::compute(b"different", ContentDigestAlgorithm::Sha256).wire_value,
            ),
            ..req
        };
        let other_message = canonical_message(&other_req, &input).unwrap();
        assert_eq!(
            verify_signature(&other_message, &signature_b64, &public_key),
            Err(SignatureError::SignatureInvalid)
        );
    }

    #[test]
    fn unknown_covered_component_returns_error_not_panic() {
        // `@bogus-derived` parses as a Header("@bogus-derived") (since
        // it doesn't match any of the known `@*` derived names). When
        // the request has no such header, canonical_message returns
        // MissingCoveredComponent — not a panic.
        let header = "sig1=(\"@bogus-derived\");created=1;expires=2;keyid=\"k\";alg=\"ed25519\"";
        let parsed = parse_signature_input(header).unwrap();
        let req = SignedRequestParts {
            method: "GET".to_owned(),
            target_uri: "https://x/".to_owned(),
            authority: "x".to_owned(),
            path: "/".to_owned(),
            headers: vec![],
            body_digest: None,
        };
        let err = canonical_message(&req, &parsed).unwrap_err();
        assert!(
            matches!(err, SignatureError::MissingCoveredComponent(ref c) if c == "@bogus-derived")
        );
    }

    #[test]
    fn parse_signature_input_rejects_missing_required_params() {
        // Missing `created` → MissingSignatureInputParameter("created").
        let header = "sig1=(\"@method\");expires=2;keyid=\"k\";alg=\"ed25519\"";
        let err = parse_signature_input(header).unwrap_err();
        assert_eq!(
            err,
            SignatureError::MissingSignatureInputParameter("created")
        );

        let header = "sig1=(\"@method\");created=1;expires=2;keyid=\"k\"";
        let err = parse_signature_input(header).unwrap_err();
        assert_eq!(err, SignatureError::MissingSignatureInputParameter("alg"));

        // Empty covered components → EmptyCoveredComponents.
        let header2 = "sig1=();created=1;expires=2;keyid=\"k\";alg=\"ed25519\"";
        let err2 = parse_signature_input(header2).unwrap_err();
        assert_eq!(err2, SignatureError::EmptyCoveredComponents);

        // Missing `=` after label → MalformedSignatureInput.
        let header3 = "sig1(\"@method\");created=1";
        let err3 = parse_signature_input(header3).unwrap_err();
        assert_eq!(err3, SignatureError::MalformedSignatureInput);
    }

    #[test]
    fn parse_signature_header_finds_label_among_multiple() {
        let raw = base64_standard_encode([0xABu8; 64]);
        let header = format!("sigA=:{raw}:, sigB=:{raw}:");
        let bytes = parse_signature_header(&header, "sigB").unwrap();
        assert_eq!(bytes.len(), 64);

        let missing = parse_signature_header(&header, "sigC").unwrap_err();
        assert!(matches!(
            missing,
            SignatureError::MalformedSignatureHeader(ref l) if l == "sigC"
        ));
    }

    #[test]
    fn content_digest_round_trip_and_mismatch_detected() {
        let body = b"hello world";
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        assert!(digest.wire_value.starts_with("sha-256=:"));
        let parsed = ContentDigest::parse(&digest.wire_value).unwrap();
        assert_eq!(parsed.algorithm, ContentDigestAlgorithm::Sha256);
        assert_eq!(parsed.digest.len(), 32);
        verify_content_digest(&parsed, body).expect("matches");
        let err = verify_content_digest(&parsed, b"different body").unwrap_err();
        assert_eq!(err, SignatureError::ContentDigestMismatch);

        for unsupported in ["sha512=:abc:", "sha-512=:abc:", "md5=:abc:"] {
            let error = ContentDigest::parse(unsupported).unwrap_err();
            assert_eq!(error, SignatureError::MalformedContentDigest);
        }
    }
}
