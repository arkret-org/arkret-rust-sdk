//! Validated Arkret v1 identifiers.
//!
//! The types in this crate are the protocol boundary for DIDs, object IDs,
//! content hashes, cursors and HLC values. Constructors and Serde decoding both
//! validate their input so malformed wire identifiers fail at the edge.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

pub mod generated {
    pub mod digest_suite_codes;
}

pub use generated::digest_suite_codes::DigestSuiteCode;

pub type Result<T> = std::result::Result<T, IdentifierError>;

#[derive(Debug, Error)]
pub enum IdentifierError {
    #[error("invalid Arkret identifier: {0}")]
    InvalidId(String),

    #[error("identifier random generation failed: {0}")]
    Random(String),

    /// Spec-level value violation carrying the wire reason-code message
    /// verbatim (e.g. `schema_violation: ...`, `hlc_hard_future_skew: ...`).
    /// Used by the HLC value helpers in [`crate::hlc`] so downstream error
    /// contracts keep the exact reason strings.
    #[error("{0}")]
    Protocol(String),
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $expect:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$expect(&value) {
                    return Err(IdentifierError::InvalidId(value));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

/// Like [`id_type!`] but for **pure uuidv7 typed ids** (`ak:<kind>:<uuidv7>`,
/// single prefix, no hash alternative). In addition to the string-newtype API
/// it exposes the at-rest bare-uuid form:
///
/// - [`uuid()`](#method.uuid) — the bare RFC 9562 UUIDv7 payload, the DB storage form. Wire /
///   `Display` / `as_str` keep the canonical `ak:<kind>:<uuid>` string, so the protocol surface is
///   unchanged.
/// - [`from_uuid()`](#method.from_uuid) — rebuild the typed id from a bare DB uuid + this type's
///   kind prefix.
/// - feature `diesel`: `ToSql`/`FromSql` against PostgreSQL `uuid`, so these ids persist as native
///   `uuid` columns (bare) and reload as the prefixed wire form. Gated so the wasm/protocol build
///   never pulls diesel.
///
/// Hash-bearing kinds (`BlobRef`, `SealId`, `Hash`), `OperationId`, DIDs,
/// cursors and `trust_domain` MUST stay on plain [`id_type!`] — they have no
/// bare-uuid form.
/// `ak:realm:` is not declared here because it uses the derivation-tagged
/// 33-byte Realm token rather than a UUID.
///
/// Every Realm, including a Principal Control Realm, is event-derived:
/// `realm_id = retype(genesis event_id)`. The id therefore self-certifies
/// against the genesis Event and has no DID-subject-derived branch.
/// RFC 9562 version nibble for producer-allocated typed ids (UUIDv7).
pub const UUID_VERSION_PRODUCER_ALLOCATED: u8 = b'7';

macro_rules! uuid_id_type {
    ($name:ident, $prefix:literal, $version:expr) => {
        id_type!($name, |value: &str| is_strict_typed_id(
            value, $prefix, $version
        ));

        impl $name {
            /// The `ak:<kind>:` wire prefix this id-kind validates against.
            pub const KIND_PREFIX: &'static str = $prefix;

            /// Mint a canonical typed UUIDv7 identifier from an explicit
            /// observed Unix millisecond timestamp.
            ///
            /// The timestamp is supplied by the platform boundary, while the
            /// SDK owns the RFC 9562 layout, randomness and same-millisecond
            /// monotonic counter. If the observed clock moves backward, the
            /// encoded time stays at or after the last generated id. Callers
            /// therefore cannot accidentally mint
            /// this identifier with another kind's prefix or depend on an
            /// unsupported target clock.
            pub fn new_v7_at(unix_ms: u64) -> Self {
                Self::from_uuid(uuid_v7_at(unix_ms))
            }

            /// Bare RFC 9562 UUIDv7 payload — the database at-rest form.
            /// Infallible: construction already validated the canonical
            /// `ak:<kind>:<uuidv7>` shape.
            pub fn uuid(&self) -> uuid::Uuid {
                uuid::Uuid::parse_str(&self.0[$prefix.len()..])
                    .expect("validated typed id carries a canonical uuidv7 payload")
            }

            /// Rebuild the canonical typed id from a bare DB uuid + this
            /// kind's prefix. Used at the persistence read boundary.
            pub fn from_uuid(value: uuid::Uuid) -> Self {
                Self(format!("{}{}", $prefix, value))
            }
        }
    };
}

/// Event and Event-derived token headers reserve the high nibble as zero. Realm
/// tokens reuse that position for their derivation class, which is what makes a
/// class-zero Collaboration Realm a byte-for-byte retype of its create Event.
pub const EVENT_RESERVED_HIGH_NIBBLE: u8 = 0x0;
const IDENTITY_HEADER_HIGH_NIBBLE_SHIFT: u8 = 4;
const DIGEST_SUITE_LOW_NIBBLE_MASK: u8 = 0x0F;

fn event_digest_suite_from_header(header: u8) -> Result<DigestSuiteCode> {
    let reserved = header >> IDENTITY_HEADER_HIGH_NIBBLE_SHIFT;
    if reserved != EVENT_RESERVED_HIGH_NIBBLE {
        return Err(IdentifierError::InvalidId(format!(
            "Event reserved header nibble must be zero, got 0x{reserved:x}"
        )));
    }
    DigestSuiteCode::try_from(header & DIGEST_SUITE_LOW_NIBBLE_MASK)
}

/// Parsed form of an [`EventId`]'s complete cryptographic identity.
///
/// This is a database/codec helper only: it maps one-to-one with `EventId`
/// and does not define a stronger identity tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventIdentityKey {
    suite: DigestSuiteCode,
    digest: [u8; 32],
}

impl EventIdentityKey {
    pub fn from_event_id(value: &EventId) -> Self {
        Self::new(value.digest_suite_code(), value.digest_bytes())
    }

    pub const fn new(suite: DigestSuiteCode, digest: [u8; 32]) -> Self {
        Self { suite, digest }
    }

    pub const fn suite(self) -> DigestSuiteCode {
        self.suite
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub fn event_id(self) -> EventId {
        EventId::from_identity(self)
    }
}

/// Render the 33-byte create-Event token under a typed `ak:<kind>:` prefix.
///
/// Every Event-derived id kind shares this one encoder so a storage or
/// transport boundary that has to round-trip a raw token never grows a second
/// spelling of the wire form.
pub fn encode_digest_token(prefix: &str, bytes: [u8; 33]) -> String {
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn encode_event_token(prefix: &str, bytes: [u8; 33]) -> String {
    encode_digest_token(prefix, bytes)
}

/// Recover the 33-byte token from a typed Event-derived id.
///
/// Returns `None` unless `value` carries `prefix`, decodes to exactly 33
/// octets, re-encodes byte-for-byte to the same canonical unpadded Base64URL
/// spelling, and leads with an active v1 digest suite code whose high nibble is
/// zero.
pub fn decode_digest_token(value: &str, prefix: &str) -> Option<[u8; 33]> {
    let payload = value.strip_prefix(prefix)?;
    if payload.len() != 44
        || !payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let bytes: [u8; 33] = decoded.try_into().ok()?;
    // Require the unique canonical Base64URL-no-pad spelling.
    if URL_SAFE_NO_PAD.encode(bytes) != payload {
        return None;
    }
    DigestSuiteCode::try_from(bytes[0]).ok()?;
    Some(bytes)
}

pub fn decode_event_token(value: &str, prefix: &str) -> Option<[u8; 33]> {
    let bytes = decode_digest_token(value, prefix)?;
    event_digest_suite_from_header(bytes[0]).ok()?;
    Some(bytes)
}

fn is_event_token_id(value: &str, prefix: &str) -> bool {
    decode_event_token(value, prefix).is_some()
}

macro_rules! event_token_id_type {
    ($name:ident, $prefix:literal) => {
        id_type!($name, |value: &str| is_event_token_id(value, $prefix));

        impl $name {
            pub const KIND_PREFIX: &'static str = $prefix;

            /// Retype a create Event identity without changing its 33-byte token.
            pub fn from_event_id(event_id: &EventId) -> Self {
                Self(encode_event_token($prefix, event_id.token_bytes()))
            }

            pub fn token_bytes(&self) -> [u8; 33] {
                decode_event_token(&self.0, $prefix)
                    .expect("validated Event-derived id carries a canonical token")
            }

            pub fn digest_suite_code(&self) -> DigestSuiteCode {
                event_digest_suite_from_header(self.token_bytes()[0])
                    .expect("validated Event-derived id carries an active suite code")
            }

            pub fn digest_bytes(&self) -> [u8; 32] {
                let bytes = self.token_bytes();
                let mut digest = [0_u8; 32];
                digest.copy_from_slice(&bytes[1..]);
                digest
            }
        }
    };
}

macro_rules! declare_event_token_id_kinds {
    ($($name:ident, $prefix:literal;)*) => {
        $(event_token_id_type!($name, $prefix);)*

        /// Every typed id whose payload is the create Event's 33-byte token.
        pub const DECLARED_EVENT_TOKEN_ID_KIND_PREFIXES: &[&str] = &[$($prefix),*];
    };
}

/// Declare every pure-uuidv7 typed id in one block so the crate can also
/// publish the set of `ak:<kind>:` prefixes it actually implements.
///
/// Individual [`uuid_id_type!`] calls cannot be enumerated after expansion —
/// `KIND_PREFIX` is an inherent associated const with no registry behind it —
/// so the spec-coverage constants in `arkret-schema` had to repeat the kind
/// list as hand-written strings. That copy silently fell five kinds behind the
/// registry (`authorization_lease`, `invite_locator`, `message_stream`,
/// `sidecar`). [`DECLARED_UUID_ID_KIND_PREFIXES`]
/// closes that gap: it is derived from the same literals the types validate
/// against, so it cannot disagree with them.
///
/// Hash-bearing, hybrid and special-form kinds stay on plain [`id_type!`] and
/// are deliberately absent from this block — they have no `ak:<kind>:<uuidv7>`
/// wire form and the spec lists them under `special_forms`.
macro_rules! declare_uuid_id_kinds {
    ($($name:ident, $prefix:literal, $version:expr;)*) => {
        $(uuid_id_type!($name, $prefix, $version);)*

        /// Every `ak:<kind>:` prefix this crate ships a typed uuidv7 id for.
        ///
        /// Sorted by declaration, deduplicated by construction (two types
        /// cannot share a prefix without one of them failing to validate the
        /// other's values). Cross-checked against the spec
        /// `id-kind-registry.json` by `arkret-schema`.
        pub const DECLARED_UUID_ID_KIND_PREFIXES: &[&str] = &[$($prefix),*];
    };
}

/// Declare every **special-form** id kind in one block, so the crate can also
/// publish the set of `special_forms` kinds it actually implements.
///
/// Special forms are the spec `id-kind-registry.json` `special_forms` rows:
/// `ak:<kind>:` identifiers whose payload is *not* a UUIDv7 — content digests,
/// opaque base64url tokens, a cell family plus subject. Each therefore keeps
/// its own validator instead of sharing one like [`declare_uuid_id_kinds!`].
///
/// What the two blocks share is the reason they exist. `arkret-schema`'s
/// `SUPPORTED_SPECIAL_FORM_ID_KINDS` was a hand-written list with nothing behind
/// it, and it claimed four kinds this crate shipped no type for (`mls`,
/// `pseudonym`, `plan`, `service_registration_receipt`) — the mirror image of the
/// uuid-side gap, where types existed the list had never picked up.
/// [`DECLARED_SPECIAL_FORM_ID_KINDS`] is derived from the same declarations the
/// types are generated from, so neither direction can drift unnoticed.
///
/// Identifiers that are not registry `special_forms` rows stay on plain
/// [`id_type!`]: [`Did`], [`Hash`] (a bare `<algo>:<hex>` digest with no `ak:`
/// prefix), [`OperationId`] (producer-allocated, but with no bare-uuid form)
/// and [`DeviceMessageTransactionId`] (a payload field charset, not an id
/// kind).
macro_rules! declare_special_form_id_kinds {
    ($($name:ident, $kind:literal, $expect:expr;)*) => {
        $(
            id_type!($name, $expect);

            impl $name {
                /// The `special_forms` registry `kind` this type implements.
                pub const ID_KIND: &'static str = $kind;
            }
        )*

        /// Every `special_forms` kind this crate ships a validated type for.
        ///
        /// Cross-checked against the spec `id-kind-registry.json` and
        /// `arkret_schema::SUPPORTED_SPECIAL_FORM_ID_KINDS` by
        /// `arkret-schema`'s `id_kind_coverage` test.
        pub const DECLARED_SPECIAL_FORM_ID_KINDS: &[&str] = &[$($kind),*];
    };
}

/// Validate a DID scalar. Method name
/// MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
/// method-specific-id MUST be non-empty and contain no whitespace, fragment,
/// or query marker. DID URL fields use a separate string surface and require a
/// `#key` fragment.
///
/// Zero-allocation public validator for the DID scalar form. This is the same
/// predicate used by `id_type!(Did, is_did)`, exposed for downstream callers
/// that need validation without constructing a [`Did`].
pub fn is_did(value: &str) -> bool {
    if value.len() > 2048 {
        return false;
    }
    let Some(remainder) = value.strip_prefix("did:") else {
        return false;
    };
    let Some((method, method_specific_id)) = remainder.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || method_specific_id.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
    if method_specific_id
        .bytes()
        .any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'#' | b'?'))
    {
        return false;
    }
    true
}

/// Validate the stable DID-derived identity-core form registered by the
/// protocol. A core id is deliberately not a DID and cannot be sent to a DID
/// resolver without a separately verified current [`Did`].
pub fn is_core_id(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("ak:did_core:") else {
        return false;
    };
    let Some((method, method_specific_core)) = remainder.split_once(':') else {
        return false;
    };
    !method.is_empty()
        && !method_specific_core.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !method_specific_core
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'?' | b'#'))
        && value.len() <= 512
}

fn is_hash(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    let expected_len = match algorithm {
        "sha256" | "blake3" => 64,
        _ => return false,
    };
    digest.len() == expected_len
        && digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn has_prefix<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.starts_with(prefix) && value.len() > prefix.len()
}

/// Validate a canonical Arkret cell-family identifier.
///
/// Cell families are first-class registry identifiers with the wire form
/// `ak.component.<facet-path>.v<n>`. The complete family identifier is
/// embedded unchanged in a [`CellRef`].
pub fn is_cell_family(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak.component.") else {
        return false;
    };
    let Some((facet_path, version)) = rest.rsplit_once(".v") else {
        return false;
    };

    !facet_path.is_empty()
        && facet_path.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

/// Validate the canonical `ak:cell:<cell-family>:<subject>` wire form.
///
/// The family MUST be a complete `ak.component.*.v<n>` identifier. Subjects
/// may contain colon-separated typed identifiers; an empty subject is allowed
/// for a family-scoped singleton and is represented by the trailing colon.
pub fn is_cell_ref(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:cell:") else {
        return false;
    };
    let Some((family, subject)) = rest.split_once(':') else {
        return false;
    };
    if !is_cell_family(family) {
        return false;
    }
    if subject.is_empty() {
        return true;
    }

    subject.split(':').all(is_cell_subject_segment)
}

fn is_cell_subject_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }

    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-') {
            return false;
        }
        index += 1;
    }
    true
}

/// Validate the `ak:plan:<base64url>` wire form. The suffix is an opaque,
/// non-empty, unpadded base64url token. Spec: id-kind-registry.json
/// `special_forms[plan]`; pattern matches applet-install-plan.schema.json
/// `^ak:plan:[A-Za-z0-9_-]+$`.
pub fn is_plan_id(value: &str) -> bool {
    match value.strip_prefix("ak:plan:") {
        Some(token) => {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }
        None => false,
    }
}

/// Validate the `ak:service_registration_receipt:<sha256-hex>` wire form. The
/// suffix is the lower-case hex SHA-256 over the canonical receipt claims, so
/// it is exactly 64 hex digits — unlike [`is_hash`], which carries its own
/// `<algo>:` prefix. Spec: id-kind-registry.json
/// `special_forms[service_registration_receipt]`; pattern matches
/// service-operation-dtos.schema.json
/// `^ak:service_registration_receipt:[0-9a-f]{64}$`.
pub fn is_service_registration_receipt_id(value: &str) -> bool {
    match value.strip_prefix("ak:service_registration_receipt:") {
        Some(digest) => {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        None => false,
    }
}

/// Validate the `ak:trust_domain:<scope>` wire form. Scope MUST be lowercase
/// `[a-z0-9._:-]` (alphanumerics + dot/dash/underscore/colon), max 128 chars,
/// non-empty. Round R2/R3 (2026-05-20). Spec: id-kind-registry.json
/// `special_forms[trust_domain]`; pattern matches the recovery trust-domain contract
/// `^ak:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$`.
///
/// Zero-allocation public validator for the trust-domain wire form. This is
/// the same predicate used by `id_type!(TrustDomainId, is_trust_domain)`.
pub fn is_trust_domain(value: &str) -> bool {
    let Some(scope) = value.strip_prefix("ak:trust_domain:") else {
        return false;
    };
    if scope.is_empty() || scope.len() > 128 {
        return false;
    }
    let bytes = scope.as_bytes();
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    scope.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b':'
        )
    })
}

/// Strict typed-ID validator: payload MUST be a canonical RFC 9562 UUID
/// version 7 (36 chars, lower-case hex `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx`
/// where N ∈ {8,9,a,b}) per `conformance/encoding.md` §4. Use this when
/// you need to reject malformed wire input (e.g. ULIDs, UUIDv4); the
/// default `has_prefix` only checks the kind prefix and is more permissive.
pub fn is_strict_typed_id(value: &str, prefix: &str, version_nibble: u8) -> bool {
    match value.strip_prefix(prefix) {
        Some(payload) => is_lowercase_typed_uuid(payload, version_nibble),
        None => false,
    }
}

/// Generate a fresh canonical `<prefix><uuidv7>` identifier string using a
/// freshly generated RFC 9562 UUIDv7. The output is always lowercase hex per
/// `conformance/encoding.md` §4 and is the canonical wire form for typed
/// `ak:<kind>:` identifiers (Arkret v1, 2026-05-09 onward).
pub fn new_prefixed_uuid7(prefix: &str) -> String {
    assert!(
        !EVENT_DERIVED_ID_KIND_PREFIXES.contains(&prefix),
        "{prefix} is an event-derived kind: its id MUST come from          <Kind>Id::from_event_id, never from a freshly minted identifier"
    );
    format!("{prefix}{}", uuid_v7_at(platform_unix_ms()))
}

/// The sole v1 Realm derivation class. The high nibble is reserved zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RealmDerivationClass {
    EventDerived = 0x0,
}

impl TryFrom<u8> for RealmDerivationClass {
    type Error = IdentifierError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x0 => Ok(Self::EventDerived),
            _ => Err(IdentifierError::InvalidId(format!(
                "Realm token reserved high nibble must be zero, got 0x{value:x}"
            ))),
        }
    }
}

/// Typed id prefixes whose ids are derived from a create Event rather than
/// minted, per the spec `id-kind-registry.json` `id_form` column.
pub const EVENT_DERIVED_ID_KIND_PREFIXES: &[&str] = &[
    "ak:actor_profile:",
    "ak:appeal:",
    "ak:audit_binding:",
    "ak:audit_release:",
    "ak:audit_session:",
    "ak:call:",
    "ak:circle:",
    "ak:event:",
    "ak:grant:",
    "ak:invite:",
    "ak:message:",
    "ak:moderation_queue_item:",
    "ak:morph:",
    "ak:realm:",
    "ak:relation:",
    "ak:report:",
    "ak:sidecar:",
    "ak:space:",
    "ak:strand:",
    "ak:view:",
];

static UUID_V7_CONTEXT: std::sync::Mutex<uuid::ContextV7> =
    std::sync::Mutex::new(uuid::ContextV7::new());

/// Generate a bare RFC 9562 UUIDv7 from an explicit observed platform time.
///
/// This is the only untyped generation primitive exposed by the SDK. Protocol
/// identifiers should use their concrete `new_v7_at` constructor instead;
/// this function exists for opaque non-protocol correlation values that still
/// require UUIDv7 ordering. The shared context preserves monotonicity across a
/// clock rollback, so the encoded timestamp may be later than `unix_ms` but is
/// never moved backward relative to an id already minted in this process.
pub fn uuid_v7_at(unix_ms: u64) -> uuid::Uuid {
    let seconds = unix_ms / 1_000;
    let subsec_nanos = ((unix_ms % 1_000) * 1_000_000) as u32;
    let context = UUID_V7_CONTEXT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    uuid::Uuid::new_v7(uuid::Timestamp::from_unix(&*context, seconds, subsec_nanos))
}

fn platform_unix_ms() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Validate that `value` is a canonical lower-case RFC 9562 UUIDv7 in the
/// 36-character `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` form (N ∈ {8,9,a,b}),
/// per `conformance/encoding.md` §4.
///
/// The v1 wire forbids upper-case hex, missing dashes, URN/Microsoft braces,
/// and any UUID version other than 7.
pub fn is_lowercase_typed_uuid(value: &str, version_nibble: u8) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    // Reject upper-case hex.
    for &b in bytes {
        if b.is_ascii_uppercase() {
            return false;
        }
    }
    // Position structure check, then version + variant nibble check.
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                let c = b as char;
                if !c.is_ascii_digit() && !matches!(c, 'a'..='f') {
                    return false;
                }
            }
        }
    }
    // Version nibble at byte position 14 (third group: Vxxx).
    // `0` is reserved for derivation-tagged identifiers. Realm identifiers
    // use the event-derived v8 form exclusively.
    if version_nibble == 0 {
        if bytes[14] != b'8' {
            return false;
        }
    } else if bytes[14] != version_nibble {
        return false;
    }
    // Variant nibble at byte position 19 (fourth group: Nxxx, N ∈ {8,9,a,b}).
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    true
}

id_type!(
    /// Stable DID-derived identity core used for subject equality, historical
    /// attribution, identity references, membership indexes, and the identity
    /// component of business hash preimages.
    ///
    /// This is not a resolvable DID and must never be used as registration or
    /// resolution input. It answers only "who" and is not, by itself, an
    /// authorization proof; authorization must bind the applicable PCR,
    /// registration, MLS, service, or Agent authority lineage.
    DidCoreId,
    is_core_id
);

impl DidCoreId {
    /// Borrow this already-normalized identity core.
    ///
    /// This is a shape-neutral convenience for APIs that also accept projected
    /// DIDs; it performs no role or authority admission.
    pub const fn as_core_id(&self) -> &Self {
        self
    }
}

id_type!(
    /// Canonical resolvable bare DID used only at registration, resolution,
    /// proof verification-method, and method-evidence boundaries.
    ///
    /// It may legitimately change as resolution state evolves. It must not be
    /// used for subject equality and is not, by itself, a business authority.
    Did,
    is_did
);

/// Project a canonical resolvable DID through the active v1 method adapter.
///
/// This deliberately implements only registry-active adapters. Generic code
/// must never manufacture a core id by prefix substitution.
pub fn project_did_to_core_id(did: &Did) -> Result<DidCoreId> {
    let value = did.as_str();
    if let Some(remainder) = value.strip_prefix("did:webvh:") {
        let scid = remainder
            .split_once(':')
            .map(|(scid, _)| scid)
            .filter(|scid| !scid.is_empty())
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))?;
        return DidCoreId::new(format!("ak:did_core:webvh:{scid}"));
    }
    if value.starts_with("did:web:") {
        let method_specific_id = value
            .strip_prefix("did:web:")
            .expect("checked did:web prefix");
        return DidCoreId::new(format!("ak:did_core:web:{method_specific_id}"));
    }
    if let Some(method_specific_id) = value.strip_prefix("did:key:") {
        return DidCoreId::new(format!("ak:did_core:key:{method_specific_id}"));
    }
    Err(IdentifierError::InvalidId(format!(
        "no active DID method adapter for {value}"
    )))
}

// Protocol object IDs use typed prefixes with canonical RFC 9562 UUIDv7
// payloads. Pure-uuid kinds go through `declare_uuid_id_kinds!` so they
// persist as native `uuid` columns (bare) while keeping the
// `ak:<kind>:<uuid>` wire form — and so the prefix set stays enumerable.
//
// Every entry here MUST have an active `id_kinds` row in the spec
// `registry/id-kind-registry.json`; `arkret-schema` fails closed in both
// directions.
declare_uuid_id_kinds! {
    // AKP-0008/0009 (spec head 37ce729) — personal agent auxiliary typed ids.
    // `agent_id` business references use the stable `DidCoreId`; full Agent
    // DIDs remain confined to registration and method-resolution evidence.
    // Audit release-session + attestation typed ids (id-kind-registry kinds
    // `attestation` / `audit_binding` / `audit_release` / `audit_session`).
    AttestationId, "ak:attestation:", UUID_VERSION_PRODUCER_ALLOCATED;
    // RTC call participant id (id-kind-registry kind `rtc_participant`).
    RtcParticipantId, "ak:rtc_participant:", UUID_VERSION_PRODUCER_ALLOCATED;
    // Key-backup hardening (B-C) typed ids.
    BackupSeriesId, "ak:backup_series:", UUID_VERSION_PRODUCER_ALLOCATED;
    RecoverySessionId, "ak:recovery_session:", UUID_VERSION_PRODUCER_ALLOCATED;
    AnnounceId, "ak:announce:", UUID_VERSION_PRODUCER_ALLOCATED;
    AppletId, "ak:applet:", UUID_VERSION_PRODUCER_ALLOCATED;
    BackupId, "ak:backup:", UUID_VERSION_PRODUCER_ALLOCATED;
    BatchId, "ak:batch:", UUID_VERSION_PRODUCER_ALLOCATED;
    BlobId, "ak:blob:", UUID_VERSION_PRODUCER_ALLOCATED;
    BlockId, "ak:block:", UUID_VERSION_PRODUCER_ALLOCATED;
    ConsentId, "ak:consent:", UUID_VERSION_PRODUCER_ALLOCATED;
    CapabilityId, "ak:capability:", UUID_VERSION_PRODUCER_ALLOCATED;
    ChunkId, "ak:chunk:", UUID_VERSION_PRODUCER_ALLOCATED;
    // AKP-0007 (2026-05-08) — Circle id-kind. Intra-Realm cryptographic
    // sub-boundary; see spec artifacts/registry/id-kind-registry.json and
    // zh/models/circle.md.
    ClaimId, "ak:claim:", UUID_VERSION_PRODUCER_ALLOCATED;
    DeviceMessageId, "ak:device_message:", UUID_VERSION_PRODUCER_ALLOCATED;
    FilterId, "ak:filter:", UUID_VERSION_PRODUCER_ALLOCATED;
    FrameId, "ak:frame:", UUID_VERSION_PRODUCER_ALLOCATED;
    MessageStreamId, "ak:message_stream:", UUID_VERSION_PRODUCER_ALLOCATED;
    InviteLocatorId, "ak:invite_locator:", UUID_VERSION_PRODUCER_ALLOCATED;
    KeyEventId, "ak:key_event:", UUID_VERSION_PRODUCER_ALLOCATED;
    AuthorizationLeaseId, "ak:authorization_lease:", UUID_VERSION_PRODUCER_ALLOCATED;
    DeviceId, "ak:device:", UUID_VERSION_PRODUCER_ALLOCATED;
    NotificationId, "ak:notification:", UUID_VERSION_PRODUCER_ALLOCATED;
    PolicyId, "ak:policy:", UUID_VERSION_PRODUCER_ALLOCATED;
    PresentationId, "ak:presentation:", UUID_VERSION_PRODUCER_ALLOCATED;
    ReceiptId, "ak:receipt:", UUID_VERSION_PRODUCER_ALLOCATED;
    ReadCursorId, "ak:read_cursor:", UUID_VERSION_PRODUCER_ALLOCATED;
    RequestId, "ak:request:", UUID_VERSION_PRODUCER_ALLOCATED;
    ScheduledSendId, "ak:scheduled_send:", UUID_VERSION_PRODUCER_ALLOCATED;
    SnapshotId, "ak:snapshot:", UUID_VERSION_PRODUCER_ALLOCATED;
    SubscriptionId, "ak:subscription:", UUID_VERSION_PRODUCER_ALLOCATED;
    TransactionId, "ak:transaction:", UUID_VERSION_PRODUCER_ALLOCATED;
}

declare_event_token_id_kinds! {
    ActorProfileId, "ak:actor_profile:";
    TypedAppealId, "ak:appeal:";
    AuditBindingId, "ak:audit_binding:";
    AuditReleaseId, "ak:audit_release:";
    AuditSessionId, "ak:audit_session:";
    CallId, "ak:call:";
    CircleId, "ak:circle:";
    EventId, "ak:event:";
    GrantId, "ak:grant:";
    InviteId, "ak:invite:";
    MessageId, "ak:message:";
    ModerationQueueItemId, "ak:moderation_queue_item:";
    MorphId, "ak:morph:";
    RelationId, "ak:relation:";
    ReportId, "ak:report:";
    SidecarId, "ak:sidecar:";
    SpaceId, "ak:space:";
    StrandId, "ak:strand:";
    ViewId, "ak:view:";
}

fn decode_session_grant_token(value: &str) -> Option<[u8; 33]> {
    let token = decode_digest_token(value, SessionGrantId::KIND_PREFIX)?;
    (token[0] == DigestSuiteCode::Sha256.as_u8()).then_some(token)
}

fn decode_account_status_record_token(value: &str) -> Option<[u8; 33]> {
    let token = decode_digest_token(value, AccountStatusRecordId::KIND_PREFIX)?;
    (token[0] == DigestSuiteCode::Sha256.as_u8()).then_some(token)
}

id_type!(AccountStatusRecordId, |value: &str| {
    decode_account_status_record_token(value).is_some()
});

impl AccountStatusRecordId {
    pub const KIND_PREFIX: &'static str = "ak:account_status_record:";

    pub fn from_record_digest(digest: [u8; 32]) -> Self {
        let mut token = [0_u8; 33];
        token[0] = DigestSuiteCode::Sha256.as_u8();
        token[1..].copy_from_slice(&digest);
        Self(encode_digest_token(Self::KIND_PREFIX, token))
    }

    pub fn record_digest(&self) -> [u8; 32] {
        let token = decode_account_status_record_token(&self.0)
            .expect("validated account-status record id carries a canonical digest token");
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&token[1..]);
        digest
    }
}

id_type!(SessionGrantId, |value: &str| decode_session_grant_token(
    value
)
.is_some());

impl SessionGrantId {
    pub const KIND_PREFIX: &'static str = "ak:session_grant:";

    /// Derive the issuer-record identifier from the SHA-256 digest of the
    /// closed `ak.session_grant.issuance.v1` preimage.
    pub fn from_issuance_digest(digest: [u8; 32]) -> Self {
        let mut token = [0_u8; 33];
        token[0] = DigestSuiteCode::Sha256.as_u8();
        token[1..].copy_from_slice(&digest);
        Self(encode_digest_token(Self::KIND_PREFIX, token))
    }

    pub fn token_bytes(&self) -> [u8; 33] {
        decode_session_grant_token(&self.0)
            .expect("validated SessionGrant id carries a canonical digest token")
    }

    pub fn digest_suite_code(&self) -> DigestSuiteCode {
        DigestSuiteCode::try_from(self.token_bytes()[0])
            .expect("validated SessionGrant id carries an active digest suite")
    }

    pub fn issuance_digest(&self) -> [u8; 32] {
        let token = self.token_bytes();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&token[1..]);
        digest
    }
}

/// Issuer-record identifiers whose wire payload is a complete registered
/// suite byte plus a 32-byte digest, but whose authority is not an Event.
pub const DECLARED_SUITE_TAGGED_FULL_DIGEST_ID_KIND_PREFIXES: &[&str] = &[
    SessionGrantId::KIND_PREFIX,
    AccountStatusRecordId::KIND_PREFIX,
];

fn decode_realm_token(value: &str) -> Option<[u8; 33]> {
    let payload = value.strip_prefix("ak:realm:")?;
    if payload.len() != 44
        || !payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let bytes: [u8; 33] = decoded.try_into().ok()?;
    if URL_SAFE_NO_PAD.encode(bytes) != payload {
        return None;
    }
    RealmDerivationClass::try_from(bytes[0] >> IDENTITY_HEADER_HIGH_NIBBLE_SHIFT).ok()?;
    let suite = DigestSuiteCode::try_from(bytes[0] & DIGEST_SUITE_LOW_NIBBLE_MASK).ok()?;
    if suite != DigestSuiteCode::Sha256 {
        return None;
    }
    Some(bytes)
}

fn is_realm_id(value: &str) -> bool {
    decode_realm_token(value).is_some()
}

id_type!(RealmId, is_realm_id);

impl RealmId {
    pub const KIND_PREFIX: &'static str = "ak:realm:";

    pub fn from_event_id(event_id: &EventId) -> Self {
        assert_eq!(
            event_id.digest_suite_code(),
            DigestSuiteCode::Sha256,
            "v1 Realm identity is fixed to SHA-256"
        );
        Self(encode_event_token(
            Self::KIND_PREFIX,
            event_id.token_bytes(),
        ))
    }

    pub fn token_bytes(&self) -> [u8; 33] {
        decode_realm_token(&self.0).expect("validated Realm id carries a canonical token")
    }

    pub fn digest_suite_code(&self) -> DigestSuiteCode {
        DigestSuiteCode::try_from(self.token_bytes()[0] & DIGEST_SUITE_LOW_NIBBLE_MASK)
            .expect("validated Realm id carries an active digest suite")
    }

    pub fn digest_bytes(&self) -> [u8; 32] {
        let token = self.token_bytes();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&token[1..]);
        digest
    }

    /// Retype any Realm back to its genesis Event identity.
    pub fn event_id(&self) -> EventId {
        EventId::from_token_bytes(self.token_bytes())
            .expect("validated Realm id is a retyped genesis Event id")
    }
}

// Special-form id kinds (`special_forms` in the spec id-kind-registry). Every
// entry here MUST have an active `special_forms` row; `arkret-schema` fails
// closed in both directions, exactly as it does for the uuid block above.
//
// `mls` and `pseudonym` are deliberately absent: the registry marks both
// `profile_extension`, they are validated by the E2EE profile rather than by
// this crate, and the SDK ships no type for either. Declaring them was a false
// coverage claim, not a gap to fill.
declare_special_form_id_kinds! {
    // Hybrid: a bare `<algo>:<hex>` digest or the `ak:blob:` content-addressed
    // form. Distinct from `BlobId`, which is the `ak:blob:<uuidv7>` metadata id.
    BlobRef, "blob", is_blob_ref;
    CellRef, "cell", is_cell_ref;
    Cursor, "cursor", has_prefix("ak:cursor:");
    PlanId, "plan", is_plan_id;
    SealId, "seal", is_content_addressed("ak:seal:");
    ServiceRegistrationReceiptId,
        "service_registration_receipt",
        is_service_registration_receipt_id;
    // Deployment-scope replay-boundary identifier. The public name follows
    // the same kind-aligned convention as RealmId/EventId/DidCoreId.
    TrustDomainId, "trust_domain", is_trust_domain;
}

// `id-kind-registry.json` gives `operation` `wire_form: ak:operation:<uuid>`
// and `id_form: producer_allocated`, and it is not a `special_forms` row — the
// content-addressed kinds (`blob`, `seal`, `service_registration_receipt`,
// `membership_compensation_delegation`) all are. So a bare digest is not an
// Operation id: accepting one here was permissiveness no producer emitted and
// no consumer relied on. It stays a text `id_type!` because there is no bare
// uuid form.
id_type!(OperationId, |value: &str| is_strict_typed_id(
    value,
    "ak:operation:",
    UUID_VERSION_PRODUCER_ALLOCATED
));

impl OperationId {
    /// Mint the UUIDv7 form of an Operation id at an explicit Unix timestamp.
    pub fn new_v7_at(unix_ms: u64) -> Self {
        Self(format!("ak:operation:{}", uuid_v7_at(unix_ms)))
    }
}
id_type!(DeviceMessageTransactionId, is_device_message_transaction_id);

impl MessageId {
    /// Retype this Message token as its durable create Event identity.
    pub fn event_id(&self) -> EventId {
        EventId(encode_event_token("ak:event:", self.token_bytes()))
    }
}

impl EventId {
    /// Construct from the canonical binary token used by database/wire codecs.
    pub fn from_token_bytes(token: [u8; 33]) -> Result<Self> {
        event_digest_suite_from_header(token[0])?;
        Ok(Self(encode_event_token(Self::KIND_PREFIX, token)))
    }

    /// Encode the complete cryptographic identity as a zero reserved nibble,
    /// suite nibble, and full digest.
    pub fn from_identity(identity: EventIdentityKey) -> Self {
        let mut token = [0_u8; 33];
        token[0] = (EVENT_RESERVED_HIGH_NIBBLE << IDENTITY_HEADER_HIGH_NIBBLE_SHIFT)
            | identity.suite.as_u8();
        token[1..].copy_from_slice(&identity.digest);
        Self::from_token_bytes(token).expect("EventIdentityKey has an active suite code")
    }

    pub fn from_digest(suite: arkret_canonical::DigestSuite, digest: [u8; 32]) -> Self {
        Self::from_identity(EventIdentityKey::new(
            DigestSuiteCode::from_digest_suite(suite),
            digest,
        ))
    }

    /// Construct the Event identity represented by a validated full wire digest.
    pub fn from_event_digest(value: &Hash) -> Result<Self> {
        Ok(EventIdentityKey::from_event_digest(value)?.event_id())
    }

    pub fn identity_key(&self) -> EventIdentityKey {
        EventIdentityKey::from_event_id(self)
    }

    /// Recover the suite-bearing full Event digest losslessly encoded by this id.
    pub fn event_digest(&self) -> Hash {
        self.identity_key().event_digest()
    }
}

fn is_blob_ref(value: &str) -> bool {
    if is_hash(value) || is_strict_typed_id(value, "ak:blob:", UUID_VERSION_PRODUCER_ALLOCATED) {
        return true;
    }
    value.strip_prefix("ak:blob:").is_some_and(is_hash)
}

fn is_content_addressed<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.strip_prefix(prefix).is_some_and(is_hash)
}

/// `device-message.schema.json#/$defs/key_verification_content.transaction_id`:
/// `^[A-Za-z0-9._~=-]{1,128}$`.
///
/// This is a **different namespace** from [`TransactionId`], which is
/// `ak:transaction:<uuidv7>` and serves the `security-transaction.schema.json`
/// family. The two share a word, not a value space: `:` is outside the charset
/// above, so *every* `TransactionId` value violates this pattern. Typing the
/// device-message field as `TransactionId` would therefore make it impossible
/// to author conformant `ak.key.verification.*` content.
fn is_device_message_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
        })
}

fn is_push_target_id(value: &str) -> bool {
    const PREFIX: &str = "ak:pseudonym:push:";
    let Some(encoded) = value.strip_prefix(PREFIX) else {
        return false;
    };
    if encoded.len() != 43 {
        return false;
    }
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    decoded.len() == 32 && URL_SAFE_NO_PAD.encode(decoded) == encoded
}

id_type!(
    /// Canonical pairwise push pseudonym derived as the complete 32-octet
    /// HMAC-SHA256 output and encoded as an unpadded Base64URL typed ID.
    PushTargetId,
    is_push_target_id
);

// Bare `<algo>:<hex>` digest, e.g. an Event's `proof.event_digest`, a Seal
// root, or a control-plane `Seal.delta[]` entry. `ak:seal:` prefixes the
// content-addressed Seal identifier itself, which is a special form and is
// declared with the other `special_forms` kinds.
id_type!(Hash, is_hash);

impl Hash {
    /// Parse the algorithm carried by this already validated typed digest.
    ///
    /// This does not establish a Realm's trusted live suite; callers may use
    /// it only when the digest itself is the authenticated selector or
    /// commitment being verified.
    pub fn digest_suite(&self) -> Result<arkret_canonical::DigestSuite> {
        let (algorithm, _) = self
            .as_str()
            .split_once(':')
            .ok_or_else(|| IdentifierError::InvalidId(self.as_str().to_owned()))?;
        arkret_canonical::canonical::digest_suite(algorithm)
            .map_err(|_| IdentifierError::InvalidId(self.as_str().to_owned()))
    }
}

impl EventIdentityKey {
    pub fn from_event_digest(value: &Hash) -> Result<Self> {
        let (suite, hex) = value
            .as_str()
            .split_once(':')
            .ok_or_else(|| IdentifierError::InvalidId(value.as_str().to_owned()))?;
        let suite = match suite {
            "sha256" => DigestSuiteCode::Sha256,
            "blake3" => DigestSuiteCode::Blake3,
            _ => return Err(IdentifierError::InvalidId(value.as_str().to_owned())),
        };
        let mut digest = [0_u8; 32];
        for (index, octet) in digest.iter_mut().enumerate() {
            *octet = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| IdentifierError::InvalidId(value.as_str().to_owned()))?;
        }
        Ok(Self::new(suite, digest))
    }

    pub fn event_digest(self) -> Hash {
        let mut hex = String::with_capacity(64);
        for byte in self.digest {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
        }
        Hash(format!("{}:{hex}", self.suite.as_str()))
    }
}

impl BlobRef {
    /// Create a content-addressed `sha256:...` blob reference from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_digest(bytes))
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    arkret_canonical::canonical::sha256_digest(bytes)
}

impl Did {
    /// Return the DID method name.
    pub fn method(&self) -> &str {
        self.0
            .strip_prefix("did:")
            .and_then(|remainder| remainder.split_once(':').map(|(method, _)| method))
            .expect("DID constructed with method")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct Hlc(String);

impl Hlc {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        Self::parse_parts(&value)?;
        Ok(Self(value))
    }

    pub fn validate(value: &str) -> Result<()> {
        Self::parse_parts(value).map(|_| ())
    }

    pub fn from_components(physical_ms: u64, logical: u32, node_id: &str) -> Result<Self> {
        if physical_ms > 0xffff_ffff_ffff
            || logical > 0xffff
            || node_id.len() != 8
            || !node_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(IdentifierError::InvalidId(format!(
                "{physical_ms:012x}-{logical:04x}-{node_id}"
            )));
        }
        Ok(Self(format!("{physical_ms:012x}-{logical:04x}-{node_id}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    fn parse_parts(value: &str) -> Result<(u64, u64, &str)> {
        let mut parts = value.split('-');
        let unix_ms = parts
            .next()
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let logical = parts
            .next()
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let node = parts
            .next()
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))?;
        if parts.next().is_some()
            || value.len() != 26
            || value.as_bytes().get(12) != Some(&b'-')
            || value.as_bytes().get(17) != Some(&b'-')
            || node.is_empty()
            || node.len() != 8
            || !node
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(IdentifierError::InvalidId(value.to_owned()));
        }
        Ok((unix_ms, logical, node))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hlc {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_ms, self_logical, self_node) =
            Self::parse_parts(&self.0).expect("HLC constructed with valid parts");
        let (other_ms, other_logical, other_node) =
            Self::parse_parts(&other.0).expect("HLC constructed with valid parts");
        (self_ms, self_logical, self_node).cmp(&(other_ms, other_logical, other_node))
    }
}

impl Serialize for Hlc {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

fn parse_lower_hex(part: &str, original: &str) -> Result<u64> {
    if part.is_empty()
        || !matches!(part.len(), 4 | 8 | 12)
        || !part
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(IdentifierError::InvalidId(original.to_owned()));
    }
    u64::from_str_radix(part, 16).map_err(|_| IdentifierError::InvalidId(original.to_owned()))
}

pub mod hlc;

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[test]
    fn did_validation_rejects_handles() {
        assert!(Did::new("did:webvh:z6mkfixture:alice.example").is_ok());
        assert!(Did::new("alice.example").is_err());
    }

    #[test]
    fn did_validation_accepts_uuid_method() {
        assert!(Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn push_target_id_requires_complete_canonical_hmac_output() {
        let canonical = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";
        assert_eq!(PushTargetId::new(canonical).unwrap().as_str(), canonical);
        for invalid in [
            "ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV",
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm9",
            "kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "ak:device:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        ] {
            assert!(PushTargetId::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn applet_id_rejects_service_did_and_untyped_values() {
        let typed =
            serde_json::from_str::<AppletId>(r#""ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d""#)
                .unwrap();
        assert_eq!(
            typed.as_str(),
            "ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d"
        );
        assert!(serde_json::from_str::<AppletId>(r#""ak:did_core:webvh:z6mkfixture""#).is_err());
        assert!(
            serde_json::from_str::<AppletId>(r#""did:webvh:z6mkfixture:applet.example""#).is_err()
        );
        assert!(serde_json::from_str::<AppletId>(r#""applet.example""#).is_err());
    }

    /// Method-name segment is `[a-z0-9]+` only;
    /// `.`/`-`/`_`/`:` and whitespace MUST be rejected. DID scalar fields
    /// also reject DID URL query / fragment markers.
    #[test]
    fn did_validation_rejects_method_punctuation() {
        // Method-segment with dot/dash/underscore/colon — all rejected.
        assert!(Did::new("did:web.test:example").is_err()); // DRIFT-ALLOW: negative test
        assert!(Did::new("did:web-test:example").is_err()); // DRIFT-ALLOW: negative test
        assert!(Did::new("did:web_test:example").is_err()); // DRIFT-ALLOW: negative test
        // Method-specific-id containing whitespace — rejected.
        assert!(Did::new("did:webvh:z6mkfixture:exa mple").is_err());
        assert!(Did::new("did:webvh:z6mkfixture:exa\tmple").is_err());
        // Pure alnum method — accepted.
        assert!(Did::new("did:webvh:example").is_ok());
        // A bare resolvable DID excludes DID URL path/query/fragment components.
        assert!(Did::new("did:webvh:z6mkfixture:host.example/path").is_err());
        assert!(Did::new("did:webvh:z6mkfixture:host.example/path#frag").is_err());
        assert!(Did::new("did:webvh:z6mkfixture:host.example/path?versionId=1").is_err());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_err());
        assert!(DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(DeviceId::new("device-1").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(DeviceId::new("ak:device:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn trust_domain_id_validates_scope() {
        assert!(TrustDomainId::new("ak:trust_domain:example.net").is_ok());
        assert!(TrustDomainId::new("ak:trust_domain:Example").is_err());
        assert!(TrustDomainId::new("ak:trust_domain:").is_err());
        let too_long = format!("ak:trust_domain:{}", "a".repeat(129));
        assert!(TrustDomainId::new(too_long).is_err());
    }

    #[test]
    fn plan_id_requires_a_non_empty_base64url_token() {
        assert!(PlanId::new("ak:plan:AbC-012_xyz").is_ok());
        assert!(PlanId::new("ak:plan:").is_err());
        // base64url has no padding and no standard-alphabet `+` / `/`.
        assert!(PlanId::new("ak:plan:AbC=").is_err());
        assert!(PlanId::new("ak:plan:Ab+C").is_err());
        assert!(PlanId::new("ak:plan:Ab/C").is_err());
        assert!(PlanId::new("plan:AbC").is_err());
    }

    #[test]
    fn service_registration_receipt_id_requires_lowercase_sha256_hex() {
        let digest64 = "a".repeat(64);
        assert!(
            ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{digest64}"
            ))
            .is_ok()
        );
        assert!(
            ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "A".repeat(64)
            ))
            .is_err()
        );
        assert!(
            ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "a".repeat(63)
            ))
            .is_err()
        );
        // The suffix is a bare digest, not an algorithm-prefixed `Hash`.
        assert!(
            ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:sha256:{digest64}"
            ))
            .is_err()
        );
    }

    /// Each declared special form must be implemented by exactly one type, and
    /// that type must accept its own registry wire form. Without this the
    /// `ID_KIND` consts could be transposed between two types and the
    /// `arkret-schema` set comparison would still pass.
    #[test]
    fn special_form_id_kinds_are_declared_once_by_their_own_type() {
        let declared: std::collections::BTreeSet<&str> =
            DECLARED_SPECIAL_FORM_ID_KINDS.iter().copied().collect();
        assert_eq!(
            declared.len(),
            DECLARED_SPECIAL_FORM_ID_KINDS.len(),
            "two special-form types claim the same registry kind"
        );

        let digest64 = "a".repeat(64);
        assert_eq!(BlobRef::ID_KIND, "blob");
        assert!(BlobRef::new(format!("ak:blob:sha256:{digest64}")).is_ok());
        assert_eq!(CellRef::ID_KIND, "cell");
        assert!(CellRef::new("ak:cell:ak.component.relation.lifecycle.v1:subject").is_ok());
        assert_eq!(Cursor::ID_KIND, "cursor");
        assert!(Cursor::new("ak:cursor:b3RoZXI").is_ok());
        assert_eq!(PlanId::ID_KIND, "plan");
        assert!(PlanId::new("ak:plan:b3RoZXI").is_ok());
        assert_eq!(SealId::ID_KIND, "seal");
        assert!(SealId::new(format!("ak:seal:sha256:{digest64}")).is_ok());
        assert_eq!(
            ServiceRegistrationReceiptId::ID_KIND,
            "service_registration_receipt"
        );
        assert!(
            ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{digest64}"
            ))
            .is_ok()
        );
        assert_eq!(TrustDomainId::ID_KIND, "trust_domain");
        assert!(TrustDomainId::new("ak:trust_domain:example.net").is_ok());
    }

    #[test]
    fn active_id_kind_wrappers_accept_their_registered_wire_forms() {
        macro_rules! assert_id {
            ($ty:ty, $prefix:literal) => {{
                let value = if EVENT_DERIVED_ID_KIND_PREFIXES.contains(&$prefix) {
                    let event =
                        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
                    format!(
                        "{}{}",
                        $prefix,
                        &event.as_str()[EventId::KIND_PREFIX.len()..]
                    )
                } else if DECLARED_SUITE_TAGGED_FULL_DIGEST_ID_KIND_PREFIXES.contains(&$prefix) {
                    SessionGrantId::from_issuance_digest([0x11; 32]).into_string()
                } else {
                    format!("{}01904100-0000-7000-8000-000000000001", $prefix)
                };
                assert!(<$ty>::new(value).is_ok(), "{}", stringify!($ty));
            }};
        }

        assert_id!(ActorProfileId, "ak:actor_profile:");
        assert_id!(AttestationId, "ak:attestation:");
        assert_id!(AuditBindingId, "ak:audit_binding:");
        assert_id!(AuditReleaseId, "ak:audit_release:");
        assert_id!(AuditSessionId, "ak:audit_session:");
        assert_id!(RtcParticipantId, "ak:rtc_participant:");
        assert_id!(BackupSeriesId, "ak:backup_series:");
        assert_id!(RecoverySessionId, "ak:recovery_session:");
        assert_id!(AnnounceId, "ak:announce:");
        assert_id!(AppletId, "ak:applet:");
        assert_id!(BackupId, "ak:backup:");
        assert_id!(BatchId, "ak:batch:");
        assert_id!(BlobId, "ak:blob:");
        assert_id!(BlockId, "ak:block:");
        assert_id!(CallId, "ak:call:");
        assert_id!(ConsentId, "ak:consent:");
        assert_id!(CapabilityId, "ak:capability:");
        assert_id!(ChunkId, "ak:chunk:");
        assert_id!(ClaimId, "ak:claim:");
        assert_id!(DeviceId, "ak:device:");
        assert_id!(DeviceMessageId, "ak:device_message:");
        assert_id!(EventId, "ak:event:");
        assert_id!(FilterId, "ak:filter:");
        assert_id!(StrandId, "ak:strand:");
        assert_id!(FrameId, "ak:frame:");
        assert_id!(GrantId, "ak:grant:");
        assert_id!(SessionGrantId, "ak:session_grant:");
        assert_id!(InviteId, "ak:invite:");
        assert_id!(KeyEventId, "ak:key_event:");
        assert_id!(MessageId, "ak:message:");
        assert_id!(MessageStreamId, "ak:message_stream:");
        assert_id!(ModerationQueueItemId, "ak:moderation_queue_item:");
        assert_id!(MorphId, "ak:morph:");
        assert_id!(AuthorizationLeaseId, "ak:authorization_lease:");
        assert_id!(NotificationId, "ak:notification:");
        assert_id!(RealmId, "ak:realm:");
        assert_id!(SpaceId, "ak:space:");
        assert_id!(PolicyId, "ak:policy:");
        assert_id!(PresentationId, "ak:presentation:");
        assert_id!(ReceiptId, "ak:receipt:");
        assert_id!(RelationId, "ak:relation:");
        assert_id!(SidecarId, "ak:sidecar:");
        assert_id!(ReportId, "ak:report:");
        assert_id!(ReadCursorId, "ak:read_cursor:");
        assert_id!(RequestId, "ak:request:");
        assert_id!(ScheduledSendId, "ak:scheduled_send:");
        assert_id!(SnapshotId, "ak:snapshot:");
        assert_id!(TransactionId, "ak:transaction:");
        assert_id!(ViewId, "ak:view:");
    }

    #[test]
    fn message_and_create_event_ids_retype_the_same_token() {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32]);
        let message_id = MessageId::from_event_id(&event_id);

        assert_eq!(message_id.token_bytes(), event_id.token_bytes());
        assert_eq!(message_id.event_id(), event_id);
    }

    #[test]
    fn session_grant_id_is_an_issuer_record_digest_token() {
        let id = SessionGrantId::from_issuance_digest([0x42; 32]);
        assert_eq!(id.digest_suite_code(), DigestSuiteCode::Sha256);
        assert_eq!(id.issuance_digest(), [0x42; 32]);
        assert!(SessionGrantId::new(id.as_str()).is_ok());
        assert!(!EVENT_DERIVED_ID_KIND_PREFIXES.contains(&SessionGrantId::KIND_PREFIX));

        let mut unknown = id.token_bytes();
        unknown[0] = 0x7f;
        assert!(
            SessionGrantId::new(encode_digest_token(SessionGrantId::KIND_PREFIX, unknown)).is_err()
        );

        let mut blake3 = id.token_bytes();
        blake3[0] = DigestSuiteCode::Blake3.as_u8();
        let blake3_token = encode_digest_token(SessionGrantId::KIND_PREFIX, blake3);
        assert_eq!(
            decode_digest_token(&blake3_token, SessionGrantId::KIND_PREFIX),
            Some(blake3)
        );
        assert!(SessionGrantId::new(blake3_token).is_err());

        let blake3_event = EventId::from_digest(arkret_canonical::DigestSuite::Blake3, [0x42; 32]);
        assert!(EventId::new(blake3_event.as_str()).is_ok());
    }

    #[test]
    fn hash_and_content_addressed_ids_accept_registry_algorithms() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(Hash::new(format!("sha256:{digest64}")).is_ok());
        assert!(Hash::new(format!("blake3:{digest64}")).is_ok());
        assert!(Hash::new(format!("sha3_256:{digest64}")).is_err());
        assert!(Hash::new(format!("sha512:{digest128}")).is_err());
        assert!(BlobRef::new(format!("ak:blob:sha3_256:{digest64}")).is_err());
        assert!(SealId::new(format!("ak:seal:blake3:{digest64}")).is_ok());
        assert!(SealId::new(format!("ak:seal:sha512:{digest128}")).is_err());
    }

    #[test]
    fn cell_ref_requires_complete_cell_family_identifier() {
        assert!(CellRef::new("ak:cell:ak.component.strand.position.v1:board:strand").is_ok());
        assert!(CellRef::new("ak:cell:ak.component.realm.join_rule.v1:").is_ok());
        assert!(CellRef::new(
            "ak:cell:ak.component.member.state.v1:did:webvh:z6mkfixture:127.0.0.1%3A22816:webvh:alice"
        )
        .is_ok());
        assert!(CellRef::new("ak:cell:ak.component.member.state.v1:did:web:host%3").is_err());
        assert!(CellRef::new("ak:cell:ak.component.member.state.v1:did:web:host%XZ").is_err());
        assert!(CellRef::new("ak:cell:component.strand.position.v1:board:strand").is_err());
        assert!(CellRef::new("ak:cell:message:019640ed-8000-7000-8000-000000000000").is_err());
        assert!(CellRef::new("ak:cell:ak.component.strand.position.v1:board:").is_err());
        assert!(CellRef::new("ak:cell:ak.component.Strand.position.v1:board:strand").is_err());
        assert!(CellRef::new("ak:cell:ak.component.strand.position:board:strand").is_err());
    }

    #[test]
    fn strand_id_accepts_active_strand_prefix() {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Blake3, [0x23; 32]);
        let strand_id = StrandId::from_event_id(&event_id);
        assert_eq!(strand_id.digest_suite_code(), DigestSuiteCode::Blake3);
        assert!(StrandId::new(strand_id.as_str()).is_ok());
        assert!(StrandId::new(format!("ak:space:{}", &strand_id.as_str()[10..])).is_err());
        assert!(StrandId::new("ak:strand:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn new_prefixed_uuid7_produces_strict_typed_id() {
        // C19.B: helper for newly-issued Arkret wire ids.
        // `ak:space:` is event-derived now, so it must NOT be minted here;
        // use a producer-allocated kind instead.
        let id = new_prefixed_uuid7("ak:receipt:");
        assert!(is_strict_typed_id(
            &id,
            "ak:receipt:",
            UUID_VERSION_PRODUCER_ALLOCATED
        ));
        // Two consecutive calls produce different ids.
        let id2 = new_prefixed_uuid7("ak:receipt:");
        assert_ne!(id, id2);
        assert!(ReceiptId::new(id).is_ok());
        // Minting for an event-derived kind is a contract violation, not a
        // valid alternative path: SpaceId can only come from from_event_id.
        assert!(SpaceId::new(new_prefixed_uuid7("ak:receipt:")).is_err());
    }

    #[test]
    #[should_panic(expected = "ak:realm: is an event-derived kind")]
    fn new_prefixed_uuid7_rejects_event_derived_kinds_in_all_build_profiles() {
        let _ = new_prefixed_uuid7("ak:realm:");
    }

    #[test]
    fn realm_tokens_are_event_derived_and_reject_reserved_header_bits() {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32]);
        let realm_id = RealmId::from_event_id(&event_id);
        assert_eq!(realm_id.token_bytes()[0], 0x01);
        assert_eq!(realm_id.digest_suite_code(), DigestSuiteCode::Sha256);
        assert_eq!(realm_id.event_id(), event_id);

        let mut reserved = realm_id.token_bytes();
        reserved[0] = 0x11;
        assert!(RealmId::new(encode_event_token("ak:realm:", reserved)).is_err());

        assert!(RealmId::new("ak:realm:019a6aa0-0000-7000-8000-000000000001").is_err());
        let blake3_event = EventId::from_digest(arkret_canonical::DigestSuite::Blake3, [0x42; 32]);
        let blake3_retyped = encode_event_token("ak:realm:", blake3_event.token_bytes());
        assert!(
            RealmId::new(blake3_retyped).is_err(),
            "v1 Realm IDs reject non-SHA-256 Event suites"
        );
    }

    #[test]
    fn typed_uuidv7_generation_preserves_kind_time_and_monotonicity() {
        let unix_ms = 1_725_000_123_456;
        let first = ReceiptId::new_v7_at(unix_ms);
        let second = ReceiptId::new_v7_at(unix_ms);

        assert!(first.as_str().starts_with(ReceiptId::KIND_PREFIX));
        assert!(second.as_str().starts_with(ReceiptId::KIND_PREFIX));
        assert!(first < second, "same-millisecond ids must remain ordered");

        let timestamp = first.uuid().get_timestamp().expect("UUIDv7 timestamp");
        let (seconds, nanos) = timestamp.to_unix();
        let encoded_unix_ms = seconds
            .saturating_mul(1_000)
            .saturating_add(u64::from(nanos / 1_000_000));
        assert!(
            encoded_unix_ms >= unix_ms,
            "the shared monotonic context may advance a rolled-back clock but never regress it"
        );

        let operation = OperationId::new_v7_at(unix_ms);
        assert!(operation.as_str().starts_with("ak:operation:"));
        assert!(OperationId::new(operation.into_string()).is_ok());
    }

    /// `DeviceMessageTransactionId` and `TransactionId` are disjoint value
    /// spaces, not two spellings of one id.
    ///
    /// The regression this pins: `KeyVerificationContent.transaction_id` used to
    /// be a `TransactionId`, and *every* value of that type violates the
    /// device-message pattern, so the field could not be given a conformant
    /// value at all.
    #[test]
    fn device_message_transaction_id_and_typed_transaction_id_are_disjoint() {
        // A bare UUIDv7 is what the wire actually carries, and it is accepted.
        let bare = "0196419b-0000-7000-8000-000000000000";
        assert!(DeviceMessageTransactionId::new(bare).is_ok());
        assert!(TransactionId::new(bare).is_err());

        // The typed transaction id is rejected: `:` is outside the charset.
        let typed = format!("ak:transaction:{bare}");
        assert!(TransactionId::new(typed.clone()).is_ok());
        assert!(DeviceMessageTransactionId::new(typed).is_err());

        // Charset boundaries: the punctuation the pattern allows, and
        // representative rejects.
        assert!(DeviceMessageTransactionId::new("aZ0._~=-").is_ok());
        for rejected in ["", " ", "a b", "a/b", "a+b", "a#b", "sas:1", "\u{4e2d}"] {
            assert!(
                DeviceMessageTransactionId::new(rejected).is_err(),
                "`{rejected}` must be rejected"
            );
        }

        // Length bound is 128 inclusive.
        assert!(DeviceMessageTransactionId::new("a".repeat(128)).is_ok());
        assert!(DeviceMessageTransactionId::new("a".repeat(129)).is_err());
    }

    #[test]
    fn event_token_rejects_noncanonical_and_unsupported_values() {
        let valid = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0; 32]);
        assert_eq!(valid.as_str().len(), 53);
        assert_eq!(valid.token_bytes().len(), 33);
        assert!(EventId::new(valid.as_str()).is_ok());
        assert!(EventId::new("ak:event:not-a-token").is_err());
        assert!(EventId::new(format!("{}=", valid.as_str())).is_err());

        let mut unknown_suite = valid.token_bytes();
        unknown_suite[0] = 0x03;
        assert!(EventId::new(encode_event_token("ak:event:", unknown_suite)).is_err());

        let mut nonzero_reserved_nibble = valid.token_bytes();
        nonzero_reserved_nibble[0] = 0x11;
        assert!(EventId::new(encode_event_token("ak:event:", nonzero_reserved_nibble)).is_err());
        assert!(
            MessageId::new(encode_event_token("ak:message:", nonzero_reserved_nibble)).is_err(),
            "every Event-derived kind must reject a non-zero Event reserved nibble"
        );

        let mut invalid_alphabet = valid.as_str().to_owned();
        invalid_alphabet.pop();
        invalid_alphabet.push('+');
        assert!(EventId::new(invalid_alphabet).is_err());
    }

    #[test]
    fn event_id_binary_layout_kat_and_strong_reference_validation() {
        let mut digest = [0_u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let sha = EventIdentityKey::new(DigestSuiteCode::Sha256, digest);
        let blake = EventIdentityKey::new(DigestSuiteCode::Blake3, digest);
        assert_eq!(
            sha.event_id().as_str(),
            "ak:event:AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        );
        assert_eq!(
            blake.event_id().as_str(),
            "ak:event:AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        );
        assert_eq!(sha.event_id().digest_bytes(), digest);
        assert_eq!(sha.event_id().identity_key(), sha);
        assert_eq!(sha.event_id().event_digest(), sha.event_digest());
        assert_eq!(blake.event_id().event_digest(), blake.event_digest());
        assert_ne!(blake.event_id(), sha.event_id());
        assert_eq!(
            EventIdentityKey::from_event_digest(&sha.event_digest()).unwrap(),
            sha
        );
    }

    #[test]
    fn serde_deserialization_validates_identifier_values() {
        #[derive(Deserialize)]
        struct Envelope {
            space_id: SpaceId,
            hlc: Hlc,
        }

        let space_id = SpaceId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x55; 32],
        ));
        let valid: Envelope = serde_json::from_value(serde_json::json!({
            "space_id": space_id,
            "hlc": "01970e589d21-0004-a13f9c2e",
        }))
        .unwrap();
        assert_eq!(valid.space_id, space_id);
        assert_eq!(valid.hlc.as_str(), "01970e589d21-0004-a13f9c2e");

        let invalid_id = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "space-01",
            "hlc": "01970e589d21-0004-a13f9c2e",
        }));
        assert!(invalid_id.is_err());

        let invalid_hlc = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": space_id,
            "hlc": "1970",
        }));
        assert!(invalid_hlc.is_err());
    }

    #[test]
    fn did_and_core_id_method_adapter_kats() {
        let webvh = Did::new("did:webvh:zQ3shExampleScid:alice.example:webvh:user").unwrap();
        assert_eq!(
            project_did_to_core_id(&webvh).unwrap().as_str(),
            "ak:did_core:webvh:zQ3shExampleScid"
        );

        let web = Did::new("did:web:peer-ps.example:users:alice").unwrap();
        assert_eq!(
            project_did_to_core_id(&web).unwrap().as_str(),
            "ak:did_core:web:peer-ps.example:users:alice"
        );

        let key = Did::new("did:key:z6MkruntimeExample").unwrap();
        assert_eq!(
            project_did_to_core_id(&key).unwrap().as_str(),
            "ak:did_core:key:z6MkruntimeExample"
        );

        for invalid in [
            "did:web:example.test/path",
            "did:web:example.test?version=1",
            "did:web:example.test#key-1",
            "did:Web:example.test",
        ] {
            assert!(Did::new(invalid).is_err(), "{invalid} must fail");
        }
        assert!(Did::new(format!("did:web:{}", "a".repeat(2040))).is_ok());
        assert!(Did::new(format!("did:web:{}", "a".repeat(2041))).is_err());
        assert!(DidCoreId::new("ak:did_core:web:peer-ps.example").is_ok());
        assert!(DidCoreId::new("ak:did_core:web:peer-ps.example/path").is_err());
    }
}
