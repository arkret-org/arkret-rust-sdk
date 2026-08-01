//! Validated Arkret v1 identifiers.
//!
//! The types in this crate are the protocol boundary for DIDs, object IDs,
//! content hashes, cursors and HLC values. Constructors and Serde decoding both
//! validate their input so malformed wire identifiers fail at the edge.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

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
    ($name:ident, $expect:expr) => {
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
/// Hash-bearing or hybrid kinds (`OperationId`, `BlobRef`, `SealId`,
/// `Hash`, `Hash`), DIDs, cursors and `trust_domain` MUST stay on plain
/// [`id_type!`] — they have no bare-uuid form.
macro_rules! uuid_id_type {
    ($name:ident, $prefix:literal) => {
        id_type!($name, |value: &str| is_strict_typed_id(value, $prefix));

        impl $name {
            /// The `ak:<kind>:` wire prefix this id-kind validates against.
            pub const KIND_PREFIX: &'static str = $prefix;

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

        #[cfg(feature = "diesel")]
        impl diesel::serialize::ToSql<diesel::sql_types::Uuid, diesel::pg::Pg> for $name {
            fn to_sql<'b>(
                &'b self,
                out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
            ) -> diesel::serialize::Result {
                let value = self.uuid();
                <uuid::Uuid as diesel::serialize::ToSql<
                                                            diesel::sql_types::Uuid,
                                                            diesel::pg::Pg,
                                                        >>::to_sql(&value, &mut out.reborrow())
            }
        }

        #[cfg(feature = "diesel")]
        impl diesel::deserialize::FromSql<diesel::sql_types::Uuid, diesel::pg::Pg> for $name {
            fn from_sql(
                bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
            ) -> diesel::deserialize::Result<Self> {
                let value = <uuid::Uuid as diesel::deserialize::FromSql<
                    diesel::sql_types::Uuid,
                    diesel::pg::Pg,
                >>::from_sql(bytes)?;
                Ok(Self::from_uuid(value))
            }
        }
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
/// `recovery_authority_ticket`, `sidecar`). [`DECLARED_UUID_ID_KIND_PREFIXES`]
/// closes that gap: it is derived from the same literals the types validate
/// against, so it cannot disagree with them.
///
/// Hash-bearing, hybrid and special-form kinds stay on plain [`id_type!`] and
/// are deliberately absent from this block — they have no `ak:<kind>:<uuidv7>`
/// wire form and the spec lists them under `special_forms`.
macro_rules! declare_uuid_id_kinds {
    ($($name:ident, $prefix:literal;)*) => {
        $(uuid_id_type!($name, $prefix);)*

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
/// prefix), [`OperationId`] (hybrid typed-uuid-or-digest) and
/// [`DeviceMessageTransactionId`] (a payload field charset, not an id kind).
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

/// Validate a DID scalar against the Round 4 tightened pattern. Method name
/// MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
/// method-specific-id MUST be non-empty and contain no whitespace, fragment,
/// or query marker. DID URL fields use a separate string surface and require a
/// `#key` fragment.
///
/// Zero-allocation public validator for the DID scalar form. This is the same
/// predicate used by `id_type!(Did, is_did)`, exposed for downstream callers
/// that need validation without constructing a [`Did`].
pub fn is_did(value: &str) -> bool {
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
        .any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'#' | b'?'))
    {
        return false;
    }
    true
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
/// `special_forms[trust_domain]`; pattern matches cross-signing-reset.schema.json
/// `^ak:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$`.
///
/// Zero-allocation public validator for the trust-domain wire form. This is
/// the same predicate used by `id_type!(TypedTrustDomainId, is_trust_domain)`.
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
pub fn is_strict_typed_id(value: &str, prefix: &str) -> bool {
    match value.strip_prefix(prefix) {
        Some(payload) => is_lowercase_uuidv7(payload),
        None => false,
    }
}

/// Generate a fresh canonical `<prefix><uuidv7>` identifier string using a
/// freshly generated RFC 9562 UUIDv7. The output is always lowercase hex per
/// `conformance/encoding.md` §4 and is the canonical wire form for typed
/// `ak:<kind>:` identifiers (Arkret v1, 2026-05-09 onward).
pub fn new_prefixed_uuid7(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Validate that `value` is a canonical lower-case RFC 9562 UUIDv7 in the
/// 36-character `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` form (N ∈ {8,9,a,b}),
/// per `conformance/encoding.md` §4.
///
/// The v1 wire forbids upper-case hex, missing dashes, URN/Microsoft braces,
/// and any UUID version other than 7.
pub fn is_lowercase_uuidv7(value: &str) -> bool {
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
    // Version nibble at byte position 14 (third group: 7xxx).
    if bytes[14] != b'7' {
        return false;
    }
    // Variant nibble at byte position 19 (fourth group: Nxxx, N ∈ {8,9,a,b}).
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    true
}

id_type!(Did, is_did);

// Protocol object IDs use typed prefixes with canonical RFC 9562 UUIDv7
// payloads. Pure-uuid kinds go through `declare_uuid_id_kinds!` so they
// persist as native `uuid` columns (bare) while keeping the
// `ak:<kind>:<uuid>` wire form — and so the prefix set stays enumerable.
//
// Every entry here MUST have an active `id_kinds` row in the spec
// `registry/id-kind-registry.json`; `arkret-schema` fails closed in both
// directions.
declare_uuid_id_kinds! {
    ActorProfileId, "ak:actor_profile:";
    // AKP-0008/0009 (spec head 37ce729) — personal agent auxiliary typed ids.
    // `agent_id` is a DID scalar, represented by `Did`.
    // Audit release-session + attestation typed ids (id-kind-registry kinds
    // `attestation` / `audit_binding` / `audit_release` / `audit_session`).
    AttestationId, "ak:attestation:";
    AuditBindingId, "ak:audit_binding:";
    AuditReleaseId, "ak:audit_release:";
    AuditSessionId, "ak:audit_session:";
    // RTC call participant id (id-kind-registry kind `rtc_participant`).
    RtcParticipantId, "ak:rtc_participant:";
    // Key-backup hardening (B-C) typed ids.
    BackupSeriesId, "ak:backup_series:";
    RecoverySessionId, "ak:recovery_session:";
    RecoveryAuthorityTicketId, "ak:recovery_authority_ticket:";
    AnnounceId, "ak:announce:";
    AppletId, "ak:applet:";
    RealmId, "ak:realm:";
    SpaceId, "ak:space:";
    BackupId, "ak:backup:";
    BatchId, "ak:batch:";
    BlobId, "ak:blob:";
    BlockId, "ak:block:";
    CallId, "ak:call:";
    ConsentId, "ak:consent:";
    CapabilityId, "ak:capability:";
    ChunkId, "ak:chunk:";
    // AKP-0007 (2026-05-08) — Circle id-kind. Intra-Realm cryptographic
    // sub-boundary; see spec artifacts/registry/id-kind-registry.json and
    // zh/models/circle.md.
    CircleId, "ak:circle:";
    SidecarId, "ak:sidecar:";
    ClaimId, "ak:claim:";
    DeviceMessageId, "ak:device_message:";
    StrandId, "ak:strand:";
    FilterId, "ak:filter:";
    FrameId, "ak:frame:";
    FrankingProofId, "ak:franking_proof:";
    MorphId, "ak:morph:";
    // Round R2/R3 (2026-05-20) — moderation appeal cell key
    // (`ak:appeal:<uuidv7>`). id-kind-registry kind=appeal; see
    // schemas/moderation-appeal.schema.json. Named `TypedAppealId` because
    // `AppealId` is already the plain-string payload alias in
    // `arkret-models-collaboration`.
    TypedAppealId, "ak:appeal:";
    MessageId, "ak:message:";
    MessageStreamId, "ak:message_stream:";
    RelationId, "ak:relation:";
    EventId, "ak:event:";
    GrantId, "ak:grant:";
    InviteId, "ak:invite:";
    InviteLocatorId, "ak:invite_locator:";
    KeyEventId, "ak:key_event:";
    AuthorizationLeaseId, "ak:authorization_lease:";
    DeviceId, "ak:device:";
    NotificationId, "ak:notification:";
    PolicyId, "ak:policy:";
    PresentationId, "ak:presentation:";
    ReceiptId, "ak:receipt:";
    ReportId, "ak:report:";
    ReadCursorId, "ak:read_cursor:";
    ModerationQueueItemId, "ak:moderation_queue_item:";
    RequestId, "ak:request:";
    SnapshotId, "ak:snapshot:";
    SubscriptionId, "ak:subscription:";
    TransactionId, "ak:transaction:";
    ViewId, "ak:view:";
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
    // Round R2/R3 (2026-05-20) — deployment-scope trust domain identifier.
    // Named `Typed…` because `TrustDomain` is the plain-string payload alias.
    TypedTrustDomainId, "trust_domain", is_trust_domain;
}

/// Applet identity accepted by the v1 wire protocol: either a service DID or
/// a typed `ak:applet:<uuidv7>` identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletIdentifier {
    Did(Did),
    Cx(AppletId),
}

impl AppletIdentifier {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Did(value) => value.as_str(),
            Self::Cx(value) => value.as_str(),
        }
    }
}

// OperationId is hybrid: `ak:operation:<uuidv7>` OR a content hash. No bare
// uuid form and no `special_forms` row, so it stays a text `id_type!`.
id_type!(OperationId, |value: &str| is_strict_typed_id(
    value,
    "ak:operation:"
) || is_hash(value));
id_type!(DeviceMessageTransactionId, is_device_message_transaction_id);

impl MessageId {
    /// Retype a durable `ak.message.create` Event UUIDv7 as the Message identity.
    pub fn from_event_id(event_id: &EventId) -> Self {
        Self::from_uuid(event_id.uuid())
    }

    /// Retype this Message UUIDv7 as its planned durable create Event identity.
    pub fn event_id(&self) -> EventId {
        EventId::from_uuid(self.uuid())
    }
}

fn is_blob_ref(value: &str) -> bool {
    if is_hash(value) || is_strict_typed_id(value, "ak:blob:") {
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
/// device-message field as `TransactionId` therefore made it impossible to
/// author a conformant `ak.key.verification.*` content — see
/// `arkret-work/review/code/2026-07-31-sdk-key-verification-transaction-id-off-spec.md`.
fn is_device_message_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
        })
}

// Bare `<algo>:<hex>` digest, e.g. an Event's `proof.event_digest`, a Seal
// root, or a control-plane `Seal.delta[]` entry. `ak:seal:` prefixes the
// content-addressed Seal identifier itself, which is a special form and is
// declared with the other `special_forms` kinds.
id_type!(Hash, is_hash);

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
    fn applet_identifier_accepts_only_did_or_typed_applet_id() {
        let did =
            serde_json::from_str::<AppletIdentifier>(r#""did:webvh:z6mkfixture:applet.example""#)
                .unwrap();
        assert!(matches!(did, AppletIdentifier::Did(_)));

        let typed = serde_json::from_str::<AppletIdentifier>(
            r#""ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d""#,
        )
        .unwrap();
        assert!(matches!(typed, AppletIdentifier::Cx(_)));
        assert!(serde_json::from_str::<AppletIdentifier>(r#""applet.example""#).is_err());
    }

    /// Round 4 (spec a77b995): method-name segment is `[a-z0-9]+` only;
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
        assert!(Did::new("did:webvh:z6mkfixture:host.example/path").is_ok());
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
        assert!(TypedTrustDomainId::new("ak:trust_domain:example.net").is_ok());
        assert!(TypedTrustDomainId::new("ak:trust_domain:Example").is_err());
        assert!(TypedTrustDomainId::new("ak:trust_domain:").is_err());
        let too_long = format!("ak:trust_domain:{}", "a".repeat(129));
        assert!(TypedTrustDomainId::new(too_long).is_err());
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
        assert_eq!(TypedTrustDomainId::ID_KIND, "trust_domain");
        assert!(TypedTrustDomainId::new("ak:trust_domain:example.net").is_ok());
    }

    #[test]
    fn active_id_kind_wrappers_accept_uuidv7_wire_forms() {
        macro_rules! assert_id {
            ($ty:ty, $prefix:literal) => {{
                let value = format!("{}01904100-0000-7000-8000-000000000001", $prefix);
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
        assert_id!(RecoveryAuthorityTicketId, "ak:recovery_authority_ticket:");
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
        assert_id!(FrankingProofId, "ak:franking_proof:");
        assert_id!(GrantId, "ak:grant:");
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
        assert_id!(SnapshotId, "ak:snapshot:");
        assert_id!(TransactionId, "ak:transaction:");
        assert_id!(ViewId, "ak:view:");
    }

    #[test]
    fn message_and_create_event_ids_retype_the_same_uuid() {
        let event_id = EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap();
        let message_id = MessageId::from_event_id(&event_id);

        assert_eq!(
            message_id.as_str(),
            "ak:message:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(message_id.event_id(), event_id);
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
        assert!(StrandId::new("ak:strand:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(StrandId::new("ak:space:01904100-0000-7000-8000-000000000001").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(StrandId::new("ak:strand:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn new_prefixed_uuid7_produces_strict_typed_id() {
        // C19.B: helper for newly-issued Arkret wire ids.
        let id = new_prefixed_uuid7("ak:space:");
        assert!(is_strict_typed_id(&id, "ak:space:"));
        // Two consecutive calls produce different ids.
        let id2 = new_prefixed_uuid7("ak:space:");
        assert_ne!(id, id2);
        assert!(SpaceId::new(id).is_ok());
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
    fn is_strict_typed_id_rejects_ulid_and_bad_uuid_payloads() {
        // C19 wire-break: typed wire ids MUST be canonical lowercase UUIDv7.
        // Mixed-case ULID-form is rejected (intentionally non-UUIDv7).
        assert!(!is_strict_typed_id(
            "ak:space:01js0ke000000000000000000",
            "ak:space:"
        ));
        // Uppercase hex forbidden.
        assert!(!is_strict_typed_id(
            "ak:space:0196419B-0000-7000-8000-000000000000",
            "ak:space:"
        ));
        // Wrong UUID version (4 instead of 7).
        assert!(!is_strict_typed_id(
            "ak:space:0196419b-0000-4000-8000-000000000000",
            "ak:space:"
        ));
        // Wrong variant nibble (c not in {8,9,a,b}).
        assert!(!is_strict_typed_id(
            "ak:space:0196419b-0000-7000-c000-000000000000",
            "ak:space:"
        ));
        // Canonical UUIDv7 accepted.
        assert!(is_strict_typed_id(
            "ak:space:0196419b-0000-7000-8000-000000000000",
            "ak:space:"
        ));
    }

    #[test]
    fn serde_deserialization_validates_identifier_values() {
        #[derive(Deserialize)]
        struct Envelope {
            space_id: SpaceId,
            hlc: Hlc,
        }

        let valid: Envelope = serde_json::from_value(serde_json::json!({
            "space_id": "ak:space:01904100-0000-7000-8000-000000000001",
            "hlc": "01970e589d21-0004-a13f9c2e",
        }))
        .unwrap();
        assert_eq!(
            valid.space_id.as_str(),
            "ak:space:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(valid.hlc.as_str(), "01970e589d21-0004-a13f9c2e");

        let invalid_id = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "space-01",
            "hlc": "01970e589d21-0004-a13f9c2e",
        }));
        assert!(invalid_id.is_err());

        let invalid_hlc = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "ak:space:01904100-0000-7000-8000-000000000001",
            "hlc": "1970",
        }));
        assert!(invalid_hlc.is_err());
    }
}
