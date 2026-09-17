//! Verified DID binding value object (`did-usage-and-verification.md` §5).
//!
//! A DID authority verification MUST produce a *reusable, auditable* binding —
//! not a context-free `verified = true`. [`VerifiedDidBinding`] is that product:
//! it pins **what** was verified (`did` / `method` / `verification_method`),
//! **for whom** (`trust_domain` / `purpose`), **against which evidence**
//! (`document_digest` / `history_head` / `version_id` / `evidence_digest` /
//! `policy_digest`) and **for how long** (`verified_at` / `refresh_after` /
//! `expires_at` / `status`).
//!
//! The type has no public fields. Every instance goes through
//! [`VerifiedDidBinding::new`] (or [`VerifiedDidBinding::from_verified_document`],
//! which computes the document digest itself so a caller cannot hand-fill an
//! inconsistent one). `Deserialize` routes through the same validation, so a
//! binding cannot be forged by round-tripping JSON either.

use arkret_canonical::canonical;
pub use arkret_wire::DidFreshnessRiskTier;
use arkret_wire::{Did, DidFreshnessProfileId, DidUrl, Hash, TrustDomainId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::DidDocument;
use crate::binding_digest::EvidenceDependencies;

// ============================================================================
// Closed enums
// ============================================================================

/// Closed set of purposes a [`VerifiedDidBinding`] may be accepted for
/// (`did-usage-and-verification.md` §5, "`trust_domain` / `purpose`").
///
/// A binding is scoped to exactly one purpose: an `Issuer` acceptance never
/// authorizes a `Service` route, and a `DeviceSigner` acceptance never
/// authorizes a `Controller` operation. The enum is deliberately **closed** —
/// there is no free-form `Other(String)` variant and unknown serde values are a
/// hard deserialization error — so a peer cannot smuggle an unreviewed purpose
/// across the wire.
///
/// Adding a variant MUST first be checked against `did-usage-and-verification.md`
/// §4 (closed authority trigger table) and §5 (binding fields); when the new
/// purpose is not covered by an existing trigger row, follow
/// `arkret-work/tasks/spec-open/README-status.md` and file a dated finding
/// before implementing it.
///
/// Provenance of the current variants:
///
/// | variant | source |
/// | --- | --- |
/// | [`Principal`](Self::Principal) | task DID-P0-B01 |
/// | [`Service`](Self::Service) | task DID-P0-B01 |
/// | [`Issuer`](Self::Issuer) | task DID-P0-B01 |
/// | [`Controller`](Self::Controller) | task DID-P0-B01 |
/// | [`DeviceSigner`](Self::DeviceSigner) | task DID-P0-B01 (device signer authorization) |
/// | [`AgentSigner`](Self::AgentSigner) | task DID-P0-B01 (agent signer authorization) |
/// | [`DirectoryIngest`](Self::DirectoryIngest) | Teabay DID-P0-C02 |
/// | [`DirectoryIssuer`](Self::DirectoryIssuer) | Teabay DID-P0-C02 |
/// | [`PrincipalServiceEndpoint`](Self::PrincipalServiceEndpoint) | Teabay DID-P0-C02 |
/// | [`AccountBinding`](Self::AccountBinding) | Coauth DID-P2-A |
/// | [`Recovery`](Self::Recovery) | Coauth DID-P2-A |
/// | [`OrganizationRegistry`](Self::OrganizationRegistry) | Coauth DID-P2-A |
/// | [`AdminAction`](Self::AdminAction) | Coauth DID-P2-A (the acting admin's own DID) |
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingPurpose {
    /// Principal (human / organization actor) identity control.
    Principal,
    /// Service DID control (federation peer, media, push, audit, policy...).
    Service,
    /// Claim / receipt / attestation issuer key.
    Issuer,
    /// Controller or delegation authority over another subject.
    Controller,
    /// Device signing key authorization for a principal.
    DeviceSigner,
    /// Agent signer epoch authorization for a principal.
    AgentSigner,
    /// Directory ingest of an announced resource (Teabay DID-P0-C02).
    DirectoryIngest,
    /// Directory-scoped claim / invite issuer (Teabay DID-P0-C02).
    DirectoryIssuer,
    /// Station service endpoint binding (Teabay DID-P0-C02).
    PrincipalServiceEndpoint,
    /// Account registration / claim binding (Coauth DID-P2-A).
    AccountBinding,
    /// Account recovery authority (Coauth DID-P2-A).
    Recovery,
    /// Organization registry control (Coauth DID-P2-A).
    OrganizationRegistry,
    /// The DID of the **admin performing** an administrative action
    /// (Coauth DID-P2-A).
    ///
    /// Not for erasure receipts: verifying a receipt resolves
    /// `receipt.issuer`, which is §4's last row ("verifying a third-party
    /// claim / receipt / attestation whose issuer key has no accepted binding
    /// here") and therefore takes [`Issuer`](Self::Issuer). Using
    /// `AdminAction` there would file the issuer's key under the acting
    /// admin's purpose and let one acceptance authorize the other.
    AdminAction,
}

impl DidBindingPurpose {
    /// Stable snake_case wire token, identical to the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Service => "service",
            Self::Issuer => "issuer",
            Self::Controller => "controller",
            Self::DeviceSigner => "device_signer",
            Self::AgentSigner => "agent_signer",
            Self::DirectoryIngest => "directory_ingest",
            Self::DirectoryIssuer => "directory_issuer",
            Self::PrincipalServiceEndpoint => "principal_service_endpoint",
            Self::AccountBinding => "account_binding",
            Self::Recovery => "recovery",
            Self::OrganizationRegistry => "organization_registry",
            Self::AdminAction => "admin_action",
        }
    }
}

impl std::fmt::Display for DidBindingPurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed binding status (`did-usage-and-verification.md` §5, `status` row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingStatus {
    /// Verified and inside its freshness window.
    Active,
    /// Past `refresh_after` but not hard-expired. Usable for ordinary
    /// verification; an authority path must refresh or fail closed.
    Stale,
    /// The DID (or this key) was deactivated. Never usable.
    Deactivated,
    /// Held back after a witness fork / conflicting evidence. Never usable.
    Quarantined,
}

impl DidBindingStatus {
    /// Whether ordinary (non-authority) signature verification may consume a
    /// binding in this status. `Stale` is deliberately allowed:
    /// `did-usage-and-verification.md` §5 states cache TTL expiry MUST NOT turn
    /// an ordinary business request into an online DID resolution.
    pub fn is_usable_for_ordinary_verification(self) -> bool {
        matches!(self, Self::Active | Self::Stale)
    }
}

impl std::fmt::Display for DidBindingStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Deactivated => "deactivated",
            Self::Quarantined => "quarantined",
        })
    }
}

/// The state of one `did-usage-and-verification.md` §5.5 trust pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinState {
    /// The pin is present on the binding.
    Pinned,
    /// The method genuinely has nothing to pin (`did:key` has no history). A
    /// legitimate terminal state.
    MethodUnsupported,
    /// The method supports this pin but the resolver did not deliver it. A
    /// **failure** state, not an audit note: once the §5.2 resolver channel
    /// surfaces method evidence, `did:webvh` should never record it.
    NotSurfaced,
}

impl PinState {
    /// Registered wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::MethodUnsupported => "method_unsupported",
            Self::NotSurfaced => "not_surfaced",
        }
    }

    /// Whether this state claims the pin is present.
    pub fn is_pinned(self) -> bool {
        matches!(self, Self::Pinned)
    }
}

impl std::fmt::Display for PinState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Per-pin limited-trust record
/// (`did-binding-contracts.schema.json#/$defs/limited_trust`).
///
/// §5.5 replaced the old single "reason" with one state per pin, because the two
/// pins fail independently and for different reasons: a `did:webvh` binding that
/// lost only `version_id` because the resolver did not surface it is a resolver
/// defect, while a `did:key` binding that has no history at all is a terminal
/// property of the method. Collapsing both into one enum made those
/// indistinguishable.
///
/// The record is omitted entirely when both pins are present; every state MUST
/// agree with the actual presence of its pin, and [`VerifiedDidBinding::new`]
/// rejects a binding where it does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedTrust {
    pub history_head_status: PinState,
    pub version_id_status: PinState,
}

impl LimitedTrust {
    /// The record implied by the pins a **proofless** method produced.
    ///
    /// Absent pins are `method_unsupported`, which is the terminal state
    /// `did:key` / bare `did:web` legitimately reach.
    pub fn for_proofless_method(history_head: Option<&str>, version_id: Option<&str>) -> Self {
        Self {
            history_head_status: pin_state(history_head.is_some(), PinState::MethodUnsupported),
            version_id_status: pin_state(version_id.is_some(), PinState::MethodUnsupported),
        }
    }

    /// The record implied by the pins an **evidence-bearing** method produced.
    ///
    /// An absent pin here is `not_surfaced`: the method supports it, so its
    /// absence is a resolver failure that must stay visible rather than be
    /// laundered into `method_unsupported`.
    pub fn for_evidence_bearing_method(
        history_head: Option<&str>,
        version_id: Option<&str>,
    ) -> Self {
        Self {
            history_head_status: pin_state(history_head.is_some(), PinState::NotSurfaced),
            version_id_status: pin_state(version_id.is_some(), PinState::NotSurfaced),
        }
    }

    /// Whether every pin is present, in which case the record MUST be omitted.
    pub fn is_fully_pinned(self) -> bool {
        self.history_head_status.is_pinned() && self.version_id_status.is_pinned()
    }

    /// The record a binding with these pins must carry, or `None` when both are
    /// pinned.
    pub fn record_for(self) -> Option<Self> {
        (!self.is_fully_pinned()).then_some(self)
    }
}

fn pin_state(present: bool, absent: PinState) -> PinState {
    if present { PinState::Pinned } else { absent }
}

// ============================================================================
// Freshness profile and requirement
// ============================================================================

/// What a call site does with a binding that is past `refresh_after` (§5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleBehavior {
    AcceptedWithoutNetwork,
    AcceptedAndBackgroundRefresh,
    SynchronousRefreshOrFailClosed,
}

/// One registered freshness profile row
/// (`did-binding-contracts.schema.json#/$defs/freshness_profile`).
///
/// §5.4 makes every DID authority call site reference exactly one profile id
/// through its operation / action registration — natural-language tier guessing
/// ("directory-ish, so any cache will do") is forbidden, and an unknown id is
/// treated as `high`, never as "anything cached is fine".
///
/// `fresh_for_seconds` is the **single** freshness threshold: `refresh_after =
/// verified_at + fresh_for_seconds` and an authority call's `max_age` is the
/// same value. Two separately maintained constants are exactly the drift §5.4
/// forbids, so [`Self::requirement`] is the only way to obtain a
/// [`FreshnessRequirement`] from a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessProfile {
    pub freshness_profile_id: String,
    pub risk_tier: DidFreshnessRiskTier,
    /// `did:<method>:` prefixes this row applies to, or the single `"*"`.
    pub did_method_selector: Vec<String>,
    pub fresh_for_seconds: Option<u64>,
    pub stale_grace_seconds: Option<u64>,
    pub hard_expiry_seconds: Option<u64>,
    pub stale_behavior: StaleBehavior,
}

impl FreshnessProfile {
    /// A `high` tier row for a registered profile id.
    ///
    /// The id comes from the generated registry surface, never from a string a
    /// deployment spells itself: §5.4 forbids inventing a `freshness_profile_id`
    /// as firmly as it forbids guessing a tier. The **numbers** are the
    /// deployment's to declare (§5.4 last bullet), which is why they are
    /// parameters and the id is not.
    ///
    /// `fresh_for` is the single freshness threshold: it is where
    /// `refresh_after` lands and it is the authority `max_age`. Passing a
    /// `hard_expiry` shorter than it is rejected by the §5.4 tier constraint
    /// `0 < fresh_for <= hard_expiry`, so the caller gets the clamped value
    /// rather than a row that claims a window it cannot honor.
    ///
    /// # Panics
    ///
    /// Never. A non-positive `fresh_for` is clamped to one second, which is the
    /// strictest representable window — the fail-closed direction.
    pub fn high_tier(
        id: DidFreshnessProfileId,
        fresh_for: Duration,
        hard_expiry: Option<Duration>,
    ) -> Self {
        debug_assert_eq!(
            id.risk_tier(),
            DidFreshnessRiskTier::High,
            "`high_tier` may only build a profile registered as the high tier"
        );
        let fresh_for_seconds = fresh_for.num_seconds().max(1) as u64;
        Self {
            freshness_profile_id: id.as_str().to_owned(),
            risk_tier: DidFreshnessRiskTier::High,
            did_method_selector: vec!["*".to_owned()],
            fresh_for_seconds: Some(fresh_for_seconds),
            // §5.4: a `high` row has no stale consumption window at all.
            stale_grace_seconds: None,
            hard_expiry_seconds: Some(
                hard_expiry
                    .map_or(fresh_for_seconds, |window| {
                        window.num_seconds().max(1) as u64
                    })
                    .max(fresh_for_seconds),
            ),
            stale_behavior: StaleBehavior::SynchronousRefreshOrFailClosed,
        }
    }

    /// The freshness this profile demands of a reusable binding.
    ///
    /// `max_age` is the oldest verification this tier will consume, which is
    /// exactly what §5.4 gives each tier:
    ///
    /// | tier | oldest consumable | stale? |
    /// | --- | --- | --- |
    /// | `high` | `fresh_for_seconds` | never — refresh synchronously or fail closed |
    /// | `medium` | `stale_grace_seconds` | inside the finite grace window |
    /// | `low` | unbounded (hard expiry still applies) | yes, and never with a live fallback |
    ///
    /// `fresh_for_seconds` stays the single freshness threshold: it is where
    /// `refresh_after` lands for every tier, and it is the `high` tier's
    /// `max_age`. A tier that consumes stale bindings is bounded by its grace
    /// window instead, not by a second independently maintained constant.
    pub fn requirement(&self) -> FreshnessRequirement {
        FreshnessRequirement {
            max_age: match self.risk_tier {
                DidFreshnessRiskTier::High => self.max_age(),
                DidFreshnessRiskTier::Medium => self.stale_grace(),
                DidFreshnessRiskTier::Low => None,
            },
            require_fresh: self.risk_tier == DidFreshnessRiskTier::High,
        }
    }

    /// `refresh_after` for a binding verified at `verified_at`.
    pub fn refresh_after(&self, verified_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.max_age().map(|window| verified_at + window)
    }

    /// `expires_at` for a binding verified at `verified_at`.
    pub fn expires_at(&self, verified_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.hard_expiry_seconds
            .and_then(|seconds| Duration::try_seconds(seconds as i64))
            .map(|window| verified_at + window)
    }

    fn max_age(&self) -> Option<Duration> {
        self.fresh_for_seconds
            .and_then(|seconds| Duration::try_seconds(seconds as i64))
    }

    fn stale_grace(&self) -> Option<Duration> {
        self.stale_grace_seconds
            .and_then(|seconds| Duration::try_seconds(seconds as i64))
    }
}

/// Freshness an authority caller demands of a reusable binding
/// (`did-usage-and-verification.md` §4 / §5.4).
///
/// There is no `Default` and no "any accepted" constructor: §5.4 requires every
/// authority call site to reference a registered [`FreshnessProfile`], so a
/// requirement is derived from a profile rather than hand-written per call site.
/// A profile-free construction is exactly how five deployments ended up with
/// five different thresholds for the same obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshnessRequirement {
    /// Maximum age of the *verification* (`now - verified_at`), equal to the
    /// profile's `fresh_for_seconds`. `None` only for a profile that declares no
    /// freshness threshold at all (a `low` accepted-only row).
    pub max_age: Option<Duration>,
    /// When `true`, a binding past its `refresh_after` point (status `Stale`)
    /// is rejected and the caller refreshes or fails closed.
    pub require_fresh: bool,
}

// ============================================================================
// Errors
// ============================================================================

/// Internal-consistency violations rejected by [`VerifiedDidBinding::new`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindingError {
    /// `method` does not match the DID's own method segment.
    #[error("binding method `{declared}` does not match DID method `{actual}`")]
    MethodMismatch { declared: String, actual: String },
    /// The DID URL's DID part is not the bound DID.
    #[error("verification_method `{verification_method}` is not controlled by `{did}`")]
    VerificationMethodDidMismatch {
        verification_method: String,
        did: String,
    },
    /// The DID URL carries a `?query`. The spec `did_url` pattern is
    /// `[^\s#?]+#...`, so a query component is not a valid verification method.
    /// `DidUrl::new` does not currently reject it (see the P0-A hand-off list),
    /// so this layer rejects it itself instead of trusting the wire type.
    #[error("verification_method `{verification_method}` must not carry a `?query` component")]
    VerificationMethodHasQuery { verification_method: String },
    /// `expires_at` is not strictly after `verified_at`.
    #[error("expires_at {expires_at} must be after verified_at {verified_at}")]
    ExpiryNotAfterVerification {
        verified_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    /// `refresh_after` precedes `verified_at`.
    #[error("refresh_after {refresh_after} must not precede verified_at {verified_at}")]
    RefreshBeforeVerification {
        verified_at: DateTime<Utc>,
        refresh_after: DateTime<Utc>,
    },
    /// `refresh_after` is past the hard-expiry point.
    #[error("refresh_after {refresh_after} must not exceed expires_at {expires_at}")]
    RefreshAfterExpiry {
        refresh_after: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    /// A pin is missing but no limited-trust record was carried.
    #[error("`{pin}` is not pinned but no limited-trust record was carried")]
    LimitedTrustNotRecorded { pin: &'static str },
    /// Both pins are present but a limited-trust record was still carried.
    #[error(
        "limited-trust record {declared:?} carried although history_head and version_id are both pinned"
    )]
    LimitedTrustNotApplicable { declared: LimitedTrust },
    /// A recorded pin state contradicts the actual presence of that pin.
    #[error(
        "limited-trust `{pin}` records `{declared}` but the pin is {}",
        if *pinned { "present" } else { "absent" }
    )]
    LimitedTrustMismatch {
        pin: &'static str,
        declared: PinState,
        pinned: bool,
    },
    /// The DID document could not be canonicalized for digesting.
    #[error("DID document canonicalization failed: {0}")]
    Canonicalization(String),
    /// The computed digest is not a valid [`Hash`](struct@Hash).
    #[error("computed document digest is invalid: {0}")]
    InvalidDigest(String),
}

// ============================================================================
// Canonical document digest
// ============================================================================

/// Canonical SHA-256 digest of the Arkret v1 normalized DID Document projection.
/// Resolver/convenience metadata is never part of this preimage; raw resolver
/// bytes, when retained as internal evidence, use the separately named
/// `raw_document_digest` contract.
pub fn document_canonical_digest(document: &DidDocument) -> Result<Hash, BindingError> {
    arkret_models_identity::normalized_did_document_digest(document)
        .map_err(|error| BindingError::Canonicalization(error.to_string()))
}

// ============================================================================
// VerifiedDidBinding
// ============================================================================

/// Validated construction input for [`VerifiedDidBinding::new`].
///
/// Every field is required; there is no `Default`, so a call site cannot omit
/// the trust domain, purpose or policy digest by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDidBindingInput {
    /// The bare DID that was verified.
    pub did: Did,
    /// Local trust domain this acceptance is scoped to.
    pub trust_domain: TrustDomainId,
    /// Purpose this acceptance authorizes — and only this one.
    pub purpose: DidBindingPurpose,
    /// DID method name; MUST equal `did.method()`.
    pub method: String,
    /// The accepted concrete verification method, when the acceptance is
    /// key-specific. `None` for subject-level acceptances.
    pub verification_method: Option<DidUrl>,
    /// Canonical digest of the pinned DID document.
    pub document_digest: Hash,
    /// Method history head (`versionId` / entry-hash form), when the method
    /// exposes one. Typed as the schema types it — a webvh `versionId` is not a
    /// `<algo>:<hex>` digest, and forcing it into one is why webvh bindings
    /// could never pin a history head at all.
    pub history_head: Option<String>,
    /// Method version identifier, when the method exposes one.
    pub version_id: Option<String>,
    /// Per-pin limited-trust record; MUST be `Some` exactly when at least one
    /// pin above is absent (§5.5).
    pub limited_trust: Option<LimitedTrust>,
    /// Digest of the canonical evidence receipt the acceptance rests on (§5.2).
    pub evidence_digest: Hash,
    /// Dependency coordinates mechanically extracted from that receipt, so
    /// witness-level invalidation can be selective (§5.6).
    #[serde(default)]
    pub evidence_dependencies: EvidenceDependencies,
    /// Digest of the resolver / Realm policy in force at acceptance time.
    pub policy_digest: Hash,
    /// When the verification happened.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub verified_at: DateTime<Utc>,
    /// Background-refresh point; crossing it only marks the binding `Stale`.
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub refresh_after: Option<DateTime<Utc>>,
    /// Hard-expiry point; past it the binding no longer exists for readers.
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    /// Closed acceptance status.
    pub status: DidBindingStatus,
}

/// Construction input for [`VerifiedDidBinding::from_verified_document`].
///
/// Same as [`VerifiedDidBindingInput`] minus `did` / `method` /
/// `document_digest`, all three of which are derived from the already-verified
/// document so the caller cannot supply an inconsistent digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidBindingDocumentInput {
    pub trust_domain: TrustDomainId,
    pub purpose: DidBindingPurpose,
    pub verification_method: Option<DidUrl>,
    pub history_head: Option<String>,
    pub version_id: Option<String>,
    pub limited_trust: Option<LimitedTrust>,
    pub evidence_digest: Hash,
    pub evidence_dependencies: EvidenceDependencies,
    pub policy_digest: Hash,
    pub verified_at: DateTime<Utc>,
    pub refresh_after: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: DidBindingStatus,
}

/// Immutable, auditable product of one DID authority verification
/// (`did-usage-and-verification.md` §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct VerifiedDidBinding {
    inner: VerifiedDidBindingInput,
}

impl<'de> Deserialize<'de> for VerifiedDidBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = VerifiedDidBindingInput::deserialize(deserializer)?;
        Self::new(input).map_err(serde::de::Error::custom)
    }
}

impl VerifiedDidBinding {
    /// Validating constructor — the only way to obtain a binding.
    ///
    /// Rejects (`did-usage-and-verification.md` §5):
    ///
    /// 1. `method` that disagrees with `did.method()`;
    /// 2. a `verification_method` whose DID part is not `did`;
    /// 3. an incoherent freshness window (`expires_at <= verified_at`, `refresh_after <
    ///    verified_at`, `refresh_after > expires_at`);
    /// 4. a missing `history_head` / `version_id` pin with no recorded [`LimitedTrust`] state (and
    ///    vice versa).
    ///
    /// The digest fields are typed [`Hash`](struct@Hash) values, so `<algo>:<hex>` validity
    /// and non-emptiness are already enforced by the identifier layer.
    ///
    /// The three freshness instants are floored to the canonical millisecond
    /// precision before anything else, so the window checks below and the
    /// serialized form agree with the value the binding keeps in memory. A
    /// caller passing `Utc::now()` would otherwise hold sub-millisecond digits
    /// that no round-trip through the store can preserve.
    pub fn new(mut input: VerifiedDidBindingInput) -> Result<Self, BindingError> {
        input.verified_at = canonical::normalize_timestamp_canonical(input.verified_at);
        input.refresh_after = input
            .refresh_after
            .map(canonical::normalize_timestamp_canonical);
        input.expires_at = input
            .expires_at
            .map(canonical::normalize_timestamp_canonical);

        if input.method != input.did.method() {
            return Err(BindingError::MethodMismatch {
                declared: input.method.clone(),
                actual: input.did.method().to_owned(),
            });
        }

        if let Some(verification_method) = &input.verification_method {
            if verification_method.as_str().contains('?') {
                return Err(BindingError::VerificationMethodHasQuery {
                    verification_method: verification_method.as_str().to_owned(),
                });
            }
            let did_part = verification_method
                .as_str()
                .split_once('#')
                .map(|(did, _)| did)
                .unwrap_or(verification_method.as_str());
            if did_part != input.did.as_str() {
                return Err(BindingError::VerificationMethodDidMismatch {
                    verification_method: verification_method.as_str().to_owned(),
                    did: input.did.as_str().to_owned(),
                });
            }
        }

        if let Some(expires_at) = input.expires_at
            && expires_at <= input.verified_at
        {
            return Err(BindingError::ExpiryNotAfterVerification {
                verified_at: input.verified_at,
                expires_at,
            });
        }
        if let Some(refresh_after) = input.refresh_after {
            if refresh_after < input.verified_at {
                return Err(BindingError::RefreshBeforeVerification {
                    verified_at: input.verified_at,
                    refresh_after,
                });
            }
            if let Some(expires_at) = input.expires_at
                && refresh_after > expires_at
            {
                return Err(BindingError::RefreshAfterExpiry {
                    refresh_after,
                    expires_at,
                });
            }
        }

        // §5.5: the record is omitted exactly when both pins are present, and
        // every recorded state must agree with the actual presence of its pin.
        // "missing pin, no record", "fully pinned but a record anyway" and
        // "record contradicts the pins" are all construction-time rejections —
        // that consistency is a protocol obligation, not a producer courtesy.
        let pins = [
            ("history_head", input.history_head.is_some()),
            ("version_id", input.version_id.is_some()),
        ];
        match input.limited_trust {
            None => {
                if let Some((pin, _)) = pins.iter().find(|(_, pinned)| !pinned) {
                    return Err(BindingError::LimitedTrustNotRecorded { pin });
                }
            }
            Some(declared) => {
                if pins.iter().all(|(_, pinned)| *pinned) {
                    return Err(BindingError::LimitedTrustNotApplicable { declared });
                }
                for ((pin, pinned), state) in pins
                    .iter()
                    .zip([declared.history_head_status, declared.version_id_status])
                {
                    if state.is_pinned() != *pinned {
                        return Err(BindingError::LimitedTrustMismatch {
                            pin,
                            declared: state,
                            pinned: *pinned,
                        });
                    }
                }
            }
        }

        Ok(Self { inner: input })
    }

    /// Build a binding from an **already-verified** DID document, computing the
    /// canonical `document_digest` here so it can never disagree with the
    /// document the acceptance actually rests on.
    ///
    /// `did` and `method` are taken from `document.id`.
    pub fn from_verified_document(
        document: &DidDocument,
        input: VerifiedDidBindingDocumentInput,
    ) -> Result<Self, BindingError> {
        let document_digest = document_canonical_digest(document)?;
        Self::new(VerifiedDidBindingInput {
            did: document.id.clone(),
            trust_domain: input.trust_domain,
            purpose: input.purpose,
            method: document.id.method().to_owned(),
            verification_method: input.verification_method,
            document_digest,
            history_head: input.history_head,
            version_id: input.version_id,
            limited_trust: input.limited_trust,
            evidence_digest: input.evidence_digest,
            evidence_dependencies: input.evidence_dependencies,
            policy_digest: input.policy_digest,
            verified_at: input.verified_at,
            refresh_after: input.refresh_after,
            expires_at: input.expires_at,
            status: input.status,
        })
    }

    /// Return a copy with a different [`DidBindingStatus`].
    ///
    /// Status is the only field that legitimately changes after acceptance
    /// (`Active` → `Stale` on TTL crossing, → `Deactivated` / `Quarantined` on
    /// invalidation); every other invariant is unaffected, so this cannot
    /// produce an inconsistent binding.
    pub fn with_status(&self, status: DidBindingStatus) -> Self {
        let mut inner = self.inner.clone();
        inner.status = status;
        Self { inner }
    }

    /// The lookup key this binding is filed under.
    pub fn key(&self) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: self.inner.did.clone(),
            trust_domain: self.inner.trust_domain.clone(),
            purpose: self.inner.purpose,
            policy_digest: self.inner.policy_digest.clone(),
            verification_method: self.inner.verification_method.clone(),
        }
    }

    /// Whether ordinary per-signature verification may consume this binding.
    ///
    /// `Deactivated` / `Quarantined` bindings are never usable — that is how a
    /// deactivated DID stops authorizing signatures without any resolver call.
    pub fn is_usable_for_ordinary_verification(&self) -> bool {
        self.inner.status.is_usable_for_ordinary_verification()
    }

    /// Whether this binding satisfies an authority caller's freshness policy at
    /// `now` (`did-usage-and-verification.md` §4, last trigger row).
    ///
    /// `now` is explicit rather than read from the wall clock so replay /
    /// historical verification uses the acceptance-time reference.
    pub fn is_usable_for_authority(
        &self,
        freshness: &FreshnessRequirement,
        now: DateTime<Utc>,
    ) -> bool {
        if !self.is_usable_for_ordinary_verification() {
            return false;
        }
        if let Some(expires_at) = self.inner.expires_at
            && now > expires_at
        {
            return false;
        }
        if freshness.require_fresh {
            if self.inner.status != DidBindingStatus::Active {
                return false;
            }
            if let Some(refresh_after) = self.inner.refresh_after
                && now > refresh_after
            {
                return false;
            }
        }
        if let Some(max_age) = freshness.max_age
            && now - self.inner.verified_at > max_age
        {
            return false;
        }
        true
    }

    /// Whether `now` is past the hard-expiry point.
    pub fn is_hard_expired(&self, now: DateTime<Utc>) -> bool {
        self.inner.expires_at.is_some_and(|expires| now > expires)
    }

    /// The bare DID this binding was accepted for.
    pub fn did(&self) -> &Did {
        &self.inner.did
    }

    /// The local trust domain this acceptance is scoped to.
    pub fn trust_domain(&self) -> &TrustDomainId {
        &self.inner.trust_domain
    }

    /// The single purpose this acceptance authorizes.
    pub fn purpose(&self) -> DidBindingPurpose {
        self.inner.purpose
    }

    /// The DID method name.
    pub fn method(&self) -> &str {
        &self.inner.method
    }

    /// The accepted concrete verification method, when key-specific.
    pub fn verification_method(&self) -> Option<&DidUrl> {
        self.inner.verification_method.as_ref()
    }

    /// Canonical digest of the pinned DID document.
    pub fn document_digest(&self) -> &Hash {
        &self.inner.document_digest
    }

    /// Method history head, when pinned.
    pub fn history_head(&self) -> Option<&str> {
        self.inner.history_head.as_deref()
    }

    /// Method version identifier, when pinned.
    pub fn version_id(&self) -> Option<&str> {
        self.inner.version_id.as_deref()
    }

    /// Recorded limited-trust capability, when the pins are incomplete.
    pub fn limited_trust(&self) -> Option<LimitedTrust> {
        self.inner.limited_trust
    }

    /// The §5.6 dependency coordinates this acceptance can be invalidated by.
    pub fn evidence_dependencies(&self) -> &EvidenceDependencies {
        &self.inner.evidence_dependencies
    }

    /// Digest of the canonical evidence receipt behind this acceptance (§5.2).
    pub fn evidence_digest(&self) -> &Hash {
        &self.inner.evidence_digest
    }

    /// Digest of the resolver / Realm policy in force at acceptance time.
    pub fn policy_digest(&self) -> &Hash {
        &self.inner.policy_digest
    }

    /// Verification timestamp.
    pub fn verified_at(&self) -> DateTime<Utc> {
        self.inner.verified_at
    }

    /// Background-refresh point.
    pub fn refresh_after(&self) -> Option<DateTime<Utc>> {
        self.inner.refresh_after
    }

    /// Hard-expiry point.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.inner.expires_at
    }

    /// Closed acceptance status.
    pub fn status(&self) -> DidBindingStatus {
        self.inner.status
    }
}

// ============================================================================
// Lookup key
// ============================================================================

/// Store lookup key (`did-usage-and-verification.md` §4: a result may be reused
/// "only when it is bound to the same DID, trust domain, purpose, policy digest
/// and an acceptable freshness").
///
/// Keying by DID alone would silently reuse an acceptance across trust domains
/// or purposes, which the task's risk section explicitly forbids.
///
/// `version_id` is deliberately **not** a key dimension. §5.2 makes it a product
/// of the resolution, so a caller cannot know it before looking the entry up;
/// keying on it would make every lookup miss and every rotation file a parallel
/// entry nobody can reach instead of replacing the one it supersedes. It stays a
/// binding field and an invalidation dimension.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VerifiedDidBindingKey {
    pub did: Did,
    pub trust_domain: TrustDomainId,
    pub purpose: DidBindingPurpose,
    pub policy_digest: Hash,
    pub verification_method: Option<DidUrl>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn trust_domain(scope: &str) -> TrustDomainId {
        TrustDomainId::new(format!("ak:trust_domain:{scope}")).expect("valid trust domain")
    }

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:binding.example".to_owned()).expect("valid did")
    }

    /// A `low` accepted-only profile's requirement.
    fn accepted_only() -> FreshnessRequirement {
        FreshnessRequirement {
            max_age: None,
            require_fresh: false,
        }
    }

    /// A `high` profile's requirement over `window`.
    fn fresh_within(window: Duration) -> FreshnessRequirement {
        FreshnessRequirement {
            max_age: Some(window),
            require_fresh: true,
        }
    }

    fn input() -> VerifiedDidBindingInput {
        let did = did();
        VerifiedDidBindingInput {
            method: did.method().to_owned(),
            verification_method: Some(DidUrl::new(format!("{did}#key-1")).expect("valid did url")),
            did,
            trust_domain: trust_domain("local"),
            purpose: DidBindingPurpose::Principal,
            document_digest: hash(0x11),
            history_head: Some("1-abc".to_owned()),
            version_id: Some("1-abc".to_owned()),
            limited_trust: None,
            evidence_digest: hash(0x33),
            evidence_dependencies: EvidenceDependencies::default(),
            policy_digest: hash(0x44),
            verified_at: Utc::now(),
            refresh_after: None,
            expires_at: None,
            status: DidBindingStatus::Active,
        }
    }

    #[test]
    fn accepts_a_fully_pinned_binding() {
        let binding = VerifiedDidBinding::new(input()).expect("valid binding");
        assert!(binding.is_usable_for_ordinary_verification());
        assert_eq!(binding.limited_trust(), None);
    }

    #[test]
    fn rejects_method_that_disagrees_with_the_did() {
        let mut input = input();
        input.method = "web".to_owned();
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::MethodMismatch { .. })
        ));
    }

    #[test]
    fn rejects_verification_method_controlled_by_another_did() {
        let mut input = input();
        input.verification_method = Some(
            DidUrl::new("did:webvh:z6mkfixture:other.example#key-1".to_owned())
                .expect("valid did url"),
        );
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::VerificationMethodDidMismatch { .. })
        ));
    }

    #[test]
    fn rejects_expiry_at_or_before_verification() {
        let mut input = input();
        input.expires_at = Some(input.verified_at);
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::ExpiryNotAfterVerification { .. })
        ));
    }

    #[test]
    fn rejects_refresh_point_outside_the_window() {
        let mut before = input();
        before.refresh_after = Some(before.verified_at - Duration::seconds(1));
        assert!(matches!(
            VerifiedDidBinding::new(before),
            Err(BindingError::RefreshBeforeVerification { .. })
        ));

        let mut after = input();
        after.expires_at = Some(after.verified_at + Duration::minutes(5));
        after.refresh_after = Some(after.verified_at + Duration::minutes(6));
        assert!(matches!(
            VerifiedDidBinding::new(after),
            Err(BindingError::RefreshAfterExpiry { .. })
        ));
    }

    #[test]
    fn rejects_missing_pins_without_a_limited_trust_record() {
        let mut input = input();
        input.history_head = None;
        input.version_id = None;
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustNotRecorded {
                pin: "history_head"
            })
        ));
    }

    #[test]
    fn rejects_a_limited_trust_state_that_contradicts_its_pin() {
        let mut input = input();
        input.history_head = None;
        input.limited_trust = Some(LimitedTrust {
            history_head_status: PinState::Pinned,
            version_id_status: PinState::MethodUnsupported,
        });
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustMismatch {
                pin: "history_head",
                declared: PinState::Pinned,
                pinned: false,
            })
        ));
    }

    #[test]
    fn rejects_a_limited_trust_record_on_a_fully_pinned_binding() {
        let mut input = input();
        input.limited_trust = Some(LimitedTrust {
            history_head_status: PinState::Pinned,
            version_id_status: PinState::Pinned,
        });
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustNotApplicable { .. })
        ));
    }

    /// The distinction §5.5 exists for: a resolver that failed to surface a pin
    /// its method supports must not be recorded as a method that has none.
    #[test]
    fn pin_states_separate_an_unsupported_method_from_a_silent_resolver() {
        assert_eq!(
            LimitedTrust::for_proofless_method(None, None),
            LimitedTrust {
                history_head_status: PinState::MethodUnsupported,
                version_id_status: PinState::MethodUnsupported,
            }
        );
        assert_eq!(
            LimitedTrust::for_evidence_bearing_method(None, Some("1-abc")),
            LimitedTrust {
                history_head_status: PinState::NotSurfaced,
                version_id_status: PinState::Pinned,
            }
        );
        assert_eq!(
            LimitedTrust::for_evidence_bearing_method(Some("1-abc"), Some("1-abc")).record_for(),
            None,
            "a fully pinned binding omits the record entirely"
        );
    }

    #[test]
    fn deactivated_binding_is_never_usable() {
        let mut input = input();
        input.status = DidBindingStatus::Deactivated;
        let binding = VerifiedDidBinding::new(input).expect("valid binding");
        assert!(!binding.is_usable_for_ordinary_verification());
        assert!(!binding.is_usable_for_authority(&accepted_only(), Utc::now()));
    }

    #[test]
    fn quarantined_binding_is_never_usable() {
        let mut input = input();
        input.status = DidBindingStatus::Quarantined;
        let binding = VerifiedDidBinding::new(input).expect("valid binding");
        assert!(!binding.is_usable_for_ordinary_verification());
    }

    #[test]
    fn stale_binding_serves_ordinary_verification_but_not_a_fresh_authority_call() {
        let mut input = input();
        input.status = DidBindingStatus::Stale;
        let now = input.verified_at + Duration::minutes(30);
        let binding = VerifiedDidBinding::new(input).expect("valid binding");
        assert!(binding.is_usable_for_ordinary_verification());
        assert!(binding.is_usable_for_authority(&accepted_only(), now));
        assert!(!binding.is_usable_for_authority(&fresh_within(Duration::hours(1)), now));
    }

    #[test]
    fn max_age_bounds_authority_reuse() {
        let binding = VerifiedDidBinding::new(input()).expect("valid binding");
        let requirement = fresh_within(Duration::minutes(10));
        assert!(
            binding.is_usable_for_authority(
                &requirement,
                binding.verified_at() + Duration::minutes(5)
            )
        );
        assert!(
            !binding.is_usable_for_authority(
                &requirement,
                binding.verified_at() + Duration::minutes(11)
            )
        );
    }

    #[test]
    fn generated_freshness_tier_preserves_profile_wire_contract() {
        let profile = FreshnessProfile::high_tier(
            DidFreshnessProfileId::RegistrationCurrentV1,
            Duration::seconds(30),
            None,
        );
        let mut value = serde_json::to_value(&profile).expect("profile serializes");
        assert_eq!(value["risk_tier"], "high");
        for tier in ["low", "medium", "high"] {
            value["risk_tier"] = serde_json::json!(tier);
            let parsed: FreshnessProfile = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap()["risk_tier"], tier);
        }
        value["risk_tier"] = serde_json::json!("critical");
        assert!(serde_json::from_value::<FreshnessProfile>(value).is_err());
    }

    #[test]
    fn purpose_rejects_unknown_serde_values() {
        assert!(serde_json::from_str::<DidBindingPurpose>("\"principal\"").is_ok());
        assert!(serde_json::from_str::<DidBindingPurpose>("\"admin_action\"").is_ok());
        assert!(
            serde_json::from_str::<DidBindingPurpose>("\"totally_new_purpose\"").is_err(),
            "purpose must be a closed enum, not an arbitrary string"
        );
    }

    #[test]
    fn status_rejects_unknown_serde_values() {
        assert!(serde_json::from_str::<DidBindingStatus>("\"quarantined\"").is_ok());
        assert!(serde_json::from_str::<DidBindingStatus>("\"probably_fine\"").is_err());
    }

    #[test]
    fn deserialization_reruns_the_constructor_checks() {
        let mut tampered = input();
        tampered.method = "web".to_owned();
        let json = serde_json::to_string(&tampered).expect("serialize");
        assert!(
            serde_json::from_str::<VerifiedDidBinding>(&json).is_err(),
            "serde must not be a back door around the validating constructor"
        );

        let json = serde_json::to_string(&input()).expect("serialize");
        let round_tripped: VerifiedDidBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_tripped.did().as_str(), did().as_str());
    }

    #[test]
    fn from_verified_document_computes_the_digest_itself() {
        let did = Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned())
            .expect("valid did");
        let document = DidDocument::new(
            did.clone(),
            format!("{did}#k1"),
            "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        );
        let binding = VerifiedDidBinding::from_verified_document(
            &document,
            VerifiedDidBindingDocumentInput {
                trust_domain: trust_domain("local"),
                purpose: DidBindingPurpose::DeviceSigner,
                verification_method: None,
                history_head: None,
                version_id: None,
                limited_trust: Some(LimitedTrust::for_proofless_method(None, None)),
                evidence_digest: hash(0x55),
                evidence_dependencies: EvidenceDependencies::default(),
                policy_digest: hash(0x66),
                verified_at: Utc::now(),
                refresh_after: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            },
        )
        .expect("valid binding");

        assert_eq!(binding.method(), "key");
        assert_eq!(
            binding.document_digest(),
            &document_canonical_digest(&document).expect("digest")
        );
    }

    #[test]
    fn document_digest_matches_the_cached_resolution_hash_format() {
        // The digest MUST stay byte-identical to the string the resolver cache
        // stores in `CachedResolution::document_hash`.
        let did = Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned())
            .expect("valid did");
        let document = DidDocument::new(
            did.clone(),
            format!("{did}#k1"),
            "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        );
        let cached = crate::CachedResolution::new(
            document.clone(),
            Utc::now(),
            Utc::now() + Duration::minutes(5),
        )
        .expect("cache entry");
        assert_eq!(
            document_canonical_digest(&document)
                .expect("digest")
                .as_str(),
            cached.document_hash
        );
    }
}
