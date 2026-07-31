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
use arkret_wire::{Did, DidUrl, Hash, TypedTrustDomainId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::DidDocument;

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
/// purpose is not covered by an existing trigger row, file a
/// `review/spec-open/` entry before implementing it.
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
/// | [`AdminAction`](Self::AdminAction) | Coauth DID-P2-A (admin / erasure) |
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
    /// Principal-server service endpoint binding (Teabay DID-P0-C02).
    PrincipalServiceEndpoint,
    /// Account registration / claim binding (Coauth DID-P2-A).
    AccountBinding,
    /// Account recovery authority (Coauth DID-P2-A).
    Recovery,
    /// Organization registry control (Coauth DID-P2-A).
    OrganizationRegistry,
    /// Admin / erasure action authority (Coauth DID-P2-A).
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

/// Why a binding could not pin a full history / version anchor.
///
/// `did-usage-and-verification.md` §5 allows `history_head` / `version_id` to be
/// absent for methods that do not support them — **but the limited-trust
/// capability MUST be recorded**. This enum is that record; leaving both pins
/// empty without a reason is rejected by [`VerifiedDidBinding::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitedTrustReason {
    /// The method has no verifiable append-only history log (`did:key`,
    /// plain `did:web`): `history_head` is absent, `version_id` is pinned.
    MethodHasNoHistoryLog,
    /// The method exposes a history head but no stable version identifier.
    MethodHasNoVersionId,
    /// Neither a history head nor a version identifier could be pinned; the
    /// binding rests on the document digest and policy alone.
    MethodHasNeitherHistoryNorVersion,
}

impl LimitedTrustReason {
    /// Return the reason implied by the supplied pins, or `None` when both are
    /// pinned (full-trust acceptance).
    ///
    /// Callers building a binding from a resolver result should use this to
    /// fill [`VerifiedDidBindingInput::limited_trust`] instead of guessing;
    /// [`VerifiedDidBinding::new`] validates the result either way.
    pub fn for_pins(history_head: Option<&Hash>, version_id: Option<&str>) -> Option<Self> {
        match (history_head.is_some(), version_id.is_some()) {
            (true, true) => None,
            (false, true) => Some(Self::MethodHasNoHistoryLog),
            (true, false) => Some(Self::MethodHasNoVersionId),
            (false, false) => Some(Self::MethodHasNeitherHistoryNorVersion),
        }
    }
}

// ============================================================================
// Freshness requirement
// ============================================================================

/// Freshness an authority caller demands of a reusable binding
/// (`did-usage-and-verification.md` §4, last trigger row).
///
/// There is no `Default`: the spec requires every authority call site to state
/// its own freshness policy explicitly, so an omitted requirement cannot
/// silently degrade into "any cached binding will do".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshnessRequirement {
    /// Maximum age of the *verification* (`now - verified_at`). `None` means
    /// the age itself is unbounded and only `require_fresh` applies.
    pub max_age: Option<Duration>,
    /// When `true`, a binding past its `refresh_after` point (status `Stale`)
    /// is rejected and the caller refreshes or fails closed.
    pub require_fresh: bool,
}

impl FreshnessRequirement {
    /// High-risk authority profile: the binding must not be past
    /// `refresh_after` and must be no older than `max_age`.
    pub fn fresh_within(max_age: Duration) -> Self {
        Self {
            max_age: Some(max_age),
            require_fresh: true,
        }
    }

    /// Low-risk profile: any non-hard-expired binding is acceptable, including
    /// a `Stale` one. Used by read paths that MUST NOT live-fallback.
    pub fn any_accepted() -> Self {
        Self {
            max_age: None,
            require_fresh: false,
        }
    }
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
    /// A pin is missing but no limited-trust reason was recorded.
    #[error(
        "history_head / version_id incomplete but no limited-trust reason was recorded (expected {expected:?})"
    )]
    LimitedTrustNotRecorded { expected: LimitedTrustReason },
    /// Both pins are present but a limited-trust reason was still claimed.
    #[error("limited-trust reason {declared:?} recorded although history_head and version_id are both pinned")]
    LimitedTrustNotApplicable { declared: LimitedTrustReason },
    /// The recorded limited-trust reason contradicts the actual pins.
    #[error("limited-trust reason {declared:?} contradicts the recorded pins (expected {expected:?})")]
    LimitedTrustMismatch {
        declared: LimitedTrustReason,
        expected: LimitedTrustReason,
    },
    /// The DID document could not be canonicalized for digesting.
    #[error("DID document canonicalization failed: {0}")]
    Canonicalization(String),
    /// The computed digest is not a valid [`Hash`].
    #[error("computed document digest is invalid: {0}")]
    InvalidDigest(String),
}

// ============================================================================
// Canonical document digest
// ============================================================================

/// Canonical SHA-256 digest of a DID document, byte-identical to the value
/// stored in [`CachedResolution::document_hash`](crate::CachedResolution) — the
/// same `canonical_json_bytes` + `sha256_digest` pair, wrapped in the typed
/// [`Hash`] newtype so it cannot be confused with an arbitrary string.
pub fn document_canonical_digest(document: &DidDocument) -> Result<Hash, BindingError> {
    let bytes = canonical::canonical_json_bytes(document)
        .map_err(|error| BindingError::Canonicalization(error.to_string()))?;
    Hash::new(canonical::sha256_digest(bytes))
        .map_err(|error| BindingError::InvalidDigest(error.to_string()))
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
    pub trust_domain: TypedTrustDomainId,
    /// Purpose this acceptance authorizes — and only this one.
    pub purpose: DidBindingPurpose,
    /// DID method name; MUST equal `did.method()`.
    pub method: String,
    /// The accepted concrete verification method, when the acceptance is
    /// key-specific. `None` for subject-level acceptances.
    pub verification_method: Option<DidUrl>,
    /// Canonical digest of the pinned DID document.
    pub document_digest: Hash,
    /// Method history head, when the method exposes one.
    pub history_head: Option<Hash>,
    /// Method version identifier, when the method exposes one.
    pub version_id: Option<String>,
    /// Why the pins above are incomplete; MUST be `Some` exactly when at least
    /// one of them is absent.
    pub limited_trust: Option<LimitedTrustReason>,
    /// Digest of the method evidence the acceptance rests on.
    pub evidence_digest: Hash,
    /// Digest of the resolver / Realm policy in force at acceptance time.
    pub policy_digest: Hash,
    /// When the verification happened.
    pub verified_at: DateTime<Utc>,
    /// Background-refresh point; crossing it only marks the binding `Stale`.
    pub refresh_after: Option<DateTime<Utc>>,
    /// Hard-expiry point; past it the binding no longer exists for readers.
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
    pub trust_domain: TypedTrustDomainId,
    pub purpose: DidBindingPurpose,
    pub verification_method: Option<DidUrl>,
    pub history_head: Option<Hash>,
    pub version_id: Option<String>,
    pub limited_trust: Option<LimitedTrustReason>,
    pub evidence_digest: Hash,
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
    /// 3. an incoherent freshness window (`expires_at <= verified_at`,
    ///    `refresh_after < verified_at`, `refresh_after > expires_at`);
    /// 4. a missing `history_head` / `version_id` pin with no recorded
    ///    [`LimitedTrustReason`] (and vice versa).
    ///
    /// The digest fields are typed [`Hash`] values, so `<algo>:<hex>` validity
    /// and non-emptiness are already enforced by the identifier layer.
    pub fn new(input: VerifiedDidBindingInput) -> Result<Self, BindingError> {
        if input.method != input.did.method() {
            return Err(BindingError::MethodMismatch {
                declared: input.method.clone(),
                actual: input.did.method().to_owned(),
            });
        }

        if let Some(verification_method) = &input.verification_method {
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

        let expected_limited_trust = LimitedTrustReason::for_pins(
            input.history_head.as_ref(),
            input.version_id.as_deref(),
        );
        match (expected_limited_trust, input.limited_trust) {
            (None, None) => {}
            (Some(expected), None) => {
                return Err(BindingError::LimitedTrustNotRecorded { expected });
            }
            (None, Some(declared)) => {
                return Err(BindingError::LimitedTrustNotApplicable { declared });
            }
            (Some(expected), Some(declared)) if expected != declared => {
                return Err(BindingError::LimitedTrustMismatch { declared, expected });
            }
            (Some(_), Some(_)) => {}
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
            version_id: self.inner.version_id.clone(),
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

    /// Whether `now` is past the background-refresh point (but see
    /// [`Self::is_hard_expired`] first).
    pub fn is_past_refresh(&self, now: DateTime<Utc>) -> bool {
        self.inner.refresh_after.is_some_and(|refresh| now > refresh)
    }

    /// The bare DID this binding was accepted for.
    pub fn did(&self) -> &Did {
        &self.inner.did
    }

    /// The local trust domain this acceptance is scoped to.
    pub fn trust_domain(&self) -> &TypedTrustDomainId {
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
    pub fn history_head(&self) -> Option<&Hash> {
        self.inner.history_head.as_ref()
    }

    /// Method version identifier, when pinned.
    pub fn version_id(&self) -> Option<&str> {
        self.inner.version_id.as_deref()
    }

    /// Recorded limited-trust capability, when the pins are incomplete.
    pub fn limited_trust(&self) -> Option<LimitedTrustReason> {
        self.inner.limited_trust
    }

    /// Digest of the method evidence behind this acceptance.
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VerifiedDidBindingKey {
    pub did: Did,
    pub trust_domain: TypedTrustDomainId,
    pub purpose: DidBindingPurpose,
    pub policy_digest: Hash,
    pub verification_method: Option<DidUrl>,
    pub version_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn trust_domain(scope: &str) -> TypedTrustDomainId {
        TypedTrustDomainId::new(format!("ak:trust_domain:{scope}")).expect("valid trust domain")
    }

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:binding.example".to_owned()).expect("valid did")
    }

    fn input() -> VerifiedDidBindingInput {
        let did = did();
        VerifiedDidBindingInput {
            method: did.method().to_owned(),
            verification_method: Some(
                DidUrl::new(format!("{did}#key-1")).expect("valid did url"),
            ),
            did,
            trust_domain: trust_domain("local"),
            purpose: DidBindingPurpose::Principal,
            document_digest: hash(0x11),
            history_head: Some(hash(0x22)),
            version_id: Some("1-abc".to_owned()),
            limited_trust: None,
            evidence_digest: hash(0x33),
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
    fn rejects_missing_pins_without_a_limited_trust_reason() {
        let mut input = input();
        input.history_head = None;
        input.version_id = None;
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustNotRecorded {
                expected: LimitedTrustReason::MethodHasNeitherHistoryNorVersion
            })
        ));
    }

    #[test]
    fn rejects_a_limited_trust_reason_that_contradicts_the_pins() {
        let mut input = input();
        input.history_head = None;
        input.limited_trust = Some(LimitedTrustReason::MethodHasNoVersionId);
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustMismatch { .. })
        ));
    }

    #[test]
    fn rejects_a_limited_trust_reason_on_a_fully_pinned_binding() {
        let mut input = input();
        input.limited_trust = Some(LimitedTrustReason::MethodHasNoHistoryLog);
        assert!(matches!(
            VerifiedDidBinding::new(input),
            Err(BindingError::LimitedTrustNotApplicable { .. })
        ));
    }

    #[test]
    fn deactivated_binding_is_never_usable() {
        let mut input = input();
        input.status = DidBindingStatus::Deactivated;
        let binding = VerifiedDidBinding::new(input).expect("valid binding");
        assert!(!binding.is_usable_for_ordinary_verification());
        assert!(!binding.is_usable_for_authority(&FreshnessRequirement::any_accepted(), Utc::now()));
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
        assert!(binding.is_usable_for_authority(&FreshnessRequirement::any_accepted(), now));
        assert!(!binding.is_usable_for_authority(
            &FreshnessRequirement::fresh_within(Duration::hours(1)),
            now
        ));
    }

    #[test]
    fn max_age_bounds_authority_reuse() {
        let binding = VerifiedDidBinding::new(input()).expect("valid binding");
        let requirement = FreshnessRequirement::fresh_within(Duration::minutes(10));
        assert!(binding.is_usable_for_authority(
            &requirement,
            binding.verified_at() + Duration::minutes(5)
        ));
        assert!(!binding.is_usable_for_authority(
            &requirement,
            binding.verified_at() + Duration::minutes(11)
        ));
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
        let mut input = input();
        input.method = "web".to_owned();
        let json = serde_json::to_string(&input).expect("serialize");
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
        let did = Did::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
        )
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
                limited_trust: Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion),
                evidence_digest: hash(0x55),
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
        let did = Did::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
        )
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
