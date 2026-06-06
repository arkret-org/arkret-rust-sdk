use super::*;

/// Verification state for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationState {
    /// Device has not been verified.
    Unverified,
    /// Verification is in progress.
    VerificationStarted,
    /// Device has been verified.
    Verified,
    /// Cross-signing was reset since this device was last verified. The
    /// device must be re-verified before being treated as `verified` again.
    /// See `crypto-media/device-lifecycle.md` §14.2.
    NeedsReverification,
    /// Device is blocked.
    Blocked,
    /// Device was deleted locally.
    Deleted,
    /// Verification failed due to mismatch.
    VerificationFailed,
    /// Verification was cancelled before completion.
    VerificationCancelled,
    /// Verification expired before completion.
    VerificationExpired,
}

/// Round 4 (2026-05-20, spec a77b995) — `ServiceDescribe` v2 has 17
/// REQUIRED top-level fields plus a discriminated `rate_limit`. The
/// pre-round-4 sparse-default surface is wire-broken; receivers MUST
/// reject describe responses missing any required field with
/// `schema_violation`.
///
/// The 17 required fields (matches `service-describe.schema.json`):
/// `service_did`, `trust_domain`, `service_type`, `protocol_version`,
/// `supported_profiles`, `supported_operations`, `supported_bindings`,
/// `supported_features`, `auth_metadata`, `limits`,
/// `plaintext_visibility`, `implemented_features`, `claimed_profiles`,
/// `verified_profiles`, `experimental_features`, `compat_surfaces`,
/// `development_mode`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ServerDescription {
    pub service_did: Did,
    /// Round 4 — REQUIRED trust domain. Receivers MUST refuse to
    /// register a peer whose `trust_domain` disagrees with the
    /// expected deployment scope.
    pub trust_domain: TypedTrustDomainId,
    pub service_type: String,
    pub protocol_version: String,
    /// Round 4 — REQUIRED (no longer defaulted): profiles the service
    /// declares conformance to. Empty array is valid; missing is not.
    pub supported_profiles: Vec<String>,
    pub supported_operations: Vec<String>,
    pub supported_bindings: Vec<Value>,
    pub supported_features: Vec<String>,
    pub auth_metadata: Value,
    pub limits: Value,
    /// Round 4 — plaintext visibility advertisement. Receivers MUST
    /// treat a missing value as `untrusted` (fail-closed for the
    /// mention-redirect / late-recovery paths). Wire shape per
    /// `service-describe.schema.json#plaintext_visibility`.
    pub plaintext_visibility: Value,
    /// Round 4 — features the service has actually implemented (subset
    /// of `supported_features`). Tracks the difference between
    /// announce and run-time implementation.
    pub implemented_features: Vec<String>,
    /// Round 4 — profiles the service claims (self-declared). Wire
    /// shape per
    /// `service-describe.schema.json#/properties/claimed_profiles`:
    /// every entry MUST be an object with `profile_id` +
    /// `claim_kind = "self_claimed"`; verified-only assertions live in
    /// [`Self::verified_profiles`].
    pub claimed_profiles: Vec<ClaimedProfileEntry>,
    /// Round 4 — profiles a third party has verified the service
    /// against. MUST be empty when `development_mode == true`. Wire
    /// shape per
    /// `service-describe.schema.json#/properties/verified_profiles`.
    pub verified_profiles: Vec<VerifiedProfileEntry>,
    /// Round 4 — non-final extension features. Treated as opt-in by
    /// peers.
    pub experimental_features: Vec<String>,
    /// Round 4 — back-compat / external-interop surfaces this service
    /// exposes outside its claimed v1 conformance (e.g. MIMI/Matrix
    /// passthrough). Wire shape per
    /// `service-describe.schema.json#/properties/compat_surfaces`.
    pub compat_surfaces: Vec<CompatSurfaceEntry>,
    /// Round 4 — REQUIRED. When `true` the service is in development
    /// mode; receivers MUST refuse to advertise `verified_profiles`
    /// and SHOULD warn on connection.
    pub development_mode: bool,
    /// Round 4 — `oneOf` rate-limit declaration (windowed / token /
    /// adaptive). Left as `Value` here so the SDK doesn't pin to one
    /// variant; service-specific helpers may parse further.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub rate_limit: Value,
    /// R3.4 — coarse outbound network policy for SSRF-sensitive service
    /// calls such as DID resolution, federation, media fetch, snapshots,
    /// webhooks, applets, agents, directory and push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_network_policy: Option<EgressNetworkPolicy>,
    /// Reducer profiles supported (kept for back-compat — populated
    /// by the producer alongside `supported_profiles`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_schema_profiles: Vec<String>,
    /// Current causal frontier exposed by the service. Clients SHOULD
    /// use this to detect a service that has fallen behind a known
    /// snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontier: Vec<EventId>,
    /// Frontier of the most recent snapshot the service can serve from
    /// (empty means snapshot-assisted resolution is unavailable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshot_frontier: Vec<EventId>,
    /// Active reducer profile (e.g. `ck.reducer.v1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer_profile: Option<String>,
    /// Wall-clock time of the most recent successful state
    /// materialization. A stale `last_materialized_at` paired with a
    /// fresh `frontier` indicates the projection layer is degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_materialized_at: Option<DateTime<Utc>>,
}

impl ServerDescription {
    /// Round 4 — validate the cross-field invariants:
    /// - `verified_profiles` MUST be empty when `development_mode = true`.
    /// - `protocol_version` MUST equal [`crate::PROTOCOL_VERSION`].
    pub fn validate(&self) -> Result<()> {
        if self.development_mode && !self.verified_profiles.is_empty() {
            return Err(Error::Protocol(format!(
                "ServiceDescribe: development_mode=true forbids non-empty verified_profiles \
                 ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

impl ServerDescription {
    pub fn supports_cokret_v1(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EgressNetworkPolicy {
    pub version: u32,
    pub private_network_default: EgressPrivateNetworkDefault,
    #[serde(default)]
    pub protected_purposes: Vec<EgressProtectedPurpose>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_private_exceptions: Vec<EgressPrivateException>,
    pub dns_rebind_protection: bool,
    pub redirect_recheck: bool,
}

impl EgressNetworkPolicy {
    /// Fail-closed baseline recommended for public service descriptions.
    pub fn deny_private_defaults() -> Self {
        Self {
            version: 1,
            private_network_default: EgressPrivateNetworkDefault::Deny,
            protected_purposes: EgressProtectedPurpose::ALL.to_vec(),
            denied_cidrs: Vec::new(),
            allowed_cidrs: Vec::new(),
            allowed_private_exceptions: Vec::new(),
            dns_rebind_protection: true,
            redirect_recheck: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EgressPrivateNetworkDefault {
    Deny,
    DenyUnlessExplicitException,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EgressProtectedPurpose {
    DidResolution,
    Federation,
    MediaFetch,
    PolicyServer,
    SnapshotFetch,
    Webhook,
    Applet,
    Agent,
    Directory,
    Push,
}

impl EgressProtectedPurpose {
    pub const ALL: &'static [Self] = &[
        Self::DidResolution,
        Self::Federation,
        Self::MediaFetch,
        Self::PolicyServer,
        Self::SnapshotFetch,
        Self::Webhook,
        Self::Applet,
        Self::Agent,
        Self::Directory,
        Self::Push,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EgressPrivateException {
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TypedTrustDomainId>,
    pub cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub development_mode_only: Option<bool>,
    pub expires_at: DateTime<Utc>,
}

/// Round 4 — wire-level entry in
/// [`ServerDescription::claimed_profiles`]. Mirrors
/// `service-describe.schema.json#/properties/claimed_profiles/items`:
/// `profile_id` + `claim_kind = "self_claimed"` are required, the rest
/// is optional + open (`additionalProperties: true`) so receivers can
/// round-trip future fields without losing them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ClaimedProfileEntry {
    pub profile_id: String,
    pub claim_kind: SelfClaimedKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ClaimedProfileEntry {
    pub fn self_claimed(profile_id: impl Into<String>) -> Self {
        Self {
            profile_id: profile_id.into(),
            claim_kind: SelfClaimedKind::SelfClaimed,
            claimed_at: None,
            notes: None,
            extra: BTreeMap::new(),
        }
    }
}

/// Round 4 — `claim_kind` discriminant for
/// [`ClaimedProfileEntry`]. The spec restricts this slot to
/// `self_claimed`; verified-by-cotest claims belong in
/// [`VerifiedProfileEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SelfClaimedKind {
    SelfClaimed,
}

/// Round 4 — wire-level entry in
/// [`ServerDescription::verified_profiles`]. Mirrors
/// `service-describe.schema.json#/properties/verified_profiles/items`:
/// requires a cotest run id, artifact hash, artifact reference, issuer DID,
/// issuer signature, and timestamp so consumers can pin the claim to an
/// auditable run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct VerifiedProfileEntry {
    pub profile_id: String,
    pub claim_kind: CotestVerifiedKind,
    pub cotest_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub cotest_issuer_did: Did,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Round 4 — `claim_kind` discriminant for
/// [`VerifiedProfileEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CotestVerifiedKind {
    CotestVerified,
}

/// Round 4 — wire-level entry in
/// [`ServerDescription::compat_surfaces`]. Mirrors
/// `service-describe.schema.json#/properties/compat_surfaces/items`:
/// `name` + `kind` are required and `kind` is restricted to a closed
/// enum so receivers can fast-path the dispatch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CompatSurfaceEntry {
    pub name: String,
    pub kind: CompatSurfaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl CompatSurfaceEntry {
    pub fn new(name: impl Into<String>, kind: CompatSurfaceKind) -> Self {
        Self { name: name.into(), kind, since: None, notes: None, extra: BTreeMap::new() }
    }

    pub fn matrix_passthrough(name: impl Into<String>) -> Self {
        Self::new(name, CompatSurfaceKind::MatrixPassthrough)
    }

    pub fn mimi_passthrough(name: impl Into<String>) -> Self {
        Self::new(name, CompatSurfaceKind::MimiPassthrough)
    }

    pub fn external_interop(name: impl Into<String>) -> Self {
        Self::new(name, CompatSurfaceKind::ExternalInterop)
    }

    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = Some(since.into());
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn with_extra_string(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.with_extra(key, Value::String(value.into()))
    }
}

/// Round 4 — closed enum of compat-surface kinds the spec recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CompatSurfaceKind {
    MatrixPassthrough,
    MimiPassthrough,
    ExternalInterop,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub error: ErrorDetail,
    pub request_id: String,
}

impl ErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "unknown".to_owned(),
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: Option<u64>) -> Self {
        self.error.retry_after_ms = retry_after_ms;
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.error.details.insert(key.into(), value);
        self
    }

    pub fn code(&self) -> &str {
        &self.error.code
    }

    pub fn message(&self) -> &str {
        &self.error.message
    }

    pub fn retry_after_ms(&self) -> Option<u64> {
        self.error.retry_after_ms
    }

    pub fn details(&self) -> &BTreeMap<String, Value> {
        &self.error.details
    }
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}

#[cfg(test)]
mod error_envelope_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn error_envelope_serializes_to_spec_canonical_shape() {
        let envelope = ErrorEnvelope::new("capability_denied", "session grant is revoked")
            .with_request_id("ck:request:test")
            .with_retry_after_ms(None);

        let value = serde_json::to_value(envelope).unwrap();

        assert_eq!(
            value,
            json!({
                "ok": false,
                "error": {
                    "code": "capability_denied",
                    "message": "session grant is revoked"
                },
                "request_id": "ck:request:test"
            })
        );
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityDescription {
    pub service_did: Did,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityResolveReqBody {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_evidence_kinds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityResolveResBody {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub method_evidence: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidDocumentRef {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub document: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityDocumentResBody {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLogResBody {
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitDidOperationReqBody {
    pub did: Did,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_digest: Option<Hash>,
    pub patch: Value,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitDidOperationResBody {
    pub status: String,
    pub head_event_digest: Hash,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityReceiptsResBody {
    #[serde(default)]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_presence: Option<String>,
}

/// Folded account-aggregate delta used by SDK internals.
///
/// Current wire delivery is `ck.self.account.subscribe`: an NDJSON stream of
/// [`AccountSubscribeFrame`] values. The SDK folds `delta` frames into this
/// shape so existing reducers and UI code can consume a single account snapshot
/// value without depending on transport streaming details.
///
/// Per-realm bodies are kept as raw `Value` so consumers can introspect the
/// bucket / inner shape without colliding with the typed SDK sync_client
/// surface in [`crate::sync::SyncRealm`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncResBody {
    /// Opaque stream cursor — clients MUST treat it as opaque and pass it back
    /// as `after` on the next `/account/subscribe` request.
    pub cursor: String,
    /// Realm sync bodies keyed by `ck:realm:*`. Kept as `Value` so the HTTP
    /// layer doesn't constrain per-realm extra
    /// fields (e.g. `state_after`, `flows`) that the spec leaves open.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub realms: BTreeMap<String, Value>,
    /// Realms the viewer no longer has access to after the supplied
    /// `after` cursor — left rooms, kicks, bans, server-side
    /// deletions. Empty on full sync (omission from `realms` is
    /// authoritative there).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_realms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_device: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_lists: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub account_data: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<Value>,
    /// Notification delta (inbox / push). `Value` to round-trip the
    /// spec's events-container shape without committing to a typed
    /// projection here.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub notifications: Value,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

impl SyncResBody {
    /// Realm sync map.
    pub fn effective_realms(&self) -> &BTreeMap<String, Value> {
        &self.realms
    }

    /// Fold a single `ck.self.account.subscribe` data frame into the SDK aggregate
    /// snapshot shape. Control frames without data return `None`.
    pub fn from_account_subscribe_frame(frame: AccountSubscribeFrame) -> Option<Self> {
        if frame.kind != AccountSubscribeFrameKind::Delta {
            return None;
        }
        let cursor = frame.cursor?;
        let mut realms = BTreeMap::new();
        if let Some(frame_realms) = frame.realms {
            realms.extend(frame_realms.entries);
        }

        Some(Self {
            cursor,
            realms,
            left_realms: Vec::new(),
            to_device: frame
                .to_device
                .and_then(|value| value.get("messages").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default(),
            device_lists: frame.device_lists.unwrap_or(Value::Null),
            account_data: frame
                .account_data
                .and_then(|value| value.get("events").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default(),
            presence: frame
                .presence
                .and_then(|value| value.get("events").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default(),
            notifications: frame.notifications.unwrap_or(Value::Null),
            partial: frame.partial.unwrap_or(false),
        })
    }
}

/// One NDJSON frame on `ck.self.account.subscribe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountSubscribeFrameKind {
    Delta,
    CatchupComplete,
    Frontier,
    Heartbeat,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

impl AccountSubscribeFrame {
    /// Parse one NDJSON line. Empty / whitespace-only lines return
    /// `Ok(None)` so callers can chunk-read transparently. Mirrors the
    /// existing `EventsSubscribeFrame::from_ndjson_line` API
    /// (see `crates/sdk/src/sync_client/wire.rs`).
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        Ok(Some(frame))
    }

    /// True iff this frame requires the client to reset its cursor and
    /// re-subscribe (kinds `dropped` / `resync_required`).
    pub fn requires_resubscribe(&self) -> bool {
        matches!(
            self.kind,
            AccountSubscribeFrameKind::Dropped | AccountSubscribeFrameKind::ResyncRequired
        )
    }

    /// Server-advertised lower bound before reconnecting the same
    /// account-subscribe scope.
    pub fn reconnect_after_ms(&self) -> Option<u64> {
        self.reconnect_after_ms
    }

    /// True iff `kind == catchup_complete`.
    pub fn is_catchup_complete(&self) -> bool {
        matches!(self.kind, AccountSubscribeFrameKind::CatchupComplete)
    }
}

#[cfg(test)]
mod account_subscribe_frame_tests {
    use super::*;

    #[test]
    fn account_subscribe_frame_from_ndjson_line_delta() {
        let line = r#"{"kind":"delta","cursor":"sx:acc:1"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Delta);
        assert_eq!(frame.cursor.as_deref(), Some("sx:acc:1"));
        assert!(!frame.requires_resubscribe());
        assert!(!frame.is_catchup_complete());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_catchup_complete() {
        let line = r#"{"kind":"catchup_complete","cursor":"sx:live:0"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert!(frame.is_catchup_complete());
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_frontier() {
        let line = r#"{"kind":"frontier","cursor":"sx:adv:7"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Frontier);
        assert!(!frame.requires_resubscribe());
        assert!(!frame.is_catchup_complete());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_heartbeat() {
        let line = r#"{"kind":"heartbeat"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Heartbeat);
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_dropped_requires_resubscribe() {
        let line = r#"{"kind":"dropped","reason":"buffer overflow","reconnect_after_ms":10000}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reason.as_deref(), Some("buffer overflow"));
        assert_eq!(frame.reconnect_after_ms(), Some(10_000));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_resync_required_requires_resubscribe() {
        let line =
            r#"{"kind":"resync_required","reason":"epoch rotated","reconnect_after_ms":7500}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reconnect_after_ms(), Some(7_500));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_unauthorized() {
        let line = r#"{"kind":"unauthorized","reason":"revoked"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Unauthorized);
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_empty_returns_none() {
        assert!(AccountSubscribeFrame::from_ndjson_line("").unwrap().is_none());
        assert!(AccountSubscribeFrame::from_ndjson_line("   \n  ").unwrap().is_none());
    }

    #[test]
    fn account_subscribe_frame_rejects_non_nfc_string() {
        let line = "{\"kind\":\"dropped\",\"reason\":\"cafe\u{301}\"}";
        assert!(AccountSubscribeFrame::from_ndjson_line(line).is_err());
    }

    #[test]
    fn account_subscribe_frame_rejects_duplicate_key() {
        let line = r#"{"kind":"heartbeat","kind":"heartbeat"}"#;
        assert!(AccountSubscribeFrame::from_ndjson_line(line).is_err());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_unknown_kind_errors() {
        // AccountSubscribeFrameKind is a closed enum: parsing an unknown
        // discriminant returns Err, distinct from the "Unknown" variant
        // tolerance EventsSubscribeFrame has.
        let line = r#"{"kind":"future_kind_42"}"#;
        let err = AccountSubscribeFrame::from_ndjson_line(line).unwrap_err();
        assert!(format!("{err}").contains("future_kind_42"));
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSubscribeRealms {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub entries: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncDescription {
    pub service_did: Did,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncBackfillResBody {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncSnapshotHeadResBody {
    /// Self-field on the snapshot manifest. Spec rename: `snapshot_ref` → `id`
    /// (CKP spec head 37ce729). External references to a snapshot in other
    /// objects keep the `snapshot_ref` name; only the manifest's own self-id
    /// is renamed here.
    pub id: String,
    pub state_digest: Hash,
    pub frontier: String,
    pub signature: Value,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckReqBody {
    pub actor_id: Did,
    pub action: String,
    pub resource: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckResBody {
    pub decision: AuthzDecision,
    #[serde(default)]
    pub matched_grants: Vec<GrantId>,
    #[serde(default)]
    pub applied_constraints: Vec<Value>,
    #[serde(default)]
    pub policy_results: Vec<Value>,
    #[serde(default)]
    pub missing_proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_expires_at: Option<DateTime<Utc>>,
}

pub type Capability = CapabilityGrant;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EffectiveGrantsResBody {
    #[serde(default)]
    pub grants: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<Hash>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzInvitesResBody {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionReqBody {
    pub origin: Did,
    pub destination: Did,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionResBody {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsReqBody {
    pub origin: Did,
    pub destination: Did,
    pub realm_id: RealmId,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsResBody {
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPullOperationsResBody {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationRealmMembersResBody {
    #[serde(default)]
    pub members: Vec<MemberRef>,
    pub membership_frontier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MemberRef {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub membership: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationVerifyActorReqBody {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_payload_digest: Option<Hash>,
    pub signature: Value,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationVerifyActorResBody {
    pub valid: bool,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryResult<T> {
    pub item: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryDescription {
    pub service_did: Did,
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub discovery_profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_query_proof: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchRealmsReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchRealmsResBody {
    #[serde(default)]
    pub results: Vec<RealmPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmPreview {
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

/// Service class that can receive Realm join-side submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateServiceType {
    PrincipalServer,
    SyncNode,
    Anchorer,
}

/// Routing role for a Realm join candidate. This is an ordering and
/// diagnostics hint, not an authorization grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateRole {
    Primary,
    Mirror,
    Anchorer,
    Sync,
    FederationPeer,
    InviteOrigin,
    ReviewerIngress,
}

/// Join-side flow supported by a Realm join candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinMethod {
    InviteAccept,
    MemberJoin,
    Knock,
    Application,
    RestrictedJoin,
}

/// Source from which a Realm join candidate was derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateSource {
    RealmSyncEndpoint,
    DirectoryIngest,
    InviteHint,
    SignedLinkHint,
    FederationRedirect,
    LocalCache,
}

/// `ck.schema.realm_join_candidate.v1`: time-bounded routing hint for
/// submitting Realm join, invite-accept, knock, or restricted-join material.
/// It is distinct from member delivery binding and does not authorize
/// membership by itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmJoinCandidate {
    pub realm_id: RealmId,
    pub service_did: Did,
    pub service_type: RealmJoinCandidateServiceType,
    pub role: RealmJoinCandidateRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub operations: Vec<String>,
    pub join_methods: Vec<RealmJoinMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub source: RealmJoinCandidateSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<String>,
    pub as_of: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveRealmReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveRealmResBody {
    pub realm_preview: RealmPreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stripped_state: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
}

/// R3.3 (CKP-0011, cokret-spec @ cced4b8) — the resolved object class of a
/// shareable address. The address grammar (`crate::model::object_address`)
/// fixes the hierarchy `realm` ⊃ `flow` ⊃ `m` (message).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Realm,
    Flow,
    Message,
}

/// R3.3 (CKP-0011) — request body for `ck.find.directory.resolve_target`.
///
/// `address` is a client-agnostic shareable object address in either the
/// `web+cokret:` URI form or the HTTPS-landing fragment form (see
/// [`crate::model::object_address::parse_address`]). `token` is present iff
/// the address carries `lt=invite` or `lt=preview`; the server MUST bind it to
/// the resolved object via [`crate::model::object_address::verify_token_target`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveTargetReqBody {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// R3.3 (CKP-0011) — response body for `ck.find.directory.resolve_target`.
///
/// Common §9.1 directory fields (`as_of`, `source_refs`, `join_candidates`,
/// `policy_revision`, `stale`, `divergent`) mirror the other directory
/// responses. `object_preview` is a target-kind-dependent opaque preview
/// (a stripped Flow / Message projection); it stays a `serde_json::Value`
/// because its shape varies by `target_kind`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveTargetResBody {
    pub target_kind: TargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_preview: Option<RealmPreview>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_preview: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    pub as_of: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsResBody {
    #[serde(default)]
    pub results: Vec<OrganizationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OrganizationPreview {
    pub organization_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationResBody {
    pub organization_preview: OrganizationPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchActorsReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchActorsResBody {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorPreview {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchUsersReqBody {
    #[serde(alias = "query")]
    pub q: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchUsersResBody {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleReqBody {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    /// Resolution purpose. `lookup` / `mention` return display-safe
    /// identity data; `member_add` / `invite` request a Realm/audience-bound
    /// membership candidate per `identity-handles.md` §3.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// DID or service DID of the requester. Required by directory policy for
    /// `member_add` / `invite` disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    /// Target Realm ID or inviting service DID the result must be bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Target Realm for membership-builder intents. Used by directory
    /// implementations to apply `delivery_binding_policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleResBody {
    #[serde(alias = "subject")]
    pub did: Did,
    pub handle: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim: Option<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub divergent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_services: Vec<String>,
}

/// R3.2 (cokret-spec @ b56cab1) — request body for
/// `ck.find.directory.list_handles_for_subject`. Known holder/principal DID +
/// context → current visible handle claims (inverse of `resolve_handle`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryListHandlesForSubjectReqBody {
    /// Holder/principal DID reverse-lookup key. NOT a Realm actor_id.
    pub subject: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// R3.2 — response body for `ck.find.directory.list_handles_for_subject`.
/// Schema `ck.schema.list_handles_for_subject_response.v1`. Every
/// `claims[].subject` MUST equal [`Self::subject`] (byte-equal); use
/// [`Self::validate`] to enforce.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryListHandlesForSubjectResBody {
    pub subject: Did,
    #[serde(default)]
    pub claims: Vec<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_handle: Option<Handle>,
    pub as_of: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl DirectoryListHandlesForSubjectResBody {
    /// Enforce the schema invariant that every claim's `subject` equals the
    /// top-level `subject`. Mismatching claims MUST be dropped or fail the
    /// response closed; this validator fails closed.
    pub fn validate(&self) -> Result<()> {
        for claim in &self.claims {
            match &claim.subject {
                Some(s) if *s == self.subject => {}
                _ => {
                    return Err(Error::Protocol(
                        "list_handles_for_subject: claims[].subject must equal response.subject"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadResBody {
    pub blob_ref: BlobRef,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub content_digest: Hash,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceReqBody {
    pub device_id: DeviceId,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceResBody {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushUnregisterDeviceReqBody {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OkResBody {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushNotifyReqBody {
    pub notification: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushNotifyResBody {
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckReqBody {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub request_canonical_digest: Hash,
    pub action: String,
    pub actor: Did,
    pub source: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub event_preview: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth_context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckResBody {
    pub decision: AuthzDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
    pub signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigReqBody {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigResBody {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub ice_servers: Vec<Value>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub force_turn: bool,
    pub signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportReqBody {
    pub realm_id: RealmId,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportResBody {
    pub report_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_to: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletPingResBody {
    pub ok: bool,
    pub applet_id: String,
    pub service_did: Did,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletDescription {
    pub applet_id: String,
    pub service_did: Did,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub namespaces: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionReqBody {
    pub source_service_did: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub ephemeral: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionResBody {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletActorResBody {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletRealmResBody {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CursorRevokeScope {
    ThisCursor,
    SameDevice,
    SameSession,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountCursorRevokeReqBody {
    pub cursor: String,
    pub reason_code: String,
    #[serde(default = "default_cursor_revoke_scope")]
    pub revoke_scope: CursorRevokeScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountCursorRevokeResBody {
    pub revoked: bool,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_scope_effective: Option<CursorRevokeScope>,
}

fn default_cursor_revoke_scope() -> CursorRevokeScope {
    CursorRevokeScope::ThisCursor
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletProtocolResBody {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub field_types: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadReqBody {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
    pub device_signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadResBody {
    pub one_time_key_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryReqBody {
    pub device_keys: BTreeMap<Did, Vec<DeviceId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryResBody {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimReqBody {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimResBody {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendReqBody {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, ToDeviceMessage>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ToDeviceMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendResBody {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesReceiveResBody {
    pub events: Vec<ToDeviceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

// ── Spec-aligned canonical types added in 2026-05 alignment pass ───────────
//
// These types fill gaps identified in `_todos.md` between the Rust SDK
// surface and `cokret-spec/spec/v1/zh/` v1-core-rc.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAnnounceReqBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub discovery_state: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub principal_server_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_announce_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAnnounceResBody {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: u64,
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryWithdrawReqBody {
    pub resource_id: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub governance_proof: Value,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryWithdrawResBody {
    pub withdraw_id: String,
    pub acked_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupPath {
    pub backup_id: BackupId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupsListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_class: Option<BackupClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupsListResBody {
    #[serde(default)]
    pub backups: Vec<KeyBackupSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupDeleteReqBody {
    pub backup_id: BackupId,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupDeleteResBody {
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupPutStatus {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupPutResBody {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: BackupClass,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<KeyBackupContentItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackup {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: BackupClass,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_secret_storage: bool,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub encryption: KeyBackupEncryption,
    pub contents: Vec<KeyBackupContentItem>,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<KeyBackupAuthData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<KeyBackupRetention>,
    /// Key-backup hardening (B-C, spec head 37ce729) — series chain identifier.
    /// Every envelope in a backup chain shares the same `series_id`; the chain
    /// is ordered by `series_seq`. Genesis vs successor are distinguished by
    /// `series_seq == 0` (genesis) vs `series_seq > 0` (successor with
    /// `supersedes` + `supersedes_digest` REQUIRED).
    pub series_id: BackupSeriesId,
    /// Key-backup hardening — monotonically increasing chain sequence number.
    /// `0` for the genesis envelope; reducer MUST reject non-monotonic
    /// successors with `series_seq_not_monotonic`.
    pub series_seq: u64,
    /// Key-backup hardening — `backup_id` of the immediate predecessor in
    /// the chain. REQUIRED on every successor (`series_seq >= 1`); MUST be
    /// absent on genesis. Reducer MUST reject mismatches with
    /// `series_chain_broken` or `series_predecessor_not_found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<BackupId>,
    /// Key-backup hardening — content digest of the predecessor's
    /// `ciphertext_digest` mixed into the signing transcript on successor
    /// envelopes. REQUIRED whenever `supersedes` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_digest: Option<String>,
    /// Key-backup hardening — opaque reference to the originating-key
    /// frontier the backup encrypts (e.g. recovery key frontier, MLS group
    /// epoch frontier). Reducer rejects stale frontiers with
    /// `backup_frontier_stale`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl KeyBackup {
    pub fn summary(&self) -> KeyBackupSummary {
        KeyBackupSummary {
            backup_id: self.backup_id.clone(),
            actor_id: self.actor_id.clone(),
            device_id: self.device_id.clone(),
            backup_class: self.backup_class,
            backup_version: self.backup_version.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            ciphertext_digest: self.ciphertext_digest.clone(),
            contents: self.contents.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupRecipientMethod {
    PassphraseKdf,
    RecoveryPublicKey,
    SecretStorageKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KeyBackupKdf>,
    pub aead: KeyBackupAead,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "KeyBackupKdfWire")]
pub struct KeyBackupKdf {
    pub name: String,
    pub salt: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_profile_reason: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct KeyBackupKdfWire {
    name: String,
    salt: String,
    #[serde(default)]
    params: Value,
    degraded_profile_reason: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, Value>,
}

impl TryFrom<KeyBackupKdfWire> for KeyBackupKdf {
    type Error = String;

    fn try_from(wire: KeyBackupKdfWire) -> std::result::Result<Self, Self::Error> {
        if wire.params.as_object().is_some_and(|params| {
            params.keys().any(|key| {
                crate::is_forbidden_in_context(key, crate::WireContext::KeyBackupKdfParams)
            })
        }) {
            return Err("KeyBackupKdf.params contains forbidden wire field".to_owned());
        }
        Ok(Self {
            name: wire.name,
            salt: wire.salt,
            params: wire.params,
            degraded_profile_reason: wire.degraded_profile_reason,
            extra: wire.extra,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupAead {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupContentItem {
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupAuthData {
    pub device_id: DeviceId,
    pub verification_method: String,
    pub signature_algorithm: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
    pub signed_fields: Vec<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupRetention {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Key-backup hardening (B-C, spec head 37ce729) — minimal Rust shape for
/// `ck.schema.recovery_policy.v1`. Carries the policy lifecycle plus the
/// commitment / KDF profile branches.
///
/// The fields below mirror the spec's `policy_id` / `lifecycle` / `body`
/// shape but leave `body` as a free-form `Value` for now: the full
/// commitment-branch shape (passphrase commitment, threshold params, AEAD
/// profile, etc.) lands in a follow-up.
///
// TODO(P1): expand `body` into a tagged enum (passphrase | recovery_key |
// threshold | hardware_wrapped) matching the spec's `oneOf` branches.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryPolicy {
    /// Schema id (`ck.schema.recovery_policy.v1`).
    pub schema: String,
    pub policy_id: String,
    pub lifecycle: RecoveryPolicyLifecycle,
    pub epoch: u64,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub body: Value,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Key-backup hardening — three-state lifecycle for recovery policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicyLifecycle {
    Pending,
    Active,
    Retired,
}

/// CKP recovery policy proof-kind enum (R3 spec-sync 2026-05-27,
/// cokret-spec b47ff6ec). Mirrors `recovery-policy.schema.json`
/// `body.proof_kinds[]`. Validation of the proof internals is
/// deferred to R3.1 (verifier implementation).
//
// TODO(R3.1): internal proof verification (cross-signing reset proof
// equivalents, threshold device quorum, OIDC trusted recovery service,
// principal-signing) — wire-level shape only at this round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProofKind {
    /// Device-quorum signed reset (threshold of trusted devices).
    DeviceQuorum,
    /// Recovery passphrase / hardware-wrapped unlock evidence.
    RecoveryUnlock,
    /// External trusted recovery service (e.g. OIDC, custodian).
    TrustedRecoveryService,
    /// Principal-key direct signature (sovereign deployments).
    PrincipalSigning,
}

impl RecoveryProofKind {
    /// All variants in registry order. Helpful for schema-driven
    /// validators.
    pub const ALL: &'static [Self] = &[
        Self::DeviceQuorum,
        Self::RecoveryUnlock,
        Self::TrustedRecoveryService,
        Self::PrincipalSigning,
    ];

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::DeviceQuorum => "device_quorum",
            Self::RecoveryUnlock => "recovery_unlock",
            Self::TrustedRecoveryService => "trusted_recovery_service",
            Self::PrincipalSigning => "principal_signing",
        }
    }
}

/// Key-backup hardening (B-C, spec head 37ce729) — minimal Rust shape for
/// `ck.schema.recovery_receipt.v1`. Captures verification evidence + a
/// proof that binds the receipt to a specific recovery session.
///
// TODO(P1): expand `evidence` into a tagged enum matching the spec's
// recovery-attestation oneOf (self-asserted | hardware-attested | quorum).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryReceipt {
    /// Schema id (`ck.schema.recovery_receipt.v1`).
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: String,
    pub policy_epoch: u64,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub evidence: Value,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub bound_proof: Value,
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

// ─── S-2 (savfox SDK gap): DID-proof session grant flow ────────────────────
//
// Wire shapes for `POST /_cokret/gate/account/session-grants` per spec
// `identity-did.md` §5.1. Step 1 returns a `SessionGrantChallenge`; step 2
// submits a signed `ck.did.proof` (envelope inside `SessionGrantSubmitReq`).

/// Step 1 request: client asks for a challenge bound to a `(principal_id,
/// device_id, audience)` tuple. Spec `identity-did.md` §5.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantChallengeReq {
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// DID of the Principal Server / service the grant is for. Bound
    /// into the `ck.did.proof` audience.
    pub audience: String,
    /// Optional origin hint (per spec §5.1 the proof carries `origin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// Step 1 response: server-issued challenge for `ck.did.proof`.
///
/// `purpose` is always `ck.session.grant` (only purpose the SDK helper
/// drives today). `expires_at` bounds the challenge's freshness window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantChallenge {
    pub challenge_id: String,
    pub purpose: String,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

impl SessionGrantChallenge {
    pub const PURPOSE_SESSION_GRANT: &'static str = "ck.session.grant";

    /// True iff `purpose == ck.session.grant`. Receivers MUST refuse
    /// any other purpose for the session-grant exchange.
    pub fn is_session_grant_purpose(&self) -> bool {
        self.purpose == Self::PURPOSE_SESSION_GRANT
    }
}

/// Step 2 request: client submits the signed `ck.did.proof` body.
///
/// The proof payload (`SessionGrantDidProof`) is what the controller
/// actually signed; `proof` is the detached-JWS `Proof` envelope
/// produced by the SDK signer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantSubmitReq {
    pub challenge_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub proof_payload: SessionGrantDidProof,
    pub proof: Proof,
}

/// Canonical body of the `ck.did.proof` payload spec
/// `identity-did.md` §5.1. The signer commits to this object; the
/// receiver re-derives canonical bytes and verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantDidProof {
    pub kind: String,
    pub purpose: String,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub challenge: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub expires_at: DateTime<Utc>,
}

impl SessionGrantDidProof {
    pub const KIND: &'static str = "ck.did.proof";

    /// Build the canonical proof payload for a given challenge. Stamps
    /// `kind=ck.did.proof` so callers don't have to.
    pub fn from_challenge(
        challenge: &SessionGrantChallenge,
        principal_id: Did,
        device_id: DeviceId,
    ) -> Self {
        Self {
            kind: Self::KIND.to_owned(),
            purpose: challenge.purpose.clone(),
            audience: challenge.audience.clone(),
            origin: challenge.origin.clone(),
            challenge: challenge.challenge.clone(),
            principal_id,
            device_id,
            expires_at: challenge.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_surface_entry_serializes_schema_shape() {
        let surface = CompatSurfaceEntry::external_interop("soland_private_local_routes")
            .with_notes("local compatibility surface")
            .with_extra_string("base_path", "/_soland")
            .with_extra_string("status", "soland_private_local");

        let value = serde_json::to_value(surface).unwrap();

        assert_eq!(value["name"], "soland_private_local_routes");
        assert_eq!(value["kind"], "external_interop");
        assert_eq!(value["notes"], "local compatibility surface");
        assert_eq!(value["base_path"], "/_soland");
        assert_eq!(value["status"], "soland_private_local");
    }

    #[test]
    fn compat_surface_kind_rejects_removed_wire_values() {
        for value in ["legacy_alias", "deprecated_alias"] {
            let parsed: std::result::Result<CompatSurfaceKind, _> =
                serde_json::from_value(serde_json::json!(value));
            assert!(parsed.is_err(), "{value} is not a v1 compat_surface kind");
        }
    }

    #[test]
    fn key_backup_recipient_method_rejects_removed_wire_values() {
        for value in ["device_snapshot_secret", "threshold_recovery", "hardware_wrapped_key"] {
            let parsed: std::result::Result<KeyBackupRecipientMethod, _> =
                serde_json::from_value(serde_json::json!(value));
            assert!(parsed.is_err(), "{value} must not be a key-backup recipient_method");
        }
    }
}
