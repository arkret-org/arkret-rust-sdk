use super::*;
use crate::http::SessionGrantProofKind;

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
    pub auth_metadata: AuthMetadata,
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

/// Strongly-typed `auth_metadata` block of the service-describe response.
/// Mirrors `service-describe.schema.json#/properties/auth_metadata`. Every
/// field other than `mode` is optional or defaulted so older / sparser wire
/// payloads still deserialize; the `extra` flatten captures `x_*` and any
/// future unknown keys (`additionalProperties: true`) without data loss.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthMetadata {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_authority: Option<AccountAuthority>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_server_url: Option<String>,
    /// Compatibility alias for legacy clients (`methods[].issuer`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_issuer: Option<String>,
    /// Compatibility alias for legacy clients (`methods[].openid_configuration`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid_configuration: Option<String>,
    /// Compatibility alias for legacy clients (`methods[].method`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_auth_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_binding_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    /// Captures `x_*` and any other `additionalProperties: true` keys so the
    /// SDK round-trips future / vendor-specific fields without dropping them.
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AuthMetadata {
    /// Convenience constructor for tests / mocks: fills `mode` and leaves
    /// every other field empty / `None`.
    pub fn minimal(mode: impl Into<String>) -> Self {
        Self {
            mode: mode.into(),
            account_authority: None,
            methods: Vec::new(),
            auth_server_url: None,
            oauth_issuer: None,
            openid_configuration: None,
            supported_auth_methods: Vec::new(),
            did_binding_methods: Vec::new(),
            read: None,
            extra: std::collections::BTreeMap::new(),
        }
    }
}

/// Mirrors `service-describe.schema.json#/$defs/account_authority`. Carries
/// the client-visible Account Authority origin and the gate/account base URL
/// from which all `/_cokret/gate/account/*` endpoints are derived.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountAuthority {
    pub origin: String,
    pub gate_account_base: String,
}

/// Mirrors `service-describe.schema.json#/$defs/auth_method`. Describes a
/// single proof provider, its discovery metadata and the proof kind accepted
/// by the Account Authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthMethod {
    pub method: AuthMethodKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid_configuration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub grant_exchange: AuthGrantExchange,
}

/// `method` discriminant for [`AuthMethod`]. Mirrors the closed enum in
/// `service-describe.schema.json#/$defs/auth_method/properties/method`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuthMethodKind {
    Oidc,
    Passkey,
    DevicePairing,
    RecoveryChallenge,
    Gnap,
}

/// Mirrors `service-describe.schema.json#/$defs/auth_grant_exchange`. The
/// `proof_kind` reuses the authoritative [`SessionGrantProofKind`] enum so
/// the describe surface and the session-grant request surface stay in lockstep.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthGrantExchange {
    pub proof_kind: SessionGrantProofKind,
}

pub type ActorDid = Did;
pub type ServiceDid = Did;
pub type AccountId = String;
pub type ServiceDescribe = ServerDescription;
pub type EventSubmitEnvelope = Event;
pub type FacetName = Facet;
pub type ObjectRef = String;
pub type BooleanFilter = Filter;
pub type QueryFilter = Filter;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BottomDiagnosticSealView {
    pub leaves: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BottomDiagnostic {
    pub kind: BottomKind,
    pub cells: Vec<CellRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_view: Option<BottomDiagnosticSealView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum AppletInstallAppletId {
    Did(Did),
    AppletId(AppletId),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPlan {
    pub schema: String,
    pub plan_id: String,
    pub applet_id: AppletInstallAppletId,
    pub package_digest: Hash,
    pub registration_epoch: Hash,
    pub effective_scope: EffectiveScope,
    pub requested_scopes: Vec<String>,
    pub approved_scopes: Vec<ScopeGrant>,
    pub denied_scopes: Vec<DeniedScope>,
    pub events_to_submit: Vec<EventSubmission>,
    pub capability_constraints: Vec<CapabilityConstraint>,
    pub namespace_conflicts: Vec<NamespaceConflict>,
    pub e2ee_effect: E2eeEffect,
    pub widget_effect: WidgetEffect,
    pub warnings: Vec<String>,
    pub plan_digest: Hash,
}

impl AppletInstallPlan {
    pub const SCHEMA: &'static str = "ck.schema.applet_install_plan.v1";
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
/// requires a verification run id, artifact hash, artifact reference,
/// verifier DID, issuer signature, and timestamp so consumers can pin the
/// claim to an auditable run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct VerifiedProfileEntry {
    pub profile_id: String,
    pub claim_kind: ConformanceVerifiedKind,
    pub verification_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub verifier_did: Did,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `claim_kind` discriminant for [`VerifiedProfileEntry`]. Conformance
/// Verifier neutralization (2026-06-10) renamed `cotest_verified` →
/// `conformance_verified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConformanceVerifiedKind {
    ConformanceVerified,
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
        Self {
            name: name.into(),
            kind,
            since: None,
            notes: None,
            extra: BTreeMap::new(),
        }
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
