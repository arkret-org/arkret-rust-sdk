use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use arkret_wire::{Did, DidCoreId, ProfileId, SchemaId, *};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKind {
    Realm,
}

impl DirectoryResourceKind {
    pub const ALL: [Self; 1] = [Self::Realm];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Realm => "realm",
        }
    }
}

impl FromStr for DirectoryResourceKind {
    type Err = DirectoryResourceKindParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or(DirectoryResourceKindParseError)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryResourceKindParseError;

impl fmt::Display for DirectoryResourceKindParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown directory resource_kind value")
    }
}

impl std::error::Error for DirectoryResourceKindParseError {}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerLimits {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extensions: BTreeMap<String, Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushTargetDerivationProfile {
    #[serde(rename = "ak.push_target_id.hmac_sha256.v1")]
    HmacSha256V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTargetSecretScope {
    PerService,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTargetInputBinding {
    AccountId,
    DeviceId,
    PushRouteId,
    SaltEpochId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushTargetPrivacyDerivation {
    pub derivation_profile: PushTargetDerivationProfile,
    pub secret_scope: PushTargetSecretScope,
    pub salt_epoch_id: String,
    pub salt_rotation_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_binding: Option<Vec<PushTargetInputBinding>>,
}

impl PushTargetPrivacyDerivation {
    pub fn validate(&self) -> Result<()> {
        if self.salt_epoch_id.is_empty()
            || self.salt_epoch_id.chars().count() > 128
            || !(3_600..=2_592_000).contains(&self.salt_rotation_seconds)
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: invalid push_target privacy derivation ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyDerivation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id_derivation: Option<PushTargetPrivacyDerivation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TusVersion {
    #[serde(rename = "1.0.0")]
    V1_0_0,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TusExtension {
    Creation,
    CreationWithUpload,
    Checksum,
    Expiration,
    Termination,
}

/// Closed transport endpoint union. Operation membership is intentionally
/// absent and comes only from registered operation bundles.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportBinding {
    HttpJson {
        base_url: String,
        extension_profile_required: (),
    },
    Tus {
        base_url: String,
        extension_profile_required: (),
        tus_version: Vec<TusVersion>,
        tus_extensions: Vec<TusExtension>,
    },
    /// `kind = websocket` fixes the binding profile, the `arkret.v1`
    /// subprotocol and `challenge_dpop_session_v1` authentication through the
    /// binding-kind registry and the profile itself, so the descriptor carries
    /// only the connection coordinates and transport limits.
    Websocket {
        base_url: String,
        max_frame_bytes: u32,
        max_channels: u32,
    },
}

impl TransportBinding {
    pub fn http_json(base_url: impl Into<String>) -> Self {
        Self::HttpJson {
            base_url: base_url.into(),
            extension_profile_required: (),
        }
    }

    pub fn tus(base_url: impl Into<String>, tus_extensions: Vec<TusExtension>) -> Self {
        Self::Tus {
            base_url: base_url.into(),
            extension_profile_required: (),
            tus_version: vec![TusVersion::V1_0_0],
            tus_extensions,
        }
    }

    pub fn websocket(base_url: impl Into<String>, max_frame_bytes: u32, max_channels: u32) -> Self {
        Self::Websocket {
            base_url: base_url.into(),
            max_frame_bytes,
            max_channels,
        }
    }

    pub const fn kind(&self) -> BindingKind {
        match self {
            Self::HttpJson { .. } => BindingKind::HttpJson,
            Self::Tus { .. } => BindingKind::Tus,
            Self::Websocket { .. } => BindingKind::Websocket,
        }
    }

    pub fn base_url(&self) -> &str {
        match self {
            Self::HttpJson { base_url, .. }
            | Self::Tus { base_url, .. }
            | Self::Websocket { base_url, .. } => base_url,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let parsed = url::Url::parse(self.base_url())
            .map_err(|error| WireError::Protocol(format!("invalid transport base_url: {error}")))?;
        if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
            return Err(WireError::Protocol(
                "transport base_url must be an absolute hierarchical URI".to_owned(),
            ));
        }
        match self {
            Self::HttpJson { .. } => Ok(()),
            Self::Tus {
                tus_version,
                tus_extensions,
                ..
            } => {
                if tus_version != &[TusVersion::V1_0_0]
                    || tus_extensions.is_empty()
                    || tus_extensions
                        .iter()
                        .enumerate()
                        .any(|(index, item)| tus_extensions[..index].contains(item))
                {
                    return Err(WireError::Protocol(
                        "tus transport requires version 1.0.0 and unique non-empty extensions"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            Self::Websocket { .. } => crate::websocket_binding::validate_websocket_transport(self),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteIntroductionKind {
    LocatorRef,
    ConsentGrant,
    SharedRealm,
    HandleClaim,
    SameStation,
    ExplicitAddress,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteMaxBehavior {
    Drop,
    Quarantine,
    Notify,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteAddressing {
    pub supported_introduction_kinds: Vec<InviteIntroductionKind>,
    pub handle_claim_max_behavior: InviteMaxBehavior,
    pub explicit_address_max_behavior: InviteMaxBehavior,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ServiceProtocolVersion {
    #[serde(rename = "1.0")]
    V1,
}

impl ServiceProtocolVersion {
    pub const fn as_str(self) -> &'static str {
        PROTOCOL_VERSION
    }
}

impl fmt::Display for ServiceProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ServiceProtocolVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // The bootstrap classification is normative and shared: a *non-canonical
        // literal* (`"1.0.0"`, `"01.0"`) is `schema_violation` because the object
        // is corrupt, while a well-formed value that simply is not `"1.0"` is
        // `unsupported_protocol_version` because the peer generation is
        // unsupported and its response is not a damaged v1 object
        // (`evolution-and-compatibility.md` section 4, conformance `ak-sdk-024`).
        // `arkret_wire` owns that split so a second carrier cannot re-derive it.
        let value = String::deserialize(deserializer)?;
        match protocol_version_bootstrap_error(&value) {
            None => Ok(Self::V1),
            Some(code) => Err(serde::de::Error::custom(format!(
                "{}: protocol_version {value} does not match Arkret {PROTOCOL_VERSION}",
                code.as_str()
            ))),
        }
    }
}

/// Canonical service description defined by `service-describe.schema.json`.
/// Receivers reject responses missing required fields with `schema_violation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceDescribe {
    pub service_id: DidCoreId,
    pub service_resolution: arkret_models_identity::ResolutionCommitment,
    /// Required trust domain. Receivers MUST refuse to
    /// register a peer whose `trust_domain` disagrees with the
    /// expected deployment scope.
    pub trust_domain: TrustDomainId,
    pub service_kind: ServiceKind,
    pub protocol_version: ServiceProtocolVersion,
    /// Profiles the service
    /// declares conformance to. Empty array is valid; missing is not.
    pub supported_profiles: Vec<String>,
    /// Profile-specific carrier declarations keyed by profile id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_bindings: BTreeMap<String, ProfileBinding>,
    /// Canonical-sorted registered bundles fully implemented by this role
    /// endpoint. Unknown or partial bundles are rejected.
    pub supported_operation_bundles: Vec<String>,
    /// Transport endpoints in descending server preference.
    pub transport_bindings: Vec<TransportBinding>,
    pub supported_features: Vec<String>,
    /// Exact IANA TZDB releases this service can execute for Calendar
    /// schedules. Required whenever a Calendar profile is claimed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calendar_tzdb_versions: Vec<String>,
    pub auth_metadata: AuthMetadata,
    pub limits: ServerLimits,
    /// Plaintext visibility advertisement. Receivers MUST
    /// treat a missing value as `untrusted` (fail-closed for the
    /// mention-redirect / late-recovery paths). Wire shape per
    /// `service-describe.schema.json#plaintext_visibility`.
    pub plaintext_visibility: PlaintextVisibility,
    /// Machine-readable privacy-preserving identifier derivation claims.
    /// Secret material is never published here; producers expose only the
    /// public derivation profile and epoch metadata needed by clients and
    /// conformance tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_derivation: Option<PrivacyDerivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub receive_policy_constraints: Option<ReceivePolicyConstraints>,
    /// Profiles a third party has verified the service
    /// against. MUST be empty when `development_mode == true`. Wire
    /// shape per
    /// `service-describe.schema.json#/properties/verified_profiles`.
    pub verified_profiles: Vec<VerifiedProfileEntry>,
    /// External-interop surfaces this service
    /// exposes outside its claimed v1 conformance (e.g. MIMI/Matrix
    /// passthrough). Wire shape per
    /// `service-describe.schema.json#/properties/interop_surfaces`.
    pub interop_surfaces: Vec<InteropSurfaceEntry>,
    /// Registered invite-addressing negotiation. Required exactly when the
    /// corresponding feature is advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_addressing: Option<InviteAddressing>,
    /// When `true` the service is in development
    /// mode; receivers MUST refuse to advertise `verified_profiles`
    /// and SHOULD warn on connection.
    pub development_mode: bool,
    /// Inline rate-limit policy. The describe schema requires either
    /// `rate_limit_policy` or `rate_limit_policy_id`; producers MUST set
    /// one of the two. Wire shape per
    /// `service-describe.schema.json#/properties/rate_limit_policy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_policy: Option<RateLimitPolicy>,
    /// Identifier for a cacheable, verifiable rate-limit policy object
    /// (alternative to inlining [`Self::rate_limit_policy`]). Wire shape
    /// per `service-describe.schema.json#/properties/rate_limit_policy_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_policy_id: Option<String>,
    /// R3.4 — coarse outbound network policy for SSRF-sensitive service
    /// calls such as DID resolution, federation, media fetch, snapshots,
    /// webhooks, applets, agents, directory and push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_network_policy: Option<EgressNetworkPolicy>,
    /// Directory-service overlay: resource classes indexed by
    /// `ak.find.directory.read.describe.v1`. Required when
    /// `service_kind == "directory_service"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_kinds: Vec<DirectoryResourceKind>,
    /// Vendor extensions permitted by the service-describe schema. Keys must
    /// use the reserved `x_<vendor>_*` namespace and are serialized at the
    /// top level.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extensions: XExtensionMap,
}

impl ServiceDescribe {
    /// Confirm the exact route after independent DID-method verification.
    pub fn validate_route_projection(
        &self,
        route: &arkret_models_identity::ServiceResolutionProjection,
    ) -> Result<()> {
        self.validate()?;
        if self.protocol_version.as_str() != PROTOCOL_VERSION
            || self.service_id != route.service_id
            || self.service_kind.as_str() != route.service_kind
            || self.service_resolution.did != route.did
            || self.service_resolution.method_history_head != route.method_history_head
            || self.service_resolution.version_id != route.version_id
        {
            return Err(WireError::Protocol(
                "ServiceDescribe differs from the verified DID state".to_owned(),
            ));
        }
        let bases: Vec<_> = self
            .transport_bindings
            .iter()
            .filter_map(|binding| match binding {
                TransportBinding::HttpJson { base_url, .. } => Some(base_url.as_str()),
                _ => None,
            })
            .collect();
        if bases != [route.base_url.as_str()] {
            return Err(WireError::Protocol(
                "ServiceDescribe must confirm exactly one verified HTTP endpoint".to_owned(),
            ));
        }
        Ok(())
    }

    pub const SCHEMA: &'static str = SchemaId::SERVICE_DESCRIBE_V1;

    /// Build a complete development-mode description for a service surface.
    pub fn development(
        did: Did,
        trust_domain: TrustDomainId,
        service_kind: ServiceKind,
        supported_operation_bundles: Vec<String>,
        transport_bindings: Vec<TransportBinding>,
    ) -> Self {
        let service_id = project_did_to_core_id(&did)
            .expect("development service full id must use a registered adapter");
        Self {
            service_id,
            service_resolution: arkret_models_identity::ResolutionCommitment {
                did,
                method_history_head: "development-unverified".to_owned(),
                version_id: "development-unverified".to_owned(),
            },
            trust_domain,
            service_kind,
            protocol_version: ServiceProtocolVersion::V1,
            supported_profiles: Vec::new(),
            profile_bindings: BTreeMap::new(),
            supported_operation_bundles,
            transport_bindings,
            supported_features: Vec::new(),
            calendar_tzdb_versions: Vec::new(),
            auth_metadata: AuthMetadata::minimal(),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            verified_profiles: Vec::new(),
            interop_surfaces: Vec::new(),
            invite_addressing: None,
            development_mode: true,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: None,
            resource_kinds: Vec::new(),
            extensions: XExtensionMap::default(),
        }
    }

    /// Validate the cross-field invariants:
    /// - `verified_profiles` MUST be empty when `development_mode = true`.
    /// - the describe `anyOf` requires `rate_limit_policy` or `rate_limit_policy_id`.
    pub fn validate(&self) -> Result<()> {
        debug_assert_eq!(self.protocol_version, ServiceProtocolVersion::V1);
        if project_did_to_core_id(&self.service_resolution.did)? != self.service_id
            || self.service_resolution.method_history_head.is_empty()
            || self.service_resolution.version_id.is_empty()
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: service_resolution does not project to service_id ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if !self.service_kind.valid_in("service_describe") {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: service_kind={} is not valid in service_describe ({})",
                self.service_kind.as_str(),
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.supported_operation_bundles.is_empty()
            || self
                .supported_operation_bundles
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: supported_operation_bundles must be non-empty, unique and canonical-sorted ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        let describe_bundle_id = role_describe_bundle_descriptor(self.service_kind)
            .map(|bundle| bundle.operation_bundle_id)
            .ok_or_else(|| {
                WireError::Protocol(format!(
                    "ServiceDescribe: service kind {} has no registered describe bundle ({})",
                    self.service_kind,
                    ErrorCode::SCHEMA_VIOLATION
                ))
            })?;
        if !self
            .supported_operation_bundles
            .iter()
            .any(|bundle_id| bundle_id == describe_bundle_id)
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: missing mandatory role describe bundle {describe_bundle_id} ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        let mut operation_pairs = BTreeSet::new();
        for bundle_id in &self.supported_operation_bundles {
            let bundle = operation_bundle_descriptor(bundle_id).ok_or_else(|| {
                WireError::Protocol(format!(
                    "ServiceDescribe: unknown operation bundle {bundle_id} ({})",
                    ErrorCode::SCHEMA_VIOLATION
                ))
            })?;
            if bundle.service_kind != self.service_kind {
                return Err(WireError::Protocol(format!(
                    "ServiceDescribe: bundle {bundle_id} belongs to {}, not {} ({})",
                    bundle.service_kind,
                    self.service_kind,
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
            operation_pairs.extend(bundle.members.iter().copied());
        }
        let transport_kinds = self
            .transport_bindings
            .iter()
            .map(TransportBinding::kind)
            .collect::<BTreeSet<_>>();
        if self
            .transport_bindings
            .iter()
            .enumerate()
            .any(|(index, transport)| {
                transport.validate().is_err()
                    || self.transport_bindings[..index].contains(transport)
            })
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: transport_bindings contain an invalid or duplicate entry ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if operation_pairs
            .iter()
            .any(|pair| !transport_kinds.contains(&pair.binding_kind))
            || transport_kinds.iter().any(|kind| {
                !operation_pairs
                    .iter()
                    .any(|pair| pair.binding_kind == *kind)
            })
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: transport_bindings must exactly cover bundle binding kinds ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self
            .supported_features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: supported_features must be unique and canonical-sorted ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        for feature_id in &self.supported_features {
            let feature = feature_descriptor(feature_id).ok_or_else(|| {
                WireError::Protocol(format!(
                    "ServiceDescribe: unknown feature {feature_id} ({})",
                    ErrorCode::SCHEMA_VIOLATION
                ))
            })?;
            if feature.status == FeatureStatus::TestOnly
                || (!feature.service_kinds.is_empty()
                    && !feature.service_kinds.contains(&self.service_kind))
                || feature
                    .required_operation_pairs
                    .iter()
                    .any(|pair| !operation_pairs.contains(pair))
                || feature.required_profiles.iter().any(|profile| {
                    !self
                        .supported_profiles
                        .iter()
                        .any(|actual| actual == profile)
                })
                || feature
                    .required_limits
                    .iter()
                    .any(|limit| !self.limits.extensions.contains_key(*limit))
                || feature
                    .conflicts
                    .iter()
                    .any(|conflict| self.supported_features.iter().any(|id| id == conflict))
            {
                return Err(WireError::Protocol(format!(
                    "ServiceDescribe: feature {feature_id} prerequisites are not satisfied ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
        }
        let advertises_invite_addressing = self
            .supported_features
            .iter()
            .any(|feature| feature == "ak.feature.invite_addressing.v1");
        if advertises_invite_addressing != self.invite_addressing.is_some() {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: invite_addressing and ak.feature.invite_addressing.v1 must appear together ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if let Some(push_target) = self
            .privacy_derivation
            .as_ref()
            .and_then(|derivation| derivation.push_target_id_derivation.as_ref())
        {
            push_target.validate()?;
        }
        if self.development_mode && !self.verified_profiles.is_empty() {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: development_mode=true forbids non-empty verified_profiles \
                 ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        let claims_calendar = self.supported_profiles.iter().any(|profile| {
            matches!(
                profile.as_str(),
                ProfileId::CALENDAR_EVENT_V1 | ProfileId::CALENDAR_NOTIFICATION_DISPATCH_V1
            )
        });
        let valid_tzdb_version = |version: &str| {
            let bytes = version.as_bytes();
            bytes.len() == 5
                && bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4].is_ascii_lowercase()
        };
        let unique_tzdb_versions = self
            .calendar_tzdb_versions
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == self.calendar_tzdb_versions.len();
        if (claims_calendar && self.calendar_tzdb_versions.is_empty())
            || !unique_tzdb_versions
            || self
                .calendar_tzdb_versions
                .iter()
                .any(|version| !valid_tzdb_version(version))
        {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: Calendar profile claims require a non-empty, unique \
                 calendar_tzdb_versions release set ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.profile_bindings.iter().any(|(profile, binding)| {
            binding.carrier.is_empty()
                || !self
                    .supported_profiles
                    .iter()
                    .any(|supported| supported == profile)
        }) {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: profile_bindings must reference supported_profiles and \
                 carry a non-empty carrier ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.rate_limit_policy.is_none() && self.rate_limit_policy_id.is_none() {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: one of rate_limit_policy or rate_limit_policy_id is required \
                 ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.extensions.keys().any(|key| {
            let mut suffix = key.strip_prefix("x_").map(str::bytes).into_iter().flatten();
            !suffix.next().is_some_and(|byte| byte.is_ascii_lowercase())
                || !suffix
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }) {
            return Err(WireError::Protocol(format!(
                "ServiceDescribe: extension keys must match ^x_[a-z][a-z0-9_]*$ ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.service_kind == ServiceKind::DirectoryService {
            if self.resource_kinds.as_slice() != [DirectoryResourceKind::Realm] {
                return Err(WireError::Protocol(format!(
                    "ServiceDescribe: service_kind=directory_service indexes only public Realm metadata ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
        }
        Ok(())
    }

    /// Whether any advertised bundle contains this operation.
    pub fn supports_operation(&self, operation_id: ServiceOperationId) -> bool {
        self.supported_operation_bundles
            .iter()
            .filter_map(|id| operation_bundle_descriptor(id))
            .flat_map(|bundle| bundle.members)
            .any(|pair| pair.operation_id == operation_id)
    }

    pub fn supports_operation_binding(
        &self,
        operation_id: ServiceOperationId,
        binding_kind: BindingKind,
    ) -> bool {
        self.supported_operation_bundles
            .iter()
            .filter_map(|id| operation_bundle_descriptor(id))
            .flat_map(|bundle| bundle.members)
            .any(|pair| pair.operation_id == operation_id && pair.binding_kind == binding_kind)
    }

    /// Select the first server-preferred transport which both the exact
    /// operation bundle and the caller support.
    pub fn select_transport_binding<'a>(
        &'a self,
        operation_id: ServiceOperationId,
        locally_supported: &[BindingKind],
    ) -> Option<&'a TransportBinding> {
        self.transport_bindings.iter().find(|transport| {
            let kind = transport.kind();
            locally_supported.contains(&kind) && self.supports_operation_binding(operation_id, kind)
        })
    }
}

/// Profile-specific interoperable carrier binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProfileBinding {
    pub carrier: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;

    use super::*;

    fn station_description() -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.http_core.v1".to_owned(),
            ],
            vec![TransportBinding::HttpJson {
                base_url: "https://service.example".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    fn station_account_authority_description() -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:webvh:z6mkfixture:auth.example").unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.account_authority_support.v1".to_owned(),
                "ak.operation_bundle.station.http_core.v1".to_owned(),
            ],
            vec![TransportBinding::HttpJson {
                base_url: "https://auth.example".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn directory_resource_kind_tokens_are_closed_and_round_trip() {
        let tokens = ["realm"];
        assert_eq!(
            DirectoryResourceKind::ALL.map(DirectoryResourceKind::as_str),
            tokens
        );
        for (value, token) in DirectoryResourceKind::ALL.into_iter().zip(tokens) {
            assert_eq!(DirectoryResourceKind::from_str(token), Ok(value));
            assert_eq!(serde_json::to_value(value).unwrap(), token);
        }
        assert!(DirectoryResourceKind::from_str("actor").is_err());
    }

    #[test]
    fn removed_flat_operation_field_is_rejected_during_decode() {
        let description = station_description();
        let mut wire = serde_json::to_value(description).unwrap();
        wire.as_object_mut().unwrap().insert(
            "supported_operations".to_owned(),
            json!([ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1]),
        );

        assert!(serde_json::from_value::<ServiceDescribe>(wire).is_err());
    }

    #[test]
    fn bundle_driven_transport_selection_is_exact() {
        let description = station_description();
        assert!(
            description
                .select_transport_binding(
                    ServiceOperationId::SelfCommittedEventReadScanV1,
                    &[BindingKind::HttpJson],
                )
                .is_some()
        );
        assert!(
            description
                .select_transport_binding(
                    ServiceOperationId::SelfCommittedEventReadScanV1,
                    &[BindingKind::Websocket],
                )
                .is_none()
        );
    }

    #[test]
    fn station_http_core_bundle_expands_service_resolution_capability() {
        let description = station_account_authority_description();

        assert!(description.supports_operation_binding(
            ServiceOperationId::OpenServiceReadResolutionV1,
            BindingKind::HttpJson,
        ));
        assert!(
            description
                .select_transport_binding(
                    ServiceOperationId::OpenServiceReadResolutionV1,
                    &[BindingKind::HttpJson],
                )
                .is_some()
        );
    }

    #[test]
    fn auth_grant_exchange_is_the_closed_account_handoff_shape() {
        let exchange: AuthGrantExchange =
            serde_json::from_value(json!({"kind": "account_handoff"})).unwrap();
        assert_eq!(exchange.kind, AuthGrantExchangeKind::AccountHandoff);
        assert!(exchange.extra.is_empty());
        assert!(
            serde_json::from_value::<AuthGrantExchange>(
                json!({"kind": "account_handoff", "x_vendor": true})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<AuthGrantExchange>(
                json!({"kind": "account_handoff", "mode": "vendor"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<AuthGrantExchange>(
                json!({"proof_kind": "oidc_code_exchange"})
            )
            .is_err()
        );
    }

    #[test]
    fn auth_metadata_subtree_accepts_only_protocol_inert_extensions() {
        let value = json!({
            "account_authority": {
                "origin": "https://auth.example",
                "gate_account_base_url": "https://auth.example/_arkret/gate/account",
                "x_authority_note": "display-only"
            },
            "methods": [{
                "method": "oidc",
                "issuer_uri": "https://auth.example",
                "openid_configuration_url": "https://auth.example/.well-known/openid-configuration",
                "grant_exchange": {
                    "kind": "account_handoff",
                    "x_exchange_note": true
                },
                "x_method_note": 7
            }],
            "x_auth_note": {"display": true}
        });
        let metadata: AuthMetadata = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(metadata).unwrap(), value);

        assert!(serde_json::from_value::<AuthMetadata>(json!({"mode": "vendor"})).is_err());
        assert!(serde_json::from_value::<AuthMetadata>(json!({"read": "vendor"})).is_err());
        assert!(
            serde_json::from_value::<AuthMethod>(json!({
                "method": "passkey",
                "grant_exchange": {"kind": "account_handoff"},
                "mode": "vendor"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AccountAuthority>(json!({
                "origin": "https://auth.example",
                "gate_account_base_url": "https://auth.example/_arkret/gate/account",
                "mode": "vendor"
            }))
            .is_err()
        );
    }

    fn directory_description() -> ServiceDescribe {
        ServiceDescribe {
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            service_resolution: arkret_models_identity::ResolutionCommitment {
                did: Did::new("did:webvh:z6mkfixture:directory.example").unwrap(),
                method_history_head: "fixture-head".to_owned(),
                version_id: "fixture-version".to_owned(),
            },
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            service_kind: ServiceKind::DirectoryService,
            protocol_version: ServiceProtocolVersion::V1,
            supported_profiles: vec![],
            profile_bindings: BTreeMap::new(),
            supported_operation_bundles: vec![
                "ak.operation_bundle.directory_service.describe.v1".to_owned(),
                "ak.operation_bundle.directory_service.http_core.v1".to_owned(),
            ],
            transport_bindings: vec![TransportBinding::HttpJson {
                base_url: "https://directory.example".to_owned(),
                extension_profile_required: (),
            }],
            supported_features: vec![],
            calendar_tzdb_versions: vec![],
            auth_metadata: AuthMetadata::minimal(),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            verified_profiles: vec![],
            interop_surfaces: vec![],
            invite_addressing: None,
            development_mode: false,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: None,
            resource_kinds: vec![DirectoryResourceKind::Realm],
            extensions: XExtensionMap::default(),
        }
    }

    #[test]
    fn removed_describe_mirrors_are_not_extensions() {
        for field in ["claimed_profiles", "ingest_modes"] {
            let mut wire = serde_json::to_value(station_description()).unwrap();
            wire[field] = json!([]);
            match serde_json::from_value::<ServiceDescribe>(wire) {
                Ok(description) => assert!(description.validate().is_err()),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn calendar_profile_claim_requires_an_executable_tzdb_release() {
        let mut description = station_description();
        description
            .supported_profiles
            .push("ak.profile.calendar_notification_dispatch.v1".to_owned());
        assert!(description.validate().is_err());

        description.calendar_tzdb_versions = vec!["2025b".to_owned()];
        assert!(description.validate().is_ok());
    }

    #[test]
    fn directory_service_overlay_validates() {
        directory_description().validate().unwrap();
    }

    #[test]
    fn directory_service_requires_overlay_fields() {
        let mut description = directory_description();
        description.resource_kinds.clear();

        let error = description.validate().unwrap_err().to_string();
        assert!(error.contains("public Realm metadata"));
    }

    #[test]
    fn directory_service_rejects_non_realm_resource_kinds() {
        let mut description = directory_description();
        description.resource_kinds.clear();

        let error = description.validate().unwrap_err().to_string();
        assert!(error.contains("public Realm metadata"));
    }
}

/// Strongly-typed `auth_metadata` block of the service-describe response.
/// Mirrors `service-describe.schema.json#/properties/auth_metadata`. Every
/// declared field is optional or defaulted so a conforming service that sends
/// only what the schema declares still deserializes; the `extra` flatten
/// round-trips only the closed `x_*` extension namespace.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_authority: Option<AccountAuthority>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_binding_methods: Vec<String>,
    /// Closed `x_*` metadata extensions. These values are protocol-inert.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}

impl AuthMetadata {
    /// Convenience constructor for tests / mocks: leaves every field
    /// empty / `None`.
    pub fn minimal() -> Self {
        Self {
            account_authority: None,
            methods: Vec::new(),
            did_binding_methods: Vec::new(),
            extra: XExtensionMap::default(),
        }
    }
}

/// Mirrors `service-describe.schema.json#/$defs/account_authority`. Carries
/// the client-visible Account Authority origin and the gate/account base URL
/// from which all `/_arkret/gate/account/*` endpoints are derived.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAuthority {
    pub origin: WebOrigin,
    pub gate_account_base_url: String,
    /// Closed `x_*` metadata extensions. These values are protocol-inert.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}

/// Mirrors `service-describe.schema.json#/$defs/auth_method`. Describes a
/// single proof provider, its discovery metadata and the proof kind accepted
/// by the Account Authority.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMethod {
    pub method: AuthMethodKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid_configuration_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub grant_exchange: AuthGrantExchange,
    /// Closed `x_*` metadata extensions. These values are protocol-inert.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}

/// `method` discriminant for [`AuthMethod`]. Mirrors the closed enum in
/// `service-describe.schema.json#/$defs/auth_method/properties/method`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethodKind {
    Oidc,
    Passkey,
    DevicePairing,
    RecoveryChallenge,
    Gnap,
}

/// Mirrors `service-describe.schema.json#/$defs/auth_grant_exchange`. The
/// OIDC discovery describes the only authorization-code consumer: account
/// handoff. SessionGrant issue is a later, separately authenticated operation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthGrantExchange {
    pub kind: AuthGrantExchangeKind,
    /// Closed `x_*` metadata extensions. These values are protocol-inert.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthGrantExchangeKind {
    #[serde(rename = "account_handoff")]
    AccountHandoff,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPrivateNetworkDefault {
    Deny,
    DenyUnlessExplicitException,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressProtectedPurpose {
    DidResolution,
    Federation,
    MediaFetch,
    RealmStateSnapshotFetch,
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
        Self::RealmStateSnapshotFetch,
        Self::Webhook,
        Self::Applet,
        Self::Agent,
        Self::Directory,
        Self::Push,
    ];
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPrivateException {
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomainId>,
    pub cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub development_mode_only: Option<bool>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Wire-level entry in
/// [`ServiceDescribe::verified_profiles`]. Mirrors
/// `service-describe.schema.json#/properties/verified_profiles/items`:
/// requires a verification run id, artifact hash, artifact reference,
/// verifier DID, issuer signature, and timestamp so consumers can pin the
/// claim to an auditable run.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedProfileEntry {
    pub profile_id: String,
    pub claim_kind: ConformanceVerifiedKind,
    pub verification_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub verifier_id: DidCoreId,
    pub signature: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// `claim_kind` discriminant for [`VerifiedProfileEntry`]. Conformance
/// Verifier neutralization (2026-06-10) renamed `cotest_verified` →
/// `conformance_verified`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceVerifiedKind {
    ConformanceVerified,
}

/// Wire-level entry in
/// [`ServiceDescribe::interop_surfaces`]. Mirrors
/// `service-describe.schema.json#/properties/interop_surfaces/items`:
/// `name` + `kind` are required and `kind` is restricted to a closed
/// enum so receivers can fast-path the dispatch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteropSurfaceEntry {
    pub name: String,
    pub kind: InteropSurfaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl InteropSurfaceEntry {
    pub fn new(name: impl Into<String>, kind: InteropSurfaceKind) -> Self {
        Self {
            name: name.into(),
            kind,
            since: None,
            notes: None,
        }
    }

    pub fn matrix_passthrough(name: impl Into<String>) -> Self {
        Self::new(name, InteropSurfaceKind::MatrixPassthrough)
    }

    pub fn mimi_passthrough(name: impl Into<String>) -> Self {
        Self::new(name, InteropSurfaceKind::MimiPassthrough)
    }

    pub fn external_interop(name: impl Into<String>) -> Self {
        Self::new(name, InteropSurfaceKind::ExternalInterop)
    }

    pub fn delegated_resolver(name: impl Into<String>) -> Self {
        Self::new(name, InteropSurfaceKind::DelegatedResolver)
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Closed enum of interop-surface kinds the spec recognises.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropSurfaceKind {
    MatrixPassthrough,
    MimiPassthrough,
    ExternalInterop,
    DelegatedResolver,
}

/// Strongly-typed [`ServiceDescribe::plaintext_visibility`]. Mirrors
/// `service-describe.schema.json#/properties/plaintext_visibility`: the
/// object is closed (`additionalProperties: false`) apart from `x_*`
/// extensions, which the `extra` flatten captures. An all-empty value
/// (`PlaintextVisibility::default()`) means the service claims no plaintext
/// classes.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PlaintextVisibility {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<String>)))]
    pub data_classes: Vec<PlaintextDataClassKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_visibility: Option<PlaintextMaxVisibility>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_purposes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection_outputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// `x_*` extension keys (`additionalProperties: false` otherwise).
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl PlaintextVisibility {
    /// The service receives no plaintext or reversible-derived content.
    pub fn none() -> Self {
        Self::default()
    }
}

/// `max_visibility` discriminant for [`PlaintextVisibility`]. Mirrors the
/// closed enum in
/// `service-describe.schema.json#/properties/plaintext_visibility/properties/max_visibility`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextMaxVisibility {
    None,
    DerivedPlaintext,
    PrivatePlaintext,
}

/// Strongly-typed [`ServiceDescribe::rate_limit_policy`]. Mirrors
/// `service-describe.schema.json#/properties/rate_limit_policy`
/// (`additionalProperties: true`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<RateLimitEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<u32>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

impl RateLimitPolicy {
    /// An empty policy: no predictable endpoint-level rate limit beyond
    /// generic abuse protection (schema: empty `entries[]`).
    pub fn unspecified() -> Self {
        Self {
            policy_version: Some("1".to_owned()),
            ..Self::default()
        }
    }

    /// Convenience: a single service-wide windowed limit of
    /// `max_requests` per 60s.
    pub fn windowed_per_minute(max_requests: u32) -> Self {
        Self {
            policy_version: Some("1".to_owned()),
            entries: vec![RateLimitEntry {
                endpoint: Some("*".to_owned()),
                rate_limit_scope: Some(RateLimitScope::Single("service".to_owned())),
                window_seconds: Some(60),
                max_requests: Some(max_requests),
                ..RateLimitEntry::default()
            }],
            ..Self::default()
        }
    }
}

/// One entry of [`RateLimitPolicy::entries`]. Mirrors the
/// `additionalProperties: true` entry object; every documented field is
/// optional and the `extra` flatten preserves the rest.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RateLimitEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_scope: Option<RateLimitScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events_per_batch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// `rate_limit_scope` is `string | string[]` in the schema.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RateLimitScope {
    Single(String),
    Multiple(Vec<String>),
}
