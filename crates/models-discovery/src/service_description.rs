use std::collections::BTreeMap;

pub use arkret_models_identity::session_credential::SessionGrantProofKind;
use arkret_wire::{ProfileId, SchemaId, *};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<u64>)))]
    pub max_get_query_selectors: Option<std::num::NonZeroU64>,
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
    RecipientServiceId,
    PrincipalId,
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
            return Err(Error::Protocol(format!(
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
    pub push_target_id: Option<PushTargetPrivacyDerivation>,
}

/// Canonical service description defined by `service-describe.schema.json`.
/// Receivers reject responses missing required fields with `schema_violation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceDescribe {
    pub service_id: Did,
    /// Required trust domain. Receivers MUST refuse to
    /// register a peer whose `trust_domain` disagrees with the
    /// expected deployment scope.
    pub trust_domain: TypedTrustDomainId,
    pub service_kind: ServiceKind,
    pub protocol_version: String,
    /// Profiles the service
    /// declares conformance to. Empty array is valid; missing is not.
    pub supported_profiles: Vec<String>,
    /// Profile-specific carrier declarations keyed by profile id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_bindings: BTreeMap<String, ProfileBinding>,
    pub supported_operations: Vec<String>,
    pub supported_bindings: Vec<SupportedBinding>,
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
    /// Features the service has actually implemented (subset
    /// of `supported_features`). Tracks the difference between
    /// announce and run-time implementation.
    pub implemented_features: Vec<String>,
    /// Profiles the service claims (self-declared). Wire
    /// shape per
    /// `service-describe.schema.json#/properties/claimed_profiles`:
    /// every entry MUST be an object with `profile_id` +
    /// `claim_kind = "self_claimed"`; verified-only assertions live in
    /// [`Self::verified_profiles`].
    pub claimed_profiles: Vec<ClaimedProfileEntry>,
    /// Profiles a third party has verified the service
    /// against. MUST be empty when `development_mode == true`. Wire
    /// shape per
    /// `service-describe.schema.json#/properties/verified_profiles`.
    pub verified_profiles: Vec<VerifiedProfileEntry>,
    /// Non-final extension features. Treated as opt-in by
    /// peers.
    pub experimental_features: Vec<String>,
    /// External-interop surfaces this service
    /// exposes outside its claimed v1 conformance (e.g. MIMI/Matrix
    /// passthrough). Wire shape per
    /// `service-describe.schema.json#/properties/compat_surfaces`.
    pub compat_surfaces: Vec<CompatSurfaceEntry>,
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
    /// `ak.find.directory.query.describe`. Required when
    /// `service_kind == "directory_service"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_kinds: Vec<DirectoryResourceKind>,
    /// Directory-service overlay: discovery profiles and extension
    /// profile ids advertised by the directory surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovery_profiles: Vec<String>,
    /// Directory-service overlay: whether restricted or privacy-sensitive
    /// queries require holder-approved proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_query_proof: Option<bool>,
    /// Directory-service overlay: supported ingest modes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingest_modes: Vec<DirectoryIngestMode>,
    /// Directory-service overlay: resource acceptance policy kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_policy_kind: Option<DirectoryAcceptPolicyKind>,
    /// Directory-service overlay: optional governance or human-readable
    /// reference for obtaining acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_policy_ref: Option<BTreeMap<String, Value>>,
    /// Directory-service overlay: default entry TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<u64>,
    /// Directory-service overlay: maximum accepted entry TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    /// Directory-service overlay: refresh grace period in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidation_grace_seconds: Option<u64>,
    /// Directory-service overlay: resource kinds accepted by this instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_resource_kinds: Vec<DirectoryResourceKind>,
    /// Directory-service overlay: accepted principal/governance DID methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_did_methods: Vec<String>,
    /// Directory-service overlay: takedown notification or appeal contact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takedown_contact: Option<String>,
    /// Directory-service overlay: readable per-DID/per-org/per-IP quota
    /// limits that do not fit the global `rate_limit_policy` shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<BTreeMap<String, Value>>,
    /// Registered Realm reducer profiles this service can actually execute.
    /// This is a capability set, not a selected Realm profile.
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
    /// Wall-clock time of the most recent successful state
    /// materialization. A stale `last_materialized_at` paired with a
    /// fresh `frontier` indicates the projection layer is degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_materialized_at: Option<DateTime<Utc>>,
    /// Vendor extensions permitted by the service-describe schema. Keys must
    /// use the reserved `x_<vendor>_*` namespace and are serialized at the
    /// top level.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extensions: BTreeMap<String, Value>,
}

impl ServiceDescribe {
    pub const SCHEMA: &'static str = SchemaId::SERVICE_DESCRIBE_V1;

    /// Publish the exact shared SDK build compiled into this service.
    pub fn install_current_arkret_build_identity(&mut self) -> Result<()> {
        self.extensions.insert(
            ARKRET_BUILD_IDENTITY_EXTENSION.to_owned(),
            serde_json::to_value(ArkretBuildIdentity::current())?,
        );
        Ok(())
    }

    /// Decode the SDK-owned build identity extension without a local DTO.
    pub fn arkret_build_identity(&self) -> Result<Option<ArkretBuildIdentity>> {
        self.extensions
            .get(ARKRET_BUILD_IDENTITY_EXTENSION)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(Error::from)
    }

    /// Require this service description to come from the exact SDK source
    /// compiled into the caller.
    pub fn validate_current_arkret_build_identity(&self) -> Result<()> {
        let identity = self.arkret_build_identity()?.ok_or_else(|| {
            Error::Protocol(format!(
                "ServiceDescribe: missing {ARKRET_BUILD_IDENTITY_EXTENSION}"
            ))
        })?;
        identity.validate_current()
    }

    /// Build a complete development-mode description for a service surface.
    pub fn development(
        service_id: Did,
        trust_domain: TypedTrustDomainId,
        service_kind: ServiceKind,
    ) -> Self {
        Self {
            service_id,
            trust_domain,
            service_kind,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            supported_profiles: Vec::new(),
            profile_bindings: BTreeMap::new(),
            supported_operations: Vec::new(),
            supported_bindings: Vec::new(),
            supported_features: Vec::new(),
            calendar_tzdb_versions: Vec::new(),
            auth_metadata: AuthMetadata::minimal("development"),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            implemented_features: Vec::new(),
            claimed_profiles: Vec::new(),
            verified_profiles: Vec::new(),
            experimental_features: Vec::new(),
            compat_surfaces: Vec::new(),
            development_mode: true,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: None,
            resource_kinds: Vec::new(),
            discovery_profiles: Vec::new(),
            restricted_query_proof: None,
            ingest_modes: Vec::new(),
            accept_policy_kind: None,
            accept_policy_ref: None,
            default_ttl_seconds: None,
            max_ttl_seconds: None,
            revalidation_grace_seconds: None,
            accepted_resource_kinds: Vec::new(),
            accepted_did_methods: Vec::new(),
            takedown_contact: None,
            rate_limits: None,
            supported_reducer_profiles: Vec::new(),
            supported_schema_profiles: Vec::new(),
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            last_materialized_at: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Validate the cross-field invariants:
    /// - `verified_profiles` MUST be empty when `development_mode = true`.
    /// - the describe `anyOf` requires `rate_limit_policy` or `rate_limit_policy_id`.
    pub fn validate(&self) -> Result<()> {
        if !self.service_kind.valid_in("service_describe") {
            return Err(Error::Protocol(format!(
                "ServiceDescribe: service_kind={} is not valid in service_describe ({})",
                self.service_kind.as_str(),
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if let Some(push_target) = self
            .privacy_derivation
            .as_ref()
            .and_then(|derivation| derivation.push_target_id.as_ref())
        {
            push_target.validate()?;
        }
        if self.development_mode && !self.verified_profiles.is_empty() {
            return Err(Error::Protocol(format!(
                "ServiceDescribe: development_mode=true forbids non-empty verified_profiles \
                 ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        let claims_calendar = self.supported_profiles.iter().any(|profile| {
            matches!(
                profile.as_str(),
                "ak.profile.calendar_event.v1" | "ak.profile.calendar_notification_dispatch.v1"
            )
        }) || self.claimed_profiles.iter().any(|claim| {
            matches!(
                claim.profile_id.as_str(),
                "ak.profile.calendar_event.v1" | "ak.profile.calendar_notification_dispatch.v1"
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
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == self.calendar_tzdb_versions.len();
        if (claims_calendar && self.calendar_tzdb_versions.is_empty())
            || !unique_tzdb_versions
            || self
                .calendar_tzdb_versions
                .iter()
                .any(|version| !valid_tzdb_version(version))
        {
            return Err(Error::Protocol(format!(
                "ServiceDescribe: Calendar profile claims require a non-empty, unique \
                 calendar_tzdb_versions release set ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        const JOIN_OPERATIONS: &[&str] = &[
            "ak.self.realm.join_application.command.submit",
            "ak.self.realm.join_application.command.review",
            "ak.self.realm.join_application.command.cancel",
            "ak.self.realm.join_application.query.list",
            "ak.self.realm.join_application.resource.get",
            "ak.self.realm.join_application.audit.query.list",
        ];
        const JOIN_FEATURES: &[&str] = &[
            "candidate_join_policy_reviewer",
            "candidate_member_application_intake",
            "profile_private_http_receipt_v1",
        ];
        if self.profile_bindings.iter().any(|(profile, binding)| {
            binding.carrier.is_empty()
                || !self
                    .supported_profiles
                    .iter()
                    .any(|supported| supported == profile)
        }) {
            return Err(Error::Protocol(format!(
                "ServiceDescribe: profile_bindings must reference supported_profiles and \
                 carry a non-empty carrier ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self
            .supported_profiles
            .iter()
            .any(|profile| profile == ProfileId::CANDIDATE_JOIN_POLICY_V1)
        {
            let carrier = self
                .profile_bindings
                .get(ProfileId::CANDIDATE_JOIN_POLICY_V1)
                .map(|binding| binding.carrier.as_str());
            if carrier != Some("profile_private_http_receipt_v1") {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: {profileid_candidate_join_policy_v1} requires \
                     profile_bindings carrier=profile_private_http_receipt_v1 ({})",
                    ErrorCode::SCHEMA_VIOLATION,
                    profileid_candidate_join_policy_v1 = ProfileId::CANDIDATE_JOIN_POLICY_V1
                )));
            }
            if JOIN_OPERATIONS.iter().any(|required| {
                !self
                    .supported_operations
                    .iter()
                    .any(|operation| operation == required)
            }) || JOIN_FEATURES.iter().any(|required| {
                !self
                    .supported_features
                    .iter()
                    .any(|feature| feature == required)
            }) {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: {profileid_candidate_join_policy_v1} requires its complete operation and \
                     feature surface ({})",
                    ErrorCode::SCHEMA_VIOLATION,
                    profileid_candidate_join_policy_v1 = ProfileId::CANDIDATE_JOIN_POLICY_V1
                )));
            }
        }
        if self.rate_limit_policy.is_none() && self.rate_limit_policy_id.is_none() {
            return Err(Error::Protocol(format!(
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
            return Err(Error::Protocol(format!(
                "ServiceDescribe: extension keys must match ^x_[a-z][a-z0-9_]*$ ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        if self.service_kind == ServiceKind::DirectoryService {
            if !self
                .supported_profiles
                .iter()
                .any(|profile| profile == "ak.profile.directory_service.v1")
            {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: service_kind=directory_service requires \
                     supported_profiles to include ak.profile.directory_service.v1 ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
            if self.resource_kinds.is_empty()
                || self.discovery_profiles.is_empty()
                || self.ingest_modes.is_empty()
                || self.accept_policy_kind.is_none()
                || self.default_ttl_seconds.is_none()
                || self.max_ttl_seconds.is_none()
                || self.revalidation_grace_seconds.is_none()
                || self.accepted_resource_kinds.is_empty()
                || self.accepted_did_methods.is_empty()
                || self.rate_limits.is_none()
            {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: service_kind=directory_service requires the directory \
                     describe overlay fields ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
            let default_ttl = self.default_ttl_seconds.unwrap_or_default();
            let max_ttl = self.max_ttl_seconds.unwrap_or_default();
            if max_ttl > 2_592_000 || default_ttl > max_ttl {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: directory TTL fields must satisfy \
                     default_ttl_seconds <= max_ttl_seconds <= 2592000 ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
            if self
                .accepted_did_methods
                .iter()
                .any(|method| !is_valid_directory_did_method(method))
            {
                return Err(Error::Protocol(format!(
                    "ServiceDescribe: directory accepted_did_methods entries must match \
                     did:<method> with lowercase alphanumeric method names ({})",
                    ErrorCode::SCHEMA_VIOLATION
                )));
            }
        }
        Ok(())
    }
}

/// Profile-specific interoperable carrier binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProfileBinding {
    pub carrier: String,
}

fn is_valid_directory_did_method(value: &str) -> bool {
    value.strip_prefix("did:").is_some_and(|method| {
        !method.is_empty()
            && method
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

impl ServiceDescribe {
    pub fn supports_arkret_v1(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sdk_build_identity_round_trips_through_shared_type() {
        let mut description = ServiceDescribe::development(
            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::PrincipalServer,
        );
        description.install_current_arkret_build_identity().unwrap();

        assert_eq!(
            description.arkret_build_identity().unwrap(),
            Some(ArkretBuildIdentity::current())
        );
        description
            .validate_current_arkret_build_identity()
            .unwrap();
    }

    fn directory_description() -> ServiceDescribe {
        ServiceDescribe {
            service_id: Did::new("did:webvh:z6mkfixture:directory.example").unwrap(),
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            service_kind: ServiceKind::DirectoryService,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            supported_profiles: vec![ProfileId::DIRECTORY_SERVICE_V1.to_owned()],
            profile_bindings: BTreeMap::new(),
            supported_operations: vec!["ak.find.directory.query.describe".to_owned()],
            supported_bindings: vec![],
            supported_features: vec![],
            calendar_tzdb_versions: vec![],
            auth_metadata: AuthMetadata::minimal("development"),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            implemented_features: vec![],
            claimed_profiles: vec![ClaimedProfileEntry::self_claimed(
                ProfileId::DIRECTORY_SERVICE_V1,
            )],
            verified_profiles: vec![],
            experimental_features: vec![],
            compat_surfaces: vec![],
            development_mode: false,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: None,
            resource_kinds: vec![
                DirectoryResourceKind::Realm,
                DirectoryResourceKind::Organization,
                DirectoryResourceKind::Actor,
                DirectoryResourceKind::Applet,
                DirectoryResourceKind::Handle,
            ],
            discovery_profiles: vec![ProfileId::DIRECTORY_SERVICE_V1.to_owned()],
            restricted_query_proof: Some(true),
            ingest_modes: vec![DirectoryIngestMode::Push],
            accept_policy_kind: Some(DirectoryAcceptPolicyKind::Open),
            accept_policy_ref: None,
            default_ttl_seconds: Some(86_400),
            max_ttl_seconds: Some(604_800),
            revalidation_grace_seconds: Some(3_600),
            accepted_resource_kinds: vec![
                DirectoryResourceKind::Realm,
                DirectoryResourceKind::Organization,
                DirectoryResourceKind::Actor,
                DirectoryResourceKind::Applet,
                DirectoryResourceKind::Handle,
            ],
            accepted_did_methods: vec!["did:web".to_owned(), "did:webvh".to_owned()],
            takedown_contact: None,
            rate_limits: Some(BTreeMap::from([(
                "per_ip_per_minute".to_owned(),
                json!(60),
            )])),
            supported_reducer_profiles: vec![],
            supported_schema_profiles: vec![],
            frontier: vec![],
            snapshot_frontier: vec![],
            last_materialized_at: None,
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn candidate_join_policy_requires_complete_private_carrier_claim() {
        let mut description = ServiceDescribe::development(
            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::PrincipalServer,
        );
        description
            .supported_profiles
            .push(ProfileId::CANDIDATE_JOIN_POLICY_V1.to_owned());
        assert!(description.validate().is_err());
        description.profile_bindings.insert(
            ProfileId::CANDIDATE_JOIN_POLICY_V1.to_owned(),
            ProfileBinding {
                carrier: "profile_private_http_receipt_v1".to_owned(),
            },
        );
        description.supported_operations.extend(
            [
                "ak.self.realm.join_application.command.submit",
                "ak.self.realm.join_application.command.review",
                "ak.self.realm.join_application.command.cancel",
                "ak.self.realm.join_application.query.list",
                "ak.self.realm.join_application.resource.get",
                "ak.self.realm.join_application.audit.query.list",
            ]
            .map(ToOwned::to_owned),
        );
        description.supported_features.extend(
            [
                "candidate_join_policy_reviewer",
                "candidate_member_application_intake",
                "profile_private_http_receipt_v1",
            ]
            .map(ToOwned::to_owned),
        );
        assert!(description.validate().is_ok());
    }

    #[test]
    fn calendar_profile_claim_requires_an_executable_tzdb_release() {
        let mut description = ServiceDescribe::development(
            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::PrincipalServer,
        );
        description
            .supported_profiles
            .push("ak.profile.calendar_notification_dispatch.v1".to_owned());
        description
            .claimed_profiles
            .push(ClaimedProfileEntry::self_claimed(
                "ak.profile.calendar_notification_dispatch.v1",
            ));
        assert!(description.validate().is_err());

        description.calendar_tzdb_versions = vec!["2025b".to_owned()];
        assert!(description.validate().is_ok());
    }

    #[test]
    fn directory_service_overlay_validates() {
        directory_description().validate().unwrap();
    }

    #[test]
    fn service_description_checks_protocol_version() {
        let mut description = directory_description();
        assert!(description.supports_arkret_v1());

        description.protocol_version = "2.0".to_owned();
        assert!(!description.supports_arkret_v1());
    }

    #[test]
    fn directory_service_requires_overlay_fields() {
        let mut description = directory_description();
        description.resource_kinds.clear();

        let error = description.validate().unwrap_err().to_string();
        assert!(error.contains("directory describe overlay"));
    }

    #[test]
    fn directory_service_rejects_invalid_did_method_tokens() {
        let mut description = directory_description();
        description.accepted_did_methods = vec!["web".to_owned()];

        let error = description.validate().unwrap_err().to_string();
        assert!(error.contains("accepted_did_methods"));
    }

    #[test]
    fn directory_service_rejects_invalid_ttl_order() {
        let mut description = directory_description();
        description.default_ttl_seconds = Some(604_801);

        let error = description.validate().unwrap_err().to_string();
        assert!(error.contains("default_ttl_seconds <= max_ttl_seconds"));
    }
}

/// Strongly-typed `auth_metadata` block of the service-describe response.
/// Mirrors `service-describe.schema.json#/properties/auth_metadata`. Every
/// field other than `mode` is optional or defaulted so older / sparser wire
/// payloads still deserialize; the `extra` flatten captures `x_*` and any
/// future unknown keys (`additionalProperties: true`) without data loss.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthMetadata {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_authority: Option<AccountAuthority>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_binding_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    /// Captures `x_*` and any other `additionalProperties: true` keys so the
    /// SDK round-trips future / vendor-specific fields without dropping them.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

impl AuthMetadata {
    /// Convenience constructor for tests / mocks: fills `mode` and leaves
    /// every other field empty / `None`.
    pub fn minimal(mode: impl Into<String>) -> Self {
        Self {
            mode: mode.into(),
            account_authority: None,
            methods: Vec::new(),
            did_binding_methods: Vec::new(),
            read: None,
            extra: BTreeMap::new(),
        }
    }
}

/// Mirrors `service-describe.schema.json#/$defs/account_authority`. Carries
/// the client-visible Account Authority origin and the gate/account base URL
/// from which all `/_arkret/gate/account/*` endpoints are derived.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountAuthority {
    pub origin: String,
    pub gate_account_base: String,
    /// Deployment-pinned authority delegated to sign B-model first-device
    /// enrollment. Account-first clients use this value when authoring entry 0
    /// and MUST NOT learn it from the Account Authority response they are
    /// about to trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_authority_did: Option<Did>,
}

/// Mirrors `service-describe.schema.json#/$defs/auth_method`. Describes a
/// single proof provider, its discovery metadata and the proof kind accepted
/// by the Account Authority.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
/// `proof_kind` reuses the authoritative [`SessionGrantProofKind`] enum so
/// the describe surface and the session-grant request surface stay in lockstep.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthGrantExchange {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub proof_kind: SessionGrantProofKind,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BottomDiagnosticSealView {
    pub leaves: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BottomDiagnostic {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: BottomKind,
    pub cells: Vec<CellRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_view: Option<BottomDiagnosticSealView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<BottomDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub escalated_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPrivateException {
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TypedTrustDomainId>,
    pub cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub development_mode_only: Option<bool>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Ingest mode vocabulary for the directory-service describe overlay.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryIngestMode {
    Push,
    Pull,
}

/// Acceptance policy vocabulary for the directory-service describe overlay.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryAcceptPolicyKind {
    Open,
    Allowlist,
    TrustRootSigned,
    OperatorReview,
}

/// Round 4 — wire-level entry in
/// [`ServiceDescribe::claimed_profiles`]. Mirrors
/// `service-describe.schema.json#/properties/claimed_profiles/items`:
/// `profile_id` + `claim_kind = "self_claimed"` are required, the rest
/// is optional + open (`additionalProperties: true`) so receivers can
/// round-trip future fields without losing them.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimedProfileEntry {
    pub profile_id: String,
    pub claim_kind: SelfClaimedKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub claimed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfClaimedKind {
    SelfClaimed,
}

/// Round 4 — wire-level entry in
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
    pub verifier_did: Did,
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

/// Round 4 — wire-level entry in
/// [`ServiceDescribe::compat_surfaces`]. Mirrors
/// `service-describe.schema.json#/properties/compat_surfaces/items`:
/// `name` + `kind` are required and `kind` is restricted to a closed
/// enum so receivers can fast-path the dispatch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatSurfaceEntry {
    pub name: String,
    pub kind: CompatSurfaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl CompatSurfaceEntry {
    pub fn new(name: impl Into<String>, kind: CompatSurfaceKind) -> Self {
        Self {
            name: name.into(),
            kind,
            since: None,
            notes: None,
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

    pub fn delegated_resolver(name: impl Into<String>) -> Self {
        Self::new(name, CompatSurfaceKind::DelegatedResolver)
    }

    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = Some(since.into());
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Round 4 — closed enum of compat-surface kinds the spec recognises.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatSurfaceKind {
    MatrixPassthrough,
    MimiPassthrough,
    ExternalInterop,
    DelegatedResolver,
}

/// Strongly-typed entry of [`ServiceDescribe::supported_bindings`].
/// Mirrors `service-describe.schema.json#/properties/supported_bindings/items`:
/// `kind` is required, `base_url` optional, and the item is
/// `additionalProperties: true` so the `extra` flatten round-trips any
/// transport-specific keys without loss.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportedBinding {
    pub kind: BindingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

impl SupportedBinding {
    pub fn new(kind: BindingKind) -> Self {
        Self {
            kind,
            base_url: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }
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
