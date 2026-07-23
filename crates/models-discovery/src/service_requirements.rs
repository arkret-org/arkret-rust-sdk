//! Service endpoint binding allowlists, describe-verification
//! requirements, and the API-convention metadata wire shapes
//! (rate-limit / quota / not-found privacy / trace). The server-side
//! `ErrorEnvelope` constructors that consume these metadata shapes stay
//! with the service runtime in the `arkret` umbrella.

use std::collections::BTreeMap;

use arkret_wire::{
    DeviceId, Did, Error, OperationId, PROTOCOL_VERSION, RealmId, Result, ServiceType,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::service_description::ServiceDescribe;

/// DID-document `service[].type` value designating a device enrollment
/// authority (the entity allowed to sign `service_attested` `ak.device.authorize`
/// for this principal). PascalCase per DID-core service-type convention,
/// mirroring `ArkretPrincipalServer`. See `zh/identity/identity-did.md` and
/// `zh/crypto-media/device-lifecycle.md` §5.4. This is distinct from the
/// snake_case [`ServiceType`] used by `ServiceEndpointBinding`.
pub const DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY: &str = "ArkretDeviceEnrollmentAuthority";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ServiceEndpointBinding {
    pub service_id: Did,
    pub service_type: ServiceType,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ServiceIdAllowlist {
    #[serde(default)]
    pub services: BTreeMap<Did, ServiceEndpointBinding>,
}

impl ServiceIdAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(mut self, binding: ServiceEndpointBinding) -> Self {
        self.services.insert(binding.service_id.clone(), binding);
        self
    }

    pub fn insert(&mut self, binding: ServiceEndpointBinding) {
        self.services.insert(binding.service_id.clone(), binding);
    }

    pub fn contains(&self, service_id: &Did) -> bool {
        self.services.contains_key(service_id)
    }

    pub fn binding(&self, service_id: &Did) -> Option<&ServiceEndpointBinding> {
        self.services.get(service_id)
    }

    pub fn verify_description(&self, description: &ServiceDescribe) -> Result<()> {
        let binding = self.services.get(&description.service_id).ok_or_else(|| {
            Error::Protocol(format!(
                "service DID {} is not allowlisted",
                description.service_id
            ))
        })?;
        if description.service_type != binding.service_type {
            return Err(Error::Protocol(format!(
                "service DID {} is allowlisted as {}, not {}",
                description.service_id,
                binding.service_type.as_str(),
                description.service_type
            )));
        }
        for operation in &binding.operations {
            if !description
                .supported_operations
                .iter()
                .any(|actual| actual == operation)
            {
                return Err(Error::Protocol(format!(
                    "allowlisted service {} does not advertise operation {operation}",
                    description.service_id
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotFoundPrivacy {
    HideNonexistentAndInvisible,
    RevealForbiddenWhenAuthenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScopeKind {
    Actor,
    Ip,
    Device,
    ServiceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct RateLimitMetadata {
    pub scope: RateLimitScopeKind,
    pub subject: String,
    pub limit: u64,
    pub remaining: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub reset_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum QuotaKind {
    BlobBytes,
    AccountStorageBytes,
    OperationWindow,
    DeviceCount,
    OneTimeKeyCount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct QuotaMetadata {
    pub quota: QuotaKind,
    pub subject: String,
    pub limit: u64,
    pub used: u64,
    pub unit: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct HttpTraceMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ApiConventionMetadata {
    pub not_found_privacy: NotFoundPrivacy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quotas: Vec<QuotaMetadata>,
    #[serde(default)]
    pub trace: HttpTraceMetadata,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceRequirements {
    service_type: Option<ServiceType>,
    profiles: Vec<String>,
    reducer_profiles: Vec<String>,
    schema_profiles: Vec<String>,
    operations: Vec<String>,
}

impl ServiceRequirements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn service_type(mut self, service_type: ServiceType) -> Self {
        self.service_type = Some(service_type);
        self
    }

    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profiles.push(profile.into());
        self
    }

    pub fn reducer_profile(mut self, profile: impl Into<String>) -> Self {
        self.reducer_profiles.push(profile.into());
        self
    }

    pub fn schema_profile(mut self, profile: impl Into<String>) -> Self {
        self.schema_profiles.push(profile.into());
        self
    }

    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operations.push(operation.into());
        self
    }

    pub fn verify(&self, description: &ServiceDescribe) -> Result<()> {
        if description.protocol_version != PROTOCOL_VERSION {
            return Err(Error::Protocol(format!(
                "service protocol_version {} does not match Arkret {PROTOCOL_VERSION}",
                description.protocol_version
            )));
        }

        if let Some(service_type) = &self.service_type {
            if description.service_type != *service_type {
                return Err(Error::Protocol(format!(
                    "service_type {} does not match expected {}",
                    description.service_type, service_type
                )));
            }
            // Cross-check the service-type capability matrix (T3-10):
            // refuse a description that advertises operations forbidden
            // for its declared `service_type`.
            for op in &description.supported_operations {
                if !service_type.permits_operation(op) {
                    return Err(Error::Protocol(format!(
                        "service_type {} must not advertise operation {op}",
                        service_type
                    )));
                }
            }
        }

        for profile in &self.profiles {
            if !description
                .supported_profiles
                .iter()
                .any(|actual| actual == profile)
            {
                return Err(Error::Protocol(format!(
                    "service does not support profile {profile}"
                )));
            }
        }

        for profile in &self.reducer_profiles {
            if !description
                .supported_reducer_profiles
                .iter()
                .any(|actual| actual == profile)
            {
                return Err(Error::Protocol(format!(
                    "service does not support reducer profile {profile}"
                )));
            }
        }

        for profile in &self.schema_profiles {
            if !description
                .supported_schema_profiles
                .iter()
                .any(|actual| actual == profile)
            {
                return Err(Error::Protocol(format!(
                    "service does not support schema profile {profile}"
                )));
            }
        }

        for operation in &self.operations {
            if !description
                .supported_operations
                .iter()
                .any(|actual| actual == operation)
            {
                return Err(Error::Protocol(format!(
                    "service does not support operation {operation}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{PROFILE_DIRECTORY_SERVICE, TypedTrustDomainId};

    use super::*;
    use crate::service_description::{
        AuthMetadata, ClaimedProfileEntry, DirectoryAcceptPolicyKind, DirectoryIngestMode,
        DirectoryResourceKind, EgressNetworkPolicy, PlaintextVisibility, RateLimitPolicy,
        ServerLimits,
    };

    #[test]
    fn verifies_required_service_profile_and_operation() {
        let description = ServiceDescribe {
            service_id: Did::new("did:webvh:z6mkfixture:svc.example").unwrap(),
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            service_type: ServiceType::DirectoryService,
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec![PROFILE_DIRECTORY_SERVICE.to_owned()],
            supported_features: vec![],
            supported_operations: vec!["ak.find.directory.query.search_realms".to_owned()],
            supported_bindings: vec![],
            auth_metadata: AuthMetadata::minimal("development"),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            implemented_features: vec![],
            claimed_profiles: vec![ClaimedProfileEntry::self_claimed(PROFILE_DIRECTORY_SERVICE)],
            verified_profiles: vec![],
            experimental_features: vec![],
            compat_surfaces: vec![],
            development_mode: false,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
            resource_types: vec![
                DirectoryResourceKind::Realm,
                DirectoryResourceKind::Organization,
                DirectoryResourceKind::Actor,
                DirectoryResourceKind::Applet,
                DirectoryResourceKind::Handle,
            ],
            discovery_profiles: vec![PROFILE_DIRECTORY_SERVICE.to_owned()],
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
            rate_limits: Some(BTreeMap::new()),
            supported_reducer_profiles: vec!["ak.reducer.v1".to_owned()],
            supported_schema_profiles: vec!["ak.schema.core.v1".to_owned()],
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            reducer_profile: None,
            last_materialized_at: None,
            extensions: Default::default(),
        };

        ServiceRequirements::new()
            .service_type(ServiceType::DirectoryService)
            .profile(PROFILE_DIRECTORY_SERVICE)
            .reducer_profile("ak.reducer.v1")
            .schema_profile("ak.schema.core.v1")
            .operation("ak.find.directory.query.search_realms")
            .verify(&description)
            .unwrap();
    }

    #[test]
    fn service_id_allowlist_verifies_description_and_operations() {
        let service_id = Did::new("did:webvh:z6mkfixture:svc.example").unwrap();
        let allowlist = ServiceIdAllowlist::new().allow(ServiceEndpointBinding {
            service_id: service_id.clone(),
            service_type: ServiceType::DirectoryService,
            endpoint: "https://svc.example/_arkret/find/directory".to_owned(),
            operations: vec!["ak.find.directory.query.search_realms".to_owned()],
        });
        let description = ServiceDescribe {
            service_id,
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            service_type: ServiceType::DirectoryService,
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec![PROFILE_DIRECTORY_SERVICE.to_owned()],
            supported_features: vec![],
            supported_operations: vec!["ak.find.directory.query.search_realms".to_owned()],
            supported_bindings: vec![],
            auth_metadata: AuthMetadata::minimal("development"),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            implemented_features: vec![],
            claimed_profiles: vec![],
            verified_profiles: vec![],
            experimental_features: vec![],
            compat_surfaces: vec![],
            development_mode: false,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
            resource_types: vec![
                DirectoryResourceKind::Realm,
                DirectoryResourceKind::Organization,
                DirectoryResourceKind::Actor,
                DirectoryResourceKind::Applet,
                DirectoryResourceKind::Handle,
            ],
            discovery_profiles: vec![PROFILE_DIRECTORY_SERVICE.to_owned()],
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
            rate_limits: Some(BTreeMap::new()),
            supported_reducer_profiles: vec![],
            supported_schema_profiles: vec![],
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            reducer_profile: None,
            last_materialized_at: None,
            extensions: Default::default(),
        };

        allowlist.verify_description(&description).unwrap();
    }

    #[test]
    fn push_gateway_permits_current_edge_push_operations() {
        let service_type = ServiceType::PushGateway;
        // The three `ak.edge.push.*` operations registered in
        // `operation-registry.json` MUST all be advertisable by a push gateway.
        assert!(service_type.permits_operation("ak.edge.push.command.register_device"));
        assert!(service_type.permits_operation("ak.edge.push.command.unregister_device"));
        assert!(service_type.permits_operation("ak.edge.push.command.notify"));
        // Operations outside the `ak.edge.push.` surface (e.g. applet or
        // self-API operations) MUST NOT be advertisable by a push gateway.
        assert!(!service_type.permits_operation("ak.edge.applet.command.invoke"));
        assert!(!service_type.permits_operation("ak.self.events.query.sync"));
    }
}
