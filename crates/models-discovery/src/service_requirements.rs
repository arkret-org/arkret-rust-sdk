//! Service endpoint binding allowlists, describe-verification
//! requirements, and the API-convention metadata wire shapes
//! (rate-limit / quota / not-found privacy / trace). The server-side
//! `ErrorEnvelope` constructors that consume these metadata shapes stay
//! with the service runtime in the `arkret` umbrella.

use std::collections::BTreeMap;

use arkret_wire::{
    BindingKind, DeviceId, DidCoreId, OperationId, RealmId, Result, ServiceKind,
    ServiceOperationId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::service_description::ServiceDescribe;

/// DID-document `service[].type` value designating a device enrollment
/// authority (the entity allowed to sign `service_attested` `ak.device.authorize`
/// for this principal). PascalCase per DID-core service-kind convention,
/// mirroring `ArkretStation`. See `zh/identity/identity-did.md` and
/// `zh/crypto-media/device-lifecycle.md` §5.4. This is distinct from the
/// snake_case [`ServiceKind`] used by `ServiceEndpointBinding`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpointBinding {
    pub service_id: DidCoreId,
    pub service_kind: ServiceKind,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidCoreIdAllowlist {
    #[serde(default)]
    pub services: BTreeMap<DidCoreId, ServiceEndpointBinding>,
}

impl DidCoreIdAllowlist {
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

    pub fn contains(&self, service_id: &DidCoreId) -> bool {
        self.services.contains_key(service_id)
    }

    pub fn binding(&self, service_id: &DidCoreId) -> Option<&ServiceEndpointBinding> {
        self.services.get(service_id)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotFoundPrivacy {
    HideNonexistentAndInvisible,
    RevealForbiddenWhenAuthenticated,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScopeKind {
    Actor,
    Ip,
    Device,
    DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitMetadata {
    pub scope: RateLimitScopeKind,
    pub subject: String,
    pub limit: u64,
    pub remaining: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub reset_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaKind {
    BlobBytes,
    AccountStorageBytes,
    OperationWindow,
    DeviceCount,
    OneTimeKeyCount,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaMetadata {
    pub quota: QuotaKind,
    pub subject: String,
    pub limit: u64,
    pub used: u64,
    pub unit: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpTraceMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    service_kind: Option<ServiceKind>,
    profiles: Vec<String>,
    reducer_profiles: Vec<String>,
    operation_pairs: Vec<(ServiceOperationId, BindingKind)>,
}

impl ServiceRequirements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn service_kind(mut self, service_kind: ServiceKind) -> Self {
        self.service_kind = Some(service_kind);
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

    pub fn operation_binding(
        mut self,
        operation_id: ServiceOperationId,
        binding_kind: BindingKind,
    ) -> Self {
        self.operation_pairs.push((operation_id, binding_kind));
        self
    }

    pub fn verify(&self, description: &ServiceDescribe) -> Result<()> {
        if let Some(service_kind) = &self.service_kind
            && description.service_kind != *service_kind
        {
            return Err(WireError::Protocol(format!(
                "service_kind {} does not match expected {}",
                description.service_kind, service_kind
            )));
            // `ServiceDescribe::validate` checks canonical bundle ownership;
            // the bundle registry, not operation-name prefixes, is authoritative.
        }

        for profile in &self.profiles {
            if !description
                .supported_profiles
                .iter()
                .any(|actual| actual == profile)
            {
                return Err(WireError::Protocol(format!(
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
                return Err(WireError::Protocol(format!(
                    "service does not support reducer profile {profile}"
                )));
            }
        }

        for &(operation_id, binding_kind) in &self.operation_pairs {
            if !description.supports_operation_binding(operation_id, binding_kind) {
                return Err(WireError::Protocol(format!(
                    "service does not support operation {operation_id} over {binding_kind}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, DidCoreId, ServiceOperationId, TrustDomainId};

    use super::*;
    use crate::service_description::{
        AuthMetadata, DirectoryAcceptPolicyKind, DirectoryIngestMode, DirectoryResourceKind,
        EgressNetworkPolicy, PlaintextVisibility, RateLimitPolicy, ServerLimits, TransportBinding,
    };

    #[test]
    fn verifies_required_service_profile_and_operation() {
        let description = ServiceDescribe {
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            service_resolution: arkret_models_identity::ResolutionCommitment {
                did: Did::new("did:webvh:z6mkfixture:svc.example").unwrap(),
                method_history_head: "fixture-head".to_owned(),
                version_id: "fixture-version".to_owned(),
            },
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            service_kind: ServiceKind::DirectoryService,
            protocol_version: crate::service_description::ServiceProtocolVersion::V1,
            supported_profiles: vec![],
            profile_bindings: Default::default(),
            supported_features: vec![],
            calendar_tzdb_versions: vec![],
            supported_operation_bundles: vec![
                "ak.operation_bundle.directory_service.describe.v1".to_owned(),
                "ak.operation_bundle.directory_service.http_core.v1".to_owned(),
            ],
            transport_bindings: vec![TransportBinding::HttpJson {
                base_url: "https://directory.example".to_owned(),
                extension_profile_required: (),
            }],
            auth_metadata: AuthMetadata::minimal(),
            limits: ServerLimits::default(),
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            claimed_profiles: vec![],
            verified_profiles: vec![],
            interop_surfaces: vec![],
            invite_addressing: None,
            development_mode: false,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
            resource_kinds: vec![
                DirectoryResourceKind::Realm,
                DirectoryResourceKind::Organization,
                DirectoryResourceKind::Actor,
                DirectoryResourceKind::Applet,
                DirectoryResourceKind::Handle,
            ],
            private_contact_discovery: None,
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
            supported_reducer_profiles: vec![arkret_wire::CORE_REDUCER_PROFILE.to_owned()],
            extensions: Default::default(),
        };

        ServiceRequirements::new()
            .service_kind(ServiceKind::DirectoryService)
            .reducer_profile(arkret_wire::CORE_REDUCER_PROFILE)
            .operation_binding(
                ServiceOperationId::FindDirectoryReadSearchRealmsV1,
                BindingKind::HttpJson,
            )
            .verify(&description)
            .unwrap();

        let mut incompatible_json = serde_json::to_value(description).unwrap();
        incompatible_json["protocol_version"] = serde_json::json!("2.0");
        let error = serde_json::from_value::<ServiceDescribe>(incompatible_json)
            .expect_err("the v1 typed consumer must reject another protocol family");
        assert!(
            error
                .to_string()
                .contains(arkret_wire::ErrorCode::UNSUPPORTED_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn push_gateway_permits_current_edge_push_operations() {
        let service_kind = ServiceKind::PushGateway;
        // The three `ak.edge.push.*` operations registered in
        // `operation-registry.json` MUST all be advertisable by a push gateway.
        assert!(service_kind.permits_operation("ak.edge.push.command.register_device.v1"));
        assert!(service_kind.permits_operation("ak.edge.push.command.unregister_device.v1"));
        assert!(service_kind.permits_operation("ak.edge.push.command.notify.v1"));
        // Operations outside the `ak.edge.push.` surface (e.g. applet or
        // self-API operations) MUST NOT be advertisable by a push gateway.
        assert!(!service_kind.permits_operation("ak.edge.applet.command.invoke"));
        assert!(!service_kind.permits_operation("ak.self.events.read.unknown"));
        assert!(!service_kind.permits_operation("ak.self.events.read.sync"));
    }
}
