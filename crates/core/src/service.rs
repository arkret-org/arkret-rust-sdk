use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CommitId, DeviceId, Did, Error, ErrorEnvelope, OperationId, PROTOCOL_VERSION, Result,
    ServerDescription, SpaceId,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    PrincipalServer,
    IdentityRegistry,
    AuthServer,
    SyncNode,
    IndexNode,
    AppViewNode,
    BlobNode,
    DirectoryService,
    DeviceKeyService,
    AuthzService,
    PolicyServer,
    PushGateway,
    AppletService,
    AgentRuntime,
    MediaService,
    SfuService,
    TurnService,
    ModerationService,
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrincipalServer => "principal_server",
            Self::IdentityRegistry => "identity_registry",
            Self::AuthServer => "auth_server",
            Self::SyncNode => "sync_node",
            Self::IndexNode => "index_node",
            Self::AppViewNode => "appview_node",
            Self::BlobNode => "blob_node",
            Self::DirectoryService => "directory_service",
            Self::DeviceKeyService => "device_key_service",
            Self::AuthzService => "authz_service",
            Self::PolicyServer => "policy_server",
            Self::PushGateway => "push_gateway",
            Self::AppletService => "applet_service",
            Self::AgentRuntime => "agent_runtime",
            Self::MediaService => "media_service",
            Self::SfuService => "sfu_service",
            Self::TurnService => "turn_service",
            Self::ModerationService => "moderation_service",
        }
    }

    /// Operation-kind prefixes a service of this type is allowed to
    /// advertise (T3-10 / `service-surface.md` capability matrix).
    ///
    /// `cx.applet.*` for applet services, `cx.federation.*` for principal
    /// servers and sync nodes, etc. An empty slice means "no allow-list
    /// constraint" (e.g. `PrincipalServer` accepts the union of all
    /// kinds).
    pub fn allowed_operation_prefixes(&self) -> &'static [&'static str] {
        match self {
            Self::PrincipalServer => &[
                "cx.events.",
                "cx.sync.",
                "cx.federation.",
                "cx.account.",
                "cx.policy.",
                "cx.authz.",
                "cx.identity.",
                "cx.repo.",
                "cx.server.",
                "cx.admin.",
                "cx.moderation.",
            ],
            Self::IdentityRegistry => &["cx.identity.", "cx.directory.resolve_handle"],
            Self::AuthServer => &["cx.account.", "cx.identity.resolve"],
            Self::SyncNode => &["cx.sync.", "cx.events.", "cx.federation."],
            Self::IndexNode => &["cx.index."],
            Self::AppViewNode => &["cx.index.", "cx.directory.search_"],
            Self::BlobNode | Self::MediaService => &["cx.blob.", "cx.media."],
            Self::DirectoryService => &["cx.directory."],
            Self::DeviceKeyService => &["cx.keys.", "cx.device_messages."],
            Self::AuthzService => &["cx.authz.", "cx.policy."],
            Self::PolicyServer => &["cx.policy."],
            Self::PushGateway => &["cx.push."],
            Self::AppletService => &["cx.applet."],
            Self::AgentRuntime => &["cx.applet.", "cx.agent."],
            Self::SfuService => &["cx.media.", "cx.webrtc."],
            Self::TurnService => &["cx.media.ice_config"],
            Self::ModerationService => &["cx.moderation.", "cx.admin.get_moderation_queue"],
        }
    }

    /// Returns `true` when `operation_kind` is permitted to be
    /// advertised by a service of this type.
    pub fn permits_operation(&self, operation_kind: &str) -> bool {
        let prefixes = self.allowed_operation_prefixes();
        if prefixes.is_empty() {
            return true;
        }
        prefixes.iter().any(|prefix| {
            operation_kind == prefix.trim_end_matches('.') || operation_kind.starts_with(prefix)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ServiceEndpointBinding {
    pub service_did: Did,
    pub service_type: ServiceType,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ServiceDidAllowlist {
    #[serde(default)]
    pub services: BTreeMap<Did, ServiceEndpointBinding>,
}

impl ServiceDidAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(mut self, binding: ServiceEndpointBinding) -> Self {
        self.services.insert(binding.service_did.clone(), binding);
        self
    }

    pub fn insert(&mut self, binding: ServiceEndpointBinding) {
        self.services.insert(binding.service_did.clone(), binding);
    }

    pub fn contains(&self, service_did: &Did) -> bool {
        self.services.contains_key(service_did)
    }

    pub fn binding(&self, service_did: &Did) -> Option<&ServiceEndpointBinding> {
        self.services.get(service_did)
    }

    pub fn verify_description(&self, description: &ServerDescription) -> Result<()> {
        let binding = self.services.get(&description.service_did).ok_or_else(|| {
            Error::Protocol(format!("service DID {} is not allowlisted", description.service_did))
        })?;
        if description.service_type != binding.service_type.as_str() {
            return Err(Error::Protocol(format!(
                "service DID {} is allowlisted as {}, not {}",
                description.service_did,
                binding.service_type.as_str(),
                description.service_type
            )));
        }
        for operation in &binding.operations {
            if !description.supported_operations.iter().any(|actual| actual == operation) {
                return Err(Error::Protocol(format!(
                    "allowlisted service {} does not advertise operation {operation}",
                    description.service_did
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotFoundPrivacy {
    HideNonexistentAndInvisible,
    RevealForbiddenWhenAuthenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScopeKind {
    Actor,
    Ip,
    Device,
    ServiceDid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RateLimitMetadata {
    pub scope: RateLimitScopeKind,
    pub subject: String,
    pub limit: u64,
    pub remaining: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum QuotaKind {
    BlobBytes,
    AccountStorageBytes,
    OperationWindow,
    DeviceCount,
    OneTimeKeyCount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QuotaMetadata {
    pub quota: QuotaKind,
    pub subject: String,
    pub limit: u64,
    pub used: u64,
    pub unit: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct HttpTraceMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<CommitId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ApiConventionMetadata {
    pub not_found_privacy: NotFoundPrivacy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quotas: Vec<QuotaMetadata>,
    #[serde(default)]
    pub trace: HttpTraceMetadata,
}

pub fn privacy_preserving_not_found(trace: Option<HttpTraceMetadata>) -> ErrorEnvelope {
    let mut extra = BTreeMap::from([(
        "not_found_privacy".to_owned(),
        Value::String("hide_nonexistent_and_invisible".to_owned()),
    )]);
    if let Some(trace) = trace {
        extra.insert("trace".to_owned(), serde_json::to_value(trace).unwrap_or(Value::Null));
    }
    ErrorEnvelope {
        errcode: "cx.error.not_found".to_owned(),
        error: "Resource not found".to_owned(),
        retry_after_ms: None,
        extra,
    }
}

pub fn rate_limited_error(metadata: RateLimitMetadata) -> ErrorEnvelope {
    ErrorEnvelope {
        errcode: "cx.error.rate_limited".to_owned(),
        error: "Too many requests".to_owned(),
        retry_after_ms: metadata.retry_after_ms,
        extra: BTreeMap::from([(
            "rate_limit".to_owned(),
            serde_json::to_value(metadata).unwrap_or(Value::Null),
        )]),
    }
}

pub fn quota_exceeded_error(metadata: QuotaMetadata) -> ErrorEnvelope {
    ErrorEnvelope {
        errcode: "cx.error.quota_exceeded".to_owned(),
        error: "Quota exceeded".to_owned(),
        retry_after_ms: None,
        extra: BTreeMap::from([(
            "quota".to_owned(),
            serde_json::to_value(metadata).unwrap_or(Value::Null),
        )]),
    }
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

    pub fn verify(&self, description: &ServerDescription) -> Result<()> {
        if description.protocol_version != PROTOCOL_VERSION {
            return Err(Error::Protocol(format!(
                "service protocol_version {} does not match Contrix {PROTOCOL_VERSION}",
                description.protocol_version
            )));
        }

        if let Some(service_type) = &self.service_type {
            let expected = service_type.as_str();
            if description.service_type != expected {
                return Err(Error::Protocol(format!(
                    "service_type {} does not match expected {expected}",
                    description.service_type
                )));
            }
            // Cross-check the service-type capability matrix (T3-10):
            // refuse a description that advertises operations forbidden
            // for its declared `service_type` (e.g. an `applet_service`
            // must not advertise `cx.federation.transaction`).
            for op in &description.supported_operations {
                if !service_type.permits_operation(op) {
                    return Err(Error::Protocol(format!(
                        "service_type {} must not advertise operation {op}",
                        expected
                    )));
                }
            }
        }

        for profile in &self.profiles {
            if !description.supported_profiles.iter().any(|actual| actual == profile) {
                return Err(Error::Protocol(format!("service does not support profile {profile}")));
            }
        }

        for profile in &self.reducer_profiles {
            if !description.supported_reducer_profiles.iter().any(|actual| actual == profile) {
                return Err(Error::Protocol(format!(
                    "service does not support reducer profile {profile}"
                )));
            }
        }

        for profile in &self.schema_profiles {
            if !description.supported_schema_profiles.iter().any(|actual| actual == profile) {
                return Err(Error::Protocol(format!(
                    "service does not support schema profile {profile}"
                )));
            }
        }

        for operation in &self.operations {
            if !description.supported_operations.iter().any(|actual| actual == operation) {
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
    use serde_json::Value;

    use super::*;
    use crate::{Did, SpaceId};

    #[test]
    fn verifies_required_service_profile_and_operation() {
        let description = ServerDescription {
            service_did: Did::new("did:web:svc.example").unwrap(),
            service_type: "index_node".to_owned(),
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec!["cx.profile.index_node.v1".to_owned()],
            supported_features: vec![],
            supported_operations: vec!["cx.index.query".to_owned()],
            supported_bindings: vec![],
            supported_reducer_profiles: vec!["cx.reducer.v1".to_owned()],
            supported_schema_profiles: vec!["cx.schema.core.v1".to_owned()],
            auth_metadata: Value::Null,
            limits: Value::Null,
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            reducer_profile: None,
            last_materialized_at: None,
        };

        ServiceRequirements::new()
            .service_type(ServiceType::IndexNode)
            .profile("cx.profile.index_node.v1")
            .reducer_profile("cx.reducer.v1")
            .schema_profile("cx.schema.core.v1")
            .operation("cx.index.query")
            .verify(&description)
            .unwrap();
    }

    #[test]
    fn service_did_allowlist_verifies_description_and_operations() {
        let service_did = Did::new("did:web:svc.example").unwrap();
        let allowlist = ServiceDidAllowlist::new().allow(ServiceEndpointBinding {
            service_did: service_did.clone(),
            service_type: ServiceType::IndexNode,
            endpoint: "https://svc.example/api/v1/index".to_owned(),
            operations: vec!["cx.index.query".to_owned()],
        });
        let description = ServerDescription {
            service_did,
            service_type: "index_node".to_owned(),
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec![],
            supported_features: vec![],
            supported_operations: vec!["cx.index.query".to_owned()],
            supported_bindings: vec![],
            supported_reducer_profiles: vec![],
            supported_schema_profiles: vec![],
            auth_metadata: Value::Null,
            limits: Value::Null,
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            reducer_profile: None,
            last_materialized_at: None,
        };

        allowlist.verify_description(&description).unwrap();
    }

    #[test]
    fn api_metadata_errors_carry_privacy_rate_limit_quota_and_trace() {
        let trace = HttpTraceMetadata {
            request_id: Some("req_123".to_owned()),
            actor_id: Some(Did::new("did:web:alice.example").unwrap()),
            device_id: None,
            space_id: Some(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap()),
            operation_id: None,
            commit_id: None,
        };
        let not_found = privacy_preserving_not_found(Some(trace));
        assert_eq!(not_found.errcode, "cx.error.not_found");
        assert_eq!(not_found.extra["not_found_privacy"], "hide_nonexistent_and_invisible");
        assert!(not_found.extra["trace"].is_object());

        let rate_limited = rate_limited_error(RateLimitMetadata {
            scope: RateLimitScopeKind::Actor,
            subject: "did:web:alice.example".to_owned(),
            limit: 60,
            remaining: 0,
            reset_at: None,
            retry_after_ms: Some(1000),
        });
        assert_eq!(rate_limited.retry_after_ms, Some(1000));
        assert_eq!(rate_limited.extra["rate_limit"]["scope"], "actor");

        let quota = quota_exceeded_error(QuotaMetadata {
            quota: QuotaKind::BlobBytes,
            subject: "did:web:alice.example".to_owned(),
            limit: 1024,
            used: 2048,
            unit: "bytes".to_owned(),
        });
        assert_eq!(quota.extra["quota"]["quota"], "blob_bytes");
    }
}
