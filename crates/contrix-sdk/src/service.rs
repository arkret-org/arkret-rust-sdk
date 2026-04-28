use serde::{Deserialize, Serialize};

use crate::{Error, PROTOCOL_VERSION, Result, ServerDescription};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    use crate::Did;

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
}
