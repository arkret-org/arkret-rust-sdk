use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    PrincipalServer,
    IdentityRegistry,
    AuthServer,
    SyncNode,
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

    pub fn allowed_operation_prefixes(&self) -> &'static [&'static str] {
        match self {
            Self::PrincipalServer => &[
                "ak.self.account.",
                "ak.self.authz.",
                "ak.self.blob.",
                "ak.self.call.",
                "ak.self.events.",
                "ak.self.keys.",
                "ak.self.moderation.",
                "ak.self.policy.",
                "ak.self.snapshot.",
                "ak.policy.",
                "ak.identity.",
                "ak.account_data.",
            ],
            Self::IdentityRegistry => &["ak.root.identity.", "ak.identity."],
            Self::AuthServer => &["ak.gate.account.", "ak.self.policy.query.check"],
            Self::SyncNode => &["ak.self.events.", "ak.self.account.", "ak.self.snapshot."],
            Self::BlobNode => &["ak.self.blob."],
            Self::MediaService => &["ak.self.media.", "ak.self.call.media."],
            Self::DirectoryService => &["ak.find.directory."],
            Self::DeviceKeyService => &["ak.self.keys."],
            Self::AuthzService => &["ak.self.authz.", "ak.self.policy.", "ak.policy."],
            Self::PolicyServer => &["ak.self.policy.", "ak.policy."],
            Self::PushGateway => &["ak.edge.push."],
            Self::AppletService => &["ak.edge.applet."],
            Self::AgentRuntime => &["ak.self.agent.", "ak.gate.account.command.pair_agent_key"],
            Self::SfuService => &["ak.self.call.media.", "ak.self.media."],
            Self::TurnService => &["ak.self.media.query.ice_config"],
            Self::ModerationService => &["ak.self.moderation."],
        }
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EvaluationClass {
    Stateless,
    GrantLocal,
    RealmState,
    External,
}
