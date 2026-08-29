use serde::{Deserialize, Serialize};

pub use crate::generated::service_kinds::{
    SERVICE_KIND_DESCRIPTORS, ServiceKind, ServiceKindDescriptor,
};

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ServiceKind {
    /// Product policy projection for operations this deployed role may advertise.
    ///
    /// This is intentionally separate from registry context metadata.
    pub fn allowed_operation_prefixes(self) -> &'static [&'static str] {
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
                "ak.root.identity.service_registration.",
            ],
            Self::IdentityRegistry => &["ak.root.identity.", "ak.identity."],
            Self::AuthServer => &["ak.gate.account."],
            Self::BlobNode => &["ak.self.blob."],
            Self::MediaService => &["ak.self.media.", "ak.self.call.media."],
            Self::MimiProviderFacade => &["ak.open.mimi."],
            Self::DirectoryService => &["ak.find.directory."],
            Self::DeviceKeyService => &["ak.self.keys."],
            Self::AuthzService => &["ak.self.authz.", "ak.policy."],
            Self::PushGateway => &["ak.edge.push."],
            Self::AppletService => &["ak.edge.applet."],
            Self::AgentRuntime => &[
                "ak.self.agent.",
                crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            ],
            Self::SfuService => &["ak.self.call.media.", "ak.self.media."],
            Self::TurnService => &[crate::ServiceOperationId::SELF_MEDIA_READ_ICE_CONFIG_V1],
            Self::ModerationService => &["ak.self.moderation."],
            Self::Notary | Self::SearchService | Self::ArchiveNode => &[],
            Self::KeyRecoveryService | Self::RecoveryService => &[
                "ak.root.identity.recovery_policy.",
                "ak.root.identity.recovery_session.",
            ],
        }
    }

    pub fn permits_operation(self, operation_kind: &str) -> bool {
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
#[serde(rename_all = "snake_case")]
pub enum EvaluationClass {
    Stateless,
    GrantLocal,
    RealmState,
    External,
}
