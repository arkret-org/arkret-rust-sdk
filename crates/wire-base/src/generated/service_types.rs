//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/service-type-registry.json; version=2026-07-15; sha256=67cd0bf6f1071d1f7398bec7f01295d325e6e23c4bfc3dba0dc9ea074d0f4cc7
//! Entries: active=22

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum ServiceType {
    AgentRuntime,
    AppletService,
    ArchiveNode,
    AuthServer,
    AuthzService,
    BlobNode,
    DeviceKeyService,
    DirectoryService,
    IdentityRegistry,
    KeyRecoveryService,
    MediaService,
    MimiProviderFacade,
    ModerationService,
    Notary,
    PolicyServer,
    PrincipalServer,
    PushGateway,
    RecoveryService,
    SearchService,
    SfuService,
    SyncNode,
    TurnService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceTypeDescriptor {
    pub service_type: ServiceType,
    pub valid_in: &'static [&'static str],
    pub description: &'static str,
}

impl ServiceType {
    pub const ALL: &'static [Self] = &[
        Self::AgentRuntime,
        Self::AppletService,
        Self::ArchiveNode,
        Self::AuthServer,
        Self::AuthzService,
        Self::BlobNode,
        Self::DeviceKeyService,
        Self::DirectoryService,
        Self::IdentityRegistry,
        Self::KeyRecoveryService,
        Self::MediaService,
        Self::MimiProviderFacade,
        Self::ModerationService,
        Self::Notary,
        Self::PolicyServer,
        Self::PrincipalServer,
        Self::PushGateway,
        Self::RecoveryService,
        Self::SearchService,
        Self::SfuService,
        Self::SyncNode,
        Self::TurnService,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentRuntime => "agent_runtime",
            Self::AppletService => "applet_service",
            Self::ArchiveNode => "archive_node",
            Self::AuthServer => "auth_server",
            Self::AuthzService => "authz_service",
            Self::BlobNode => "blob_node",
            Self::DeviceKeyService => "device_key_service",
            Self::DirectoryService => "directory_service",
            Self::IdentityRegistry => "identity_registry",
            Self::KeyRecoveryService => "key_recovery_service",
            Self::MediaService => "media_service",
            Self::MimiProviderFacade => "mimi_provider_facade",
            Self::ModerationService => "moderation_service",
            Self::Notary => "notary",
            Self::PolicyServer => "policy_server",
            Self::PrincipalServer => "principal_server",
            Self::PushGateway => "push_gateway",
            Self::RecoveryService => "recovery_service",
            Self::SearchService => "search_service",
            Self::SfuService => "sfu_service",
            Self::SyncNode => "sync_node",
            Self::TurnService => "turn_service",
        }
    }

    pub fn descriptor(self) -> &'static ServiceTypeDescriptor {
        &SERVICE_TYPE_DESCRIPTORS[self as usize]
    }

    pub fn valid_in(self, context: &str) -> bool {
        self.descriptor().valid_in.contains(&context)
    }
}

pub const SERVICE_TYPE_DESCRIPTORS: &[ServiceTypeDescriptor] = &[
    ServiceTypeDescriptor {
        service_type: ServiceType::AgentRuntime,
        valid_in: &["service_describe"],
        description: "Agent execution runtime.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::AppletService,
        valid_in: &["service_describe"],
        description: "Applet / third-party bridge edge surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::ArchiveNode,
        valid_in: &["service_describe", "realm_sync_endpoint"],
        description: "Long-term archive storage and retrieval surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::AuthServer,
        valid_in: &["service_describe", "service_registration_key"],
        description: "OIDC / token issuance and account lifecycle. Hosts no DID documents of its own; obtains its service DID from an external Service Identity Provider.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::AuthzService,
        valid_in: &["service_describe"],
        description: "Authorization evaluation surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::BlobNode,
        valid_in: &["service_describe"],
        description: "Blob storage surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::DeviceKeyService,
        valid_in: &["service_describe"],
        description: "Device signing-key directory surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::DirectoryService,
        valid_in: &["service_describe"],
        description: "Discovery ingest/query with anti-enumeration and takedown audit.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::IdentityRegistry,
        valid_in: &["service_describe", "service_registration_key"],
        description: "Standalone did:webvh registry: DID documents, key logs, receipts, watcher/mirror. Self-hosts its own service DID through its local store.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::KeyRecoveryService,
        valid_in: &["service_describe", "realm_sync_endpoint"],
        description: "Cryptographic key backup and recovery surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::MediaService,
        valid_in: &["service_describe"],
        description: "Media upload / transform / delivery surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::MimiProviderFacade,
        valid_in: &["mimi_provider_directory"],
        description: "MIMI interop provider facade. Deliberately NOT valid_in service_describe: it names a facade role inside the MIMI provider-directory descriptor, not a standalone Arkret service describing itself.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::ModerationService,
        valid_in: &["service_describe"],
        description: "Moderation surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::Notary,
        valid_in: &["service_describe", "realm_sync_endpoint", "realm_join_candidate"],
        description: "Seal and state-attestation notary surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::PolicyServer,
        valid_in: &["service_describe"],
        description: "Policy distribution and evaluation surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::PrincipalServer,
        valid_in: &["service_describe", "realm_sync_endpoint", "realm_join_candidate", "service_registration_key"],
        description: "Account-owning home server: event ingestion, sync, authz projections, key backup, federation. Also acts as an embedded did:webvh host for the identities it serves, which is why it is valid_in service_registration_key both as a subject and as a Service Identity Provider.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::PushGateway,
        valid_in: &["service_describe"],
        description: "Push provider dispatch gateway.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::RecoveryService,
        valid_in: &["service_describe", "realm_sync_endpoint"],
        description: "Account recovery orchestration surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::SearchService,
        valid_in: &["service_describe", "realm_sync_endpoint"],
        description: "Search indexing and query surface.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::SfuService,
        valid_in: &["service_describe"],
        description: "Selective forwarding unit for calls.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::SyncNode,
        valid_in: &["service_describe", "realm_sync_endpoint", "realm_join_candidate"],
        description: "Event sync surface without account authority.",
    },
    ServiceTypeDescriptor {
        service_type: ServiceType::TurnService,
        valid_in: &["service_describe"],
        description: "TURN / ICE relay surface.",
    },
];
