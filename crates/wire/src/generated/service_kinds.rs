//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/service-kind-registry.json; version=2026-08-30.4;
//! sha256=6179fd41e555ff44af8d2674f087ac3a218df968f8f7dc810ff7688941700531 Entries: active=20

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ServiceKind {
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
    PrincipalServer,
    PushGateway,
    RecoveryService,
    SearchService,
    SfuService,
    TurnService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceKindDescriptor {
    pub service_kind: ServiceKind,
    pub valid_in: &'static [&'static str],
    pub description: &'static str,
}

impl ServiceKind {
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
        Self::PrincipalServer,
        Self::PushGateway,
        Self::RecoveryService,
        Self::SearchService,
        Self::SfuService,
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
            Self::PrincipalServer => "principal_server",
            Self::PushGateway => "push_gateway",
            Self::RecoveryService => "recovery_service",
            Self::SearchService => "search_service",
            Self::SfuService => "sfu_service",
            Self::TurnService => "turn_service",
        }
    }

    pub fn descriptor(self) -> &'static ServiceKindDescriptor {
        &SERVICE_KIND_DESCRIPTORS[self as usize]
    }

    pub fn valid_in(self, context: &str) -> bool {
        self.descriptor().valid_in.contains(&context)
    }
}

pub const SERVICE_KIND_DESCRIPTORS: &[ServiceKindDescriptor] = &[
    ServiceKindDescriptor {
        service_kind: ServiceKind::AgentRuntime,
        valid_in: &["service_describe"],
        description: "Agent execution runtime.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::AppletService,
        valid_in: &["service_describe"],
        description: "Applet / third-party bridge edge surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::ArchiveNode,
        valid_in: &["service_describe"],
        description: "Long-term archive storage and retrieval surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::AuthServer,
        valid_in: &["service_describe", "service_registration_key"],
        description: "OIDC / token issuance and account lifecycle. Hosts no DID documents of its own; obtains its service DID from an external Service Identity Provider.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::AuthzService,
        valid_in: &["service_describe"],
        description: "Authorization evaluation surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::BlobNode,
        valid_in: &["service_describe"],
        description: "Blob storage surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::DeviceKeyService,
        valid_in: &["service_describe"],
        description: "Device signing-key directory surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::DirectoryService,
        valid_in: &["service_describe"],
        description: "Discovery ingest/query with anti-enumeration and takedown audit.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::IdentityRegistry,
        valid_in: &["service_describe", "service_registration_key"],
        description: "Standalone did:webvh registry: DID documents, key logs, receipts, watcher/mirror. Self-hosts its own service DID through its local store.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::KeyRecoveryService,
        valid_in: &["service_describe"],
        description: "Cryptographic key backup and recovery surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::MediaService,
        valid_in: &["service_describe"],
        description: "Media upload / transform / delivery surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::MimiProviderFacade,
        valid_in: &["mimi_provider_directory"],
        description: "MIMI interop provider facade. Deliberately NOT valid_in service_describe: it names a facade role inside the MIMI provider-directory descriptor, not a standalone Arkret service describing itself.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::ModerationService,
        valid_in: &["service_describe"],
        description: "Moderation surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::Notary,
        valid_in: &["service_describe"],
        description: "Seal and state-attestation notary surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::PrincipalServer,
        valid_in: &[
            "service_describe",
            "realm_join_candidate",
            "service_registration_key",
        ],
        description: "Account-owning home server: event ingestion, sync, authz projections, key backup, federation. Also acts as an embedded did:webvh host for the identities it serves, which is why it is valid_in service_registration_key both as a subject and as a Service Identity Provider.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::PushGateway,
        valid_in: &["service_describe"],
        description: "Push provider dispatch gateway.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::RecoveryService,
        valid_in: &["service_describe"],
        description: "Account recovery orchestration surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::SearchService,
        valid_in: &["service_describe"],
        description: "Search indexing and query surface.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::SfuService,
        valid_in: &["service_describe"],
        description: "Selective forwarding unit for calls.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::TurnService,
        valid_in: &["service_describe"],
        description: "TURN / ICE relay surface.",
    },
];
