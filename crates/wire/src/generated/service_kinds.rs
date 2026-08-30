//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/service-kind-registry.json; version=2026-08-30.5;
//! sha256=3ba6fc77e9034642544b6077a69f5c38210c14117c0c010ad3ffe9af243abf04 Entries: active=16

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ServiceKind {
    AgentRuntime,
    AppletService,
    ArchiveNode,
    BlobNode,
    DirectoryService,
    IdentityRegistry,
    KeyRecoveryService,
    MediaService,
    MimiProviderFacade,
    ModerationService,
    Notary,
    PushGateway,
    RecoveryService,
    SfuService,
    Station,
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
        Self::BlobNode,
        Self::DirectoryService,
        Self::IdentityRegistry,
        Self::KeyRecoveryService,
        Self::MediaService,
        Self::MimiProviderFacade,
        Self::ModerationService,
        Self::Notary,
        Self::PushGateway,
        Self::RecoveryService,
        Self::SfuService,
        Self::Station,
        Self::TurnService,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentRuntime => "agent_runtime",
            Self::AppletService => "applet_service",
            Self::ArchiveNode => "archive_node",
            Self::BlobNode => "blob_node",
            Self::DirectoryService => "directory_service",
            Self::IdentityRegistry => "identity_registry",
            Self::KeyRecoveryService => "key_recovery_service",
            Self::MediaService => "media_service",
            Self::MimiProviderFacade => "mimi_provider_facade",
            Self::ModerationService => "moderation_service",
            Self::Notary => "notary",
            Self::PushGateway => "push_gateway",
            Self::RecoveryService => "recovery_service",
            Self::SfuService => "sfu_service",
            Self::Station => "station",
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
        service_kind: ServiceKind::BlobNode,
        valid_in: &["service_describe"],
        description: "Blob storage surface.",
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
        service_kind: ServiceKind::SfuService,
        valid_in: &["service_describe"],
        description: "Selective forwarding unit for calls.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::Station,
        valid_in: &[
            "service_describe",
            "realm_join_candidate",
            "service_registration_key",
        ],
        description: "Authoritative Station for closed AccountId pairs: business data, account and Event admission, client sync, federation, authz, device/key state, queues, cursors, and Account Authority discovery. Internal Auth, policy, sync, federation, and key processes do not acquire separate service kinds. A Station may also act as an embedded did:webvh host for identities it serves.",
    },
    ServiceKindDescriptor {
        service_kind: ServiceKind::TurnService,
        valid_in: &["service_describe"],
        description: "TURN / ICE relay surface.",
    },
];
