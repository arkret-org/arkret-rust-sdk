//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-08.1;
//! sha256=819dba54cb38a1208e5cf2c4d6a94e3ca8b8f14fee9d0059988cca2cf31afc61
//! Entries: operation_bundles=36 features=21

use crate::{BindingKind, ServiceKind, ServiceOperationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationBindingPair {
    pub operation_id: ServiceOperationId,
    pub binding_kind: BindingKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationBundleDescriptor {
    pub operation_bundle_id: &'static str,
    pub service_kind: ServiceKind,
    pub members: &'static [OperationBindingPair],
}
impl OperationBundleDescriptor {
    pub fn contains(&self, operation_id: ServiceOperationId, binding_kind: BindingKind) -> bool {
        self.members
            .iter()
            .any(|pair| pair.operation_id == operation_id && pair.binding_kind == binding_kind)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureStatus {
    Active,
    Experimental,
    TestOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureDescriptor {
    pub feature_id: &'static str,
    pub status: FeatureStatus,
    pub defined_in: &'static str,
    pub service_kinds: &'static [ServiceKind],
    pub required_operation_pairs: &'static [OperationBindingPair],
    pub required_profiles: &'static [&'static str],
    pub required_limits: &'static [&'static str],
    pub semantic_guarantees: &'static [&'static str],
    pub conflicts: &'static [&'static str],
}

pub const OPERATION_BUNDLES: &[OperationBundleDescriptor] = &[
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.agent_runtime.describe.v1",
        service_kind: ServiceKind::AgentRuntime,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.applet_service.describe.v1",
        service_kind: ServiceKind::AppletService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.archive_node.describe.v1",
        service_kind: ServiceKind::ArchiveNode,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.blob_node.describe.v1",
        service_kind: ServiceKind::BlobNode,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.directory_service.describe.v1",
        service_kind: ServiceKind::DirectoryService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.directory_service.http_core.v1",
        service_kind: ServiceKind::DirectoryService,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryCommandAnnounceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryCommandWithdrawV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryPushCommandRegisterV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadListHandlesForSubjectV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadResolveHandleV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadResolveOrganizationV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadResolveRealmV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadResolveTargetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadSearchActorsV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadSearchOrganizationsV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadSearchRealmsV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadSearchUsersV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.directory_service.private_contact_discovery.v1",
        service_kind: ServiceKind::DirectoryService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::FindDirectoryReadPrivateContactDiscoveryV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.directory_service.resolve_agent_selector.v1",
        service_kind: ServiceKind::DirectoryService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::FindDirectoryReadResolveAgentSelectorV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.identity_registry.describe.v1",
        service_kind: ServiceKind::IdentityRegistry,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.identity_registry.http_core.v1",
        service_kind: ServiceKind::IdentityRegistry,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityCommandSubmitDidOperationV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityDocumentResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityLogReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::RootIdentityOrganizationRegistrationCommandEnsureV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::RootIdentityOrganizationRegistrationCommandPrepareV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::RootIdentityOrganizationRegistrationCommandRefreshV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::RootIdentityOrganizationRegistrationCommandRevokeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityOrganizationRegistrationResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityReceiptsReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRecoveryPolicyCommandPublishV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRecoveryPolicyResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRecoverySessionCommandCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProofV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRecoverySessionResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRegistryReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityServiceRegistrationCommandEnsureV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityServiceRegistrationResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.key_recovery_service.describe.v1",
        service_kind: ServiceKind::KeyRecoveryService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.media_service.describe.v1",
        service_kind: ServiceKind::MediaService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.moderation_service.describe.v1",
        service_kind: ServiceKind::ModerationService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.notary.describe.v1",
        service_kind: ServiceKind::Notary,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.push_gateway.describe.v1",
        service_kind: ServiceKind::PushGateway,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.push_gateway.http_notify.v1",
        service_kind: ServiceKind::PushGateway,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::EdgePushCommandNotifyV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.recovery_service.describe.v1",
        service_kind: ServiceKind::RecoveryService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.sfu_service.describe.v1",
        service_kind: ServiceKind::SfuService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.account_authority.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandAbandonIdentityCreationV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::GateAccountCommandIssueControllerGateAttestationV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandIssueDidBindingChallengeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::GateAccountCommandIssueIdentityAbandonmentChallengeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandRequestErasureV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountReadOnboardingV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.account_authority_support.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::FindDirectoryReadResolveHandleV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandIntrospectSessionGrantV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandIssueIdentityBindingChallengeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandIssueRecoveryCompletionGrantV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandIssueSessionGrantV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandLogoutAuthSessionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandRefreshSessionGrantV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandRegisterV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountExchangeCreateHandoffV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityDocumentResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::RootIdentityRegistryReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.agent_pairing_handoff.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenAgentPairingReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenAgentPairingReadRuntimeKeyRequestStatusV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.agent_runtime.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandPairAgentKeyV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentCommandDeactivateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentCommandPauseV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentCommandProvisionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentCommandRenewPairingV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentCommandResumeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentParticipationResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentParticipationResourceReplaceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentSidecarCommandEnsureV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentSidecarReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentSidecarResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.applet.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletActorReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletCommandTransactionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletManagedActorCommandAuthorV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletReadPingV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletReadProtocolMetadataV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletRealmReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletThirdPartyLocationsReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgeAppletThirdPartyUsersReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.applet_ghost.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletGhostCommandPreviewV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletGhostCommandProvisionV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.applet_install.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletCommandInstallV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletCommandRevokeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletInstallCommandPreviewV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAppletRevokeCommandPreviewV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.current_signer_evidence.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerCurrentSignerEvidenceReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCurrentSignerEvidenceReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.describe.v1",
        service_kind: ServiceKind::Station,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.device_pairing_handoff.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenDevicePairingCommandStageV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenDevicePairingReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenDevicePairingReadStatusV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.history_key_recovery.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerHistoryKeyRequestsCommandReplicateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerHistoryKeyResponsesCommandRelayV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::PeerOrganizationRecoveryArchivesCommandReplicateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadGovernanceDependenciesV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadMlsGovernanceProofV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyRequestsCommandCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyRequestsReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesCommandAckV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesCommandSendV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfOrganizationRecoveryArchivesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.http_core.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandLogoutV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandPairDeviceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::GateAccountCommandRevokeSessionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenIdentityReadResolutionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenInviteLocatorReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenServiceReadResolutionV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerAccountStatusCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerAccountStatusReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerContactsCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerDeviceRevocationsCommandCheckV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerErasureReceiptCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerErasureReceiptResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerEventsCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerEventsReadFrontierV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerEventsReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerEventsReadScanV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerEventsReadSiblingPositionsV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerInvitesCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerKeysKeypackagesCommandClaimV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerKeysKeypackagesReadClaimV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerMlsReadGroupStateMaterialV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerPrincipalGenesisCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadFrontierV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerServiceResolutionCommandPublishV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerServiceResolutionReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSignalCommandRelayV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountCommandRevokeCursorV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountCommandUpdateProfileV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountReadViewerV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountStreamSubscribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountDataReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountDataResourceDeleteV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountDataResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountDataResourceReplaceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfActorProfileReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAgentSignerEvidenceReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAuthorizationLeasesCommandIssueV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAuthzGrantsReadEffectiveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAuthzInvitesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAuthzReadCheckV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfBlobCommandPresignV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfBlobResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfBlobResourceHeadV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfBlobUploadCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCallMediaExchangeIssueTokenV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleCommandCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleCommandRotateScopeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleMemberCommandAddV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleMemberResourceDeleteV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfCircleResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfConsentCommandGrantV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfConsentCommandRequestV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfConsentCommandRevokeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfConsentReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfConsentResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandCheckpointV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandRejectV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandRequestV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandRespondV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandScopeUpdateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactCommandTombstoneV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfContactReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfControlProposalAcksCommandIssueV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfControlProposalDecisionsCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfControlProposalDecisionsReadGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfDeviceMessagesCommandAckV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfDeviceMessagesCommandSendV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfDeviceMessagesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfDirectConversationReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsReadDeliveryStatusV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsReadDescribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsReadFrontierV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsReadScanV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsStreamSubscribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfIdentityReadResolutionAuditV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInviteLocatorCommandIssueV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInviteLocatorCommandRevokeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInviteLocatorCommandRotateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInviteReceivePolicyResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInviteReceivePolicyResourceReplaceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfInvitesCommandDispatchV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupSeriesCommandEraseV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupsCommandIssueDeleteChallengeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupsCommandUnlockV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupsReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupsResourceDeleteV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysBackupsResourceReplaceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysCommandClaimV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysReadLookupV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfKeysUploadCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfMediaReadIceConfigV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfModerationCommandReportV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfModerationReadFrankingSealObservationV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfMorphReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfMorphResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfReadCursorCommandAdvanceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfReadCursorReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmReadExportV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmResourceGetV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmLinkReadEffectivePolicyV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmLinkReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmOrganizationReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsCommandIssueAvailabilityReceiptsV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsCommandSubmitV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsReadFrontierV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsReadGovernanceDependenciesV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsReadMlsGovernanceProofV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSealsReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSignalCommandSendV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSignalStreamSubscribeV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSpaceReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfStrandReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.mimi_interop.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandNotifyV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandProxyDownloadV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandReportAbuseV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandRequestConsentV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandSubmitMessageV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandUpdateConsentV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiCommandUpdateRoomV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiExchangeRequestKeyMaterialV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiReadIdentifiersV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::OpenMimiReadProviderDirectoryV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.push.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgePushCommandNotifyV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgePushCommandRegisterDeviceV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::EdgePushCommandUnregisterDeviceV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.third_party_invite_handoff.v1",
        service_kind: ServiceKind::Station,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::OpenThirdPartyInviteCommandPresentTokenV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.tus_upload.v1",
        service_kind: ServiceKind::Station,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfBlobUploadCreateV1,
            binding_kind: BindingKind::Tus,
        }],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.station.websocket.v1",
        service_kind: ServiceKind::Station,
        members: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfAccountStreamSubscribeV1,
                binding_kind: BindingKind::Websocket,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfEventsStreamSubscribeV1,
                binding_kind: BindingKind::Websocket,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfSignalStreamSubscribeV1,
                binding_kind: BindingKind::Websocket,
            },
        ],
    },
    OperationBundleDescriptor {
        operation_bundle_id: "ak.operation_bundle.turn_service.describe.v1",
        service_kind: ServiceKind::TurnService,
        members: &[OperationBindingPair {
            operation_id: ServiceOperationId::ServerReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
    },
];

pub fn operation_bundle_descriptor(
    operation_bundle_id: &str,
) -> Option<&'static OperationBundleDescriptor> {
    OPERATION_BUNDLES
        .binary_search_by_key(&operation_bundle_id, |row| row.operation_bundle_id)
        .ok()
        .map(|index| &OPERATION_BUNDLES[index])
}
pub fn operation_bundles_for_service_kind(
    service_kind: ServiceKind,
) -> impl Iterator<Item = &'static OperationBundleDescriptor> {
    OPERATION_BUNDLES
        .iter()
        .filter(move |bundle| bundle.service_kind == service_kind)
}
pub fn role_describe_bundle_descriptor(
    service_kind: ServiceKind,
) -> Option<&'static OperationBundleDescriptor> {
    operation_bundles_for_service_kind(service_kind)
        .find(|bundle| bundle.operation_bundle_id.ends_with(".describe.v1"))
}
pub fn operation_binding_is_registered(
    operation_id: ServiceOperationId,
    binding_kind: BindingKind,
) -> bool {
    OPERATION_BUNDLES
        .iter()
        .any(|bundle| bundle.contains(operation_id, binding_kind))
}

pub const FEATURES: &[FeatureDescriptor] = &[
    FeatureDescriptor {
        feature_id: "ak.feature.agent_runtime_approval_notifications.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/client-sync.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Agent runtime approval transitions emit the normative user-visible notification surface.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.blob.resumable_upload.tus.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/crypto-media/media-and-blob.md#21-可续传上传resumable-upload-bindingoptional-extension",
        service_kinds: &[],
        required_operation_pairs: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfBlobUploadCreateV1,
            binding_kind: BindingKind::Tus,
        }],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.cursor_revoke_high_assurance.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/client-sync.md#1221-high-assurance-cursor-revoke",
        service_kinds: &[],
        required_operation_pairs: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfAccountCommandRevokeCursorV1,
            binding_kind: BindingKind::HttpJson,
        }],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.detached_jws.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/conformance/encoding.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Detached JWS inputs and verification results follow the canonical Arkret detached-signature transcript.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.direct_conversation_realm_role.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/identity/contact-and-direct-conversation.md",
        service_kinds: &[],
        required_operation_pairs: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfDirectConversationReadResolveV1,
            binding_kind: BindingKind::HttpJson,
        }],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.e2ee_relaxed.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/crypto-media/encryption-and-audit.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "The deployment supports the explicitly relaxed E2EE policy branch defined by the normative encryption contract.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.example.unknown.v1",
        status: FeatureStatus::TestOnly,
        defined_in: "artifacts/fixtures/schema-validation-fixture.json",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.future_optional.v1",
        status: FeatureStatus::TestOnly,
        defined_in: "artifacts/fixtures/event-envelope-negative-fixture.json",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.future_required.v1",
        status: FeatureStatus::TestOnly,
        defined_in: "artifacts/fixtures/event-envelope-negative-fixture.json",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.history_key_recovery.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/governance/history-visibility.md",
        service_kinds: &[],
        required_operation_pairs: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerHistoryKeyRequestsCommandReplicateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerHistoryKeyResponsesCommandRelayV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id:
                    ServiceOperationId::PeerOrganizationRecoveryArchivesCommandReplicateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadGovernanceDependenciesV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerSealsReadMlsGovernanceProofV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyRequestsCommandCreateV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyRequestsReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesCommandAckV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesCommandSendV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfHistoryKeyResponsesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::SelfOrganizationRecoveryArchivesReadListV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Eligible members can execute the normative private history-key recovery protocol.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.identity.webvh_native_log.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/identity/identity-did.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Identity resolution verifies and serves the native did:webvh log contract.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.invite_addressing.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/invite-addressing.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Invite addressing accepts only the registered introduction kinds and advertised maximum-behavior policy.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.message_content_block.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/models/strand-and-message.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Message bodies accept the versioned Content Block structural contract.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.mls_exporter_aead.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/crypto-media/encryption-and-audit.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Application encryption derives AEAD material through the registered MLS exporter labels.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.mls_governance_binding.full.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/crypto-media/encryption-and-audit.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "MLS epochs are fully bound to the accepted Arkret governance frontier.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.mls_last_resort_keypackage.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/crypto-media/encryption-and-audit.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Last-resort KeyPackages follow the replay, consumption, and rotation rules of the normative MLS contract.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.notifications.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/client-sync.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "The deployment can emit the normative notification projection without implying push transport support.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.realm_service_resolution_mirror.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/service-surface.md",
        service_kinds: &[],
        required_operation_pairs: &[],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[
            "Realm service-resolution state is mirrored with the normative authenticated frontier semantics.",
        ],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.realm_state_snapshot.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/service-surface.md",
        service_kinds: &[],
        required_operation_pairs: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1,
            binding_kind: BindingKind::HttpJson,
        }],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.service_route_handover.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/service-surface.md",
        service_kinds: &[],
        required_operation_pairs: &[
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerServiceResolutionCommandPublishV1,
                binding_kind: BindingKind::HttpJson,
            },
            OperationBindingPair {
                operation_id: ServiceOperationId::PeerServiceResolutionReadResolveV1,
                binding_kind: BindingKind::HttpJson,
            },
        ],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
    FeatureDescriptor {
        feature_id: "ak.feature.sync_stream.v1",
        status: FeatureStatus::Active,
        defined_in: "zh/sync/client-sync.md",
        service_kinds: &[],
        required_operation_pairs: &[OperationBindingPair {
            operation_id: ServiceOperationId::SelfAccountStreamSubscribeV1,
            binding_kind: BindingKind::HttpJson,
        }],
        required_profiles: &[],
        required_limits: &[],
        semantic_guarantees: &[],
        conflicts: &[],
    },
];

pub fn feature_descriptor(feature_id: &str) -> Option<&'static FeatureDescriptor> {
    FEATURES
        .binary_search_by_key(&feature_id, |row| row.feature_id)
        .ok()
        .map(|index| &FEATURES[index])
}
