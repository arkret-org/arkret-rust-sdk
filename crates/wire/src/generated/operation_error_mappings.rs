//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/operation-registry.json; version=2026-08-12.2;
//! sha256=e7c3c9074162b355ebb2f1873877624279240179b25257cf157a36e644978451 Input: registry/
//! operations-error-mapping.json; version=2026-08-12.2;
//! sha256=c0c20a7f2abb4d5bcd0ad2d964f9fbb1be087dd2a691cbf5b122231e3d27ec74 Input: registry/
//! error-code-registry.json; version=2026-08-11.3;
//! sha256=200f0d443eeae73aa77c6e42fc7b909b1b191a13560be6052a961f83d03cb878 Entries: operations=237

use crate::{ErrorCode, ReasonCode, ServiceOperationId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationSpecificError {
    ErrorCode(ErrorCode),
    ReasonCode(ReasonCode),
}

impl OperationSpecificError {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ErrorCode(code) => code.as_str(),
            Self::ReasonCode(code) => code.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationErrorMappingDescriptor {
    pub operation: ServiceOperationId,
    pub operation_specific: &'static [OperationSpecificError],
}

pub const OPERATION_ERROR_MAPPINGS: &[OperationErrorMappingDescriptor] = &[
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletActorReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletCommandTransaction,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::HttpSignatureRequired),
            OperationSpecificError::ErrorCode(ErrorCode::HttpSignatureInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureWindowInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::AppletRegistrationUnauthorized),
            OperationSpecificError::ReasonCode(ReasonCode::AppletNamespaceMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletReadPing,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletReadProtocolMetadata,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletRealmReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletThirdPartyLocationsReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgeAppletThirdPartyUsersReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgePushCommandNotify,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::PushGatewayUnreachable),
            OperationSpecificError::ErrorCode(ErrorCode::PushTargetUnknown),
            OperationSpecificError::ErrorCode(ErrorCode::PushPayloadTooLarge),
            OperationSpecificError::ErrorCode(ErrorCode::ProfileUnsupported),
            OperationSpecificError::ErrorCode(ErrorCode::DeliveryBindingStale),
            OperationSpecificError::ErrorCode(ErrorCode::PushTokenUnknown),
            OperationSpecificError::ErrorCode(ErrorCode::PushTokenInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgePushCommandRegisterDevice,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::PushGatewayUnreachable),
            OperationSpecificError::ErrorCode(ErrorCode::PushTokenInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::EdgePushCommandUnregisterDevice,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::PushTokenUnknown,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryCommandAnnounce,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DirectoryNotAuthorized),
            OperationSpecificError::ErrorCode(ErrorCode::AcceptPolicyDenied),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureStale),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::GovernanceKeyInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::TtlOutOfRange),
            OperationSpecificError::ErrorCode(ErrorCode::TakedownInForce),
            OperationSpecificError::ErrorCode(ErrorCode::PolicyRevisionRollback),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryCommandTakedownAppeal,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::DirectoryNotAuthorized),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureStale),
            OperationSpecificError::ErrorCode(ErrorCode::GovernanceKeyInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::TakedownInForce),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryCommandWithdraw,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DirectoryNotAuthorized),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryPushCommandRegister,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadListHandlesForSubject,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadPrivateContactDiscovery,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::PsiQuotaExhausted),
            OperationSpecificError::ErrorCode(ErrorCode::PsiBatchUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::PolicyDenied),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadResolveAgentSelector,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadResolveHandle,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::HandleUnverified),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadResolveOrganization,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadResolveRealm,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadResolveTarget,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadSearchActors,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadSearchOrganizations,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadSearchRealms,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::FindDirectoryReadSearchUsers,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandAbandonIdentityCreation,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationLeaseFenced),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationChallengeExpired),
            OperationSpecificError::ReasonCode(
                ReasonCode::IdentityCreationChallengeAlreadyConsumed,
            ),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationAlreadyAccepted),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIntrospectSessionGrant,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueControllerGateAttestation,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::DuplicateConflict,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueDidBindingChallenge,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedDidMethod),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueIdentityAbandonmentChallenge,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationLeaseFenced),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationAlreadyAccepted),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueIdentityBindingChallenge,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueRecoveryCompletionGrant,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DeviceGenerationFenced),
            OperationSpecificError::ErrorCode(ErrorCode::DeviceReanchorAuthorizeMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandIssueSessionGrant,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::AudienceUnknown),
            OperationSpecificError::ErrorCode(ErrorCode::PrincipalUnknown),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayExpired),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayTerminal),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayIndeterminate),
            OperationSpecificError::ReasonCode(ReasonCode::VerificationMethodPrincipalMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::AgentPaused),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ReasonCode(ReasonCode::AgentKeyAuthorizationExpired),
            OperationSpecificError::ReasonCode(ReasonCode::AccountabilityGrantMissing),
            OperationSpecificError::ReasonCode(ReasonCode::AgentRequestedScopeCommitmentInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandLogout,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandLogoutAuthSession,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandPairAgentKey,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::VerificationMethodPrincipalMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::PairingRequestExpired),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::AgentPcrRecoveryNotReady),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ReasonCode(ReasonCode::AgentRequestedScopeCommitmentInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandPairDevice,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandRefreshSessionGrant,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::GrantAlreadyConsumed),
            OperationSpecificError::ErrorCode(ErrorCode::SessionLoggedOut),
            OperationSpecificError::ErrorCode(ErrorCode::AudienceMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayExpired),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayTerminal),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayIndeterminate),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::DidProofRequired),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandRegister,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationChallengeExpired),
            OperationSpecificError::ReasonCode(
                ReasonCode::IdentityCreationChallengeAlreadyConsumed,
            ),
            OperationSpecificError::ReasonCode(ReasonCode::AccountBindingPrincipalMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::CrossDomainReplayRejected),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::FoundingDeviceCommitmentMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationLeaseFenced),
            OperationSpecificError::ReasonCode(ReasonCode::InitialSessionRequestMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::PcrGenesisConflict),
            OperationSpecificError::ReasonCode(ReasonCode::PcrGenesisUnitInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountCommandRevokeSession,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::SessionRevokeSelectorConflict),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::SessionGrantReplayIndeterminate),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountExchangeCompleteOidc,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountExchangeCreateHandoff,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::GateAccountReadOnboarding,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        operation_specific: &[OperationSpecificError::ReasonCode(
            ReasonCode::AgentRuntimeRequestConflict,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenAgentPairingReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenAgentPairingReadRuntimeKeyRequestStatus,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenDevicePairingCommandStage,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenDevicePairingReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenDevicePairingReadStatus,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenIdentityReadResolution,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenInviteLocatorReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandNotify,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandProxyDownload,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandReportAbuse,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandRequestConsent,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandSubmitMessage,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandUpdateConsent,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiCommandUpdateRoom,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiExchangeRequestKeyMaterial,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiReadGroupInfo,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiReadIdentifiers,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenMimiReadProviderDirectory,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::OpenServiceReadResolution,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerAccountStatusCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::AccountStatusTransitionInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::ErasurePendingIsTerminal),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerAccountStatusReadAuthoringBasis,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerContactsCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerDirectConversationCommandRepairRelay,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DirectConversationUnavailable),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerErasureReceiptCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::ErasureReceiptAuthorityInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::ErasureReceiptProofInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::ErasureReceiptStubBindingMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::ErasureReceiptStubDigestMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerErasureReceiptResourceGet,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerEventsCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DependencyMissing),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::ExpiredInviteToken),
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedJoinRule),
            OperationSpecificError::ErrorCode(ErrorCode::ActorSeqInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::StaleSealRef),
            OperationSpecificError::ErrorCode(ErrorCode::RealmFrozen),
            OperationSpecificError::ErrorCode(ErrorCode::Quarantine),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
            OperationSpecificError::ErrorCode(ErrorCode::DeliveryBindingStale),
            OperationSpecificError::ErrorCode(ErrorCode::DeliveryBindingHandedOver),
            OperationSpecificError::ErrorCode(ErrorCode::MlsGenerationProposalFanoutExceeded),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerEventsReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerEventsReadFrontier,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FrontierUnavailable,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerEventsReadResolve,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::LimitExceeded)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerEventsReadScan,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerInvitesCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
            OperationSpecificError::ErrorCode(ErrorCode::ContactScopeStale),
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerKeysKeypackagesCommandClaim,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::ClaimFailed),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerKeysKeypackagesReadClaim,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::ClaimFailed),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerMlsReadGroupStateMaterial,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DependencyMissing),
            OperationSpecificError::ErrorCode(ErrorCode::DigestMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::StateMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::LimitExceeded),
            OperationSpecificError::ErrorCode(ErrorCode::StalePeer),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerPrincipalGenesisCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::PcrGenesisConflict),
            OperationSpecificError::ReasonCode(ReasonCode::PcrGenesisNotFirst),
            OperationSpecificError::ReasonCode(ReasonCode::PcrGenesisUnitInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::FoundingDeviceCommitmentMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::IdentityCreationLeaseFenced),
            OperationSpecificError::ReasonCode(ReasonCode::InitialSessionRequestMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerServiceResolutionCommandPublish,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceRouteNoticeBasisStale),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceRouteNoticeConflict),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceRouteNoticeCancelled),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceRouteNoticeExpired),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceRouteFork),
            OperationSpecificError::ReasonCode(ReasonCode::ServiceResolutionMirrorResponseLimit),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerServiceResolutionReadResolve,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerSignalCommandRelay,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::PeerSnapshotReadManifestHead,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityCommandSubmitDidOperation,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedDidMethod),
            OperationSpecificError::ErrorCode(ErrorCode::DidAlreadyExists),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityDocumentResourceGet,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedDidMethod),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::DidRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityLogReadList,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedDidMethod),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityOrganizationRegistrationCommandEnsure,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationChallengeInvalid),
            OperationSpecificError::ErrorCode(
                ErrorCode::OrganizationRegistrationControlProofInvalid,
            ),
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationQuorumNotMet),
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationScopeUnsupported),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityOrganizationRegistrationCommandPrepare,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationScopeUnsupported),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRefresh,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationChallengeInvalid),
            OperationSpecificError::ErrorCode(
                ErrorCode::OrganizationRegistrationControlProofInvalid,
            ),
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationQuorumNotMet),
            OperationSpecificError::ErrorCode(ErrorCode::OrganizationRegistrationRevoked),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRevoke,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::DidNotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityOrganizationRegistrationResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::DidNotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityReadResolve,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedDidMethod),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
            OperationSpecificError::ErrorCode(ErrorCode::DidRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityReceiptsReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRecoveryPolicyCommandPublish,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryPrincipalIsolation),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryPolicyGenesisNotV1),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryPolicySupersedesInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryPolicyVersionNotMonotonic),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryProofKindUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRecoveryPolicyResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRecoverySessionCommandCreate,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::RecoveryPolicyMismatch,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProof,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::RecoveryPolicyMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryEvidenceUnbound),
            OperationSpecificError::ReasonCode(ReasonCode::RecoverySessionChallengeMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRecoverySessionResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityRegistryReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityServiceRegistrationCommandEnsure,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::ServiceIdentityProviderUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::ServiceRegistrationRejected),
            OperationSpecificError::ErrorCode(ErrorCode::ServiceIdentityConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::RootIdentityServiceRegistrationResourceGet,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::ServiceIdentityProviderUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::DidNotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountCommandRevokeCursor,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountCommandUpdateProfile,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::InvalidAvatarBlobRef),
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedProfilePatchPath),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountReadViewer,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::SourceRefsUnverifiable,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountStreamSubscribe,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked),
            OperationSpecificError::ErrorCode(ErrorCode::StreamDropped),
            OperationSpecificError::ErrorCode(ErrorCode::StreamResyncRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountDataReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountDataResourceDelete,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CasConflict)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountDataResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAccountDataResourceReplace,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CasConflict)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandAbandonProvisioning,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::AgentProvisioningChallengeExpired),
            OperationSpecificError::ReasonCode(
                ReasonCode::AgentProvisioningChallengeAlreadyConsumed,
            ),
            OperationSpecificError::ReasonCode(ReasonCode::AgentPcrGenesisAlreadyAccepted),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandDeactivate,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::ControllerSignedEventRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandIssueProvisioningAbandonmentChallenge,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::AgentPcrGenesisAlreadyAccepted),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandPause,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::AgentPaused),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::ControllerSignedEventRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandProvision,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::AccountabilityGrantMissing),
            OperationSpecificError::ReasonCode(ReasonCode::AgentRequestedScopeCommitmentInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandRenewPairing,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ReasonCode(ReasonCode::AccountabilityGrantMissing),
            OperationSpecificError::ReasonCode(ReasonCode::AgentRequestedScopeCommitmentInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentCommandResume,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::SidecarExposureAckRequired),
            OperationSpecificError::ReasonCode(ReasonCode::AccountabilityGrantMissing),
            OperationSpecificError::ErrorCode(ErrorCode::ControllerSignedEventRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentGrantCommandAttach,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::AgentPaused),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::AgentGrantExceedsRequestedScope),
            OperationSpecificError::ReasonCode(ReasonCode::AgentRequestedScopeCommitmentInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentGrantResourceDelete,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentParticipationResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentParticipationResourceReplace,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CasConflict)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentReadList,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentSidecarCommandEnsure,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::SidecarCreateDenied),
            OperationSpecificError::ReasonCode(ReasonCode::AgentPaused),
            OperationSpecificError::ReasonCode(ReasonCode::AgentDeactivated),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentSidecarReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentSidecarResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAgentSignerEvidenceReadResolve,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::AgentSignerEvidenceMissing),
            OperationSpecificError::ErrorCode(ErrorCode::AgentSignerEvidenceStale),
            OperationSpecificError::ErrorCode(ErrorCode::AgentAuthorizationInactive),
            OperationSpecificError::ErrorCode(ErrorCode::AgentAuthorizationConflicted),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAppletCommandInstall,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::AppletInstallPlanMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::AppletRegistrationUnauthorized),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAppletCommandRevoke,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::AppletRevoked),
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAppletGhostCommandProvision,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::AppletNamespaceMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::AppletRegistrationUnauthorized),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAppletInstallCommandPreview,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::AppletRegistrationUnauthorized,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAppletRevokeCommandPreview,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::AppletRegistrationUnauthorized),
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAuthorizationLeasesCommandIssue,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::StaleSealRef),
            OperationSpecificError::ErrorCode(ErrorCode::SealRefUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAuthzGrantsReadEffective,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAuthzInvitesReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfAuthzReadCheck,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::PolicyUnavailable,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfBlobCommandPresign,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::BlobExpired),
            OperationSpecificError::ErrorCode(ErrorCode::BlobPresignInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::PresignInvalid),
            OperationSpecificError::ReasonCode(ReasonCode::PresignExpired),
            OperationSpecificError::ReasonCode(ReasonCode::PresignScopeMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::LegalHoldActive),
            OperationSpecificError::ReasonCode(ReasonCode::BlobRedacted),
            OperationSpecificError::ReasonCode(ReasonCode::PrivateAttachment),
            OperationSpecificError::ReasonCode(
                ReasonCode::DirectDownloadDisallowedPresignForbidden,
            ),
            OperationSpecificError::ReasonCode(ReasonCode::MinimalMetadataPresignForbidden),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfBlobResourceGet,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::BlobExpired),
            OperationSpecificError::ErrorCode(ErrorCode::BlobPresignInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfBlobResourceHead,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::BlobExpired),
            OperationSpecificError::ErrorCode(ErrorCode::BlobPresignInvalid),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfBlobUploadCreate,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::BlobQuotaExceeded),
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedMediaPolicy),
            OperationSpecificError::ErrorCode(ErrorCode::BlobDigestMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCallMediaExchangeIssueToken,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::FocusMismatch),
            OperationSpecificError::ReasonCode(ReasonCode::UnknownFocusType),
            OperationSpecificError::ReasonCode(ReasonCode::TokenIssuerUnauthorised),
            OperationSpecificError::ReasonCode(ReasonCode::MlsGovernanceBindingStale),
            OperationSpecificError::ReasonCode(ReasonCode::MediaPlaintextServiceNotAuthorised),
            OperationSpecificError::ReasonCode(ReasonCode::MediaServiceFociRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleCommandArchive,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleCommandCreate,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleCommandRestore,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FailedPrecondition,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleCommandRotateScope,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleCommandTombstone,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleMemberCommandAdd,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleMemberResourceDelete,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfCircleResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfConsentCommandGrant,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfConsentCommandRequest,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfConsentCommandRevoke,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfConsentReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfConsentResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactCommandReject,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactCommandRequest,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactCommandRespond,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactCommandScopeUpdate,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
            OperationSpecificError::ErrorCode(ErrorCode::ContactScopeStale),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactCommandTombstone,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::SourceRefsUnverifiable),
            OperationSpecificError::ErrorCode(ErrorCode::ContactLineageConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfContactReadList,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfControlProposalAcksCommandIssue,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::StaleSealRef),
            OperationSpecificError::ErrorCode(ErrorCode::SealRefUnknown),
            OperationSpecificError::ReasonCode(ReasonCode::QuorumUnreachable),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfDeviceMessagesCommandAck,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfDeviceMessagesCommandSend,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::DuplicateConflict,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfDeviceMessagesReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfDirectConversationCommandRepairDispatch,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DirectConversationUnavailable),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfDirectConversationReadResolve,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::DirectConversationUnavailable),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::ExpiredInviteToken),
            OperationSpecificError::ErrorCode(ErrorCode::UnsupportedJoinRule),
            OperationSpecificError::ErrorCode(ErrorCode::ActorSeqInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::StaleSealRef),
            OperationSpecificError::ErrorCode(ErrorCode::SealRefUnknown),
            OperationSpecificError::ErrorCode(ErrorCode::RealmFrozen),
            OperationSpecificError::ErrorCode(ErrorCode::Quarantine),
            OperationSpecificError::ErrorCode(ErrorCode::MlsGenerationProposalFanoutExceeded),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsCommandSubmitSeal,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DeviceGenerationFenced),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::SealDeferredFutureSkew),
            OperationSpecificError::ErrorCode(ErrorCode::SealSignerUnauthorized),
            OperationSpecificError::ErrorCode(ErrorCode::StateMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsReadDescribe,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsReadFrontier,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FrontierUnavailable,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsReadMlsGovernanceProof,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::MlsGovernanceAnchorUnreachable),
            OperationSpecificError::ErrorCode(ErrorCode::MlsGovernanceProofBoundsExceeded),
            OperationSpecificError::ErrorCode(ErrorCode::FrontierUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::StateMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::SignatureInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::ProfileUnsupported),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsReadResolve,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsReadScan,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfEventsStreamSubscribe,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::CursorRevoked),
            OperationSpecificError::ErrorCode(ErrorCode::StreamDropped),
            OperationSpecificError::ErrorCode(ErrorCode::StreamResyncRequired),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfInviteLocatorCommandIssue,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::RateLimited),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfInviteLocatorCommandRevoke,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfInviteLocatorCommandRotate,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfInviteReceivePolicyResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfInviteReceivePolicyResourceReplace,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupSeriesCommandErase,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::BackupFrontierStale),
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupsCommandIssueDeleteChallenge,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupsCommandUnlock,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ReasonCode(ReasonCode::RecoveryEvidenceUnbound),
            OperationSpecificError::ReasonCode(ReasonCode::BackupFrontierStale),
            OperationSpecificError::ReasonCode(ReasonCode::SeriesChainBroken),
            OperationSpecificError::ErrorCode(ErrorCode::InvalidSignature),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupsReadList,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::CursorInvalid)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupsResourceDelete,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::ChallengeExpired),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysBackupsResourceReplace,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::KeyBackupWireSchemaRequired),
            OperationSpecificError::ReasonCode(ReasonCode::SeriesChainBroken),
            OperationSpecificError::ReasonCode(ReasonCode::SeriesSeqNotMonotonic),
            OperationSpecificError::ReasonCode(ReasonCode::SeriesPredecessorNotFound),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysCommandClaim,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::OneTimeKeysExhausted),
            OperationSpecificError::ErrorCode(ErrorCode::DeviceUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysKeypackagesCommandClaim,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::OneTimeKeysExhausted),
            OperationSpecificError::ErrorCode(ErrorCode::PrincipalUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysKeypackagesCommandConsume,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::KeypackageAlreadyConsumed),
            OperationSpecificError::ErrorCode(ErrorCode::KeypackageUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysKeypackagesCommandRevoke,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::KeypackageAlreadyConsumed),
            OperationSpecificError::ErrorCode(ErrorCode::KeypackageUnknown),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysKeypackagesUploadCreate,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysReadLookup,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfKeysUploadCreate,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DeviceUnknown),
            OperationSpecificError::ErrorCode(ErrorCode::KeyReplay),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfMediaReadIceConfig,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::IceConfigDenied),
            OperationSpecificError::ErrorCode(ErrorCode::TurnCredentialExpired),
            OperationSpecificError::ReasonCode(ReasonCode::MediaServiceBindingUncovered),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfModerationCommandReport,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ReasonCode(ReasonCode::EvidenceRecipientMismatch),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfMorphReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfMorphResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfPolicyReadCheck,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::PolicyUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::PolicyStale),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfPrincipalServiceBindingCommandCommit,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ReasonCode(ReasonCode::ChallengeExpired),
            OperationSpecificError::ErrorCode(ErrorCode::CasConflict),
            OperationSpecificError::ErrorCode(ErrorCode::InvalidSignature),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfPrincipalServiceBindingCommandPrepare,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::CasConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfReadCursorCommandAdvance,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfReadCursorReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmCommandArchive,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FailedPrecondition,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmCommandDestroy,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FailedPrecondition,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmCommandFreeze,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FailedPrecondition,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmCommandTombstone,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::FailedPrecondition,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationAuditReadList,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationCommandCancel,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationCommandReview,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::TtlExpired),
            OperationSpecificError::ErrorCode(ErrorCode::ReviewerCapabilityRevoked),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationCommandSubmit,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::ProofInvalid),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ReasonCode(ReasonCode::GateCheckFailed),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmJoinApplicationResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmModerationPolicyReadEffective,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmModerationPolicyResourceReplace,
        operation_specific: &[
            OperationSpecificError::ReasonCode(ReasonCode::RequiresOrganizationApproval),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::FailedBottom),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmReadExport,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmLinkCommandCreate,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmLinkReadEffectivePolicy,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmLinkReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmLinkResourceDelete,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmOrganizationReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmPolicyServerResourceDelete,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmPolicyServerResourceGet,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfRealmPolicyServerResourceReplace,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSecurityTransactionCommandContinue,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::NotFound),
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
            OperationSpecificError::ErrorCode(ErrorCode::StateMismatch),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSecurityTransactionCommandCreate,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::DuplicateConflict),
            OperationSpecificError::ErrorCode(ErrorCode::FailedPrecondition),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSecurityTransactionResourceGet,
        operation_specific: &[OperationSpecificError::ErrorCode(ErrorCode::NotFound)],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSignalCommandSend,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::SignalClassNotPermitted),
            OperationSpecificError::ErrorCode(ErrorCode::SignalTtlOutOfRange),
            OperationSpecificError::ErrorCode(ErrorCode::SignalRailUnavailable),
            OperationSpecificError::ReasonCode(ReasonCode::SignalPlaintextForbidden),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSignalStreamSubscribe,
        operation_specific: &[OperationSpecificError::ErrorCode(
            ErrorCode::SignalRailUnavailable,
        )],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSnapshotReadManifestHead,
        operation_specific: &[
            OperationSpecificError::ErrorCode(ErrorCode::SnapshotUnavailable),
            OperationSpecificError::ErrorCode(ErrorCode::SnapshotAuthorityUnverified),
        ],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfSpaceReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfStrandReadList,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::SelfViewsCollectionProjectionCommandMaterialize,
        operation_specific: &[],
    },
    OperationErrorMappingDescriptor {
        operation: ServiceOperationId::ServerReadDescribe,
        operation_specific: &[],
    },
];

pub const fn operation_error_mapping(
    operation: ServiceOperationId,
) -> &'static OperationErrorMappingDescriptor {
    &OPERATION_ERROR_MAPPINGS[operation as usize]
}
