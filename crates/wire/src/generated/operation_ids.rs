//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/operation-registry.json; version=2026-08-20.2;
//! sha256=25022cde238919dd6772dbae82dc35dc60882c3bfcdbcfe2b0bb2bd10c0a27bc Entries: registered=243

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ServiceOperationId {
    EdgeAppletActorReadResolve,
    EdgeAppletCommandTransaction,
    EdgeAppletReadDescribe,
    EdgeAppletReadPing,
    EdgeAppletReadProtocolMetadata,
    EdgeAppletRealmReadResolve,
    EdgeAppletThirdPartyLocationsReadList,
    EdgeAppletThirdPartyUsersReadList,
    EdgePushCommandNotify,
    EdgePushCommandRegisterDevice,
    EdgePushCommandUnregisterDevice,
    FindDirectoryCommandAnnounce,
    FindDirectoryCommandTakedownAppeal,
    FindDirectoryCommandWithdraw,
    FindDirectoryPushCommandRegister,
    FindDirectoryReadDescribe,
    FindDirectoryReadListHandlesForSubject,
    FindDirectoryReadPrivateContactDiscovery,
    FindDirectoryReadResolveAgentSelector,
    FindDirectoryReadResolveHandle,
    FindDirectoryReadResolveOrganization,
    FindDirectoryReadResolveRealm,
    FindDirectoryReadResolveTarget,
    FindDirectoryReadSearchActors,
    FindDirectoryReadSearchOrganizations,
    FindDirectoryReadSearchRealms,
    FindDirectoryReadSearchUsers,
    GateAccountCommandAbandonIdentityCreation,
    GateAccountCommandIntrospectSessionGrant,
    GateAccountCommandIssueControllerGateAttestation,
    GateAccountCommandIssueDidBindingChallenge,
    GateAccountCommandIssueIdentityAbandonmentChallenge,
    GateAccountCommandIssueIdentityBindingChallenge,
    GateAccountCommandIssueRecoveryCompletionGrant,
    GateAccountCommandIssueSessionGrant,
    GateAccountCommandLogout,
    GateAccountCommandLogoutAuthSession,
    GateAccountCommandPairAgentKey,
    GateAccountCommandPairDevice,
    GateAccountCommandRefreshSessionGrant,
    GateAccountCommandRegister,
    GateAccountCommandRequestErasure,
    GateAccountCommandRevokeSession,
    GateAccountExchangeCreateHandoff,
    GateAccountReadOnboarding,
    OpenAgentPairingCommandSubmitRuntimeKeyRequest,
    OpenAgentPairingReadResolve,
    OpenAgentPairingReadRuntimeKeyRequestStatus,
    OpenDevicePairingCommandStage,
    OpenDevicePairingReadResolve,
    OpenDevicePairingReadStatus,
    OpenIdentityReadResolution,
    OpenInviteLocatorReadResolve,
    OpenMimiCommandNotify,
    OpenMimiCommandProxyDownload,
    OpenMimiCommandReportAbuse,
    OpenMimiCommandRequestConsent,
    OpenMimiCommandSubmitMessage,
    OpenMimiCommandUpdateConsent,
    OpenMimiCommandUpdateRoom,
    OpenMimiExchangeRequestKeyMaterial,
    OpenMimiReadGroupInfo,
    OpenMimiReadIdentifiers,
    OpenMimiReadProviderDirectory,
    OpenServiceReadResolution,
    PeerAccountStatusCommandSubmit,
    PeerAccountStatusReadResolve,
    PeerContactsCommandSubmit,
    PeerDeviceRevocationsCommandCheck,
    PeerDirectConversationCommandRepairRelay,
    PeerErasureReceiptCommandSubmit,
    PeerErasureReceiptResourceGet,
    PeerEventsCommandSubmit,
    PeerEventsReadDescribe,
    PeerEventsReadFrontier,
    PeerEventsReadResolve,
    PeerEventsReadScan,
    PeerInvitesCommandSubmit,
    PeerKeysKeypackagesCommandClaim,
    PeerKeysKeypackagesReadClaim,
    PeerMlsReadGroupStateMaterial,
    PeerPrincipalGenesisCommandSubmit,
    PeerServiceResolutionCommandPublish,
    PeerServiceResolutionReadResolve,
    PeerSignalCommandRelay,
    PeerSnapshotReadManifestHead,
    RootIdentityCommandSubmitDidOperation,
    RootIdentityDocumentResourceGet,
    RootIdentityLogReadList,
    RootIdentityOrganizationRegistrationCommandEnsure,
    RootIdentityOrganizationRegistrationCommandPrepare,
    RootIdentityOrganizationRegistrationCommandRefresh,
    RootIdentityOrganizationRegistrationCommandRevoke,
    RootIdentityOrganizationRegistrationResourceGet,
    RootIdentityReadResolve,
    RootIdentityReceiptsReadList,
    RootIdentityRecoveryPolicyCommandPublish,
    RootIdentityRecoveryPolicyResourceGet,
    RootIdentityRecoverySessionCommandCreate,
    RootIdentityRecoverySessionCommandSubmitProof,
    RootIdentityRecoverySessionResourceGet,
    RootIdentityRegistryReadDescribe,
    RootIdentityServiceRegistrationCommandEnsure,
    RootIdentityServiceRegistrationResourceGet,
    SelfAccountCommandRevokeCursor,
    SelfAccountCommandUpdateProfile,
    SelfAccountReadDescribe,
    SelfAccountReadViewer,
    SelfAccountStreamSubscribe,
    SelfAccountDataReadList,
    SelfAccountDataResourceDelete,
    SelfAccountDataResourceGet,
    SelfAccountDataResourceReplace,
    SelfActorProfileReadResolve,
    SelfAgentCommandAbandonProvisioning,
    SelfAgentCommandDeactivate,
    SelfAgentCommandIssueProvisioningAbandonmentChallenge,
    SelfAgentCommandPause,
    SelfAgentCommandProvision,
    SelfAgentCommandRenewPairing,
    SelfAgentCommandResume,
    SelfAgentGrantCommandAttach,
    SelfAgentGrantResourceDelete,
    SelfAgentParticipationResourceGet,
    SelfAgentParticipationResourceReplace,
    SelfAgentReadList,
    SelfAgentResourceGet,
    SelfAgentSidecarCommandEnsure,
    SelfAgentSidecarReadList,
    SelfAgentSidecarResourceGet,
    SelfAgentSignerEvidenceReadResolve,
    SelfAppletCommandInstall,
    SelfAppletCommandRevoke,
    SelfAppletGhostCommandProvision,
    SelfAppletInstallCommandPreview,
    SelfAppletRevokeCommandPreview,
    SelfAuthorizationLeasesCommandIssue,
    SelfAuthzGrantsReadEffective,
    SelfAuthzInvitesReadList,
    SelfAuthzReadCheck,
    SelfBlobCommandPresign,
    SelfBlobResourceGet,
    SelfBlobResourceHead,
    SelfBlobUploadCreate,
    SelfCallMediaExchangeIssueToken,
    SelfCircleCommandArchive,
    SelfCircleCommandCreate,
    SelfCircleCommandRestore,
    SelfCircleCommandRotateScope,
    SelfCircleCommandTombstone,
    SelfCircleMemberCommandAdd,
    SelfCircleMemberResourceDelete,
    SelfCircleReadList,
    SelfCircleResourceGet,
    SelfConsentCommandGrant,
    SelfConsentCommandRequest,
    SelfConsentCommandRevoke,
    SelfConsentReadList,
    SelfConsentResourceGet,
    SelfContactCommandCheckpoint,
    SelfContactCommandReject,
    SelfContactCommandRequest,
    SelfContactCommandRespond,
    SelfContactCommandScopeUpdate,
    SelfContactCommandTombstone,
    SelfContactReadList,
    SelfControlProposalAcksCommandIssue,
    SelfControlProposalDecisionsCommandSubmit,
    SelfControlProposalDecisionsReadGet,
    SelfDeviceMessagesCommandAck,
    SelfDeviceMessagesCommandSend,
    SelfDeviceMessagesReadList,
    SelfDirectConversationCommandRepairDispatch,
    SelfDirectConversationReadResolve,
    SelfEventsCommandSubmit,
    SelfEventsCommandSubmitSeal,
    SelfEventsReadDeliveryStatus,
    SelfEventsReadDescribe,
    SelfEventsReadFrontier,
    SelfEventsReadMlsGovernanceProof,
    SelfEventsReadResolve,
    SelfEventsReadScan,
    SelfEventsResourceGet,
    SelfEventsStreamSubscribe,
    SelfIdentityReadResolutionAudit,
    SelfInviteLocatorCommandIssue,
    SelfInviteLocatorCommandRevoke,
    SelfInviteLocatorCommandRotate,
    SelfInviteReceivePolicyResourceGet,
    SelfInviteReceivePolicyResourceReplace,
    SelfInvitesCommandDispatch,
    SelfKeysBackupSeriesCommandErase,
    SelfKeysBackupsCommandIssueDeleteChallenge,
    SelfKeysBackupsCommandUnlock,
    SelfKeysBackupsReadList,
    SelfKeysBackupsResourceDelete,
    SelfKeysBackupsResourceReplace,
    SelfKeysCommandClaim,
    SelfKeysKeypackagesCommandClaim,
    SelfKeysKeypackagesCommandConsume,
    SelfKeysKeypackagesCommandRevoke,
    SelfKeysKeypackagesUploadCreate,
    SelfKeysReadLookup,
    SelfKeysUploadCreate,
    SelfMediaReadIceConfig,
    SelfModerationCommandReport,
    SelfMorphReadList,
    SelfMorphResourceGet,
    SelfPolicyReadCheck,
    SelfReadCursorCommandAdvance,
    SelfReadCursorReadList,
    SelfRealmCommandArchive,
    SelfRealmCommandDestroy,
    SelfRealmCommandFreeze,
    SelfRealmCommandTombstone,
    SelfRealmJoinApplicationAuditReadList,
    SelfRealmJoinApplicationCommandCancel,
    SelfRealmJoinApplicationCommandReview,
    SelfRealmJoinApplicationCommandSubmit,
    SelfRealmJoinApplicationReadList,
    SelfRealmJoinApplicationResourceGet,
    SelfRealmModerationPolicyReadEffective,
    SelfRealmModerationPolicyResourceReplace,
    SelfRealmReadExport,
    SelfRealmResourceGet,
    SelfRealmLinkCommandCreate,
    SelfRealmLinkReadEffectivePolicy,
    SelfRealmLinkReadList,
    SelfRealmLinkResourceDelete,
    SelfRealmOrganizationReadList,
    SelfRealmPolicyServerResourceDelete,
    SelfRealmPolicyServerResourceGet,
    SelfRealmPolicyServerResourceReplace,
    SelfSecurityTransactionCommandContinue,
    SelfSecurityTransactionCommandCreate,
    SelfSecurityTransactionResourceGet,
    SelfSignalCommandSend,
    SelfSignalStreamSubscribe,
    SelfSnapshotReadManifestHead,
    SelfSpaceReadList,
    SelfStrandReadList,
    SelfViewsCollectionProjectionCommandMaterialize,
    ServerReadDescribe,
}

pub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[
    ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE,
    ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
    ServiceOperationId::EDGE_APPLET_READ_DESCRIBE,
    ServiceOperationId::EDGE_APPLET_READ_PING,
    ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA,
    ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST,
    ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY,
    ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
    ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
    ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE,
    ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT,
    ServiceOperationId::FIND_DIRECTORY_READ_PRIVATE_CONTACT_DISCOVERY,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_TARGET,
    ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS,
    ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS,
    ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS,
    ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_ABANDONMENT_CHALLENGE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
    ServiceOperationId::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF,
    ServiceOperationId::GATE_ACCOUNT_READ_ONBOARDING,
    ServiceOperationId::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST,
    ServiceOperationId::OPEN_AGENT_PAIRING_READ_RESOLVE,
    ServiceOperationId::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS,
    ServiceOperationId::OPEN_DEVICE_PAIRING_COMMAND_STAGE,
    ServiceOperationId::OPEN_DEVICE_PAIRING_READ_RESOLVE,
    ServiceOperationId::OPEN_DEVICE_PAIRING_READ_STATUS,
    ServiceOperationId::OPEN_IDENTITY_READ_RESOLUTION,
    ServiceOperationId::OPEN_INVITE_LOCATOR_READ_RESOLVE,
    ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY,
    ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD,
    ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE,
    ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT,
    ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM,
    ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL,
    ServiceOperationId::OPEN_MIMI_READ_GROUP_INFO,
    ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS,
    ServiceOperationId::OPEN_MIMI_READ_PROVIDER_DIRECTORY,
    ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION,
    ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_ACCOUNT_STATUS_READ_RESOLVE,
    ServiceOperationId::PEER_CONTACTS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK,
    ServiceOperationId::PEER_DIRECT_CONVERSATION_COMMAND_REPAIR_RELAY,
    ServiceOperationId::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT,
    ServiceOperationId::PEER_ERASURE_RECEIPT_RESOURCE_GET,
    ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_EVENTS_READ_DESCRIBE,
    ServiceOperationId::PEER_EVENTS_READ_FRONTIER,
    ServiceOperationId::PEER_EVENTS_READ_RESOLVE,
    ServiceOperationId::PEER_EVENTS_READ_SCAN,
    ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_READ_CLAIM,
    ServiceOperationId::PEER_MLS_READ_GROUP_STATE_MATERIAL,
    ServiceOperationId::PEER_PRINCIPAL_GENESIS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_SERVICE_RESOLUTION_COMMAND_PUBLISH,
    ServiceOperationId::PEER_SERVICE_RESOLUTION_READ_RESOLVE,
    ServiceOperationId::PEER_SIGNAL_COMMAND_RELAY,
    ServiceOperationId::PEER_SNAPSHOT_READ_MANIFEST_HEAD,
    ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION,
    ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_LOG_READ_LIST,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE,
    ServiceOperationId::ROOT_IDENTITY_RECEIPTS_READ_LIST,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE,
    ServiceOperationId::SELF_ACCOUNT_READ_DESCRIBE,
    ServiceOperationId::SELF_ACCOUNT_READ_VIEWER,
    ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_ACCOUNT_DATA_READ_LIST,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_DELETE,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE,
    ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE,
    ServiceOperationId::SELF_AGENT_COMMAND_ABANDON_PROVISIONING,
    ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
    ServiceOperationId::SELF_AGENT_COMMAND_ISSUE_PROVISIONING_ABANDONMENT_CHALLENGE,
    ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
    ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
    ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
    ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
    ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE,
    ServiceOperationId::SELF_AGENT_READ_LIST,
    ServiceOperationId::SELF_AGENT_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    ServiceOperationId::SELF_AGENT_SIDECAR_READ_LIST,
    ServiceOperationId::SELF_AGENT_SIDECAR_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_SIGNER_EVIDENCE_READ_RESOLVE,
    ServiceOperationId::SELF_APPLET_COMMAND_INSTALL,
    ServiceOperationId::SELF_APPLET_COMMAND_REVOKE,
    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION,
    ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW,
    ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW,
    ServiceOperationId::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE,
    ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE,
    ServiceOperationId::SELF_AUTHZ_INVITES_READ_LIST,
    ServiceOperationId::SELF_AUTHZ_READ_CHECK,
    ServiceOperationId::SELF_BLOB_COMMAND_PRESIGN,
    ServiceOperationId::SELF_BLOB_RESOURCE_GET,
    ServiceOperationId::SELF_BLOB_RESOURCE_HEAD,
    ServiceOperationId::SELF_BLOB_UPLOAD_CREATE,
    ServiceOperationId::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN,
    ServiceOperationId::SELF_CIRCLE_COMMAND_ARCHIVE,
    ServiceOperationId::SELF_CIRCLE_COMMAND_CREATE,
    ServiceOperationId::SELF_CIRCLE_COMMAND_RESTORE,
    ServiceOperationId::SELF_CIRCLE_COMMAND_ROTATE_SCOPE,
    ServiceOperationId::SELF_CIRCLE_COMMAND_TOMBSTONE,
    ServiceOperationId::SELF_CIRCLE_MEMBER_COMMAND_ADD,
    ServiceOperationId::SELF_CIRCLE_MEMBER_RESOURCE_DELETE,
    ServiceOperationId::SELF_CIRCLE_READ_LIST,
    ServiceOperationId::SELF_CIRCLE_RESOURCE_GET,
    ServiceOperationId::SELF_CONSENT_COMMAND_GRANT,
    ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST,
    ServiceOperationId::SELF_CONSENT_COMMAND_REVOKE,
    ServiceOperationId::SELF_CONSENT_READ_LIST,
    ServiceOperationId::SELF_CONSENT_RESOURCE_GET,
    ServiceOperationId::SELF_CONTACT_COMMAND_CHECKPOINT,
    ServiceOperationId::SELF_CONTACT_COMMAND_REJECT,
    ServiceOperationId::SELF_CONTACT_COMMAND_REQUEST,
    ServiceOperationId::SELF_CONTACT_COMMAND_RESPOND,
    ServiceOperationId::SELF_CONTACT_COMMAND_SCOPE_UPDATE,
    ServiceOperationId::SELF_CONTACT_COMMAND_TOMBSTONE,
    ServiceOperationId::SELF_CONTACT_READ_LIST,
    ServiceOperationId::SELF_CONTROL_PROPOSAL_ACKS_COMMAND_ISSUE,
    ServiceOperationId::SELF_CONTROL_PROPOSAL_DECISIONS_COMMAND_SUBMIT,
    ServiceOperationId::SELF_CONTROL_PROPOSAL_DECISIONS_READ_GET,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND,
    ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST,
    ServiceOperationId::SELF_DIRECT_CONVERSATION_COMMAND_REPAIR_DISPATCH,
    ServiceOperationId::SELF_DIRECT_CONVERSATION_READ_RESOLVE,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_SEAL,
    ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS,
    ServiceOperationId::SELF_EVENTS_READ_DESCRIBE,
    ServiceOperationId::SELF_EVENTS_READ_FRONTIER,
    ServiceOperationId::SELF_EVENTS_READ_MLS_GOVERNANCE_PROOF,
    ServiceOperationId::SELF_EVENTS_READ_RESOLVE,
    ServiceOperationId::SELF_EVENTS_READ_SCAN,
    ServiceOperationId::SELF_EVENTS_RESOURCE_GET,
    ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_IDENTITY_READ_RESOLUTION_AUDIT,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ISSUE,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_REVOKE,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ROTATE,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE,
    ServiceOperationId::SELF_INVITES_COMMAND_DISPATCH,
    ServiceOperationId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK,
    ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE,
    ServiceOperationId::SELF_KEYS_COMMAND_CLAIM,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE,
    ServiceOperationId::SELF_KEYS_READ_LOOKUP,
    ServiceOperationId::SELF_KEYS_UPLOAD_CREATE,
    ServiceOperationId::SELF_MEDIA_READ_ICE_CONFIG,
    ServiceOperationId::SELF_MODERATION_COMMAND_REPORT,
    ServiceOperationId::SELF_MORPH_READ_LIST,
    ServiceOperationId::SELF_MORPH_RESOURCE_GET,
    ServiceOperationId::SELF_POLICY_READ_CHECK,
    ServiceOperationId::SELF_READ_CURSOR_COMMAND_ADVANCE,
    ServiceOperationId::SELF_READ_CURSOR_READ_LIST,
    ServiceOperationId::SELF_REALM_COMMAND_ARCHIVE,
    ServiceOperationId::SELF_REALM_COMMAND_DESTROY,
    ServiceOperationId::SELF_REALM_COMMAND_FREEZE,
    ServiceOperationId::SELF_REALM_COMMAND_TOMBSTONE,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_AUDIT_READ_LIST,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_READ_LIST,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_MODERATION_POLICY_READ_EFFECTIVE,
    ServiceOperationId::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE,
    ServiceOperationId::SELF_REALM_READ_EXPORT,
    ServiceOperationId::SELF_REALM_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_LINK_COMMAND_CREATE,
    ServiceOperationId::SELF_REALM_LINK_READ_EFFECTIVE_POLICY,
    ServiceOperationId::SELF_REALM_LINK_READ_LIST,
    ServiceOperationId::SELF_REALM_LINK_RESOURCE_DELETE,
    ServiceOperationId::SELF_REALM_ORGANIZATION_READ_LIST,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CREATE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_RESOURCE_GET,
    ServiceOperationId::SELF_SIGNAL_COMMAND_SEND,
    ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_SNAPSHOT_READ_MANIFEST_HEAD,
    ServiceOperationId::SELF_SPACE_READ_LIST,
    ServiceOperationId::SELF_STRAND_READ_LIST,
    ServiceOperationId::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE,
    ServiceOperationId::SERVER_READ_DESCRIBE,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableEffectKind {
    EventLog,
    ActorPrivateEvent,
    Branched,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableEventTarget {
    Static(&'static [&'static str]),
    Dynamic(&'static str),
    DynamicMany(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableEffectDescriptor {
    pub kind: DurableEffectKind,
    pub target: Option<DurableEventTarget>,
    pub rationale: Option<&'static str>,
    pub branch_contract_json: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceOperationDescriptor {
    pub id: ServiceOperationId,
    pub http_method: &'static str,
    pub http_path: &'static str,
    pub grpc: Option<&'static str>,
    pub mq: Option<&'static str>,
    pub body_class: Option<&'static str>,
    pub max_canonical_body_bytes: Option<usize>,
    pub success_shape_kind: &'static str,
    pub idempotency_mechanism: Option<&'static str>,
    pub retry_safe: Option<bool>,
    pub request_schema_ref: Option<&'static str>,
    pub response_schema_ref: Option<&'static str>,
    pub uncertain_outcome: Option<&'static str>,
    pub durable_effect: Option<DurableEffectDescriptor>,
}

impl ServiceOperationId {
    pub const ALL: &'static [Self] = &[
        Self::EdgeAppletActorReadResolve,
        Self::EdgeAppletCommandTransaction,
        Self::EdgeAppletReadDescribe,
        Self::EdgeAppletReadPing,
        Self::EdgeAppletReadProtocolMetadata,
        Self::EdgeAppletRealmReadResolve,
        Self::EdgeAppletThirdPartyLocationsReadList,
        Self::EdgeAppletThirdPartyUsersReadList,
        Self::EdgePushCommandNotify,
        Self::EdgePushCommandRegisterDevice,
        Self::EdgePushCommandUnregisterDevice,
        Self::FindDirectoryCommandAnnounce,
        Self::FindDirectoryCommandTakedownAppeal,
        Self::FindDirectoryCommandWithdraw,
        Self::FindDirectoryPushCommandRegister,
        Self::FindDirectoryReadDescribe,
        Self::FindDirectoryReadListHandlesForSubject,
        Self::FindDirectoryReadPrivateContactDiscovery,
        Self::FindDirectoryReadResolveAgentSelector,
        Self::FindDirectoryReadResolveHandle,
        Self::FindDirectoryReadResolveOrganization,
        Self::FindDirectoryReadResolveRealm,
        Self::FindDirectoryReadResolveTarget,
        Self::FindDirectoryReadSearchActors,
        Self::FindDirectoryReadSearchOrganizations,
        Self::FindDirectoryReadSearchRealms,
        Self::FindDirectoryReadSearchUsers,
        Self::GateAccountCommandAbandonIdentityCreation,
        Self::GateAccountCommandIntrospectSessionGrant,
        Self::GateAccountCommandIssueControllerGateAttestation,
        Self::GateAccountCommandIssueDidBindingChallenge,
        Self::GateAccountCommandIssueIdentityAbandonmentChallenge,
        Self::GateAccountCommandIssueIdentityBindingChallenge,
        Self::GateAccountCommandIssueRecoveryCompletionGrant,
        Self::GateAccountCommandIssueSessionGrant,
        Self::GateAccountCommandLogout,
        Self::GateAccountCommandLogoutAuthSession,
        Self::GateAccountCommandPairAgentKey,
        Self::GateAccountCommandPairDevice,
        Self::GateAccountCommandRefreshSessionGrant,
        Self::GateAccountCommandRegister,
        Self::GateAccountCommandRequestErasure,
        Self::GateAccountCommandRevokeSession,
        Self::GateAccountExchangeCreateHandoff,
        Self::GateAccountReadOnboarding,
        Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        Self::OpenAgentPairingReadResolve,
        Self::OpenAgentPairingReadRuntimeKeyRequestStatus,
        Self::OpenDevicePairingCommandStage,
        Self::OpenDevicePairingReadResolve,
        Self::OpenDevicePairingReadStatus,
        Self::OpenIdentityReadResolution,
        Self::OpenInviteLocatorReadResolve,
        Self::OpenMimiCommandNotify,
        Self::OpenMimiCommandProxyDownload,
        Self::OpenMimiCommandReportAbuse,
        Self::OpenMimiCommandRequestConsent,
        Self::OpenMimiCommandSubmitMessage,
        Self::OpenMimiCommandUpdateConsent,
        Self::OpenMimiCommandUpdateRoom,
        Self::OpenMimiExchangeRequestKeyMaterial,
        Self::OpenMimiReadGroupInfo,
        Self::OpenMimiReadIdentifiers,
        Self::OpenMimiReadProviderDirectory,
        Self::OpenServiceReadResolution,
        Self::PeerAccountStatusCommandSubmit,
        Self::PeerAccountStatusReadResolve,
        Self::PeerContactsCommandSubmit,
        Self::PeerDeviceRevocationsCommandCheck,
        Self::PeerDirectConversationCommandRepairRelay,
        Self::PeerErasureReceiptCommandSubmit,
        Self::PeerErasureReceiptResourceGet,
        Self::PeerEventsCommandSubmit,
        Self::PeerEventsReadDescribe,
        Self::PeerEventsReadFrontier,
        Self::PeerEventsReadResolve,
        Self::PeerEventsReadScan,
        Self::PeerInvitesCommandSubmit,
        Self::PeerKeysKeypackagesCommandClaim,
        Self::PeerKeysKeypackagesReadClaim,
        Self::PeerMlsReadGroupStateMaterial,
        Self::PeerPrincipalGenesisCommandSubmit,
        Self::PeerServiceResolutionCommandPublish,
        Self::PeerServiceResolutionReadResolve,
        Self::PeerSignalCommandRelay,
        Self::PeerSnapshotReadManifestHead,
        Self::RootIdentityCommandSubmitDidOperation,
        Self::RootIdentityDocumentResourceGet,
        Self::RootIdentityLogReadList,
        Self::RootIdentityOrganizationRegistrationCommandEnsure,
        Self::RootIdentityOrganizationRegistrationCommandPrepare,
        Self::RootIdentityOrganizationRegistrationCommandRefresh,
        Self::RootIdentityOrganizationRegistrationCommandRevoke,
        Self::RootIdentityOrganizationRegistrationResourceGet,
        Self::RootIdentityReadResolve,
        Self::RootIdentityReceiptsReadList,
        Self::RootIdentityRecoveryPolicyCommandPublish,
        Self::RootIdentityRecoveryPolicyResourceGet,
        Self::RootIdentityRecoverySessionCommandCreate,
        Self::RootIdentityRecoverySessionCommandSubmitProof,
        Self::RootIdentityRecoverySessionResourceGet,
        Self::RootIdentityRegistryReadDescribe,
        Self::RootIdentityServiceRegistrationCommandEnsure,
        Self::RootIdentityServiceRegistrationResourceGet,
        Self::SelfAccountCommandRevokeCursor,
        Self::SelfAccountCommandUpdateProfile,
        Self::SelfAccountReadDescribe,
        Self::SelfAccountReadViewer,
        Self::SelfAccountStreamSubscribe,
        Self::SelfAccountDataReadList,
        Self::SelfAccountDataResourceDelete,
        Self::SelfAccountDataResourceGet,
        Self::SelfAccountDataResourceReplace,
        Self::SelfActorProfileReadResolve,
        Self::SelfAgentCommandAbandonProvisioning,
        Self::SelfAgentCommandDeactivate,
        Self::SelfAgentCommandIssueProvisioningAbandonmentChallenge,
        Self::SelfAgentCommandPause,
        Self::SelfAgentCommandProvision,
        Self::SelfAgentCommandRenewPairing,
        Self::SelfAgentCommandResume,
        Self::SelfAgentGrantCommandAttach,
        Self::SelfAgentGrantResourceDelete,
        Self::SelfAgentParticipationResourceGet,
        Self::SelfAgentParticipationResourceReplace,
        Self::SelfAgentReadList,
        Self::SelfAgentResourceGet,
        Self::SelfAgentSidecarCommandEnsure,
        Self::SelfAgentSidecarReadList,
        Self::SelfAgentSidecarResourceGet,
        Self::SelfAgentSignerEvidenceReadResolve,
        Self::SelfAppletCommandInstall,
        Self::SelfAppletCommandRevoke,
        Self::SelfAppletGhostCommandProvision,
        Self::SelfAppletInstallCommandPreview,
        Self::SelfAppletRevokeCommandPreview,
        Self::SelfAuthorizationLeasesCommandIssue,
        Self::SelfAuthzGrantsReadEffective,
        Self::SelfAuthzInvitesReadList,
        Self::SelfAuthzReadCheck,
        Self::SelfBlobCommandPresign,
        Self::SelfBlobResourceGet,
        Self::SelfBlobResourceHead,
        Self::SelfBlobUploadCreate,
        Self::SelfCallMediaExchangeIssueToken,
        Self::SelfCircleCommandArchive,
        Self::SelfCircleCommandCreate,
        Self::SelfCircleCommandRestore,
        Self::SelfCircleCommandRotateScope,
        Self::SelfCircleCommandTombstone,
        Self::SelfCircleMemberCommandAdd,
        Self::SelfCircleMemberResourceDelete,
        Self::SelfCircleReadList,
        Self::SelfCircleResourceGet,
        Self::SelfConsentCommandGrant,
        Self::SelfConsentCommandRequest,
        Self::SelfConsentCommandRevoke,
        Self::SelfConsentReadList,
        Self::SelfConsentResourceGet,
        Self::SelfContactCommandCheckpoint,
        Self::SelfContactCommandReject,
        Self::SelfContactCommandRequest,
        Self::SelfContactCommandRespond,
        Self::SelfContactCommandScopeUpdate,
        Self::SelfContactCommandTombstone,
        Self::SelfContactReadList,
        Self::SelfControlProposalAcksCommandIssue,
        Self::SelfControlProposalDecisionsCommandSubmit,
        Self::SelfControlProposalDecisionsReadGet,
        Self::SelfDeviceMessagesCommandAck,
        Self::SelfDeviceMessagesCommandSend,
        Self::SelfDeviceMessagesReadList,
        Self::SelfDirectConversationCommandRepairDispatch,
        Self::SelfDirectConversationReadResolve,
        Self::SelfEventsCommandSubmit,
        Self::SelfEventsCommandSubmitSeal,
        Self::SelfEventsReadDeliveryStatus,
        Self::SelfEventsReadDescribe,
        Self::SelfEventsReadFrontier,
        Self::SelfEventsReadMlsGovernanceProof,
        Self::SelfEventsReadResolve,
        Self::SelfEventsReadScan,
        Self::SelfEventsResourceGet,
        Self::SelfEventsStreamSubscribe,
        Self::SelfIdentityReadResolutionAudit,
        Self::SelfInviteLocatorCommandIssue,
        Self::SelfInviteLocatorCommandRevoke,
        Self::SelfInviteLocatorCommandRotate,
        Self::SelfInviteReceivePolicyResourceGet,
        Self::SelfInviteReceivePolicyResourceReplace,
        Self::SelfInvitesCommandDispatch,
        Self::SelfKeysBackupSeriesCommandErase,
        Self::SelfKeysBackupsCommandIssueDeleteChallenge,
        Self::SelfKeysBackupsCommandUnlock,
        Self::SelfKeysBackupsReadList,
        Self::SelfKeysBackupsResourceDelete,
        Self::SelfKeysBackupsResourceReplace,
        Self::SelfKeysCommandClaim,
        Self::SelfKeysKeypackagesCommandClaim,
        Self::SelfKeysKeypackagesCommandConsume,
        Self::SelfKeysKeypackagesCommandRevoke,
        Self::SelfKeysKeypackagesUploadCreate,
        Self::SelfKeysReadLookup,
        Self::SelfKeysUploadCreate,
        Self::SelfMediaReadIceConfig,
        Self::SelfModerationCommandReport,
        Self::SelfMorphReadList,
        Self::SelfMorphResourceGet,
        Self::SelfPolicyReadCheck,
        Self::SelfReadCursorCommandAdvance,
        Self::SelfReadCursorReadList,
        Self::SelfRealmCommandArchive,
        Self::SelfRealmCommandDestroy,
        Self::SelfRealmCommandFreeze,
        Self::SelfRealmCommandTombstone,
        Self::SelfRealmJoinApplicationAuditReadList,
        Self::SelfRealmJoinApplicationCommandCancel,
        Self::SelfRealmJoinApplicationCommandReview,
        Self::SelfRealmJoinApplicationCommandSubmit,
        Self::SelfRealmJoinApplicationReadList,
        Self::SelfRealmJoinApplicationResourceGet,
        Self::SelfRealmModerationPolicyReadEffective,
        Self::SelfRealmModerationPolicyResourceReplace,
        Self::SelfRealmReadExport,
        Self::SelfRealmResourceGet,
        Self::SelfRealmLinkCommandCreate,
        Self::SelfRealmLinkReadEffectivePolicy,
        Self::SelfRealmLinkReadList,
        Self::SelfRealmLinkResourceDelete,
        Self::SelfRealmOrganizationReadList,
        Self::SelfRealmPolicyServerResourceDelete,
        Self::SelfRealmPolicyServerResourceGet,
        Self::SelfRealmPolicyServerResourceReplace,
        Self::SelfSecurityTransactionCommandContinue,
        Self::SelfSecurityTransactionCommandCreate,
        Self::SelfSecurityTransactionResourceGet,
        Self::SelfSignalCommandSend,
        Self::SelfSignalStreamSubscribe,
        Self::SelfSnapshotReadManifestHead,
        Self::SelfSpaceReadList,
        Self::SelfStrandReadList,
        Self::SelfViewsCollectionProjectionCommandMaterialize,
        Self::ServerReadDescribe,
    ];

    pub const EDGE_APPLET_ACTOR_READ_RESOLVE: &'static str = "ak.edge.applet.actor.read.resolve";
    pub const EDGE_APPLET_COMMAND_TRANSACTION: &'static str = "ak.edge.applet.command.transaction";
    pub const EDGE_APPLET_READ_DESCRIBE: &'static str = "ak.edge.applet.read.describe";
    pub const EDGE_APPLET_READ_PING: &'static str = "ak.edge.applet.read.ping";
    pub const EDGE_APPLET_READ_PROTOCOL_METADATA: &'static str =
        "ak.edge.applet.read.protocol_metadata";
    pub const EDGE_APPLET_REALM_READ_RESOLVE: &'static str = "ak.edge.applet.realm.read.resolve";
    pub const EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST: &'static str =
        "ak.edge.applet.third_party_locations.read.list";
    pub const EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST: &'static str =
        "ak.edge.applet.third_party_users.read.list";
    pub const EDGE_PUSH_COMMAND_NOTIFY: &'static str = "ak.edge.push.command.notify";
    pub const EDGE_PUSH_COMMAND_REGISTER_DEVICE: &'static str =
        "ak.edge.push.command.register_device";
    pub const EDGE_PUSH_COMMAND_UNREGISTER_DEVICE: &'static str =
        "ak.edge.push.command.unregister_device";
    pub const FIND_DIRECTORY_COMMAND_ANNOUNCE: &'static str = "ak.find.directory.command.announce";
    pub const FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL: &'static str =
        "ak.find.directory.command.takedown_appeal";
    pub const FIND_DIRECTORY_COMMAND_WITHDRAW: &'static str = "ak.find.directory.command.withdraw";
    pub const FIND_DIRECTORY_PUSH_COMMAND_REGISTER: &'static str =
        "ak.find.directory.push.command.register";
    pub const FIND_DIRECTORY_READ_DESCRIBE: &'static str = "ak.find.directory.read.describe";
    pub const FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT: &'static str =
        "ak.find.directory.read.list_handles_for_subject";
    pub const FIND_DIRECTORY_READ_PRIVATE_CONTACT_DISCOVERY: &'static str =
        "ak.find.directory.read.private_contact_discovery";
    pub const FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR: &'static str =
        "ak.find.directory.read.resolve_agent_selector";
    pub const FIND_DIRECTORY_READ_RESOLVE_HANDLE: &'static str =
        "ak.find.directory.read.resolve_handle";
    pub const FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION: &'static str =
        "ak.find.directory.read.resolve_organization";
    pub const FIND_DIRECTORY_READ_RESOLVE_REALM: &'static str =
        "ak.find.directory.read.resolve_realm";
    pub const FIND_DIRECTORY_READ_RESOLVE_TARGET: &'static str =
        "ak.find.directory.read.resolve_target";
    pub const FIND_DIRECTORY_READ_SEARCH_ACTORS: &'static str =
        "ak.find.directory.read.search_actors";
    pub const FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS: &'static str =
        "ak.find.directory.read.search_organizations";
    pub const FIND_DIRECTORY_READ_SEARCH_REALMS: &'static str =
        "ak.find.directory.read.search_realms";
    pub const FIND_DIRECTORY_READ_SEARCH_USERS: &'static str =
        "ak.find.directory.read.search_users";
    pub const GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION: &'static str =
        "ak.gate.account.command.abandon_identity_creation";
    pub const GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT: &'static str =
        "ak.gate.account.command.introspect_session_grant";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION: &'static str =
        "ak.gate.account.command.issue_controller_gate_attestation";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE: &'static str =
        "ak.gate.account.command.issue_did_binding_challenge";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_ABANDONMENT_CHALLENGE: &'static str =
        "ak.gate.account.command.issue_identity_abandonment_challenge";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE: &'static str =
        "ak.gate.account.command.issue_identity_binding_challenge";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT: &'static str =
        "ak.gate.account.command.issue_recovery_completion_grant";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT: &'static str =
        "ak.gate.account.command.issue_session_grant";
    pub const GATE_ACCOUNT_COMMAND_LOGOUT: &'static str = "ak.gate.account.command.logout";
    pub const GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION: &'static str =
        "ak.gate.account.command.logout_auth_session";
    pub const GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY: &'static str =
        "ak.gate.account.command.pair_agent_key";
    pub const GATE_ACCOUNT_COMMAND_PAIR_DEVICE: &'static str =
        "ak.gate.account.command.pair_device";
    pub const GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT: &'static str =
        "ak.gate.account.command.refresh_session_grant";
    pub const GATE_ACCOUNT_COMMAND_REGISTER: &'static str = "ak.gate.account.command.register";
    pub const GATE_ACCOUNT_COMMAND_REQUEST_ERASURE: &'static str =
        "ak.gate.account.command.request_erasure";
    pub const GATE_ACCOUNT_COMMAND_REVOKE_SESSION: &'static str =
        "ak.gate.account.command.revoke_session";
    pub const GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF: &'static str =
        "ak.gate.account.exchange.create_handoff";
    pub const GATE_ACCOUNT_READ_ONBOARDING: &'static str = "ak.gate.account.read.onboarding";
    pub const OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST: &'static str =
        "ak.open.agent_pairing.command.submit_runtime_key_request";
    pub const OPEN_AGENT_PAIRING_READ_RESOLVE: &'static str = "ak.open.agent_pairing.read.resolve";
    pub const OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS: &'static str =
        "ak.open.agent_pairing.read.runtime_key_request_status";
    pub const OPEN_DEVICE_PAIRING_COMMAND_STAGE: &'static str =
        "ak.open.device_pairing.command.stage";
    pub const OPEN_DEVICE_PAIRING_READ_RESOLVE: &'static str =
        "ak.open.device_pairing.read.resolve";
    pub const OPEN_DEVICE_PAIRING_READ_STATUS: &'static str = "ak.open.device_pairing.read.status";
    pub const OPEN_IDENTITY_READ_RESOLUTION: &'static str = "ak.open.identity.read.resolution";
    pub const OPEN_INVITE_LOCATOR_READ_RESOLVE: &'static str =
        "ak.open.invite_locator.read.resolve";
    pub const OPEN_MIMI_COMMAND_NOTIFY: &'static str = "ak.open.mimi.command.notify";
    pub const OPEN_MIMI_COMMAND_PROXY_DOWNLOAD: &'static str =
        "ak.open.mimi.command.proxy_download";
    pub const OPEN_MIMI_COMMAND_REPORT_ABUSE: &'static str = "ak.open.mimi.command.report_abuse";
    pub const OPEN_MIMI_COMMAND_REQUEST_CONSENT: &'static str =
        "ak.open.mimi.command.request_consent";
    pub const OPEN_MIMI_COMMAND_SUBMIT_MESSAGE: &'static str =
        "ak.open.mimi.command.submit_message";
    pub const OPEN_MIMI_COMMAND_UPDATE_CONSENT: &'static str =
        "ak.open.mimi.command.update_consent";
    pub const OPEN_MIMI_COMMAND_UPDATE_ROOM: &'static str = "ak.open.mimi.command.update_room";
    pub const OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL: &'static str =
        "ak.open.mimi.exchange.request_key_material";
    pub const OPEN_MIMI_READ_GROUP_INFO: &'static str = "ak.open.mimi.read.group_info";
    pub const OPEN_MIMI_READ_IDENTIFIERS: &'static str = "ak.open.mimi.read.identifiers";
    pub const OPEN_MIMI_READ_PROVIDER_DIRECTORY: &'static str =
        "ak.open.mimi.read.provider_directory";
    pub const OPEN_SERVICE_READ_RESOLUTION: &'static str = "ak.open.service.read.resolution";
    pub const PEER_ACCOUNT_STATUS_COMMAND_SUBMIT: &'static str =
        "ak.peer.account_status.command.submit";
    pub const PEER_ACCOUNT_STATUS_READ_RESOLVE: &'static str =
        "ak.peer.account_status.read.resolve";
    pub const PEER_CONTACTS_COMMAND_SUBMIT: &'static str = "ak.peer.contacts.command.submit";
    pub const PEER_DEVICE_REVOCATIONS_COMMAND_CHECK: &'static str =
        "ak.peer.device_revocations.command.check";
    pub const PEER_DIRECT_CONVERSATION_COMMAND_REPAIR_RELAY: &'static str =
        "ak.peer.direct_conversation.command.repair_relay";
    pub const PEER_ERASURE_RECEIPT_COMMAND_SUBMIT: &'static str =
        "ak.peer.erasure_receipt.command.submit";
    pub const PEER_ERASURE_RECEIPT_RESOURCE_GET: &'static str =
        "ak.peer.erasure_receipt.resource.get";
    pub const PEER_EVENTS_COMMAND_SUBMIT: &'static str = "ak.peer.events.command.submit";
    pub const PEER_EVENTS_READ_DESCRIBE: &'static str = "ak.peer.events.read.describe";
    pub const PEER_EVENTS_READ_FRONTIER: &'static str = "ak.peer.events.read.frontier";
    pub const PEER_EVENTS_READ_RESOLVE: &'static str = "ak.peer.events.read.resolve";
    pub const PEER_EVENTS_READ_SCAN: &'static str = "ak.peer.events.read.scan";
    pub const PEER_INVITES_COMMAND_SUBMIT: &'static str = "ak.peer.invites.command.submit";
    pub const PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM: &'static str =
        "ak.peer.keys.keypackages.command.claim";
    pub const PEER_KEYS_KEYPACKAGES_READ_CLAIM: &'static str =
        "ak.peer.keys.keypackages.read.claim";
    pub const PEER_MLS_READ_GROUP_STATE_MATERIAL: &'static str =
        "ak.peer.mls.read.group_state_material";
    pub const PEER_PRINCIPAL_GENESIS_COMMAND_SUBMIT: &'static str =
        "ak.peer.principal_genesis.command.submit";
    pub const PEER_SERVICE_RESOLUTION_COMMAND_PUBLISH: &'static str =
        "ak.peer.service_resolution.command.publish";
    pub const PEER_SERVICE_RESOLUTION_READ_RESOLVE: &'static str =
        "ak.peer.service_resolution.read.resolve";
    pub const PEER_SIGNAL_COMMAND_RELAY: &'static str = "ak.peer.signal.command.relay";
    pub const PEER_SNAPSHOT_READ_MANIFEST_HEAD: &'static str =
        "ak.peer.snapshot.read.manifest_head";
    pub const ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION: &'static str =
        "ak.root.identity.command.submit_did_operation";
    pub const ROOT_IDENTITY_DOCUMENT_RESOURCE_GET: &'static str =
        "ak.root.identity.document.resource.get";
    pub const ROOT_IDENTITY_LOG_READ_LIST: &'static str = "ak.root.identity.log.read.list";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE: &'static str =
        "ak.root.identity.organization_registration.command.ensure";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE: &'static str =
        "ak.root.identity.organization_registration.command.prepare";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH: &'static str =
        "ak.root.identity.organization_registration.command.refresh";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE: &'static str =
        "ak.root.identity.organization_registration.command.revoke";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET: &'static str =
        "ak.root.identity.organization_registration.resource.get";
    pub const ROOT_IDENTITY_READ_RESOLVE: &'static str = "ak.root.identity.read.resolve";
    pub const ROOT_IDENTITY_RECEIPTS_READ_LIST: &'static str =
        "ak.root.identity.receipts.read.list";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH: &'static str =
        "ak.root.identity.recovery_policy.command.publish";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET: &'static str =
        "ak.root.identity.recovery_policy.resource.get";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE: &'static str =
        "ak.root.identity.recovery_session.command.create";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF: &'static str =
        "ak.root.identity.recovery_session.command.submit_proof";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET: &'static str =
        "ak.root.identity.recovery_session.resource.get";
    pub const ROOT_IDENTITY_REGISTRY_READ_DESCRIBE: &'static str =
        "ak.root.identity.registry.read.describe";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE: &'static str =
        "ak.root.identity.service_registration.command.ensure";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET: &'static str =
        "ak.root.identity.service_registration.resource.get";
    pub const SELF_ACCOUNT_COMMAND_REVOKE_CURSOR: &'static str =
        "ak.self.account.command.revoke_cursor";
    pub const SELF_ACCOUNT_COMMAND_UPDATE_PROFILE: &'static str =
        "ak.self.account.command.update_profile";
    pub const SELF_ACCOUNT_READ_DESCRIBE: &'static str = "ak.self.account.read.describe";
    pub const SELF_ACCOUNT_READ_VIEWER: &'static str = "ak.self.account.read.viewer";
    pub const SELF_ACCOUNT_STREAM_SUBSCRIBE: &'static str = "ak.self.account.stream.subscribe";
    pub const SELF_ACCOUNT_DATA_READ_LIST: &'static str = "ak.self.account_data.read.list";
    pub const SELF_ACCOUNT_DATA_RESOURCE_DELETE: &'static str =
        "ak.self.account_data.resource.delete";
    pub const SELF_ACCOUNT_DATA_RESOURCE_GET: &'static str = "ak.self.account_data.resource.get";
    pub const SELF_ACCOUNT_DATA_RESOURCE_REPLACE: &'static str =
        "ak.self.account_data.resource.replace";
    pub const SELF_ACTOR_PROFILE_READ_RESOLVE: &'static str = "ak.self.actor_profile.read.resolve";
    pub const SELF_AGENT_COMMAND_ABANDON_PROVISIONING: &'static str =
        "ak.self.agent.command.abandon_provisioning";
    pub const SELF_AGENT_COMMAND_DEACTIVATE: &'static str = "ak.self.agent.command.deactivate";
    pub const SELF_AGENT_COMMAND_ISSUE_PROVISIONING_ABANDONMENT_CHALLENGE: &'static str =
        "ak.self.agent.command.issue_provisioning_abandonment_challenge";
    pub const SELF_AGENT_COMMAND_PAUSE: &'static str = "ak.self.agent.command.pause";
    pub const SELF_AGENT_COMMAND_PROVISION: &'static str = "ak.self.agent.command.provision";
    pub const SELF_AGENT_COMMAND_RENEW_PAIRING: &'static str =
        "ak.self.agent.command.renew_pairing";
    pub const SELF_AGENT_COMMAND_RESUME: &'static str = "ak.self.agent.command.resume";
    pub const SELF_AGENT_GRANT_COMMAND_ATTACH: &'static str = "ak.self.agent.grant.command.attach";
    pub const SELF_AGENT_GRANT_RESOURCE_DELETE: &'static str =
        "ak.self.agent.grant.resource.delete";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_GET: &'static str =
        "ak.self.agent.participation.resource.get";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE: &'static str =
        "ak.self.agent.participation.resource.replace";
    pub const SELF_AGENT_READ_LIST: &'static str = "ak.self.agent.read.list";
    pub const SELF_AGENT_RESOURCE_GET: &'static str = "ak.self.agent.resource.get";
    pub const SELF_AGENT_SIDECAR_COMMAND_ENSURE: &'static str =
        "ak.self.agent.sidecar.command.ensure";
    pub const SELF_AGENT_SIDECAR_READ_LIST: &'static str = "ak.self.agent.sidecar.read.list";
    pub const SELF_AGENT_SIDECAR_RESOURCE_GET: &'static str = "ak.self.agent.sidecar.resource.get";
    pub const SELF_AGENT_SIGNER_EVIDENCE_READ_RESOLVE: &'static str =
        "ak.self.agent_signer_evidence.read.resolve";
    pub const SELF_APPLET_COMMAND_INSTALL: &'static str = "ak.self.applet.command.install";
    pub const SELF_APPLET_COMMAND_REVOKE: &'static str = "ak.self.applet.command.revoke";
    pub const SELF_APPLET_GHOST_COMMAND_PROVISION: &'static str =
        "ak.self.applet.ghost.command.provision";
    pub const SELF_APPLET_INSTALL_COMMAND_PREVIEW: &'static str =
        "ak.self.applet.install.command.preview";
    pub const SELF_APPLET_REVOKE_COMMAND_PREVIEW: &'static str =
        "ak.self.applet.revoke.command.preview";
    pub const SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE: &'static str =
        "ak.self.authorization_leases.command.issue";
    pub const SELF_AUTHZ_GRANTS_READ_EFFECTIVE: &'static str =
        "ak.self.authz.grants.read.effective";
    pub const SELF_AUTHZ_INVITES_READ_LIST: &'static str = "ak.self.authz.invites.read.list";
    pub const SELF_AUTHZ_READ_CHECK: &'static str = "ak.self.authz.read.check";
    pub const SELF_BLOB_COMMAND_PRESIGN: &'static str = "ak.self.blob.command.presign";
    pub const SELF_BLOB_RESOURCE_GET: &'static str = "ak.self.blob.resource.get";
    pub const SELF_BLOB_RESOURCE_HEAD: &'static str = "ak.self.blob.resource.head";
    pub const SELF_BLOB_UPLOAD_CREATE: &'static str = "ak.self.blob.upload.create";
    pub const SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN: &'static str =
        "ak.self.call.media.exchange.issue_token";
    pub const SELF_CIRCLE_COMMAND_ARCHIVE: &'static str = "ak.self.circle.command.archive";
    pub const SELF_CIRCLE_COMMAND_CREATE: &'static str = "ak.self.circle.command.create";
    pub const SELF_CIRCLE_COMMAND_RESTORE: &'static str = "ak.self.circle.command.restore";
    pub const SELF_CIRCLE_COMMAND_ROTATE_SCOPE: &'static str =
        "ak.self.circle.command.rotate_scope";
    pub const SELF_CIRCLE_COMMAND_TOMBSTONE: &'static str = "ak.self.circle.command.tombstone";
    pub const SELF_CIRCLE_MEMBER_COMMAND_ADD: &'static str = "ak.self.circle.member.command.add";
    pub const SELF_CIRCLE_MEMBER_RESOURCE_DELETE: &'static str =
        "ak.self.circle.member.resource.delete";
    pub const SELF_CIRCLE_READ_LIST: &'static str = "ak.self.circle.read.list";
    pub const SELF_CIRCLE_RESOURCE_GET: &'static str = "ak.self.circle.resource.get";
    pub const SELF_CONSENT_COMMAND_GRANT: &'static str = "ak.self.consent.command.grant";
    pub const SELF_CONSENT_COMMAND_REQUEST: &'static str = "ak.self.consent.command.request";
    pub const SELF_CONSENT_COMMAND_REVOKE: &'static str = "ak.self.consent.command.revoke";
    pub const SELF_CONSENT_READ_LIST: &'static str = "ak.self.consent.read.list";
    pub const SELF_CONSENT_RESOURCE_GET: &'static str = "ak.self.consent.resource.get";
    pub const SELF_CONTACT_COMMAND_CHECKPOINT: &'static str = "ak.self.contact.command.checkpoint";
    pub const SELF_CONTACT_COMMAND_REJECT: &'static str = "ak.self.contact.command.reject";
    pub const SELF_CONTACT_COMMAND_REQUEST: &'static str = "ak.self.contact.command.request";
    pub const SELF_CONTACT_COMMAND_RESPOND: &'static str = "ak.self.contact.command.respond";
    pub const SELF_CONTACT_COMMAND_SCOPE_UPDATE: &'static str =
        "ak.self.contact.command.scope_update";
    pub const SELF_CONTACT_COMMAND_TOMBSTONE: &'static str = "ak.self.contact.command.tombstone";
    pub const SELF_CONTACT_READ_LIST: &'static str = "ak.self.contact.read.list";
    pub const SELF_CONTROL_PROPOSAL_ACKS_COMMAND_ISSUE: &'static str =
        "ak.self.control_proposal_acks.command.issue";
    pub const SELF_CONTROL_PROPOSAL_DECISIONS_COMMAND_SUBMIT: &'static str =
        "ak.self.control_proposal_decisions.command.submit";
    pub const SELF_CONTROL_PROPOSAL_DECISIONS_READ_GET: &'static str =
        "ak.self.control_proposal_decisions.read.get";
    pub const SELF_DEVICE_MESSAGES_COMMAND_ACK: &'static str =
        "ak.self.device_messages.command.ack";
    pub const SELF_DEVICE_MESSAGES_COMMAND_SEND: &'static str =
        "ak.self.device_messages.command.send";
    pub const SELF_DEVICE_MESSAGES_READ_LIST: &'static str = "ak.self.device_messages.read.list";
    pub const SELF_DIRECT_CONVERSATION_COMMAND_REPAIR_DISPATCH: &'static str =
        "ak.self.direct_conversation.command.repair_dispatch";
    pub const SELF_DIRECT_CONVERSATION_READ_RESOLVE: &'static str =
        "ak.self.direct_conversation.read.resolve";
    pub const SELF_EVENTS_COMMAND_SUBMIT: &'static str = "ak.self.events.command.submit";
    pub const SELF_EVENTS_COMMAND_SUBMIT_SEAL: &'static str = "ak.self.events.command.submit_seal";
    pub const SELF_EVENTS_READ_DELIVERY_STATUS: &'static str =
        "ak.self.events.read.delivery_status";
    pub const SELF_EVENTS_READ_DESCRIBE: &'static str = "ak.self.events.read.describe";
    pub const SELF_EVENTS_READ_FRONTIER: &'static str = "ak.self.events.read.frontier";
    pub const SELF_EVENTS_READ_MLS_GOVERNANCE_PROOF: &'static str =
        "ak.self.events.read.mls_governance_proof";
    pub const SELF_EVENTS_READ_RESOLVE: &'static str = "ak.self.events.read.resolve";
    pub const SELF_EVENTS_READ_SCAN: &'static str = "ak.self.events.read.scan";
    pub const SELF_EVENTS_RESOURCE_GET: &'static str = "ak.self.events.resource.get";
    pub const SELF_EVENTS_STREAM_SUBSCRIBE: &'static str = "ak.self.events.stream.subscribe";
    pub const SELF_IDENTITY_READ_RESOLUTION_AUDIT: &'static str =
        "ak.self.identity.read.resolution_audit";
    pub const SELF_INVITE_LOCATOR_COMMAND_ISSUE: &'static str =
        "ak.self.invite_locator.command.issue";
    pub const SELF_INVITE_LOCATOR_COMMAND_REVOKE: &'static str =
        "ak.self.invite_locator.command.revoke";
    pub const SELF_INVITE_LOCATOR_COMMAND_ROTATE: &'static str =
        "ak.self.invite_locator.command.rotate";
    pub const SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET: &'static str =
        "ak.self.invite_receive_policy.resource.get";
    pub const SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE: &'static str =
        "ak.self.invite_receive_policy.resource.replace";
    pub const SELF_INVITES_COMMAND_DISPATCH: &'static str = "ak.self.invites.command.dispatch";
    pub const SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE: &'static str =
        "ak.self.keys.backup_series.command.erase";
    pub const SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE: &'static str =
        "ak.self.keys.backups.command.issue_delete_challenge";
    pub const SELF_KEYS_BACKUPS_COMMAND_UNLOCK: &'static str =
        "ak.self.keys.backups.command.unlock";
    pub const SELF_KEYS_BACKUPS_READ_LIST: &'static str = "ak.self.keys.backups.read.list";
    pub const SELF_KEYS_BACKUPS_RESOURCE_DELETE: &'static str =
        "ak.self.keys.backups.resource.delete";
    pub const SELF_KEYS_BACKUPS_RESOURCE_REPLACE: &'static str =
        "ak.self.keys.backups.resource.replace";
    pub const SELF_KEYS_COMMAND_CLAIM: &'static str = "ak.self.keys.command.claim";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM: &'static str =
        "ak.self.keys.keypackages.command.claim";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME: &'static str =
        "ak.self.keys.keypackages.command.consume";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE: &'static str =
        "ak.self.keys.keypackages.command.revoke";
    pub const SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE: &'static str =
        "ak.self.keys.keypackages.upload.create";
    pub const SELF_KEYS_READ_LOOKUP: &'static str = "ak.self.keys.read.lookup";
    pub const SELF_KEYS_UPLOAD_CREATE: &'static str = "ak.self.keys.upload.create";
    pub const SELF_MEDIA_READ_ICE_CONFIG: &'static str = "ak.self.media.read.ice_config";
    pub const SELF_MODERATION_COMMAND_REPORT: &'static str = "ak.self.moderation.command.report";
    pub const SELF_MORPH_READ_LIST: &'static str = "ak.self.morph.read.list";
    pub const SELF_MORPH_RESOURCE_GET: &'static str = "ak.self.morph.resource.get";
    pub const SELF_POLICY_READ_CHECK: &'static str = "ak.self.policy.read.check";
    pub const SELF_READ_CURSOR_COMMAND_ADVANCE: &'static str =
        "ak.self.read_cursor.command.advance";
    pub const SELF_READ_CURSOR_READ_LIST: &'static str = "ak.self.read_cursor.read.list";
    pub const SELF_REALM_COMMAND_ARCHIVE: &'static str = "ak.self.realm.command.archive";
    pub const SELF_REALM_COMMAND_DESTROY: &'static str = "ak.self.realm.command.destroy";
    pub const SELF_REALM_COMMAND_FREEZE: &'static str = "ak.self.realm.command.freeze";
    pub const SELF_REALM_COMMAND_TOMBSTONE: &'static str = "ak.self.realm.command.tombstone";
    pub const SELF_REALM_JOIN_APPLICATION_AUDIT_READ_LIST: &'static str =
        "ak.self.realm.join_application.audit.read.list";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL: &'static str =
        "ak.self.realm.join_application.command.cancel";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW: &'static str =
        "ak.self.realm.join_application.command.review";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT: &'static str =
        "ak.self.realm.join_application.command.submit";
    pub const SELF_REALM_JOIN_APPLICATION_READ_LIST: &'static str =
        "ak.self.realm.join_application.read.list";
    pub const SELF_REALM_JOIN_APPLICATION_RESOURCE_GET: &'static str =
        "ak.self.realm.join_application.resource.get";
    pub const SELF_REALM_MODERATION_POLICY_READ_EFFECTIVE: &'static str =
        "ak.self.realm.moderation_policy.read.effective";
    pub const SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE: &'static str =
        "ak.self.realm.moderation_policy.resource.replace";
    pub const SELF_REALM_READ_EXPORT: &'static str = "ak.self.realm.read.export";
    pub const SELF_REALM_RESOURCE_GET: &'static str = "ak.self.realm.resource.get";
    pub const SELF_REALM_LINK_COMMAND_CREATE: &'static str = "ak.self.realm_link.command.create";
    pub const SELF_REALM_LINK_READ_EFFECTIVE_POLICY: &'static str =
        "ak.self.realm_link.read.effective_policy";
    pub const SELF_REALM_LINK_READ_LIST: &'static str = "ak.self.realm_link.read.list";
    pub const SELF_REALM_LINK_RESOURCE_DELETE: &'static str = "ak.self.realm_link.resource.delete";
    pub const SELF_REALM_ORGANIZATION_READ_LIST: &'static str =
        "ak.self.realm_organization.read.list";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_DELETE: &'static str =
        "ak.self.realm_policy_server.resource.delete";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_GET: &'static str =
        "ak.self.realm_policy_server.resource.get";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE: &'static str =
        "ak.self.realm_policy_server.resource.replace";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE: &'static str =
        "ak.self.security_transaction.command.continue";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CREATE: &'static str =
        "ak.self.security_transaction.command.create";
    pub const SELF_SECURITY_TRANSACTION_RESOURCE_GET: &'static str =
        "ak.self.security_transaction.resource.get";
    pub const SELF_SIGNAL_COMMAND_SEND: &'static str = "ak.self.signal.command.send";
    pub const SELF_SIGNAL_STREAM_SUBSCRIBE: &'static str = "ak.self.signal.stream.subscribe";
    pub const SELF_SNAPSHOT_READ_MANIFEST_HEAD: &'static str =
        "ak.self.snapshot.read.manifest_head";
    pub const SELF_SPACE_READ_LIST: &'static str = "ak.self.space.read.list";
    pub const SELF_STRAND_READ_LIST: &'static str = "ak.self.strand.read.list";
    pub const SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE: &'static str =
        "ak.self.views.collection_projection.command.materialize";
    pub const SERVER_READ_DESCRIBE: &'static str = "ak.server.read.describe";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeAppletActorReadResolve => Self::EDGE_APPLET_ACTOR_READ_RESOLVE,
            Self::EdgeAppletCommandTransaction => Self::EDGE_APPLET_COMMAND_TRANSACTION,
            Self::EdgeAppletReadDescribe => Self::EDGE_APPLET_READ_DESCRIBE,
            Self::EdgeAppletReadPing => Self::EDGE_APPLET_READ_PING,
            Self::EdgeAppletReadProtocolMetadata => Self::EDGE_APPLET_READ_PROTOCOL_METADATA,
            Self::EdgeAppletRealmReadResolve => Self::EDGE_APPLET_REALM_READ_RESOLVE,
            Self::EdgeAppletThirdPartyLocationsReadList => {
                Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST
            }
            Self::EdgeAppletThirdPartyUsersReadList => {
                Self::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST
            }
            Self::EdgePushCommandNotify => Self::EDGE_PUSH_COMMAND_NOTIFY,
            Self::EdgePushCommandRegisterDevice => Self::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            Self::EdgePushCommandUnregisterDevice => Self::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE,
            Self::FindDirectoryCommandAnnounce => Self::FIND_DIRECTORY_COMMAND_ANNOUNCE,
            Self::FindDirectoryCommandTakedownAppeal => {
                Self::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL
            }
            Self::FindDirectoryCommandWithdraw => Self::FIND_DIRECTORY_COMMAND_WITHDRAW,
            Self::FindDirectoryPushCommandRegister => Self::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
            Self::FindDirectoryReadDescribe => Self::FIND_DIRECTORY_READ_DESCRIBE,
            Self::FindDirectoryReadListHandlesForSubject => {
                Self::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT
            }
            Self::FindDirectoryReadPrivateContactDiscovery => {
                Self::FIND_DIRECTORY_READ_PRIVATE_CONTACT_DISCOVERY
            }
            Self::FindDirectoryReadResolveAgentSelector => {
                Self::FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR
            }
            Self::FindDirectoryReadResolveHandle => Self::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
            Self::FindDirectoryReadResolveOrganization => {
                Self::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION
            }
            Self::FindDirectoryReadResolveRealm => Self::FIND_DIRECTORY_READ_RESOLVE_REALM,
            Self::FindDirectoryReadResolveTarget => Self::FIND_DIRECTORY_READ_RESOLVE_TARGET,
            Self::FindDirectoryReadSearchActors => Self::FIND_DIRECTORY_READ_SEARCH_ACTORS,
            Self::FindDirectoryReadSearchOrganizations => {
                Self::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS
            }
            Self::FindDirectoryReadSearchRealms => Self::FIND_DIRECTORY_READ_SEARCH_REALMS,
            Self::FindDirectoryReadSearchUsers => Self::FIND_DIRECTORY_READ_SEARCH_USERS,
            Self::GateAccountCommandAbandonIdentityCreation => {
                Self::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION
            }
            Self::GateAccountCommandIntrospectSessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT
            }
            Self::GateAccountCommandIssueControllerGateAttestation => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION
            }
            Self::GateAccountCommandIssueDidBindingChallenge => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE
            }
            Self::GateAccountCommandIssueIdentityAbandonmentChallenge => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_ABANDONMENT_CHALLENGE
            }
            Self::GateAccountCommandIssueIdentityBindingChallenge => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE
            }
            Self::GateAccountCommandIssueRecoveryCompletionGrant => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT
            }
            Self::GateAccountCommandIssueSessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT
            }
            Self::GateAccountCommandLogout => Self::GATE_ACCOUNT_COMMAND_LOGOUT,
            Self::GateAccountCommandLogoutAuthSession => {
                Self::GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION
            }
            Self::GateAccountCommandPairAgentKey => Self::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            Self::GateAccountCommandPairDevice => Self::GATE_ACCOUNT_COMMAND_PAIR_DEVICE,
            Self::GateAccountCommandRefreshSessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT
            }
            Self::GateAccountCommandRegister => Self::GATE_ACCOUNT_COMMAND_REGISTER,
            Self::GateAccountCommandRequestErasure => Self::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE,
            Self::GateAccountCommandRevokeSession => Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
            Self::GateAccountExchangeCreateHandoff => Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF,
            Self::GateAccountReadOnboarding => Self::GATE_ACCOUNT_READ_ONBOARDING,
            Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest => {
                Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST
            }
            Self::OpenAgentPairingReadResolve => Self::OPEN_AGENT_PAIRING_READ_RESOLVE,
            Self::OpenAgentPairingReadRuntimeKeyRequestStatus => {
                Self::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS
            }
            Self::OpenDevicePairingCommandStage => Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE,
            Self::OpenDevicePairingReadResolve => Self::OPEN_DEVICE_PAIRING_READ_RESOLVE,
            Self::OpenDevicePairingReadStatus => Self::OPEN_DEVICE_PAIRING_READ_STATUS,
            Self::OpenIdentityReadResolution => Self::OPEN_IDENTITY_READ_RESOLUTION,
            Self::OpenInviteLocatorReadResolve => Self::OPEN_INVITE_LOCATOR_READ_RESOLVE,
            Self::OpenMimiCommandNotify => Self::OPEN_MIMI_COMMAND_NOTIFY,
            Self::OpenMimiCommandProxyDownload => Self::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD,
            Self::OpenMimiCommandReportAbuse => Self::OPEN_MIMI_COMMAND_REPORT_ABUSE,
            Self::OpenMimiCommandRequestConsent => Self::OPEN_MIMI_COMMAND_REQUEST_CONSENT,
            Self::OpenMimiCommandSubmitMessage => Self::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE,
            Self::OpenMimiCommandUpdateConsent => Self::OPEN_MIMI_COMMAND_UPDATE_CONSENT,
            Self::OpenMimiCommandUpdateRoom => Self::OPEN_MIMI_COMMAND_UPDATE_ROOM,
            Self::OpenMimiExchangeRequestKeyMaterial => {
                Self::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL
            }
            Self::OpenMimiReadGroupInfo => Self::OPEN_MIMI_READ_GROUP_INFO,
            Self::OpenMimiReadIdentifiers => Self::OPEN_MIMI_READ_IDENTIFIERS,
            Self::OpenMimiReadProviderDirectory => Self::OPEN_MIMI_READ_PROVIDER_DIRECTORY,
            Self::OpenServiceReadResolution => Self::OPEN_SERVICE_READ_RESOLUTION,
            Self::PeerAccountStatusCommandSubmit => Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT,
            Self::PeerAccountStatusReadResolve => Self::PEER_ACCOUNT_STATUS_READ_RESOLVE,
            Self::PeerContactsCommandSubmit => Self::PEER_CONTACTS_COMMAND_SUBMIT,
            Self::PeerDeviceRevocationsCommandCheck => Self::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK,
            Self::PeerDirectConversationCommandRepairRelay => {
                Self::PEER_DIRECT_CONVERSATION_COMMAND_REPAIR_RELAY
            }
            Self::PeerErasureReceiptCommandSubmit => Self::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT,
            Self::PeerErasureReceiptResourceGet => Self::PEER_ERASURE_RECEIPT_RESOURCE_GET,
            Self::PeerEventsCommandSubmit => Self::PEER_EVENTS_COMMAND_SUBMIT,
            Self::PeerEventsReadDescribe => Self::PEER_EVENTS_READ_DESCRIBE,
            Self::PeerEventsReadFrontier => Self::PEER_EVENTS_READ_FRONTIER,
            Self::PeerEventsReadResolve => Self::PEER_EVENTS_READ_RESOLVE,
            Self::PeerEventsReadScan => Self::PEER_EVENTS_READ_SCAN,
            Self::PeerInvitesCommandSubmit => Self::PEER_INVITES_COMMAND_SUBMIT,
            Self::PeerKeysKeypackagesCommandClaim => Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM,
            Self::PeerKeysKeypackagesReadClaim => Self::PEER_KEYS_KEYPACKAGES_READ_CLAIM,
            Self::PeerMlsReadGroupStateMaterial => Self::PEER_MLS_READ_GROUP_STATE_MATERIAL,
            Self::PeerPrincipalGenesisCommandSubmit => Self::PEER_PRINCIPAL_GENESIS_COMMAND_SUBMIT,
            Self::PeerServiceResolutionCommandPublish => {
                Self::PEER_SERVICE_RESOLUTION_COMMAND_PUBLISH
            }
            Self::PeerServiceResolutionReadResolve => Self::PEER_SERVICE_RESOLUTION_READ_RESOLVE,
            Self::PeerSignalCommandRelay => Self::PEER_SIGNAL_COMMAND_RELAY,
            Self::PeerSnapshotReadManifestHead => Self::PEER_SNAPSHOT_READ_MANIFEST_HEAD,
            Self::RootIdentityCommandSubmitDidOperation => {
                Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION
            }
            Self::RootIdentityDocumentResourceGet => Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET,
            Self::RootIdentityLogReadList => Self::ROOT_IDENTITY_LOG_READ_LIST,
            Self::RootIdentityOrganizationRegistrationCommandEnsure => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE
            }
            Self::RootIdentityOrganizationRegistrationCommandPrepare => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE
            }
            Self::RootIdentityOrganizationRegistrationCommandRefresh => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH
            }
            Self::RootIdentityOrganizationRegistrationCommandRevoke => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE
            }
            Self::RootIdentityOrganizationRegistrationResourceGet => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET
            }
            Self::RootIdentityReadResolve => Self::ROOT_IDENTITY_READ_RESOLVE,
            Self::RootIdentityReceiptsReadList => Self::ROOT_IDENTITY_RECEIPTS_READ_LIST,
            Self::RootIdentityRecoveryPolicyCommandPublish => {
                Self::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH
            }
            Self::RootIdentityRecoveryPolicyResourceGet => {
                Self::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET
            }
            Self::RootIdentityRecoverySessionCommandCreate => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE
            }
            Self::RootIdentityRecoverySessionCommandSubmitProof => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF
            }
            Self::RootIdentityRecoverySessionResourceGet => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET
            }
            Self::RootIdentityRegistryReadDescribe => Self::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE,
            Self::RootIdentityServiceRegistrationCommandEnsure => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE
            }
            Self::RootIdentityServiceRegistrationResourceGet => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET
            }
            Self::SelfAccountCommandRevokeCursor => Self::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR,
            Self::SelfAccountCommandUpdateProfile => Self::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE,
            Self::SelfAccountReadDescribe => Self::SELF_ACCOUNT_READ_DESCRIBE,
            Self::SelfAccountReadViewer => Self::SELF_ACCOUNT_READ_VIEWER,
            Self::SelfAccountStreamSubscribe => Self::SELF_ACCOUNT_STREAM_SUBSCRIBE,
            Self::SelfAccountDataReadList => Self::SELF_ACCOUNT_DATA_READ_LIST,
            Self::SelfAccountDataResourceDelete => Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE,
            Self::SelfAccountDataResourceGet => Self::SELF_ACCOUNT_DATA_RESOURCE_GET,
            Self::SelfAccountDataResourceReplace => Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE,
            Self::SelfActorProfileReadResolve => Self::SELF_ACTOR_PROFILE_READ_RESOLVE,
            Self::SelfAgentCommandAbandonProvisioning => {
                Self::SELF_AGENT_COMMAND_ABANDON_PROVISIONING
            }
            Self::SelfAgentCommandDeactivate => Self::SELF_AGENT_COMMAND_DEACTIVATE,
            Self::SelfAgentCommandIssueProvisioningAbandonmentChallenge => {
                Self::SELF_AGENT_COMMAND_ISSUE_PROVISIONING_ABANDONMENT_CHALLENGE
            }
            Self::SelfAgentCommandPause => Self::SELF_AGENT_COMMAND_PAUSE,
            Self::SelfAgentCommandProvision => Self::SELF_AGENT_COMMAND_PROVISION,
            Self::SelfAgentCommandRenewPairing => Self::SELF_AGENT_COMMAND_RENEW_PAIRING,
            Self::SelfAgentCommandResume => Self::SELF_AGENT_COMMAND_RESUME,
            Self::SelfAgentGrantCommandAttach => Self::SELF_AGENT_GRANT_COMMAND_ATTACH,
            Self::SelfAgentGrantResourceDelete => Self::SELF_AGENT_GRANT_RESOURCE_DELETE,
            Self::SelfAgentParticipationResourceGet => Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET,
            Self::SelfAgentParticipationResourceReplace => {
                Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE
            }
            Self::SelfAgentReadList => Self::SELF_AGENT_READ_LIST,
            Self::SelfAgentResourceGet => Self::SELF_AGENT_RESOURCE_GET,
            Self::SelfAgentSidecarCommandEnsure => Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
            Self::SelfAgentSidecarReadList => Self::SELF_AGENT_SIDECAR_READ_LIST,
            Self::SelfAgentSidecarResourceGet => Self::SELF_AGENT_SIDECAR_RESOURCE_GET,
            Self::SelfAgentSignerEvidenceReadResolve => {
                Self::SELF_AGENT_SIGNER_EVIDENCE_READ_RESOLVE
            }
            Self::SelfAppletCommandInstall => Self::SELF_APPLET_COMMAND_INSTALL,
            Self::SelfAppletCommandRevoke => Self::SELF_APPLET_COMMAND_REVOKE,
            Self::SelfAppletGhostCommandProvision => Self::SELF_APPLET_GHOST_COMMAND_PROVISION,
            Self::SelfAppletInstallCommandPreview => Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW,
            Self::SelfAppletRevokeCommandPreview => Self::SELF_APPLET_REVOKE_COMMAND_PREVIEW,
            Self::SelfAuthorizationLeasesCommandIssue => {
                Self::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE
            }
            Self::SelfAuthzGrantsReadEffective => Self::SELF_AUTHZ_GRANTS_READ_EFFECTIVE,
            Self::SelfAuthzInvitesReadList => Self::SELF_AUTHZ_INVITES_READ_LIST,
            Self::SelfAuthzReadCheck => Self::SELF_AUTHZ_READ_CHECK,
            Self::SelfBlobCommandPresign => Self::SELF_BLOB_COMMAND_PRESIGN,
            Self::SelfBlobResourceGet => Self::SELF_BLOB_RESOURCE_GET,
            Self::SelfBlobResourceHead => Self::SELF_BLOB_RESOURCE_HEAD,
            Self::SelfBlobUploadCreate => Self::SELF_BLOB_UPLOAD_CREATE,
            Self::SelfCallMediaExchangeIssueToken => Self::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN,
            Self::SelfCircleCommandArchive => Self::SELF_CIRCLE_COMMAND_ARCHIVE,
            Self::SelfCircleCommandCreate => Self::SELF_CIRCLE_COMMAND_CREATE,
            Self::SelfCircleCommandRestore => Self::SELF_CIRCLE_COMMAND_RESTORE,
            Self::SelfCircleCommandRotateScope => Self::SELF_CIRCLE_COMMAND_ROTATE_SCOPE,
            Self::SelfCircleCommandTombstone => Self::SELF_CIRCLE_COMMAND_TOMBSTONE,
            Self::SelfCircleMemberCommandAdd => Self::SELF_CIRCLE_MEMBER_COMMAND_ADD,
            Self::SelfCircleMemberResourceDelete => Self::SELF_CIRCLE_MEMBER_RESOURCE_DELETE,
            Self::SelfCircleReadList => Self::SELF_CIRCLE_READ_LIST,
            Self::SelfCircleResourceGet => Self::SELF_CIRCLE_RESOURCE_GET,
            Self::SelfConsentCommandGrant => Self::SELF_CONSENT_COMMAND_GRANT,
            Self::SelfConsentCommandRequest => Self::SELF_CONSENT_COMMAND_REQUEST,
            Self::SelfConsentCommandRevoke => Self::SELF_CONSENT_COMMAND_REVOKE,
            Self::SelfConsentReadList => Self::SELF_CONSENT_READ_LIST,
            Self::SelfConsentResourceGet => Self::SELF_CONSENT_RESOURCE_GET,
            Self::SelfContactCommandCheckpoint => Self::SELF_CONTACT_COMMAND_CHECKPOINT,
            Self::SelfContactCommandReject => Self::SELF_CONTACT_COMMAND_REJECT,
            Self::SelfContactCommandRequest => Self::SELF_CONTACT_COMMAND_REQUEST,
            Self::SelfContactCommandRespond => Self::SELF_CONTACT_COMMAND_RESPOND,
            Self::SelfContactCommandScopeUpdate => Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE,
            Self::SelfContactCommandTombstone => Self::SELF_CONTACT_COMMAND_TOMBSTONE,
            Self::SelfContactReadList => Self::SELF_CONTACT_READ_LIST,
            Self::SelfControlProposalAcksCommandIssue => {
                Self::SELF_CONTROL_PROPOSAL_ACKS_COMMAND_ISSUE
            }
            Self::SelfControlProposalDecisionsCommandSubmit => {
                Self::SELF_CONTROL_PROPOSAL_DECISIONS_COMMAND_SUBMIT
            }
            Self::SelfControlProposalDecisionsReadGet => {
                Self::SELF_CONTROL_PROPOSAL_DECISIONS_READ_GET
            }
            Self::SelfDeviceMessagesCommandAck => Self::SELF_DEVICE_MESSAGES_COMMAND_ACK,
            Self::SelfDeviceMessagesCommandSend => Self::SELF_DEVICE_MESSAGES_COMMAND_SEND,
            Self::SelfDeviceMessagesReadList => Self::SELF_DEVICE_MESSAGES_READ_LIST,
            Self::SelfDirectConversationCommandRepairDispatch => {
                Self::SELF_DIRECT_CONVERSATION_COMMAND_REPAIR_DISPATCH
            }
            Self::SelfDirectConversationReadResolve => Self::SELF_DIRECT_CONVERSATION_READ_RESOLVE,
            Self::SelfEventsCommandSubmit => Self::SELF_EVENTS_COMMAND_SUBMIT,
            Self::SelfEventsCommandSubmitSeal => Self::SELF_EVENTS_COMMAND_SUBMIT_SEAL,
            Self::SelfEventsReadDeliveryStatus => Self::SELF_EVENTS_READ_DELIVERY_STATUS,
            Self::SelfEventsReadDescribe => Self::SELF_EVENTS_READ_DESCRIBE,
            Self::SelfEventsReadFrontier => Self::SELF_EVENTS_READ_FRONTIER,
            Self::SelfEventsReadMlsGovernanceProof => Self::SELF_EVENTS_READ_MLS_GOVERNANCE_PROOF,
            Self::SelfEventsReadResolve => Self::SELF_EVENTS_READ_RESOLVE,
            Self::SelfEventsReadScan => Self::SELF_EVENTS_READ_SCAN,
            Self::SelfEventsResourceGet => Self::SELF_EVENTS_RESOURCE_GET,
            Self::SelfEventsStreamSubscribe => Self::SELF_EVENTS_STREAM_SUBSCRIBE,
            Self::SelfIdentityReadResolutionAudit => Self::SELF_IDENTITY_READ_RESOLUTION_AUDIT,
            Self::SelfInviteLocatorCommandIssue => Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE,
            Self::SelfInviteLocatorCommandRevoke => Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE,
            Self::SelfInviteLocatorCommandRotate => Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE,
            Self::SelfInviteReceivePolicyResourceGet => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET
            }
            Self::SelfInviteReceivePolicyResourceReplace => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE
            }
            Self::SelfInvitesCommandDispatch => Self::SELF_INVITES_COMMAND_DISPATCH,
            Self::SelfKeysBackupSeriesCommandErase => Self::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE,
            Self::SelfKeysBackupsCommandIssueDeleteChallenge => {
                Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE
            }
            Self::SelfKeysBackupsCommandUnlock => Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK,
            Self::SelfKeysBackupsReadList => Self::SELF_KEYS_BACKUPS_READ_LIST,
            Self::SelfKeysBackupsResourceDelete => Self::SELF_KEYS_BACKUPS_RESOURCE_DELETE,
            Self::SelfKeysBackupsResourceReplace => Self::SELF_KEYS_BACKUPS_RESOURCE_REPLACE,
            Self::SelfKeysCommandClaim => Self::SELF_KEYS_COMMAND_CLAIM,
            Self::SelfKeysKeypackagesCommandClaim => Self::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM,
            Self::SelfKeysKeypackagesCommandConsume => Self::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME,
            Self::SelfKeysKeypackagesCommandRevoke => Self::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE,
            Self::SelfKeysKeypackagesUploadCreate => Self::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE,
            Self::SelfKeysReadLookup => Self::SELF_KEYS_READ_LOOKUP,
            Self::SelfKeysUploadCreate => Self::SELF_KEYS_UPLOAD_CREATE,
            Self::SelfMediaReadIceConfig => Self::SELF_MEDIA_READ_ICE_CONFIG,
            Self::SelfModerationCommandReport => Self::SELF_MODERATION_COMMAND_REPORT,
            Self::SelfMorphReadList => Self::SELF_MORPH_READ_LIST,
            Self::SelfMorphResourceGet => Self::SELF_MORPH_RESOURCE_GET,
            Self::SelfPolicyReadCheck => Self::SELF_POLICY_READ_CHECK,
            Self::SelfReadCursorCommandAdvance => Self::SELF_READ_CURSOR_COMMAND_ADVANCE,
            Self::SelfReadCursorReadList => Self::SELF_READ_CURSOR_READ_LIST,
            Self::SelfRealmCommandArchive => Self::SELF_REALM_COMMAND_ARCHIVE,
            Self::SelfRealmCommandDestroy => Self::SELF_REALM_COMMAND_DESTROY,
            Self::SelfRealmCommandFreeze => Self::SELF_REALM_COMMAND_FREEZE,
            Self::SelfRealmCommandTombstone => Self::SELF_REALM_COMMAND_TOMBSTONE,
            Self::SelfRealmJoinApplicationAuditReadList => {
                Self::SELF_REALM_JOIN_APPLICATION_AUDIT_READ_LIST
            }
            Self::SelfRealmJoinApplicationCommandCancel => {
                Self::SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL
            }
            Self::SelfRealmJoinApplicationCommandReview => {
                Self::SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW
            }
            Self::SelfRealmJoinApplicationCommandSubmit => {
                Self::SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT
            }
            Self::SelfRealmJoinApplicationReadList => Self::SELF_REALM_JOIN_APPLICATION_READ_LIST,
            Self::SelfRealmJoinApplicationResourceGet => {
                Self::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET
            }
            Self::SelfRealmModerationPolicyReadEffective => {
                Self::SELF_REALM_MODERATION_POLICY_READ_EFFECTIVE
            }
            Self::SelfRealmModerationPolicyResourceReplace => {
                Self::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE
            }
            Self::SelfRealmReadExport => Self::SELF_REALM_READ_EXPORT,
            Self::SelfRealmResourceGet => Self::SELF_REALM_RESOURCE_GET,
            Self::SelfRealmLinkCommandCreate => Self::SELF_REALM_LINK_COMMAND_CREATE,
            Self::SelfRealmLinkReadEffectivePolicy => Self::SELF_REALM_LINK_READ_EFFECTIVE_POLICY,
            Self::SelfRealmLinkReadList => Self::SELF_REALM_LINK_READ_LIST,
            Self::SelfRealmLinkResourceDelete => Self::SELF_REALM_LINK_RESOURCE_DELETE,
            Self::SelfRealmOrganizationReadList => Self::SELF_REALM_ORGANIZATION_READ_LIST,
            Self::SelfRealmPolicyServerResourceDelete => {
                Self::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE
            }
            Self::SelfRealmPolicyServerResourceGet => Self::SELF_REALM_POLICY_SERVER_RESOURCE_GET,
            Self::SelfRealmPolicyServerResourceReplace => {
                Self::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE
            }
            Self::SelfSecurityTransactionCommandContinue => {
                Self::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE
            }
            Self::SelfSecurityTransactionCommandCreate => {
                Self::SELF_SECURITY_TRANSACTION_COMMAND_CREATE
            }
            Self::SelfSecurityTransactionResourceGet => {
                Self::SELF_SECURITY_TRANSACTION_RESOURCE_GET
            }
            Self::SelfSignalCommandSend => Self::SELF_SIGNAL_COMMAND_SEND,
            Self::SelfSignalStreamSubscribe => Self::SELF_SIGNAL_STREAM_SUBSCRIBE,
            Self::SelfSnapshotReadManifestHead => Self::SELF_SNAPSHOT_READ_MANIFEST_HEAD,
            Self::SelfSpaceReadList => Self::SELF_SPACE_READ_LIST,
            Self::SelfStrandReadList => Self::SELF_STRAND_READ_LIST,
            Self::SelfViewsCollectionProjectionCommandMaterialize => {
                Self::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE
            }
            Self::ServerReadDescribe => Self::SERVER_READ_DESCRIBE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::EDGE_APPLET_ACTOR_READ_RESOLVE => Some(Self::EdgeAppletActorReadResolve),
            Self::EDGE_APPLET_COMMAND_TRANSACTION => Some(Self::EdgeAppletCommandTransaction),
            Self::EDGE_APPLET_READ_DESCRIBE => Some(Self::EdgeAppletReadDescribe),
            Self::EDGE_APPLET_READ_PING => Some(Self::EdgeAppletReadPing),
            Self::EDGE_APPLET_READ_PROTOCOL_METADATA => Some(Self::EdgeAppletReadProtocolMetadata),
            Self::EDGE_APPLET_REALM_READ_RESOLVE => Some(Self::EdgeAppletRealmReadResolve),
            Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST => {
                Some(Self::EdgeAppletThirdPartyLocationsReadList)
            }
            Self::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST => {
                Some(Self::EdgeAppletThirdPartyUsersReadList)
            }
            Self::EDGE_PUSH_COMMAND_NOTIFY => Some(Self::EdgePushCommandNotify),
            Self::EDGE_PUSH_COMMAND_REGISTER_DEVICE => Some(Self::EdgePushCommandRegisterDevice),
            Self::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE => {
                Some(Self::EdgePushCommandUnregisterDevice)
            }
            Self::FIND_DIRECTORY_COMMAND_ANNOUNCE => Some(Self::FindDirectoryCommandAnnounce),
            Self::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL => {
                Some(Self::FindDirectoryCommandTakedownAppeal)
            }
            Self::FIND_DIRECTORY_COMMAND_WITHDRAW => Some(Self::FindDirectoryCommandWithdraw),
            Self::FIND_DIRECTORY_PUSH_COMMAND_REGISTER => {
                Some(Self::FindDirectoryPushCommandRegister)
            }
            Self::FIND_DIRECTORY_READ_DESCRIBE => Some(Self::FindDirectoryReadDescribe),
            Self::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT => {
                Some(Self::FindDirectoryReadListHandlesForSubject)
            }
            Self::FIND_DIRECTORY_READ_PRIVATE_CONTACT_DISCOVERY => {
                Some(Self::FindDirectoryReadPrivateContactDiscovery)
            }
            Self::FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR => {
                Some(Self::FindDirectoryReadResolveAgentSelector)
            }
            Self::FIND_DIRECTORY_READ_RESOLVE_HANDLE => Some(Self::FindDirectoryReadResolveHandle),
            Self::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION => {
                Some(Self::FindDirectoryReadResolveOrganization)
            }
            Self::FIND_DIRECTORY_READ_RESOLVE_REALM => Some(Self::FindDirectoryReadResolveRealm),
            Self::FIND_DIRECTORY_READ_RESOLVE_TARGET => Some(Self::FindDirectoryReadResolveTarget),
            Self::FIND_DIRECTORY_READ_SEARCH_ACTORS => Some(Self::FindDirectoryReadSearchActors),
            Self::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS => {
                Some(Self::FindDirectoryReadSearchOrganizations)
            }
            Self::FIND_DIRECTORY_READ_SEARCH_REALMS => Some(Self::FindDirectoryReadSearchRealms),
            Self::FIND_DIRECTORY_READ_SEARCH_USERS => Some(Self::FindDirectoryReadSearchUsers),
            Self::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION => {
                Some(Self::GateAccountCommandAbandonIdentityCreation)
            }
            Self::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT => {
                Some(Self::GateAccountCommandIntrospectSessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION => {
                Some(Self::GateAccountCommandIssueControllerGateAttestation)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE => {
                Some(Self::GateAccountCommandIssueDidBindingChallenge)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_ABANDONMENT_CHALLENGE => {
                Some(Self::GateAccountCommandIssueIdentityAbandonmentChallenge)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE => {
                Some(Self::GateAccountCommandIssueIdentityBindingChallenge)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT => {
                Some(Self::GateAccountCommandIssueRecoveryCompletionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT => {
                Some(Self::GateAccountCommandIssueSessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_LOGOUT => Some(Self::GateAccountCommandLogout),
            Self::GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION => {
                Some(Self::GateAccountCommandLogoutAuthSession)
            }
            Self::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY => Some(Self::GateAccountCommandPairAgentKey),
            Self::GATE_ACCOUNT_COMMAND_PAIR_DEVICE => Some(Self::GateAccountCommandPairDevice),
            Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT => {
                Some(Self::GateAccountCommandRefreshSessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_REGISTER => Some(Self::GateAccountCommandRegister),
            Self::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE => {
                Some(Self::GateAccountCommandRequestErasure)
            }
            Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION => {
                Some(Self::GateAccountCommandRevokeSession)
            }
            Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF => {
                Some(Self::GateAccountExchangeCreateHandoff)
            }
            Self::GATE_ACCOUNT_READ_ONBOARDING => Some(Self::GateAccountReadOnboarding),
            Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST => {
                Some(Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest)
            }
            Self::OPEN_AGENT_PAIRING_READ_RESOLVE => Some(Self::OpenAgentPairingReadResolve),
            Self::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS => {
                Some(Self::OpenAgentPairingReadRuntimeKeyRequestStatus)
            }
            Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE => Some(Self::OpenDevicePairingCommandStage),
            Self::OPEN_DEVICE_PAIRING_READ_RESOLVE => Some(Self::OpenDevicePairingReadResolve),
            Self::OPEN_DEVICE_PAIRING_READ_STATUS => Some(Self::OpenDevicePairingReadStatus),
            Self::OPEN_IDENTITY_READ_RESOLUTION => Some(Self::OpenIdentityReadResolution),
            Self::OPEN_INVITE_LOCATOR_READ_RESOLVE => Some(Self::OpenInviteLocatorReadResolve),
            Self::OPEN_MIMI_COMMAND_NOTIFY => Some(Self::OpenMimiCommandNotify),
            Self::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD => Some(Self::OpenMimiCommandProxyDownload),
            Self::OPEN_MIMI_COMMAND_REPORT_ABUSE => Some(Self::OpenMimiCommandReportAbuse),
            Self::OPEN_MIMI_COMMAND_REQUEST_CONSENT => Some(Self::OpenMimiCommandRequestConsent),
            Self::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE => Some(Self::OpenMimiCommandSubmitMessage),
            Self::OPEN_MIMI_COMMAND_UPDATE_CONSENT => Some(Self::OpenMimiCommandUpdateConsent),
            Self::OPEN_MIMI_COMMAND_UPDATE_ROOM => Some(Self::OpenMimiCommandUpdateRoom),
            Self::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL => {
                Some(Self::OpenMimiExchangeRequestKeyMaterial)
            }
            Self::OPEN_MIMI_READ_GROUP_INFO => Some(Self::OpenMimiReadGroupInfo),
            Self::OPEN_MIMI_READ_IDENTIFIERS => Some(Self::OpenMimiReadIdentifiers),
            Self::OPEN_MIMI_READ_PROVIDER_DIRECTORY => Some(Self::OpenMimiReadProviderDirectory),
            Self::OPEN_SERVICE_READ_RESOLUTION => Some(Self::OpenServiceReadResolution),
            Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT => Some(Self::PeerAccountStatusCommandSubmit),
            Self::PEER_ACCOUNT_STATUS_READ_RESOLVE => Some(Self::PeerAccountStatusReadResolve),
            Self::PEER_CONTACTS_COMMAND_SUBMIT => Some(Self::PeerContactsCommandSubmit),
            Self::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK => {
                Some(Self::PeerDeviceRevocationsCommandCheck)
            }
            Self::PEER_DIRECT_CONVERSATION_COMMAND_REPAIR_RELAY => {
                Some(Self::PeerDirectConversationCommandRepairRelay)
            }
            Self::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT => {
                Some(Self::PeerErasureReceiptCommandSubmit)
            }
            Self::PEER_ERASURE_RECEIPT_RESOURCE_GET => Some(Self::PeerErasureReceiptResourceGet),
            Self::PEER_EVENTS_COMMAND_SUBMIT => Some(Self::PeerEventsCommandSubmit),
            Self::PEER_EVENTS_READ_DESCRIBE => Some(Self::PeerEventsReadDescribe),
            Self::PEER_EVENTS_READ_FRONTIER => Some(Self::PeerEventsReadFrontier),
            Self::PEER_EVENTS_READ_RESOLVE => Some(Self::PeerEventsReadResolve),
            Self::PEER_EVENTS_READ_SCAN => Some(Self::PeerEventsReadScan),
            Self::PEER_INVITES_COMMAND_SUBMIT => Some(Self::PeerInvitesCommandSubmit),
            Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM => {
                Some(Self::PeerKeysKeypackagesCommandClaim)
            }
            Self::PEER_KEYS_KEYPACKAGES_READ_CLAIM => Some(Self::PeerKeysKeypackagesReadClaim),
            Self::PEER_MLS_READ_GROUP_STATE_MATERIAL => Some(Self::PeerMlsReadGroupStateMaterial),
            Self::PEER_PRINCIPAL_GENESIS_COMMAND_SUBMIT => {
                Some(Self::PeerPrincipalGenesisCommandSubmit)
            }
            Self::PEER_SERVICE_RESOLUTION_COMMAND_PUBLISH => {
                Some(Self::PeerServiceResolutionCommandPublish)
            }
            Self::PEER_SERVICE_RESOLUTION_READ_RESOLVE => {
                Some(Self::PeerServiceResolutionReadResolve)
            }
            Self::PEER_SIGNAL_COMMAND_RELAY => Some(Self::PeerSignalCommandRelay),
            Self::PEER_SNAPSHOT_READ_MANIFEST_HEAD => Some(Self::PeerSnapshotReadManifestHead),
            Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION => {
                Some(Self::RootIdentityCommandSubmitDidOperation)
            }
            Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET => {
                Some(Self::RootIdentityDocumentResourceGet)
            }
            Self::ROOT_IDENTITY_LOG_READ_LIST => Some(Self::RootIdentityLogReadList),
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE => {
                Some(Self::RootIdentityOrganizationRegistrationCommandEnsure)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE => {
                Some(Self::RootIdentityOrganizationRegistrationCommandPrepare)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH => {
                Some(Self::RootIdentityOrganizationRegistrationCommandRefresh)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE => {
                Some(Self::RootIdentityOrganizationRegistrationCommandRevoke)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET => {
                Some(Self::RootIdentityOrganizationRegistrationResourceGet)
            }
            Self::ROOT_IDENTITY_READ_RESOLVE => Some(Self::RootIdentityReadResolve),
            Self::ROOT_IDENTITY_RECEIPTS_READ_LIST => Some(Self::RootIdentityReceiptsReadList),
            Self::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH => {
                Some(Self::RootIdentityRecoveryPolicyCommandPublish)
            }
            Self::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET => {
                Some(Self::RootIdentityRecoveryPolicyResourceGet)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE => {
                Some(Self::RootIdentityRecoverySessionCommandCreate)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF => {
                Some(Self::RootIdentityRecoverySessionCommandSubmitProof)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET => {
                Some(Self::RootIdentityRecoverySessionResourceGet)
            }
            Self::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE => {
                Some(Self::RootIdentityRegistryReadDescribe)
            }
            Self::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE => {
                Some(Self::RootIdentityServiceRegistrationCommandEnsure)
            }
            Self::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET => {
                Some(Self::RootIdentityServiceRegistrationResourceGet)
            }
            Self::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR => Some(Self::SelfAccountCommandRevokeCursor),
            Self::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE => {
                Some(Self::SelfAccountCommandUpdateProfile)
            }
            Self::SELF_ACCOUNT_READ_DESCRIBE => Some(Self::SelfAccountReadDescribe),
            Self::SELF_ACCOUNT_READ_VIEWER => Some(Self::SelfAccountReadViewer),
            Self::SELF_ACCOUNT_STREAM_SUBSCRIBE => Some(Self::SelfAccountStreamSubscribe),
            Self::SELF_ACCOUNT_DATA_READ_LIST => Some(Self::SelfAccountDataReadList),
            Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE => Some(Self::SelfAccountDataResourceDelete),
            Self::SELF_ACCOUNT_DATA_RESOURCE_GET => Some(Self::SelfAccountDataResourceGet),
            Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE => Some(Self::SelfAccountDataResourceReplace),
            Self::SELF_ACTOR_PROFILE_READ_RESOLVE => Some(Self::SelfActorProfileReadResolve),
            Self::SELF_AGENT_COMMAND_ABANDON_PROVISIONING => {
                Some(Self::SelfAgentCommandAbandonProvisioning)
            }
            Self::SELF_AGENT_COMMAND_DEACTIVATE => Some(Self::SelfAgentCommandDeactivate),
            Self::SELF_AGENT_COMMAND_ISSUE_PROVISIONING_ABANDONMENT_CHALLENGE => {
                Some(Self::SelfAgentCommandIssueProvisioningAbandonmentChallenge)
            }
            Self::SELF_AGENT_COMMAND_PAUSE => Some(Self::SelfAgentCommandPause),
            Self::SELF_AGENT_COMMAND_PROVISION => Some(Self::SelfAgentCommandProvision),
            Self::SELF_AGENT_COMMAND_RENEW_PAIRING => Some(Self::SelfAgentCommandRenewPairing),
            Self::SELF_AGENT_COMMAND_RESUME => Some(Self::SelfAgentCommandResume),
            Self::SELF_AGENT_GRANT_COMMAND_ATTACH => Some(Self::SelfAgentGrantCommandAttach),
            Self::SELF_AGENT_GRANT_RESOURCE_DELETE => Some(Self::SelfAgentGrantResourceDelete),
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET => {
                Some(Self::SelfAgentParticipationResourceGet)
            }
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE => {
                Some(Self::SelfAgentParticipationResourceReplace)
            }
            Self::SELF_AGENT_READ_LIST => Some(Self::SelfAgentReadList),
            Self::SELF_AGENT_RESOURCE_GET => Some(Self::SelfAgentResourceGet),
            Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE => Some(Self::SelfAgentSidecarCommandEnsure),
            Self::SELF_AGENT_SIDECAR_READ_LIST => Some(Self::SelfAgentSidecarReadList),
            Self::SELF_AGENT_SIDECAR_RESOURCE_GET => Some(Self::SelfAgentSidecarResourceGet),
            Self::SELF_AGENT_SIGNER_EVIDENCE_READ_RESOLVE => {
                Some(Self::SelfAgentSignerEvidenceReadResolve)
            }
            Self::SELF_APPLET_COMMAND_INSTALL => Some(Self::SelfAppletCommandInstall),
            Self::SELF_APPLET_COMMAND_REVOKE => Some(Self::SelfAppletCommandRevoke),
            Self::SELF_APPLET_GHOST_COMMAND_PROVISION => {
                Some(Self::SelfAppletGhostCommandProvision)
            }
            Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW => {
                Some(Self::SelfAppletInstallCommandPreview)
            }
            Self::SELF_APPLET_REVOKE_COMMAND_PREVIEW => Some(Self::SelfAppletRevokeCommandPreview),
            Self::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE => {
                Some(Self::SelfAuthorizationLeasesCommandIssue)
            }
            Self::SELF_AUTHZ_GRANTS_READ_EFFECTIVE => Some(Self::SelfAuthzGrantsReadEffective),
            Self::SELF_AUTHZ_INVITES_READ_LIST => Some(Self::SelfAuthzInvitesReadList),
            Self::SELF_AUTHZ_READ_CHECK => Some(Self::SelfAuthzReadCheck),
            Self::SELF_BLOB_COMMAND_PRESIGN => Some(Self::SelfBlobCommandPresign),
            Self::SELF_BLOB_RESOURCE_GET => Some(Self::SelfBlobResourceGet),
            Self::SELF_BLOB_RESOURCE_HEAD => Some(Self::SelfBlobResourceHead),
            Self::SELF_BLOB_UPLOAD_CREATE => Some(Self::SelfBlobUploadCreate),
            Self::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN => {
                Some(Self::SelfCallMediaExchangeIssueToken)
            }
            Self::SELF_CIRCLE_COMMAND_ARCHIVE => Some(Self::SelfCircleCommandArchive),
            Self::SELF_CIRCLE_COMMAND_CREATE => Some(Self::SelfCircleCommandCreate),
            Self::SELF_CIRCLE_COMMAND_RESTORE => Some(Self::SelfCircleCommandRestore),
            Self::SELF_CIRCLE_COMMAND_ROTATE_SCOPE => Some(Self::SelfCircleCommandRotateScope),
            Self::SELF_CIRCLE_COMMAND_TOMBSTONE => Some(Self::SelfCircleCommandTombstone),
            Self::SELF_CIRCLE_MEMBER_COMMAND_ADD => Some(Self::SelfCircleMemberCommandAdd),
            Self::SELF_CIRCLE_MEMBER_RESOURCE_DELETE => Some(Self::SelfCircleMemberResourceDelete),
            Self::SELF_CIRCLE_READ_LIST => Some(Self::SelfCircleReadList),
            Self::SELF_CIRCLE_RESOURCE_GET => Some(Self::SelfCircleResourceGet),
            Self::SELF_CONSENT_COMMAND_GRANT => Some(Self::SelfConsentCommandGrant),
            Self::SELF_CONSENT_COMMAND_REQUEST => Some(Self::SelfConsentCommandRequest),
            Self::SELF_CONSENT_COMMAND_REVOKE => Some(Self::SelfConsentCommandRevoke),
            Self::SELF_CONSENT_READ_LIST => Some(Self::SelfConsentReadList),
            Self::SELF_CONSENT_RESOURCE_GET => Some(Self::SelfConsentResourceGet),
            Self::SELF_CONTACT_COMMAND_CHECKPOINT => Some(Self::SelfContactCommandCheckpoint),
            Self::SELF_CONTACT_COMMAND_REJECT => Some(Self::SelfContactCommandReject),
            Self::SELF_CONTACT_COMMAND_REQUEST => Some(Self::SelfContactCommandRequest),
            Self::SELF_CONTACT_COMMAND_RESPOND => Some(Self::SelfContactCommandRespond),
            Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE => Some(Self::SelfContactCommandScopeUpdate),
            Self::SELF_CONTACT_COMMAND_TOMBSTONE => Some(Self::SelfContactCommandTombstone),
            Self::SELF_CONTACT_READ_LIST => Some(Self::SelfContactReadList),
            Self::SELF_CONTROL_PROPOSAL_ACKS_COMMAND_ISSUE => {
                Some(Self::SelfControlProposalAcksCommandIssue)
            }
            Self::SELF_CONTROL_PROPOSAL_DECISIONS_COMMAND_SUBMIT => {
                Some(Self::SelfControlProposalDecisionsCommandSubmit)
            }
            Self::SELF_CONTROL_PROPOSAL_DECISIONS_READ_GET => {
                Some(Self::SelfControlProposalDecisionsReadGet)
            }
            Self::SELF_DEVICE_MESSAGES_COMMAND_ACK => Some(Self::SelfDeviceMessagesCommandAck),
            Self::SELF_DEVICE_MESSAGES_COMMAND_SEND => Some(Self::SelfDeviceMessagesCommandSend),
            Self::SELF_DEVICE_MESSAGES_READ_LIST => Some(Self::SelfDeviceMessagesReadList),
            Self::SELF_DIRECT_CONVERSATION_COMMAND_REPAIR_DISPATCH => {
                Some(Self::SelfDirectConversationCommandRepairDispatch)
            }
            Self::SELF_DIRECT_CONVERSATION_READ_RESOLVE => {
                Some(Self::SelfDirectConversationReadResolve)
            }
            Self::SELF_EVENTS_COMMAND_SUBMIT => Some(Self::SelfEventsCommandSubmit),
            Self::SELF_EVENTS_COMMAND_SUBMIT_SEAL => Some(Self::SelfEventsCommandSubmitSeal),
            Self::SELF_EVENTS_READ_DELIVERY_STATUS => Some(Self::SelfEventsReadDeliveryStatus),
            Self::SELF_EVENTS_READ_DESCRIBE => Some(Self::SelfEventsReadDescribe),
            Self::SELF_EVENTS_READ_FRONTIER => Some(Self::SelfEventsReadFrontier),
            Self::SELF_EVENTS_READ_MLS_GOVERNANCE_PROOF => {
                Some(Self::SelfEventsReadMlsGovernanceProof)
            }
            Self::SELF_EVENTS_READ_RESOLVE => Some(Self::SelfEventsReadResolve),
            Self::SELF_EVENTS_READ_SCAN => Some(Self::SelfEventsReadScan),
            Self::SELF_EVENTS_RESOURCE_GET => Some(Self::SelfEventsResourceGet),
            Self::SELF_EVENTS_STREAM_SUBSCRIBE => Some(Self::SelfEventsStreamSubscribe),
            Self::SELF_IDENTITY_READ_RESOLUTION_AUDIT => {
                Some(Self::SelfIdentityReadResolutionAudit)
            }
            Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE => Some(Self::SelfInviteLocatorCommandIssue),
            Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE => Some(Self::SelfInviteLocatorCommandRevoke),
            Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE => Some(Self::SelfInviteLocatorCommandRotate),
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET => {
                Some(Self::SelfInviteReceivePolicyResourceGet)
            }
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE => {
                Some(Self::SelfInviteReceivePolicyResourceReplace)
            }
            Self::SELF_INVITES_COMMAND_DISPATCH => Some(Self::SelfInvitesCommandDispatch),
            Self::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE => {
                Some(Self::SelfKeysBackupSeriesCommandErase)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE => {
                Some(Self::SelfKeysBackupsCommandIssueDeleteChallenge)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK => Some(Self::SelfKeysBackupsCommandUnlock),
            Self::SELF_KEYS_BACKUPS_READ_LIST => Some(Self::SelfKeysBackupsReadList),
            Self::SELF_KEYS_BACKUPS_RESOURCE_DELETE => Some(Self::SelfKeysBackupsResourceDelete),
            Self::SELF_KEYS_BACKUPS_RESOURCE_REPLACE => Some(Self::SelfKeysBackupsResourceReplace),
            Self::SELF_KEYS_COMMAND_CLAIM => Some(Self::SelfKeysCommandClaim),
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM => {
                Some(Self::SelfKeysKeypackagesCommandClaim)
            }
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME => {
                Some(Self::SelfKeysKeypackagesCommandConsume)
            }
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE => {
                Some(Self::SelfKeysKeypackagesCommandRevoke)
            }
            Self::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE => {
                Some(Self::SelfKeysKeypackagesUploadCreate)
            }
            Self::SELF_KEYS_READ_LOOKUP => Some(Self::SelfKeysReadLookup),
            Self::SELF_KEYS_UPLOAD_CREATE => Some(Self::SelfKeysUploadCreate),
            Self::SELF_MEDIA_READ_ICE_CONFIG => Some(Self::SelfMediaReadIceConfig),
            Self::SELF_MODERATION_COMMAND_REPORT => Some(Self::SelfModerationCommandReport),
            Self::SELF_MORPH_READ_LIST => Some(Self::SelfMorphReadList),
            Self::SELF_MORPH_RESOURCE_GET => Some(Self::SelfMorphResourceGet),
            Self::SELF_POLICY_READ_CHECK => Some(Self::SelfPolicyReadCheck),
            Self::SELF_READ_CURSOR_COMMAND_ADVANCE => Some(Self::SelfReadCursorCommandAdvance),
            Self::SELF_READ_CURSOR_READ_LIST => Some(Self::SelfReadCursorReadList),
            Self::SELF_REALM_COMMAND_ARCHIVE => Some(Self::SelfRealmCommandArchive),
            Self::SELF_REALM_COMMAND_DESTROY => Some(Self::SelfRealmCommandDestroy),
            Self::SELF_REALM_COMMAND_FREEZE => Some(Self::SelfRealmCommandFreeze),
            Self::SELF_REALM_COMMAND_TOMBSTONE => Some(Self::SelfRealmCommandTombstone),
            Self::SELF_REALM_JOIN_APPLICATION_AUDIT_READ_LIST => {
                Some(Self::SelfRealmJoinApplicationAuditReadList)
            }
            Self::SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL => {
                Some(Self::SelfRealmJoinApplicationCommandCancel)
            }
            Self::SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW => {
                Some(Self::SelfRealmJoinApplicationCommandReview)
            }
            Self::SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT => {
                Some(Self::SelfRealmJoinApplicationCommandSubmit)
            }
            Self::SELF_REALM_JOIN_APPLICATION_READ_LIST => {
                Some(Self::SelfRealmJoinApplicationReadList)
            }
            Self::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET => {
                Some(Self::SelfRealmJoinApplicationResourceGet)
            }
            Self::SELF_REALM_MODERATION_POLICY_READ_EFFECTIVE => {
                Some(Self::SelfRealmModerationPolicyReadEffective)
            }
            Self::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE => {
                Some(Self::SelfRealmModerationPolicyResourceReplace)
            }
            Self::SELF_REALM_READ_EXPORT => Some(Self::SelfRealmReadExport),
            Self::SELF_REALM_RESOURCE_GET => Some(Self::SelfRealmResourceGet),
            Self::SELF_REALM_LINK_COMMAND_CREATE => Some(Self::SelfRealmLinkCommandCreate),
            Self::SELF_REALM_LINK_READ_EFFECTIVE_POLICY => {
                Some(Self::SelfRealmLinkReadEffectivePolicy)
            }
            Self::SELF_REALM_LINK_READ_LIST => Some(Self::SelfRealmLinkReadList),
            Self::SELF_REALM_LINK_RESOURCE_DELETE => Some(Self::SelfRealmLinkResourceDelete),
            Self::SELF_REALM_ORGANIZATION_READ_LIST => Some(Self::SelfRealmOrganizationReadList),
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE => {
                Some(Self::SelfRealmPolicyServerResourceDelete)
            }
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_GET => {
                Some(Self::SelfRealmPolicyServerResourceGet)
            }
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE => {
                Some(Self::SelfRealmPolicyServerResourceReplace)
            }
            Self::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE => {
                Some(Self::SelfSecurityTransactionCommandContinue)
            }
            Self::SELF_SECURITY_TRANSACTION_COMMAND_CREATE => {
                Some(Self::SelfSecurityTransactionCommandCreate)
            }
            Self::SELF_SECURITY_TRANSACTION_RESOURCE_GET => {
                Some(Self::SelfSecurityTransactionResourceGet)
            }
            Self::SELF_SIGNAL_COMMAND_SEND => Some(Self::SelfSignalCommandSend),
            Self::SELF_SIGNAL_STREAM_SUBSCRIBE => Some(Self::SelfSignalStreamSubscribe),
            Self::SELF_SNAPSHOT_READ_MANIFEST_HEAD => Some(Self::SelfSnapshotReadManifestHead),
            Self::SELF_SPACE_READ_LIST => Some(Self::SelfSpaceReadList),
            Self::SELF_STRAND_READ_LIST => Some(Self::SelfStrandReadList),
            Self::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE => {
                Some(Self::SelfViewsCollectionProjectionCommandMaterialize)
            }
            Self::SERVER_READ_DESCRIBE => Some(Self::ServerReadDescribe),
            _ => None,
        }
    }

    pub fn descriptor(self) -> &'static ServiceOperationDescriptor {
        &SERVICE_OPERATION_DESCRIPTORS[self as usize]
    }
}

impl std::fmt::Display for ServiceOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ServiceOperationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ServiceOperationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown service operation id: {raw}")))
    }
}

pub const SERVICE_OPERATION_DESCRIPTORS: &[ServiceOperationDescriptor] = &[
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletActorReadResolve,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/actors/{actor_id}",
        grpc: Some("EdgeApplet/ResolveActor"),
        mq: Some("edge.applet.actor.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_actor_view",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletCommandTransaction,
        http_method: "POST",
        http_path: "/_arkret/edge/applet/transactions",
        grpc: Some("EdgeApplet/Transaction"),
        mq: Some("edge.applet.command.transaction"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_transaction_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_transaction_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletReadDescribe,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/describe",
        grpc: Some("EdgeApplet/Describe"),
        mq: Some("edge.applet.query.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletReadPing,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/ping",
        grpc: Some("EdgeApplet/Ping"),
        mq: Some("edge.applet.query.ping"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_ping_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletReadProtocolMetadata,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/protocols/{protocol}",
        grpc: Some("EdgeApplet/ProtocolMetadata"),
        mq: Some("edge.applet.query.protocol_metadata"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_protocol_metadata",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletRealmReadResolve,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        grpc: Some("EdgeApplet/ResolveRealm"),
        mq: Some("edge.applet.realm.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_realm_view",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletThirdPartyLocationsReadList,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/third_party/locations",
        grpc: Some("EdgeApplet/ThirdPartyLocations"),
        mq: Some("edge.applet.third_party_locations.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_third_party_location_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletThirdPartyUsersReadList,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/third_party/users",
        grpc: Some("EdgeApplet/ThirdPartyUsers"),
        mq: Some("edge.applet.third_party_users.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_third_party_user_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandNotify,
        http_method: "POST",
        http_path: "/_arkret/edge/push/notify",
        grpc: Some("EdgePush/Notify"),
        mq: Some("edge.push.command.notify"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_notify_request_body",
        ),
        response_schema_ref: Some("schemas/push-operations.schema.json#/$defs/push_notify_outcome"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandRegisterDevice,
        http_method: "POST",
        http_path: "/_arkret/edge/push/register-device",
        grpc: Some("EdgePush/RegisterDevice"),
        mq: Some("edge.push.command.register_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_register_device_request_body",
        ),
        response_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_register_device_outcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandUnregisterDevice,
        http_method: "POST",
        http_path: "/_arkret/edge/push/unregister-device",
        grpc: Some("EdgePush/UnregisterDevice"),
        mq: Some("edge.push.command.unregister_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_unregister_device_request_body",
        ),
        response_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_unregister_device_outcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandAnnounce,
        http_method: "POST",
        http_path: "/_arkret/find/directory/announce",
        grpc: Some("FindDirectory/Announce"),
        mq: Some("find.directory.command.announce"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryAnnounceRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryAnnounceOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.find.directory.read.resolve_target\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandTakedownAppeal,
        http_method: "POST",
        http_path: "/_arkret/find/directory/takedown/appeal",
        grpc: Some("FindDirectory/TakedownAppeal"),
        mq: Some("find.directory.command.takedown_appeal"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryTakedownAppealRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryTakedownAppealOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandWithdraw,
        http_method: "POST",
        http_path: "/_arkret/find/directory/withdraw",
        grpc: Some("FindDirectory/Withdraw"),
        mq: Some("find.directory.command.withdraw"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryWithdrawRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DirectoryWithdrawOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryPushCommandRegister,
        http_method: "POST",
        http_path: "/_arkret/find/directory/push/register",
        grpc: Some("FindDirectory/PushRegister"),
        mq: Some("find.directory.push.command.register"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_push_register_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_push_register_outcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadDescribe,
        http_method: "GET",
        http_path: "/_arkret/find/directory/describe",
        grpc: Some("FindDirectory/Describe"),
        mq: Some("find.directory.query.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadListHandlesForSubject,
        http_method: "POST",
        http_path: "/_arkret/find/directory/list-handles-for-subject",
        grpc: Some("FindDirectory/ListHandlesForSubject"),
        mq: Some("find.directory.query.list_handles_for_subject"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_list_handles_for_subject_request_body",
        ),
        response_schema_ref: Some("schemas/list-handles-for-subject-response.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadPrivateContactDiscovery,
        http_method: "POST",
        http_path: "/_arkret/find/directory/private-contact-discovery",
        grpc: Some("FindDirectory/PrivateContactDiscovery"),
        mq: Some("find.directory.query.private_contact_discovery"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_private_contact_discovery_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_private_contact_discovery_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveAgentSelector,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-agent-selector",
        grpc: Some("FindDirectory/ResolveAgentSelector"),
        mq: Some("find.directory.query.resolve_agent_selector"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_resolve_agent_selector_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_agent_selector_resolution_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveHandle,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-handle",
        grpc: Some("FindDirectory/ResolveHandle"),
        mq: Some("find.directory.query.resolve_handle"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_resolve_handle_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_handle_resolution_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveOrganization,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-organization",
        grpc: Some("FindDirectory/ResolveOrganization"),
        mq: Some("find.directory.query.resolve_organization"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_resolve_organization_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_organization_resolution_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveRealm,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-realm",
        grpc: Some("FindDirectory/ResolveRealm"),
        mq: Some("find.directory.query.resolve_realm"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_resolve_realm_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_realm_resolution_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveTarget,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-target",
        grpc: Some("FindDirectory/ResolveTarget"),
        mq: Some("find.directory.query.resolve_target"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_resolve_target_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_target_resolution_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadSearchActors,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-actors",
        grpc: Some("FindDirectory/SearchActors"),
        mq: Some("find.directory.query.search_actors"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_search_actors_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_actor_search_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadSearchOrganizations,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-organizations",
        grpc: Some("FindDirectory/SearchOrganizations"),
        mq: Some("find.directory.query.search_organizations"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_search_organizations_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_organization_search_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadSearchRealms,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-realms",
        grpc: Some("FindDirectory/SearchRealms"),
        mq: Some("find.directory.query.search_realms"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_search_realms_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_realm_search_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadSearchUsers,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-users",
        grpc: Some("FindDirectory/SearchUsers"),
        mq: Some("find.directory.query.search_users"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_search_users_request_body",
        ),
        response_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_user_search_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandAbandonIdentityCreation,
        http_method: "POST",
        http_path: "/_arkret/gate/account/identity-abandonments",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_abandonment_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_abandonment_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "records_only_a_service_local_orphan_anchor_tombstone_audit_reservation_and_releases_the_identity_creation_lease_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIntrospectSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/introspect",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueControllerGateAttestation,
        http_method: "POST",
        http_path: "/_arkret/gate/account/controller-gate-attestations",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-signer-evidence-operations.schema.json#/$defs/controller_account_gate_attestation_issue_request",
        ),
        response_schema_ref: Some(
            "schemas/agent-signer-evidence-operations.schema.json#/$defs/controller_account_gate_attestation_issue_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "issues_only_a_short_lived_signed_gate_attestation_and_may_retain_a_service_local_exact_replay_record",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueDidBindingChallenge,
        http_method: "POST",
        http_path: "/_arkret/gate/account/did-binding-challenges",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/did_binding_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/did_binding_challenge_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_a_service_local_single_use_challenge_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueIdentityAbandonmentChallenge,
        http_method: "POST",
        http_path: "/_arkret/gate/account/identity-abandonment-challenges",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_abandonment_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_abandonment_challenge_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_a_service_local_single_use_challenge_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueIdentityBindingChallenge,
        http_method: "POST",
        http_path: "/_arkret/gate/account/identity-binding-challenges",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_binding_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/identity_binding_challenge_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_a_service_local_single_use_challenge_and_holder_authenticated_did_operation_checkpoint_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueRecoveryCompletionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/recovery-session-grants/issue",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/issue_recovery_completion_grant_request",
        ),
        response_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/issue_recovery_completion_grant_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants",
        grpc: Some("GateAccount/IssueSessionGrant"),
        mq: Some("gate.account.command.issue_session_grant"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.issue_session_grant\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandLogout,
        http_method: "POST",
        http_path: "/_arkret/gate/account/logout",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountLogoutRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountLogoutOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.introspect_session_grant\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandLogoutAuthSession,
        http_method: "POST",
        http_path: "/_arkret/gate/account/auth-sessions/logout",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthSessionLogoutRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthSessionLogoutOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.introspect_session_grant\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPairAgentKey,
        http_method: "POST",
        http_path: "/_arkret/gate/account/agent-key-pair",
        grpc: Some("GateAccount/AgentKeyPair"),
        mq: Some("gate.account.command.pair_agent_key"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_key_pair_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_key_pair_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPairDevice,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-pair",
        grpc: Some("GateAccount/DevicePair"),
        mq: Some("gate.account.command.pair_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_pair_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_pair_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.account.read.viewer\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.device.authorize"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRefreshSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/refresh",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRefreshRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRefreshOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.refresh_session_grant\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRegister,
        http_method: "POST",
        http_path: "/_arkret/gate/account/register",
        grpc: Some("GateAccount/Register"),
        mq: Some("gate.account.command.register"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_register_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_register_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.register\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.realm.create",
                "ak.device.authorize",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRequestErasure,
        http_method: "POST",
        http_path: "/_arkret/gate/account/erasure-requests",
        grpc: Some("GateAccount/RequestErasure"),
        mq: Some("gate.account.command.request_erasure"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_request_erasure_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_request_erasure_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("records_only_a_service_local_erasure_intent_no_event_is_authored"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRevokeSession,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/revoke",
        grpc: Some("GateAccount/SessionRevoke"),
        mq: Some("gate.account.command.revoke_session"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/session_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/session_revoke_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.revoke_session\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountExchangeCreateHandoff,
        http_method: "POST",
        http_path: "/_arkret/gate/account/authentication-handoffs",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_handoff_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_handoff_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_service_local_dpop_handoff_lease_fence_and_account_binding_state_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountReadOnboarding,
        http_method: "GET",
        http_path: "/_arkret/gate/account/onboarding",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_onboarding_snapshot",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("reads_only_the_current_service_local_account_onboarding_projection"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/runtime-key-requests",
        grpc: Some("OpenAgentPairing/SubmitRuntimeKeyRequest"),
        mq: Some("open.agent_pairing.command.submit_runtime_key_request"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingReadResolve,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/resolve",
        grpc: Some("OpenAgentPairing/Resolve"),
        mq: Some("open.agent_pairing.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_pairing_resolve_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_pairing_bootstrap",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingReadRuntimeKeyRequestStatus,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/runtime-key-requests/status",
        grpc: Some("OpenAgentPairing/RuntimeKeyRequestStatus"),
        mq: Some("open.agent_pairing.query.runtime_key_request_status"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_status_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_status_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenDevicePairingCommandStage,
        http_method: "POST",
        http_path: "/_arkret/open/device-pairing/requests",
        grpc: Some("OpenDevicePairing/Stage"),
        mq: Some("open.device_pairing.command.stage"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_stage_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_stage_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.device_pairing.command.stage\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenDevicePairingReadResolve,
        http_method: "POST",
        http_path: "/_arkret/open/device-pairing/resolve",
        grpc: Some("OpenDevicePairing/Resolve"),
        mq: Some("open.device_pairing.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_resolve_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_bootstrap",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenDevicePairingReadStatus,
        http_method: "POST",
        http_path: "/_arkret/open/device-pairing/requests/status",
        grpc: Some("OpenDevicePairing/Status"),
        mq: Some("open.device_pairing.query.status"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_status_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_status_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenIdentityReadResolution,
        http_method: "GET",
        http_path: "/_arkret/open/principals/{principal_id}/resolution",
        grpc: Some("OpenIdentity/Resolution"),
        mq: Some("open.identity.query.resolution"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/public_principal_resolution",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenInviteLocatorReadResolve,
        http_method: "POST",
        http_path: "/_arkret/open/invite-locators/resolve",
        grpc: Some("OpenInviteLocator/Resolve"),
        mq: Some("open.invite_locator.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/principal_locator_resolve_request_body",
        ),
        response_schema_ref: Some("schemas/principal-locator.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandNotify,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/notify",
        grpc: Some("OpenMimi/Notify"),
        mq: Some("open.mimi.command.notify"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_notify_request_body",
        ),
        response_schema_ref: Some("schemas/mimi-operations.schema.json#/$defs/mimi_notify_outcome"),
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandProxyDownload,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/proxy-download",
        grpc: Some("OpenMimi/ProxyDownload"),
        mq: Some("open.mimi.command.proxy_download"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_proxy_download_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.mimi.command.proxy_download\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandReportAbuse,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/report-abuse",
        grpc: Some("OpenMimi/ReportAbuse"),
        mq: Some("open.mimi.command.report_abuse"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_outcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandRequestConsent,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/consent/request",
        grpc: Some("OpenMimi/RequestConsent"),
        mq: Some("open.mimi.command.request_consent"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_request_consent_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_request_consent_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandSubmitMessage,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/messages",
        grpc: Some("OpenMimi/SubmitMessage"),
        mq: Some("open.mimi.command.submit_message"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_submit_message_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_submit_message_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.mimi.read.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandUpdateConsent,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/consent/update",
        grpc: Some("OpenMimi/UpdateConsent"),
        mq: Some("open.mimi.command.update_consent"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Dynamic(
                "$request.consent_event.event.kind",
            )),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandUpdateRoom,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/update",
        grpc: Some("OpenMimi/RoomUpdate"),
        mq: Some("open.mimi.command.update_room"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_room_update_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_room_update_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.mimi.read.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::Branched,
            target: None,
            rationale: None,
            branch_contract_json: Some(
                "{\"discriminator\":{\"description\":\"The caller-declared semantic MIMI update kind. The decoded opaque payload MUST carry the same kind before a branch is admitted.\",\"request_path\":\"/update/kind\"},\"effect_branches\":[{\"effect\":{\"event_kinds\":[\"ak.mimi.room_binding\"],\"event_submission_path\":\"/room_binding_event\",\"kind\":\"event_log\"},\"equals\":\"ak.mimi.room_binding\"},{\"effect\":{\"kind\":\"none\",\"rationale\":\"receipt_only_mimi_room_update\"},\"otherwise\":true}]}",
            ),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiExchangeRequestKeyMaterial,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/key-material",
        grpc: Some("OpenMimi/KeyMaterial"),
        mq: Some("open.mimi.exchange.request_key_material"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_key_material_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_key_material_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.mimi.read.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiReadGroupInfo,
        http_method: "GET",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/group-info",
        grpc: Some("OpenMimi/GroupInfo"),
        mq: Some("open.mimi.query.group_info"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_group_info_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiReadIdentifiers,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/identifiers/query",
        grpc: Some("OpenMimi/IdentifierQuery"),
        mq: Some("open.mimi.query.identifiers"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiReadProviderDirectory,
        http_method: "GET",
        http_path: "/_arkret/open/mimi/provider-directory",
        grpc: Some("OpenMimi/ProviderDirectory"),
        mq: Some("open.mimi.query.provider_directory"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/mimi-interop.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenServiceReadResolution,
        http_method: "GET",
        http_path: "/_arkret/open/services/{service_id}/resolution",
        grpc: Some("OpenService/Resolution"),
        mq: Some("open.service.query.resolution"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/service_resolution_record",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAccountStatusCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/account-status",
        grpc: Some("PeerAccountStatus/Submit"),
        mq: Some("peer.account_status.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_publication_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_publication_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "replicates_an_existing_account_authority_issuer_record_without_authoring_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAccountStatusReadResolve,
        http_method: "POST",
        http_path: "/_arkret/peer/account-status/resolve",
        grpc: Some("PeerAccountStatus/Resolve"),
        mq: Some("peer.account_status.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_resolve_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_resolve_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerContactsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/contacts",
        grpc: Some("PeerContacts/Submit"),
        mq: Some("peer.contacts.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/peer_contact_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/peer_contact_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("delivers_existing_signed_fact_without_committing_a_local_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDeviceRevocationsCommandCheck,
        http_method: "POST",
        http_path: "/_arkret/peer/device-revocations/check",
        grpc: Some("PeerDeviceRevocations/Check"),
        mq: Some("peer.device_revocations.command.check"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/device-revocation-state.schema.json#/$defs/device_revocation_gate_check_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-revocation-state.schema.json#/$defs/device_revocation_gate_check_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("origin_service_local_durable_revocation_gate_decision_ledger_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDirectConversationCommandRepairRelay,
        http_method: "POST",
        http_path: "/_arkret/peer/direct-conversations/repair-relay",
        grpc: Some("PeerDirectConversation/RepairRelay"),
        mq: Some("peer.direct_conversation.command.repair_relay"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_repair_relay_request",
        ),
        response_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_repair_enqueue_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "atomically_freezes_one_closed_recipient_target_snapshot_and_queue_batch_without_authoring_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerErasureReceiptCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/erasure-receipts",
        grpc: Some("PeerErasureReceipts/Submit"),
        mq: Some("peer.erasure_receipt.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_submit_request_body",
        ),
        response_schema_ref: Some(
            "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "accepts_a_signed_terminal_result_and_never_triggers_erasure_or_authors_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerErasureReceiptResourceGet,
        http_method: "GET",
        http_path: "/_arkret/peer/erasure-receipts/{receipt_id}",
        grpc: Some("PeerErasureReceipts/Get"),
        mq: Some("peer.erasure_receipt.resource.get"),
        body_class: Some("none"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_resource",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Submit"),
        mq: Some("peer.events.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitFederationRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::DynamicMany(&[
                "$request.events[*].event.kind",
                "$request.controller_transition.event.kind",
                "$request.agent_transitions[*].event.kind",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsReadDescribe,
        http_method: "QUERY",
        http_path: "/_arkret/peer/events/describe",
        grpc: Some("PeerEvents/Describe"),
        mq: Some("peer.events.read.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PeerEventsDescribeRequestBody",
        ),
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsReadFrontier,
        http_method: "QUERY",
        http_path: "/_arkret/peer/events/frontier",
        grpc: Some("PeerEvents/Frontier"),
        mq: Some("peer.events.read.frontier"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PeerEventsFrontierRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierFederationPeerState",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsReadResolve,
        http_method: "QUERY",
        http_path: "/_arkret/peer/events/resolve",
        grpc: Some("PeerEvents/Resolve"),
        mq: Some("peer.events.read.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PeerEventsResolveRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PeerEventsResolveOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsReadScan,
        http_method: "QUERY",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Scan"),
        mq: Some("peer.events.read.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryPostRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerInvitesCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/invites",
        grpc: Some("PeerInvites/Submit"),
        mq: Some("peer.invites.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/invite-delivery-request.schema.json"),
        response_schema_ref: Some(
            "schemas/invite-delivery-request.schema.json#/$defs/invite_delivery_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("delivers_existing_signed_event_without_committing_a_local_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/keypackages/claim",
        grpc: Some("PeerKeys/KeyPackagesClaim"),
        mq: Some("peer.keys.keypackages.command.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.peer.keys.keypackages.read.claim\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesReadClaim,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/keypackages/claims/query",
        grpc: Some("PeerKeys/KeyPackagesClaimQuery"),
        mq: Some("peer.keys.keypackages.query.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/peer_keypackages_claim_query_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/peer_keypackages_claim_query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerMlsReadGroupStateMaterial,
        http_method: "POST",
        http_path: "/_arkret/peer/mls/group-state-material",
        grpc: Some("PeerMls/GroupStateMaterial"),
        mq: Some("peer.mls.query.group_state_material"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/MlsGroupStateMaterialRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/MlsGroupStateMaterialOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerPrincipalGenesisCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/principal-genesis",
        grpc: Some("PeerPrincipalGenesis/Submit"),
        mq: Some("peer.principal_genesis.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/principal-operations.schema.json#/$defs/pcr_genesis_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/principal-operations.schema.json#/$defs/pcr_genesis_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.realm.create",
                "ak.device.authorize",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerServiceResolutionCommandPublish,
        http_method: "POST",
        http_path: "/_arkret/peer/service-resolution/publish",
        grpc: Some("PeerServiceResolution/Publish"),
        mq: Some("peer.service_resolution.command.publish"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/service_resolution_publish_request",
        ),
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/service_resolution_publish_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "service_local_durable_route_mirror_ledger_and_ack_only_no_realm_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerServiceResolutionReadResolve,
        http_method: "QUERY",
        http_path: "/_arkret/peer/service-resolution/resolve",
        grpc: Some("PeerServiceResolution/Resolve"),
        mq: Some("peer.service_resolution.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(16384),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/service_resolution_resolve_request",
        ),
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/service_resolution_resolve_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerSignalCommandRelay,
        http_method: "POST",
        http_path: "/_arkret/peer/signal",
        grpc: Some("PeerSignal/Relay"),
        mq: Some("peer.signal.command.relay"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(1048576),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/signal-relay.schema.json"),
        response_schema_ref: Some("schemas/signal-relay.schema.json#/$defs/signal_relay_outcome"),
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("ephemeral_signal_must_not_be_durable_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerSnapshotReadManifestHead,
        http_method: "GET",
        http_path: "/_arkret/peer/snapshot/head",
        grpc: Some("PeerSnapshot/Head"),
        mq: Some("peer.snapshot.query.manifest_head"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/snapshot.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityCommandSubmitDidOperation,
        http_method: "POST",
        http_path: "/_arkret/root/identity/submit-did-operation",
        grpc: Some("RootIdentity/SubmitDidOperation"),
        mq: Some("root.identity.command.submit_did_operation"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DidOperationSubmitRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DidOperationSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityDocumentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/document",
        grpc: Some("RootIdentity/GetDocument"),
        mq: Some("root.identity.document.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityDocumentView",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityLogReadList,
        http_method: "GET",
        http_path: "/_arkret/root/identity/log",
        grpc: Some("RootIdentity/GetLog"),
        mq: Some("root.identity.log.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityLogListOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandEnsure,
        http_method: "POST",
        http_path: "/_arkret/root/identity/organization-registrations:ensure",
        grpc: Some("RootIdentity/EnsureOrganizationRegistration"),
        mq: Some("root.identity.organization_registration.command.ensure"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationEnsureRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandPrepare,
        http_method: "POST",
        http_path: "/_arkret/root/identity/organization-registrations:prepare",
        grpc: Some("RootIdentity/PrepareOrganizationRegistration"),
        mq: Some("root.identity.organization_registration.command.prepare"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationChallengeRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationChallenge",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.root.identity.organization_registration.command.prepare\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRefresh,
        http_method: "POST",
        http_path: "/_arkret/root/identity/organization-registrations:refresh",
        grpc: Some("RootIdentity/RefreshOrganizationRegistration"),
        mq: Some("root.identity.organization_registration.command.refresh"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationRefreshRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/root/identity/organization-registrations:revoke",
        grpc: Some("RootIdentity/RevokeOrganizationRegistration"),
        mq: Some("root.identity.organization_registration.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationRevokeRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/organization-registrations",
        grpc: Some("RootIdentity/GetOrganizationRegistration"),
        mq: Some("root.identity.organization_registration.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityReadResolve,
        http_method: "POST",
        http_path: "/_arkret/root/identity/resolve",
        grpc: Some("RootIdentity/Resolve"),
        mq: Some("root.identity.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityResolveRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityResolveOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityReceiptsReadList,
        http_method: "GET",
        http_path: "/_arkret/root/identity/receipts",
        grpc: Some("RootIdentity/GetReceipts"),
        mq: Some("root.identity.receipts.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityReceiptListOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoveryPolicyCommandPublish,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-policy",
        grpc: Some("RootIdentity/RecoveryPolicyPublish"),
        mq: Some("root.identity.recovery_policy.command.publish"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-policy.schema.json#/$defs/recovery_policy_publish_request",
        ),
        response_schema_ref: Some(
            "schemas/recovery-policy.schema.json#/$defs/recovery_policy_publish_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.policy.set"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoveryPolicyResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/recovery-policy",
        grpc: Some("RootIdentity/RecoveryPolicyGet"),
        mq: Some("root.identity.recovery_policy.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/recovery-policy.schema.json#/$defs/recovery_policy_active_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions",
        grpc: Some("RootIdentity/RecoverySessionCreate"),
        mq: Some("root.identity.recovery_session.command.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_create_request_body",
        ),
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_state",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.root.identity.recovery_session.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProof,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions/{recovery_session_id}/proofs",
        grpc: Some("RootIdentity/RecoverySessionSubmitProof"),
        mq: Some("root.identity.recovery_session.command.submit_proof"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_proof_submit_request_body",
        ),
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_proof_submit_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.root.identity.recovery_session.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/recovery-sessions/{recovery_session_id}",
        grpc: Some("RootIdentity/RecoverySessionGet"),
        mq: Some("root.identity.recovery_session.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_state",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRegistryReadDescribe,
        http_method: "GET",
        http_path: "/_arkret/root/identity/describe",
        grpc: Some("RootIdentity/DescribeRegistry"),
        mq: Some("root.identity.registry.query.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityServiceRegistrationCommandEnsure,
        http_method: "POST",
        http_path: "/_arkret/root/identity/service-registrations:ensure",
        grpc: Some("RootIdentity/EnsureServiceRegistration"),
        mq: Some("root.identity.service_registration.command.ensure"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationEnsureRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityServiceRegistrationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/service-registrations",
        grpc: Some("RootIdentity/GetServiceRegistration"),
        mq: Some("root.identity.service_registration.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountCommandRevokeCursor,
        http_method: "POST",
        http_path: "/_arkret/self/account/cursor/revoke",
        grpc: Some("SelfAccount/CursorRevoke"),
        mq: Some("self.account.command.revoke_cursor"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountCursorRevokeRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountCursorRevokeOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountCommandUpdateProfile,
        http_method: "POST",
        http_path: "/_arkret/self/account/profile",
        grpc: Some("SelfAccount/UpdateProfile"),
        mq: Some("self.account.command.update_profile"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_update_profile_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_update_profile_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.profile.create",
                "ak.profile.update",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountReadDescribe,
        http_method: "GET",
        http_path: "/_arkret/self/account/describe",
        grpc: Some("SelfAccount/Describe"),
        mq: Some("self.account.query.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountReadViewer,
        http_method: "GET",
        http_path: "/_arkret/self/account/viewer",
        grpc: Some("SelfAccount/Viewer"),
        mq: Some("self.account.query.viewer"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/account-operations.schema.json#/$defs/account_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountStreamSubscribe,
        http_method: "GET",
        http_path: "/_arkret/self/account/subscribe",
        grpc: Some("SelfAccount/Subscribe"),
        mq: Some("self.account.stream.subscribe"),
        body_class: Some("streaming_ndjson"),
        max_canonical_body_bytes: None,
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataReadList,
        http_method: "GET",
        http_path: "/_arkret/self/account_data",
        grpc: Some("SelfAccountData/List"),
        mq: Some("self.account_data.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/account_data/{account_data_key}",
        grpc: Some("SelfAccountData/Delete"),
        mq: Some("self.account_data.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_delete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_delete_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::ActorPrivateEvent,
            target: Some(DurableEventTarget::Static(&["ak.account_data.set"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/account_data/{account_data_key}",
        grpc: Some("SelfAccountData/Get"),
        mq: Some("self.account_data.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_entry",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/account_data/{account_data_key}",
        grpc: Some("SelfAccountData/Replace"),
        mq: Some("self.account_data.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_replace_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_entry",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::ActorPrivateEvent,
            target: Some(DurableEventTarget::Static(&["ak.account_data.set"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfActorProfileReadResolve,
        http_method: "POST",
        http_path: "/_arkret/self/actor-profiles/query",
        grpc: Some("SelfActorProfile/Resolve"),
        mq: Some("self.actor_profile.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/actor-profile-operations.schema.json#/$defs/resolve_request",
        ),
        response_schema_ref: Some(
            "schemas/actor-profile-operations.schema.json#/$defs/resolve_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandAbandonProvisioning,
        http_method: "POST",
        http_path: "/_arkret/self/agent-provisioning-abandonments",
        grpc: Some("SelfAgent/AbandonProvisioning"),
        mq: Some("self.agent.command.abandon_provisioning"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provisioning_abandonment_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provisioning_abandonment_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "releases_only_service_local_slug_and_realm_id_claims_and_records_a_tombstone_audit_reservation_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandDeactivate,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/deactivate",
        grpc: Some("SelfAgent/Deactivate"),
        mq: Some("self.agent.command.deactivate"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_deactivate_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_lifecycle_state",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.agent.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.deactivate"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandIssueProvisioningAbandonmentChallenge,
        http_method: "POST",
        http_path: "/_arkret/self/agent-provisioning-abandonment-challenges",
        grpc: Some("SelfAgent/IssueProvisioningAbandonmentChallenge"),
        mq: Some("self.agent.command.issue_provisioning_abandonment_challenge"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provisioning_abandonment_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provisioning_abandonment_challenge_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_a_service_local_single_use_challenge_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandPause,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/pause",
        grpc: Some("SelfAgent/Pause"),
        mq: Some("self.agent.command.pause"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_pause_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_lifecycle_state",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.agent.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.pause"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandProvision,
        http_method: "POST",
        http_path: "/_arkret/self/agents",
        grpc: Some("SelfAgent/Provision"),
        mq: Some("self.agent.command.provision"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provision_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_provision_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.agent.provision"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandRenewPairing,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/renew-pairing",
        grpc: Some("SelfAgent/RenewPairing"),
        mq: Some("self.agent.command.renew_pairing"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_renew_pairing_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_renew_pairing_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.agent.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandResume,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/resume",
        grpc: Some("SelfAgent/Resume"),
        mq: Some("self.agent.command.resume"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_resume_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_lifecycle_state",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.agent.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.resume"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentGrantCommandAttach,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/grants",
        grpc: Some("SelfAgent/GrantAttach"),
        mq: Some("self.agent.grant.command.attach"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_attach_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_attach_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.authz.grants.read.effective\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.capability.grant"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentGrantResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/agents/{agent_id}/grants/{grant_id}",
        grpc: Some("SelfAgent/GrantDetach"),
        mq: Some("self.agent.grant.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_detach_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_detach_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.capability.revoke"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agents/{agent_id}/participation",
        grpc: Some("SelfAgent/ParticipationGet"),
        mq: Some("self.agent.participation.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_participation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/agents/{agent_id}/participation",
        grpc: Some("SelfAgent/ParticipationReplace"),
        mq: Some("self.agent.participation.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/principal-operations.schema.json#/$defs/participation_replace_request",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_participation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("controller_private_versioned_account_state"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentReadList,
        http_method: "GET",
        http_path: "/_arkret/self/agents",
        grpc: Some("SelfAgent/List"),
        mq: Some("self.agent.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agents/{agent_id}",
        grpc: Some("SelfAgent/Get"),
        mq: Some("self.agent.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarCommandEnsure,
        http_method: "POST",
        http_path: "/_arkret/self/agent-sidecars:ensure",
        grpc: Some("SelfAgent/SidecarEnsure"),
        mq: Some("self.agent.sidecar.command.ensure"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/principal-operations.schema.json#/$defs/sidecar_ensure_request",
        ),
        response_schema_ref: Some(
            "schemas/principal-operations.schema.json#/$defs/sidecar_ensure_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.sidecar.create",
                "ak.sidecar.context.attach",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarReadList,
        http_method: "GET",
        http_path: "/_arkret/self/agent-sidecars",
        grpc: Some("SelfAgent/SidecarList"),
        mq: Some("self.agent.sidecar.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_sidecar_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agent-sidecars/{sidecar_id}",
        grpc: Some("SelfAgent/SidecarGet"),
        mq: Some("self.agent.sidecar.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_sidecar_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSignerEvidenceReadResolve,
        http_method: "POST",
        http_path: "/_arkret/self/agent-signer-evidence/query",
        grpc: Some("SelfAgentSignerEvidence/Resolve"),
        mq: Some("self.agent_signer_evidence.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/agent-signer-evidence-operations.schema.json#/$defs/query_request",
        ),
        response_schema_ref: Some(
            "schemas/agent-signer-evidence-operations.schema.json#/$defs/query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletCommandInstall,
        http_method: "POST",
        http_path: "/_arkret/self/applets/install",
        grpc: Some("SelfApplet/Install"),
        mq: Some("self.applet.command.install"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_install_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_install_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.applet.registration",
                "ak.capability.grant",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/revoke",
        grpc: Some("SelfApplet/Revoke"),
        mq: Some("self.applet.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_revoke_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.capability.revoke",
                "ak.member.state",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletGhostCommandProvision,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/ghosts/provision",
        grpc: Some("SelfApplet/GhostProvision"),
        mq: Some("self.applet.ghost.command.provision"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-ghost-operations.schema.json#/$defs/ghost_actor_provision_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-ghost-operations.schema.json#/$defs/ghost_actor_provision_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.identity.accountability_grant",
                "ak.profile.create",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletInstallCommandPreview,
        http_method: "POST",
        http_path: "/_arkret/self/applets/install/preview",
        grpc: Some("SelfApplet/InstallPreview"),
        mq: Some("self.applet.install.command.preview"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_install_preview_request_body",
        ),
        response_schema_ref: Some("schemas/applet-install-plan.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("read_only_preview_despite_post_binding"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletRevokeCommandPreview,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/revoke/preview",
        grpc: Some("SelfApplet/RevokePreview"),
        mq: Some("self.applet.revoke.command.preview"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_revoke_preview_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_revoke_preview_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("query_only_recomputed_revoke_plan"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthorizationLeasesCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/authorization-leases",
        grpc: Some("SelfAuthorizationLeases/Issue"),
        mq: Some("self.authorization_leases.command.issue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthorizationLeaseIssueRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthorizationLeaseIssueOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("pre_admission_only_no_event_commit"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzGrantsReadEffective,
        http_method: "GET",
        http_path: "/_arkret/self/authz/effective-grants",
        grpc: Some("SelfAuthz/GetEffectiveGrants"),
        mq: Some("self.authz.grants.query.effective"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/service-operation-dtos.schema.json#/$defs/GrantList"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzInvitesReadList,
        http_method: "GET",
        http_path: "/_arkret/self/authz/invites",
        grpc: Some("SelfAuthz/GetInvites"),
        mq: Some("self.authz.invites.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/authz-operations.schema.json#/$defs/authz_invite_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzReadCheck,
        http_method: "POST",
        http_path: "/_arkret/self/authz/check",
        grpc: Some("SelfAuthz/Check"),
        mq: Some("self.authz.query.check"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthzCheckRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthzCheckOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobCommandPresign,
        http_method: "POST",
        http_path: "/_arkret/self/blob/presign",
        grpc: Some("SelfBlob/Presign"),
        mq: Some("self.blob.command.presign"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/BlobPresignRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/BlobPresignOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.blob.command.presign\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/blob/get",
        grpc: Some("SelfBlob/Get"),
        mq: Some("self.blob.resource.get"),
        body_class: Some("binary_stream"),
        max_canonical_body_bytes: None,
        success_shape_kind: "binary_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobResourceHead,
        http_method: "HEAD",
        http_path: "/_arkret/self/blob/get",
        grpc: Some("SelfBlob/Head"),
        mq: Some("self.blob.resource.head"),
        body_class: Some("binary_stream"),
        max_canonical_body_bytes: None,
        success_shape_kind: "metadata_headers",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/blob/upload",
        grpc: Some("SelfBlob/Upload"),
        mq: Some("self.blob.upload.create"),
        body_class: Some("binary_stream"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/blob-operations.schema.json#/$defs/blob_upload_request_body",
        ),
        response_schema_ref: Some("schemas/blob-operations.schema.json#/$defs/blob_upload_outcome"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCallMediaExchangeIssueToken,
        http_method: "POST",
        http_path: "/_arkret/self/rtc/token",
        grpc: Some("SelfCallMedia/TokenExchange"),
        mq: Some("self.call.media.exchange.issue_token"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/CallMediaTokenExchangeRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/CallMediaTokenExchangeOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.call.media.exchange.issue_token\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandArchive,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/archive",
        grpc: Some("SelfCircle/Archive"),
        mq: Some("self.circle.command.archive"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_archive_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.archive"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/self/circles",
        grpc: Some("SelfCircle/Create"),
        mq: Some("self.circle.command.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_create_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.create"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandRestore,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/restore",
        grpc: Some("SelfCircle/Restore"),
        mq: Some("self.circle.command.restore"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_restore_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.restore"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandRotateScope,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/scope-rotate",
        grpc: Some("SelfCircle/ScopeRotate"),
        mq: Some("self.circle.command.rotate_scope"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_scope_rotate_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "v1_surface_is_declared_but_always_returns_unsupported_feature_until_a_signed_event_submission_request_contract_is_registered",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/tombstone",
        grpc: Some("SelfCircle/Tombstone"),
        mq: Some("self.circle.command.tombstone"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_tombstone_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.tombstone"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleMemberCommandAdd,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/members",
        grpc: Some("SelfCircle/MemberAdd"),
        mq: Some("self.circle.member.command.add"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_member_request_body",
        ),
        response_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.member.state"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleMemberResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/circles/{circle_id}/members/{actor_id}",
        grpc: Some("SelfCircle/MemberRemove"),
        mq: Some("self.circle.member.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_member_delete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.member.state"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleReadList,
        http_method: "GET",
        http_path: "/_arkret/self/circles",
        grpc: Some("SelfCircle/List"),
        mq: Some("self.circle.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/circles/{circle_id}",
        grpc: Some("SelfCircle/Get"),
        mq: Some("self.circle.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandGrant,
        http_method: "POST",
        http_path: "/_arkret/self/consent/cells/{holder_principal_id}/grant",
        grpc: Some("SelfConsent/Grant"),
        mq: Some("self.consent.command.grant"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_grant_request_body",
        ),
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.grant"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRequest,
        http_method: "POST",
        http_path: "/_arkret/self/consent/request",
        grpc: Some("SelfConsent/Request"),
        mq: Some("self.consent.command.request"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_request_request_body",
        ),
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_request_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/consent/cells/{holder_principal_id}/revoke",
        grpc: Some("SelfConsent/Revoke"),
        mq: Some("self.consent.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.revoke"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentReadList,
        http_method: "GET",
        http_path: "/_arkret/self/consent/cells",
        grpc: Some("SelfConsent/List"),
        mq: Some("self.consent.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/consent/cells/{holder_principal_id}",
        grpc: Some("SelfConsent/Get"),
        mq: Some("self.consent.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandCheckpoint,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/continuity-checkpoint",
        grpc: Some("SelfContact/ContinuityCheckpoint"),
        mq: Some("self.contact.command.checkpoint"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_continuity_checkpoint_request_body",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_continuity_checkpoint_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "compacts_already_accepted_contact_evidence_without_authoring_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandReject,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/reject",
        grpc: Some("SelfContact/Reject"),
        mq: Some("self.contact.command.reject"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_reject_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_reject_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.rejected"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandRequest,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/request",
        grpc: Some("SelfContact/Request"),
        mq: Some("self.contact.command.request"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_operation_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_request_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.requested"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandRespond,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/respond",
        grpc: Some("SelfContact/Respond"),
        mq: Some("self.contact.command.respond"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_respond_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_respond_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.accepted"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandScopeUpdate,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/scope-update",
        grpc: Some("SelfContact/ScopeUpdate"),
        mq: Some("self.contact.command.scope_update"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_scope_update_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_scope_update_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.scope.update"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/tombstone",
        grpc: Some("SelfContact/Tombstone"),
        mq: Some("self.contact.command.tombstone"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_tombstone_request",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_tombstone_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.tombstone"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactReadList,
        http_method: "GET",
        http_path: "/_arkret/self/contacts",
        grpc: Some("SelfContact/List"),
        mq: Some("self.contact.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/contact-operations.schema.json#/$defs/contact_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfControlProposalAcksCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/control-proposal-acks",
        grpc: Some("SelfControlProposalAcks/Issue"),
        mq: Some("self.control_proposal_acks.command.issue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_ack_issue_request",
        ),
        response_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_ack_issue_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("pre_admission_receipt_only_no_event_commit"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfControlProposalDecisionsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/self/control-proposal-decisions",
        grpc: Some("SelfControlProposalDecisions/Submit"),
        mq: Some("self.control_proposal_decisions.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_decision_submit_request_body",
        ),
        response_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_decision_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("durable_control_proposal_decision_log_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfControlProposalDecisionsReadGet,
        http_method: "POST",
        http_path: "/_arkret/self/control-proposal-decisions/query",
        grpc: Some("SelfControlProposalDecisions/Get"),
        mq: Some("self.control_proposal_decisions.read.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_decision_read_request_body",
        ),
        response_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_decision_read_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesCommandAck,
        http_method: "POST",
        http_path: "/_arkret/self/device_messages/ack",
        grpc: Some("SelfDeviceMessages/Ack"),
        mq: Some("self.device_messages.command.ack"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesAckRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesAckOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesCommandSend,
        http_method: "POST",
        http_path: "/_arkret/self/device_messages",
        grpc: Some("SelfDeviceMessages/Send"),
        mq: Some("self.device_messages.command.send"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesSendRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesSendOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesReadList,
        http_method: "GET",
        http_path: "/_arkret/self/device_messages",
        grpc: Some("SelfDeviceMessages/Get"),
        mq: Some("self.device_messages.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesGetOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDirectConversationCommandRepairDispatch,
        http_method: "POST",
        http_path: "/_arkret/self/direct-conversations/repair-dispatch",
        grpc: Some("SelfDirectConversation/RepairDispatch"),
        mq: Some("self.direct_conversation.command.repair_dispatch"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_repair_dispatch_request",
        ),
        response_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_repair_enqueue_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_a_byte_identical_service_local_peer_relay_outbox_without_authoring_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDirectConversationReadResolve,
        http_method: "POST",
        http_path: "/_arkret/self/direct-conversations/resolve",
        grpc: Some("SelfDirectConversation/Resolve"),
        mq: Some("self.direct_conversation.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_request",
        ),
        response_schema_ref: Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Submit"),
        mq: Some("self.events.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SelfEventsSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::DynamicMany(&[
                "$request.event.kind",
                "$request.events[*].event.kind",
                "$request.controller_transition.event.kind",
                "$request.agent_transitions[*].event.kind",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsCommandSubmitSeal,
        http_method: "POST",
        http_path: "/_arkret/self/events/seals",
        grpc: Some("SelfEvents/SubmitSeal"),
        mq: Some("self.events.command.submit_seal"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/seal.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventSealSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("commits_a_seal_not_an_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadDeliveryStatus,
        http_method: "QUERY",
        http_path: "/_arkret/self/events/delivery-status",
        grpc: Some("SelfEvents/DeliveryStatus"),
        mq: Some("self.events.read.delivery_status"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadDescribe,
        http_method: "QUERY",
        http_path: "/_arkret/self/events/describe",
        grpc: Some("SelfEvents/Describe"),
        mq: Some("self.events.read.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsDescribeRequestBody",
        ),
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadFrontier,
        http_method: "QUERY",
        http_path: "/_arkret/self/events/frontier",
        grpc: Some("SelfEvents/Frontier"),
        mq: Some("self.events.read.frontier"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierState",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadMlsGovernanceProof,
        http_method: "QUERY",
        http_path: "/_arkret/self/events/mls-governance-proof",
        grpc: Some("SelfEvents/MlsGovernanceProof"),
        mq: Some("self.events.read.mls_governance_proof"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mls-governance-proof-bundle.schema.json#/$defs/proof_request",
        ),
        response_schema_ref: Some("schemas/mls-governance-proof-bundle.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadResolve,
        http_method: "QUERY",
        http_path: "/_arkret/self/events/resolve",
        grpc: Some("SelfEvents/Resolve"),
        mq: Some("self.events.read.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsResolveRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsResolveOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadScan,
        http_method: "QUERY",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Scan"),
        mq: Some("self.events.read.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryPostRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/events/{event_id}",
        grpc: Some("SelfEvents/Get"),
        mq: Some("self.events.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/service-operation-dtos.schema.json#/$defs/EventView"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsStreamSubscribe,
        http_method: "GET",
        http_path: "/_arkret/self/events/subscribe",
        grpc: Some("SelfEvents/Subscribe"),
        mq: Some("self.events.stream.subscribe"),
        body_class: Some("streaming_ndjson"),
        max_canonical_body_bytes: None,
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfIdentityReadResolutionAudit,
        http_method: "POST",
        http_path: "/_arkret/self/identity/resolution-audit/query",
        grpc: Some("SelfIdentity/ResolutionAudit"),
        mq: Some("self.identity.query.resolution_audit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/principal_resolution_audit_request",
        ),
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/principal_resolution_audit_evidence",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators",
        grpc: Some("SelfInviteLocator/Issue"),
        mq: Some("self.invite_locator.command.issue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_issue_request_body",
        ),
        response_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_issue_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.invite_locator.command.issue\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators/revoke",
        grpc: Some("SelfInviteLocator/Revoke"),
        mq: Some("self.invite_locator.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_revoke_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandRotate,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators/rotate",
        grpc: Some("SelfInviteLocator/Rotate"),
        mq: Some("self.invite_locator.command.rotate"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_rotate_request_body",
        ),
        response_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_issue_outcome",
        ),
        uncertain_outcome: Some(
            "{\"reissue_operation_id\":\"ak.self.invite_locator.command.issue\",\"requires_fresh_request_identity\":true,\"revoke_operation_id\":\"ak.self.invite_locator.command.revoke\",\"strategy\":\"revoke_then_reissue\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteReceivePolicyResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/invite-receive-policy",
        grpc: Some("SelfInviteReceivePolicy/Get"),
        mq: Some("self.invite_receive_policy.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteReceivePolicyResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/invite-receive-policy",
        grpc: Some("SelfInviteReceivePolicy/Replace"),
        mq: Some("self.invite_receive_policy.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        response_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInvitesCommandDispatch,
        http_method: "POST",
        http_path: "/_arkret/self/invites/dispatch",
        grpc: Some("SelfInvites/Dispatch"),
        mq: Some("self.invites.command.dispatch"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/invite-delivery-request.schema.json"),
        response_schema_ref: Some(
            "schemas/invite-delivery-request.schema.json#/$defs/invite_delivery_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_a_byte_identical_service_local_peer_relay_outbox_without_authoring_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupSeriesCommandErase,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backup-series/erase",
        grpc: Some("SelfKeys/BackupSeriesErase"),
        mq: Some("self.keys.backup_series.command.erase"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/backup_series_erase_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/backup_series_erase_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsCommandIssueDeleteChallenge,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backups/{backup_id}/delete-challenge",
        grpc: Some("SelfKeys/BackupsIssueDeleteChallenge"),
        mq: Some("self.keys.backups.command.issue_delete_challenge"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_issue_delete_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_challenge",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsCommandUnlock,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backups/{backup_id}/unlock",
        grpc: Some("SelfKeys/BackupsUnlock"),
        mq: Some("self.keys.backups.command.unlock"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_unlock_request_body",
        ),
        response_schema_ref: Some("schemas/key-backup.schema.json"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.backups.command.unlock\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsReadList,
        http_method: "GET",
        http_path: "/_arkret/self/keys/backups",
        grpc: Some("SelfKeys/BackupsList"),
        mq: Some("self.keys.backups.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_backups_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/keys/backups/{backup_id}",
        grpc: Some("SelfKeys/BackupsDelete"),
        mq: Some("self.keys.backups.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/keys/backups/{backup_id}",
        grpc: Some("SelfKeys/BackupsReplace"),
        mq: Some("self.keys.backups.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/key-backup.schema.json"),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_replace_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/self/keys/claim",
        grpc: Some("SelfKeys/Claim"),
        mq: Some("self.keys.command.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_claim_request_body",
        ),
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_claim_outcome"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.read.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/claim",
        grpc: Some("SelfKeys/KeyPackagesClaim"),
        mq: Some("self.keys.keypackages.command.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.peer.keys.keypackages.read.claim\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandConsume,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/consume",
        grpc: Some("SelfKeys/KeyPackagesConsume"),
        mq: Some("self.keys.keypackages.command.consume"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_consume_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_consume_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.read.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/revoke",
        grpc: Some("SelfKeys/KeyPackagesRevoke"),
        mq: Some("self.keys.keypackages.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_revoke_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.read.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/upload",
        grpc: Some("SelfKeys/KeyPackagesUpload"),
        mq: Some("self.keys.keypackages.upload.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_upload_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_upload_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.keypackages.upload.create\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysReadLookup,
        http_method: "POST",
        http_path: "/_arkret/self/keys/query",
        grpc: Some("SelfKeys/Query"),
        mq: Some("self.keys.query.lookup"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_query_request_body",
        ),
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_query_outcome"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/keys/upload",
        grpc: Some("SelfKeys/Upload"),
        mq: Some("self.keys.upload.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_upload_request_body",
        ),
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_upload_outcome"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.read.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMediaReadIceConfig,
        http_method: "POST",
        http_path: "/_arkret/self/rtc/ice-config",
        grpc: Some("SelfMedia/IceConfig"),
        mq: Some("self.media.query.ice_config"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/media-operations.schema.json#/$defs/media_ice_config_request_body",
        ),
        response_schema_ref: Some("schemas/ice-config-response.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfModerationCommandReport,
        http_method: "POST",
        http_path: "/_arkret/self/moderation/report",
        grpc: Some("SelfModeration/Report"),
        mq: Some("self.moderation.command.report"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/moderation-report.schema.json#/$defs/moderation_report_request_body",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ModerationReportOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.moderation.report"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMorphReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/morphs",
        grpc: Some("SelfMorph/List"),
        mq: Some("self.morph.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionMorphList",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMorphResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/morphs/{morph_id}",
        grpc: Some("SelfMorph/Get"),
        mq: Some("self.morph.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/view.schema.json#/$defs/document_morph_projection_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfPolicyReadCheck,
        http_method: "POST",
        http_path: "/_arkret/self/policy/check",
        grpc: Some("SelfPolicy/Check"),
        mq: Some("self.policy.query.check"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PolicyCheckRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/PolicyCheckOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfReadCursorCommandAdvance,
        http_method: "POST",
        http_path: "/_arkret/self/read-cursors",
        grpc: Some("SelfReadCursor/Advance"),
        mq: Some("self.read_cursor.command.advance"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/read-cursor-operations.schema.json#/$defs/read_cursor_advance_request_body",
        ),
        response_schema_ref: Some(
            "schemas/read-cursor-operations.schema.json#/$defs/read_marker_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::ActorPrivateEvent,
            target: Some(DurableEventTarget::Static(&["ak.read_cursor.advance"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfReadCursorReadList,
        http_method: "GET",
        http_path: "/_arkret/self/read-cursors",
        grpc: Some("SelfReadCursor/List"),
        mq: Some("self.read_cursor.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/read-cursor-operations.schema.json#/$defs/read_cursor_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandArchive,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/archive",
        grpc: Some("SelfRealm/Archive"),
        mq: Some("self.realm.command.archive"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_archive_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.realm.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.archive"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandDestroy,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/destroy",
        grpc: Some("SelfRealm/Destroy"),
        mq: Some("self.realm.command.destroy"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_destroy_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.realm.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.destroy"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandFreeze,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/freeze",
        grpc: Some("SelfRealm/Freeze"),
        mq: Some("self.realm.command.freeze"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_freeze_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.realm.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.freeze"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/tombstone",
        grpc: Some("SelfRealm/Tombstone"),
        mq: Some("self.realm.command.tombstone"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_tombstone_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.realm.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.tombstone"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationAuditReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/audit",
        grpc: Some("SelfRealmJoinApplication/ListAudit"),
        mq: Some("self.realm.join_application.audit.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_audit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandCancel,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/cancel",
        grpc: Some("SelfRealmJoinApplication/Cancel"),
        mq: Some("self.realm.join_application.command.cancel"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_cancel_request",
        ),
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_mutation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandReview,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/reviews",
        grpc: Some("SelfRealmJoinApplication/Review"),
        mq: Some("self.realm.join_application.command.review"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_review_request",
        ),
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_mutation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications",
        grpc: Some("SelfRealmJoinApplication/Submit"),
        mq: Some("self.realm.join_application.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_mutation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications",
        grpc: Some("SelfRealmJoinApplication/List"),
        mq: Some("self.realm.join_application.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_list_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}",
        grpc: Some("SelfRealmJoinApplication/Get"),
        mq: Some("self.realm.join_application.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_get_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmModerationPolicyReadEffective,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/moderation-policy/effective",
        grpc: Some("SelfRealm/ModerationPolicyEffective"),
        mq: Some("self.realm.moderation_policy.query.effective"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_effective_moderation_policy",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmModerationPolicyResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/realms/{realm_id}/moderation-policy",
        grpc: Some("SelfRealm/ModerationPolicyReplace"),
        mq: Some("self.realm.moderation_policy.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_moderation_policy_replace_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_moderation_policy_document",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.moderation_policy"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmReadExport,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/export",
        grpc: Some("SelfRealm/Export"),
        mq: Some("self.realm.query.export"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/realm-read-operations.schema.json#/$defs/realm_export"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}",
        grpc: Some("SelfRealm/Get"),
        mq: Some("self.realm.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/links",
        grpc: Some("SelfRealmLink/Create"),
        mq: Some("self.realm_link.command.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_create_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_mutation_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.realm_link.read.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.link"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkReadEffectivePolicy,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/effective-policy",
        grpc: Some("SelfRealmLink/EffectivePolicy"),
        mq: Some("self.realm_link.query.effective_policy"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_effective_policy_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/links",
        grpc: Some("SelfRealmLink/List"),
        mq: Some("self.realm_link.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/realms/{realm_id}/links/{target_realm_id}",
        grpc: Some("SelfRealmLink/Delete"),
        mq: Some("self.realm_link.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_delete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_mutation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.link"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmOrganizationReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/organizations",
        grpc: Some("SelfRealmOrganization/List"),
        mq: Some("self.realm_organization.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Delete"),
        mq: Some("self.realm_policy_server.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "empty_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/realm-policy-server-operations.schema.json#/$defs/realm_policy_server_delete_request_body",
        ),
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.policy_server"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Get"),
        mq: Some("self.realm_policy_server.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-policy-server-operations.schema.json#/$defs/realm_policy_server_view",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Replace"),
        mq: Some("self.realm_policy_server.resource.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/realm-policy-server-operations.schema.json#/$defs/realm_policy_server_replace_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-policy-server-operations.schema.json#/$defs/realm_policy_server_view",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.policy_server"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSecurityTransactionCommandContinue,
        http_method: "POST",
        http_path: "/_arkret/self/security-transactions/{transaction_id}/continue",
        grpc: Some("SelfSecurityTransactions/Continue"),
        mq: Some("self.security_transaction.command.continue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/security-transaction.schema.json#/$defs/continue_request",
        ),
        response_schema_ref: Some("schemas/security-transaction.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSecurityTransactionCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/self/security-transactions",
        grpc: Some("SelfSecurityTransactions/Create"),
        mq: Some("self.security_transaction.command.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/security-transaction.schema.json#/$defs/create_request"),
        response_schema_ref: Some("schemas/security-transaction.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSecurityTransactionResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/security-transactions/{transaction_id}",
        grpc: Some("SelfSecurityTransactions/Get"),
        mq: Some("self.security_transaction.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/security-transaction.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSignalCommandSend,
        http_method: "POST",
        http_path: "/_arkret/self/signal",
        grpc: Some("SelfSignal/Send"),
        mq: Some("self.signal.command.send"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/signal-envelope.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SignalSubmitOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("ephemeral_signal_must_not_be_durable_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSignalStreamSubscribe,
        http_method: "GET",
        http_path: "/_arkret/self/signal/subscribe",
        grpc: Some("SelfSignal/Subscribe"),
        mq: Some("self.signal.stream.subscribe"),
        body_class: Some("streaming_ndjson"),
        max_canonical_body_bytes: None,
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSnapshotReadManifestHead,
        http_method: "GET",
        http_path: "/_arkret/self/snapshot/head",
        grpc: Some("SelfSnapshot/Head"),
        mq: Some("self.snapshot.query.manifest_head"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/snapshot.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSpaceReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/spaces",
        grpc: Some("SelfSpace/List"),
        mq: Some("self.space.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionSpaceList",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfStrandReadList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/strands",
        grpc: Some("SelfStrand/List"),
        mq: Some("self.strand.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionStrandList",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfViewsCollectionProjectionCommandMaterialize,
        http_method: "POST",
        http_path: "/_arkret/self/views/{view_id}/projection",
        grpc: Some("SelfViews/CollectionProjection"),
        mq: Some("self.views.collection_projection.command.materialize"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/view.schema.json#/$defs/view_projection_request_body"),
        response_schema_ref: Some("schemas/view.schema.json#/$defs/collection_projection_view"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::ServerReadDescribe,
        http_method: "GET",
        http_path: "/_arkret/describe",
        grpc: Some("Server/Describe"),
        mq: Some("server.query.describe"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: None,
    },
];
