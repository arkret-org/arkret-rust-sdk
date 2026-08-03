//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/operation-registry.json; version=2026-08-03.7;
//! sha256=27b3edb940c95fa3d37e14a5284845424136c3daf37813974b46f49ef28c4d1a Entries: registered=231

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ServiceOperationId {
    EdgeAppletActorQueryResolve,
    EdgeAppletCommandTransaction,
    EdgeAppletQueryDescribe,
    EdgeAppletQueryPing,
    EdgeAppletQueryProtocolMetadata,
    EdgeAppletRealmQueryResolve,
    EdgeAppletThirdPartyLocationsQueryList,
    EdgeAppletThirdPartyUsersQueryList,
    EdgePushCommandNotify,
    EdgePushCommandRegisterDevice,
    EdgePushCommandUnregisterDevice,
    FindDirectoryCommandAnnounce,
    FindDirectoryCommandTakedownAppeal,
    FindDirectoryCommandWithdraw,
    FindDirectoryPushCommandRegister,
    FindDirectoryQueryDescribe,
    FindDirectoryQueryListHandlesForSubject,
    FindDirectoryQueryPrivateContactDiscovery,
    FindDirectoryQueryResolveAgentSelector,
    FindDirectoryQueryResolveHandle,
    FindDirectoryQueryResolveOrganization,
    FindDirectoryQueryResolveRealm,
    FindDirectoryQueryResolveTarget,
    FindDirectoryQuerySearchActors,
    FindDirectoryQuerySearchOrganizations,
    FindDirectoryQuerySearchRealms,
    FindDirectoryQuerySearchUsers,
    GateAccountCommandAuthorizeRecoveryDevice,
    GateAccountCommandCancelDeviceBootstrap,
    GateAccountCommandEnrollDevice,
    GateAccountCommandIntrospectSessionGrant,
    GateAccountCommandIssueIdentityBindingChallenge,
    GateAccountCommandIssueSessionGrant,
    GateAccountCommandLogout,
    GateAccountCommandLogoutAuthSession,
    GateAccountCommandPairAgentKey,
    GateAccountCommandPairDevice,
    GateAccountCommandPromoteRecoverySessionGrant,
    GateAccountCommandRefreshSessionGrant,
    GateAccountCommandRegister,
    GateAccountCommandRevokeSession,
    GateAccountExchangeCompleteOidc,
    GateAccountExchangeCreateHandoff,
    OpenAgentPairingCommandSubmitRuntimeKeyRequest,
    OpenAgentPairingQueryResolve,
    OpenAgentPairingQueryRuntimeKeyRequestStatus,
    OpenDevicePairingCommandStage,
    OpenDevicePairingQueryResolve,
    OpenDevicePairingQueryStatus,
    OpenInviteLocatorQueryResolve,
    OpenMimiCommandNotify,
    OpenMimiCommandProxyDownload,
    OpenMimiCommandReportAbuse,
    OpenMimiCommandRequestConsent,
    OpenMimiCommandSubmitMessage,
    OpenMimiCommandUpdateConsent,
    OpenMimiCommandUpdateRoom,
    OpenMimiExchangeRequestKeyMaterial,
    OpenMimiQueryGroupInfo,
    OpenMimiQueryIdentifiers,
    OpenMimiQueryProviderDirectory,
    PeerAccountStatusCommandSubmit,
    PeerAccountStatusQueryAuthoringBasis,
    PeerAgentParticipationCommandReplace,
    PeerAgentParticipationQueryPrepareScopeEvidence,
    PeerContactsCommandSubmit,
    PeerDirectConversationOperationControlCommandDeliver,
    PeerDirectConversationOperationControlCommandSubmit,
    PeerDirectConversationOperationControlQueryExecutionBundle,
    PeerDirectConversationOperationControlQueryReadCertificate,
    PeerEventsCommandSubmit,
    PeerEventsQueryDescribe,
    PeerEventsQueryFrontier,
    PeerEventsQueryResolve,
    PeerEventsQueryScan,
    PeerEventsQueryScanBody,
    PeerInvitesCommandSubmit,
    PeerKeysKeypackagesCommandClaim,
    PeerKeysKeypackagesQueryClaim,
    PeerMlsQueryGroupStateMaterial,
    PeerSignalCommandRelay,
    PeerSnapshotQueryManifestHead,
    RootIdentityCommandSubmitDidOperation,
    RootIdentityDocumentResourceGet,
    RootIdentityLogQueryList,
    RootIdentityOrganizationRegistrationCommandEnsure,
    RootIdentityOrganizationRegistrationCommandPrepare,
    RootIdentityOrganizationRegistrationCommandRefresh,
    RootIdentityOrganizationRegistrationCommandRevoke,
    RootIdentityOrganizationRegistrationResourceGet,
    RootIdentityQueryResolve,
    RootIdentityReceiptsQueryList,
    RootIdentityRecoveryPolicyCommandPublish,
    RootIdentityRecoveryPolicyResourceGet,
    RootIdentityRecoverySessionCommandCreate,
    RootIdentityRecoverySessionCommandSubmitProof,
    RootIdentityRecoverySessionResourceGet,
    RootIdentityRegistryQueryDescribe,
    RootIdentityServiceRegistrationCommandEnsure,
    RootIdentityServiceRegistrationResourceGet,
    SelfAccountCommandRevokeCursor,
    SelfAccountCommandUpdateProfile,
    SelfAccountQueryDescribe,
    SelfAccountQueryViewer,
    SelfAccountStreamSubscribe,
    SelfAccountDataQueryList,
    SelfAccountDataResourceDelete,
    SelfAccountDataResourceGet,
    SelfAccountDataResourceReplace,
    SelfAgentCommandDeactivate,
    SelfAgentCommandPause,
    SelfAgentCommandProvision,
    SelfAgentCommandRenewPairing,
    SelfAgentCommandResume,
    SelfAgentGrantCommandAttach,
    SelfAgentGrantResourceDelete,
    SelfAgentParticipationQueryPrepareScopeEvidence,
    SelfAgentParticipationResourceGet,
    SelfAgentParticipationResourceReplace,
    SelfAgentQueryList,
    SelfAgentResourceGet,
    SelfAgentSidecarCommandEnsure,
    SelfAgentSidecarQueryList,
    SelfAgentSidecarResourceGet,
    SelfAgentSignerEvidenceQueryResolve,
    SelfAppletCommandInstall,
    SelfAppletCommandRevoke,
    SelfAppletGhostCommandProvision,
    SelfAppletInstallCommandPreview,
    SelfAuthorizationLeasesCommandIssue,
    SelfAuthzGrantsQueryEffective,
    SelfAuthzInvitesQueryList,
    SelfAuthzQueryCheck,
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
    SelfCircleQueryList,
    SelfCircleResourceGet,
    SelfConsentCommandGrant,
    SelfConsentCommandRequest,
    SelfConsentCommandRevoke,
    SelfConsentQueryList,
    SelfConsentResourceGet,
    SelfContactCommandReject,
    SelfContactCommandRequest,
    SelfContactCommandRespond,
    SelfContactCommandScopeUpdate,
    SelfContactCommandTombstone,
    SelfContactQueryList,
    SelfControlProposalReceiptsCommandIssue,
    SelfDeviceMessagesCommandAck,
    SelfDeviceMessagesCommandSend,
    SelfDeviceMessagesQueryList,
    SelfDirectConversationCommandResolve,
    SelfEventsCommandSubmit,
    SelfEventsCommandSubmitSeal,
    SelfEventsQueryDescribe,
    SelfEventsQueryFrontier,
    SelfEventsQueryMlsGovernanceProof,
    SelfEventsQueryResolve,
    SelfEventsQueryScan,
    SelfEventsQueryScanBody,
    SelfEventsResourceGet,
    SelfEventsStreamSubscribe,
    SelfInviteLocatorCommandIssue,
    SelfInviteLocatorCommandRevoke,
    SelfInviteLocatorCommandRotate,
    SelfInviteReceivePolicyResourceGet,
    SelfInviteReceivePolicyResourceReplace,
    SelfKeysBackupSeriesCommandErase,
    SelfKeysBackupsCommandIssueDeleteChallenge,
    SelfKeysBackupsCommandUnlock,
    SelfKeysBackupsQueryList,
    SelfKeysBackupsResourceDelete,
    SelfKeysBackupsResourceReplace,
    SelfKeysCommandClaim,
    SelfKeysKeypackagesCommandClaim,
    SelfKeysKeypackagesCommandConsume,
    SelfKeysKeypackagesCommandRevoke,
    SelfKeysKeypackagesUploadCreate,
    SelfKeysQueryLookup,
    SelfKeysUploadCreate,
    SelfMediaQueryIceConfig,
    SelfModerationCommandReport,
    SelfMorphQueryList,
    SelfMorphResourceGet,
    SelfPolicyQueryCheck,
    SelfReadCursorCommandAdvance,
    SelfReadCursorQueryList,
    SelfRealmCommandArchive,
    SelfRealmCommandDestroy,
    SelfRealmCommandFreeze,
    SelfRealmCommandTombstone,
    SelfRealmJoinApplicationAuditQueryList,
    SelfRealmJoinApplicationCommandCancel,
    SelfRealmJoinApplicationCommandReview,
    SelfRealmJoinApplicationCommandSubmit,
    SelfRealmJoinApplicationQueryList,
    SelfRealmJoinApplicationResourceGet,
    SelfRealmModerationPolicyQueryEffective,
    SelfRealmModerationPolicyResourceReplace,
    SelfRealmQueryExport,
    SelfRealmResourceGet,
    SelfRealmLinkCommandCreate,
    SelfRealmLinkQueryEffectivePolicy,
    SelfRealmLinkQueryList,
    SelfRealmLinkResourceDelete,
    SelfRealmOrganizationQueryList,
    SelfRealmPolicyServerResourceDelete,
    SelfRealmPolicyServerResourceGet,
    SelfRealmPolicyServerResourceReplace,
    SelfRecoveryAuthorityTicketCommandIssue,
    SelfSecurityTransactionCommandContinue,
    SelfSecurityTransactionCommandCreate,
    SelfSecurityTransactionResourceGet,
    SelfSignalCommandSend,
    SelfSignalStreamSubscribe,
    SelfSnapshotQueryManifestHead,
    SelfSpaceQueryList,
    SelfStrandQueryList,
    SelfViewsCollectionProjectionCommandMaterialize,
    ServerQueryDescribe,
}

pub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[
    ServiceOperationId::EDGE_APPLET_ACTOR_QUERY_RESOLVE,
    ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
    ServiceOperationId::EDGE_APPLET_QUERY_DESCRIBE,
    ServiceOperationId::EDGE_APPLET_QUERY_PING,
    ServiceOperationId::EDGE_APPLET_QUERY_PROTOCOL_METADATA,
    ServiceOperationId::EDGE_APPLET_REALM_QUERY_RESOLVE,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST,
    ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY,
    ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
    ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
    ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
    ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE,
    ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT,
    ServiceOperationId::FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY,
    ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_AGENT_SELECTOR,
    ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE,
    ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION,
    ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM,
    ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET,
    ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS,
    ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS,
    ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS,
    ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_AUTHORIZE_RECOVERY_DEVICE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_CANCEL_DEVICE_BOOTSTRAP,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ENROLL_DEVICE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PROMOTE_RECOVERY_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
    ServiceOperationId::GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC,
    ServiceOperationId::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF,
    ServiceOperationId::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST,
    ServiceOperationId::OPEN_AGENT_PAIRING_QUERY_RESOLVE,
    ServiceOperationId::OPEN_AGENT_PAIRING_QUERY_RUNTIME_KEY_REQUEST_STATUS,
    ServiceOperationId::OPEN_DEVICE_PAIRING_COMMAND_STAGE,
    ServiceOperationId::OPEN_DEVICE_PAIRING_QUERY_RESOLVE,
    ServiceOperationId::OPEN_DEVICE_PAIRING_QUERY_STATUS,
    ServiceOperationId::OPEN_INVITE_LOCATOR_QUERY_RESOLVE,
    ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY,
    ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD,
    ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE,
    ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT,
    ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM,
    ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL,
    ServiceOperationId::OPEN_MIMI_QUERY_GROUP_INFO,
    ServiceOperationId::OPEN_MIMI_QUERY_IDENTIFIERS,
    ServiceOperationId::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY,
    ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_ACCOUNT_STATUS_QUERY_AUTHORING_BASIS,
    ServiceOperationId::PEER_AGENT_PARTICIPATION_COMMAND_REPLACE,
    ServiceOperationId::PEER_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE,
    ServiceOperationId::PEER_CONTACTS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_DELIVER,
    ServiceOperationId::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_SUBMIT,
    ServiceOperationId::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_EXECUTION_BUNDLE,
    ServiceOperationId::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_READ_CERTIFICATE,
    ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT,
    ServiceOperationId::PEER_EVENTS_QUERY_DESCRIBE,
    ServiceOperationId::PEER_EVENTS_QUERY_FRONTIER,
    ServiceOperationId::PEER_EVENTS_QUERY_RESOLVE,
    ServiceOperationId::PEER_EVENTS_QUERY_SCAN,
    ServiceOperationId::PEER_EVENTS_QUERY_SCAN_BODY,
    ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_QUERY_CLAIM,
    ServiceOperationId::PEER_MLS_QUERY_GROUP_STATE_MATERIAL,
    ServiceOperationId::PEER_SIGNAL_COMMAND_RELAY,
    ServiceOperationId::PEER_SNAPSHOT_QUERY_MANIFEST_HEAD,
    ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION,
    ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_QUERY_RESOLVE,
    ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET,
    ServiceOperationId::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE,
    ServiceOperationId::SELF_ACCOUNT_QUERY_DESCRIBE,
    ServiceOperationId::SELF_ACCOUNT_QUERY_VIEWER,
    ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_ACCOUNT_DATA_QUERY_LIST,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_DELETE,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE,
    ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
    ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
    ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
    ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
    ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
    ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE,
    ServiceOperationId::SELF_AGENT_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    ServiceOperationId::SELF_AGENT_SIDECAR_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_SIDECAR_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_SIGNER_EVIDENCE_QUERY_RESOLVE,
    ServiceOperationId::SELF_APPLET_COMMAND_INSTALL,
    ServiceOperationId::SELF_APPLET_COMMAND_REVOKE,
    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION,
    ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW,
    ServiceOperationId::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE,
    ServiceOperationId::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE,
    ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST,
    ServiceOperationId::SELF_AUTHZ_QUERY_CHECK,
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
    ServiceOperationId::SELF_CIRCLE_QUERY_LIST,
    ServiceOperationId::SELF_CIRCLE_RESOURCE_GET,
    ServiceOperationId::SELF_CONSENT_COMMAND_GRANT,
    ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST,
    ServiceOperationId::SELF_CONSENT_COMMAND_REVOKE,
    ServiceOperationId::SELF_CONSENT_QUERY_LIST,
    ServiceOperationId::SELF_CONSENT_RESOURCE_GET,
    ServiceOperationId::SELF_CONTACT_COMMAND_REJECT,
    ServiceOperationId::SELF_CONTACT_COMMAND_REQUEST,
    ServiceOperationId::SELF_CONTACT_COMMAND_RESPOND,
    ServiceOperationId::SELF_CONTACT_COMMAND_SCOPE_UPDATE,
    ServiceOperationId::SELF_CONTACT_COMMAND_TOMBSTONE,
    ServiceOperationId::SELF_CONTACT_QUERY_LIST,
    ServiceOperationId::SELF_CONTROL_PROPOSAL_RECEIPTS_COMMAND_ISSUE,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND,
    ServiceOperationId::SELF_DEVICE_MESSAGES_QUERY_LIST,
    ServiceOperationId::SELF_DIRECT_CONVERSATION_COMMAND_RESOLVE,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_SEAL,
    ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE,
    ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER,
    ServiceOperationId::SELF_EVENTS_QUERY_MLS_GOVERNANCE_PROOF,
    ServiceOperationId::SELF_EVENTS_QUERY_RESOLVE,
    ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
    ServiceOperationId::SELF_EVENTS_QUERY_SCAN_BODY,
    ServiceOperationId::SELF_EVENTS_RESOURCE_GET,
    ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ISSUE,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_REVOKE,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ROTATE,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE,
    ServiceOperationId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK,
    ServiceOperationId::SELF_KEYS_BACKUPS_QUERY_LIST,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE,
    ServiceOperationId::SELF_KEYS_COMMAND_CLAIM,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE,
    ServiceOperationId::SELF_KEYS_QUERY_LOOKUP,
    ServiceOperationId::SELF_KEYS_UPLOAD_CREATE,
    ServiceOperationId::SELF_MEDIA_QUERY_ICE_CONFIG,
    ServiceOperationId::SELF_MODERATION_COMMAND_REPORT,
    ServiceOperationId::SELF_MORPH_QUERY_LIST,
    ServiceOperationId::SELF_MORPH_RESOURCE_GET,
    ServiceOperationId::SELF_POLICY_QUERY_CHECK,
    ServiceOperationId::SELF_READ_CURSOR_COMMAND_ADVANCE,
    ServiceOperationId::SELF_READ_CURSOR_QUERY_LIST,
    ServiceOperationId::SELF_REALM_COMMAND_ARCHIVE,
    ServiceOperationId::SELF_REALM_COMMAND_DESTROY,
    ServiceOperationId::SELF_REALM_COMMAND_FREEZE,
    ServiceOperationId::SELF_REALM_COMMAND_TOMBSTONE,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_AUDIT_QUERY_LIST,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_QUERY_LIST,
    ServiceOperationId::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_MODERATION_POLICY_QUERY_EFFECTIVE,
    ServiceOperationId::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE,
    ServiceOperationId::SELF_REALM_QUERY_EXPORT,
    ServiceOperationId::SELF_REALM_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_LINK_COMMAND_CREATE,
    ServiceOperationId::SELF_REALM_LINK_QUERY_EFFECTIVE_POLICY,
    ServiceOperationId::SELF_REALM_LINK_QUERY_LIST,
    ServiceOperationId::SELF_REALM_LINK_RESOURCE_DELETE,
    ServiceOperationId::SELF_REALM_ORGANIZATION_QUERY_LIST,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_GET,
    ServiceOperationId::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE,
    ServiceOperationId::SELF_RECOVERY_AUTHORITY_TICKET_COMMAND_ISSUE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CREATE,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_RESOURCE_GET,
    ServiceOperationId::SELF_SIGNAL_COMMAND_SEND,
    ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD,
    ServiceOperationId::SELF_SPACE_QUERY_LIST,
    ServiceOperationId::SELF_STRAND_QUERY_LIST,
    ServiceOperationId::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE,
    ServiceOperationId::SERVER_QUERY_DESCRIBE,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableEffectKind {
    EventLog,
    ActorPrivateEvent,
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
        Self::EdgeAppletActorQueryResolve,
        Self::EdgeAppletCommandTransaction,
        Self::EdgeAppletQueryDescribe,
        Self::EdgeAppletQueryPing,
        Self::EdgeAppletQueryProtocolMetadata,
        Self::EdgeAppletRealmQueryResolve,
        Self::EdgeAppletThirdPartyLocationsQueryList,
        Self::EdgeAppletThirdPartyUsersQueryList,
        Self::EdgePushCommandNotify,
        Self::EdgePushCommandRegisterDevice,
        Self::EdgePushCommandUnregisterDevice,
        Self::FindDirectoryCommandAnnounce,
        Self::FindDirectoryCommandTakedownAppeal,
        Self::FindDirectoryCommandWithdraw,
        Self::FindDirectoryPushCommandRegister,
        Self::FindDirectoryQueryDescribe,
        Self::FindDirectoryQueryListHandlesForSubject,
        Self::FindDirectoryQueryPrivateContactDiscovery,
        Self::FindDirectoryQueryResolveAgentSelector,
        Self::FindDirectoryQueryResolveHandle,
        Self::FindDirectoryQueryResolveOrganization,
        Self::FindDirectoryQueryResolveRealm,
        Self::FindDirectoryQueryResolveTarget,
        Self::FindDirectoryQuerySearchActors,
        Self::FindDirectoryQuerySearchOrganizations,
        Self::FindDirectoryQuerySearchRealms,
        Self::FindDirectoryQuerySearchUsers,
        Self::GateAccountCommandAuthorizeRecoveryDevice,
        Self::GateAccountCommandCancelDeviceBootstrap,
        Self::GateAccountCommandEnrollDevice,
        Self::GateAccountCommandIntrospectSessionGrant,
        Self::GateAccountCommandIssueIdentityBindingChallenge,
        Self::GateAccountCommandIssueSessionGrant,
        Self::GateAccountCommandLogout,
        Self::GateAccountCommandLogoutAuthSession,
        Self::GateAccountCommandPairAgentKey,
        Self::GateAccountCommandPairDevice,
        Self::GateAccountCommandPromoteRecoverySessionGrant,
        Self::GateAccountCommandRefreshSessionGrant,
        Self::GateAccountCommandRegister,
        Self::GateAccountCommandRevokeSession,
        Self::GateAccountExchangeCompleteOidc,
        Self::GateAccountExchangeCreateHandoff,
        Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        Self::OpenAgentPairingQueryResolve,
        Self::OpenAgentPairingQueryRuntimeKeyRequestStatus,
        Self::OpenDevicePairingCommandStage,
        Self::OpenDevicePairingQueryResolve,
        Self::OpenDevicePairingQueryStatus,
        Self::OpenInviteLocatorQueryResolve,
        Self::OpenMimiCommandNotify,
        Self::OpenMimiCommandProxyDownload,
        Self::OpenMimiCommandReportAbuse,
        Self::OpenMimiCommandRequestConsent,
        Self::OpenMimiCommandSubmitMessage,
        Self::OpenMimiCommandUpdateConsent,
        Self::OpenMimiCommandUpdateRoom,
        Self::OpenMimiExchangeRequestKeyMaterial,
        Self::OpenMimiQueryGroupInfo,
        Self::OpenMimiQueryIdentifiers,
        Self::OpenMimiQueryProviderDirectory,
        Self::PeerAccountStatusCommandSubmit,
        Self::PeerAccountStatusQueryAuthoringBasis,
        Self::PeerAgentParticipationCommandReplace,
        Self::PeerAgentParticipationQueryPrepareScopeEvidence,
        Self::PeerContactsCommandSubmit,
        Self::PeerDirectConversationOperationControlCommandDeliver,
        Self::PeerDirectConversationOperationControlCommandSubmit,
        Self::PeerDirectConversationOperationControlQueryExecutionBundle,
        Self::PeerDirectConversationOperationControlQueryReadCertificate,
        Self::PeerEventsCommandSubmit,
        Self::PeerEventsQueryDescribe,
        Self::PeerEventsQueryFrontier,
        Self::PeerEventsQueryResolve,
        Self::PeerEventsQueryScan,
        Self::PeerEventsQueryScanBody,
        Self::PeerInvitesCommandSubmit,
        Self::PeerKeysKeypackagesCommandClaim,
        Self::PeerKeysKeypackagesQueryClaim,
        Self::PeerMlsQueryGroupStateMaterial,
        Self::PeerSignalCommandRelay,
        Self::PeerSnapshotQueryManifestHead,
        Self::RootIdentityCommandSubmitDidOperation,
        Self::RootIdentityDocumentResourceGet,
        Self::RootIdentityLogQueryList,
        Self::RootIdentityOrganizationRegistrationCommandEnsure,
        Self::RootIdentityOrganizationRegistrationCommandPrepare,
        Self::RootIdentityOrganizationRegistrationCommandRefresh,
        Self::RootIdentityOrganizationRegistrationCommandRevoke,
        Self::RootIdentityOrganizationRegistrationResourceGet,
        Self::RootIdentityQueryResolve,
        Self::RootIdentityReceiptsQueryList,
        Self::RootIdentityRecoveryPolicyCommandPublish,
        Self::RootIdentityRecoveryPolicyResourceGet,
        Self::RootIdentityRecoverySessionCommandCreate,
        Self::RootIdentityRecoverySessionCommandSubmitProof,
        Self::RootIdentityRecoverySessionResourceGet,
        Self::RootIdentityRegistryQueryDescribe,
        Self::RootIdentityServiceRegistrationCommandEnsure,
        Self::RootIdentityServiceRegistrationResourceGet,
        Self::SelfAccountCommandRevokeCursor,
        Self::SelfAccountCommandUpdateProfile,
        Self::SelfAccountQueryDescribe,
        Self::SelfAccountQueryViewer,
        Self::SelfAccountStreamSubscribe,
        Self::SelfAccountDataQueryList,
        Self::SelfAccountDataResourceDelete,
        Self::SelfAccountDataResourceGet,
        Self::SelfAccountDataResourceReplace,
        Self::SelfAgentCommandDeactivate,
        Self::SelfAgentCommandPause,
        Self::SelfAgentCommandProvision,
        Self::SelfAgentCommandRenewPairing,
        Self::SelfAgentCommandResume,
        Self::SelfAgentGrantCommandAttach,
        Self::SelfAgentGrantResourceDelete,
        Self::SelfAgentParticipationQueryPrepareScopeEvidence,
        Self::SelfAgentParticipationResourceGet,
        Self::SelfAgentParticipationResourceReplace,
        Self::SelfAgentQueryList,
        Self::SelfAgentResourceGet,
        Self::SelfAgentSidecarCommandEnsure,
        Self::SelfAgentSidecarQueryList,
        Self::SelfAgentSidecarResourceGet,
        Self::SelfAgentSignerEvidenceQueryResolve,
        Self::SelfAppletCommandInstall,
        Self::SelfAppletCommandRevoke,
        Self::SelfAppletGhostCommandProvision,
        Self::SelfAppletInstallCommandPreview,
        Self::SelfAuthorizationLeasesCommandIssue,
        Self::SelfAuthzGrantsQueryEffective,
        Self::SelfAuthzInvitesQueryList,
        Self::SelfAuthzQueryCheck,
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
        Self::SelfCircleQueryList,
        Self::SelfCircleResourceGet,
        Self::SelfConsentCommandGrant,
        Self::SelfConsentCommandRequest,
        Self::SelfConsentCommandRevoke,
        Self::SelfConsentQueryList,
        Self::SelfConsentResourceGet,
        Self::SelfContactCommandReject,
        Self::SelfContactCommandRequest,
        Self::SelfContactCommandRespond,
        Self::SelfContactCommandScopeUpdate,
        Self::SelfContactCommandTombstone,
        Self::SelfContactQueryList,
        Self::SelfControlProposalReceiptsCommandIssue,
        Self::SelfDeviceMessagesCommandAck,
        Self::SelfDeviceMessagesCommandSend,
        Self::SelfDeviceMessagesQueryList,
        Self::SelfDirectConversationCommandResolve,
        Self::SelfEventsCommandSubmit,
        Self::SelfEventsCommandSubmitSeal,
        Self::SelfEventsQueryDescribe,
        Self::SelfEventsQueryFrontier,
        Self::SelfEventsQueryMlsGovernanceProof,
        Self::SelfEventsQueryResolve,
        Self::SelfEventsQueryScan,
        Self::SelfEventsQueryScanBody,
        Self::SelfEventsResourceGet,
        Self::SelfEventsStreamSubscribe,
        Self::SelfInviteLocatorCommandIssue,
        Self::SelfInviteLocatorCommandRevoke,
        Self::SelfInviteLocatorCommandRotate,
        Self::SelfInviteReceivePolicyResourceGet,
        Self::SelfInviteReceivePolicyResourceReplace,
        Self::SelfKeysBackupSeriesCommandErase,
        Self::SelfKeysBackupsCommandIssueDeleteChallenge,
        Self::SelfKeysBackupsCommandUnlock,
        Self::SelfKeysBackupsQueryList,
        Self::SelfKeysBackupsResourceDelete,
        Self::SelfKeysBackupsResourceReplace,
        Self::SelfKeysCommandClaim,
        Self::SelfKeysKeypackagesCommandClaim,
        Self::SelfKeysKeypackagesCommandConsume,
        Self::SelfKeysKeypackagesCommandRevoke,
        Self::SelfKeysKeypackagesUploadCreate,
        Self::SelfKeysQueryLookup,
        Self::SelfKeysUploadCreate,
        Self::SelfMediaQueryIceConfig,
        Self::SelfModerationCommandReport,
        Self::SelfMorphQueryList,
        Self::SelfMorphResourceGet,
        Self::SelfPolicyQueryCheck,
        Self::SelfReadCursorCommandAdvance,
        Self::SelfReadCursorQueryList,
        Self::SelfRealmCommandArchive,
        Self::SelfRealmCommandDestroy,
        Self::SelfRealmCommandFreeze,
        Self::SelfRealmCommandTombstone,
        Self::SelfRealmJoinApplicationAuditQueryList,
        Self::SelfRealmJoinApplicationCommandCancel,
        Self::SelfRealmJoinApplicationCommandReview,
        Self::SelfRealmJoinApplicationCommandSubmit,
        Self::SelfRealmJoinApplicationQueryList,
        Self::SelfRealmJoinApplicationResourceGet,
        Self::SelfRealmModerationPolicyQueryEffective,
        Self::SelfRealmModerationPolicyResourceReplace,
        Self::SelfRealmQueryExport,
        Self::SelfRealmResourceGet,
        Self::SelfRealmLinkCommandCreate,
        Self::SelfRealmLinkQueryEffectivePolicy,
        Self::SelfRealmLinkQueryList,
        Self::SelfRealmLinkResourceDelete,
        Self::SelfRealmOrganizationQueryList,
        Self::SelfRealmPolicyServerResourceDelete,
        Self::SelfRealmPolicyServerResourceGet,
        Self::SelfRealmPolicyServerResourceReplace,
        Self::SelfRecoveryAuthorityTicketCommandIssue,
        Self::SelfSecurityTransactionCommandContinue,
        Self::SelfSecurityTransactionCommandCreate,
        Self::SelfSecurityTransactionResourceGet,
        Self::SelfSignalCommandSend,
        Self::SelfSignalStreamSubscribe,
        Self::SelfSnapshotQueryManifestHead,
        Self::SelfSpaceQueryList,
        Self::SelfStrandQueryList,
        Self::SelfViewsCollectionProjectionCommandMaterialize,
        Self::ServerQueryDescribe,
    ];

    pub const EDGE_APPLET_ACTOR_QUERY_RESOLVE: &'static str = "ak.edge.applet.actor.query.resolve";
    pub const EDGE_APPLET_COMMAND_TRANSACTION: &'static str = "ak.edge.applet.command.transaction";
    pub const EDGE_APPLET_QUERY_DESCRIBE: &'static str = "ak.edge.applet.query.describe";
    pub const EDGE_APPLET_QUERY_PING: &'static str = "ak.edge.applet.query.ping";
    pub const EDGE_APPLET_QUERY_PROTOCOL_METADATA: &'static str =
        "ak.edge.applet.query.protocol_metadata";
    pub const EDGE_APPLET_REALM_QUERY_RESOLVE: &'static str = "ak.edge.applet.realm.query.resolve";
    pub const EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST: &'static str =
        "ak.edge.applet.third_party_locations.query.list";
    pub const EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST: &'static str =
        "ak.edge.applet.third_party_users.query.list";
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
    pub const FIND_DIRECTORY_QUERY_DESCRIBE: &'static str = "ak.find.directory.query.describe";
    pub const FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT: &'static str =
        "ak.find.directory.query.list_handles_for_subject";
    pub const FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY: &'static str =
        "ak.find.directory.query.private_contact_discovery";
    pub const FIND_DIRECTORY_QUERY_RESOLVE_AGENT_SELECTOR: &'static str =
        "ak.find.directory.query.resolve_agent_selector";
    pub const FIND_DIRECTORY_QUERY_RESOLVE_HANDLE: &'static str =
        "ak.find.directory.query.resolve_handle";
    pub const FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION: &'static str =
        "ak.find.directory.query.resolve_organization";
    pub const FIND_DIRECTORY_QUERY_RESOLVE_REALM: &'static str =
        "ak.find.directory.query.resolve_realm";
    pub const FIND_DIRECTORY_QUERY_RESOLVE_TARGET: &'static str =
        "ak.find.directory.query.resolve_target";
    pub const FIND_DIRECTORY_QUERY_SEARCH_ACTORS: &'static str =
        "ak.find.directory.query.search_actors";
    pub const FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS: &'static str =
        "ak.find.directory.query.search_organizations";
    pub const FIND_DIRECTORY_QUERY_SEARCH_REALMS: &'static str =
        "ak.find.directory.query.search_realms";
    pub const FIND_DIRECTORY_QUERY_SEARCH_USERS: &'static str =
        "ak.find.directory.query.search_users";
    pub const GATE_ACCOUNT_COMMAND_AUTHORIZE_RECOVERY_DEVICE: &'static str =
        "ak.gate.account.command.authorize_recovery_device";
    pub const GATE_ACCOUNT_COMMAND_CANCEL_DEVICE_BOOTSTRAP: &'static str =
        "ak.gate.account.command.cancel_device_bootstrap";
    pub const GATE_ACCOUNT_COMMAND_ENROLL_DEVICE: &'static str =
        "ak.gate.account.command.enroll_device";
    pub const GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT: &'static str =
        "ak.gate.account.command.introspect_session_grant";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE: &'static str =
        "ak.gate.account.command.issue_identity_binding_challenge";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT: &'static str =
        "ak.gate.account.command.issue_session_grant";
    pub const GATE_ACCOUNT_COMMAND_LOGOUT: &'static str = "ak.gate.account.command.logout";
    pub const GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION: &'static str =
        "ak.gate.account.command.logout_auth_session";
    pub const GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY: &'static str =
        "ak.gate.account.command.pair_agent_key";
    pub const GATE_ACCOUNT_COMMAND_PAIR_DEVICE: &'static str =
        "ak.gate.account.command.pair_device";
    pub const GATE_ACCOUNT_COMMAND_PROMOTE_RECOVERY_SESSION_GRANT: &'static str =
        "ak.gate.account.command.promote_recovery_session_grant";
    pub const GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT: &'static str =
        "ak.gate.account.command.refresh_session_grant";
    pub const GATE_ACCOUNT_COMMAND_REGISTER: &'static str = "ak.gate.account.command.register";
    pub const GATE_ACCOUNT_COMMAND_REVOKE_SESSION: &'static str =
        "ak.gate.account.command.revoke_session";
    pub const GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC: &'static str =
        "ak.gate.account.exchange.complete_oidc";
    pub const GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF: &'static str =
        "ak.gate.account.exchange.create_handoff";
    pub const OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST: &'static str =
        "ak.open.agent_pairing.command.submit_runtime_key_request";
    pub const OPEN_AGENT_PAIRING_QUERY_RESOLVE: &'static str =
        "ak.open.agent_pairing.query.resolve";
    pub const OPEN_AGENT_PAIRING_QUERY_RUNTIME_KEY_REQUEST_STATUS: &'static str =
        "ak.open.agent_pairing.query.runtime_key_request_status";
    pub const OPEN_DEVICE_PAIRING_COMMAND_STAGE: &'static str =
        "ak.open.device_pairing.command.stage";
    pub const OPEN_DEVICE_PAIRING_QUERY_RESOLVE: &'static str =
        "ak.open.device_pairing.query.resolve";
    pub const OPEN_DEVICE_PAIRING_QUERY_STATUS: &'static str =
        "ak.open.device_pairing.query.status";
    pub const OPEN_INVITE_LOCATOR_QUERY_RESOLVE: &'static str =
        "ak.open.invite_locator.query.resolve";
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
    pub const OPEN_MIMI_QUERY_GROUP_INFO: &'static str = "ak.open.mimi.query.group_info";
    pub const OPEN_MIMI_QUERY_IDENTIFIERS: &'static str = "ak.open.mimi.query.identifiers";
    pub const OPEN_MIMI_QUERY_PROVIDER_DIRECTORY: &'static str =
        "ak.open.mimi.query.provider_directory";
    pub const PEER_ACCOUNT_STATUS_COMMAND_SUBMIT: &'static str =
        "ak.peer.account_status.command.submit";
    pub const PEER_ACCOUNT_STATUS_QUERY_AUTHORING_BASIS: &'static str =
        "ak.peer.account_status.query.authoring_basis";
    pub const PEER_AGENT_PARTICIPATION_COMMAND_REPLACE: &'static str =
        "ak.peer.agent.participation.command.replace";
    pub const PEER_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE: &'static str =
        "ak.peer.agent.participation.query.prepare_scope_evidence";
    pub const PEER_CONTACTS_COMMAND_SUBMIT: &'static str = "ak.peer.contacts.command.submit";
    pub const PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_DELIVER: &'static str =
        "ak.peer.direct_conversation.operation_control.command.deliver";
    pub const PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_SUBMIT: &'static str =
        "ak.peer.direct_conversation.operation_control.command.submit";
    pub const PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_EXECUTION_BUNDLE: &'static str =
        "ak.peer.direct_conversation.operation_control.query.execution_bundle";
    pub const PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_READ_CERTIFICATE: &'static str =
        "ak.peer.direct_conversation.operation_control.query.read_certificate";
    pub const PEER_EVENTS_COMMAND_SUBMIT: &'static str = "ak.peer.events.command.submit";
    pub const PEER_EVENTS_QUERY_DESCRIBE: &'static str = "ak.peer.events.query.describe";
    pub const PEER_EVENTS_QUERY_FRONTIER: &'static str = "ak.peer.events.query.frontier";
    pub const PEER_EVENTS_QUERY_RESOLVE: &'static str = "ak.peer.events.query.resolve";
    pub const PEER_EVENTS_QUERY_SCAN: &'static str = "ak.peer.events.query.scan";
    pub const PEER_EVENTS_QUERY_SCAN_BODY: &'static str = "ak.peer.events.query.scan_body";
    pub const PEER_INVITES_COMMAND_SUBMIT: &'static str = "ak.peer.invites.command.submit";
    pub const PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM: &'static str =
        "ak.peer.keys.keypackages.command.claim";
    pub const PEER_KEYS_KEYPACKAGES_QUERY_CLAIM: &'static str =
        "ak.peer.keys.keypackages.query.claim";
    pub const PEER_MLS_QUERY_GROUP_STATE_MATERIAL: &'static str =
        "ak.peer.mls.query.group_state_material";
    pub const PEER_SIGNAL_COMMAND_RELAY: &'static str = "ak.peer.signal.command.relay";
    pub const PEER_SNAPSHOT_QUERY_MANIFEST_HEAD: &'static str =
        "ak.peer.snapshot.query.manifest_head";
    pub const ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION: &'static str =
        "ak.root.identity.command.submit_did_operation";
    pub const ROOT_IDENTITY_DOCUMENT_RESOURCE_GET: &'static str =
        "ak.root.identity.document.resource.get";
    pub const ROOT_IDENTITY_LOG_QUERY_LIST: &'static str = "ak.root.identity.log.query.list";
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
    pub const ROOT_IDENTITY_QUERY_RESOLVE: &'static str = "ak.root.identity.query.resolve";
    pub const ROOT_IDENTITY_RECEIPTS_QUERY_LIST: &'static str =
        "ak.root.identity.receipts.query.list";
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
    pub const ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE: &'static str =
        "ak.root.identity.registry.query.describe";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE: &'static str =
        "ak.root.identity.service_registration.command.ensure";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET: &'static str =
        "ak.root.identity.service_registration.resource.get";
    pub const SELF_ACCOUNT_COMMAND_REVOKE_CURSOR: &'static str =
        "ak.self.account.command.revoke_cursor";
    pub const SELF_ACCOUNT_COMMAND_UPDATE_PROFILE: &'static str =
        "ak.self.account.command.update_profile";
    pub const SELF_ACCOUNT_QUERY_DESCRIBE: &'static str = "ak.self.account.query.describe";
    pub const SELF_ACCOUNT_QUERY_VIEWER: &'static str = "ak.self.account.query.viewer";
    pub const SELF_ACCOUNT_STREAM_SUBSCRIBE: &'static str = "ak.self.account.stream.subscribe";
    pub const SELF_ACCOUNT_DATA_QUERY_LIST: &'static str = "ak.self.account_data.query.list";
    pub const SELF_ACCOUNT_DATA_RESOURCE_DELETE: &'static str =
        "ak.self.account_data.resource.delete";
    pub const SELF_ACCOUNT_DATA_RESOURCE_GET: &'static str = "ak.self.account_data.resource.get";
    pub const SELF_ACCOUNT_DATA_RESOURCE_REPLACE: &'static str =
        "ak.self.account_data.resource.replace";
    pub const SELF_AGENT_COMMAND_DEACTIVATE: &'static str = "ak.self.agent.command.deactivate";
    pub const SELF_AGENT_COMMAND_PAUSE: &'static str = "ak.self.agent.command.pause";
    pub const SELF_AGENT_COMMAND_PROVISION: &'static str = "ak.self.agent.command.provision";
    pub const SELF_AGENT_COMMAND_RENEW_PAIRING: &'static str =
        "ak.self.agent.command.renew_pairing";
    pub const SELF_AGENT_COMMAND_RESUME: &'static str = "ak.self.agent.command.resume";
    pub const SELF_AGENT_GRANT_COMMAND_ATTACH: &'static str = "ak.self.agent.grant.command.attach";
    pub const SELF_AGENT_GRANT_RESOURCE_DELETE: &'static str =
        "ak.self.agent.grant.resource.delete";
    pub const SELF_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE: &'static str =
        "ak.self.agent.participation.query.prepare_scope_evidence";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_GET: &'static str =
        "ak.self.agent.participation.resource.get";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE: &'static str =
        "ak.self.agent.participation.resource.replace";
    pub const SELF_AGENT_QUERY_LIST: &'static str = "ak.self.agent.query.list";
    pub const SELF_AGENT_RESOURCE_GET: &'static str = "ak.self.agent.resource.get";
    pub const SELF_AGENT_SIDECAR_COMMAND_ENSURE: &'static str =
        "ak.self.agent.sidecar.command.ensure";
    pub const SELF_AGENT_SIDECAR_QUERY_LIST: &'static str = "ak.self.agent.sidecar.query.list";
    pub const SELF_AGENT_SIDECAR_RESOURCE_GET: &'static str = "ak.self.agent.sidecar.resource.get";
    pub const SELF_AGENT_SIGNER_EVIDENCE_QUERY_RESOLVE: &'static str =
        "ak.self.agent_signer_evidence.query.resolve";
    pub const SELF_APPLET_COMMAND_INSTALL: &'static str = "ak.self.applet.command.install";
    pub const SELF_APPLET_COMMAND_REVOKE: &'static str = "ak.self.applet.command.revoke";
    pub const SELF_APPLET_GHOST_COMMAND_PROVISION: &'static str =
        "ak.self.applet.ghost.command.provision";
    pub const SELF_APPLET_INSTALL_COMMAND_PREVIEW: &'static str =
        "ak.self.applet.install.command.preview";
    pub const SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE: &'static str =
        "ak.self.authorization_leases.command.issue";
    pub const SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE: &'static str =
        "ak.self.authz.grants.query.effective";
    pub const SELF_AUTHZ_INVITES_QUERY_LIST: &'static str = "ak.self.authz.invites.query.list";
    pub const SELF_AUTHZ_QUERY_CHECK: &'static str = "ak.self.authz.query.check";
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
    pub const SELF_CIRCLE_QUERY_LIST: &'static str = "ak.self.circle.query.list";
    pub const SELF_CIRCLE_RESOURCE_GET: &'static str = "ak.self.circle.resource.get";
    pub const SELF_CONSENT_COMMAND_GRANT: &'static str = "ak.self.consent.command.grant";
    pub const SELF_CONSENT_COMMAND_REQUEST: &'static str = "ak.self.consent.command.request";
    pub const SELF_CONSENT_COMMAND_REVOKE: &'static str = "ak.self.consent.command.revoke";
    pub const SELF_CONSENT_QUERY_LIST: &'static str = "ak.self.consent.query.list";
    pub const SELF_CONSENT_RESOURCE_GET: &'static str = "ak.self.consent.resource.get";
    pub const SELF_CONTACT_COMMAND_REJECT: &'static str = "ak.self.contact.command.reject";
    pub const SELF_CONTACT_COMMAND_REQUEST: &'static str = "ak.self.contact.command.request";
    pub const SELF_CONTACT_COMMAND_RESPOND: &'static str = "ak.self.contact.command.respond";
    pub const SELF_CONTACT_COMMAND_SCOPE_UPDATE: &'static str =
        "ak.self.contact.command.scope_update";
    pub const SELF_CONTACT_COMMAND_TOMBSTONE: &'static str = "ak.self.contact.command.tombstone";
    pub const SELF_CONTACT_QUERY_LIST: &'static str = "ak.self.contact.query.list";
    pub const SELF_CONTROL_PROPOSAL_RECEIPTS_COMMAND_ISSUE: &'static str =
        "ak.self.control_proposal_receipts.command.issue";
    pub const SELF_DEVICE_MESSAGES_COMMAND_ACK: &'static str =
        "ak.self.device_messages.command.ack";
    pub const SELF_DEVICE_MESSAGES_COMMAND_SEND: &'static str =
        "ak.self.device_messages.command.send";
    pub const SELF_DEVICE_MESSAGES_QUERY_LIST: &'static str = "ak.self.device_messages.query.list";
    pub const SELF_DIRECT_CONVERSATION_COMMAND_RESOLVE: &'static str =
        "ak.self.direct_conversation.command.resolve";
    pub const SELF_EVENTS_COMMAND_SUBMIT: &'static str = "ak.self.events.command.submit";
    pub const SELF_EVENTS_COMMAND_SUBMIT_SEAL: &'static str = "ak.self.events.command.submit_seal";
    pub const SELF_EVENTS_QUERY_DESCRIBE: &'static str = "ak.self.events.query.describe";
    pub const SELF_EVENTS_QUERY_FRONTIER: &'static str = "ak.self.events.query.frontier";
    pub const SELF_EVENTS_QUERY_MLS_GOVERNANCE_PROOF: &'static str =
        "ak.self.events.query.mls_governance_proof";
    pub const SELF_EVENTS_QUERY_RESOLVE: &'static str = "ak.self.events.query.resolve";
    pub const SELF_EVENTS_QUERY_SCAN: &'static str = "ak.self.events.query.scan";
    pub const SELF_EVENTS_QUERY_SCAN_BODY: &'static str = "ak.self.events.query.scan_body";
    pub const SELF_EVENTS_RESOURCE_GET: &'static str = "ak.self.events.resource.get";
    pub const SELF_EVENTS_STREAM_SUBSCRIBE: &'static str = "ak.self.events.stream.subscribe";
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
    pub const SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE: &'static str =
        "ak.self.keys.backup_series.command.erase";
    pub const SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE: &'static str =
        "ak.self.keys.backups.command.issue_delete_challenge";
    pub const SELF_KEYS_BACKUPS_COMMAND_UNLOCK: &'static str =
        "ak.self.keys.backups.command.unlock";
    pub const SELF_KEYS_BACKUPS_QUERY_LIST: &'static str = "ak.self.keys.backups.query.list";
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
    pub const SELF_KEYS_QUERY_LOOKUP: &'static str = "ak.self.keys.query.lookup";
    pub const SELF_KEYS_UPLOAD_CREATE: &'static str = "ak.self.keys.upload.create";
    pub const SELF_MEDIA_QUERY_ICE_CONFIG: &'static str = "ak.self.media.query.ice_config";
    pub const SELF_MODERATION_COMMAND_REPORT: &'static str = "ak.self.moderation.command.report";
    pub const SELF_MORPH_QUERY_LIST: &'static str = "ak.self.morph.query.list";
    pub const SELF_MORPH_RESOURCE_GET: &'static str = "ak.self.morph.resource.get";
    pub const SELF_POLICY_QUERY_CHECK: &'static str = "ak.self.policy.query.check";
    pub const SELF_READ_CURSOR_COMMAND_ADVANCE: &'static str =
        "ak.self.read_cursor.command.advance";
    pub const SELF_READ_CURSOR_QUERY_LIST: &'static str = "ak.self.read_cursor.query.list";
    pub const SELF_REALM_COMMAND_ARCHIVE: &'static str = "ak.self.realm.command.archive";
    pub const SELF_REALM_COMMAND_DESTROY: &'static str = "ak.self.realm.command.destroy";
    pub const SELF_REALM_COMMAND_FREEZE: &'static str = "ak.self.realm.command.freeze";
    pub const SELF_REALM_COMMAND_TOMBSTONE: &'static str = "ak.self.realm.command.tombstone";
    pub const SELF_REALM_JOIN_APPLICATION_AUDIT_QUERY_LIST: &'static str =
        "ak.self.realm.join_application.audit.query.list";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_CANCEL: &'static str =
        "ak.self.realm.join_application.command.cancel";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_REVIEW: &'static str =
        "ak.self.realm.join_application.command.review";
    pub const SELF_REALM_JOIN_APPLICATION_COMMAND_SUBMIT: &'static str =
        "ak.self.realm.join_application.command.submit";
    pub const SELF_REALM_JOIN_APPLICATION_QUERY_LIST: &'static str =
        "ak.self.realm.join_application.query.list";
    pub const SELF_REALM_JOIN_APPLICATION_RESOURCE_GET: &'static str =
        "ak.self.realm.join_application.resource.get";
    pub const SELF_REALM_MODERATION_POLICY_QUERY_EFFECTIVE: &'static str =
        "ak.self.realm.moderation_policy.query.effective";
    pub const SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE: &'static str =
        "ak.self.realm.moderation_policy.resource.replace";
    pub const SELF_REALM_QUERY_EXPORT: &'static str = "ak.self.realm.query.export";
    pub const SELF_REALM_RESOURCE_GET: &'static str = "ak.self.realm.resource.get";
    pub const SELF_REALM_LINK_COMMAND_CREATE: &'static str = "ak.self.realm_link.command.create";
    pub const SELF_REALM_LINK_QUERY_EFFECTIVE_POLICY: &'static str =
        "ak.self.realm_link.query.effective_policy";
    pub const SELF_REALM_LINK_QUERY_LIST: &'static str = "ak.self.realm_link.query.list";
    pub const SELF_REALM_LINK_RESOURCE_DELETE: &'static str = "ak.self.realm_link.resource.delete";
    pub const SELF_REALM_ORGANIZATION_QUERY_LIST: &'static str =
        "ak.self.realm_organization.query.list";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_DELETE: &'static str =
        "ak.self.realm_policy_server.resource.delete";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_GET: &'static str =
        "ak.self.realm_policy_server.resource.get";
    pub const SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE: &'static str =
        "ak.self.realm_policy_server.resource.replace";
    pub const SELF_RECOVERY_AUTHORITY_TICKET_COMMAND_ISSUE: &'static str =
        "ak.self.recovery_authority_ticket.command.issue";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE: &'static str =
        "ak.self.security_transaction.command.continue";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CREATE: &'static str =
        "ak.self.security_transaction.command.create";
    pub const SELF_SECURITY_TRANSACTION_RESOURCE_GET: &'static str =
        "ak.self.security_transaction.resource.get";
    pub const SELF_SIGNAL_COMMAND_SEND: &'static str = "ak.self.signal.command.send";
    pub const SELF_SIGNAL_STREAM_SUBSCRIBE: &'static str = "ak.self.signal.stream.subscribe";
    pub const SELF_SNAPSHOT_QUERY_MANIFEST_HEAD: &'static str =
        "ak.self.snapshot.query.manifest_head";
    pub const SELF_SPACE_QUERY_LIST: &'static str = "ak.self.space.query.list";
    pub const SELF_STRAND_QUERY_LIST: &'static str = "ak.self.strand.query.list";
    pub const SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE: &'static str =
        "ak.self.views.collection_projection.command.materialize";
    pub const SERVER_QUERY_DESCRIBE: &'static str = "ak.server.query.describe";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeAppletActorQueryResolve => Self::EDGE_APPLET_ACTOR_QUERY_RESOLVE,
            Self::EdgeAppletCommandTransaction => Self::EDGE_APPLET_COMMAND_TRANSACTION,
            Self::EdgeAppletQueryDescribe => Self::EDGE_APPLET_QUERY_DESCRIBE,
            Self::EdgeAppletQueryPing => Self::EDGE_APPLET_QUERY_PING,
            Self::EdgeAppletQueryProtocolMetadata => Self::EDGE_APPLET_QUERY_PROTOCOL_METADATA,
            Self::EdgeAppletRealmQueryResolve => Self::EDGE_APPLET_REALM_QUERY_RESOLVE,
            Self::EdgeAppletThirdPartyLocationsQueryList => {
                Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST
            }
            Self::EdgeAppletThirdPartyUsersQueryList => {
                Self::EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST
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
            Self::FindDirectoryQueryDescribe => Self::FIND_DIRECTORY_QUERY_DESCRIBE,
            Self::FindDirectoryQueryListHandlesForSubject => {
                Self::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT
            }
            Self::FindDirectoryQueryPrivateContactDiscovery => {
                Self::FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY
            }
            Self::FindDirectoryQueryResolveAgentSelector => {
                Self::FIND_DIRECTORY_QUERY_RESOLVE_AGENT_SELECTOR
            }
            Self::FindDirectoryQueryResolveHandle => Self::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE,
            Self::FindDirectoryQueryResolveOrganization => {
                Self::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION
            }
            Self::FindDirectoryQueryResolveRealm => Self::FIND_DIRECTORY_QUERY_RESOLVE_REALM,
            Self::FindDirectoryQueryResolveTarget => Self::FIND_DIRECTORY_QUERY_RESOLVE_TARGET,
            Self::FindDirectoryQuerySearchActors => Self::FIND_DIRECTORY_QUERY_SEARCH_ACTORS,
            Self::FindDirectoryQuerySearchOrganizations => {
                Self::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS
            }
            Self::FindDirectoryQuerySearchRealms => Self::FIND_DIRECTORY_QUERY_SEARCH_REALMS,
            Self::FindDirectoryQuerySearchUsers => Self::FIND_DIRECTORY_QUERY_SEARCH_USERS,
            Self::GateAccountCommandAuthorizeRecoveryDevice => {
                Self::GATE_ACCOUNT_COMMAND_AUTHORIZE_RECOVERY_DEVICE
            }
            Self::GateAccountCommandCancelDeviceBootstrap => {
                Self::GATE_ACCOUNT_COMMAND_CANCEL_DEVICE_BOOTSTRAP
            }
            Self::GateAccountCommandEnrollDevice => Self::GATE_ACCOUNT_COMMAND_ENROLL_DEVICE,
            Self::GateAccountCommandIntrospectSessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT
            }
            Self::GateAccountCommandIssueIdentityBindingChallenge => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE
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
            Self::GateAccountCommandPromoteRecoverySessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_PROMOTE_RECOVERY_SESSION_GRANT
            }
            Self::GateAccountCommandRefreshSessionGrant => {
                Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT
            }
            Self::GateAccountCommandRegister => Self::GATE_ACCOUNT_COMMAND_REGISTER,
            Self::GateAccountCommandRevokeSession => Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
            Self::GateAccountExchangeCompleteOidc => Self::GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC,
            Self::GateAccountExchangeCreateHandoff => Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF,
            Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest => {
                Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST
            }
            Self::OpenAgentPairingQueryResolve => Self::OPEN_AGENT_PAIRING_QUERY_RESOLVE,
            Self::OpenAgentPairingQueryRuntimeKeyRequestStatus => {
                Self::OPEN_AGENT_PAIRING_QUERY_RUNTIME_KEY_REQUEST_STATUS
            }
            Self::OpenDevicePairingCommandStage => Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE,
            Self::OpenDevicePairingQueryResolve => Self::OPEN_DEVICE_PAIRING_QUERY_RESOLVE,
            Self::OpenDevicePairingQueryStatus => Self::OPEN_DEVICE_PAIRING_QUERY_STATUS,
            Self::OpenInviteLocatorQueryResolve => Self::OPEN_INVITE_LOCATOR_QUERY_RESOLVE,
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
            Self::OpenMimiQueryGroupInfo => Self::OPEN_MIMI_QUERY_GROUP_INFO,
            Self::OpenMimiQueryIdentifiers => Self::OPEN_MIMI_QUERY_IDENTIFIERS,
            Self::OpenMimiQueryProviderDirectory => Self::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY,
            Self::PeerAccountStatusCommandSubmit => Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT,
            Self::PeerAccountStatusQueryAuthoringBasis => {
                Self::PEER_ACCOUNT_STATUS_QUERY_AUTHORING_BASIS
            }
            Self::PeerAgentParticipationCommandReplace => {
                Self::PEER_AGENT_PARTICIPATION_COMMAND_REPLACE
            }
            Self::PeerAgentParticipationQueryPrepareScopeEvidence => {
                Self::PEER_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE
            }
            Self::PeerContactsCommandSubmit => Self::PEER_CONTACTS_COMMAND_SUBMIT,
            Self::PeerDirectConversationOperationControlCommandDeliver => {
                Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_DELIVER
            }
            Self::PeerDirectConversationOperationControlCommandSubmit => {
                Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_SUBMIT
            }
            Self::PeerDirectConversationOperationControlQueryExecutionBundle => {
                Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_EXECUTION_BUNDLE
            }
            Self::PeerDirectConversationOperationControlQueryReadCertificate => {
                Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_READ_CERTIFICATE
            }
            Self::PeerEventsCommandSubmit => Self::PEER_EVENTS_COMMAND_SUBMIT,
            Self::PeerEventsQueryDescribe => Self::PEER_EVENTS_QUERY_DESCRIBE,
            Self::PeerEventsQueryFrontier => Self::PEER_EVENTS_QUERY_FRONTIER,
            Self::PeerEventsQueryResolve => Self::PEER_EVENTS_QUERY_RESOLVE,
            Self::PeerEventsQueryScan => Self::PEER_EVENTS_QUERY_SCAN,
            Self::PeerEventsQueryScanBody => Self::PEER_EVENTS_QUERY_SCAN_BODY,
            Self::PeerInvitesCommandSubmit => Self::PEER_INVITES_COMMAND_SUBMIT,
            Self::PeerKeysKeypackagesCommandClaim => Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM,
            Self::PeerKeysKeypackagesQueryClaim => Self::PEER_KEYS_KEYPACKAGES_QUERY_CLAIM,
            Self::PeerMlsQueryGroupStateMaterial => Self::PEER_MLS_QUERY_GROUP_STATE_MATERIAL,
            Self::PeerSignalCommandRelay => Self::PEER_SIGNAL_COMMAND_RELAY,
            Self::PeerSnapshotQueryManifestHead => Self::PEER_SNAPSHOT_QUERY_MANIFEST_HEAD,
            Self::RootIdentityCommandSubmitDidOperation => {
                Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION
            }
            Self::RootIdentityDocumentResourceGet => Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET,
            Self::RootIdentityLogQueryList => Self::ROOT_IDENTITY_LOG_QUERY_LIST,
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
            Self::RootIdentityQueryResolve => Self::ROOT_IDENTITY_QUERY_RESOLVE,
            Self::RootIdentityReceiptsQueryList => Self::ROOT_IDENTITY_RECEIPTS_QUERY_LIST,
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
            Self::RootIdentityRegistryQueryDescribe => Self::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE,
            Self::RootIdentityServiceRegistrationCommandEnsure => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE
            }
            Self::RootIdentityServiceRegistrationResourceGet => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET
            }
            Self::SelfAccountCommandRevokeCursor => Self::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR,
            Self::SelfAccountCommandUpdateProfile => Self::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE,
            Self::SelfAccountQueryDescribe => Self::SELF_ACCOUNT_QUERY_DESCRIBE,
            Self::SelfAccountQueryViewer => Self::SELF_ACCOUNT_QUERY_VIEWER,
            Self::SelfAccountStreamSubscribe => Self::SELF_ACCOUNT_STREAM_SUBSCRIBE,
            Self::SelfAccountDataQueryList => Self::SELF_ACCOUNT_DATA_QUERY_LIST,
            Self::SelfAccountDataResourceDelete => Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE,
            Self::SelfAccountDataResourceGet => Self::SELF_ACCOUNT_DATA_RESOURCE_GET,
            Self::SelfAccountDataResourceReplace => Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE,
            Self::SelfAgentCommandDeactivate => Self::SELF_AGENT_COMMAND_DEACTIVATE,
            Self::SelfAgentCommandPause => Self::SELF_AGENT_COMMAND_PAUSE,
            Self::SelfAgentCommandProvision => Self::SELF_AGENT_COMMAND_PROVISION,
            Self::SelfAgentCommandRenewPairing => Self::SELF_AGENT_COMMAND_RENEW_PAIRING,
            Self::SelfAgentCommandResume => Self::SELF_AGENT_COMMAND_RESUME,
            Self::SelfAgentGrantCommandAttach => Self::SELF_AGENT_GRANT_COMMAND_ATTACH,
            Self::SelfAgentGrantResourceDelete => Self::SELF_AGENT_GRANT_RESOURCE_DELETE,
            Self::SelfAgentParticipationQueryPrepareScopeEvidence => {
                Self::SELF_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE
            }
            Self::SelfAgentParticipationResourceGet => Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET,
            Self::SelfAgentParticipationResourceReplace => {
                Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE
            }
            Self::SelfAgentQueryList => Self::SELF_AGENT_QUERY_LIST,
            Self::SelfAgentResourceGet => Self::SELF_AGENT_RESOURCE_GET,
            Self::SelfAgentSidecarCommandEnsure => Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
            Self::SelfAgentSidecarQueryList => Self::SELF_AGENT_SIDECAR_QUERY_LIST,
            Self::SelfAgentSidecarResourceGet => Self::SELF_AGENT_SIDECAR_RESOURCE_GET,
            Self::SelfAgentSignerEvidenceQueryResolve => {
                Self::SELF_AGENT_SIGNER_EVIDENCE_QUERY_RESOLVE
            }
            Self::SelfAppletCommandInstall => Self::SELF_APPLET_COMMAND_INSTALL,
            Self::SelfAppletCommandRevoke => Self::SELF_APPLET_COMMAND_REVOKE,
            Self::SelfAppletGhostCommandProvision => Self::SELF_APPLET_GHOST_COMMAND_PROVISION,
            Self::SelfAppletInstallCommandPreview => Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW,
            Self::SelfAuthorizationLeasesCommandIssue => {
                Self::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE
            }
            Self::SelfAuthzGrantsQueryEffective => Self::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE,
            Self::SelfAuthzInvitesQueryList => Self::SELF_AUTHZ_INVITES_QUERY_LIST,
            Self::SelfAuthzQueryCheck => Self::SELF_AUTHZ_QUERY_CHECK,
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
            Self::SelfCircleQueryList => Self::SELF_CIRCLE_QUERY_LIST,
            Self::SelfCircleResourceGet => Self::SELF_CIRCLE_RESOURCE_GET,
            Self::SelfConsentCommandGrant => Self::SELF_CONSENT_COMMAND_GRANT,
            Self::SelfConsentCommandRequest => Self::SELF_CONSENT_COMMAND_REQUEST,
            Self::SelfConsentCommandRevoke => Self::SELF_CONSENT_COMMAND_REVOKE,
            Self::SelfConsentQueryList => Self::SELF_CONSENT_QUERY_LIST,
            Self::SelfConsentResourceGet => Self::SELF_CONSENT_RESOURCE_GET,
            Self::SelfContactCommandReject => Self::SELF_CONTACT_COMMAND_REJECT,
            Self::SelfContactCommandRequest => Self::SELF_CONTACT_COMMAND_REQUEST,
            Self::SelfContactCommandRespond => Self::SELF_CONTACT_COMMAND_RESPOND,
            Self::SelfContactCommandScopeUpdate => Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE,
            Self::SelfContactCommandTombstone => Self::SELF_CONTACT_COMMAND_TOMBSTONE,
            Self::SelfContactQueryList => Self::SELF_CONTACT_QUERY_LIST,
            Self::SelfControlProposalReceiptsCommandIssue => {
                Self::SELF_CONTROL_PROPOSAL_RECEIPTS_COMMAND_ISSUE
            }
            Self::SelfDeviceMessagesCommandAck => Self::SELF_DEVICE_MESSAGES_COMMAND_ACK,
            Self::SelfDeviceMessagesCommandSend => Self::SELF_DEVICE_MESSAGES_COMMAND_SEND,
            Self::SelfDeviceMessagesQueryList => Self::SELF_DEVICE_MESSAGES_QUERY_LIST,
            Self::SelfDirectConversationCommandResolve => {
                Self::SELF_DIRECT_CONVERSATION_COMMAND_RESOLVE
            }
            Self::SelfEventsCommandSubmit => Self::SELF_EVENTS_COMMAND_SUBMIT,
            Self::SelfEventsCommandSubmitSeal => Self::SELF_EVENTS_COMMAND_SUBMIT_SEAL,
            Self::SelfEventsQueryDescribe => Self::SELF_EVENTS_QUERY_DESCRIBE,
            Self::SelfEventsQueryFrontier => Self::SELF_EVENTS_QUERY_FRONTIER,
            Self::SelfEventsQueryMlsGovernanceProof => Self::SELF_EVENTS_QUERY_MLS_GOVERNANCE_PROOF,
            Self::SelfEventsQueryResolve => Self::SELF_EVENTS_QUERY_RESOLVE,
            Self::SelfEventsQueryScan => Self::SELF_EVENTS_QUERY_SCAN,
            Self::SelfEventsQueryScanBody => Self::SELF_EVENTS_QUERY_SCAN_BODY,
            Self::SelfEventsResourceGet => Self::SELF_EVENTS_RESOURCE_GET,
            Self::SelfEventsStreamSubscribe => Self::SELF_EVENTS_STREAM_SUBSCRIBE,
            Self::SelfInviteLocatorCommandIssue => Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE,
            Self::SelfInviteLocatorCommandRevoke => Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE,
            Self::SelfInviteLocatorCommandRotate => Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE,
            Self::SelfInviteReceivePolicyResourceGet => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET
            }
            Self::SelfInviteReceivePolicyResourceReplace => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE
            }
            Self::SelfKeysBackupSeriesCommandErase => Self::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE,
            Self::SelfKeysBackupsCommandIssueDeleteChallenge => {
                Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE
            }
            Self::SelfKeysBackupsCommandUnlock => Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK,
            Self::SelfKeysBackupsQueryList => Self::SELF_KEYS_BACKUPS_QUERY_LIST,
            Self::SelfKeysBackupsResourceDelete => Self::SELF_KEYS_BACKUPS_RESOURCE_DELETE,
            Self::SelfKeysBackupsResourceReplace => Self::SELF_KEYS_BACKUPS_RESOURCE_REPLACE,
            Self::SelfKeysCommandClaim => Self::SELF_KEYS_COMMAND_CLAIM,
            Self::SelfKeysKeypackagesCommandClaim => Self::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM,
            Self::SelfKeysKeypackagesCommandConsume => Self::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME,
            Self::SelfKeysKeypackagesCommandRevoke => Self::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE,
            Self::SelfKeysKeypackagesUploadCreate => Self::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE,
            Self::SelfKeysQueryLookup => Self::SELF_KEYS_QUERY_LOOKUP,
            Self::SelfKeysUploadCreate => Self::SELF_KEYS_UPLOAD_CREATE,
            Self::SelfMediaQueryIceConfig => Self::SELF_MEDIA_QUERY_ICE_CONFIG,
            Self::SelfModerationCommandReport => Self::SELF_MODERATION_COMMAND_REPORT,
            Self::SelfMorphQueryList => Self::SELF_MORPH_QUERY_LIST,
            Self::SelfMorphResourceGet => Self::SELF_MORPH_RESOURCE_GET,
            Self::SelfPolicyQueryCheck => Self::SELF_POLICY_QUERY_CHECK,
            Self::SelfReadCursorCommandAdvance => Self::SELF_READ_CURSOR_COMMAND_ADVANCE,
            Self::SelfReadCursorQueryList => Self::SELF_READ_CURSOR_QUERY_LIST,
            Self::SelfRealmCommandArchive => Self::SELF_REALM_COMMAND_ARCHIVE,
            Self::SelfRealmCommandDestroy => Self::SELF_REALM_COMMAND_DESTROY,
            Self::SelfRealmCommandFreeze => Self::SELF_REALM_COMMAND_FREEZE,
            Self::SelfRealmCommandTombstone => Self::SELF_REALM_COMMAND_TOMBSTONE,
            Self::SelfRealmJoinApplicationAuditQueryList => {
                Self::SELF_REALM_JOIN_APPLICATION_AUDIT_QUERY_LIST
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
            Self::SelfRealmJoinApplicationQueryList => Self::SELF_REALM_JOIN_APPLICATION_QUERY_LIST,
            Self::SelfRealmJoinApplicationResourceGet => {
                Self::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET
            }
            Self::SelfRealmModerationPolicyQueryEffective => {
                Self::SELF_REALM_MODERATION_POLICY_QUERY_EFFECTIVE
            }
            Self::SelfRealmModerationPolicyResourceReplace => {
                Self::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE
            }
            Self::SelfRealmQueryExport => Self::SELF_REALM_QUERY_EXPORT,
            Self::SelfRealmResourceGet => Self::SELF_REALM_RESOURCE_GET,
            Self::SelfRealmLinkCommandCreate => Self::SELF_REALM_LINK_COMMAND_CREATE,
            Self::SelfRealmLinkQueryEffectivePolicy => Self::SELF_REALM_LINK_QUERY_EFFECTIVE_POLICY,
            Self::SelfRealmLinkQueryList => Self::SELF_REALM_LINK_QUERY_LIST,
            Self::SelfRealmLinkResourceDelete => Self::SELF_REALM_LINK_RESOURCE_DELETE,
            Self::SelfRealmOrganizationQueryList => Self::SELF_REALM_ORGANIZATION_QUERY_LIST,
            Self::SelfRealmPolicyServerResourceDelete => {
                Self::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE
            }
            Self::SelfRealmPolicyServerResourceGet => Self::SELF_REALM_POLICY_SERVER_RESOURCE_GET,
            Self::SelfRealmPolicyServerResourceReplace => {
                Self::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE
            }
            Self::SelfRecoveryAuthorityTicketCommandIssue => {
                Self::SELF_RECOVERY_AUTHORITY_TICKET_COMMAND_ISSUE
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
            Self::SelfSnapshotQueryManifestHead => Self::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD,
            Self::SelfSpaceQueryList => Self::SELF_SPACE_QUERY_LIST,
            Self::SelfStrandQueryList => Self::SELF_STRAND_QUERY_LIST,
            Self::SelfViewsCollectionProjectionCommandMaterialize => {
                Self::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE
            }
            Self::ServerQueryDescribe => Self::SERVER_QUERY_DESCRIBE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::EDGE_APPLET_ACTOR_QUERY_RESOLVE => Some(Self::EdgeAppletActorQueryResolve),
            Self::EDGE_APPLET_COMMAND_TRANSACTION => Some(Self::EdgeAppletCommandTransaction),
            Self::EDGE_APPLET_QUERY_DESCRIBE => Some(Self::EdgeAppletQueryDescribe),
            Self::EDGE_APPLET_QUERY_PING => Some(Self::EdgeAppletQueryPing),
            Self::EDGE_APPLET_QUERY_PROTOCOL_METADATA => {
                Some(Self::EdgeAppletQueryProtocolMetadata)
            }
            Self::EDGE_APPLET_REALM_QUERY_RESOLVE => Some(Self::EdgeAppletRealmQueryResolve),
            Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST => {
                Some(Self::EdgeAppletThirdPartyLocationsQueryList)
            }
            Self::EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST => {
                Some(Self::EdgeAppletThirdPartyUsersQueryList)
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
            Self::FIND_DIRECTORY_QUERY_DESCRIBE => Some(Self::FindDirectoryQueryDescribe),
            Self::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT => {
                Some(Self::FindDirectoryQueryListHandlesForSubject)
            }
            Self::FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY => {
                Some(Self::FindDirectoryQueryPrivateContactDiscovery)
            }
            Self::FIND_DIRECTORY_QUERY_RESOLVE_AGENT_SELECTOR => {
                Some(Self::FindDirectoryQueryResolveAgentSelector)
            }
            Self::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE => {
                Some(Self::FindDirectoryQueryResolveHandle)
            }
            Self::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION => {
                Some(Self::FindDirectoryQueryResolveOrganization)
            }
            Self::FIND_DIRECTORY_QUERY_RESOLVE_REALM => Some(Self::FindDirectoryQueryResolveRealm),
            Self::FIND_DIRECTORY_QUERY_RESOLVE_TARGET => {
                Some(Self::FindDirectoryQueryResolveTarget)
            }
            Self::FIND_DIRECTORY_QUERY_SEARCH_ACTORS => Some(Self::FindDirectoryQuerySearchActors),
            Self::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS => {
                Some(Self::FindDirectoryQuerySearchOrganizations)
            }
            Self::FIND_DIRECTORY_QUERY_SEARCH_REALMS => Some(Self::FindDirectoryQuerySearchRealms),
            Self::FIND_DIRECTORY_QUERY_SEARCH_USERS => Some(Self::FindDirectoryQuerySearchUsers),
            Self::GATE_ACCOUNT_COMMAND_AUTHORIZE_RECOVERY_DEVICE => {
                Some(Self::GateAccountCommandAuthorizeRecoveryDevice)
            }
            Self::GATE_ACCOUNT_COMMAND_CANCEL_DEVICE_BOOTSTRAP => {
                Some(Self::GateAccountCommandCancelDeviceBootstrap)
            }
            Self::GATE_ACCOUNT_COMMAND_ENROLL_DEVICE => Some(Self::GateAccountCommandEnrollDevice),
            Self::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT => {
                Some(Self::GateAccountCommandIntrospectSessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE => {
                Some(Self::GateAccountCommandIssueIdentityBindingChallenge)
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
            Self::GATE_ACCOUNT_COMMAND_PROMOTE_RECOVERY_SESSION_GRANT => {
                Some(Self::GateAccountCommandPromoteRecoverySessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT => {
                Some(Self::GateAccountCommandRefreshSessionGrant)
            }
            Self::GATE_ACCOUNT_COMMAND_REGISTER => Some(Self::GateAccountCommandRegister),
            Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION => {
                Some(Self::GateAccountCommandRevokeSession)
            }
            Self::GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC => {
                Some(Self::GateAccountExchangeCompleteOidc)
            }
            Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF => {
                Some(Self::GateAccountExchangeCreateHandoff)
            }
            Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST => {
                Some(Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest)
            }
            Self::OPEN_AGENT_PAIRING_QUERY_RESOLVE => Some(Self::OpenAgentPairingQueryResolve),
            Self::OPEN_AGENT_PAIRING_QUERY_RUNTIME_KEY_REQUEST_STATUS => {
                Some(Self::OpenAgentPairingQueryRuntimeKeyRequestStatus)
            }
            Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE => Some(Self::OpenDevicePairingCommandStage),
            Self::OPEN_DEVICE_PAIRING_QUERY_RESOLVE => Some(Self::OpenDevicePairingQueryResolve),
            Self::OPEN_DEVICE_PAIRING_QUERY_STATUS => Some(Self::OpenDevicePairingQueryStatus),
            Self::OPEN_INVITE_LOCATOR_QUERY_RESOLVE => Some(Self::OpenInviteLocatorQueryResolve),
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
            Self::OPEN_MIMI_QUERY_GROUP_INFO => Some(Self::OpenMimiQueryGroupInfo),
            Self::OPEN_MIMI_QUERY_IDENTIFIERS => Some(Self::OpenMimiQueryIdentifiers),
            Self::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY => Some(Self::OpenMimiQueryProviderDirectory),
            Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT => Some(Self::PeerAccountStatusCommandSubmit),
            Self::PEER_ACCOUNT_STATUS_QUERY_AUTHORING_BASIS => {
                Some(Self::PeerAccountStatusQueryAuthoringBasis)
            }
            Self::PEER_AGENT_PARTICIPATION_COMMAND_REPLACE => {
                Some(Self::PeerAgentParticipationCommandReplace)
            }
            Self::PEER_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE => {
                Some(Self::PeerAgentParticipationQueryPrepareScopeEvidence)
            }
            Self::PEER_CONTACTS_COMMAND_SUBMIT => Some(Self::PeerContactsCommandSubmit),
            Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_DELIVER => {
                Some(Self::PeerDirectConversationOperationControlCommandDeliver)
            }
            Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_COMMAND_SUBMIT => {
                Some(Self::PeerDirectConversationOperationControlCommandSubmit)
            }
            Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_EXECUTION_BUNDLE => {
                Some(Self::PeerDirectConversationOperationControlQueryExecutionBundle)
            }
            Self::PEER_DIRECT_CONVERSATION_OPERATION_CONTROL_QUERY_READ_CERTIFICATE => {
                Some(Self::PeerDirectConversationOperationControlQueryReadCertificate)
            }
            Self::PEER_EVENTS_COMMAND_SUBMIT => Some(Self::PeerEventsCommandSubmit),
            Self::PEER_EVENTS_QUERY_DESCRIBE => Some(Self::PeerEventsQueryDescribe),
            Self::PEER_EVENTS_QUERY_FRONTIER => Some(Self::PeerEventsQueryFrontier),
            Self::PEER_EVENTS_QUERY_RESOLVE => Some(Self::PeerEventsQueryResolve),
            Self::PEER_EVENTS_QUERY_SCAN => Some(Self::PeerEventsQueryScan),
            Self::PEER_EVENTS_QUERY_SCAN_BODY => Some(Self::PeerEventsQueryScanBody),
            Self::PEER_INVITES_COMMAND_SUBMIT => Some(Self::PeerInvitesCommandSubmit),
            Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM => {
                Some(Self::PeerKeysKeypackagesCommandClaim)
            }
            Self::PEER_KEYS_KEYPACKAGES_QUERY_CLAIM => Some(Self::PeerKeysKeypackagesQueryClaim),
            Self::PEER_MLS_QUERY_GROUP_STATE_MATERIAL => Some(Self::PeerMlsQueryGroupStateMaterial),
            Self::PEER_SIGNAL_COMMAND_RELAY => Some(Self::PeerSignalCommandRelay),
            Self::PEER_SNAPSHOT_QUERY_MANIFEST_HEAD => Some(Self::PeerSnapshotQueryManifestHead),
            Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION => {
                Some(Self::RootIdentityCommandSubmitDidOperation)
            }
            Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET => {
                Some(Self::RootIdentityDocumentResourceGet)
            }
            Self::ROOT_IDENTITY_LOG_QUERY_LIST => Some(Self::RootIdentityLogQueryList),
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
            Self::ROOT_IDENTITY_QUERY_RESOLVE => Some(Self::RootIdentityQueryResolve),
            Self::ROOT_IDENTITY_RECEIPTS_QUERY_LIST => Some(Self::RootIdentityReceiptsQueryList),
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
            Self::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE => {
                Some(Self::RootIdentityRegistryQueryDescribe)
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
            Self::SELF_ACCOUNT_QUERY_DESCRIBE => Some(Self::SelfAccountQueryDescribe),
            Self::SELF_ACCOUNT_QUERY_VIEWER => Some(Self::SelfAccountQueryViewer),
            Self::SELF_ACCOUNT_STREAM_SUBSCRIBE => Some(Self::SelfAccountStreamSubscribe),
            Self::SELF_ACCOUNT_DATA_QUERY_LIST => Some(Self::SelfAccountDataQueryList),
            Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE => Some(Self::SelfAccountDataResourceDelete),
            Self::SELF_ACCOUNT_DATA_RESOURCE_GET => Some(Self::SelfAccountDataResourceGet),
            Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE => Some(Self::SelfAccountDataResourceReplace),
            Self::SELF_AGENT_COMMAND_DEACTIVATE => Some(Self::SelfAgentCommandDeactivate),
            Self::SELF_AGENT_COMMAND_PAUSE => Some(Self::SelfAgentCommandPause),
            Self::SELF_AGENT_COMMAND_PROVISION => Some(Self::SelfAgentCommandProvision),
            Self::SELF_AGENT_COMMAND_RENEW_PAIRING => Some(Self::SelfAgentCommandRenewPairing),
            Self::SELF_AGENT_COMMAND_RESUME => Some(Self::SelfAgentCommandResume),
            Self::SELF_AGENT_GRANT_COMMAND_ATTACH => Some(Self::SelfAgentGrantCommandAttach),
            Self::SELF_AGENT_GRANT_RESOURCE_DELETE => Some(Self::SelfAgentGrantResourceDelete),
            Self::SELF_AGENT_PARTICIPATION_QUERY_PREPARE_SCOPE_EVIDENCE => {
                Some(Self::SelfAgentParticipationQueryPrepareScopeEvidence)
            }
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET => {
                Some(Self::SelfAgentParticipationResourceGet)
            }
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE => {
                Some(Self::SelfAgentParticipationResourceReplace)
            }
            Self::SELF_AGENT_QUERY_LIST => Some(Self::SelfAgentQueryList),
            Self::SELF_AGENT_RESOURCE_GET => Some(Self::SelfAgentResourceGet),
            Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE => Some(Self::SelfAgentSidecarCommandEnsure),
            Self::SELF_AGENT_SIDECAR_QUERY_LIST => Some(Self::SelfAgentSidecarQueryList),
            Self::SELF_AGENT_SIDECAR_RESOURCE_GET => Some(Self::SelfAgentSidecarResourceGet),
            Self::SELF_AGENT_SIGNER_EVIDENCE_QUERY_RESOLVE => {
                Some(Self::SelfAgentSignerEvidenceQueryResolve)
            }
            Self::SELF_APPLET_COMMAND_INSTALL => Some(Self::SelfAppletCommandInstall),
            Self::SELF_APPLET_COMMAND_REVOKE => Some(Self::SelfAppletCommandRevoke),
            Self::SELF_APPLET_GHOST_COMMAND_PROVISION => {
                Some(Self::SelfAppletGhostCommandProvision)
            }
            Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW => {
                Some(Self::SelfAppletInstallCommandPreview)
            }
            Self::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE => {
                Some(Self::SelfAuthorizationLeasesCommandIssue)
            }
            Self::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE => Some(Self::SelfAuthzGrantsQueryEffective),
            Self::SELF_AUTHZ_INVITES_QUERY_LIST => Some(Self::SelfAuthzInvitesQueryList),
            Self::SELF_AUTHZ_QUERY_CHECK => Some(Self::SelfAuthzQueryCheck),
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
            Self::SELF_CIRCLE_QUERY_LIST => Some(Self::SelfCircleQueryList),
            Self::SELF_CIRCLE_RESOURCE_GET => Some(Self::SelfCircleResourceGet),
            Self::SELF_CONSENT_COMMAND_GRANT => Some(Self::SelfConsentCommandGrant),
            Self::SELF_CONSENT_COMMAND_REQUEST => Some(Self::SelfConsentCommandRequest),
            Self::SELF_CONSENT_COMMAND_REVOKE => Some(Self::SelfConsentCommandRevoke),
            Self::SELF_CONSENT_QUERY_LIST => Some(Self::SelfConsentQueryList),
            Self::SELF_CONSENT_RESOURCE_GET => Some(Self::SelfConsentResourceGet),
            Self::SELF_CONTACT_COMMAND_REJECT => Some(Self::SelfContactCommandReject),
            Self::SELF_CONTACT_COMMAND_REQUEST => Some(Self::SelfContactCommandRequest),
            Self::SELF_CONTACT_COMMAND_RESPOND => Some(Self::SelfContactCommandRespond),
            Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE => Some(Self::SelfContactCommandScopeUpdate),
            Self::SELF_CONTACT_COMMAND_TOMBSTONE => Some(Self::SelfContactCommandTombstone),
            Self::SELF_CONTACT_QUERY_LIST => Some(Self::SelfContactQueryList),
            Self::SELF_CONTROL_PROPOSAL_RECEIPTS_COMMAND_ISSUE => {
                Some(Self::SelfControlProposalReceiptsCommandIssue)
            }
            Self::SELF_DEVICE_MESSAGES_COMMAND_ACK => Some(Self::SelfDeviceMessagesCommandAck),
            Self::SELF_DEVICE_MESSAGES_COMMAND_SEND => Some(Self::SelfDeviceMessagesCommandSend),
            Self::SELF_DEVICE_MESSAGES_QUERY_LIST => Some(Self::SelfDeviceMessagesQueryList),
            Self::SELF_DIRECT_CONVERSATION_COMMAND_RESOLVE => {
                Some(Self::SelfDirectConversationCommandResolve)
            }
            Self::SELF_EVENTS_COMMAND_SUBMIT => Some(Self::SelfEventsCommandSubmit),
            Self::SELF_EVENTS_COMMAND_SUBMIT_SEAL => Some(Self::SelfEventsCommandSubmitSeal),
            Self::SELF_EVENTS_QUERY_DESCRIBE => Some(Self::SelfEventsQueryDescribe),
            Self::SELF_EVENTS_QUERY_FRONTIER => Some(Self::SelfEventsQueryFrontier),
            Self::SELF_EVENTS_QUERY_MLS_GOVERNANCE_PROOF => {
                Some(Self::SelfEventsQueryMlsGovernanceProof)
            }
            Self::SELF_EVENTS_QUERY_RESOLVE => Some(Self::SelfEventsQueryResolve),
            Self::SELF_EVENTS_QUERY_SCAN => Some(Self::SelfEventsQueryScan),
            Self::SELF_EVENTS_QUERY_SCAN_BODY => Some(Self::SelfEventsQueryScanBody),
            Self::SELF_EVENTS_RESOURCE_GET => Some(Self::SelfEventsResourceGet),
            Self::SELF_EVENTS_STREAM_SUBSCRIBE => Some(Self::SelfEventsStreamSubscribe),
            Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE => Some(Self::SelfInviteLocatorCommandIssue),
            Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE => Some(Self::SelfInviteLocatorCommandRevoke),
            Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE => Some(Self::SelfInviteLocatorCommandRotate),
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET => {
                Some(Self::SelfInviteReceivePolicyResourceGet)
            }
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE => {
                Some(Self::SelfInviteReceivePolicyResourceReplace)
            }
            Self::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE => {
                Some(Self::SelfKeysBackupSeriesCommandErase)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE => {
                Some(Self::SelfKeysBackupsCommandIssueDeleteChallenge)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK => Some(Self::SelfKeysBackupsCommandUnlock),
            Self::SELF_KEYS_BACKUPS_QUERY_LIST => Some(Self::SelfKeysBackupsQueryList),
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
            Self::SELF_KEYS_QUERY_LOOKUP => Some(Self::SelfKeysQueryLookup),
            Self::SELF_KEYS_UPLOAD_CREATE => Some(Self::SelfKeysUploadCreate),
            Self::SELF_MEDIA_QUERY_ICE_CONFIG => Some(Self::SelfMediaQueryIceConfig),
            Self::SELF_MODERATION_COMMAND_REPORT => Some(Self::SelfModerationCommandReport),
            Self::SELF_MORPH_QUERY_LIST => Some(Self::SelfMorphQueryList),
            Self::SELF_MORPH_RESOURCE_GET => Some(Self::SelfMorphResourceGet),
            Self::SELF_POLICY_QUERY_CHECK => Some(Self::SelfPolicyQueryCheck),
            Self::SELF_READ_CURSOR_COMMAND_ADVANCE => Some(Self::SelfReadCursorCommandAdvance),
            Self::SELF_READ_CURSOR_QUERY_LIST => Some(Self::SelfReadCursorQueryList),
            Self::SELF_REALM_COMMAND_ARCHIVE => Some(Self::SelfRealmCommandArchive),
            Self::SELF_REALM_COMMAND_DESTROY => Some(Self::SelfRealmCommandDestroy),
            Self::SELF_REALM_COMMAND_FREEZE => Some(Self::SelfRealmCommandFreeze),
            Self::SELF_REALM_COMMAND_TOMBSTONE => Some(Self::SelfRealmCommandTombstone),
            Self::SELF_REALM_JOIN_APPLICATION_AUDIT_QUERY_LIST => {
                Some(Self::SelfRealmJoinApplicationAuditQueryList)
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
            Self::SELF_REALM_JOIN_APPLICATION_QUERY_LIST => {
                Some(Self::SelfRealmJoinApplicationQueryList)
            }
            Self::SELF_REALM_JOIN_APPLICATION_RESOURCE_GET => {
                Some(Self::SelfRealmJoinApplicationResourceGet)
            }
            Self::SELF_REALM_MODERATION_POLICY_QUERY_EFFECTIVE => {
                Some(Self::SelfRealmModerationPolicyQueryEffective)
            }
            Self::SELF_REALM_MODERATION_POLICY_RESOURCE_REPLACE => {
                Some(Self::SelfRealmModerationPolicyResourceReplace)
            }
            Self::SELF_REALM_QUERY_EXPORT => Some(Self::SelfRealmQueryExport),
            Self::SELF_REALM_RESOURCE_GET => Some(Self::SelfRealmResourceGet),
            Self::SELF_REALM_LINK_COMMAND_CREATE => Some(Self::SelfRealmLinkCommandCreate),
            Self::SELF_REALM_LINK_QUERY_EFFECTIVE_POLICY => {
                Some(Self::SelfRealmLinkQueryEffectivePolicy)
            }
            Self::SELF_REALM_LINK_QUERY_LIST => Some(Self::SelfRealmLinkQueryList),
            Self::SELF_REALM_LINK_RESOURCE_DELETE => Some(Self::SelfRealmLinkResourceDelete),
            Self::SELF_REALM_ORGANIZATION_QUERY_LIST => Some(Self::SelfRealmOrganizationQueryList),
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_DELETE => {
                Some(Self::SelfRealmPolicyServerResourceDelete)
            }
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_GET => {
                Some(Self::SelfRealmPolicyServerResourceGet)
            }
            Self::SELF_REALM_POLICY_SERVER_RESOURCE_REPLACE => {
                Some(Self::SelfRealmPolicyServerResourceReplace)
            }
            Self::SELF_RECOVERY_AUTHORITY_TICKET_COMMAND_ISSUE => {
                Some(Self::SelfRecoveryAuthorityTicketCommandIssue)
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
            Self::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD => Some(Self::SelfSnapshotQueryManifestHead),
            Self::SELF_SPACE_QUERY_LIST => Some(Self::SelfSpaceQueryList),
            Self::SELF_STRAND_QUERY_LIST => Some(Self::SelfStrandQueryList),
            Self::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE => {
                Some(Self::SelfViewsCollectionProjectionCommandMaterialize)
            }
            Self::SERVER_QUERY_DESCRIBE => Some(Self::ServerQueryDescribe),
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
        id: ServiceOperationId::EdgeAppletActorQueryResolve,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletQueryDescribe,
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
        id: ServiceOperationId::EdgeAppletQueryPing,
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
        id: ServiceOperationId::EdgeAppletQueryProtocolMetadata,
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
        id: ServiceOperationId::EdgeAppletRealmQueryResolve,
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
        id: ServiceOperationId::EdgeAppletThirdPartyLocationsQueryList,
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
        id: ServiceOperationId::EdgeAppletThirdPartyUsersQueryList,
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
            "{\"operation_id\":\"ak.find.directory.query.resolve_target\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryDescribe,
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
        id: ServiceOperationId::FindDirectoryQueryListHandlesForSubject,
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
        id: ServiceOperationId::FindDirectoryQueryPrivateContactDiscovery,
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
        id: ServiceOperationId::FindDirectoryQueryResolveAgentSelector,
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
        id: ServiceOperationId::FindDirectoryQueryResolveHandle,
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
        id: ServiceOperationId::FindDirectoryQueryResolveOrganization,
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
        id: ServiceOperationId::FindDirectoryQueryResolveRealm,
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
        id: ServiceOperationId::FindDirectoryQueryResolveTarget,
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
        id: ServiceOperationId::FindDirectoryQuerySearchActors,
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
        id: ServiceOperationId::FindDirectoryQuerySearchOrganizations,
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
        id: ServiceOperationId::FindDirectoryQuerySearchRealms,
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
        id: ServiceOperationId::FindDirectoryQuerySearchUsers,
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
        id: ServiceOperationId::GateAccountCommandAuthorizeRecoveryDevice,
        http_method: "POST",
        http_path: "/_arkret/gate/account/recovery-device-authorizations",
        grpc: Some("GateAccount/AuthorizeRecoveryDevice"),
        mq: Some("gate.account.command.authorize_recovery_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/authorize_recovery_device_request",
        ),
        response_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/authorize_recovery_device_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("returns_signed_event_material_without_committing_it"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandCancelDeviceBootstrap,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-bootstrap/cancel",
        grpc: Some("GateAccount/CancelDeviceBootstrap"),
        mq: Some("gate.account.command.cancel_device_bootstrap"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/cancel_device_bootstrap_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/cancel_device_bootstrap_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_bootstrap_transaction_terminal_or_replay_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandEnrollDevice,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-enroll",
        grpc: Some("GateAccount/DeviceEnroll"),
        mq: Some("gate.account.command.enroll_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_enroll_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_enroll_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_byte_stable_signed_enrollment_outcome_without_committing_the_event",
            ),
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
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.issue_session_grant\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "{\"operation_id\":\"ak.self.account.query.viewer\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPromoteRecoverySessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/recovery-session-grants/promote",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/promote_recovery_session_grant_request",
        ),
        response_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/promote_recovery_session_grant_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRefreshRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRefreshOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.issue_session_grant\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/session_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/session_revoke_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.introspect_session_grant\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountExchangeCompleteOidc,
        http_method: "POST",
        http_path: "/_arkret/gate/account/oidc/callback",
        grpc: Some("GateAccount/OidcCallback"),
        mq: Some("gate.account.exchange.complete_oidc"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountOidcCallbackRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountOidcCallbackOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingQueryResolve,
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
        id: ServiceOperationId::OpenAgentPairingQueryRuntimeKeyRequestStatus,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenDevicePairingQueryResolve,
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
        id: ServiceOperationId::OpenDevicePairingQueryStatus,
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
        id: ServiceOperationId::OpenInviteLocatorQueryResolve,
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
            "{\"operation_id\":\"ak.self.consent.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "{\"operation_id\":\"ak.open.mimi.query.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "{\"operation_id\":\"ak.open.mimi.query.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "{\"operation_id\":\"ak.open.mimi.query.group_info\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiQueryGroupInfo,
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
        id: ServiceOperationId::OpenMimiQueryIdentifiers,
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
        id: ServiceOperationId::OpenMimiQueryProviderDirectory,
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
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.account.status"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAccountStatusQueryAuthoringBasis,
        http_method: "POST",
        http_path: "/_arkret/peer/account-status/authoring-basis",
        grpc: Some("PeerAccountStatus/AuthoringBasis"),
        mq: Some("peer.account_status.query.authoring_basis"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_authoring_basis_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_status_authoring_basis_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAgentParticipationCommandReplace,
        http_method: "POST",
        http_path: "/_arkret/peer/agents/participation:replace",
        grpc: Some("PeerAgent/ParticipationReplace"),
        mq: Some("peer.agent.participation.command.replace"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_replace_relay_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_replace_receipt",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("transparent_signed_batch_relay"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAgentParticipationQueryPrepareScopeEvidence,
        http_method: "POST",
        http_path: "/_arkret/peer/agents/participation/scope-evidence:prepare",
        grpc: Some("PeerAgent/ParticipationScopeEvidencePrepare"),
        mq: Some("peer.agent.participation.query.prepare_scope_evidence"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_scope_evidence_prepare_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_scope_evidence_challenge",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("transparent_private_challenge_relay"),
        }),
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
            "schemas/protocol-journey-wire.schema.json#/$defs/peer_contact_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/peer_contact_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("delivers_existing_signed_fact_without_committing_a_local_event"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDirectConversationOperationControlCommandDeliver,
        http_method: "POST",
        http_path: "/_arkret/peer/direct-conversation-operation-control/execution-bundles",
        grpc: Some("PeerDirectConversationOperationControl/DeliverExecutionBundle"),
        mq: Some("peer.direct_conversation.operation_control.command.deliver"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/execution_bundle_delivery_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/execution_bundle_delivery_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("certified_external_effect_and_destination_ledger_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDirectConversationOperationControlCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/direct-conversation-operation-control/messages",
        grpc: Some("PeerDirectConversationOperationControl/Submit"),
        mq: Some("peer.direct_conversation.operation_control.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/operation_control_message_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/operation_control_message_receipt",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("authenticated_replica_protocol_log_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDirectConversationOperationControlQueryExecutionBundle,
        http_method: "POST",
        http_path: "/_arkret/peer/direct-conversation-operation-control/execution-bundles/query",
        grpc: Some("PeerDirectConversationOperationControl/QueryExecutionBundle"),
        mq: Some("peer.direct_conversation.operation_control.query.execution_bundle"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/execution_bundle_query_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/execution_bundle_query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("read_only_exact_execution_bundle_or_delivery_receipt_lookup"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerDirectConversationOperationControlQueryReadCertificate,
        http_method: "POST",
        http_path: "/_arkret/peer/direct-conversation-operation-control/read-certificates/query",
        grpc: Some("PeerDirectConversationOperationControl/ReadCertificate"),
        mq: Some("peer.direct_conversation.operation_control.query.read_certificate"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/operation_control_read_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/operation_control_read_certificate",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("read_only_fresh_quorum_certificate_assembly"),
        }),
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
            target: Some(DurableEventTarget::Dynamic("$request.events[*].event.kind")),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/peer/events/describe",
        grpc: Some("PeerEvents/Describe"),
        mq: Some("peer.events.query.scan.describe"),
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
        id: ServiceOperationId::PeerEventsQueryFrontier,
        http_method: "GET",
        http_path: "/_arkret/peer/events/frontier",
        grpc: Some("PeerEvents/Frontier"),
        mq: Some("peer.events.query.scan.frontier"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierFederationPeerState",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/peer/events/resolve",
        grpc: Some("PeerEvents/Resolve"),
        mq: Some("peer.events.query.scan.resolve"),
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
        id: ServiceOperationId::PeerEventsQueryScan,
        http_method: "GET",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Query"),
        mq: Some("peer.events.query.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryScanBody,
        http_method: "POST",
        http_path: "/_arkret/peer/events/query",
        grpc: None,
        mq: None,
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
            "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.peer.keys.keypackages.query.claim\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesQueryClaim,
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
            "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_query_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerMlsQueryGroupStateMaterial,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerSnapshotQueryManifestHead,
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
        id: ServiceOperationId::RootIdentityLogQueryList,
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
        id: ServiceOperationId::RootIdentityQueryResolve,
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
        id: ServiceOperationId::RootIdentityReceiptsQueryList,
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
        id: ServiceOperationId::RootIdentityRegistryQueryDescribe,
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
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_update_profile_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-operations.schema.json#/$defs/account_update_profile_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.account.query.viewer\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.profile.update"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountQueryDescribe,
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
        id: ServiceOperationId::SelfAccountQueryViewer,
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
        id: ServiceOperationId::SelfAccountDataQueryList,
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
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_delete_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::ActorPrivateEvent,
            target: Some(DurableEventTarget::Static(&["ak.account_data.set"])),
            rationale: None,
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
            "{\"operation_id\":\"ak.self.authz.grants.query.effective\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.capability.grant"])),
            rationale: None,
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
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_detach_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.capability.revoke"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationQueryPrepareScopeEvidence,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/participation/scope-evidence:prepare",
        grpc: Some("SelfAgent/ParticipationScopeEvidencePrepare"),
        mq: Some("self.agent.participation.query.prepare_scope_evidence"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_scope_evidence_prepare_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_scope_evidence_challenge",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("private_target_challenge_reservation_only"),
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
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_replacement_batch",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/participation_replace_receipt",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.capability.grant",
                "ak.capability.revoke",
            ])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentQueryList,
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
            "schemas/protocol-journey-wire.schema.json#/$defs/sidecar_ensure_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/sidecar_ensure_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&[
                "ak.sidecar.create",
                "ak.sidecar.context.attach",
            ])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarQueryList,
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
        id: ServiceOperationId::SelfAgentSignerEvidenceQueryResolve,
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
            "schemas/service-operation-dtos.schema.json#/$defs/AuthorizationLeaseIssueRequest",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AuthorizationLeaseIssueOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("pre_admission_only_no_event_commit"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzGrantsQueryEffective,
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
        id: ServiceOperationId::SelfAuthzInvitesQueryList,
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
        id: ServiceOperationId::SelfAuthzQueryCheck,
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
            "schemas/circle-operations.schema.json#/$defs/circle_lifecycle_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.archive"])),
            rationale: None,
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
            "{\"operation_id\":\"ak.self.circle.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.create"])),
            rationale: None,
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
            "schemas/circle-operations.schema.json#/$defs/circle_lifecycle_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.restore"])),
            rationale: None,
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
            "schemas/circle-operations.schema.json#/$defs/circle_lifecycle_request_body",
        ),
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.circle.resource.get\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.tombstone"])),
            rationale: None,
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
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.member.state"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleQueryList,
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
        http_path: "/_arkret/self/consent/cells/{holder_did}/grant",
        grpc: Some("SelfConsent/Grant"),
        mq: Some("self.consent.command.grant"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_update_request_body",
        ),
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.grant"])),
            rationale: None,
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
            "{\"operation_id\":\"ak.self.consent.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/consent/cells/{holder_did}/revoke",
        grpc: Some("SelfConsent/Revoke"),
        mq: Some("self.consent.command.revoke"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_update_request_body",
        ),
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.revoke"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentQueryList,
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
        http_path: "/_arkret/self/consent/cells/{holder_did}",
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
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_reject_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_reject_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.rejected"])),
            rationale: None,
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
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_operation_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_request_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.requested"])),
            rationale: None,
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
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_respond_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_respond_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.accepted"])),
            rationale: None,
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
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_scope_update_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_scope_update_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.scope.update"])),
            rationale: None,
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
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_tombstone_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/contact_tombstone_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.contact.tombstoned"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactQueryList,
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
        id: ServiceOperationId::SelfControlProposalReceiptsCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/control-proposal-receipts",
        grpc: Some("SelfControlProposalReceipts/Issue"),
        mq: Some("self.control_proposal_receipts.command.issue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/proposal_receipt_issue_request",
        ),
        response_schema_ref: Some(
            "schemas/control-proposal-decision.schema.json#/$defs/proposal_receipt_issue_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("pre_admission_receipt_only_no_event_commit"),
        }),
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesQueryList,
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
        id: ServiceOperationId::SelfDirectConversationCommandResolve,
        http_method: "POST",
        http_path: "/_arkret/self/direct-conversations/resolve",
        grpc: Some("SelfDirectConversation/Resolve"),
        mq: Some("self.direct_conversation.command.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/direct_conversation_resolve_request",
        ),
        response_schema_ref: Some(
            "schemas/protocol-journey-wire.schema.json#/$defs/direct_conversation_resolve_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "the_service_persists_only_the_coordinator_operation_record_and_returns_participant_authoring_material_or_an_existing_projection",
            ),
        }),
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
            "schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::DynamicMany(&[
                "$request.event.kind",
                "$request.events[*].event.kind",
            ])),
            rationale: None,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/self/events/describe",
        grpc: Some("SelfEvents/Describe"),
        mq: Some("self.events.query.scan.describe"),
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
        id: ServiceOperationId::SelfEventsQueryFrontier,
        http_method: "GET",
        http_path: "/_arkret/self/events/frontier",
        grpc: Some("SelfEvents/Frontier"),
        mq: Some("self.events.query.scan.frontier"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierState",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryMlsGovernanceProof,
        http_method: "POST",
        http_path: "/_arkret/self/events/mls-governance-proof",
        grpc: Some("SelfEvents/MlsGovernanceProof"),
        mq: Some("self.events.query.mls_governance_proof"),
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
        id: ServiceOperationId::SelfEventsQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/self/events/resolve",
        grpc: Some("SelfEvents/Resolve"),
        mq: Some("self.events.query.scan.resolve"),
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
        id: ServiceOperationId::SelfEventsQueryScan,
        http_method: "GET",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Query"),
        mq: Some("self.events.query.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryScanBody,
        http_method: "POST",
        http_path: "/_arkret/self/events/query",
        grpc: None,
        mq: None,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsQueryList,
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
            "{\"operation_id\":\"ak.self.keys.query.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_claim_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_consume_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_consume_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.query.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_revoke_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_revoke_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.query.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_upload_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_upload_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.keypackages.upload.create\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysQueryLookup,
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
            "{\"operation_id\":\"ak.self.keys.query.lookup\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMediaQueryIceConfig,
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
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/moderation-report.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ModerationReportOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.moderation.report"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMorphQueryList,
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
        id: ServiceOperationId::SelfPolicyQueryCheck,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfReadCursorQueryList,
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
        request_schema_ref: Some("schemas/event-payload.schema.json#/$defs/realm_archive_payload"),
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
        request_schema_ref: Some("schemas/event-payload.schema.json#/$defs/realm_destroy_payload"),
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
        request_schema_ref: Some("schemas/event-payload.schema.json#/$defs/realm_freeze_payload"),
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
            "schemas/event-payload.schema.json#/$defs/realm_tombstone_payload",
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationAuditQueryList,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationQueryList,
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
        id: ServiceOperationId::SelfRealmModerationPolicyQueryEffective,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmQueryExport,
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
            "{\"operation_id\":\"ak.self.realm_link.query.list\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.link"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkQueryEffectivePolicy,
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
        id: ServiceOperationId::SelfRealmLinkQueryList,
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
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_mutation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.link"])),
            rationale: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmOrganizationQueryList,
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
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.realm.policy_server"])),
            rationale: None,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRecoveryAuthorityTicketCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/recovery-authority-tickets",
        grpc: Some("SelfRecoveryAuthorityTickets/Issue"),
        mq: Some("self.recovery_authority_ticket.command.issue"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-authority.schema.json#/$defs/ticket_issue_request",
        ),
        response_schema_ref: Some("schemas/recovery-authority.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
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
        id: ServiceOperationId::SelfSnapshotQueryManifestHead,
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
        id: ServiceOperationId::SelfSpaceQueryList,
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
        id: ServiceOperationId::SelfStrandQueryList,
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
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::ServerQueryDescribe,
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
