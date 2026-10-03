//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-10-03.1;
//! sha256=d673f74f21d473a3bc1b5c3cef310f92d81ccbc60b74143e267dcedfa596518d Entries: registered=211

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ServiceOperationId {
    EdgeAppletActorReadResolveV1,
    EdgeAppletClientCommandExchangeV1,
    EdgeAppletCommandTransactionV1,
    EdgeAppletManagedActorCommandAuthorV1,
    EdgeAppletReadDescribeV1,
    EdgeAppletReadPingV1,
    EdgeAppletReadProtocolMetadataV1,
    EdgeAppletRealmReadResolveV1,
    EdgeAppletThirdPartyLocationsReadListV1,
    EdgeAppletThirdPartyUsersReadListV1,
    EdgePushCommandApplyRegistrationV1,
    EdgePushCommandNotifyV1,
    EdgePushCommandRegisterDeviceV1,
    EdgePushCommandUnregisterDeviceV1,
    FindDirectoryReadDescribeV1,
    FindDirectoryReadResolveRealmV1,
    FindDirectoryReadSearchRealmsV1,
    GateAccountCommandAbandonIdentityCreationV1,
    GateAccountCommandFinalizeDevicePairingV1,
    GateAccountCommandIssueDidBindingChallengeV1,
    GateAccountCommandIssueIdentityBindingChallengeV1,
    GateAccountCommandIssueRecoveryCompletionGrantV1,
    GateAccountCommandIssueSessionGrantV1,
    GateAccountCommandLogoutV1,
    GateAccountCommandPairAgentKeyV1,
    GateAccountCommandPairDeviceV1,
    GateAccountCommandRefreshSessionGrantV1,
    GateAccountCommandRegisterV1,
    GateAccountCommandRequestErasureV1,
    GateAccountCommandRevokeSessionV1,
    GateAccountExchangeCreateHandoffV1,
    GateAccountReadClaimDevicePairingCodeV1,
    GateAccountReadOnboardingV1,
    OpenAgentPairingCommandSubmitRuntimeKeyRequestV1,
    OpenAgentPairingReadResolveV1,
    OpenAgentPairingReadRuntimeKeyRequestStatusV1,
    OpenDevicePairingCommandStageV1,
    OpenDevicePairingReadResolveV1,
    OpenDevicePairingReadStatusV1,
    OpenIdentityReadResolutionV1,
    OpenInviteLocatorReadResolveV1,
    OpenMimiCommandNotifyV1,
    OpenMimiCommandProxyDownloadV1,
    OpenMimiCommandReportAbuseV1,
    OpenMimiCommandRequestConsentV1,
    OpenMimiCommandSubmitMessageV1,
    OpenMimiCommandUpdateConsentV1,
    OpenMimiCommandUpdateRoomV1,
    OpenMimiExchangeRequestKeyMaterialV1,
    OpenMimiReadIdentifiersV1,
    OpenMimiReadProviderDirectoryV1,
    OpenRealmAuthorityReadBundleV1,
    OpenServiceReadResolutionV1,
    OpenThirdPartyInviteCommandActivateV1,
    OpenThirdPartyInviteCommandPresentTokenV1,
    OpenThirdPartyInviteCommandProvisionV1,
    OpenThirdPartyInviteReadProvisioningStatusV1,
    PeerAccountStatusCommandSubmitV1,
    PeerAccountStatusReadResolveV1,
    PeerCommittedEventReadScanV1,
    PeerContactsCommandSubmitV1,
    PeerErasureReceiptCommandSubmitV1,
    PeerErasureReceiptResourceGetV1,
    PeerEventsCommandSubmitV1,
    PeerInvitesCommandSubmitV1,
    PeerKeysKeypackagesCommandClaimV1,
    PeerKeysKeypackagesReadClaimV1,
    PeerKeysReadLookupV1,
    PeerMlsCommandAttestAddV1,
    PeerMlsReadGroupStateMaterialV1,
    PeerMlsReadRosterAuthorityV1,
    PeerRealmAuthorityCommandHandoffV1,
    PeerRealmJoinReadBootstrapV1,
    PeerRealmJoinReadPreviewV1,
    PeerSignalCommandRelayV1,
    RootIdentityCommandSubmitDidOperationV1,
    RootIdentityDocumentResourceGetV1,
    RootIdentityLogReadListV1,
    RootIdentityOrganizationRegistrationCommandEnsureV1,
    RootIdentityOrganizationRegistrationCommandPrepareV1,
    RootIdentityOrganizationRegistrationCommandRefreshV1,
    RootIdentityOrganizationRegistrationCommandRevokeV1,
    RootIdentityOrganizationRegistrationResourceGetV1,
    RootIdentityReadResolveV1,
    RootIdentityReceiptsReadListV1,
    RootIdentityRecoveryPolicyCommandPublishV1,
    RootIdentityRecoveryPolicyResourceGetV1,
    RootIdentityRecoverySessionCommandCreateV1,
    RootIdentityRecoverySessionCommandSubmitProofV1,
    RootIdentityRecoverySessionResourceGetV1,
    RootIdentityRegistryReadDescribeV1,
    RootIdentityServiceRegistrationCommandEnsureV1,
    RootIdentityServiceRegistrationResourceGetV1,
    SelfAccountCommandRevokeCursorV1,
    SelfAccountCommandUpdateProfileV1,
    SelfAccountReadDescribeV1,
    SelfAccountReadViewerV1,
    SelfAccountStreamSubscribeV1,
    SelfAccountDataReadListV1,
    SelfAccountDataResourceDeleteV1,
    SelfAccountDataResourceGetV1,
    SelfAccountDataResourceReplaceV1,
    SelfActorPrivateEventsCommandSubmitV1,
    SelfActorProfileReadResolveV1,
    SelfAgentCommandDeactivateV1,
    SelfAgentCommandPauseV1,
    SelfAgentCommandProvisionV1,
    SelfAgentCommandRenewPairingV1,
    SelfAgentCommandResumeV1,
    SelfAgentParticipationResourceGetV1,
    SelfAgentParticipationResourceReplaceV1,
    SelfAgentReadListV1,
    SelfAgentResourceGetV1,
    SelfAgentSidecarCommandEnsureV1,
    SelfAgentSidecarReadListV1,
    SelfAgentSidecarResourceGetV1,
    SelfAppletCommandInstallV1,
    SelfAppletCommandRevokeV1,
    SelfAppletGhostCommandPreviewV1,
    SelfAppletGhostCommandProvisionV1,
    SelfAppletInstallCommandCancelV1,
    SelfAppletInstallCommandPreviewV1,
    SelfAppletRevokeCommandPreviewV1,
    SelfAuthzGrantsReadEffectiveV1,
    SelfAuthzInvitesReadListV1,
    SelfAuthzReadCheckV1,
    SelfBlobCommandPresignV1,
    SelfBlobResourceGetV1,
    SelfBlobResourceHeadV1,
    SelfBlobUploadCreateV1,
    SelfCallMediaExchangeIssueTokenV1,
    SelfCircleCommandCreateV1,
    SelfCircleCommandRotateScopeV1,
    SelfCircleMemberCommandAddV1,
    SelfCircleMemberResourceDeleteV1,
    SelfCircleReadListV1,
    SelfCircleResourceGetV1,
    SelfCommittedEventReadScanV1,
    SelfCommittedEventResourceGetV1,
    SelfCommittedEventStreamSubscribeV1,
    SelfConsentCommandGrantV1,
    SelfConsentCommandRequestV1,
    SelfConsentCommandRevokeV1,
    SelfConsentReadListV1,
    SelfConsentResourceGetV1,
    SelfContactCommandCheckpointV1,
    SelfContactCommandRejectV1,
    SelfContactCommandRequestV1,
    SelfContactCommandRespondV1,
    SelfContactCommandScopeUpdateV1,
    SelfContactCommandTombstoneV1,
    SelfContactReadListV1,
    SelfCurrentPrincipalReadResolveV1,
    SelfCurrentResultsReadExactV1,
    SelfDeviceMessagesCommandAckV1,
    SelfDeviceMessagesCommandSendV1,
    SelfDeviceMessagesReadListV1,
    SelfDirectConversationReadResolveV1,
    SelfEventsCommandSubmitV1,
    SelfEventsReadDeliveryStatusV1,
    SelfIdentityReadResolutionAuditV1,
    SelfInviteLocatorCommandIssueV1,
    SelfInviteLocatorCommandRevokeV1,
    SelfInviteLocatorCommandRotateV1,
    SelfInviteReceivePolicyResourceGetV1,
    SelfInviteReceivePolicyResourceReplaceV1,
    SelfInvitesCommandDispatchV1,
    SelfKeysBackupsCommandIssueDeleteChallengeV1,
    SelfKeysBackupsCommandIssueUnlockChallengeV1,
    SelfKeysBackupsCommandUnlockV1,
    SelfKeysBackupsReadListV1,
    SelfKeysBackupsResourceDeleteV1,
    SelfKeysBackupsResourceReplaceV1,
    SelfKeysCommandClaimV1,
    SelfKeysKeypackagesCommandClaimV1,
    SelfKeysKeypackagesCommandConsumeV1,
    SelfKeysKeypackagesCommandRevokeV1,
    SelfKeysKeypackagesReadClaimV1,
    SelfKeysKeypackagesUploadCreateV1,
    SelfKeysReadLookupV1,
    SelfKeysUploadCreateV1,
    SelfMediaReadIceConfigV1,
    SelfMediaServiceBindingReadResolveV1,
    SelfMessagesCommandPrepareV1,
    SelfMlsReadGroupStateMaterialV1,
    SelfMlsReadRosterAuthorityV1,
    SelfModerationCommandReportV1,
    SelfMorphReadListV1,
    SelfMorphResourceGetV1,
    SelfReadCursorCommandAdvanceV1,
    SelfReadCursorReadListV1,
    SelfRealmReadExportV1,
    SelfRealmReadStreamsV1,
    SelfRealmResourceGetV1,
    SelfRealmJoinCommandPrepareV1,
    SelfRealmJoinReadPreviewV1,
    SelfRealmLinkReadListV1,
    SelfRealmOrganizationReadListV1,
    SelfRealmStateSnapshotReadByRefV1,
    SelfRealmStateSnapshotReadManifestHeadV1,
    SelfSecurityTransactionCommandContinueV1,
    SelfSecurityTransactionCommandCreateV1,
    SelfSecurityTransactionResourceGetV1,
    SelfSignalCommandSendV1,
    SelfSignalStreamSubscribeV1,
    SelfSignerKeysReadResolveV1,
    SelfSpaceReadListV1,
    SelfStrandReadListV1,
    SelfStrandWatchReadCurrentV1,
    SelfThirdPartyInviteReadAcceptanceAttestationV1,
    ServerReadDescribeV1,
}

pub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[
    ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE_V1,
    ServiceOperationId::EDGE_APPLET_CLIENT_COMMAND_EXCHANGE_V1,
    ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
    ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
    ServiceOperationId::EDGE_APPLET_READ_DESCRIBE_V1,
    ServiceOperationId::EDGE_APPLET_READ_PING_V1,
    ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA_V1,
    ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE_V1,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1,
    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1,
    ServiceOperationId::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1,
    ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
    ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1,
    ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE_V1,
    ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE_V1,
    ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
    ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_FINALIZE_DEVICE_PAIRING_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE_V1,
    ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION_V1,
    ServiceOperationId::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF_V1,
    ServiceOperationId::GATE_ACCOUNT_READ_CLAIM_DEVICE_PAIRING_CODE_V1,
    ServiceOperationId::GATE_ACCOUNT_READ_ONBOARDING_V1,
    ServiceOperationId::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST_V1,
    ServiceOperationId::OPEN_AGENT_PAIRING_READ_RESOLVE_V1,
    ServiceOperationId::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS_V1,
    ServiceOperationId::OPEN_DEVICE_PAIRING_COMMAND_STAGE_V1,
    ServiceOperationId::OPEN_DEVICE_PAIRING_READ_RESOLVE_V1,
    ServiceOperationId::OPEN_DEVICE_PAIRING_READ_STATUS_V1,
    ServiceOperationId::OPEN_IDENTITY_READ_RESOLUTION_V1,
    ServiceOperationId::OPEN_INVITE_LOCATOR_READ_RESOLVE_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1,
    ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM_V1,
    ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1,
    ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
    ServiceOperationId::OPEN_MIMI_READ_PROVIDER_DIRECTORY_V1,
    ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
    ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
    ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1,
    ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1,
    ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1,
    ServiceOperationId::OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1,
    ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
    ServiceOperationId::PEER_ACCOUNT_STATUS_READ_RESOLVE_V1,
    ServiceOperationId::PEER_COMMITTED_EVENT_READ_SCAN_V1,
    ServiceOperationId::PEER_CONTACTS_COMMAND_SUBMIT_V1,
    ServiceOperationId::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1,
    ServiceOperationId::PEER_ERASURE_RECEIPT_RESOURCE_GET_V1,
    ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
    ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT_V1,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
    ServiceOperationId::PEER_KEYS_KEYPACKAGES_READ_CLAIM_V1,
    ServiceOperationId::PEER_KEYS_READ_LOOKUP_V1,
    ServiceOperationId::PEER_MLS_COMMAND_ATTEST_ADD_V1,
    ServiceOperationId::PEER_MLS_READ_GROUP_STATE_MATERIAL_V1,
    ServiceOperationId::PEER_MLS_READ_ROSTER_AUTHORITY_V1,
    ServiceOperationId::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1,
    ServiceOperationId::PEER_REALM_JOIN_READ_BOOTSTRAP_V1,
    ServiceOperationId::PEER_REALM_JOIN_READ_PREVIEW_V1,
    ServiceOperationId::PEER_SIGNAL_COMMAND_RELAY_V1,
    ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1,
    ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET_V1,
    ServiceOperationId::ROOT_IDENTITY_LOG_READ_LIST_V1,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE_V1,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE_V1,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH_V1,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE_V1,
    ServiceOperationId::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET_V1,
    ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE_V1,
    ServiceOperationId::ROOT_IDENTITY_RECEIPTS_READ_LIST_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1,
    ServiceOperationId::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE_V1,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1,
    ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET_V1,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1,
    ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
    ServiceOperationId::SELF_ACCOUNT_READ_DESCRIBE_V1,
    ServiceOperationId::SELF_ACCOUNT_READ_VIEWER_V1,
    ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
    ServiceOperationId::SELF_ACCOUNT_DATA_READ_LIST_V1,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET_V1,
    ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
    ServiceOperationId::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1,
    ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
    ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE_V1,
    ServiceOperationId::SELF_AGENT_COMMAND_PAUSE_V1,
    ServiceOperationId::SELF_AGENT_COMMAND_PROVISION_V1,
    ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING_V1,
    ServiceOperationId::SELF_AGENT_COMMAND_RESUME_V1,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_GET_V1,
    ServiceOperationId::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1,
    ServiceOperationId::SELF_AGENT_READ_LIST_V1,
    ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1,
    ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
    ServiceOperationId::SELF_AGENT_SIDECAR_READ_LIST_V1,
    ServiceOperationId::SELF_AGENT_SIDECAR_RESOURCE_GET_V1,
    ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
    ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
    ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_CANCEL_V1,
    ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
    ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
    ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1,
    ServiceOperationId::SELF_AUTHZ_INVITES_READ_LIST_V1,
    ServiceOperationId::SELF_AUTHZ_READ_CHECK_V1,
    ServiceOperationId::SELF_BLOB_COMMAND_PRESIGN_V1,
    ServiceOperationId::SELF_BLOB_RESOURCE_GET_V1,
    ServiceOperationId::SELF_BLOB_RESOURCE_HEAD_V1,
    ServiceOperationId::SELF_BLOB_UPLOAD_CREATE_V1,
    ServiceOperationId::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1,
    ServiceOperationId::SELF_CIRCLE_COMMAND_CREATE_V1,
    ServiceOperationId::SELF_CIRCLE_COMMAND_ROTATE_SCOPE_V1,
    ServiceOperationId::SELF_CIRCLE_MEMBER_COMMAND_ADD_V1,
    ServiceOperationId::SELF_CIRCLE_MEMBER_RESOURCE_DELETE_V1,
    ServiceOperationId::SELF_CIRCLE_READ_LIST_V1,
    ServiceOperationId::SELF_CIRCLE_RESOURCE_GET_V1,
    ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
    ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
    ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
    ServiceOperationId::SELF_CONSENT_COMMAND_GRANT_V1,
    ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST_V1,
    ServiceOperationId::SELF_CONSENT_COMMAND_REVOKE_V1,
    ServiceOperationId::SELF_CONSENT_READ_LIST_V1,
    ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_CHECKPOINT_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_REJECT_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_REQUEST_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_RESPOND_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_SCOPE_UPDATE_V1,
    ServiceOperationId::SELF_CONTACT_COMMAND_TOMBSTONE_V1,
    ServiceOperationId::SELF_CONTACT_READ_LIST_V1,
    ServiceOperationId::SELF_CURRENT_PRINCIPAL_READ_RESOLVE_V1,
    ServiceOperationId::SELF_CURRENT_RESULTS_READ_EXACT_V1,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
    ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1,
    ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
    ServiceOperationId::SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
    ServiceOperationId::SELF_IDENTITY_READ_RESOLUTION_AUDIT_V1,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ISSUE_V1,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_REVOKE_V1,
    ServiceOperationId::SELF_INVITE_LOCATOR_COMMAND_ROTATE_V1,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
    ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1,
    ServiceOperationId::SELF_INVITES_COMMAND_DISPATCH_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_ISSUE_UNLOCK_CHALLENGE_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
    ServiceOperationId::SELF_KEYS_COMMAND_CLAIM_V1,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
    ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
    ServiceOperationId::SELF_KEYS_READ_LOOKUP_V1,
    ServiceOperationId::SELF_KEYS_UPLOAD_CREATE_V1,
    ServiceOperationId::SELF_MEDIA_READ_ICE_CONFIG_V1,
    ServiceOperationId::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1,
    ServiceOperationId::SELF_MESSAGES_COMMAND_PREPARE_V1,
    ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
    ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
    ServiceOperationId::SELF_MODERATION_COMMAND_REPORT_V1,
    ServiceOperationId::SELF_MORPH_READ_LIST_V1,
    ServiceOperationId::SELF_MORPH_RESOURCE_GET_V1,
    ServiceOperationId::SELF_READ_CURSOR_COMMAND_ADVANCE_V1,
    ServiceOperationId::SELF_READ_CURSOR_READ_LIST_V1,
    ServiceOperationId::SELF_REALM_READ_EXPORT_V1,
    ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
    ServiceOperationId::SELF_REALM_RESOURCE_GET_V1,
    ServiceOperationId::SELF_REALM_JOIN_COMMAND_PREPARE_V1,
    ServiceOperationId::SELF_REALM_JOIN_READ_PREVIEW_V1,
    ServiceOperationId::SELF_REALM_LINK_READ_LIST_V1,
    ServiceOperationId::SELF_REALM_ORGANIZATION_READ_LIST_V1,
    ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1,
    ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1,
    ServiceOperationId::SELF_SIGNAL_COMMAND_SEND_V1,
    ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE_V1,
    ServiceOperationId::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
    ServiceOperationId::SELF_SPACE_READ_LIST_V1,
    ServiceOperationId::SELF_STRAND_READ_LIST_V1,
    ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
    ServiceOperationId::SELF_THIRD_PARTY_INVITE_READ_ACCEPTANCE_ATTESTATION_V1,
    ServiceOperationId::SERVER_READ_DESCRIBE_V1,
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
        Self::EdgeAppletActorReadResolveV1,
        Self::EdgeAppletClientCommandExchangeV1,
        Self::EdgeAppletCommandTransactionV1,
        Self::EdgeAppletManagedActorCommandAuthorV1,
        Self::EdgeAppletReadDescribeV1,
        Self::EdgeAppletReadPingV1,
        Self::EdgeAppletReadProtocolMetadataV1,
        Self::EdgeAppletRealmReadResolveV1,
        Self::EdgeAppletThirdPartyLocationsReadListV1,
        Self::EdgeAppletThirdPartyUsersReadListV1,
        Self::EdgePushCommandApplyRegistrationV1,
        Self::EdgePushCommandNotifyV1,
        Self::EdgePushCommandRegisterDeviceV1,
        Self::EdgePushCommandUnregisterDeviceV1,
        Self::FindDirectoryReadDescribeV1,
        Self::FindDirectoryReadResolveRealmV1,
        Self::FindDirectoryReadSearchRealmsV1,
        Self::GateAccountCommandAbandonIdentityCreationV1,
        Self::GateAccountCommandFinalizeDevicePairingV1,
        Self::GateAccountCommandIssueDidBindingChallengeV1,
        Self::GateAccountCommandIssueIdentityBindingChallengeV1,
        Self::GateAccountCommandIssueRecoveryCompletionGrantV1,
        Self::GateAccountCommandIssueSessionGrantV1,
        Self::GateAccountCommandLogoutV1,
        Self::GateAccountCommandPairAgentKeyV1,
        Self::GateAccountCommandPairDeviceV1,
        Self::GateAccountCommandRefreshSessionGrantV1,
        Self::GateAccountCommandRegisterV1,
        Self::GateAccountCommandRequestErasureV1,
        Self::GateAccountCommandRevokeSessionV1,
        Self::GateAccountExchangeCreateHandoffV1,
        Self::GateAccountReadClaimDevicePairingCodeV1,
        Self::GateAccountReadOnboardingV1,
        Self::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1,
        Self::OpenAgentPairingReadResolveV1,
        Self::OpenAgentPairingReadRuntimeKeyRequestStatusV1,
        Self::OpenDevicePairingCommandStageV1,
        Self::OpenDevicePairingReadResolveV1,
        Self::OpenDevicePairingReadStatusV1,
        Self::OpenIdentityReadResolutionV1,
        Self::OpenInviteLocatorReadResolveV1,
        Self::OpenMimiCommandNotifyV1,
        Self::OpenMimiCommandProxyDownloadV1,
        Self::OpenMimiCommandReportAbuseV1,
        Self::OpenMimiCommandRequestConsentV1,
        Self::OpenMimiCommandSubmitMessageV1,
        Self::OpenMimiCommandUpdateConsentV1,
        Self::OpenMimiCommandUpdateRoomV1,
        Self::OpenMimiExchangeRequestKeyMaterialV1,
        Self::OpenMimiReadIdentifiersV1,
        Self::OpenMimiReadProviderDirectoryV1,
        Self::OpenRealmAuthorityReadBundleV1,
        Self::OpenServiceReadResolutionV1,
        Self::OpenThirdPartyInviteCommandActivateV1,
        Self::OpenThirdPartyInviteCommandPresentTokenV1,
        Self::OpenThirdPartyInviteCommandProvisionV1,
        Self::OpenThirdPartyInviteReadProvisioningStatusV1,
        Self::PeerAccountStatusCommandSubmitV1,
        Self::PeerAccountStatusReadResolveV1,
        Self::PeerCommittedEventReadScanV1,
        Self::PeerContactsCommandSubmitV1,
        Self::PeerErasureReceiptCommandSubmitV1,
        Self::PeerErasureReceiptResourceGetV1,
        Self::PeerEventsCommandSubmitV1,
        Self::PeerInvitesCommandSubmitV1,
        Self::PeerKeysKeypackagesCommandClaimV1,
        Self::PeerKeysKeypackagesReadClaimV1,
        Self::PeerKeysReadLookupV1,
        Self::PeerMlsCommandAttestAddV1,
        Self::PeerMlsReadGroupStateMaterialV1,
        Self::PeerMlsReadRosterAuthorityV1,
        Self::PeerRealmAuthorityCommandHandoffV1,
        Self::PeerRealmJoinReadBootstrapV1,
        Self::PeerRealmJoinReadPreviewV1,
        Self::PeerSignalCommandRelayV1,
        Self::RootIdentityCommandSubmitDidOperationV1,
        Self::RootIdentityDocumentResourceGetV1,
        Self::RootIdentityLogReadListV1,
        Self::RootIdentityOrganizationRegistrationCommandEnsureV1,
        Self::RootIdentityOrganizationRegistrationCommandPrepareV1,
        Self::RootIdentityOrganizationRegistrationCommandRefreshV1,
        Self::RootIdentityOrganizationRegistrationCommandRevokeV1,
        Self::RootIdentityOrganizationRegistrationResourceGetV1,
        Self::RootIdentityReadResolveV1,
        Self::RootIdentityReceiptsReadListV1,
        Self::RootIdentityRecoveryPolicyCommandPublishV1,
        Self::RootIdentityRecoveryPolicyResourceGetV1,
        Self::RootIdentityRecoverySessionCommandCreateV1,
        Self::RootIdentityRecoverySessionCommandSubmitProofV1,
        Self::RootIdentityRecoverySessionResourceGetV1,
        Self::RootIdentityRegistryReadDescribeV1,
        Self::RootIdentityServiceRegistrationCommandEnsureV1,
        Self::RootIdentityServiceRegistrationResourceGetV1,
        Self::SelfAccountCommandRevokeCursorV1,
        Self::SelfAccountCommandUpdateProfileV1,
        Self::SelfAccountReadDescribeV1,
        Self::SelfAccountReadViewerV1,
        Self::SelfAccountStreamSubscribeV1,
        Self::SelfAccountDataReadListV1,
        Self::SelfAccountDataResourceDeleteV1,
        Self::SelfAccountDataResourceGetV1,
        Self::SelfAccountDataResourceReplaceV1,
        Self::SelfActorPrivateEventsCommandSubmitV1,
        Self::SelfActorProfileReadResolveV1,
        Self::SelfAgentCommandDeactivateV1,
        Self::SelfAgentCommandPauseV1,
        Self::SelfAgentCommandProvisionV1,
        Self::SelfAgentCommandRenewPairingV1,
        Self::SelfAgentCommandResumeV1,
        Self::SelfAgentParticipationResourceGetV1,
        Self::SelfAgentParticipationResourceReplaceV1,
        Self::SelfAgentReadListV1,
        Self::SelfAgentResourceGetV1,
        Self::SelfAgentSidecarCommandEnsureV1,
        Self::SelfAgentSidecarReadListV1,
        Self::SelfAgentSidecarResourceGetV1,
        Self::SelfAppletCommandInstallV1,
        Self::SelfAppletCommandRevokeV1,
        Self::SelfAppletGhostCommandPreviewV1,
        Self::SelfAppletGhostCommandProvisionV1,
        Self::SelfAppletInstallCommandCancelV1,
        Self::SelfAppletInstallCommandPreviewV1,
        Self::SelfAppletRevokeCommandPreviewV1,
        Self::SelfAuthzGrantsReadEffectiveV1,
        Self::SelfAuthzInvitesReadListV1,
        Self::SelfAuthzReadCheckV1,
        Self::SelfBlobCommandPresignV1,
        Self::SelfBlobResourceGetV1,
        Self::SelfBlobResourceHeadV1,
        Self::SelfBlobUploadCreateV1,
        Self::SelfCallMediaExchangeIssueTokenV1,
        Self::SelfCircleCommandCreateV1,
        Self::SelfCircleCommandRotateScopeV1,
        Self::SelfCircleMemberCommandAddV1,
        Self::SelfCircleMemberResourceDeleteV1,
        Self::SelfCircleReadListV1,
        Self::SelfCircleResourceGetV1,
        Self::SelfCommittedEventReadScanV1,
        Self::SelfCommittedEventResourceGetV1,
        Self::SelfCommittedEventStreamSubscribeV1,
        Self::SelfConsentCommandGrantV1,
        Self::SelfConsentCommandRequestV1,
        Self::SelfConsentCommandRevokeV1,
        Self::SelfConsentReadListV1,
        Self::SelfConsentResourceGetV1,
        Self::SelfContactCommandCheckpointV1,
        Self::SelfContactCommandRejectV1,
        Self::SelfContactCommandRequestV1,
        Self::SelfContactCommandRespondV1,
        Self::SelfContactCommandScopeUpdateV1,
        Self::SelfContactCommandTombstoneV1,
        Self::SelfContactReadListV1,
        Self::SelfCurrentPrincipalReadResolveV1,
        Self::SelfCurrentResultsReadExactV1,
        Self::SelfDeviceMessagesCommandAckV1,
        Self::SelfDeviceMessagesCommandSendV1,
        Self::SelfDeviceMessagesReadListV1,
        Self::SelfDirectConversationReadResolveV1,
        Self::SelfEventsCommandSubmitV1,
        Self::SelfEventsReadDeliveryStatusV1,
        Self::SelfIdentityReadResolutionAuditV1,
        Self::SelfInviteLocatorCommandIssueV1,
        Self::SelfInviteLocatorCommandRevokeV1,
        Self::SelfInviteLocatorCommandRotateV1,
        Self::SelfInviteReceivePolicyResourceGetV1,
        Self::SelfInviteReceivePolicyResourceReplaceV1,
        Self::SelfInvitesCommandDispatchV1,
        Self::SelfKeysBackupsCommandIssueDeleteChallengeV1,
        Self::SelfKeysBackupsCommandIssueUnlockChallengeV1,
        Self::SelfKeysBackupsCommandUnlockV1,
        Self::SelfKeysBackupsReadListV1,
        Self::SelfKeysBackupsResourceDeleteV1,
        Self::SelfKeysBackupsResourceReplaceV1,
        Self::SelfKeysCommandClaimV1,
        Self::SelfKeysKeypackagesCommandClaimV1,
        Self::SelfKeysKeypackagesCommandConsumeV1,
        Self::SelfKeysKeypackagesCommandRevokeV1,
        Self::SelfKeysKeypackagesReadClaimV1,
        Self::SelfKeysKeypackagesUploadCreateV1,
        Self::SelfKeysReadLookupV1,
        Self::SelfKeysUploadCreateV1,
        Self::SelfMediaReadIceConfigV1,
        Self::SelfMediaServiceBindingReadResolveV1,
        Self::SelfMessagesCommandPrepareV1,
        Self::SelfMlsReadGroupStateMaterialV1,
        Self::SelfMlsReadRosterAuthorityV1,
        Self::SelfModerationCommandReportV1,
        Self::SelfMorphReadListV1,
        Self::SelfMorphResourceGetV1,
        Self::SelfReadCursorCommandAdvanceV1,
        Self::SelfReadCursorReadListV1,
        Self::SelfRealmReadExportV1,
        Self::SelfRealmReadStreamsV1,
        Self::SelfRealmResourceGetV1,
        Self::SelfRealmJoinCommandPrepareV1,
        Self::SelfRealmJoinReadPreviewV1,
        Self::SelfRealmLinkReadListV1,
        Self::SelfRealmOrganizationReadListV1,
        Self::SelfRealmStateSnapshotReadByRefV1,
        Self::SelfRealmStateSnapshotReadManifestHeadV1,
        Self::SelfSecurityTransactionCommandContinueV1,
        Self::SelfSecurityTransactionCommandCreateV1,
        Self::SelfSecurityTransactionResourceGetV1,
        Self::SelfSignalCommandSendV1,
        Self::SelfSignalStreamSubscribeV1,
        Self::SelfSignerKeysReadResolveV1,
        Self::SelfSpaceReadListV1,
        Self::SelfStrandReadListV1,
        Self::SelfStrandWatchReadCurrentV1,
        Self::SelfThirdPartyInviteReadAcceptanceAttestationV1,
        Self::ServerReadDescribeV1,
    ];

    pub const EDGE_APPLET_ACTOR_READ_RESOLVE_V1: &'static str =
        "ak.edge.applet.actor.read.resolve.v1";
    pub const EDGE_APPLET_CLIENT_COMMAND_EXCHANGE_V1: &'static str =
        "ak.edge.applet.client.command.exchange.v1";
    pub const EDGE_APPLET_COMMAND_TRANSACTION_V1: &'static str =
        "ak.edge.applet.command.transaction.v1";
    pub const EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1: &'static str =
        "ak.edge.applet.managed_actor.command.author.v1";
    pub const EDGE_APPLET_READ_DESCRIBE_V1: &'static str = "ak.edge.applet.read.describe.v1";
    pub const EDGE_APPLET_READ_PING_V1: &'static str = "ak.edge.applet.read.ping.v1";
    pub const EDGE_APPLET_READ_PROTOCOL_METADATA_V1: &'static str =
        "ak.edge.applet.read.protocol_metadata.v1";
    pub const EDGE_APPLET_REALM_READ_RESOLVE_V1: &'static str =
        "ak.edge.applet.realm.read.resolve.v1";
    pub const EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1: &'static str =
        "ak.edge.applet.third_party_locations.read.list.v1";
    pub const EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1: &'static str =
        "ak.edge.applet.third_party_users.read.list.v1";
    pub const EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1: &'static str =
        "ak.edge.push.command.apply_registration.v1";
    pub const EDGE_PUSH_COMMAND_NOTIFY_V1: &'static str = "ak.edge.push.command.notify.v1";
    pub const EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1: &'static str =
        "ak.edge.push.command.register_device.v1";
    pub const EDGE_PUSH_COMMAND_UNREGISTER_DEVICE_V1: &'static str =
        "ak.edge.push.command.unregister_device.v1";
    pub const FIND_DIRECTORY_READ_DESCRIBE_V1: &'static str = "ak.find.directory.read.describe.v1";
    pub const FIND_DIRECTORY_READ_RESOLVE_REALM_V1: &'static str =
        "ak.find.directory.read.resolve_realm.v1";
    pub const FIND_DIRECTORY_READ_SEARCH_REALMS_V1: &'static str =
        "ak.find.directory.read.search_realms.v1";
    pub const GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1: &'static str =
        "ak.gate.account.command.abandon_identity_creation.v1";
    pub const GATE_ACCOUNT_COMMAND_FINALIZE_DEVICE_PAIRING_V1: &'static str =
        "ak.gate.account.command.finalize_device_pairing.v1";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1: &'static str =
        "ak.gate.account.command.issue_did_binding_challenge.v1";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1: &'static str =
        "ak.gate.account.command.issue_identity_binding_challenge.v1";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1: &'static str =
        "ak.gate.account.command.issue_recovery_completion_grant.v1";
    pub const GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1: &'static str =
        "ak.gate.account.command.issue_session_grant.v1";
    pub const GATE_ACCOUNT_COMMAND_LOGOUT_V1: &'static str = "ak.gate.account.command.logout.v1";
    pub const GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1: &'static str =
        "ak.gate.account.command.pair_agent_key.v1";
    pub const GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1: &'static str =
        "ak.gate.account.command.pair_device.v1";
    pub const GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT_V1: &'static str =
        "ak.gate.account.command.refresh_session_grant.v1";
    pub const GATE_ACCOUNT_COMMAND_REGISTER_V1: &'static str =
        "ak.gate.account.command.register.v1";
    pub const GATE_ACCOUNT_COMMAND_REQUEST_ERASURE_V1: &'static str =
        "ak.gate.account.command.request_erasure.v1";
    pub const GATE_ACCOUNT_COMMAND_REVOKE_SESSION_V1: &'static str =
        "ak.gate.account.command.revoke_session.v1";
    pub const GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF_V1: &'static str =
        "ak.gate.account.exchange.create_handoff.v1";
    pub const GATE_ACCOUNT_READ_CLAIM_DEVICE_PAIRING_CODE_V1: &'static str =
        "ak.gate.account.read.claim_device_pairing_code.v1";
    pub const GATE_ACCOUNT_READ_ONBOARDING_V1: &'static str = "ak.gate.account.read.onboarding.v1";
    pub const OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST_V1: &'static str =
        "ak.open.agent_pairing.command.submit_runtime_key_request.v1";
    pub const OPEN_AGENT_PAIRING_READ_RESOLVE_V1: &'static str =
        "ak.open.agent_pairing.read.resolve.v1";
    pub const OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS_V1: &'static str =
        "ak.open.agent_pairing.read.runtime_key_request_status.v1";
    pub const OPEN_DEVICE_PAIRING_COMMAND_STAGE_V1: &'static str =
        "ak.open.device_pairing.command.stage.v1";
    pub const OPEN_DEVICE_PAIRING_READ_RESOLVE_V1: &'static str =
        "ak.open.device_pairing.read.resolve.v1";
    pub const OPEN_DEVICE_PAIRING_READ_STATUS_V1: &'static str =
        "ak.open.device_pairing.read.status.v1";
    pub const OPEN_IDENTITY_READ_RESOLUTION_V1: &'static str =
        "ak.open.identity.read.resolution.v1";
    pub const OPEN_INVITE_LOCATOR_READ_RESOLVE_V1: &'static str =
        "ak.open.invite_locator.read.resolve.v1";
    pub const OPEN_MIMI_COMMAND_NOTIFY_V1: &'static str = "ak.open.mimi.command.notify.v1";
    pub const OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1: &'static str =
        "ak.open.mimi.command.proxy_download.v1";
    pub const OPEN_MIMI_COMMAND_REPORT_ABUSE_V1: &'static str =
        "ak.open.mimi.command.report_abuse.v1";
    pub const OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1: &'static str =
        "ak.open.mimi.command.request_consent.v1";
    pub const OPEN_MIMI_COMMAND_SUBMIT_MESSAGE_V1: &'static str =
        "ak.open.mimi.command.submit_message.v1";
    pub const OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1: &'static str =
        "ak.open.mimi.command.update_consent.v1";
    pub const OPEN_MIMI_COMMAND_UPDATE_ROOM_V1: &'static str =
        "ak.open.mimi.command.update_room.v1";
    pub const OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1: &'static str =
        "ak.open.mimi.exchange.request_key_material.v1";
    pub const OPEN_MIMI_READ_IDENTIFIERS_V1: &'static str = "ak.open.mimi.read.identifiers.v1";
    pub const OPEN_MIMI_READ_PROVIDER_DIRECTORY_V1: &'static str =
        "ak.open.mimi.read.provider_directory.v1";
    pub const OPEN_REALM_AUTHORITY_READ_BUNDLE_V1: &'static str =
        "ak.open.realm_authority.read.bundle.v1";
    pub const OPEN_SERVICE_READ_RESOLUTION_V1: &'static str = "ak.open.service.read.resolution.v1";
    pub const OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1: &'static str =
        "ak.open.third_party_invite.command.activate.v1";
    pub const OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1: &'static str =
        "ak.open.third_party_invite.command.present_token.v1";
    pub const OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1: &'static str =
        "ak.open.third_party_invite.command.provision.v1";
    pub const OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1: &'static str =
        "ak.open.third_party_invite.read.provisioning_status.v1";
    pub const PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1: &'static str =
        "ak.peer.account_status.command.submit.v1";
    pub const PEER_ACCOUNT_STATUS_READ_RESOLVE_V1: &'static str =
        "ak.peer.account_status.read.resolve.v1";
    pub const PEER_COMMITTED_EVENT_READ_SCAN_V1: &'static str =
        "ak.peer.committed_event.read.scan.v1";
    pub const PEER_CONTACTS_COMMAND_SUBMIT_V1: &'static str = "ak.peer.contacts.command.submit.v1";
    pub const PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1: &'static str =
        "ak.peer.erasure_receipt.command.submit.v1";
    pub const PEER_ERASURE_RECEIPT_RESOURCE_GET_V1: &'static str =
        "ak.peer.erasure_receipt.resource.get.v1";
    pub const PEER_EVENTS_COMMAND_SUBMIT_V1: &'static str = "ak.peer.events.command.submit.v1";
    pub const PEER_INVITES_COMMAND_SUBMIT_V1: &'static str = "ak.peer.invites.command.submit.v1";
    pub const PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1: &'static str =
        "ak.peer.keys.keypackages.command.claim.v1";
    pub const PEER_KEYS_KEYPACKAGES_READ_CLAIM_V1: &'static str =
        "ak.peer.keys.keypackages.read.claim.v1";
    pub const PEER_KEYS_READ_LOOKUP_V1: &'static str = "ak.peer.keys.read.lookup.v1";
    pub const PEER_MLS_COMMAND_ATTEST_ADD_V1: &'static str = "ak.peer.mls.command.attest_add.v1";
    pub const PEER_MLS_READ_GROUP_STATE_MATERIAL_V1: &'static str =
        "ak.peer.mls.read.group_state_material.v1";
    pub const PEER_MLS_READ_ROSTER_AUTHORITY_V1: &'static str =
        "ak.peer.mls.read.roster_authority.v1";
    pub const PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1: &'static str =
        "ak.peer.realm_authority.command.handoff.v1";
    pub const PEER_REALM_JOIN_READ_BOOTSTRAP_V1: &'static str =
        "ak.peer.realm_join.read.bootstrap.v1";
    pub const PEER_REALM_JOIN_READ_PREVIEW_V1: &'static str = "ak.peer.realm_join.read.preview.v1";
    pub const PEER_SIGNAL_COMMAND_RELAY_V1: &'static str = "ak.peer.signal.command.relay.v1";
    pub const ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1: &'static str =
        "ak.root.identity.command.submit_did_operation.v1";
    pub const ROOT_IDENTITY_DOCUMENT_RESOURCE_GET_V1: &'static str =
        "ak.root.identity.document.resource.get.v1";
    pub const ROOT_IDENTITY_LOG_READ_LIST_V1: &'static str = "ak.root.identity.log.read.list.v1";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE_V1: &'static str =
        "ak.root.identity.organization_registration.command.ensure.v1";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE_V1: &'static str =
        "ak.root.identity.organization_registration.command.prepare.v1";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH_V1: &'static str =
        "ak.root.identity.organization_registration.command.refresh.v1";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE_V1: &'static str =
        "ak.root.identity.organization_registration.command.revoke.v1";
    pub const ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET_V1: &'static str =
        "ak.root.identity.organization_registration.resource.get.v1";
    pub const ROOT_IDENTITY_READ_RESOLVE_V1: &'static str = "ak.root.identity.read.resolve.v1";
    pub const ROOT_IDENTITY_RECEIPTS_READ_LIST_V1: &'static str =
        "ak.root.identity.receipts.read.list.v1";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1: &'static str =
        "ak.root.identity.recovery_policy.command.publish.v1";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1: &'static str =
        "ak.root.identity.recovery_policy.resource.get.v1";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1: &'static str =
        "ak.root.identity.recovery_session.command.create.v1";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1: &'static str =
        "ak.root.identity.recovery_session.command.submit_proof.v1";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1: &'static str =
        "ak.root.identity.recovery_session.resource.get.v1";
    pub const ROOT_IDENTITY_REGISTRY_READ_DESCRIBE_V1: &'static str =
        "ak.root.identity.registry.read.describe.v1";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1: &'static str =
        "ak.root.identity.service_registration.command.ensure.v1";
    pub const ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET_V1: &'static str =
        "ak.root.identity.service_registration.resource.get.v1";
    pub const SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1: &'static str =
        "ak.self.account.command.revoke_cursor.v1";
    pub const SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1: &'static str =
        "ak.self.account.command.update_profile.v1";
    pub const SELF_ACCOUNT_READ_DESCRIBE_V1: &'static str = "ak.self.account.read.describe.v1";
    pub const SELF_ACCOUNT_READ_VIEWER_V1: &'static str = "ak.self.account.read.viewer.v1";
    pub const SELF_ACCOUNT_STREAM_SUBSCRIBE_V1: &'static str =
        "ak.self.account.stream.subscribe.v1";
    pub const SELF_ACCOUNT_DATA_READ_LIST_V1: &'static str = "ak.self.account_data.read.list.v1";
    pub const SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1: &'static str =
        "ak.self.account_data.resource.delete.v1";
    pub const SELF_ACCOUNT_DATA_RESOURCE_GET_V1: &'static str =
        "ak.self.account_data.resource.get.v1";
    pub const SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1: &'static str =
        "ak.self.account_data.resource.replace.v1";
    pub const SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1: &'static str =
        "ak.self.actor_private_events.command.submit.v1";
    pub const SELF_ACTOR_PROFILE_READ_RESOLVE_V1: &'static str =
        "ak.self.actor_profile.read.resolve.v1";
    pub const SELF_AGENT_COMMAND_DEACTIVATE_V1: &'static str =
        "ak.self.agent.command.deactivate.v1";
    pub const SELF_AGENT_COMMAND_PAUSE_V1: &'static str = "ak.self.agent.command.pause.v1";
    pub const SELF_AGENT_COMMAND_PROVISION_V1: &'static str = "ak.self.agent.command.provision.v1";
    pub const SELF_AGENT_COMMAND_RENEW_PAIRING_V1: &'static str =
        "ak.self.agent.command.renew_pairing.v1";
    pub const SELF_AGENT_COMMAND_RESUME_V1: &'static str = "ak.self.agent.command.resume.v1";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_GET_V1: &'static str =
        "ak.self.agent.participation.resource.get.v1";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1: &'static str =
        "ak.self.agent.participation.resource.replace.v1";
    pub const SELF_AGENT_READ_LIST_V1: &'static str = "ak.self.agent.read.list.v1";
    pub const SELF_AGENT_RESOURCE_GET_V1: &'static str = "ak.self.agent.resource.get.v1";
    pub const SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1: &'static str =
        "ak.self.agent.sidecar.command.ensure.v1";
    pub const SELF_AGENT_SIDECAR_READ_LIST_V1: &'static str = "ak.self.agent.sidecar.read.list.v1";
    pub const SELF_AGENT_SIDECAR_RESOURCE_GET_V1: &'static str =
        "ak.self.agent.sidecar.resource.get.v1";
    pub const SELF_APPLET_COMMAND_INSTALL_V1: &'static str = "ak.self.applet.command.install.v1";
    pub const SELF_APPLET_COMMAND_REVOKE_V1: &'static str = "ak.self.applet.command.revoke.v1";
    pub const SELF_APPLET_GHOST_COMMAND_PREVIEW_V1: &'static str =
        "ak.self.applet.ghost.command.preview.v1";
    pub const SELF_APPLET_GHOST_COMMAND_PROVISION_V1: &'static str =
        "ak.self.applet.ghost.command.provision.v1";
    pub const SELF_APPLET_INSTALL_COMMAND_CANCEL_V1: &'static str =
        "ak.self.applet.install.command.cancel.v1";
    pub const SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1: &'static str =
        "ak.self.applet.install.command.preview.v1";
    pub const SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1: &'static str =
        "ak.self.applet.revoke.command.preview.v1";
    pub const SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1: &'static str =
        "ak.self.authz.grants.read.effective.v1";
    pub const SELF_AUTHZ_INVITES_READ_LIST_V1: &'static str = "ak.self.authz.invites.read.list.v1";
    pub const SELF_AUTHZ_READ_CHECK_V1: &'static str = "ak.self.authz.read.check.v1";
    pub const SELF_BLOB_COMMAND_PRESIGN_V1: &'static str = "ak.self.blob.command.presign.v1";
    pub const SELF_BLOB_RESOURCE_GET_V1: &'static str = "ak.self.blob.resource.get.v1";
    pub const SELF_BLOB_RESOURCE_HEAD_V1: &'static str = "ak.self.blob.resource.head.v1";
    pub const SELF_BLOB_UPLOAD_CREATE_V1: &'static str = "ak.self.blob.upload.create.v1";
    pub const SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1: &'static str =
        "ak.self.call.media.exchange.issue_token.v1";
    pub const SELF_CIRCLE_COMMAND_CREATE_V1: &'static str = "ak.self.circle.command.create.v1";
    pub const SELF_CIRCLE_COMMAND_ROTATE_SCOPE_V1: &'static str =
        "ak.self.circle.command.rotate_scope.v1";
    pub const SELF_CIRCLE_MEMBER_COMMAND_ADD_V1: &'static str =
        "ak.self.circle.member.command.add.v1";
    pub const SELF_CIRCLE_MEMBER_RESOURCE_DELETE_V1: &'static str =
        "ak.self.circle.member.resource.delete.v1";
    pub const SELF_CIRCLE_READ_LIST_V1: &'static str = "ak.self.circle.read.list.v1";
    pub const SELF_CIRCLE_RESOURCE_GET_V1: &'static str = "ak.self.circle.resource.get.v1";
    pub const SELF_COMMITTED_EVENT_READ_SCAN_V1: &'static str =
        "ak.self.committed_event.read.scan.v1";
    pub const SELF_COMMITTED_EVENT_RESOURCE_GET_V1: &'static str =
        "ak.self.committed_event.resource.get.v1";
    pub const SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1: &'static str =
        "ak.self.committed_event.stream.subscribe.v1";
    pub const SELF_CONSENT_COMMAND_GRANT_V1: &'static str = "ak.self.consent.command.grant.v1";
    pub const SELF_CONSENT_COMMAND_REQUEST_V1: &'static str = "ak.self.consent.command.request.v1";
    pub const SELF_CONSENT_COMMAND_REVOKE_V1: &'static str = "ak.self.consent.command.revoke.v1";
    pub const SELF_CONSENT_READ_LIST_V1: &'static str = "ak.self.consent.read.list.v1";
    pub const SELF_CONSENT_RESOURCE_GET_V1: &'static str = "ak.self.consent.resource.get.v1";
    pub const SELF_CONTACT_COMMAND_CHECKPOINT_V1: &'static str =
        "ak.self.contact.command.checkpoint.v1";
    pub const SELF_CONTACT_COMMAND_REJECT_V1: &'static str = "ak.self.contact.command.reject.v1";
    pub const SELF_CONTACT_COMMAND_REQUEST_V1: &'static str = "ak.self.contact.command.request.v1";
    pub const SELF_CONTACT_COMMAND_RESPOND_V1: &'static str = "ak.self.contact.command.respond.v1";
    pub const SELF_CONTACT_COMMAND_SCOPE_UPDATE_V1: &'static str =
        "ak.self.contact.command.scope_update.v1";
    pub const SELF_CONTACT_COMMAND_TOMBSTONE_V1: &'static str =
        "ak.self.contact.command.tombstone.v1";
    pub const SELF_CONTACT_READ_LIST_V1: &'static str = "ak.self.contact.read.list.v1";
    pub const SELF_CURRENT_PRINCIPAL_READ_RESOLVE_V1: &'static str =
        "ak.self.current_principal.read.resolve.v1";
    pub const SELF_CURRENT_RESULTS_READ_EXACT_V1: &'static str =
        "ak.self.current_results.read.exact.v1";
    pub const SELF_DEVICE_MESSAGES_COMMAND_ACK_V1: &'static str =
        "ak.self.device_messages.command.ack.v1";
    pub const SELF_DEVICE_MESSAGES_COMMAND_SEND_V1: &'static str =
        "ak.self.device_messages.command.send.v1";
    pub const SELF_DEVICE_MESSAGES_READ_LIST_V1: &'static str =
        "ak.self.device_messages.read.list.v1";
    pub const SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1: &'static str =
        "ak.self.direct_conversation.read.resolve.v1";
    pub const SELF_EVENTS_COMMAND_SUBMIT_V1: &'static str = "ak.self.events.command.submit.v1";
    pub const SELF_EVENTS_READ_DELIVERY_STATUS_V1: &'static str =
        "ak.self.events.read.delivery_status.v1";
    pub const SELF_IDENTITY_READ_RESOLUTION_AUDIT_V1: &'static str =
        "ak.self.identity.read.resolution_audit.v1";
    pub const SELF_INVITE_LOCATOR_COMMAND_ISSUE_V1: &'static str =
        "ak.self.invite_locator.command.issue.v1";
    pub const SELF_INVITE_LOCATOR_COMMAND_REVOKE_V1: &'static str =
        "ak.self.invite_locator.command.revoke.v1";
    pub const SELF_INVITE_LOCATOR_COMMAND_ROTATE_V1: &'static str =
        "ak.self.invite_locator.command.rotate.v1";
    pub const SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1: &'static str =
        "ak.self.invite_receive_policy.resource.get.v1";
    pub const SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1: &'static str =
        "ak.self.invite_receive_policy.resource.replace.v1";
    pub const SELF_INVITES_COMMAND_DISPATCH_V1: &'static str =
        "ak.self.invites.command.dispatch.v1";
    pub const SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE_V1: &'static str =
        "ak.self.keys.backups.command.issue_delete_challenge.v1";
    pub const SELF_KEYS_BACKUPS_COMMAND_ISSUE_UNLOCK_CHALLENGE_V1: &'static str =
        "ak.self.keys.backups.command.issue_unlock_challenge.v1";
    pub const SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1: &'static str =
        "ak.self.keys.backups.command.unlock.v1";
    pub const SELF_KEYS_BACKUPS_READ_LIST_V1: &'static str = "ak.self.keys.backups.read.list.v1";
    pub const SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1: &'static str =
        "ak.self.keys.backups.resource.delete.v1";
    pub const SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1: &'static str =
        "ak.self.keys.backups.resource.replace.v1";
    pub const SELF_KEYS_COMMAND_CLAIM_V1: &'static str = "ak.self.keys.command.claim.v1";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1: &'static str =
        "ak.self.keys.keypackages.command.claim.v1";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1: &'static str =
        "ak.self.keys.keypackages.command.consume.v1";
    pub const SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1: &'static str =
        "ak.self.keys.keypackages.command.revoke.v1";
    pub const SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1: &'static str =
        "ak.self.keys.keypackages.read.claim.v1";
    pub const SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1: &'static str =
        "ak.self.keys.keypackages.upload.create.v1";
    pub const SELF_KEYS_READ_LOOKUP_V1: &'static str = "ak.self.keys.read.lookup.v1";
    pub const SELF_KEYS_UPLOAD_CREATE_V1: &'static str = "ak.self.keys.upload.create.v1";
    pub const SELF_MEDIA_READ_ICE_CONFIG_V1: &'static str = "ak.self.media.read.ice_config.v1";
    pub const SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1: &'static str =
        "ak.self.media_service_binding.read.resolve.v1";
    pub const SELF_MESSAGES_COMMAND_PREPARE_V1: &'static str =
        "ak.self.messages.command.prepare.v1";
    pub const SELF_MLS_READ_GROUP_STATE_MATERIAL_V1: &'static str =
        "ak.self.mls.read.group_state_material.v1";
    pub const SELF_MLS_READ_ROSTER_AUTHORITY_V1: &'static str =
        "ak.self.mls.read.roster_authority.v1";
    pub const SELF_MODERATION_COMMAND_REPORT_V1: &'static str =
        "ak.self.moderation.command.report.v1";
    pub const SELF_MORPH_READ_LIST_V1: &'static str = "ak.self.morph.read.list.v1";
    pub const SELF_MORPH_RESOURCE_GET_V1: &'static str = "ak.self.morph.resource.get.v1";
    pub const SELF_READ_CURSOR_COMMAND_ADVANCE_V1: &'static str =
        "ak.self.read_cursor.command.advance.v1";
    pub const SELF_READ_CURSOR_READ_LIST_V1: &'static str = "ak.self.read_cursor.read.list.v1";
    pub const SELF_REALM_READ_EXPORT_V1: &'static str = "ak.self.realm.read.export.v1";
    pub const SELF_REALM_READ_STREAMS_V1: &'static str = "ak.self.realm.read.streams.v1";
    pub const SELF_REALM_RESOURCE_GET_V1: &'static str = "ak.self.realm.resource.get.v1";
    pub const SELF_REALM_JOIN_COMMAND_PREPARE_V1: &'static str =
        "ak.self.realm_join.command.prepare.v1";
    pub const SELF_REALM_JOIN_READ_PREVIEW_V1: &'static str = "ak.self.realm_join.read.preview.v1";
    pub const SELF_REALM_LINK_READ_LIST_V1: &'static str = "ak.self.realm_link.read.list.v1";
    pub const SELF_REALM_ORGANIZATION_READ_LIST_V1: &'static str =
        "ak.self.realm_organization.read.list.v1";
    pub const SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1: &'static str =
        "ak.self.realm_state_snapshot.read.by_ref.v1";
    pub const SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1: &'static str =
        "ak.self.realm_state_snapshot.read.manifest_head.v1";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1: &'static str =
        "ak.self.security_transaction.command.continue.v1";
    pub const SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1: &'static str =
        "ak.self.security_transaction.command.create.v1";
    pub const SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1: &'static str =
        "ak.self.security_transaction.resource.get.v1";
    pub const SELF_SIGNAL_COMMAND_SEND_V1: &'static str = "ak.self.signal.command.send.v1";
    pub const SELF_SIGNAL_STREAM_SUBSCRIBE_V1: &'static str = "ak.self.signal.stream.subscribe.v1";
    pub const SELF_SIGNER_KEYS_READ_RESOLVE_V1: &'static str =
        "ak.self.signer_keys.read.resolve.v1";
    pub const SELF_SPACE_READ_LIST_V1: &'static str = "ak.self.space.read.list.v1";
    pub const SELF_STRAND_READ_LIST_V1: &'static str = "ak.self.strand.read.list.v1";
    pub const SELF_STRAND_WATCH_READ_CURRENT_V1: &'static str =
        "ak.self.strand.watch.read.current.v1";
    pub const SELF_THIRD_PARTY_INVITE_READ_ACCEPTANCE_ATTESTATION_V1: &'static str =
        "ak.self.third_party_invite.read.acceptance_attestation.v1";
    pub const SERVER_READ_DESCRIBE_V1: &'static str = "ak.server.read.describe.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeAppletActorReadResolveV1 => Self::EDGE_APPLET_ACTOR_READ_RESOLVE_V1,
            Self::EdgeAppletClientCommandExchangeV1 => Self::EDGE_APPLET_CLIENT_COMMAND_EXCHANGE_V1,
            Self::EdgeAppletCommandTransactionV1 => Self::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            Self::EdgeAppletManagedActorCommandAuthorV1 => {
                Self::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1
            }
            Self::EdgeAppletReadDescribeV1 => Self::EDGE_APPLET_READ_DESCRIBE_V1,
            Self::EdgeAppletReadPingV1 => Self::EDGE_APPLET_READ_PING_V1,
            Self::EdgeAppletReadProtocolMetadataV1 => Self::EDGE_APPLET_READ_PROTOCOL_METADATA_V1,
            Self::EdgeAppletRealmReadResolveV1 => Self::EDGE_APPLET_REALM_READ_RESOLVE_V1,
            Self::EdgeAppletThirdPartyLocationsReadListV1 => {
                Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1
            }
            Self::EdgeAppletThirdPartyUsersReadListV1 => {
                Self::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1
            }
            Self::EdgePushCommandApplyRegistrationV1 => {
                Self::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1
            }
            Self::EdgePushCommandNotifyV1 => Self::EDGE_PUSH_COMMAND_NOTIFY_V1,
            Self::EdgePushCommandRegisterDeviceV1 => Self::EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1,
            Self::EdgePushCommandUnregisterDeviceV1 => Self::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE_V1,
            Self::FindDirectoryReadDescribeV1 => Self::FIND_DIRECTORY_READ_DESCRIBE_V1,
            Self::FindDirectoryReadResolveRealmV1 => Self::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            Self::FindDirectoryReadSearchRealmsV1 => Self::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            Self::GateAccountCommandAbandonIdentityCreationV1 => {
                Self::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1
            }
            Self::GateAccountCommandFinalizeDevicePairingV1 => {
                Self::GATE_ACCOUNT_COMMAND_FINALIZE_DEVICE_PAIRING_V1
            }
            Self::GateAccountCommandIssueDidBindingChallengeV1 => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1
            }
            Self::GateAccountCommandIssueIdentityBindingChallengeV1 => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1
            }
            Self::GateAccountCommandIssueRecoveryCompletionGrantV1 => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1
            }
            Self::GateAccountCommandIssueSessionGrantV1 => {
                Self::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1
            }
            Self::GateAccountCommandLogoutV1 => Self::GATE_ACCOUNT_COMMAND_LOGOUT_V1,
            Self::GateAccountCommandPairAgentKeyV1 => Self::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            Self::GateAccountCommandPairDeviceV1 => Self::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,
            Self::GateAccountCommandRefreshSessionGrantV1 => {
                Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT_V1
            }
            Self::GateAccountCommandRegisterV1 => Self::GATE_ACCOUNT_COMMAND_REGISTER_V1,
            Self::GateAccountCommandRequestErasureV1 => {
                Self::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE_V1
            }
            Self::GateAccountCommandRevokeSessionV1 => Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION_V1,
            Self::GateAccountExchangeCreateHandoffV1 => {
                Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF_V1
            }
            Self::GateAccountReadClaimDevicePairingCodeV1 => {
                Self::GATE_ACCOUNT_READ_CLAIM_DEVICE_PAIRING_CODE_V1
            }
            Self::GateAccountReadOnboardingV1 => Self::GATE_ACCOUNT_READ_ONBOARDING_V1,
            Self::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1 => {
                Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST_V1
            }
            Self::OpenAgentPairingReadResolveV1 => Self::OPEN_AGENT_PAIRING_READ_RESOLVE_V1,
            Self::OpenAgentPairingReadRuntimeKeyRequestStatusV1 => {
                Self::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS_V1
            }
            Self::OpenDevicePairingCommandStageV1 => Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE_V1,
            Self::OpenDevicePairingReadResolveV1 => Self::OPEN_DEVICE_PAIRING_READ_RESOLVE_V1,
            Self::OpenDevicePairingReadStatusV1 => Self::OPEN_DEVICE_PAIRING_READ_STATUS_V1,
            Self::OpenIdentityReadResolutionV1 => Self::OPEN_IDENTITY_READ_RESOLUTION_V1,
            Self::OpenInviteLocatorReadResolveV1 => Self::OPEN_INVITE_LOCATOR_READ_RESOLVE_V1,
            Self::OpenMimiCommandNotifyV1 => Self::OPEN_MIMI_COMMAND_NOTIFY_V1,
            Self::OpenMimiCommandProxyDownloadV1 => Self::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1,
            Self::OpenMimiCommandReportAbuseV1 => Self::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1,
            Self::OpenMimiCommandRequestConsentV1 => Self::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
            Self::OpenMimiCommandSubmitMessageV1 => Self::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE_V1,
            Self::OpenMimiCommandUpdateConsentV1 => Self::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1,
            Self::OpenMimiCommandUpdateRoomV1 => Self::OPEN_MIMI_COMMAND_UPDATE_ROOM_V1,
            Self::OpenMimiExchangeRequestKeyMaterialV1 => {
                Self::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1
            }
            Self::OpenMimiReadIdentifiersV1 => Self::OPEN_MIMI_READ_IDENTIFIERS_V1,
            Self::OpenMimiReadProviderDirectoryV1 => Self::OPEN_MIMI_READ_PROVIDER_DIRECTORY_V1,
            Self::OpenRealmAuthorityReadBundleV1 => Self::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
            Self::OpenServiceReadResolutionV1 => Self::OPEN_SERVICE_READ_RESOLUTION_V1,
            Self::OpenThirdPartyInviteCommandActivateV1 => {
                Self::OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1
            }
            Self::OpenThirdPartyInviteCommandPresentTokenV1 => {
                Self::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1
            }
            Self::OpenThirdPartyInviteCommandProvisionV1 => {
                Self::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1
            }
            Self::OpenThirdPartyInviteReadProvisioningStatusV1 => {
                Self::OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1
            }
            Self::PeerAccountStatusCommandSubmitV1 => Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            Self::PeerAccountStatusReadResolveV1 => Self::PEER_ACCOUNT_STATUS_READ_RESOLVE_V1,
            Self::PeerCommittedEventReadScanV1 => Self::PEER_COMMITTED_EVENT_READ_SCAN_V1,
            Self::PeerContactsCommandSubmitV1 => Self::PEER_CONTACTS_COMMAND_SUBMIT_V1,
            Self::PeerErasureReceiptCommandSubmitV1 => Self::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1,
            Self::PeerErasureReceiptResourceGetV1 => Self::PEER_ERASURE_RECEIPT_RESOURCE_GET_V1,
            Self::PeerEventsCommandSubmitV1 => Self::PEER_EVENTS_COMMAND_SUBMIT_V1,
            Self::PeerInvitesCommandSubmitV1 => Self::PEER_INVITES_COMMAND_SUBMIT_V1,
            Self::PeerKeysKeypackagesCommandClaimV1 => Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
            Self::PeerKeysKeypackagesReadClaimV1 => Self::PEER_KEYS_KEYPACKAGES_READ_CLAIM_V1,
            Self::PeerKeysReadLookupV1 => Self::PEER_KEYS_READ_LOOKUP_V1,
            Self::PeerMlsCommandAttestAddV1 => Self::PEER_MLS_COMMAND_ATTEST_ADD_V1,
            Self::PeerMlsReadGroupStateMaterialV1 => Self::PEER_MLS_READ_GROUP_STATE_MATERIAL_V1,
            Self::PeerMlsReadRosterAuthorityV1 => Self::PEER_MLS_READ_ROSTER_AUTHORITY_V1,
            Self::PeerRealmAuthorityCommandHandoffV1 => {
                Self::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1
            }
            Self::PeerRealmJoinReadBootstrapV1 => Self::PEER_REALM_JOIN_READ_BOOTSTRAP_V1,
            Self::PeerRealmJoinReadPreviewV1 => Self::PEER_REALM_JOIN_READ_PREVIEW_V1,
            Self::PeerSignalCommandRelayV1 => Self::PEER_SIGNAL_COMMAND_RELAY_V1,
            Self::RootIdentityCommandSubmitDidOperationV1 => {
                Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1
            }
            Self::RootIdentityDocumentResourceGetV1 => Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET_V1,
            Self::RootIdentityLogReadListV1 => Self::ROOT_IDENTITY_LOG_READ_LIST_V1,
            Self::RootIdentityOrganizationRegistrationCommandEnsureV1 => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE_V1
            }
            Self::RootIdentityOrganizationRegistrationCommandPrepareV1 => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE_V1
            }
            Self::RootIdentityOrganizationRegistrationCommandRefreshV1 => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH_V1
            }
            Self::RootIdentityOrganizationRegistrationCommandRevokeV1 => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE_V1
            }
            Self::RootIdentityOrganizationRegistrationResourceGetV1 => {
                Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET_V1
            }
            Self::RootIdentityReadResolveV1 => Self::ROOT_IDENTITY_READ_RESOLVE_V1,
            Self::RootIdentityReceiptsReadListV1 => Self::ROOT_IDENTITY_RECEIPTS_READ_LIST_V1,
            Self::RootIdentityRecoveryPolicyCommandPublishV1 => {
                Self::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1
            }
            Self::RootIdentityRecoveryPolicyResourceGetV1 => {
                Self::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1
            }
            Self::RootIdentityRecoverySessionCommandCreateV1 => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1
            }
            Self::RootIdentityRecoverySessionCommandSubmitProofV1 => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1
            }
            Self::RootIdentityRecoverySessionResourceGetV1 => {
                Self::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1
            }
            Self::RootIdentityRegistryReadDescribeV1 => {
                Self::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE_V1
            }
            Self::RootIdentityServiceRegistrationCommandEnsureV1 => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1
            }
            Self::RootIdentityServiceRegistrationResourceGetV1 => {
                Self::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET_V1
            }
            Self::SelfAccountCommandRevokeCursorV1 => Self::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1,
            Self::SelfAccountCommandUpdateProfileV1 => Self::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
            Self::SelfAccountReadDescribeV1 => Self::SELF_ACCOUNT_READ_DESCRIBE_V1,
            Self::SelfAccountReadViewerV1 => Self::SELF_ACCOUNT_READ_VIEWER_V1,
            Self::SelfAccountStreamSubscribeV1 => Self::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
            Self::SelfAccountDataReadListV1 => Self::SELF_ACCOUNT_DATA_READ_LIST_V1,
            Self::SelfAccountDataResourceDeleteV1 => Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1,
            Self::SelfAccountDataResourceGetV1 => Self::SELF_ACCOUNT_DATA_RESOURCE_GET_V1,
            Self::SelfAccountDataResourceReplaceV1 => Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Self::SelfActorPrivateEventsCommandSubmitV1 => {
                Self::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1
            }
            Self::SelfActorProfileReadResolveV1 => Self::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
            Self::SelfAgentCommandDeactivateV1 => Self::SELF_AGENT_COMMAND_DEACTIVATE_V1,
            Self::SelfAgentCommandPauseV1 => Self::SELF_AGENT_COMMAND_PAUSE_V1,
            Self::SelfAgentCommandProvisionV1 => Self::SELF_AGENT_COMMAND_PROVISION_V1,
            Self::SelfAgentCommandRenewPairingV1 => Self::SELF_AGENT_COMMAND_RENEW_PAIRING_V1,
            Self::SelfAgentCommandResumeV1 => Self::SELF_AGENT_COMMAND_RESUME_V1,
            Self::SelfAgentParticipationResourceGetV1 => {
                Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET_V1
            }
            Self::SelfAgentParticipationResourceReplaceV1 => {
                Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1
            }
            Self::SelfAgentReadListV1 => Self::SELF_AGENT_READ_LIST_V1,
            Self::SelfAgentResourceGetV1 => Self::SELF_AGENT_RESOURCE_GET_V1,
            Self::SelfAgentSidecarCommandEnsureV1 => Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
            Self::SelfAgentSidecarReadListV1 => Self::SELF_AGENT_SIDECAR_READ_LIST_V1,
            Self::SelfAgentSidecarResourceGetV1 => Self::SELF_AGENT_SIDECAR_RESOURCE_GET_V1,
            Self::SelfAppletCommandInstallV1 => Self::SELF_APPLET_COMMAND_INSTALL_V1,
            Self::SelfAppletCommandRevokeV1 => Self::SELF_APPLET_COMMAND_REVOKE_V1,
            Self::SelfAppletGhostCommandPreviewV1 => Self::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
            Self::SelfAppletGhostCommandProvisionV1 => Self::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
            Self::SelfAppletInstallCommandCancelV1 => Self::SELF_APPLET_INSTALL_COMMAND_CANCEL_V1,
            Self::SelfAppletInstallCommandPreviewV1 => Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
            Self::SelfAppletRevokeCommandPreviewV1 => Self::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            Self::SelfAuthzGrantsReadEffectiveV1 => Self::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1,
            Self::SelfAuthzInvitesReadListV1 => Self::SELF_AUTHZ_INVITES_READ_LIST_V1,
            Self::SelfAuthzReadCheckV1 => Self::SELF_AUTHZ_READ_CHECK_V1,
            Self::SelfBlobCommandPresignV1 => Self::SELF_BLOB_COMMAND_PRESIGN_V1,
            Self::SelfBlobResourceGetV1 => Self::SELF_BLOB_RESOURCE_GET_V1,
            Self::SelfBlobResourceHeadV1 => Self::SELF_BLOB_RESOURCE_HEAD_V1,
            Self::SelfBlobUploadCreateV1 => Self::SELF_BLOB_UPLOAD_CREATE_V1,
            Self::SelfCallMediaExchangeIssueTokenV1 => {
                Self::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1
            }
            Self::SelfCircleCommandCreateV1 => Self::SELF_CIRCLE_COMMAND_CREATE_V1,
            Self::SelfCircleCommandRotateScopeV1 => Self::SELF_CIRCLE_COMMAND_ROTATE_SCOPE_V1,
            Self::SelfCircleMemberCommandAddV1 => Self::SELF_CIRCLE_MEMBER_COMMAND_ADD_V1,
            Self::SelfCircleMemberResourceDeleteV1 => Self::SELF_CIRCLE_MEMBER_RESOURCE_DELETE_V1,
            Self::SelfCircleReadListV1 => Self::SELF_CIRCLE_READ_LIST_V1,
            Self::SelfCircleResourceGetV1 => Self::SELF_CIRCLE_RESOURCE_GET_V1,
            Self::SelfCommittedEventReadScanV1 => Self::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            Self::SelfCommittedEventResourceGetV1 => Self::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
            Self::SelfCommittedEventStreamSubscribeV1 => {
                Self::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1
            }
            Self::SelfConsentCommandGrantV1 => Self::SELF_CONSENT_COMMAND_GRANT_V1,
            Self::SelfConsentCommandRequestV1 => Self::SELF_CONSENT_COMMAND_REQUEST_V1,
            Self::SelfConsentCommandRevokeV1 => Self::SELF_CONSENT_COMMAND_REVOKE_V1,
            Self::SelfConsentReadListV1 => Self::SELF_CONSENT_READ_LIST_V1,
            Self::SelfConsentResourceGetV1 => Self::SELF_CONSENT_RESOURCE_GET_V1,
            Self::SelfContactCommandCheckpointV1 => Self::SELF_CONTACT_COMMAND_CHECKPOINT_V1,
            Self::SelfContactCommandRejectV1 => Self::SELF_CONTACT_COMMAND_REJECT_V1,
            Self::SelfContactCommandRequestV1 => Self::SELF_CONTACT_COMMAND_REQUEST_V1,
            Self::SelfContactCommandRespondV1 => Self::SELF_CONTACT_COMMAND_RESPOND_V1,
            Self::SelfContactCommandScopeUpdateV1 => Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE_V1,
            Self::SelfContactCommandTombstoneV1 => Self::SELF_CONTACT_COMMAND_TOMBSTONE_V1,
            Self::SelfContactReadListV1 => Self::SELF_CONTACT_READ_LIST_V1,
            Self::SelfCurrentPrincipalReadResolveV1 => Self::SELF_CURRENT_PRINCIPAL_READ_RESOLVE_V1,
            Self::SelfCurrentResultsReadExactV1 => Self::SELF_CURRENT_RESULTS_READ_EXACT_V1,
            Self::SelfDeviceMessagesCommandAckV1 => Self::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
            Self::SelfDeviceMessagesCommandSendV1 => Self::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1,
            Self::SelfDeviceMessagesReadListV1 => Self::SELF_DEVICE_MESSAGES_READ_LIST_V1,
            Self::SelfDirectConversationReadResolveV1 => {
                Self::SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1
            }
            Self::SelfEventsCommandSubmitV1 => Self::SELF_EVENTS_COMMAND_SUBMIT_V1,
            Self::SelfEventsReadDeliveryStatusV1 => Self::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
            Self::SelfIdentityReadResolutionAuditV1 => Self::SELF_IDENTITY_READ_RESOLUTION_AUDIT_V1,
            Self::SelfInviteLocatorCommandIssueV1 => Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE_V1,
            Self::SelfInviteLocatorCommandRevokeV1 => Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE_V1,
            Self::SelfInviteLocatorCommandRotateV1 => Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE_V1,
            Self::SelfInviteReceivePolicyResourceGetV1 => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1
            }
            Self::SelfInviteReceivePolicyResourceReplaceV1 => {
                Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1
            }
            Self::SelfInvitesCommandDispatchV1 => Self::SELF_INVITES_COMMAND_DISPATCH_V1,
            Self::SelfKeysBackupsCommandIssueDeleteChallengeV1 => {
                Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE_V1
            }
            Self::SelfKeysBackupsCommandIssueUnlockChallengeV1 => {
                Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_UNLOCK_CHALLENGE_V1
            }
            Self::SelfKeysBackupsCommandUnlockV1 => Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
            Self::SelfKeysBackupsReadListV1 => Self::SELF_KEYS_BACKUPS_READ_LIST_V1,
            Self::SelfKeysBackupsResourceDeleteV1 => Self::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1,
            Self::SelfKeysBackupsResourceReplaceV1 => Self::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
            Self::SelfKeysCommandClaimV1 => Self::SELF_KEYS_COMMAND_CLAIM_V1,
            Self::SelfKeysKeypackagesCommandClaimV1 => Self::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
            Self::SelfKeysKeypackagesCommandConsumeV1 => {
                Self::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1
            }
            Self::SelfKeysKeypackagesCommandRevokeV1 => {
                Self::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1
            }
            Self::SelfKeysKeypackagesReadClaimV1 => Self::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
            Self::SelfKeysKeypackagesUploadCreateV1 => Self::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
            Self::SelfKeysReadLookupV1 => Self::SELF_KEYS_READ_LOOKUP_V1,
            Self::SelfKeysUploadCreateV1 => Self::SELF_KEYS_UPLOAD_CREATE_V1,
            Self::SelfMediaReadIceConfigV1 => Self::SELF_MEDIA_READ_ICE_CONFIG_V1,
            Self::SelfMediaServiceBindingReadResolveV1 => {
                Self::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1
            }
            Self::SelfMessagesCommandPrepareV1 => Self::SELF_MESSAGES_COMMAND_PREPARE_V1,
            Self::SelfMlsReadGroupStateMaterialV1 => Self::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
            Self::SelfMlsReadRosterAuthorityV1 => Self::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
            Self::SelfModerationCommandReportV1 => Self::SELF_MODERATION_COMMAND_REPORT_V1,
            Self::SelfMorphReadListV1 => Self::SELF_MORPH_READ_LIST_V1,
            Self::SelfMorphResourceGetV1 => Self::SELF_MORPH_RESOURCE_GET_V1,
            Self::SelfReadCursorCommandAdvanceV1 => Self::SELF_READ_CURSOR_COMMAND_ADVANCE_V1,
            Self::SelfReadCursorReadListV1 => Self::SELF_READ_CURSOR_READ_LIST_V1,
            Self::SelfRealmReadExportV1 => Self::SELF_REALM_READ_EXPORT_V1,
            Self::SelfRealmReadStreamsV1 => Self::SELF_REALM_READ_STREAMS_V1,
            Self::SelfRealmResourceGetV1 => Self::SELF_REALM_RESOURCE_GET_V1,
            Self::SelfRealmJoinCommandPrepareV1 => Self::SELF_REALM_JOIN_COMMAND_PREPARE_V1,
            Self::SelfRealmJoinReadPreviewV1 => Self::SELF_REALM_JOIN_READ_PREVIEW_V1,
            Self::SelfRealmLinkReadListV1 => Self::SELF_REALM_LINK_READ_LIST_V1,
            Self::SelfRealmOrganizationReadListV1 => Self::SELF_REALM_ORGANIZATION_READ_LIST_V1,
            Self::SelfRealmStateSnapshotReadByRefV1 => {
                Self::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1
            }
            Self::SelfRealmStateSnapshotReadManifestHeadV1 => {
                Self::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1
            }
            Self::SelfSecurityTransactionCommandContinueV1 => {
                Self::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1
            }
            Self::SelfSecurityTransactionCommandCreateV1 => {
                Self::SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1
            }
            Self::SelfSecurityTransactionResourceGetV1 => {
                Self::SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1
            }
            Self::SelfSignalCommandSendV1 => Self::SELF_SIGNAL_COMMAND_SEND_V1,
            Self::SelfSignalStreamSubscribeV1 => Self::SELF_SIGNAL_STREAM_SUBSCRIBE_V1,
            Self::SelfSignerKeysReadResolveV1 => Self::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
            Self::SelfSpaceReadListV1 => Self::SELF_SPACE_READ_LIST_V1,
            Self::SelfStrandReadListV1 => Self::SELF_STRAND_READ_LIST_V1,
            Self::SelfStrandWatchReadCurrentV1 => Self::SELF_STRAND_WATCH_READ_CURRENT_V1,
            Self::SelfThirdPartyInviteReadAcceptanceAttestationV1 => {
                Self::SELF_THIRD_PARTY_INVITE_READ_ACCEPTANCE_ATTESTATION_V1
            }
            Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::EDGE_APPLET_ACTOR_READ_RESOLVE_V1 => Some(Self::EdgeAppletActorReadResolveV1),
            Self::EDGE_APPLET_CLIENT_COMMAND_EXCHANGE_V1 => {
                Some(Self::EdgeAppletClientCommandExchangeV1)
            }
            Self::EDGE_APPLET_COMMAND_TRANSACTION_V1 => Some(Self::EdgeAppletCommandTransactionV1),
            Self::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1 => {
                Some(Self::EdgeAppletManagedActorCommandAuthorV1)
            }
            Self::EDGE_APPLET_READ_DESCRIBE_V1 => Some(Self::EdgeAppletReadDescribeV1),
            Self::EDGE_APPLET_READ_PING_V1 => Some(Self::EdgeAppletReadPingV1),
            Self::EDGE_APPLET_READ_PROTOCOL_METADATA_V1 => {
                Some(Self::EdgeAppletReadProtocolMetadataV1)
            }
            Self::EDGE_APPLET_REALM_READ_RESOLVE_V1 => Some(Self::EdgeAppletRealmReadResolveV1),
            Self::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1 => {
                Some(Self::EdgeAppletThirdPartyLocationsReadListV1)
            }
            Self::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1 => {
                Some(Self::EdgeAppletThirdPartyUsersReadListV1)
            }
            Self::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1 => {
                Some(Self::EdgePushCommandApplyRegistrationV1)
            }
            Self::EDGE_PUSH_COMMAND_NOTIFY_V1 => Some(Self::EdgePushCommandNotifyV1),
            Self::EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1 => {
                Some(Self::EdgePushCommandRegisterDeviceV1)
            }
            Self::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE_V1 => {
                Some(Self::EdgePushCommandUnregisterDeviceV1)
            }
            Self::FIND_DIRECTORY_READ_DESCRIBE_V1 => Some(Self::FindDirectoryReadDescribeV1),
            Self::FIND_DIRECTORY_READ_RESOLVE_REALM_V1 => {
                Some(Self::FindDirectoryReadResolveRealmV1)
            }
            Self::FIND_DIRECTORY_READ_SEARCH_REALMS_V1 => {
                Some(Self::FindDirectoryReadSearchRealmsV1)
            }
            Self::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1 => {
                Some(Self::GateAccountCommandAbandonIdentityCreationV1)
            }
            Self::GATE_ACCOUNT_COMMAND_FINALIZE_DEVICE_PAIRING_V1 => {
                Some(Self::GateAccountCommandFinalizeDevicePairingV1)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1 => {
                Some(Self::GateAccountCommandIssueDidBindingChallengeV1)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1 => {
                Some(Self::GateAccountCommandIssueIdentityBindingChallengeV1)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1 => {
                Some(Self::GateAccountCommandIssueRecoveryCompletionGrantV1)
            }
            Self::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1 => {
                Some(Self::GateAccountCommandIssueSessionGrantV1)
            }
            Self::GATE_ACCOUNT_COMMAND_LOGOUT_V1 => Some(Self::GateAccountCommandLogoutV1),
            Self::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1 => {
                Some(Self::GateAccountCommandPairAgentKeyV1)
            }
            Self::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1 => Some(Self::GateAccountCommandPairDeviceV1),
            Self::GATE_ACCOUNT_COMMAND_REFRESH_SESSION_GRANT_V1 => {
                Some(Self::GateAccountCommandRefreshSessionGrantV1)
            }
            Self::GATE_ACCOUNT_COMMAND_REGISTER_V1 => Some(Self::GateAccountCommandRegisterV1),
            Self::GATE_ACCOUNT_COMMAND_REQUEST_ERASURE_V1 => {
                Some(Self::GateAccountCommandRequestErasureV1)
            }
            Self::GATE_ACCOUNT_COMMAND_REVOKE_SESSION_V1 => {
                Some(Self::GateAccountCommandRevokeSessionV1)
            }
            Self::GATE_ACCOUNT_EXCHANGE_CREATE_HANDOFF_V1 => {
                Some(Self::GateAccountExchangeCreateHandoffV1)
            }
            Self::GATE_ACCOUNT_READ_CLAIM_DEVICE_PAIRING_CODE_V1 => {
                Some(Self::GateAccountReadClaimDevicePairingCodeV1)
            }
            Self::GATE_ACCOUNT_READ_ONBOARDING_V1 => Some(Self::GateAccountReadOnboardingV1),
            Self::OPEN_AGENT_PAIRING_COMMAND_SUBMIT_RUNTIME_KEY_REQUEST_V1 => {
                Some(Self::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1)
            }
            Self::OPEN_AGENT_PAIRING_READ_RESOLVE_V1 => Some(Self::OpenAgentPairingReadResolveV1),
            Self::OPEN_AGENT_PAIRING_READ_RUNTIME_KEY_REQUEST_STATUS_V1 => {
                Some(Self::OpenAgentPairingReadRuntimeKeyRequestStatusV1)
            }
            Self::OPEN_DEVICE_PAIRING_COMMAND_STAGE_V1 => {
                Some(Self::OpenDevicePairingCommandStageV1)
            }
            Self::OPEN_DEVICE_PAIRING_READ_RESOLVE_V1 => Some(Self::OpenDevicePairingReadResolveV1),
            Self::OPEN_DEVICE_PAIRING_READ_STATUS_V1 => Some(Self::OpenDevicePairingReadStatusV1),
            Self::OPEN_IDENTITY_READ_RESOLUTION_V1 => Some(Self::OpenIdentityReadResolutionV1),
            Self::OPEN_INVITE_LOCATOR_READ_RESOLVE_V1 => Some(Self::OpenInviteLocatorReadResolveV1),
            Self::OPEN_MIMI_COMMAND_NOTIFY_V1 => Some(Self::OpenMimiCommandNotifyV1),
            Self::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1 => Some(Self::OpenMimiCommandProxyDownloadV1),
            Self::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1 => Some(Self::OpenMimiCommandReportAbuseV1),
            Self::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1 => {
                Some(Self::OpenMimiCommandRequestConsentV1)
            }
            Self::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE_V1 => Some(Self::OpenMimiCommandSubmitMessageV1),
            Self::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1 => Some(Self::OpenMimiCommandUpdateConsentV1),
            Self::OPEN_MIMI_COMMAND_UPDATE_ROOM_V1 => Some(Self::OpenMimiCommandUpdateRoomV1),
            Self::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1 => {
                Some(Self::OpenMimiExchangeRequestKeyMaterialV1)
            }
            Self::OPEN_MIMI_READ_IDENTIFIERS_V1 => Some(Self::OpenMimiReadIdentifiersV1),
            Self::OPEN_MIMI_READ_PROVIDER_DIRECTORY_V1 => {
                Some(Self::OpenMimiReadProviderDirectoryV1)
            }
            Self::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1 => Some(Self::OpenRealmAuthorityReadBundleV1),
            Self::OPEN_SERVICE_READ_RESOLUTION_V1 => Some(Self::OpenServiceReadResolutionV1),
            Self::OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1 => {
                Some(Self::OpenThirdPartyInviteCommandActivateV1)
            }
            Self::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1 => {
                Some(Self::OpenThirdPartyInviteCommandPresentTokenV1)
            }
            Self::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1 => {
                Some(Self::OpenThirdPartyInviteCommandProvisionV1)
            }
            Self::OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1 => {
                Some(Self::OpenThirdPartyInviteReadProvisioningStatusV1)
            }
            Self::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1 => {
                Some(Self::PeerAccountStatusCommandSubmitV1)
            }
            Self::PEER_ACCOUNT_STATUS_READ_RESOLVE_V1 => Some(Self::PeerAccountStatusReadResolveV1),
            Self::PEER_COMMITTED_EVENT_READ_SCAN_V1 => Some(Self::PeerCommittedEventReadScanV1),
            Self::PEER_CONTACTS_COMMAND_SUBMIT_V1 => Some(Self::PeerContactsCommandSubmitV1),
            Self::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1 => {
                Some(Self::PeerErasureReceiptCommandSubmitV1)
            }
            Self::PEER_ERASURE_RECEIPT_RESOURCE_GET_V1 => {
                Some(Self::PeerErasureReceiptResourceGetV1)
            }
            Self::PEER_EVENTS_COMMAND_SUBMIT_V1 => Some(Self::PeerEventsCommandSubmitV1),
            Self::PEER_INVITES_COMMAND_SUBMIT_V1 => Some(Self::PeerInvitesCommandSubmitV1),
            Self::PEER_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1 => {
                Some(Self::PeerKeysKeypackagesCommandClaimV1)
            }
            Self::PEER_KEYS_KEYPACKAGES_READ_CLAIM_V1 => Some(Self::PeerKeysKeypackagesReadClaimV1),
            Self::PEER_KEYS_READ_LOOKUP_V1 => Some(Self::PeerKeysReadLookupV1),
            Self::PEER_MLS_COMMAND_ATTEST_ADD_V1 => Some(Self::PeerMlsCommandAttestAddV1),
            Self::PEER_MLS_READ_GROUP_STATE_MATERIAL_V1 => {
                Some(Self::PeerMlsReadGroupStateMaterialV1)
            }
            Self::PEER_MLS_READ_ROSTER_AUTHORITY_V1 => Some(Self::PeerMlsReadRosterAuthorityV1),
            Self::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1 => {
                Some(Self::PeerRealmAuthorityCommandHandoffV1)
            }
            Self::PEER_REALM_JOIN_READ_BOOTSTRAP_V1 => Some(Self::PeerRealmJoinReadBootstrapV1),
            Self::PEER_REALM_JOIN_READ_PREVIEW_V1 => Some(Self::PeerRealmJoinReadPreviewV1),
            Self::PEER_SIGNAL_COMMAND_RELAY_V1 => Some(Self::PeerSignalCommandRelayV1),
            Self::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1 => {
                Some(Self::RootIdentityCommandSubmitDidOperationV1)
            }
            Self::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET_V1 => {
                Some(Self::RootIdentityDocumentResourceGetV1)
            }
            Self::ROOT_IDENTITY_LOG_READ_LIST_V1 => Some(Self::RootIdentityLogReadListV1),
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_ENSURE_V1 => {
                Some(Self::RootIdentityOrganizationRegistrationCommandEnsureV1)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_PREPARE_V1 => {
                Some(Self::RootIdentityOrganizationRegistrationCommandPrepareV1)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REFRESH_V1 => {
                Some(Self::RootIdentityOrganizationRegistrationCommandRefreshV1)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_COMMAND_REVOKE_V1 => {
                Some(Self::RootIdentityOrganizationRegistrationCommandRevokeV1)
            }
            Self::ROOT_IDENTITY_ORGANIZATION_REGISTRATION_RESOURCE_GET_V1 => {
                Some(Self::RootIdentityOrganizationRegistrationResourceGetV1)
            }
            Self::ROOT_IDENTITY_READ_RESOLVE_V1 => Some(Self::RootIdentityReadResolveV1),
            Self::ROOT_IDENTITY_RECEIPTS_READ_LIST_V1 => Some(Self::RootIdentityReceiptsReadListV1),
            Self::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1 => {
                Some(Self::RootIdentityRecoveryPolicyCommandPublishV1)
            }
            Self::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1 => {
                Some(Self::RootIdentityRecoveryPolicyResourceGetV1)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1 => {
                Some(Self::RootIdentityRecoverySessionCommandCreateV1)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1 => {
                Some(Self::RootIdentityRecoverySessionCommandSubmitProofV1)
            }
            Self::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1 => {
                Some(Self::RootIdentityRecoverySessionResourceGetV1)
            }
            Self::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE_V1 => {
                Some(Self::RootIdentityRegistryReadDescribeV1)
            }
            Self::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1 => {
                Some(Self::RootIdentityServiceRegistrationCommandEnsureV1)
            }
            Self::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET_V1 => {
                Some(Self::RootIdentityServiceRegistrationResourceGetV1)
            }
            Self::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1 => {
                Some(Self::SelfAccountCommandRevokeCursorV1)
            }
            Self::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1 => {
                Some(Self::SelfAccountCommandUpdateProfileV1)
            }
            Self::SELF_ACCOUNT_READ_DESCRIBE_V1 => Some(Self::SelfAccountReadDescribeV1),
            Self::SELF_ACCOUNT_READ_VIEWER_V1 => Some(Self::SelfAccountReadViewerV1),
            Self::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1 => Some(Self::SelfAccountStreamSubscribeV1),
            Self::SELF_ACCOUNT_DATA_READ_LIST_V1 => Some(Self::SelfAccountDataReadListV1),
            Self::SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1 => {
                Some(Self::SelfAccountDataResourceDeleteV1)
            }
            Self::SELF_ACCOUNT_DATA_RESOURCE_GET_V1 => Some(Self::SelfAccountDataResourceGetV1),
            Self::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1 => {
                Some(Self::SelfAccountDataResourceReplaceV1)
            }
            Self::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1 => {
                Some(Self::SelfActorPrivateEventsCommandSubmitV1)
            }
            Self::SELF_ACTOR_PROFILE_READ_RESOLVE_V1 => Some(Self::SelfActorProfileReadResolveV1),
            Self::SELF_AGENT_COMMAND_DEACTIVATE_V1 => Some(Self::SelfAgentCommandDeactivateV1),
            Self::SELF_AGENT_COMMAND_PAUSE_V1 => Some(Self::SelfAgentCommandPauseV1),
            Self::SELF_AGENT_COMMAND_PROVISION_V1 => Some(Self::SelfAgentCommandProvisionV1),
            Self::SELF_AGENT_COMMAND_RENEW_PAIRING_V1 => Some(Self::SelfAgentCommandRenewPairingV1),
            Self::SELF_AGENT_COMMAND_RESUME_V1 => Some(Self::SelfAgentCommandResumeV1),
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_GET_V1 => {
                Some(Self::SelfAgentParticipationResourceGetV1)
            }
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1 => {
                Some(Self::SelfAgentParticipationResourceReplaceV1)
            }
            Self::SELF_AGENT_READ_LIST_V1 => Some(Self::SelfAgentReadListV1),
            Self::SELF_AGENT_RESOURCE_GET_V1 => Some(Self::SelfAgentResourceGetV1),
            Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1 => {
                Some(Self::SelfAgentSidecarCommandEnsureV1)
            }
            Self::SELF_AGENT_SIDECAR_READ_LIST_V1 => Some(Self::SelfAgentSidecarReadListV1),
            Self::SELF_AGENT_SIDECAR_RESOURCE_GET_V1 => Some(Self::SelfAgentSidecarResourceGetV1),
            Self::SELF_APPLET_COMMAND_INSTALL_V1 => Some(Self::SelfAppletCommandInstallV1),
            Self::SELF_APPLET_COMMAND_REVOKE_V1 => Some(Self::SelfAppletCommandRevokeV1),
            Self::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1 => {
                Some(Self::SelfAppletGhostCommandPreviewV1)
            }
            Self::SELF_APPLET_GHOST_COMMAND_PROVISION_V1 => {
                Some(Self::SelfAppletGhostCommandProvisionV1)
            }
            Self::SELF_APPLET_INSTALL_COMMAND_CANCEL_V1 => {
                Some(Self::SelfAppletInstallCommandCancelV1)
            }
            Self::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1 => {
                Some(Self::SelfAppletInstallCommandPreviewV1)
            }
            Self::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1 => {
                Some(Self::SelfAppletRevokeCommandPreviewV1)
            }
            Self::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1 => Some(Self::SelfAuthzGrantsReadEffectiveV1),
            Self::SELF_AUTHZ_INVITES_READ_LIST_V1 => Some(Self::SelfAuthzInvitesReadListV1),
            Self::SELF_AUTHZ_READ_CHECK_V1 => Some(Self::SelfAuthzReadCheckV1),
            Self::SELF_BLOB_COMMAND_PRESIGN_V1 => Some(Self::SelfBlobCommandPresignV1),
            Self::SELF_BLOB_RESOURCE_GET_V1 => Some(Self::SelfBlobResourceGetV1),
            Self::SELF_BLOB_RESOURCE_HEAD_V1 => Some(Self::SelfBlobResourceHeadV1),
            Self::SELF_BLOB_UPLOAD_CREATE_V1 => Some(Self::SelfBlobUploadCreateV1),
            Self::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1 => {
                Some(Self::SelfCallMediaExchangeIssueTokenV1)
            }
            Self::SELF_CIRCLE_COMMAND_CREATE_V1 => Some(Self::SelfCircleCommandCreateV1),
            Self::SELF_CIRCLE_COMMAND_ROTATE_SCOPE_V1 => Some(Self::SelfCircleCommandRotateScopeV1),
            Self::SELF_CIRCLE_MEMBER_COMMAND_ADD_V1 => Some(Self::SelfCircleMemberCommandAddV1),
            Self::SELF_CIRCLE_MEMBER_RESOURCE_DELETE_V1 => {
                Some(Self::SelfCircleMemberResourceDeleteV1)
            }
            Self::SELF_CIRCLE_READ_LIST_V1 => Some(Self::SelfCircleReadListV1),
            Self::SELF_CIRCLE_RESOURCE_GET_V1 => Some(Self::SelfCircleResourceGetV1),
            Self::SELF_COMMITTED_EVENT_READ_SCAN_V1 => Some(Self::SelfCommittedEventReadScanV1),
            Self::SELF_COMMITTED_EVENT_RESOURCE_GET_V1 => {
                Some(Self::SelfCommittedEventResourceGetV1)
            }
            Self::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1 => {
                Some(Self::SelfCommittedEventStreamSubscribeV1)
            }
            Self::SELF_CONSENT_COMMAND_GRANT_V1 => Some(Self::SelfConsentCommandGrantV1),
            Self::SELF_CONSENT_COMMAND_REQUEST_V1 => Some(Self::SelfConsentCommandRequestV1),
            Self::SELF_CONSENT_COMMAND_REVOKE_V1 => Some(Self::SelfConsentCommandRevokeV1),
            Self::SELF_CONSENT_READ_LIST_V1 => Some(Self::SelfConsentReadListV1),
            Self::SELF_CONSENT_RESOURCE_GET_V1 => Some(Self::SelfConsentResourceGetV1),
            Self::SELF_CONTACT_COMMAND_CHECKPOINT_V1 => Some(Self::SelfContactCommandCheckpointV1),
            Self::SELF_CONTACT_COMMAND_REJECT_V1 => Some(Self::SelfContactCommandRejectV1),
            Self::SELF_CONTACT_COMMAND_REQUEST_V1 => Some(Self::SelfContactCommandRequestV1),
            Self::SELF_CONTACT_COMMAND_RESPOND_V1 => Some(Self::SelfContactCommandRespondV1),
            Self::SELF_CONTACT_COMMAND_SCOPE_UPDATE_V1 => {
                Some(Self::SelfContactCommandScopeUpdateV1)
            }
            Self::SELF_CONTACT_COMMAND_TOMBSTONE_V1 => Some(Self::SelfContactCommandTombstoneV1),
            Self::SELF_CONTACT_READ_LIST_V1 => Some(Self::SelfContactReadListV1),
            Self::SELF_CURRENT_PRINCIPAL_READ_RESOLVE_V1 => {
                Some(Self::SelfCurrentPrincipalReadResolveV1)
            }
            Self::SELF_CURRENT_RESULTS_READ_EXACT_V1 => Some(Self::SelfCurrentResultsReadExactV1),
            Self::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1 => Some(Self::SelfDeviceMessagesCommandAckV1),
            Self::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1 => {
                Some(Self::SelfDeviceMessagesCommandSendV1)
            }
            Self::SELF_DEVICE_MESSAGES_READ_LIST_V1 => Some(Self::SelfDeviceMessagesReadListV1),
            Self::SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1 => {
                Some(Self::SelfDirectConversationReadResolveV1)
            }
            Self::SELF_EVENTS_COMMAND_SUBMIT_V1 => Some(Self::SelfEventsCommandSubmitV1),
            Self::SELF_EVENTS_READ_DELIVERY_STATUS_V1 => Some(Self::SelfEventsReadDeliveryStatusV1),
            Self::SELF_IDENTITY_READ_RESOLUTION_AUDIT_V1 => {
                Some(Self::SelfIdentityReadResolutionAuditV1)
            }
            Self::SELF_INVITE_LOCATOR_COMMAND_ISSUE_V1 => {
                Some(Self::SelfInviteLocatorCommandIssueV1)
            }
            Self::SELF_INVITE_LOCATOR_COMMAND_REVOKE_V1 => {
                Some(Self::SelfInviteLocatorCommandRevokeV1)
            }
            Self::SELF_INVITE_LOCATOR_COMMAND_ROTATE_V1 => {
                Some(Self::SelfInviteLocatorCommandRotateV1)
            }
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1 => {
                Some(Self::SelfInviteReceivePolicyResourceGetV1)
            }
            Self::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1 => {
                Some(Self::SelfInviteReceivePolicyResourceReplaceV1)
            }
            Self::SELF_INVITES_COMMAND_DISPATCH_V1 => Some(Self::SelfInvitesCommandDispatchV1),
            Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_DELETE_CHALLENGE_V1 => {
                Some(Self::SelfKeysBackupsCommandIssueDeleteChallengeV1)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_ISSUE_UNLOCK_CHALLENGE_V1 => {
                Some(Self::SelfKeysBackupsCommandIssueUnlockChallengeV1)
            }
            Self::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1 => Some(Self::SelfKeysBackupsCommandUnlockV1),
            Self::SELF_KEYS_BACKUPS_READ_LIST_V1 => Some(Self::SelfKeysBackupsReadListV1),
            Self::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1 => {
                Some(Self::SelfKeysBackupsResourceDeleteV1)
            }
            Self::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1 => {
                Some(Self::SelfKeysBackupsResourceReplaceV1)
            }
            Self::SELF_KEYS_COMMAND_CLAIM_V1 => Some(Self::SelfKeysCommandClaimV1),
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1 => {
                Some(Self::SelfKeysKeypackagesCommandClaimV1)
            }
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1 => {
                Some(Self::SelfKeysKeypackagesCommandConsumeV1)
            }
            Self::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1 => {
                Some(Self::SelfKeysKeypackagesCommandRevokeV1)
            }
            Self::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1 => Some(Self::SelfKeysKeypackagesReadClaimV1),
            Self::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1 => {
                Some(Self::SelfKeysKeypackagesUploadCreateV1)
            }
            Self::SELF_KEYS_READ_LOOKUP_V1 => Some(Self::SelfKeysReadLookupV1),
            Self::SELF_KEYS_UPLOAD_CREATE_V1 => Some(Self::SelfKeysUploadCreateV1),
            Self::SELF_MEDIA_READ_ICE_CONFIG_V1 => Some(Self::SelfMediaReadIceConfigV1),
            Self::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1 => {
                Some(Self::SelfMediaServiceBindingReadResolveV1)
            }
            Self::SELF_MESSAGES_COMMAND_PREPARE_V1 => Some(Self::SelfMessagesCommandPrepareV1),
            Self::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1 => {
                Some(Self::SelfMlsReadGroupStateMaterialV1)
            }
            Self::SELF_MLS_READ_ROSTER_AUTHORITY_V1 => Some(Self::SelfMlsReadRosterAuthorityV1),
            Self::SELF_MODERATION_COMMAND_REPORT_V1 => Some(Self::SelfModerationCommandReportV1),
            Self::SELF_MORPH_READ_LIST_V1 => Some(Self::SelfMorphReadListV1),
            Self::SELF_MORPH_RESOURCE_GET_V1 => Some(Self::SelfMorphResourceGetV1),
            Self::SELF_READ_CURSOR_COMMAND_ADVANCE_V1 => Some(Self::SelfReadCursorCommandAdvanceV1),
            Self::SELF_READ_CURSOR_READ_LIST_V1 => Some(Self::SelfReadCursorReadListV1),
            Self::SELF_REALM_READ_EXPORT_V1 => Some(Self::SelfRealmReadExportV1),
            Self::SELF_REALM_READ_STREAMS_V1 => Some(Self::SelfRealmReadStreamsV1),
            Self::SELF_REALM_RESOURCE_GET_V1 => Some(Self::SelfRealmResourceGetV1),
            Self::SELF_REALM_JOIN_COMMAND_PREPARE_V1 => Some(Self::SelfRealmJoinCommandPrepareV1),
            Self::SELF_REALM_JOIN_READ_PREVIEW_V1 => Some(Self::SelfRealmJoinReadPreviewV1),
            Self::SELF_REALM_LINK_READ_LIST_V1 => Some(Self::SelfRealmLinkReadListV1),
            Self::SELF_REALM_ORGANIZATION_READ_LIST_V1 => {
                Some(Self::SelfRealmOrganizationReadListV1)
            }
            Self::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1 => {
                Some(Self::SelfRealmStateSnapshotReadByRefV1)
            }
            Self::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1 => {
                Some(Self::SelfRealmStateSnapshotReadManifestHeadV1)
            }
            Self::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1 => {
                Some(Self::SelfSecurityTransactionCommandContinueV1)
            }
            Self::SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1 => {
                Some(Self::SelfSecurityTransactionCommandCreateV1)
            }
            Self::SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1 => {
                Some(Self::SelfSecurityTransactionResourceGetV1)
            }
            Self::SELF_SIGNAL_COMMAND_SEND_V1 => Some(Self::SelfSignalCommandSendV1),
            Self::SELF_SIGNAL_STREAM_SUBSCRIBE_V1 => Some(Self::SelfSignalStreamSubscribeV1),
            Self::SELF_SIGNER_KEYS_READ_RESOLVE_V1 => Some(Self::SelfSignerKeysReadResolveV1),
            Self::SELF_SPACE_READ_LIST_V1 => Some(Self::SelfSpaceReadListV1),
            Self::SELF_STRAND_READ_LIST_V1 => Some(Self::SelfStrandReadListV1),
            Self::SELF_STRAND_WATCH_READ_CURRENT_V1 => Some(Self::SelfStrandWatchReadCurrentV1),
            Self::SELF_THIRD_PARTY_INVITE_READ_ACCEPTANCE_ATTESTATION_V1 => {
                Some(Self::SelfThirdPartyInviteReadAcceptanceAttestationV1)
            }
            Self::SERVER_READ_DESCRIBE_V1 => Some(Self::ServerReadDescribeV1),
            _ => None,
        }
    }

    pub fn from_grpc(value: &str) -> Option<Self> {
        SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.grpc == Some(value))
            .map(|descriptor| descriptor.id)
    }

    pub fn from_mq_topic(value: &str) -> Option<Self> {
        SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.mq == Some(value))
            .map(|descriptor| descriptor.id)
    }

    pub fn from_http_request(method: &str, path: &str) -> Option<Self> {
        let specificity = SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .filter(|descriptor| {
                descriptor.http_method == method
                    && http_path_template_matches(descriptor.http_path, path)
            })
            .map(|descriptor| {
                descriptor
                    .http_path
                    .bytes()
                    .filter(|byte| *byte == b'{')
                    .count()
            })
            .min()?;
        let mut matches = SERVICE_OPERATION_DESCRIPTORS.iter().filter(|descriptor| {
            descriptor.http_method == method
                && http_path_template_matches(descriptor.http_path, path)
                && descriptor
                    .http_path
                    .bytes()
                    .filter(|byte| *byte == b'{')
                    .count()
                    == specificity
        });
        let selected = matches.next()?.id;
        matches.next().is_none().then_some(selected)
    }

    pub fn matches_http_request(self, method: &str, path: &str) -> bool {
        let descriptor = self.descriptor();
        descriptor.http_method == method && http_path_template_matches(descriptor.http_path, path)
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

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for ServiceOperationId {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .enum_values(Self::ALL.iter().map(|value| value.as_str()))
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for ServiceOperationId {
    fn compose(
        components: &mut salvo_oapi::Components,
        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        let _ = generics;
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}

pub const SERVICE_OPERATION_DESCRIPTORS: &[ServiceOperationDescriptor] = &[
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletActorReadResolveV1,
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
        id: ServiceOperationId::EdgeAppletClientCommandExchangeV1,
        http_method: "POST",
        http_path: "/_arkret/edge/applet/client/exchange",
        grpc: Some("EdgeApplet/ClientExchange"),
        mq: Some("edge.applet.client.command.exchange"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-client-operations.schema.json#/$defs/exchange_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-client-operations.schema.json#/$defs/exchange_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "Durable local request, bundle, queue and ack ledger only; Events retain dedicated admission.",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletCommandTransactionV1,
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
        id: ServiceOperationId::EdgeAppletManagedActorCommandAuthorV1,
        http_method: "POST",
        http_path: "/_arkret/edge/applet/managed-actors/author",
        grpc: Some("EdgeApplet/ManagedActorAuthor"),
        mq: Some("edge.applet.managed_actor.command.author"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-authoring.schema.json#/$defs/author_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-install-authoring.schema.json#/$defs/author_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "The operation admits no Arkret Event; independently, the Applet service atomically persists the subject/request-digest ledger, exact request and bundle, Applet Service signer root, actor key custody, method history, and provision state before returning",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletReadDescribeV1,
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
        response_schema_ref: Some("schemas/service-describe.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletReadPingV1,
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
        id: ServiceOperationId::EdgeAppletReadProtocolMetadataV1,
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
        id: ServiceOperationId::EdgeAppletRealmReadResolveV1,
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
        id: ServiceOperationId::EdgeAppletThirdPartyLocationsReadListV1,
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
        id: ServiceOperationId::EdgeAppletThirdPartyUsersReadListV1,
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
        id: ServiceOperationId::EdgePushCommandApplyRegistrationV1,
        http_method: "POST",
        http_path: "/_arkret/edge/push/registrations:apply",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_registration_handoff_request_body",
        ),
        response_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_registration_handoff_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.edge.push.command.apply_registration.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_gateway_local_provider_route_tenant_tombstone_and_signed_installation_receipt",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandNotifyV1,
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
        id: ServiceOperationId::EdgePushCommandRegisterDeviceV1,
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
        id: ServiceOperationId::EdgePushCommandUnregisterDeviceV1,
        http_method: "POST",
        http_path: "/_arkret/edge/push/unregister-device",
        grpc: Some("EdgePush/UnregisterDevice"),
        mq: Some("edge.push.command.unregister_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "empty_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_unregister_device_request_body",
        ),
        response_schema_ref: None,
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadDescribeV1,
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
        response_schema_ref: Some("schemas/service-describe.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryReadResolveRealmV1,
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
        id: ServiceOperationId::FindDirectoryReadSearchRealmsV1,
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
        id: ServiceOperationId::GateAccountCommandAbandonIdentityCreationV1,
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
        id: ServiceOperationId::GateAccountCommandFinalizeDevicePairingV1,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-pairing/finalizations",
        grpc: Some("GateAccount/FinalizeDevicePairing"),
        mq: Some("gate.account.command.finalize_device_pairing"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_finalize_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_finalize_outcome",
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
        id: ServiceOperationId::GateAccountCommandIssueDidBindingChallengeV1,
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
        id: ServiceOperationId::GateAccountCommandIssueIdentityBindingChallengeV1,
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
        id: ServiceOperationId::GateAccountCommandIssueRecoveryCompletionGrantV1,
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
        id: ServiceOperationId::GateAccountCommandIssueSessionGrantV1,
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
            "{\"operation_id\":\"ak.gate.account.command.issue_session_grant.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandLogoutV1,
        http_method: "POST",
        http_path: "/_arkret/gate/account/logout",
        grpc: None,
        mq: None,
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountLogoutRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/AccountLogoutOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.logout.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPairAgentKeyV1,
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
        id: ServiceOperationId::GateAccountCommandPairDeviceV1,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-pair",
        grpc: Some("GateAccount/DevicePair"),
        mq: Some("gate.account.command.pair_device"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_pair_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_pair_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.device.authorize"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRefreshSessionGrantV1,
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
            "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantOutcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.gate.account.command.refresh_session_grant.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRegisterV1,
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
            "{\"operation_id\":\"ak.gate.account.command.register.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_expired\",\"session_grant_replay_terminal\",\"session_grant_replay_indeterminate\"]}",
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
        id: ServiceOperationId::GateAccountCommandRequestErasureV1,
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
        id: ServiceOperationId::GateAccountCommandRevokeSessionV1,
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
            "{\"operation_id\":\"ak.gate.account.command.revoke_session.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\",\"terminal_outcomes\":[\"session_grant_replay_indeterminate\"]}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountExchangeCreateHandoffV1,
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
        id: ServiceOperationId::GateAccountReadClaimDevicePairingCodeV1,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-pairing/code-claims",
        grpc: Some("GateAccount/ClaimDevicePairingCode"),
        mq: Some("gate.account.query.claim_device_pairing_code"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_code_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/device-pairing.schema.json#/$defs/device_pairing_code_claim_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountReadOnboardingV1,
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
            "schemas/account-operations.schema.json#/$defs/account_onboarding_state",
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
        id: ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1,
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
        id: ServiceOperationId::OpenAgentPairingReadResolveV1,
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
        id: ServiceOperationId::OpenAgentPairingReadRuntimeKeyRequestStatusV1,
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
        id: ServiceOperationId::OpenDevicePairingCommandStageV1,
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
            "{\"operation_id\":\"ak.open.device_pairing.command.stage.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenDevicePairingReadResolveV1,
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
        id: ServiceOperationId::OpenDevicePairingReadStatusV1,
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
        id: ServiceOperationId::OpenIdentityReadResolutionV1,
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
        id: ServiceOperationId::OpenInviteLocatorReadResolveV1,
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
        id: ServiceOperationId::OpenMimiCommandNotifyV1,
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
        id: ServiceOperationId::OpenMimiCommandProxyDownloadV1,
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
            "{\"operation_id\":\"ak.open.mimi.command.proxy_download.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandReportAbuseV1,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/report-abuse",
        grpc: Some("OpenMimi/ReportAbuse"),
        mq: Some("open.mimi.command.report_abuse"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_request_body",
        ),
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_outcome",
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
        id: ServiceOperationId::OpenMimiCommandRequestConsentV1,
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
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandSubmitMessageV1,
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
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandUpdateConsentV1,
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
        id: ServiceOperationId::OpenMimiCommandUpdateRoomV1,
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
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
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
        id: ServiceOperationId::OpenMimiExchangeRequestKeyMaterialV1,
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
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiReadIdentifiersV1,
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
        id: ServiceOperationId::OpenMimiReadProviderDirectoryV1,
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
        id: ServiceOperationId::OpenRealmAuthorityReadBundleV1,
        http_method: "POST",
        http_path: "/_arkret/open/realm-authority/bundle",
        grpc: Some("OpenRealmAuthority/Bundle"),
        mq: Some("open.realm_authority.read.bundle"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/authority_bundle_request",
        ),
        response_schema_ref: Some("schemas/realm-authority-bundle.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenServiceReadResolutionV1,
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
            "schemas/identity-resolution.schema.json#/$defs/authenticated_service_resolution",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenThirdPartyInviteCommandActivateV1,
        http_method: "POST",
        http_path: "/_arkret/open/third-party-invites/activate",
        grpc: Some("OpenThirdPartyInvite/Activate"),
        mq: Some("open.third_party_invite.command.activate"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_activation_request_body",
        ),
        response_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_activation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "persists_only_the_verification_service_private_invite_binding_and_delivery_intent_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenThirdPartyInviteCommandPresentTokenV1,
        http_method: "POST",
        http_path: "/_arkret/open/third-party-invites/present",
        grpc: Some("OpenThirdPartyInvite/PresentToken"),
        mq: Some("open.third_party_invite.command.present_token"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_present_request_body",
        ),
        response_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_present_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.third_party_invite.command.present_token.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenThirdPartyInviteCommandProvisionV1,
        http_method: "POST",
        http_path: "/_arkret/open/third-party-invites/provision",
        grpc: Some("OpenThirdPartyInvite/Provision"),
        mq: Some("open.third_party_invite.command.provision"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_provision_request_body",
        ),
        response_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_provision_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.open.third_party_invite.command.provision.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "mints_and_persists_only_verification_service_private_invite_material_no_event_is_authored",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenThirdPartyInviteReadProvisioningStatusV1,
        http_method: "POST",
        http_path: "/_arkret/open/third-party-invites/status",
        grpc: Some("OpenThirdPartyInvite/ProvisioningStatus"),
        mq: Some("open.third_party_invite.query.provisioning_status"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_provisioning_status_request_body",
        ),
        response_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_provisioning_status_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerAccountStatusCommandSubmitV1,
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
        id: ServiceOperationId::PeerAccountStatusReadResolveV1,
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
        id: ServiceOperationId::PeerCommittedEventReadScanV1,
        http_method: "POST",
        http_path: "/_arkret/peer/streams/scan",
        grpc: Some("PeerStreams/Scan"),
        mq: Some("peer.streams.read.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_request",
        ),
        response_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerContactsCommandSubmitV1,
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
        id: ServiceOperationId::PeerErasureReceiptCommandSubmitV1,
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
                "accepts_a_signed_terminal_outcome_and_never_triggers_erasure_or_authors_an_event",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerErasureReceiptResourceGetV1,
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
        id: ServiceOperationId::PeerEventsCommandSubmitV1,
        http_method: "POST",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Submit"),
        mq: Some("peer.events.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::Branched,
            target: None,
            rationale: None,
            branch_contract_json: Some(
                "{\"discriminator\":{\"description\":\"Closed peer ingress semantic branch. Schema validation proves that final otherwise can only be registered_atomic_unit.\",\"request_path\":\"/branch\"},\"effect_branches\":[{\"effect\":{\"event_kind_sources\":[\"$request.event_submission.event.kind\",\"$request.mls_submission.commit_event.kind\"],\"event_submission_path\":\"/event_submission\",\"kind\":\"event_log\",\"rationale\":\"Only the verified current governance Station performs first admission and signs the new RealmCommit.\"},\"equals\":\"authority_forward\"},{\"effect\":{\"kind\":\"none\",\"rationale\":\"stores_exact_source_committed_replicas_without_new_event_finality_resigning_or_second_fanout\"},\"equals\":\"committed_replication\"},{\"effect\":{\"kind\":\"none\",\"rationale\":\"atomically_materializes_a_registered_source_committed_unit_without_new_event_finality_resigning_or_second_fanout\"},\"otherwise\":true}]}",
            ),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerInvitesCommandSubmitV1,
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
        id: ServiceOperationId::PeerKeysKeypackagesCommandClaimV1,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/keypackages/claim",
        grpc: Some("PeerKeys/KeyPackagesClaim"),
        mq: Some("peer.keys.keypackages.command.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/peer_keypackages_claim_command_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.peer.keys.keypackages.command.claim.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesReadClaimV1,
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
        id: ServiceOperationId::PeerKeysReadLookupV1,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/query",
        grpc: Some("PeerKeys/Query"),
        mq: Some("peer.keys.query.lookup"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/peer_keys_query_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/peer_keys_query_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerMlsCommandAttestAddV1,
        http_method: "POST",
        http_path: "/_arkret/peer/mls/add-authority-attestations",
        grpc: Some("PeerMls/AttestAdd"),
        mq: Some("peer.mls.command.attest_add"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/attest_add_request",
        ),
        response_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/attest_add_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.peer.mls.command.attest_add.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_verified_historical_mls_provenance_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerMlsReadGroupStateMaterialV1,
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
        id: ServiceOperationId::PeerMlsReadRosterAuthorityV1,
        http_method: "POST",
        http_path: "/_arkret/peer/mls/roster-authority/query",
        grpc: Some("PeerMls/RosterAuthority"),
        mq: Some("peer.mls.query.roster_authority"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/roster_read_request",
        ),
        response_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/roster_read_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerRealmAuthorityCommandHandoffV1,
        http_method: "POST",
        http_path: "/_arkret/peer/realm-authority/handoff",
        grpc: Some("PeerRealmAuthority/Handoff"),
        mq: Some("peer.realm_authority.command.handoff"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/handoff_request",
        ),
        response_schema_ref: Some("schemas/realm-authority-handoff.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "installs_only_the_verified_governance_generation_snapshot_and_private_stream_heads",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerRealmJoinReadBootstrapV1,
        http_method: "POST",
        http_path: "/_arkret/peer/realm-joins/bootstrap",
        grpc: Some("PeerRealmJoin/Bootstrap"),
        mq: Some("peer.realm_join.query.bootstrap"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/peer_bootstrap_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/peer_bootstrap_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerRealmJoinReadPreviewV1,
        http_method: "POST",
        http_path: "/_arkret/peer/realm-joins/preview",
        grpc: Some("PeerRealmJoin/Preview"),
        mq: Some("peer.realm_join.query.preview"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/peer_preview_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/peer_preview_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerSignalCommandRelayV1,
        http_method: "POST",
        http_path: "/_arkret/peer/signal",
        grpc: Some("PeerSignal/Relay"),
        mq: Some("peer.signal.command.relay"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(1048576),
        success_shape_kind: "empty_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/signal-relay.schema.json"),
        response_schema_ref: None,
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("ephemeral_signal_must_not_be_durable_event"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityCommandSubmitDidOperationV1,
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
        id: ServiceOperationId::RootIdentityDocumentResourceGetV1,
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
        id: ServiceOperationId::RootIdentityLogReadListV1,
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
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandEnsureV1,
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
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandPrepareV1,
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
            "{\"operation_id\":\"ak.root.identity.organization_registration.command.prepare.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRefreshV1,
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
        id: ServiceOperationId::RootIdentityOrganizationRegistrationCommandRevokeV1,
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
        id: ServiceOperationId::RootIdentityOrganizationRegistrationResourceGetV1,
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
        id: ServiceOperationId::RootIdentityReadResolveV1,
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
        id: ServiceOperationId::RootIdentityReceiptsReadListV1,
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
        id: ServiceOperationId::RootIdentityRecoveryPolicyCommandPublishV1,
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
        id: ServiceOperationId::RootIdentityRecoveryPolicyResourceGetV1,
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
        id: ServiceOperationId::RootIdentityRecoverySessionCommandCreateV1,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions",
        grpc: Some("RootIdentity/RecoverySessionCreate"),
        mq: Some("root.identity.recovery_session.command.create"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("request_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_create_request_body",
        ),
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_state",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.root.identity.recovery_session.command.create.v1\",\"requires_same_request_identity_and_canonical_intent\":true,\"strategy\":\"replay_same_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProofV1,
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
            "{\"operation_id\":\"ak.root.identity.recovery_session.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionResourceGetV1,
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
        id: ServiceOperationId::RootIdentityRegistryReadDescribeV1,
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
        response_schema_ref: Some("schemas/service-describe.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityServiceRegistrationCommandEnsureV1,
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
        id: ServiceOperationId::RootIdentityServiceRegistrationResourceGetV1,
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
        id: ServiceOperationId::SelfAccountCommandRevokeCursorV1,
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
        id: ServiceOperationId::SelfAccountCommandUpdateProfileV1,
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
        id: ServiceOperationId::SelfAccountReadDescribeV1,
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
        response_schema_ref: Some("schemas/service-describe.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountReadViewerV1,
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
        id: ServiceOperationId::SelfAccountStreamSubscribeV1,
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
        response_schema_ref: Some("schemas/account-subscribe-frame.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataReadListV1,
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
        id: ServiceOperationId::SelfAccountDataResourceDeleteV1,
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
        id: ServiceOperationId::SelfAccountDataResourceGetV1,
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
        id: ServiceOperationId::SelfAccountDataResourceReplaceV1,
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
        id: ServiceOperationId::SelfActorPrivateEventsCommandSubmitV1,
        http_method: "POST",
        http_path: "/_arkret/self/actor-private-events",
        grpc: Some("SelfActorPrivateEvents/Submit"),
        mq: Some("self.actor_private_events.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::Branched,
            target: None,
            rationale: None,
            branch_contract_json: Some(
                "{\"discriminator\":{\"description\":\"The kind of the submitted actor-private Event; each branch writes only that kind's registered private effect.\",\"request_path\":\"/event/kind\"},\"effect_branches\":[{\"effect\":{\"event_kind\":\"ak.agent.action_reject\",\"kind\":\"actor_private_event\"},\"equals\":\"ak.agent.action_reject\"},{\"effect\":{\"event_kind\":\"ak.agent.action_request\",\"kind\":\"actor_private_event\"},\"equals\":\"ak.agent.action_request\"},{\"effect\":{\"event_kind\":\"ak.agent.draft.propose\",\"kind\":\"actor_private_event\"},\"equals\":\"ak.agent.draft.propose\"},{\"effect\":{\"event_kind\":\"ak.device.push_route\",\"kind\":\"actor_private_event\"},\"otherwise\":true}]}",
            ),
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfActorProfileReadResolveV1,
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
        id: ServiceOperationId::SelfAgentCommandDeactivateV1,
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
            "{\"operation_id\":\"ak.self.agent.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.deactivate"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandPauseV1,
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
            "{\"operation_id\":\"ak.self.agent.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.pause"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandProvisionV1,
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
        id: ServiceOperationId::SelfAgentCommandRenewPairingV1,
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
            "{\"operation_id\":\"ak.self.agent.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandResumeV1,
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
            "{\"operation_id\":\"ak.self.agent.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.self.agent.resume"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationResourceGetV1,
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
        id: ServiceOperationId::SelfAgentParticipationResourceReplaceV1,
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
        id: ServiceOperationId::SelfAgentReadListV1,
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
        id: ServiceOperationId::SelfAgentResourceGetV1,
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
        id: ServiceOperationId::SelfAgentSidecarCommandEnsureV1,
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
        id: ServiceOperationId::SelfAgentSidecarReadListV1,
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
        id: ServiceOperationId::SelfAgentSidecarResourceGetV1,
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
        id: ServiceOperationId::SelfAppletCommandInstallV1,
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
                "ak.applet.managed_actor.provision",
                "ak.realm.create",
                "ak.identity.accountability_grant",
                "ak.profile.create",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletCommandRevokeV1,
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
        id: ServiceOperationId::SelfAppletGhostCommandPreviewV1,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/ghosts/provision/preview",
        grpc: Some("SelfApplet/GhostPreview"),
        mq: Some("self.applet.ghost.command.preview"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-ghost-operations.schema.json#/$defs/ghost_preview_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-ghost-operations.schema.json#/$defs/ghost_preview_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "No Event is admitted, but the Station durably records the current subject generation and exact signed request before returning",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletGhostCommandProvisionV1,
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
                "ak.applet.managed_actor.provision",
                "ak.realm.create",
                "ak.identity.accountability_grant",
                "ak.profile.create",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletInstallCommandCancelV1,
        http_method: "POST",
        http_path: "/_arkret/self/applets/install/cancel",
        grpc: Some("SelfApplet/InstallCancel"),
        mq: Some("self.applet.install.command.cancel"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-client-operations.schema.json#/$defs/cancel_request_body",
        ),
        response_schema_ref: Some(
            "schemas/applet-client-operations.schema.json#/$defs/cancel_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "Cancel only the authenticated original installing administrator pending request; no Realm Event is admitted.",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletInstallCommandPreviewV1,
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
        response_schema_ref: Some(
            "schemas/applet-install-authoring.schema.json#/$defs/install_preview_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "No Event is admitted, but the Station atomically persists the branch-subject winner, exact unsigned payload, exact signed request, and superseded generations before returning",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletRevokeCommandPreviewV1,
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
            rationale: Some("query_only_recomputed_revoke_plan_from_one_durable_current_snapshot"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzGrantsReadEffectiveV1,
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
        id: ServiceOperationId::SelfAuthzInvitesReadListV1,
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
        id: ServiceOperationId::SelfAuthzReadCheckV1,
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
        id: ServiceOperationId::SelfBlobCommandPresignV1,
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
            "{\"operation_id\":\"ak.self.blob.command.presign.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobResourceGetV1,
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
        id: ServiceOperationId::SelfBlobResourceHeadV1,
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
        id: ServiceOperationId::SelfBlobUploadCreateV1,
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
        id: ServiceOperationId::SelfCallMediaExchangeIssueTokenV1,
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
            "{\"operation_id\":\"ak.self.call.media.exchange.issue_token.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandCreateV1,
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
            "{\"operation_id\":\"ak.self.circle.read.list.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.create"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandRotateScopeV1,
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
            "{\"operation_id\":\"ak.self.circle.resource.get.v1\",\"strategy\":\"query_operation\"}",
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
        id: ServiceOperationId::SelfCircleMemberCommandAddV1,
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
            "{\"operation_id\":\"ak.self.circle.resource.get.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.circle.member.state"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleMemberResourceDeleteV1,
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
        id: ServiceOperationId::SelfCircleReadListV1,
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
        id: ServiceOperationId::SelfCircleResourceGetV1,
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
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_read_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCommittedEventReadScanV1,
        http_method: "POST",
        http_path: "/_arkret/self/streams/scan",
        grpc: Some("SelfStreams/Scan"),
        mq: Some("self.streams.read.scan"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_request",
        ),
        response_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCommittedEventResourceGetV1,
        http_method: "GET",
        http_path: "/_arkret/self/committed-events/{event_id}",
        grpc: Some("SelfCommittedEvent/Get"),
        mq: Some("self.committed_event.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/CommittedEventView",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCommittedEventStreamSubscribeV1,
        http_method: "GET",
        http_path: "/_arkret/self/committed-events/subscribe",
        grpc: Some("SelfCommittedEvent/Subscribe"),
        mq: Some("self.committed_event.stream.subscribe"),
        body_class: Some("streaming_ndjson"),
        max_canonical_body_bytes: None,
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/committed-event-subscribe-frame.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandGrantV1,
        http_method: "POST",
        http_path: "/_arkret/self/consent/results/grant",
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
        response_schema_ref: Some("schemas/consent-operations.schema.json#/$defs/consent_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.grant"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRequestV1,
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
            "{\"operation_id\":\"ak.self.consent.read.list.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRevokeV1,
        http_method: "POST",
        http_path: "/_arkret/self/consent/results/revoke",
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
        response_schema_ref: Some("schemas/consent-operations.schema.json#/$defs/consent_view"),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.consent.read.list.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::Static(&["ak.consent.revoke"])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentReadListV1,
        http_method: "GET",
        http_path: "/_arkret/self/consent/results",
        grpc: Some("SelfConsent/List"),
        mq: Some("self.consent.query.list"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/consent-operations.schema.json#/$defs/consent_list"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentResourceGetV1,
        http_method: "GET",
        http_path: "/_arkret/self/consent/result",
        grpc: Some("SelfConsent/Get"),
        mq: Some("self.consent.resource.get"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/consent-operations.schema.json#/$defs/consent_view"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandCheckpointV1,
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
        id: ServiceOperationId::SelfContactCommandRejectV1,
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
        id: ServiceOperationId::SelfContactCommandRequestV1,
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
        id: ServiceOperationId::SelfContactCommandRespondV1,
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
        id: ServiceOperationId::SelfContactCommandScopeUpdateV1,
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
        id: ServiceOperationId::SelfContactCommandTombstoneV1,
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
        id: ServiceOperationId::SelfContactReadListV1,
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
        id: ServiceOperationId::SelfCurrentPrincipalReadResolveV1,
        http_method: "POST",
        http_path: "/_arkret/self/account/current-principal",
        grpc: Some("SelfCurrentPrincipal/Resolve"),
        mq: Some("self.current_principal.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/current_principal_request_body",
        ),
        response_schema_ref: Some(
            "schemas/identity-resolution.schema.json#/$defs/current_principal_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCurrentResultsReadExactV1,
        http_method: "POST",
        http_path: "/_arkret/self/current-results/exact",
        grpc: Some("SelfCurrentResults/ReadExact"),
        mq: Some("self.current_results.query.exact"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/exact-current-results-read.schema.json#/$defs/exact_current_results_read_request",
        ),
        response_schema_ref: Some(
            "schemas/exact-current-results-read.schema.json#/$defs/exact_current_results_read_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("read_only_exact_current_projection_no_event_or_durable_mutation"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesCommandAckV1,
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
        id: ServiceOperationId::SelfDeviceMessagesCommandSendV1,
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
        id: ServiceOperationId::SelfDeviceMessagesReadListV1,
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
        id: ServiceOperationId::SelfDirectConversationReadResolveV1,
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
        id: ServiceOperationId::SelfEventsCommandSubmitV1,
        http_method: "POST",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Submit"),
        mq: Some("self.events.command.submit"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/self_submit_request",
        ),
        response_schema_ref: Some(
            "schemas/authority-commit-operations.schema.json#/$defs/self_submit_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::EventLog,
            target: Some(DurableEventTarget::DynamicMany(&[
                "$request.event.kind",
                "$request.commit_event.kind",
                "$request.events[*].event.kind",
                "$request.event_submission.event.kind",
            ])),
            rationale: None,
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsReadDeliveryStatusV1,
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
        id: ServiceOperationId::SelfIdentityReadResolutionAuditV1,
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
        id: ServiceOperationId::SelfInviteLocatorCommandIssueV1,
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
            "{\"operation_id\":\"ak.self.invite_locator.command.issue.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandRevokeV1,
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
        id: ServiceOperationId::SelfInviteLocatorCommandRotateV1,
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
            "{\"reissue_operation_id\":\"ak.self.invite_locator.command.issue.v1\",\"requires_fresh_request_identity\":true,\"revoke_operation_id\":\"ak.self.invite_locator.command.revoke.v1\",\"strategy\":\"revoke_then_reissue\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteReceivePolicyResourceGetV1,
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
        id: ServiceOperationId::SelfInviteReceivePolicyResourceReplaceV1,
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
        id: ServiceOperationId::SelfInvitesCommandDispatchV1,
        http_method: "POST",
        http_path: "/_arkret/self/invites/dispatch",
        grpc: Some("SelfInvites/Dispatch"),
        mq: Some("self.invites.command.dispatch"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/invite-delivery-request.schema.json#/$defs/self_invite_dispatch_request_body",
        ),
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
        id: ServiceOperationId::SelfKeysBackupsCommandIssueDeleteChallengeV1,
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
        id: ServiceOperationId::SelfKeysBackupsCommandIssueUnlockChallengeV1,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backups/{backup_id}/unlock-challenge",
        grpc: Some("SelfKeys/BackupsIssueUnlockChallenge"),
        mq: Some("self.keys.backups.command.issue_unlock_challenge"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_issue_unlock_challenge_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_unlock_challenge",
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
        id: ServiceOperationId::SelfKeysBackupsCommandUnlockV1,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backups/{backup_id}/unlock",
        grpc: Some("SelfKeys/BackupsUnlock"),
        mq: Some("self.keys.backups.command.unlock"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_unlock_request_body",
        ),
        response_schema_ref: Some("schemas/key-backup.schema.json"),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsReadListV1,
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
        id: ServiceOperationId::SelfKeysBackupsResourceDeleteV1,
        http_method: "DELETE",
        http_path: "/_arkret/self/keys/backups/{backup_id}",
        grpc: Some("SelfKeys/BackupsDelete"),
        mq: Some("self.keys.backups.resource.delete"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "empty_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_request_body",
        ),
        response_schema_ref: None,
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsResourceReplaceV1,
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
        id: ServiceOperationId::SelfKeysCommandClaimV1,
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
            "{\"operation_id\":\"ak.self.keys.read.lookup.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
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
            "{\"operation_id\":\"ak.peer.keys.keypackages.read.claim.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
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
            "{\"operation_id\":\"ak.self.keys.read.lookup.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
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
            "{\"operation_id\":\"ak.self.keys.read.lookup.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/claims/query",
        grpc: Some("SelfKeys/KeyPackagesClaimQuery"),
        mq: Some("self.keys.keypackages.query.claim"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_query_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
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
            "{\"operation_id\":\"ak.self.keys.keypackages.upload.create.v1\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysReadLookupV1,
        http_method: "POST",
        http_path: "/_arkret/self/keys/query",
        grpc: Some("SelfKeys/Query"),
        mq: Some("self.keys.query.lookup"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
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
        id: ServiceOperationId::SelfKeysUploadCreateV1,
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
            "{\"operation_id\":\"ak.self.keys.read.lookup.v1\",\"strategy\":\"query_operation\"}",
        ),
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("service_local_material_identity_log_queue_or_external_effect_only"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMediaReadIceConfigV1,
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
        id: ServiceOperationId::SelfMediaServiceBindingReadResolveV1,
        http_method: "POST",
        http_path: "/_arkret/self/media-service-bindings/query",
        grpc: Some("SelfMediaServiceBinding/Resolve"),
        mq: Some("self.media_service_binding.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/media-service-binding-result.schema.json#/$defs/media_service_binding_request_body",
        ),
        response_schema_ref: Some(
            "schemas/media-service-binding-result.schema.json#/$defs/media_service_binding_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMessagesCommandPrepareV1,
        http_method: "POST",
        http_path: "/_arkret/self/messages/prepare",
        grpc: Some("SelfMessages/Prepare"),
        mq: Some("self.messages.command.prepare"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(1048576),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/message-authoring.schema.json#/$defs/message_prepare_request_body",
        ),
        response_schema_ref: Some(
            "schemas/message-authoring.schema.json#/$defs/message_prepare_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "Only a bounded expiring preparation cache; no accepted Event, sequence, membership or projection mutation.",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
        http_method: "POST",
        http_path: "/_arkret/self/mls/group-state-material/query",
        grpc: Some("SelfMls/GroupStateMaterial"),
        mq: Some("self.mls.query.group_state_material"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/member_group_state_material_read_request",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/MlsGroupStateMaterialOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMlsReadRosterAuthorityV1,
        http_method: "POST",
        http_path: "/_arkret/self/mls/roster-authority/query",
        grpc: Some("SelfMls/RosterAuthority"),
        mq: Some("self.mls.query.roster_authority"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/roster_read_request",
        ),
        response_schema_ref: Some(
            "schemas/mls-roster-authority.schema.json#/$defs/roster_read_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfModerationCommandReportV1,
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
        id: ServiceOperationId::SelfMorphReadListV1,
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
        id: ServiceOperationId::SelfMorphResourceGetV1,
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
        id: ServiceOperationId::SelfReadCursorCommandAdvanceV1,
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
        id: ServiceOperationId::SelfReadCursorReadListV1,
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
        id: ServiceOperationId::SelfRealmReadExportV1,
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
        id: ServiceOperationId::SelfRealmReadStreamsV1,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/streams",
        grpc: Some("SelfRealm/Streams"),
        mq: Some("self.realm.query.streams"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_stream_list",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmResourceGetV1,
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
        id: ServiceOperationId::SelfRealmJoinCommandPrepareV1,
        http_method: "POST",
        http_path: "/_arkret/self/realm-joins/prepare",
        grpc: Some("SelfRealmJoin/Prepare"),
        mq: Some("self.realm_join.command.prepare"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/self_prepare_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/self_prepare_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some(
                "stores_bounded_verified_join_intake_state_but_does_not_commit_an_event_or_membership",
            ),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinReadPreviewV1,
        http_method: "POST",
        http_path: "/_arkret/self/realm-joins/preview",
        grpc: Some("SelfRealmJoin/Preview"),
        mq: Some("self.realm_join.query.preview"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/self_preview_request_body",
        ),
        response_schema_ref: Some(
            "schemas/realm-join-intake.schema.json#/$defs/self_preview_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkReadListV1,
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
        id: ServiceOperationId::SelfRealmOrganizationReadListV1,
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
        id: ServiceOperationId::SelfRealmStateSnapshotReadByRefV1,
        http_method: "GET",
        http_path: "/_arkret/self/realm-state-snapshot/{snapshot_id}",
        grpc: Some("SelfRealmStateSnapshot/ByRef"),
        mq: Some("self.realm_state_snapshot.query.by_ref"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/realm-state-snapshot.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1,
        http_method: "GET",
        http_path: "/_arkret/self/realm-state-snapshot/head",
        grpc: Some("SelfRealmStateSnapshot/Head"),
        mq: Some("self.realm_state_snapshot.query.manifest_head"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/realm-state-snapshot.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSecurityTransactionCommandContinueV1,
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
        id: ServiceOperationId::SelfSecurityTransactionCommandCreateV1,
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
        id: ServiceOperationId::SelfSecurityTransactionResourceGetV1,
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
        id: ServiceOperationId::SelfSignalCommandSendV1,
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
        id: ServiceOperationId::SelfSignalStreamSubscribeV1,
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
        response_schema_ref: Some("schemas/signal-stream-frame.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSignerKeysReadResolveV1,
        http_method: "POST",
        http_path: "/_arkret/self/signer-keys/query",
        grpc: Some("SelfSignerKeys/Resolve"),
        mq: Some("self.signer_keys.query.resolve"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(65536),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/signer-key-operations.schema.json#/$defs/query_request_body",
        ),
        response_schema_ref: Some("schemas/signer-key-operations.schema.json#/$defs/query_outcome"),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSpaceReadListV1,
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
        id: ServiceOperationId::SelfStrandReadListV1,
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
        id: ServiceOperationId::SelfStrandWatchReadCurrentV1,
        http_method: "POST",
        http_path: "/_arkret/self/strands/watch/current",
        grpc: Some("SelfStrandWatch/Current"),
        mq: Some("self.strand.watch.query.current"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: Some(16384),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/StrandWatchCurrentRequestBody",
        ),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/StrandWatchCurrentOutcome",
        ),
        uncertain_outcome: None,
        durable_effect: Some(DurableEffectDescriptor {
            kind: DurableEffectKind::None,
            target: None,
            rationale: Some("read_only_exact_current_projection_no_event_or_durable_mutation"),
            branch_contract_json: None,
        }),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfThirdPartyInviteReadAcceptanceAttestationV1,
        http_method: "POST",
        http_path: "/_arkret/self/third-party-invites/acceptance-attestation",
        grpc: Some("SelfThirdPartyInvite/AcceptanceAttestation"),
        mq: Some("self.third_party_invite.query.acceptance_attestation"),
        body_class: Some("non_streaming_json"),
        max_canonical_body_bytes: None,
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_acceptance_attestation_request_body",
        ),
        response_schema_ref: Some(
            "schemas/invite.schema.json#/$defs/third_party_invite_acceptance_attestation_outcome",
        ),
        uncertain_outcome: None,
        durable_effect: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::ServerReadDescribeV1,
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
        response_schema_ref: Some("schemas/service-describe.schema.json"),
        uncertain_outcome: None,
        durable_effect: None,
    },
];

fn http_path_template_matches(template: &str, path: &str) -> bool {
    let mut template_segments = template.split('/');
    let mut path_segments = path.split('/');
    loop {
        match (template_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual)) => {
                let placeholder =
                    expected.starts_with('{') && expected.ends_with('}') && expected.len() > 2;
                if (placeholder && actual.is_empty()) || (!placeholder && expected != actual) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}
