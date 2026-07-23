//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/operation-registry.json; version=2026-07-20;
//! sha256=863aa747cdc14e4a0e951021ee751f79599e3ef751def9424fbe55caa9879c79 Entries: registered=198

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
    GateAccountCommandEnrollDevice,
    GateAccountCommandIntrospectSessionGrant,
    GateAccountCommandIssueIdentityBindingChallenge,
    GateAccountCommandIssueSessionGrant,
    GateAccountCommandLogout,
    GateAccountCommandLogoutAuthSession,
    GateAccountCommandPairAgentKey,
    GateAccountCommandPairDevice,
    GateAccountCommandRefreshSessionGrant,
    GateAccountCommandRegister,
    GateAccountCommandRevokeSession,
    GateAccountExchangeCompleteOidc,
    GateAccountExchangeCreateHandoff,
    OpenAgentPairingCommandSubmitRuntimeKeyRequest,
    OpenAgentPairingQueryResolve,
    OpenAgentPairingQueryRuntimeKeyRequestStatus,
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
    PeerContactsCommandSubmit,
    PeerEventsCommandSubmit,
    PeerEventsQueryDescribe,
    PeerEventsQueryFrontier,
    PeerEventsQueryResolve,
    PeerEventsQueryScan,
    PeerEventsQueryScanBody,
    PeerInvitesCommandSubmit,
    PeerKeysKeypackagesCommandClaim,
    PeerKeysKeypackagesQueryClaim,
    PeerSnapshotQueryManifestHead,
    RootIdentityCommandSubmitDidOperation,
    RootIdentityDocumentResourceGet,
    RootIdentityLogQueryList,
    RootIdentityQueryResolve,
    RootIdentityReceiptsQueryList,
    RootIdentityRecoveryPolicyCommandPublish,
    RootIdentityRecoveryPolicyResourceGet,
    RootIdentityRecoverySessionCommandComplete,
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
    SelfAgentParticipationResourceGet,
    SelfAgentParticipationResourceReplace,
    SelfAgentQueryList,
    SelfAgentResourceGet,
    SelfAgentSidecarCommandEnsure,
    SelfAgentSidecarQueryList,
    SelfAgentSidecarResourceGet,
    SelfAppletCommandInstall,
    SelfAppletCommandRevoke,
    SelfAppletGhostCommandProvision,
    SelfAppletInstallCommandPreview,
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
    SelfContactCommandRequest,
    SelfContactCommandRespond,
    SelfContactCommandTombstone,
    SelfContactQueryList,
    SelfDeviceMessagesCommandAck,
    SelfDeviceMessagesCommandSend,
    SelfDeviceMessagesQueryList,
    SelfDirectConversationCommandResolve,
    SelfEphemeralCommandSend,
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
    SelfSnapshotQueryManifestHead,
    SelfSpaceQueryList,
    SelfStrandQueryList,
    SelfViewsCollectionProjectionCommandMaterialize,
    ServerQueryDescribe,
}

pub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[
    "ak.edge.applet.actor.query.resolve",
    "ak.edge.applet.command.transaction",
    "ak.edge.applet.query.describe",
    "ak.edge.applet.query.ping",
    "ak.edge.applet.query.protocol_metadata",
    "ak.edge.applet.realm.query.resolve",
    "ak.edge.applet.third_party_locations.query.list",
    "ak.edge.applet.third_party_users.query.list",
    "ak.edge.push.command.notify",
    "ak.edge.push.command.register_device",
    "ak.edge.push.command.unregister_device",
    "ak.find.directory.command.announce",
    "ak.find.directory.command.takedown_appeal",
    "ak.find.directory.command.withdraw",
    "ak.find.directory.push.command.register",
    "ak.find.directory.query.describe",
    "ak.find.directory.query.list_handles_for_subject",
    "ak.find.directory.query.private_contact_discovery",
    "ak.find.directory.query.resolve_agent_selector",
    "ak.find.directory.query.resolve_handle",
    "ak.find.directory.query.resolve_organization",
    "ak.find.directory.query.resolve_realm",
    "ak.find.directory.query.resolve_target",
    "ak.find.directory.query.search_actors",
    "ak.find.directory.query.search_organizations",
    "ak.find.directory.query.search_realms",
    "ak.find.directory.query.search_users",
    "ak.gate.account.command.enroll_device",
    "ak.gate.account.command.introspect_session_grant",
    "ak.gate.account.command.issue_identity_binding_challenge",
    "ak.gate.account.command.issue_session_grant",
    "ak.gate.account.command.logout",
    "ak.gate.account.command.logout_auth_session",
    "ak.gate.account.command.pair_agent_key",
    "ak.gate.account.command.pair_device",
    "ak.gate.account.command.refresh_session_grant",
    "ak.gate.account.command.register",
    "ak.gate.account.command.revoke_session",
    "ak.gate.account.exchange.complete_oidc",
    "ak.gate.account.exchange.create_handoff",
    "ak.open.agent_pairing.command.submit_runtime_key_request",
    "ak.open.agent_pairing.query.resolve",
    "ak.open.agent_pairing.query.runtime_key_request_status",
    "ak.open.invite_locator.query.resolve",
    "ak.open.mimi.command.notify",
    "ak.open.mimi.command.proxy_download",
    "ak.open.mimi.command.report_abuse",
    "ak.open.mimi.command.request_consent",
    "ak.open.mimi.command.submit_message",
    "ak.open.mimi.command.update_consent",
    "ak.open.mimi.command.update_room",
    "ak.open.mimi.exchange.request_key_material",
    "ak.open.mimi.query.group_info",
    "ak.open.mimi.query.identifiers",
    "ak.open.mimi.query.provider_directory",
    "ak.peer.contacts.command.submit",
    "ak.peer.events.command.submit",
    "ak.peer.events.query.describe",
    "ak.peer.events.query.frontier",
    "ak.peer.events.query.resolve",
    "ak.peer.events.query.scan",
    "ak.peer.events.query.scan_body",
    "ak.peer.invites.command.submit",
    "ak.peer.keys.keypackages.command.claim",
    "ak.peer.keys.keypackages.query.claim",
    "ak.peer.snapshot.query.manifest_head",
    "ak.root.identity.command.submit_did_operation",
    "ak.root.identity.document.resource.get",
    "ak.root.identity.log.query.list",
    "ak.root.identity.query.resolve",
    "ak.root.identity.receipts.query.list",
    "ak.root.identity.recovery_policy.command.publish",
    "ak.root.identity.recovery_policy.resource.get",
    "ak.root.identity.recovery_session.command.complete",
    "ak.root.identity.recovery_session.command.create",
    "ak.root.identity.recovery_session.command.submit_proof",
    "ak.root.identity.recovery_session.resource.get",
    "ak.root.identity.registry.query.describe",
    "ak.root.identity.service_registration.command.ensure",
    "ak.root.identity.service_registration.resource.get",
    "ak.self.account.command.revoke_cursor",
    "ak.self.account.command.update_profile",
    "ak.self.account.query.describe",
    "ak.self.account.query.viewer",
    "ak.self.account.stream.subscribe",
    "ak.self.account_data.query.list",
    "ak.self.account_data.resource.delete",
    "ak.self.account_data.resource.get",
    "ak.self.account_data.resource.replace",
    "ak.self.agent.command.deactivate",
    "ak.self.agent.command.pause",
    "ak.self.agent.command.provision",
    "ak.self.agent.command.renew_pairing",
    "ak.self.agent.command.resume",
    "ak.self.agent.grant.command.attach",
    "ak.self.agent.grant.resource.delete",
    "ak.self.agent.participation.resource.get",
    "ak.self.agent.participation.resource.replace",
    "ak.self.agent.query.list",
    "ak.self.agent.resource.get",
    "ak.self.agent.sidecar.command.ensure",
    "ak.self.agent.sidecar.query.list",
    "ak.self.agent.sidecar.resource.get",
    "ak.self.applet.command.install",
    "ak.self.applet.command.revoke",
    "ak.self.applet.ghost.command.provision",
    "ak.self.applet.install.command.preview",
    "ak.self.authz.grants.query.effective",
    "ak.self.authz.invites.query.list",
    "ak.self.authz.query.check",
    "ak.self.blob.command.presign",
    "ak.self.blob.resource.get",
    "ak.self.blob.resource.head",
    "ak.self.blob.upload.create",
    "ak.self.call.media.exchange.issue_token",
    "ak.self.circle.command.archive",
    "ak.self.circle.command.create",
    "ak.self.circle.command.restore",
    "ak.self.circle.command.rotate_scope",
    "ak.self.circle.command.tombstone",
    "ak.self.circle.member.command.add",
    "ak.self.circle.member.resource.delete",
    "ak.self.circle.query.list",
    "ak.self.circle.resource.get",
    "ak.self.consent.command.grant",
    "ak.self.consent.command.request",
    "ak.self.consent.command.revoke",
    "ak.self.consent.query.list",
    "ak.self.consent.resource.get",
    "ak.self.contact.command.request",
    "ak.self.contact.command.respond",
    "ak.self.contact.command.tombstone",
    "ak.self.contact.query.list",
    "ak.self.device_messages.command.ack",
    "ak.self.device_messages.command.send",
    "ak.self.device_messages.query.list",
    "ak.self.direct_conversation.command.resolve",
    "ak.self.ephemeral.command.send",
    "ak.self.events.command.submit",
    "ak.self.events.command.submit_seal",
    "ak.self.events.query.describe",
    "ak.self.events.query.frontier",
    "ak.self.events.query.mls_governance_proof",
    "ak.self.events.query.resolve",
    "ak.self.events.query.scan",
    "ak.self.events.query.scan_body",
    "ak.self.events.resource.get",
    "ak.self.events.stream.subscribe",
    "ak.self.invite_locator.command.issue",
    "ak.self.invite_locator.command.revoke",
    "ak.self.invite_locator.command.rotate",
    "ak.self.invite_receive_policy.resource.get",
    "ak.self.invite_receive_policy.resource.replace",
    "ak.self.keys.backups.command.unlock",
    "ak.self.keys.backups.query.list",
    "ak.self.keys.backups.resource.delete",
    "ak.self.keys.backups.resource.replace",
    "ak.self.keys.command.claim",
    "ak.self.keys.keypackages.command.claim",
    "ak.self.keys.keypackages.command.consume",
    "ak.self.keys.keypackages.command.revoke",
    "ak.self.keys.keypackages.upload.create",
    "ak.self.keys.query.lookup",
    "ak.self.keys.upload.create",
    "ak.self.media.query.ice_config",
    "ak.self.moderation.command.report",
    "ak.self.morph.query.list",
    "ak.self.morph.resource.get",
    "ak.self.policy.query.check",
    "ak.self.read_cursor.command.advance",
    "ak.self.read_cursor.query.list",
    "ak.self.realm.command.archive",
    "ak.self.realm.command.destroy",
    "ak.self.realm.command.freeze",
    "ak.self.realm.command.tombstone",
    "ak.self.realm.join_application.audit.query.list",
    "ak.self.realm.join_application.command.cancel",
    "ak.self.realm.join_application.command.review",
    "ak.self.realm.join_application.command.submit",
    "ak.self.realm.join_application.query.list",
    "ak.self.realm.join_application.resource.get",
    "ak.self.realm.moderation_policy.query.effective",
    "ak.self.realm.moderation_policy.resource.replace",
    "ak.self.realm.query.export",
    "ak.self.realm.resource.get",
    "ak.self.realm_link.command.create",
    "ak.self.realm_link.query.effective_policy",
    "ak.self.realm_link.query.list",
    "ak.self.realm_link.resource.delete",
    "ak.self.realm_organization.query.list",
    "ak.self.realm_policy_server.resource.delete",
    "ak.self.realm_policy_server.resource.get",
    "ak.self.realm_policy_server.resource.replace",
    "ak.self.snapshot.query.manifest_head",
    "ak.self.space.query.list",
    "ak.self.strand.query.list",
    "ak.self.views.collection_projection.command.materialize",
    "ak.server.query.describe",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceOperationDescriptor {
    pub id: ServiceOperationId,
    pub http_method: &'static str,
    pub http_path: &'static str,
    pub grpc: Option<&'static str>,
    pub mq: Option<&'static str>,
    pub success_shape_kind: &'static str,
    pub idempotency_mechanism: Option<&'static str>,
    pub retry_safe: Option<bool>,
    pub request_schema_ref: Option<&'static str>,
    pub response_schema_ref: Option<&'static str>,
    pub uncertain_outcome: Option<&'static str>,
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
        Self::GateAccountCommandEnrollDevice,
        Self::GateAccountCommandIntrospectSessionGrant,
        Self::GateAccountCommandIssueIdentityBindingChallenge,
        Self::GateAccountCommandIssueSessionGrant,
        Self::GateAccountCommandLogout,
        Self::GateAccountCommandLogoutAuthSession,
        Self::GateAccountCommandPairAgentKey,
        Self::GateAccountCommandPairDevice,
        Self::GateAccountCommandRefreshSessionGrant,
        Self::GateAccountCommandRegister,
        Self::GateAccountCommandRevokeSession,
        Self::GateAccountExchangeCompleteOidc,
        Self::GateAccountExchangeCreateHandoff,
        Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        Self::OpenAgentPairingQueryResolve,
        Self::OpenAgentPairingQueryRuntimeKeyRequestStatus,
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
        Self::PeerContactsCommandSubmit,
        Self::PeerEventsCommandSubmit,
        Self::PeerEventsQueryDescribe,
        Self::PeerEventsQueryFrontier,
        Self::PeerEventsQueryResolve,
        Self::PeerEventsQueryScan,
        Self::PeerEventsQueryScanBody,
        Self::PeerInvitesCommandSubmit,
        Self::PeerKeysKeypackagesCommandClaim,
        Self::PeerKeysKeypackagesQueryClaim,
        Self::PeerSnapshotQueryManifestHead,
        Self::RootIdentityCommandSubmitDidOperation,
        Self::RootIdentityDocumentResourceGet,
        Self::RootIdentityLogQueryList,
        Self::RootIdentityQueryResolve,
        Self::RootIdentityReceiptsQueryList,
        Self::RootIdentityRecoveryPolicyCommandPublish,
        Self::RootIdentityRecoveryPolicyResourceGet,
        Self::RootIdentityRecoverySessionCommandComplete,
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
        Self::SelfAgentParticipationResourceGet,
        Self::SelfAgentParticipationResourceReplace,
        Self::SelfAgentQueryList,
        Self::SelfAgentResourceGet,
        Self::SelfAgentSidecarCommandEnsure,
        Self::SelfAgentSidecarQueryList,
        Self::SelfAgentSidecarResourceGet,
        Self::SelfAppletCommandInstall,
        Self::SelfAppletCommandRevoke,
        Self::SelfAppletGhostCommandProvision,
        Self::SelfAppletInstallCommandPreview,
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
        Self::SelfContactCommandRequest,
        Self::SelfContactCommandRespond,
        Self::SelfContactCommandTombstone,
        Self::SelfContactQueryList,
        Self::SelfDeviceMessagesCommandAck,
        Self::SelfDeviceMessagesCommandSend,
        Self::SelfDeviceMessagesQueryList,
        Self::SelfDirectConversationCommandResolve,
        Self::SelfEphemeralCommandSend,
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
    pub const PEER_CONTACTS_COMMAND_SUBMIT: &'static str = "ak.peer.contacts.command.submit";
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
    pub const PEER_SNAPSHOT_QUERY_MANIFEST_HEAD: &'static str =
        "ak.peer.snapshot.query.manifest_head";
    pub const ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION: &'static str =
        "ak.root.identity.command.submit_did_operation";
    pub const ROOT_IDENTITY_DOCUMENT_RESOURCE_GET: &'static str =
        "ak.root.identity.document.resource.get";
    pub const ROOT_IDENTITY_LOG_QUERY_LIST: &'static str = "ak.root.identity.log.query.list";
    pub const ROOT_IDENTITY_QUERY_RESOLVE: &'static str = "ak.root.identity.query.resolve";
    pub const ROOT_IDENTITY_RECEIPTS_QUERY_LIST: &'static str =
        "ak.root.identity.receipts.query.list";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH: &'static str =
        "ak.root.identity.recovery_policy.command.publish";
    pub const ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET: &'static str =
        "ak.root.identity.recovery_policy.resource.get";
    pub const ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_COMPLETE: &'static str =
        "ak.root.identity.recovery_session.command.complete";
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
    pub const SELF_APPLET_COMMAND_INSTALL: &'static str = "ak.self.applet.command.install";
    pub const SELF_APPLET_COMMAND_REVOKE: &'static str = "ak.self.applet.command.revoke";
    pub const SELF_APPLET_GHOST_COMMAND_PROVISION: &'static str =
        "ak.self.applet.ghost.command.provision";
    pub const SELF_APPLET_INSTALL_COMMAND_PREVIEW: &'static str =
        "ak.self.applet.install.command.preview";
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
    pub const SELF_CONTACT_COMMAND_REQUEST: &'static str = "ak.self.contact.command.request";
    pub const SELF_CONTACT_COMMAND_RESPOND: &'static str = "ak.self.contact.command.respond";
    pub const SELF_CONTACT_COMMAND_TOMBSTONE: &'static str = "ak.self.contact.command.tombstone";
    pub const SELF_CONTACT_QUERY_LIST: &'static str = "ak.self.contact.query.list";
    pub const SELF_DEVICE_MESSAGES_COMMAND_ACK: &'static str =
        "ak.self.device_messages.command.ack";
    pub const SELF_DEVICE_MESSAGES_COMMAND_SEND: &'static str =
        "ak.self.device_messages.command.send";
    pub const SELF_DEVICE_MESSAGES_QUERY_LIST: &'static str = "ak.self.device_messages.query.list";
    pub const SELF_DIRECT_CONVERSATION_COMMAND_RESOLVE: &'static str =
        "ak.self.direct_conversation.command.resolve";
    pub const SELF_EPHEMERAL_COMMAND_SEND: &'static str = "ak.self.ephemeral.command.send";
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
    pub const SELF_SNAPSHOT_QUERY_MANIFEST_HEAD: &'static str =
        "ak.self.snapshot.query.manifest_head";
    pub const SELF_SPACE_QUERY_LIST: &'static str = "ak.self.space.query.list";
    pub const SELF_STRAND_QUERY_LIST: &'static str = "ak.self.strand.query.list";
    pub const SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE: &'static str =
        "ak.self.views.collection_projection.command.materialize";
    pub const SERVER_QUERY_DESCRIBE: &'static str = "ak.server.query.describe";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeAppletActorQueryResolve => "ak.edge.applet.actor.query.resolve",
            Self::EdgeAppletCommandTransaction => "ak.edge.applet.command.transaction",
            Self::EdgeAppletQueryDescribe => "ak.edge.applet.query.describe",
            Self::EdgeAppletQueryPing => "ak.edge.applet.query.ping",
            Self::EdgeAppletQueryProtocolMetadata => "ak.edge.applet.query.protocol_metadata",
            Self::EdgeAppletRealmQueryResolve => "ak.edge.applet.realm.query.resolve",
            Self::EdgeAppletThirdPartyLocationsQueryList => {
                "ak.edge.applet.third_party_locations.query.list"
            }
            Self::EdgeAppletThirdPartyUsersQueryList => {
                "ak.edge.applet.third_party_users.query.list"
            }
            Self::EdgePushCommandNotify => "ak.edge.push.command.notify",
            Self::EdgePushCommandRegisterDevice => "ak.edge.push.command.register_device",
            Self::EdgePushCommandUnregisterDevice => "ak.edge.push.command.unregister_device",
            Self::FindDirectoryCommandAnnounce => "ak.find.directory.command.announce",
            Self::FindDirectoryCommandTakedownAppeal => "ak.find.directory.command.takedown_appeal",
            Self::FindDirectoryCommandWithdraw => "ak.find.directory.command.withdraw",
            Self::FindDirectoryPushCommandRegister => "ak.find.directory.push.command.register",
            Self::FindDirectoryQueryDescribe => "ak.find.directory.query.describe",
            Self::FindDirectoryQueryListHandlesForSubject => {
                "ak.find.directory.query.list_handles_for_subject"
            }
            Self::FindDirectoryQueryPrivateContactDiscovery => {
                "ak.find.directory.query.private_contact_discovery"
            }
            Self::FindDirectoryQueryResolveAgentSelector => {
                "ak.find.directory.query.resolve_agent_selector"
            }
            Self::FindDirectoryQueryResolveHandle => "ak.find.directory.query.resolve_handle",
            Self::FindDirectoryQueryResolveOrganization => {
                "ak.find.directory.query.resolve_organization"
            }
            Self::FindDirectoryQueryResolveRealm => "ak.find.directory.query.resolve_realm",
            Self::FindDirectoryQueryResolveTarget => "ak.find.directory.query.resolve_target",
            Self::FindDirectoryQuerySearchActors => "ak.find.directory.query.search_actors",
            Self::FindDirectoryQuerySearchOrganizations => {
                "ak.find.directory.query.search_organizations"
            }
            Self::FindDirectoryQuerySearchRealms => "ak.find.directory.query.search_realms",
            Self::FindDirectoryQuerySearchUsers => "ak.find.directory.query.search_users",
            Self::GateAccountCommandEnrollDevice => "ak.gate.account.command.enroll_device",
            Self::GateAccountCommandIntrospectSessionGrant => {
                "ak.gate.account.command.introspect_session_grant"
            }
            Self::GateAccountCommandIssueIdentityBindingChallenge => {
                "ak.gate.account.command.issue_identity_binding_challenge"
            }
            Self::GateAccountCommandIssueSessionGrant => {
                "ak.gate.account.command.issue_session_grant"
            }
            Self::GateAccountCommandLogout => "ak.gate.account.command.logout",
            Self::GateAccountCommandLogoutAuthSession => {
                "ak.gate.account.command.logout_auth_session"
            }
            Self::GateAccountCommandPairAgentKey => "ak.gate.account.command.pair_agent_key",
            Self::GateAccountCommandPairDevice => "ak.gate.account.command.pair_device",
            Self::GateAccountCommandRefreshSessionGrant => {
                "ak.gate.account.command.refresh_session_grant"
            }
            Self::GateAccountCommandRegister => "ak.gate.account.command.register",
            Self::GateAccountCommandRevokeSession => "ak.gate.account.command.revoke_session",
            Self::GateAccountExchangeCompleteOidc => "ak.gate.account.exchange.complete_oidc",
            Self::GateAccountExchangeCreateHandoff => "ak.gate.account.exchange.create_handoff",
            Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest => {
                "ak.open.agent_pairing.command.submit_runtime_key_request"
            }
            Self::OpenAgentPairingQueryResolve => "ak.open.agent_pairing.query.resolve",
            Self::OpenAgentPairingQueryRuntimeKeyRequestStatus => {
                "ak.open.agent_pairing.query.runtime_key_request_status"
            }
            Self::OpenInviteLocatorQueryResolve => "ak.open.invite_locator.query.resolve",
            Self::OpenMimiCommandNotify => "ak.open.mimi.command.notify",
            Self::OpenMimiCommandProxyDownload => "ak.open.mimi.command.proxy_download",
            Self::OpenMimiCommandReportAbuse => "ak.open.mimi.command.report_abuse",
            Self::OpenMimiCommandRequestConsent => "ak.open.mimi.command.request_consent",
            Self::OpenMimiCommandSubmitMessage => "ak.open.mimi.command.submit_message",
            Self::OpenMimiCommandUpdateConsent => "ak.open.mimi.command.update_consent",
            Self::OpenMimiCommandUpdateRoom => "ak.open.mimi.command.update_room",
            Self::OpenMimiExchangeRequestKeyMaterial => {
                "ak.open.mimi.exchange.request_key_material"
            }
            Self::OpenMimiQueryGroupInfo => "ak.open.mimi.query.group_info",
            Self::OpenMimiQueryIdentifiers => "ak.open.mimi.query.identifiers",
            Self::OpenMimiQueryProviderDirectory => "ak.open.mimi.query.provider_directory",
            Self::PeerContactsCommandSubmit => "ak.peer.contacts.command.submit",
            Self::PeerEventsCommandSubmit => "ak.peer.events.command.submit",
            Self::PeerEventsQueryDescribe => "ak.peer.events.query.describe",
            Self::PeerEventsQueryFrontier => "ak.peer.events.query.frontier",
            Self::PeerEventsQueryResolve => "ak.peer.events.query.resolve",
            Self::PeerEventsQueryScan => "ak.peer.events.query.scan",
            Self::PeerEventsQueryScanBody => "ak.peer.events.query.scan_body",
            Self::PeerInvitesCommandSubmit => "ak.peer.invites.command.submit",
            Self::PeerKeysKeypackagesCommandClaim => "ak.peer.keys.keypackages.command.claim",
            Self::PeerKeysKeypackagesQueryClaim => "ak.peer.keys.keypackages.query.claim",
            Self::PeerSnapshotQueryManifestHead => "ak.peer.snapshot.query.manifest_head",
            Self::RootIdentityCommandSubmitDidOperation => {
                "ak.root.identity.command.submit_did_operation"
            }
            Self::RootIdentityDocumentResourceGet => "ak.root.identity.document.resource.get",
            Self::RootIdentityLogQueryList => "ak.root.identity.log.query.list",
            Self::RootIdentityQueryResolve => "ak.root.identity.query.resolve",
            Self::RootIdentityReceiptsQueryList => "ak.root.identity.receipts.query.list",
            Self::RootIdentityRecoveryPolicyCommandPublish => {
                "ak.root.identity.recovery_policy.command.publish"
            }
            Self::RootIdentityRecoveryPolicyResourceGet => {
                "ak.root.identity.recovery_policy.resource.get"
            }
            Self::RootIdentityRecoverySessionCommandComplete => {
                "ak.root.identity.recovery_session.command.complete"
            }
            Self::RootIdentityRecoverySessionCommandCreate => {
                "ak.root.identity.recovery_session.command.create"
            }
            Self::RootIdentityRecoverySessionCommandSubmitProof => {
                "ak.root.identity.recovery_session.command.submit_proof"
            }
            Self::RootIdentityRecoverySessionResourceGet => {
                "ak.root.identity.recovery_session.resource.get"
            }
            Self::RootIdentityRegistryQueryDescribe => "ak.root.identity.registry.query.describe",
            Self::RootIdentityServiceRegistrationCommandEnsure => {
                "ak.root.identity.service_registration.command.ensure"
            }
            Self::RootIdentityServiceRegistrationResourceGet => {
                "ak.root.identity.service_registration.resource.get"
            }
            Self::SelfAccountCommandRevokeCursor => "ak.self.account.command.revoke_cursor",
            Self::SelfAccountCommandUpdateProfile => "ak.self.account.command.update_profile",
            Self::SelfAccountQueryDescribe => "ak.self.account.query.describe",
            Self::SelfAccountQueryViewer => "ak.self.account.query.viewer",
            Self::SelfAccountStreamSubscribe => "ak.self.account.stream.subscribe",
            Self::SelfAccountDataQueryList => "ak.self.account_data.query.list",
            Self::SelfAccountDataResourceDelete => "ak.self.account_data.resource.delete",
            Self::SelfAccountDataResourceGet => "ak.self.account_data.resource.get",
            Self::SelfAccountDataResourceReplace => "ak.self.account_data.resource.replace",
            Self::SelfAgentCommandDeactivate => "ak.self.agent.command.deactivate",
            Self::SelfAgentCommandPause => "ak.self.agent.command.pause",
            Self::SelfAgentCommandProvision => "ak.self.agent.command.provision",
            Self::SelfAgentCommandRenewPairing => "ak.self.agent.command.renew_pairing",
            Self::SelfAgentCommandResume => "ak.self.agent.command.resume",
            Self::SelfAgentGrantCommandAttach => "ak.self.agent.grant.command.attach",
            Self::SelfAgentGrantResourceDelete => "ak.self.agent.grant.resource.delete",
            Self::SelfAgentParticipationResourceGet => "ak.self.agent.participation.resource.get",
            Self::SelfAgentParticipationResourceReplace => {
                "ak.self.agent.participation.resource.replace"
            }
            Self::SelfAgentQueryList => "ak.self.agent.query.list",
            Self::SelfAgentResourceGet => "ak.self.agent.resource.get",
            Self::SelfAgentSidecarCommandEnsure => "ak.self.agent.sidecar.command.ensure",
            Self::SelfAgentSidecarQueryList => "ak.self.agent.sidecar.query.list",
            Self::SelfAgentSidecarResourceGet => "ak.self.agent.sidecar.resource.get",
            Self::SelfAppletCommandInstall => "ak.self.applet.command.install",
            Self::SelfAppletCommandRevoke => "ak.self.applet.command.revoke",
            Self::SelfAppletGhostCommandProvision => "ak.self.applet.ghost.command.provision",
            Self::SelfAppletInstallCommandPreview => "ak.self.applet.install.command.preview",
            Self::SelfAuthzGrantsQueryEffective => "ak.self.authz.grants.query.effective",
            Self::SelfAuthzInvitesQueryList => "ak.self.authz.invites.query.list",
            Self::SelfAuthzQueryCheck => "ak.self.authz.query.check",
            Self::SelfBlobCommandPresign => "ak.self.blob.command.presign",
            Self::SelfBlobResourceGet => "ak.self.blob.resource.get",
            Self::SelfBlobResourceHead => "ak.self.blob.resource.head",
            Self::SelfBlobUploadCreate => "ak.self.blob.upload.create",
            Self::SelfCallMediaExchangeIssueToken => "ak.self.call.media.exchange.issue_token",
            Self::SelfCircleCommandArchive => "ak.self.circle.command.archive",
            Self::SelfCircleCommandCreate => "ak.self.circle.command.create",
            Self::SelfCircleCommandRestore => "ak.self.circle.command.restore",
            Self::SelfCircleCommandRotateScope => "ak.self.circle.command.rotate_scope",
            Self::SelfCircleCommandTombstone => "ak.self.circle.command.tombstone",
            Self::SelfCircleMemberCommandAdd => "ak.self.circle.member.command.add",
            Self::SelfCircleMemberResourceDelete => "ak.self.circle.member.resource.delete",
            Self::SelfCircleQueryList => "ak.self.circle.query.list",
            Self::SelfCircleResourceGet => "ak.self.circle.resource.get",
            Self::SelfConsentCommandGrant => "ak.self.consent.command.grant",
            Self::SelfConsentCommandRequest => "ak.self.consent.command.request",
            Self::SelfConsentCommandRevoke => "ak.self.consent.command.revoke",
            Self::SelfConsentQueryList => "ak.self.consent.query.list",
            Self::SelfConsentResourceGet => "ak.self.consent.resource.get",
            Self::SelfContactCommandRequest => "ak.self.contact.command.request",
            Self::SelfContactCommandRespond => "ak.self.contact.command.respond",
            Self::SelfContactCommandTombstone => "ak.self.contact.command.tombstone",
            Self::SelfContactQueryList => "ak.self.contact.query.list",
            Self::SelfDeviceMessagesCommandAck => "ak.self.device_messages.command.ack",
            Self::SelfDeviceMessagesCommandSend => "ak.self.device_messages.command.send",
            Self::SelfDeviceMessagesQueryList => "ak.self.device_messages.query.list",
            Self::SelfDirectConversationCommandResolve => {
                "ak.self.direct_conversation.command.resolve"
            }
            Self::SelfEphemeralCommandSend => "ak.self.ephemeral.command.send",
            Self::SelfEventsCommandSubmit => "ak.self.events.command.submit",
            Self::SelfEventsCommandSubmitSeal => "ak.self.events.command.submit_seal",
            Self::SelfEventsQueryDescribe => "ak.self.events.query.describe",
            Self::SelfEventsQueryFrontier => "ak.self.events.query.frontier",
            Self::SelfEventsQueryMlsGovernanceProof => "ak.self.events.query.mls_governance_proof",
            Self::SelfEventsQueryResolve => "ak.self.events.query.resolve",
            Self::SelfEventsQueryScan => "ak.self.events.query.scan",
            Self::SelfEventsQueryScanBody => "ak.self.events.query.scan_body",
            Self::SelfEventsResourceGet => "ak.self.events.resource.get",
            Self::SelfEventsStreamSubscribe => "ak.self.events.stream.subscribe",
            Self::SelfInviteLocatorCommandIssue => "ak.self.invite_locator.command.issue",
            Self::SelfInviteLocatorCommandRevoke => "ak.self.invite_locator.command.revoke",
            Self::SelfInviteLocatorCommandRotate => "ak.self.invite_locator.command.rotate",
            Self::SelfInviteReceivePolicyResourceGet => {
                "ak.self.invite_receive_policy.resource.get"
            }
            Self::SelfInviteReceivePolicyResourceReplace => {
                "ak.self.invite_receive_policy.resource.replace"
            }
            Self::SelfKeysBackupsCommandUnlock => "ak.self.keys.backups.command.unlock",
            Self::SelfKeysBackupsQueryList => "ak.self.keys.backups.query.list",
            Self::SelfKeysBackupsResourceDelete => "ak.self.keys.backups.resource.delete",
            Self::SelfKeysBackupsResourceReplace => "ak.self.keys.backups.resource.replace",
            Self::SelfKeysCommandClaim => "ak.self.keys.command.claim",
            Self::SelfKeysKeypackagesCommandClaim => "ak.self.keys.keypackages.command.claim",
            Self::SelfKeysKeypackagesCommandConsume => "ak.self.keys.keypackages.command.consume",
            Self::SelfKeysKeypackagesCommandRevoke => "ak.self.keys.keypackages.command.revoke",
            Self::SelfKeysKeypackagesUploadCreate => "ak.self.keys.keypackages.upload.create",
            Self::SelfKeysQueryLookup => "ak.self.keys.query.lookup",
            Self::SelfKeysUploadCreate => "ak.self.keys.upload.create",
            Self::SelfMediaQueryIceConfig => "ak.self.media.query.ice_config",
            Self::SelfModerationCommandReport => "ak.self.moderation.command.report",
            Self::SelfMorphQueryList => "ak.self.morph.query.list",
            Self::SelfMorphResourceGet => "ak.self.morph.resource.get",
            Self::SelfPolicyQueryCheck => "ak.self.policy.query.check",
            Self::SelfReadCursorCommandAdvance => "ak.self.read_cursor.command.advance",
            Self::SelfReadCursorQueryList => "ak.self.read_cursor.query.list",
            Self::SelfRealmCommandArchive => "ak.self.realm.command.archive",
            Self::SelfRealmCommandDestroy => "ak.self.realm.command.destroy",
            Self::SelfRealmCommandFreeze => "ak.self.realm.command.freeze",
            Self::SelfRealmCommandTombstone => "ak.self.realm.command.tombstone",
            Self::SelfRealmJoinApplicationAuditQueryList => {
                "ak.self.realm.join_application.audit.query.list"
            }
            Self::SelfRealmJoinApplicationCommandCancel => {
                "ak.self.realm.join_application.command.cancel"
            }
            Self::SelfRealmJoinApplicationCommandReview => {
                "ak.self.realm.join_application.command.review"
            }
            Self::SelfRealmJoinApplicationCommandSubmit => {
                "ak.self.realm.join_application.command.submit"
            }
            Self::SelfRealmJoinApplicationQueryList => "ak.self.realm.join_application.query.list",
            Self::SelfRealmJoinApplicationResourceGet => {
                "ak.self.realm.join_application.resource.get"
            }
            Self::SelfRealmModerationPolicyQueryEffective => {
                "ak.self.realm.moderation_policy.query.effective"
            }
            Self::SelfRealmModerationPolicyResourceReplace => {
                "ak.self.realm.moderation_policy.resource.replace"
            }
            Self::SelfRealmQueryExport => "ak.self.realm.query.export",
            Self::SelfRealmResourceGet => "ak.self.realm.resource.get",
            Self::SelfRealmLinkCommandCreate => "ak.self.realm_link.command.create",
            Self::SelfRealmLinkQueryEffectivePolicy => "ak.self.realm_link.query.effective_policy",
            Self::SelfRealmLinkQueryList => "ak.self.realm_link.query.list",
            Self::SelfRealmLinkResourceDelete => "ak.self.realm_link.resource.delete",
            Self::SelfRealmOrganizationQueryList => "ak.self.realm_organization.query.list",
            Self::SelfRealmPolicyServerResourceDelete => {
                "ak.self.realm_policy_server.resource.delete"
            }
            Self::SelfRealmPolicyServerResourceGet => "ak.self.realm_policy_server.resource.get",
            Self::SelfRealmPolicyServerResourceReplace => {
                "ak.self.realm_policy_server.resource.replace"
            }
            Self::SelfSnapshotQueryManifestHead => "ak.self.snapshot.query.manifest_head",
            Self::SelfSpaceQueryList => "ak.self.space.query.list",
            Self::SelfStrandQueryList => "ak.self.strand.query.list",
            Self::SelfViewsCollectionProjectionCommandMaterialize => {
                "ak.self.views.collection_projection.command.materialize"
            }
            Self::ServerQueryDescribe => "ak.server.query.describe",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ak.edge.applet.actor.query.resolve" => Some(Self::EdgeAppletActorQueryResolve),
            "ak.edge.applet.command.transaction" => Some(Self::EdgeAppletCommandTransaction),
            "ak.edge.applet.query.describe" => Some(Self::EdgeAppletQueryDescribe),
            "ak.edge.applet.query.ping" => Some(Self::EdgeAppletQueryPing),
            "ak.edge.applet.query.protocol_metadata" => Some(Self::EdgeAppletQueryProtocolMetadata),
            "ak.edge.applet.realm.query.resolve" => Some(Self::EdgeAppletRealmQueryResolve),
            "ak.edge.applet.third_party_locations.query.list" => {
                Some(Self::EdgeAppletThirdPartyLocationsQueryList)
            }
            "ak.edge.applet.third_party_users.query.list" => {
                Some(Self::EdgeAppletThirdPartyUsersQueryList)
            }
            "ak.edge.push.command.notify" => Some(Self::EdgePushCommandNotify),
            "ak.edge.push.command.register_device" => Some(Self::EdgePushCommandRegisterDevice),
            "ak.edge.push.command.unregister_device" => Some(Self::EdgePushCommandUnregisterDevice),
            "ak.find.directory.command.announce" => Some(Self::FindDirectoryCommandAnnounce),
            "ak.find.directory.command.takedown_appeal" => {
                Some(Self::FindDirectoryCommandTakedownAppeal)
            }
            "ak.find.directory.command.withdraw" => Some(Self::FindDirectoryCommandWithdraw),
            "ak.find.directory.push.command.register" => {
                Some(Self::FindDirectoryPushCommandRegister)
            }
            "ak.find.directory.query.describe" => Some(Self::FindDirectoryQueryDescribe),
            "ak.find.directory.query.list_handles_for_subject" => {
                Some(Self::FindDirectoryQueryListHandlesForSubject)
            }
            "ak.find.directory.query.private_contact_discovery" => {
                Some(Self::FindDirectoryQueryPrivateContactDiscovery)
            }
            "ak.find.directory.query.resolve_agent_selector" => {
                Some(Self::FindDirectoryQueryResolveAgentSelector)
            }
            "ak.find.directory.query.resolve_handle" => Some(Self::FindDirectoryQueryResolveHandle),
            "ak.find.directory.query.resolve_organization" => {
                Some(Self::FindDirectoryQueryResolveOrganization)
            }
            "ak.find.directory.query.resolve_realm" => Some(Self::FindDirectoryQueryResolveRealm),
            "ak.find.directory.query.resolve_target" => Some(Self::FindDirectoryQueryResolveTarget),
            "ak.find.directory.query.search_actors" => Some(Self::FindDirectoryQuerySearchActors),
            "ak.find.directory.query.search_organizations" => {
                Some(Self::FindDirectoryQuerySearchOrganizations)
            }
            "ak.find.directory.query.search_realms" => Some(Self::FindDirectoryQuerySearchRealms),
            "ak.find.directory.query.search_users" => Some(Self::FindDirectoryQuerySearchUsers),
            "ak.gate.account.command.enroll_device" => Some(Self::GateAccountCommandEnrollDevice),
            "ak.gate.account.command.introspect_session_grant" => {
                Some(Self::GateAccountCommandIntrospectSessionGrant)
            }
            "ak.gate.account.command.issue_identity_binding_challenge" => {
                Some(Self::GateAccountCommandIssueIdentityBindingChallenge)
            }
            "ak.gate.account.command.issue_session_grant" => {
                Some(Self::GateAccountCommandIssueSessionGrant)
            }
            "ak.gate.account.command.logout" => Some(Self::GateAccountCommandLogout),
            "ak.gate.account.command.logout_auth_session" => {
                Some(Self::GateAccountCommandLogoutAuthSession)
            }
            "ak.gate.account.command.pair_agent_key" => Some(Self::GateAccountCommandPairAgentKey),
            "ak.gate.account.command.pair_device" => Some(Self::GateAccountCommandPairDevice),
            "ak.gate.account.command.refresh_session_grant" => {
                Some(Self::GateAccountCommandRefreshSessionGrant)
            }
            "ak.gate.account.command.register" => Some(Self::GateAccountCommandRegister),
            "ak.gate.account.command.revoke_session" => Some(Self::GateAccountCommandRevokeSession),
            "ak.gate.account.exchange.complete_oidc" => Some(Self::GateAccountExchangeCompleteOidc),
            "ak.gate.account.exchange.create_handoff" => {
                Some(Self::GateAccountExchangeCreateHandoff)
            }
            "ak.open.agent_pairing.command.submit_runtime_key_request" => {
                Some(Self::OpenAgentPairingCommandSubmitRuntimeKeyRequest)
            }
            "ak.open.agent_pairing.query.resolve" => Some(Self::OpenAgentPairingQueryResolve),
            "ak.open.agent_pairing.query.runtime_key_request_status" => {
                Some(Self::OpenAgentPairingQueryRuntimeKeyRequestStatus)
            }
            "ak.open.invite_locator.query.resolve" => Some(Self::OpenInviteLocatorQueryResolve),
            "ak.open.mimi.command.notify" => Some(Self::OpenMimiCommandNotify),
            "ak.open.mimi.command.proxy_download" => Some(Self::OpenMimiCommandProxyDownload),
            "ak.open.mimi.command.report_abuse" => Some(Self::OpenMimiCommandReportAbuse),
            "ak.open.mimi.command.request_consent" => Some(Self::OpenMimiCommandRequestConsent),
            "ak.open.mimi.command.submit_message" => Some(Self::OpenMimiCommandSubmitMessage),
            "ak.open.mimi.command.update_consent" => Some(Self::OpenMimiCommandUpdateConsent),
            "ak.open.mimi.command.update_room" => Some(Self::OpenMimiCommandUpdateRoom),
            "ak.open.mimi.exchange.request_key_material" => {
                Some(Self::OpenMimiExchangeRequestKeyMaterial)
            }
            "ak.open.mimi.query.group_info" => Some(Self::OpenMimiQueryGroupInfo),
            "ak.open.mimi.query.identifiers" => Some(Self::OpenMimiQueryIdentifiers),
            "ak.open.mimi.query.provider_directory" => Some(Self::OpenMimiQueryProviderDirectory),
            "ak.peer.contacts.command.submit" => Some(Self::PeerContactsCommandSubmit),
            "ak.peer.events.command.submit" => Some(Self::PeerEventsCommandSubmit),
            "ak.peer.events.query.describe" => Some(Self::PeerEventsQueryDescribe),
            "ak.peer.events.query.frontier" => Some(Self::PeerEventsQueryFrontier),
            "ak.peer.events.query.resolve" => Some(Self::PeerEventsQueryResolve),
            "ak.peer.events.query.scan" => Some(Self::PeerEventsQueryScan),
            "ak.peer.events.query.scan_body" => Some(Self::PeerEventsQueryScanBody),
            "ak.peer.invites.command.submit" => Some(Self::PeerInvitesCommandSubmit),
            "ak.peer.keys.keypackages.command.claim" => Some(Self::PeerKeysKeypackagesCommandClaim),
            "ak.peer.keys.keypackages.query.claim" => Some(Self::PeerKeysKeypackagesQueryClaim),
            "ak.peer.snapshot.query.manifest_head" => Some(Self::PeerSnapshotQueryManifestHead),
            "ak.root.identity.command.submit_did_operation" => {
                Some(Self::RootIdentityCommandSubmitDidOperation)
            }
            "ak.root.identity.document.resource.get" => Some(Self::RootIdentityDocumentResourceGet),
            "ak.root.identity.log.query.list" => Some(Self::RootIdentityLogQueryList),
            "ak.root.identity.query.resolve" => Some(Self::RootIdentityQueryResolve),
            "ak.root.identity.receipts.query.list" => Some(Self::RootIdentityReceiptsQueryList),
            "ak.root.identity.recovery_policy.command.publish" => {
                Some(Self::RootIdentityRecoveryPolicyCommandPublish)
            }
            "ak.root.identity.recovery_policy.resource.get" => {
                Some(Self::RootIdentityRecoveryPolicyResourceGet)
            }
            "ak.root.identity.recovery_session.command.complete" => {
                Some(Self::RootIdentityRecoverySessionCommandComplete)
            }
            "ak.root.identity.recovery_session.command.create" => {
                Some(Self::RootIdentityRecoverySessionCommandCreate)
            }
            "ak.root.identity.recovery_session.command.submit_proof" => {
                Some(Self::RootIdentityRecoverySessionCommandSubmitProof)
            }
            "ak.root.identity.recovery_session.resource.get" => {
                Some(Self::RootIdentityRecoverySessionResourceGet)
            }
            "ak.root.identity.registry.query.describe" => {
                Some(Self::RootIdentityRegistryQueryDescribe)
            }
            "ak.root.identity.service_registration.command.ensure" => {
                Some(Self::RootIdentityServiceRegistrationCommandEnsure)
            }
            "ak.root.identity.service_registration.resource.get" => {
                Some(Self::RootIdentityServiceRegistrationResourceGet)
            }
            "ak.self.account.command.revoke_cursor" => Some(Self::SelfAccountCommandRevokeCursor),
            "ak.self.account.command.update_profile" => Some(Self::SelfAccountCommandUpdateProfile),
            "ak.self.account.query.describe" => Some(Self::SelfAccountQueryDescribe),
            "ak.self.account.query.viewer" => Some(Self::SelfAccountQueryViewer),
            "ak.self.account.stream.subscribe" => Some(Self::SelfAccountStreamSubscribe),
            "ak.self.account_data.query.list" => Some(Self::SelfAccountDataQueryList),
            "ak.self.account_data.resource.delete" => Some(Self::SelfAccountDataResourceDelete),
            "ak.self.account_data.resource.get" => Some(Self::SelfAccountDataResourceGet),
            "ak.self.account_data.resource.replace" => Some(Self::SelfAccountDataResourceReplace),
            "ak.self.agent.command.deactivate" => Some(Self::SelfAgentCommandDeactivate),
            "ak.self.agent.command.pause" => Some(Self::SelfAgentCommandPause),
            "ak.self.agent.command.provision" => Some(Self::SelfAgentCommandProvision),
            "ak.self.agent.command.renew_pairing" => Some(Self::SelfAgentCommandRenewPairing),
            "ak.self.agent.command.resume" => Some(Self::SelfAgentCommandResume),
            "ak.self.agent.grant.command.attach" => Some(Self::SelfAgentGrantCommandAttach),
            "ak.self.agent.grant.resource.delete" => Some(Self::SelfAgentGrantResourceDelete),
            "ak.self.agent.participation.resource.get" => {
                Some(Self::SelfAgentParticipationResourceGet)
            }
            "ak.self.agent.participation.resource.replace" => {
                Some(Self::SelfAgentParticipationResourceReplace)
            }
            "ak.self.agent.query.list" => Some(Self::SelfAgentQueryList),
            "ak.self.agent.resource.get" => Some(Self::SelfAgentResourceGet),
            "ak.self.agent.sidecar.command.ensure" => Some(Self::SelfAgentSidecarCommandEnsure),
            "ak.self.agent.sidecar.query.list" => Some(Self::SelfAgentSidecarQueryList),
            "ak.self.agent.sidecar.resource.get" => Some(Self::SelfAgentSidecarResourceGet),
            "ak.self.applet.command.install" => Some(Self::SelfAppletCommandInstall),
            "ak.self.applet.command.revoke" => Some(Self::SelfAppletCommandRevoke),
            "ak.self.applet.ghost.command.provision" => Some(Self::SelfAppletGhostCommandProvision),
            "ak.self.applet.install.command.preview" => Some(Self::SelfAppletInstallCommandPreview),
            "ak.self.authz.grants.query.effective" => Some(Self::SelfAuthzGrantsQueryEffective),
            "ak.self.authz.invites.query.list" => Some(Self::SelfAuthzInvitesQueryList),
            "ak.self.authz.query.check" => Some(Self::SelfAuthzQueryCheck),
            "ak.self.blob.command.presign" => Some(Self::SelfBlobCommandPresign),
            "ak.self.blob.resource.get" => Some(Self::SelfBlobResourceGet),
            "ak.self.blob.resource.head" => Some(Self::SelfBlobResourceHead),
            "ak.self.blob.upload.create" => Some(Self::SelfBlobUploadCreate),
            "ak.self.call.media.exchange.issue_token" => {
                Some(Self::SelfCallMediaExchangeIssueToken)
            }
            "ak.self.circle.command.archive" => Some(Self::SelfCircleCommandArchive),
            "ak.self.circle.command.create" => Some(Self::SelfCircleCommandCreate),
            "ak.self.circle.command.restore" => Some(Self::SelfCircleCommandRestore),
            "ak.self.circle.command.rotate_scope" => Some(Self::SelfCircleCommandRotateScope),
            "ak.self.circle.command.tombstone" => Some(Self::SelfCircleCommandTombstone),
            "ak.self.circle.member.command.add" => Some(Self::SelfCircleMemberCommandAdd),
            "ak.self.circle.member.resource.delete" => Some(Self::SelfCircleMemberResourceDelete),
            "ak.self.circle.query.list" => Some(Self::SelfCircleQueryList),
            "ak.self.circle.resource.get" => Some(Self::SelfCircleResourceGet),
            "ak.self.consent.command.grant" => Some(Self::SelfConsentCommandGrant),
            "ak.self.consent.command.request" => Some(Self::SelfConsentCommandRequest),
            "ak.self.consent.command.revoke" => Some(Self::SelfConsentCommandRevoke),
            "ak.self.consent.query.list" => Some(Self::SelfConsentQueryList),
            "ak.self.consent.resource.get" => Some(Self::SelfConsentResourceGet),
            "ak.self.contact.command.request" => Some(Self::SelfContactCommandRequest),
            "ak.self.contact.command.respond" => Some(Self::SelfContactCommandRespond),
            "ak.self.contact.command.tombstone" => Some(Self::SelfContactCommandTombstone),
            "ak.self.contact.query.list" => Some(Self::SelfContactQueryList),
            "ak.self.device_messages.command.ack" => Some(Self::SelfDeviceMessagesCommandAck),
            "ak.self.device_messages.command.send" => Some(Self::SelfDeviceMessagesCommandSend),
            "ak.self.device_messages.query.list" => Some(Self::SelfDeviceMessagesQueryList),
            "ak.self.direct_conversation.command.resolve" => {
                Some(Self::SelfDirectConversationCommandResolve)
            }
            "ak.self.ephemeral.command.send" => Some(Self::SelfEphemeralCommandSend),
            "ak.self.events.command.submit" => Some(Self::SelfEventsCommandSubmit),
            "ak.self.events.command.submit_seal" => Some(Self::SelfEventsCommandSubmitSeal),
            "ak.self.events.query.describe" => Some(Self::SelfEventsQueryDescribe),
            "ak.self.events.query.frontier" => Some(Self::SelfEventsQueryFrontier),
            "ak.self.events.query.mls_governance_proof" => {
                Some(Self::SelfEventsQueryMlsGovernanceProof)
            }
            "ak.self.events.query.resolve" => Some(Self::SelfEventsQueryResolve),
            "ak.self.events.query.scan" => Some(Self::SelfEventsQueryScan),
            "ak.self.events.query.scan_body" => Some(Self::SelfEventsQueryScanBody),
            "ak.self.events.resource.get" => Some(Self::SelfEventsResourceGet),
            "ak.self.events.stream.subscribe" => Some(Self::SelfEventsStreamSubscribe),
            "ak.self.invite_locator.command.issue" => Some(Self::SelfInviteLocatorCommandIssue),
            "ak.self.invite_locator.command.revoke" => Some(Self::SelfInviteLocatorCommandRevoke),
            "ak.self.invite_locator.command.rotate" => Some(Self::SelfInviteLocatorCommandRotate),
            "ak.self.invite_receive_policy.resource.get" => {
                Some(Self::SelfInviteReceivePolicyResourceGet)
            }
            "ak.self.invite_receive_policy.resource.replace" => {
                Some(Self::SelfInviteReceivePolicyResourceReplace)
            }
            "ak.self.keys.backups.command.unlock" => Some(Self::SelfKeysBackupsCommandUnlock),
            "ak.self.keys.backups.query.list" => Some(Self::SelfKeysBackupsQueryList),
            "ak.self.keys.backups.resource.delete" => Some(Self::SelfKeysBackupsResourceDelete),
            "ak.self.keys.backups.resource.replace" => Some(Self::SelfKeysBackupsResourceReplace),
            "ak.self.keys.command.claim" => Some(Self::SelfKeysCommandClaim),
            "ak.self.keys.keypackages.command.claim" => Some(Self::SelfKeysKeypackagesCommandClaim),
            "ak.self.keys.keypackages.command.consume" => {
                Some(Self::SelfKeysKeypackagesCommandConsume)
            }
            "ak.self.keys.keypackages.command.revoke" => {
                Some(Self::SelfKeysKeypackagesCommandRevoke)
            }
            "ak.self.keys.keypackages.upload.create" => Some(Self::SelfKeysKeypackagesUploadCreate),
            "ak.self.keys.query.lookup" => Some(Self::SelfKeysQueryLookup),
            "ak.self.keys.upload.create" => Some(Self::SelfKeysUploadCreate),
            "ak.self.media.query.ice_config" => Some(Self::SelfMediaQueryIceConfig),
            "ak.self.moderation.command.report" => Some(Self::SelfModerationCommandReport),
            "ak.self.morph.query.list" => Some(Self::SelfMorphQueryList),
            "ak.self.morph.resource.get" => Some(Self::SelfMorphResourceGet),
            "ak.self.policy.query.check" => Some(Self::SelfPolicyQueryCheck),
            "ak.self.read_cursor.command.advance" => Some(Self::SelfReadCursorCommandAdvance),
            "ak.self.read_cursor.query.list" => Some(Self::SelfReadCursorQueryList),
            "ak.self.realm.command.archive" => Some(Self::SelfRealmCommandArchive),
            "ak.self.realm.command.destroy" => Some(Self::SelfRealmCommandDestroy),
            "ak.self.realm.command.freeze" => Some(Self::SelfRealmCommandFreeze),
            "ak.self.realm.command.tombstone" => Some(Self::SelfRealmCommandTombstone),
            "ak.self.realm.join_application.audit.query.list" => {
                Some(Self::SelfRealmJoinApplicationAuditQueryList)
            }
            "ak.self.realm.join_application.command.cancel" => {
                Some(Self::SelfRealmJoinApplicationCommandCancel)
            }
            "ak.self.realm.join_application.command.review" => {
                Some(Self::SelfRealmJoinApplicationCommandReview)
            }
            "ak.self.realm.join_application.command.submit" => {
                Some(Self::SelfRealmJoinApplicationCommandSubmit)
            }
            "ak.self.realm.join_application.query.list" => {
                Some(Self::SelfRealmJoinApplicationQueryList)
            }
            "ak.self.realm.join_application.resource.get" => {
                Some(Self::SelfRealmJoinApplicationResourceGet)
            }
            "ak.self.realm.moderation_policy.query.effective" => {
                Some(Self::SelfRealmModerationPolicyQueryEffective)
            }
            "ak.self.realm.moderation_policy.resource.replace" => {
                Some(Self::SelfRealmModerationPolicyResourceReplace)
            }
            "ak.self.realm.query.export" => Some(Self::SelfRealmQueryExport),
            "ak.self.realm.resource.get" => Some(Self::SelfRealmResourceGet),
            "ak.self.realm_link.command.create" => Some(Self::SelfRealmLinkCommandCreate),
            "ak.self.realm_link.query.effective_policy" => {
                Some(Self::SelfRealmLinkQueryEffectivePolicy)
            }
            "ak.self.realm_link.query.list" => Some(Self::SelfRealmLinkQueryList),
            "ak.self.realm_link.resource.delete" => Some(Self::SelfRealmLinkResourceDelete),
            "ak.self.realm_organization.query.list" => Some(Self::SelfRealmOrganizationQueryList),
            "ak.self.realm_policy_server.resource.delete" => {
                Some(Self::SelfRealmPolicyServerResourceDelete)
            }
            "ak.self.realm_policy_server.resource.get" => {
                Some(Self::SelfRealmPolicyServerResourceGet)
            }
            "ak.self.realm_policy_server.resource.replace" => {
                Some(Self::SelfRealmPolicyServerResourceReplace)
            }
            "ak.self.snapshot.query.manifest_head" => Some(Self::SelfSnapshotQueryManifestHead),
            "ak.self.space.query.list" => Some(Self::SelfSpaceQueryList),
            "ak.self.strand.query.list" => Some(Self::SelfStrandQueryList),
            "ak.self.views.collection_projection.command.materialize" => {
                Some(Self::SelfViewsCollectionProjectionCommandMaterialize)
            }
            "ak.server.query.describe" => Some(Self::ServerQueryDescribe),
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
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_actor_view",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletCommandTransaction,
        http_method: "POST",
        http_path: "/_arkret/edge/applet/transactions",
        grpc: Some("EdgeApplet/Transaction"),
        mq: Some("edge.applet.command.transaction"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/describe",
        grpc: Some("EdgeApplet/Describe"),
        mq: Some("edge.applet.query.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletQueryPing,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/ping",
        grpc: Some("EdgeApplet/Ping"),
        mq: Some("edge.applet.query.ping"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_ping_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletQueryProtocolMetadata,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/protocols/{protocol}",
        grpc: Some("EdgeApplet/ProtocolMetadata"),
        mq: Some("edge.applet.query.protocol_metadata"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_protocol_metadata",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletRealmQueryResolve,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        grpc: Some("EdgeApplet/ResolveRealm"),
        mq: Some("edge.applet.realm.query.resolve"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_realm_view",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletThirdPartyLocationsQueryList,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/third_party/locations",
        grpc: Some("EdgeApplet/ThirdPartyLocations"),
        mq: Some("edge.applet.third_party_locations.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_third_party_location_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgeAppletThirdPartyUsersQueryList,
        http_method: "GET",
        http_path: "/_arkret/edge/applet/third_party/users",
        grpc: Some("EdgeApplet/ThirdPartyUsers"),
        mq: Some("edge.applet.third_party_users.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/applet-edge-operations.schema.json#/$defs/applet_third_party_user_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandNotify,
        http_method: "POST",
        http_path: "/_arkret/edge/push/notify",
        grpc: Some("EdgePush/Notify"),
        mq: Some("edge.push.command.notify"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/push-operations.schema.json#/$defs/push_notify_request_body",
        ),
        response_schema_ref: Some("schemas/push-operations.schema.json#/$defs/push_notify_outcome"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandRegisterDevice,
        http_method: "POST",
        http_path: "/_arkret/edge/push/register-device",
        grpc: Some("EdgePush/RegisterDevice"),
        mq: Some("edge.push.command.register_device"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::EdgePushCommandUnregisterDevice,
        http_method: "POST",
        http_path: "/_arkret/edge/push/unregister-device",
        grpc: Some("EdgePush/UnregisterDevice"),
        mq: Some("edge.push.command.unregister_device"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandAnnounce,
        http_method: "POST",
        http_path: "/_arkret/find/directory/announce",
        grpc: Some("FindDirectory/Announce"),
        mq: Some("find.directory.command.announce"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandTakedownAppeal,
        http_method: "POST",
        http_path: "/_arkret/find/directory/takedown/appeal",
        grpc: Some("FindDirectory/TakedownAppeal"),
        mq: Some("find.directory.command.takedown_appeal"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryCommandWithdraw,
        http_method: "POST",
        http_path: "/_arkret/find/directory/withdraw",
        grpc: Some("FindDirectory/Withdraw"),
        mq: Some("find.directory.command.withdraw"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryPushCommandRegister,
        http_method: "POST",
        http_path: "/_arkret/find/directory/push/register",
        grpc: Some("FindDirectory/PushRegister"),
        mq: Some("find.directory.push.command.register"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/find/directory/describe",
        grpc: Some("FindDirectory/Describe"),
        mq: Some("find.directory.query.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryListHandlesForSubject,
        http_method: "POST",
        http_path: "/_arkret/find/directory/list-handles-for-subject",
        grpc: Some("FindDirectory/ListHandlesForSubject"),
        mq: Some("find.directory.query.list_handles_for_subject"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/directory-operations.schema.json#/$defs/directory_list_handles_for_subject_request_body",
        ),
        response_schema_ref: Some("schemas/list-handles-for-subject-response.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryPrivateContactDiscovery,
        http_method: "POST",
        http_path: "/_arkret/find/directory/private-contact-discovery",
        grpc: Some("FindDirectory/PrivateContactDiscovery"),
        mq: Some("find.directory.query.private_contact_discovery"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryResolveAgentSelector,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-agent-selector",
        grpc: Some("FindDirectory/ResolveAgentSelector"),
        mq: Some("find.directory.query.resolve_agent_selector"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryResolveHandle,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-handle",
        grpc: Some("FindDirectory/ResolveHandle"),
        mq: Some("find.directory.query.resolve_handle"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryResolveOrganization,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-organization",
        grpc: Some("FindDirectory/ResolveOrganization"),
        mq: Some("find.directory.query.resolve_organization"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryResolveRealm,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-realm",
        grpc: Some("FindDirectory/ResolveRealm"),
        mq: Some("find.directory.query.resolve_realm"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQueryResolveTarget,
        http_method: "POST",
        http_path: "/_arkret/find/directory/resolve-target",
        grpc: Some("FindDirectory/ResolveTarget"),
        mq: Some("find.directory.query.resolve_target"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQuerySearchActors,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-actors",
        grpc: Some("FindDirectory/SearchActors"),
        mq: Some("find.directory.query.search_actors"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQuerySearchOrganizations,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-organizations",
        grpc: Some("FindDirectory/SearchOrganizations"),
        mq: Some("find.directory.query.search_organizations"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQuerySearchRealms,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-realms",
        grpc: Some("FindDirectory/SearchRealms"),
        mq: Some("find.directory.query.search_realms"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::FindDirectoryQuerySearchUsers,
        http_method: "POST",
        http_path: "/_arkret/find/directory/search-users",
        grpc: Some("FindDirectory/SearchUsers"),
        mq: Some("find.directory.query.search_users"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandEnrollDevice,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-enroll",
        grpc: Some("GateAccount/DeviceEnroll"),
        mq: Some("gate.account.command.enroll_device"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_enroll_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/account_device_enroll_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.account.query.viewer\",\"strategy\":\"query_operation\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIntrospectSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/introspect",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueIdentityBindingChallenge,
        http_method: "POST",
        http_path: "/_arkret/gate/account/identity-binding-challenges",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandIssueSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants",
        grpc: Some("GateAccount/IssueSessionGrant"),
        mq: Some("gate.account.command.issue_session_grant"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandLogout,
        http_method: "POST",
        http_path: "/_arkret/gate/account/logout",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandLogoutAuthSession,
        http_method: "POST",
        http_path: "/_arkret/gate/account/auth-sessions/logout",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPairAgentKey,
        http_method: "POST",
        http_path: "/_arkret/gate/account/agent-key-pair",
        grpc: Some("GateAccount/AgentKeyPair"),
        mq: Some("gate.account.command.pair_agent_key"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandPairDevice,
        http_method: "POST",
        http_path: "/_arkret/gate/account/device-pair",
        grpc: Some("GateAccount/DevicePair"),
        mq: Some("gate.account.command.pair_device"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRefreshSessionGrant,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/refresh",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRegister,
        http_method: "POST",
        http_path: "/_arkret/gate/account/register",
        grpc: Some("GateAccount/Register"),
        mq: Some("gate.account.command.register"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountCommandRevokeSession,
        http_method: "POST",
        http_path: "/_arkret/gate/account/session-grants/revoke",
        grpc: Some("GateAccount/SessionRevoke"),
        mq: Some("gate.account.command.revoke_session"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountExchangeCompleteOidc,
        http_method: "POST",
        http_path: "/_arkret/gate/account/oidc/callback",
        grpc: Some("GateAccount/OidcCallback"),
        mq: Some("gate.account.exchange.complete_oidc"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::GateAccountExchangeCreateHandoff,
        http_method: "POST",
        http_path: "/_arkret/gate/account/authentication-handoffs",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequest,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/runtime-key-requests",
        grpc: Some("OpenAgentPairing/SubmitRuntimeKeyRequest"),
        mq: Some("open.agent_pairing.command.submit_runtime_key_request"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/resolve",
        grpc: Some("OpenAgentPairing/Resolve"),
        mq: Some("open.agent_pairing.query.resolve"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenAgentPairingQueryRuntimeKeyRequestStatus,
        http_method: "POST",
        http_path: "/_arkret/open/agent-pairing/runtime-key-requests/status",
        grpc: Some("OpenAgentPairing/RuntimeKeyRequestStatus"),
        mq: Some("open.agent_pairing.query.runtime_key_request_status"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenInviteLocatorQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/open/invite-locators/resolve",
        grpc: Some("OpenInviteLocator/Resolve"),
        mq: Some("open.invite_locator.query.resolve"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/principal_locator_resolve_request_body",
        ),
        response_schema_ref: Some("schemas/principal-locator.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandNotify,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/notify",
        grpc: Some("OpenMimi/Notify"),
        mq: Some("open.mimi.command.notify"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_notify_request_body",
        ),
        response_schema_ref: Some("schemas/mimi-operations.schema.json#/$defs/mimi_notify_outcome"),
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandProxyDownload,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/proxy-download",
        grpc: Some("OpenMimi/ProxyDownload"),
        mq: Some("open.mimi.command.proxy_download"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandReportAbuse,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/report-abuse",
        grpc: Some("OpenMimi/ReportAbuse"),
        mq: Some("open.mimi.command.report_abuse"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandRequestConsent,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/consent/request",
        grpc: Some("OpenMimi/RequestConsent"),
        mq: Some("open.mimi.command.request_consent"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandSubmitMessage,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/messages",
        grpc: Some("OpenMimi/SubmitMessage"),
        mq: Some("open.mimi.command.submit_message"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandUpdateConsent,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/consent/update",
        grpc: Some("OpenMimi/UpdateConsent"),
        mq: Some("open.mimi.command.update_consent"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiCommandUpdateRoom,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/update",
        grpc: Some("OpenMimi/RoomUpdate"),
        mq: Some("open.mimi.command.update_room"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiExchangeRequestKeyMaterial,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/key-material",
        grpc: Some("OpenMimi/KeyMaterial"),
        mq: Some("open.mimi.exchange.request_key_material"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiQueryGroupInfo,
        http_method: "GET",
        http_path: "/_arkret/open/mimi/strands/{strand_id}/group-info",
        grpc: Some("OpenMimi/GroupInfo"),
        mq: Some("open.mimi.query.group_info"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/mimi-operations.schema.json#/$defs/mimi_group_info_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiQueryIdentifiers,
        http_method: "POST",
        http_path: "/_arkret/open/mimi/identifiers/query",
        grpc: Some("OpenMimi/IdentifierQuery"),
        mq: Some("open.mimi.query.identifiers"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::OpenMimiQueryProviderDirectory,
        http_method: "GET",
        http_path: "/_arkret/open/mimi/provider-directory",
        grpc: Some("OpenMimi/ProviderDirectory"),
        mq: Some("open.mimi.query.provider_directory"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/mimi-interop.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerContactsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/contacts",
        grpc: Some("PeerContacts/Submit"),
        mq: Some("peer.contacts.command.submit"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/peer-contact-delivery-request.schema.json"),
        response_schema_ref: Some(
            "schemas/peer-contact-delivery-request.schema.json#/$defs/peer_contact_delivery_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Submit"),
        mq: Some("peer.events.command.submit"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/peer/events/describe",
        grpc: Some("PeerEvents/Describe"),
        mq: Some("peer.events.query.scan.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryFrontier,
        http_method: "GET",
        http_path: "/_arkret/peer/events/frontier",
        grpc: Some("PeerEvents/Frontier"),
        mq: Some("peer.events.query.scan.frontier"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierFederationPeerState",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/peer/events/resolve",
        grpc: Some("PeerEvents/Resolve"),
        mq: Some("peer.events.query.scan.resolve"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryScan,
        http_method: "GET",
        http_path: "/_arkret/peer/events",
        grpc: Some("PeerEvents/Query"),
        mq: Some("peer.events.query.scan"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerEventsQueryScanBody,
        http_method: "POST",
        http_path: "/_arkret/peer/events/query",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerInvitesCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/peer/invites",
        grpc: Some("PeerInvites/Submit"),
        mq: Some("peer.invites.command.submit"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/invite-delivery-request.schema.json"),
        response_schema_ref: Some(
            "schemas/invite-delivery-request.schema.json#/$defs/invite_delivery_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/keypackages/claim",
        grpc: Some("PeerKeys/KeyPackagesClaim"),
        mq: Some("peer.keys.keypackages.command.claim"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerKeysKeypackagesQueryClaim,
        http_method: "POST",
        http_path: "/_arkret/peer/keys/keypackages/claims/query",
        grpc: Some("PeerKeys/KeyPackagesClaimQuery"),
        mq: Some("peer.keys.keypackages.query.claim"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::PeerSnapshotQueryManifestHead,
        http_method: "GET",
        http_path: "/_arkret/peer/snapshot/head",
        grpc: Some("PeerSnapshot/Head"),
        mq: Some("peer.snapshot.query.manifest_head"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/snapshot.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityCommandSubmitDidOperation,
        http_method: "POST",
        http_path: "/_arkret/root/identity/submit-did-operation",
        grpc: Some("RootIdentity/SubmitDidOperation"),
        mq: Some("root.identity.command.submit_did_operation"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityDocumentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/document",
        grpc: Some("RootIdentity/GetDocument"),
        mq: Some("root.identity.document.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityDocumentView",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityLogQueryList,
        http_method: "GET",
        http_path: "/_arkret/root/identity/log",
        grpc: Some("RootIdentity/GetLog"),
        mq: Some("root.identity.log.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityLogListOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/root/identity/resolve",
        grpc: Some("RootIdentity/Resolve"),
        mq: Some("root.identity.query.resolve"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityReceiptsQueryList,
        http_method: "GET",
        http_path: "/_arkret/root/identity/receipts",
        grpc: Some("RootIdentity/GetReceipts"),
        mq: Some("root.identity.receipts.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/IdentityReceiptListOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoveryPolicyCommandPublish,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-policy",
        grpc: Some("RootIdentity/RecoveryPolicyPublish"),
        mq: Some("root.identity.recovery_policy.command.publish"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("protocol_sequence"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/recovery-policy.schema.json"),
        response_schema_ref: Some(
            "schemas/recovery-policy.schema.json#/$defs/recovery_policy_publish_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoveryPolicyResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/recovery-policy",
        grpc: Some("RootIdentity/RecoveryPolicyGet"),
        mq: Some("root.identity.recovery_policy.resource.get"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/recovery-policy.schema.json#/$defs/recovery_policy_active_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandComplete,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions/{recovery_session_id}/complete",
        grpc: Some("RootIdentity/RecoverySessionComplete"),
        mq: Some("root.identity.recovery_session.command.complete"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_complete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_complete_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.root.identity.recovery_session.resource.get\",\"strategy\":\"query_operation\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions",
        grpc: Some("RootIdentity/RecoverySessionCreate"),
        mq: Some("root.identity.recovery_session.command.create"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProof,
        http_method: "POST",
        http_path: "/_arkret/root/identity/recovery-sessions/{recovery_session_id}/proofs",
        grpc: Some("RootIdentity/RecoverySessionSubmitProof"),
        mq: Some("root.identity.recovery_session.command.submit_proof"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRecoverySessionResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/recovery-sessions/{recovery_session_id}",
        grpc: Some("RootIdentity/RecoverySessionGet"),
        mq: Some("root.identity.recovery_session.resource.get"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/recovery-session.schema.json#/$defs/recovery_session_state",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityRegistryQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/root/identity/describe",
        grpc: Some("RootIdentity/DescribeRegistry"),
        mq: Some("root.identity.registry.query.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityServiceRegistrationCommandEnsure,
        http_method: "POST",
        http_path: "/_arkret/root/identity/service-registrations:ensure",
        grpc: Some("RootIdentity/EnsureServiceRegistration"),
        mq: Some("root.identity.service_registration.command.ensure"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::RootIdentityServiceRegistrationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/root/identity/service-registrations",
        grpc: Some("RootIdentity/GetServiceRegistration"),
        mq: Some("root.identity.service_registration.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountCommandRevokeCursor,
        http_method: "POST",
        http_path: "/_arkret/self/account/cursor/revoke",
        grpc: Some("SelfAccount/CursorRevoke"),
        mq: Some("self.account.command.revoke_cursor"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountCommandUpdateProfile,
        http_method: "POST",
        http_path: "/_arkret/self/account/profile",
        grpc: Some("SelfAccount/UpdateProfile"),
        mq: Some("self.account.command.update_profile"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/self/account/describe",
        grpc: Some("SelfAccount/Describe"),
        mq: Some("self.account.query.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountQueryViewer,
        http_method: "GET",
        http_path: "/_arkret/self/account/viewer",
        grpc: Some("SelfAccount/Viewer"),
        mq: Some("self.account.query.viewer"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/account-operations.schema.json#/$defs/account_view"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountStreamSubscribe,
        http_method: "GET",
        http_path: "/_arkret/self/account/subscribe",
        grpc: Some("SelfAccount/Subscribe"),
        mq: Some("self.account.stream.subscribe"),
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/account_data",
        grpc: Some("SelfAccountData/List"),
        mq: Some("self.account_data.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/account_data/{data_type}",
        grpc: Some("SelfAccountData/Delete"),
        mq: Some("self.account_data.resource.delete"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_delete_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/account_data/{data_type}",
        grpc: Some("SelfAccountData/Get"),
        mq: Some("self.account_data.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_entry",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAccountDataResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/account_data/{data_type}",
        grpc: Some("SelfAccountData/Replace"),
        mq: Some("self.account_data.resource.replace"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_replace_request_body",
        ),
        response_schema_ref: Some(
            "schemas/account-data-operations.schema.json#/$defs/account_data_entry",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandDeactivate,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/deactivate",
        grpc: Some("SelfAgent/Deactivate"),
        mq: Some("self.agent.command.deactivate"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandPause,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/pause",
        grpc: Some("SelfAgent/Pause"),
        mq: Some("self.agent.command.pause"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandProvision,
        http_method: "POST",
        http_path: "/_arkret/self/agents",
        grpc: Some("SelfAgent/Provision"),
        mq: Some("self.agent.command.provision"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandRenewPairing,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/renew-pairing",
        grpc: Some("SelfAgent/RenewPairing"),
        mq: Some("self.agent.command.renew_pairing"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentCommandResume,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/resume",
        grpc: Some("SelfAgent/Resume"),
        mq: Some("self.agent.command.resume"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentGrantCommandAttach,
        http_method: "POST",
        http_path: "/_arkret/self/agents/{agent_id}/grants",
        grpc: Some("SelfAgent/GrantAttach"),
        mq: Some("self.agent.grant.command.attach"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentGrantResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/agents/{agent_id}/grants/{grant_id}",
        grpc: Some("SelfAgent/GrantDetach"),
        mq: Some("self.agent.grant.resource.delete"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_grant_detach_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agents/{agent_id}/participation",
        grpc: Some("SelfAgent/ParticipationGet"),
        mq: Some("self.agent.participation.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_participation_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentParticipationResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/agents/{agent_id}/participation",
        grpc: Some("SelfAgent/ParticipationReplace"),
        mq: Some("self.agent.participation.resource.replace"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_participation_replace_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_participation_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/agents",
        grpc: Some("SelfAgent/List"),
        mq: Some("self.agent.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agents/{agent_id}",
        grpc: Some("SelfAgent/Get"),
        mq: Some("self.agent.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_view"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarCommandEnsure,
        http_method: "POST",
        http_path: "/_arkret/self/agent-sidecars:ensure",
        grpc: Some("SelfAgent/SidecarEnsure"),
        mq: Some("self.agent.sidecar.command.ensure"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_sidecar_ensure_request_body",
        ),
        response_schema_ref: Some(
            "schemas/agent-operations.schema.json#/$defs/agent_sidecar_ensure_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/agent-sidecars",
        grpc: Some("SelfAgent/SidecarList"),
        mq: Some("self.agent.sidecar.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_sidecar_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAgentSidecarResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/agent-sidecars/{sidecar_id}",
        grpc: Some("SelfAgent/SidecarGet"),
        mq: Some("self.agent.sidecar.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/agent-operations.schema.json#/$defs/agent_sidecar_view"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletCommandInstall,
        http_method: "POST",
        http_path: "/_arkret/self/applets/install",
        grpc: Some("SelfApplet/Install"),
        mq: Some("self.applet.command.install"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/revoke",
        grpc: Some("SelfApplet/Revoke"),
        mq: Some("self.applet.command.revoke"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletGhostCommandProvision,
        http_method: "POST",
        http_path: "/_arkret/self/applets/{applet_id}/ghosts/provision",
        grpc: Some("SelfApplet/GhostProvision"),
        mq: Some("self.applet.ghost.command.provision"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAppletInstallCommandPreview,
        http_method: "POST",
        http_path: "/_arkret/self/applets/install/preview",
        grpc: Some("SelfApplet/InstallPreview"),
        mq: Some("self.applet.install.command.preview"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/applet-install-operations.schema.json#/$defs/applet_install_preview_request_body",
        ),
        response_schema_ref: Some("schemas/applet-install-plan.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzGrantsQueryEffective,
        http_method: "GET",
        http_path: "/_arkret/self/authz/effective-grants",
        grpc: Some("SelfAuthz/GetEffectiveGrants"),
        mq: Some("self.authz.grants.query.effective"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/service-operation-dtos.schema.json#/$defs/GrantList"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzInvitesQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/authz/invites",
        grpc: Some("SelfAuthz/GetInvites"),
        mq: Some("self.authz.invites.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/authz-operations.schema.json#/$defs/authz_invite_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfAuthzQueryCheck,
        http_method: "POST",
        http_path: "/_arkret/self/authz/check",
        grpc: Some("SelfAuthz/Check"),
        mq: Some("self.authz.query.check"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobCommandPresign,
        http_method: "POST",
        http_path: "/_arkret/self/blob/presign",
        grpc: Some("SelfBlob/Presign"),
        mq: Some("self.blob.command.presign"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/blob/get",
        grpc: Some("SelfBlob/Get"),
        mq: Some("self.blob.resource.get"),
        success_shape_kind: "binary_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobResourceHead,
        http_method: "HEAD",
        http_path: "/_arkret/self/blob/get",
        grpc: Some("SelfBlob/Head"),
        mq: Some("self.blob.resource.head"),
        success_shape_kind: "metadata_headers",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfBlobUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/blob/upload",
        grpc: Some("SelfBlob/Upload"),
        mq: Some("self.blob.upload.create"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/blob-operations.schema.json#/$defs/blob_upload_request_body",
        ),
        response_schema_ref: Some("schemas/blob-operations.schema.json#/$defs/blob_upload_outcome"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCallMediaExchangeIssueToken,
        http_method: "POST",
        http_path: "/_arkret/self/rtc/token",
        grpc: Some("SelfCallMedia/TokenExchange"),
        mq: Some("self.call.media.exchange.issue_token"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandArchive,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/archive",
        grpc: Some("SelfCircle/Archive"),
        mq: Some("self.circle.command.archive"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/self/circles",
        grpc: Some("SelfCircle/Create"),
        mq: Some("self.circle.command.create"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandRestore,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/restore",
        grpc: Some("SelfCircle/Restore"),
        mq: Some("self.circle.command.restore"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandRotateScope,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/scope-rotate",
        grpc: Some("SelfCircle/ScopeRotate"),
        mq: Some("self.circle.command.rotate_scope"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/tombstone",
        grpc: Some("SelfCircle/Tombstone"),
        mq: Some("self.circle.command.tombstone"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleMemberCommandAdd,
        http_method: "POST",
        http_path: "/_arkret/self/circles/{circle_id}/members",
        grpc: Some("SelfCircle/MemberAdd"),
        mq: Some("self.circle.member.command.add"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleMemberResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/circles/{circle_id}/members/{actor_id}",
        grpc: Some("SelfCircle/MemberRemove"),
        mq: Some("self.circle.member.resource.delete"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/circles",
        grpc: Some("SelfCircle/List"),
        mq: Some("self.circle.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfCircleResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/circles/{circle_id}",
        grpc: Some("SelfCircle/Get"),
        mq: Some("self.circle.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/circle-operations.schema.json#/$defs/circle_view"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandGrant,
        http_method: "POST",
        http_path: "/_arkret/self/consent/cells/{holder_did}/grant",
        grpc: Some("SelfConsent/Grant"),
        mq: Some("self.consent.command.grant"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRequest,
        http_method: "POST",
        http_path: "/_arkret/self/consent/request",
        grpc: Some("SelfConsent/Request"),
        mq: Some("self.consent.command.request"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/consent/cells/{holder_did}/revoke",
        grpc: Some("SelfConsent/Revoke"),
        mq: Some("self.consent.command.revoke"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/consent/cells",
        grpc: Some("SelfConsent/List"),
        mq: Some("self.consent.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfConsentResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/consent/cells/{holder_did}",
        grpc: Some("SelfConsent/Get"),
        mq: Some("self.consent.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/consent-operations.schema.json#/$defs/consent_cell_view",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandRequest,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/request",
        grpc: Some("SelfContact/Request"),
        mq: Some("self.contact.command.request"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_request_request_body",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_request_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.contact.query.list\",\"strategy\":\"query_operation\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandRespond,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/respond",
        grpc: Some("SelfContact/Respond"),
        mq: Some("self.contact.command.respond"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_respond_request_body",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_respond_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.contact.query.list\",\"strategy\":\"query_operation\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/contacts/tombstone",
        grpc: Some("SelfContact/Tombstone"),
        mq: Some("self.contact.command.tombstone"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_tombstone_request_body",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/contact_tombstone",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.contact.query.list\",\"strategy\":\"query_operation\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfContactQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/contacts",
        grpc: Some("SelfContact/List"),
        mq: Some("self.contact.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/contact-operations.schema.json#/$defs/contact_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesCommandAck,
        http_method: "POST",
        http_path: "/_arkret/self/device_messages/ack",
        grpc: Some("SelfDeviceMessages/Ack"),
        mq: Some("self.device_messages.command.ack"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesCommandSend,
        http_method: "POST",
        http_path: "/_arkret/self/device_messages",
        grpc: Some("SelfDeviceMessages/Send"),
        mq: Some("self.device_messages.command.send"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDeviceMessagesQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/device_messages",
        grpc: Some("SelfDeviceMessages/Get"),
        mq: Some("self.device_messages.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesGetOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfDirectConversationCommandResolve,
        http_method: "POST",
        http_path: "/_arkret/self/direct-conversations/resolve",
        grpc: Some("SelfDirectConversation/Resolve"),
        mq: Some("self.direct_conversation.command.resolve"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/direct_conversation_resolve_request_body",
        ),
        response_schema_ref: Some(
            "schemas/contact-operations.schema.json#/$defs/direct_conversation_resolve_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEphemeralCommandSend,
        http_method: "POST",
        http_path: "/_arkret/self/ephemeral",
        grpc: Some("SelfEphemeral/Send"),
        mq: Some("self.ephemeral.command.send"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/ephemeral-envelope.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EphemeralSubmitOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"drop_unconfirmed\"}"),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Submit"),
        mq: Some("self.events.command.submit"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsCommandSubmitSeal,
        http_method: "POST",
        http_path: "/_arkret/self/events/seals",
        grpc: Some("SelfEvents/SubmitSeal"),
        mq: Some("self.events.command.submit_seal"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: Some("canonical_hash"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/seal.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventSealSubmitOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/self/events/describe",
        grpc: Some("SelfEvents/Describe"),
        mq: Some("self.events.query.scan.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryFrontier,
        http_method: "GET",
        http_path: "/_arkret/self/events/frontier",
        grpc: Some("SelfEvents/Frontier"),
        mq: Some("self.events.query.scan.frontier"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsFrontierState",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryMlsGovernanceProof,
        http_method: "POST",
        http_path: "/_arkret/self/events/mls-governance-proof",
        grpc: Some("SelfEvents/MlsGovernanceProof"),
        mq: Some("self.events.query.mls_governance_proof"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/mls-governance-proof-bundle.schema.json#/$defs/proof_request",
        ),
        response_schema_ref: Some("schemas/mls-governance-proof-bundle.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryResolve,
        http_method: "POST",
        http_path: "/_arkret/self/events/resolve",
        grpc: Some("SelfEvents/Resolve"),
        mq: Some("self.events.query.scan.resolve"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryScan,
        http_method: "GET",
        http_path: "/_arkret/self/events",
        grpc: Some("SelfEvents/Query"),
        mq: Some("self.events.query.scan"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsQueryScanBody,
        http_method: "POST",
        http_path: "/_arkret/self/events/query",
        grpc: None,
        mq: None,
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/events/{event_id}",
        grpc: Some("SelfEvents/Get"),
        mq: Some("self.events.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/service-operation-dtos.schema.json#/$defs/EventView"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfEventsStreamSubscribe,
        http_method: "GET",
        http_path: "/_arkret/self/events/subscribe",
        grpc: Some("SelfEvents/Subscribe"),
        mq: Some("self.events.stream.subscribe"),
        success_shape_kind: "event_stream",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandIssue,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators",
        grpc: Some("SelfInviteLocator/Issue"),
        mq: Some("self.invite_locator.command.issue"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators/revoke",
        grpc: Some("SelfInviteLocator/Revoke"),
        mq: Some("self.invite_locator.command.revoke"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteLocatorCommandRotate,
        http_method: "POST",
        http_path: "/_arkret/self/invite-locators/rotate",
        grpc: Some("SelfInviteLocator/Rotate"),
        mq: Some("self.invite_locator.command.rotate"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_rotate_request_body",
        ),
        response_schema_ref: Some(
            "schemas/principal-locator.schema.json#/$defs/invite_locator_issue_outcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteReceivePolicyResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/invite-receive-policy",
        grpc: Some("SelfInviteReceivePolicy/Get"),
        mq: Some("self.invite_receive_policy.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfInviteReceivePolicyResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/invite-receive-policy",
        grpc: Some("SelfInviteReceivePolicy/Replace"),
        mq: Some("self.invite_receive_policy.resource.replace"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        response_schema_ref: Some("schemas/invite-receive-policy.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsCommandUnlock,
        http_method: "POST",
        http_path: "/_arkret/self/keys/backups/{backup_id}/unlock",
        grpc: Some("SelfKeys/BackupsUnlock"),
        mq: Some("self.keys.backups.command.unlock"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/keys/backups",
        grpc: Some("SelfKeys/BackupsList"),
        mq: Some("self.keys.backups.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_backups_list"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/keys/backups/{backup_id}",
        grpc: Some("SelfKeys/BackupsDelete"),
        mq: Some("self.keys.backups.resource.delete"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_delete_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysBackupsResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/keys/backups/{backup_id}",
        grpc: Some("SelfKeys/BackupsReplace"),
        mq: Some("self.keys.backups.resource.replace"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("idempotency_key"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/key-backup.schema.json"),
        response_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_backups_replace_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/self/keys/claim",
        grpc: Some("SelfKeys/Claim"),
        mq: Some("self.keys.command.claim"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandClaim,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/claim",
        grpc: Some("SelfKeys/KeyPackagesClaim"),
        mq: Some("self.keys.keypackages.command.claim"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_claim_request_body",
        ),
        response_schema_ref: Some(
            "schemas/keypackage-operations.schema.json#/$defs/key_packages_claim_outcome",
        ),
        uncertain_outcome: Some(
            "{\"operation_id\":\"ak.self.keys.keypackages.command.claim\",\"requires_fresh_request_identity\":true,\"strategy\":\"reissue_material\"}",
        ),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandConsume,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/consume",
        grpc: Some("SelfKeys/KeyPackagesConsume"),
        mq: Some("self.keys.keypackages.command.consume"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesCommandRevoke,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/revoke",
        grpc: Some("SelfKeys/KeyPackagesRevoke"),
        mq: Some("self.keys.keypackages.command.revoke"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysKeypackagesUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/keys/keypackages/upload",
        grpc: Some("SelfKeys/KeyPackagesUpload"),
        mq: Some("self.keys.keypackages.upload.create"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysQueryLookup,
        http_method: "POST",
        http_path: "/_arkret/self/keys/query",
        grpc: Some("SelfKeys/Query"),
        mq: Some("self.keys.query.lookup"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/keys-operations.schema.json#/$defs/keys_query_request_body",
        ),
        response_schema_ref: Some("schemas/keys-operations.schema.json#/$defs/keys_query_outcome"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfKeysUploadCreate,
        http_method: "POST",
        http_path: "/_arkret/self/keys/upload",
        grpc: Some("SelfKeys/Upload"),
        mq: Some("self.keys.upload.create"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMediaQueryIceConfig,
        http_method: "POST",
        http_path: "/_arkret/self/rtc/ice-config",
        grpc: Some("SelfMedia/IceConfig"),
        mq: Some("self.media.query.ice_config"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: Some(
            "schemas/media-operations.schema.json#/$defs/media_ice_config_request_body",
        ),
        response_schema_ref: Some("schemas/ice-config-response.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfModerationCommandReport,
        http_method: "POST",
        http_path: "/_arkret/self/moderation/report",
        grpc: Some("SelfModeration/Report"),
        mq: Some("self.moderation.command.report"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(false),
        request_schema_ref: Some("schemas/moderation-report.schema.json"),
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ModerationReportOutcome",
        ),
        uncertain_outcome: Some("{\"strategy\":\"manual_confirmation\"}"),
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMorphQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/morphs",
        grpc: Some("SelfMorph/List"),
        mq: Some("self.morph.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionMorphList",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfMorphResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/morphs/{morph_id}",
        grpc: Some("SelfMorph/Get"),
        mq: Some("self.morph.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/view.schema.json#/$defs/document_morph_projection_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfPolicyQueryCheck,
        http_method: "POST",
        http_path: "/_arkret/self/policy/check",
        grpc: Some("SelfPolicy/Check"),
        mq: Some("self.policy.query.check"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfReadCursorCommandAdvance,
        http_method: "POST",
        http_path: "/_arkret/self/read-cursors",
        grpc: Some("SelfReadCursor/Advance"),
        mq: Some("self.read_cursor.command.advance"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfReadCursorQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/read-cursors",
        grpc: Some("SelfReadCursor/List"),
        mq: Some("self.read_cursor.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/read-cursor-operations.schema.json#/$defs/read_cursor_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandArchive,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/archive",
        grpc: Some("SelfRealm/Archive"),
        mq: Some("self.realm.command.archive"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandDestroy,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/destroy",
        grpc: Some("SelfRealm/Destroy"),
        mq: Some("self.realm.command.destroy"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandFreeze,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/freeze",
        grpc: Some("SelfRealm/Freeze"),
        mq: Some("self.realm.command.freeze"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmCommandTombstone,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/tombstone",
        grpc: Some("SelfRealm/Tombstone"),
        mq: Some("self.realm.command.tombstone"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationAuditQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/audit",
        grpc: Some("SelfRealmJoinApplication/ListAudit"),
        mq: Some("self.realm.join_application.audit.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_audit_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandCancel,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/cancel",
        grpc: Some("SelfRealmJoinApplication/Cancel"),
        mq: Some("self.realm.join_application.command.cancel"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandReview,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}/reviews",
        grpc: Some("SelfRealmJoinApplication/Review"),
        mq: Some("self.realm.join_application.command.review"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationCommandSubmit,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications",
        grpc: Some("SelfRealmJoinApplication/Submit"),
        mq: Some("self.realm.join_application.command.submit"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications",
        grpc: Some("SelfRealmJoinApplication/List"),
        mq: Some("self.realm.join_application.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_list_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmJoinApplicationResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/join-applications/{application_ref}",
        grpc: Some("SelfRealmJoinApplication/Get"),
        mq: Some("self.realm.join_application.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/join-policy-operations.schema.json#/$defs/application_get_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmModerationPolicyQueryEffective,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/moderation-policy/effective",
        grpc: Some("SelfRealm/ModerationPolicyEffective"),
        mq: Some("self.realm.moderation_policy.query.effective"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_effective_moderation_policy",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmModerationPolicyResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/realms/{realm_id}/moderation-policy",
        grpc: Some("SelfRealm/ModerationPolicyReplace"),
        mq: Some("self.realm.moderation_policy.resource.replace"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmQueryExport,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/export",
        grpc: Some("SelfRealm/Export"),
        mq: Some("self.realm.query.export"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/realm-read-operations.schema.json#/$defs/realm_export"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}",
        grpc: Some("SelfRealm/Get"),
        mq: Some("self.realm.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-read-operations.schema.json#/$defs/realm_lifecycle_view",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkCommandCreate,
        http_method: "POST",
        http_path: "/_arkret/self/realms/{realm_id}/links",
        grpc: Some("SelfRealmLink/Create"),
        mq: Some("self.realm_link.command.create"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkQueryEffectivePolicy,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/effective-policy",
        grpc: Some("SelfRealmLink/EffectivePolicy"),
        mq: Some("self.realm_link.query.effective_policy"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_effective_policy_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/links",
        grpc: Some("SelfRealmLink/List"),
        mq: Some("self.realm_link.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmLinkResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/realms/{realm_id}/links/{target_realm_id}",
        grpc: Some("SelfRealmLink/Delete"),
        mq: Some("self.realm_link.resource.delete"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-link-operations.schema.json#/$defs/realm_link_mutation_outcome",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmOrganizationQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/organizations",
        grpc: Some("SelfRealmOrganization/List"),
        mq: Some("self.realm_organization.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceDelete,
        http_method: "DELETE",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Delete"),
        mq: Some("self.realm_policy_server.resource.delete"),
        success_shape_kind: "empty_response",
        idempotency_mechanism: Some("object_id"),
        retry_safe: Some(true),
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceGet,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Get"),
        mq: Some("self.realm_policy_server.resource.get"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/realm-policy-server-operations.schema.json#/$defs/realm_policy_server_view",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfRealmPolicyServerResourceReplace,
        http_method: "PUT",
        http_path: "/_arkret/self/realms/{realm_id}/policy-server",
        grpc: Some("SelfRealmPolicyServer/Replace"),
        mq: Some("self.realm_policy_server.resource.replace"),
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
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSnapshotQueryManifestHead,
        http_method: "GET",
        http_path: "/_arkret/self/snapshot/head",
        grpc: Some("SelfSnapshot/Head"),
        mq: Some("self.snapshot.query.manifest_head"),
        success_shape_kind: "schema_resource",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some("schemas/snapshot.schema.json"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfSpaceQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/spaces",
        grpc: Some("SelfSpace/List"),
        mq: Some("self.space.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionSpaceList",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfStrandQueryList,
        http_method: "GET",
        http_path: "/_arkret/self/realms/{realm_id}/strands",
        grpc: Some("SelfStrand/List"),
        mq: Some("self.strand.query.list"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: Some(
            "schemas/service-operation-dtos.schema.json#/$defs/ProjectionStrandList",
        ),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::SelfViewsCollectionProjectionCommandMaterialize,
        http_method: "POST",
        http_path: "/_arkret/self/views/{view_id}/projection",
        grpc: Some("SelfViews/CollectionProjection"),
        mq: Some("self.views.collection_projection.command.materialize"),
        success_shape_kind: "typed_response",
        idempotency_mechanism: Some("none"),
        retry_safe: Some(true),
        request_schema_ref: Some("schemas/view.schema.json#/$defs/view_projection_request_body"),
        response_schema_ref: Some("schemas/view.schema.json#/$defs/collection_projection_view"),
        uncertain_outcome: None,
    },
    ServiceOperationDescriptor {
        id: ServiceOperationId::ServerQueryDescribe,
        http_method: "GET",
        http_path: "/_arkret/describe",
        grpc: Some("Server/Describe"),
        mq: Some("server.query.describe"),
        success_shape_kind: "service_describe",
        idempotency_mechanism: None,
        retry_safe: None,
        request_schema_ref: None,
        response_schema_ref: None,
        uncertain_outcome: None,
    },
];
