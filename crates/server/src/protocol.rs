use super::*;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ServerRequestBody {
    ServerDescribe,
    IdentityDescribe,
    IdentityResolve(IdentityResolveRequestBody),
    IdentityDocument {
        did: String,
        version: Option<String>,
    },
    IdentityLog {
        did: String,
        cursor: Option<String>,
        limit: Option<u32>,
    },
    IdentitySubmitDidOperation(DidOperationSubmitRequestBody),
    IdentityEnsureServiceRegistration(ServiceRegistrationEnsureRequestBody),
    IdentityGetServiceRegistration(ServiceRegistrationKey),
    IdentityReceipts {
        did: String,
        head: String,
    },
    Sync(SyncRequestBody),
    SyncDescribe,
    AccountCursorRevoke(AccountCursorRevokeRequestBody),
    SyncBackfill {
        realm_id: String,
        cursor: Option<String>,
        limit: Option<u32>,
    },
    SyncSnapshotHead {
        realm_id: String,
    },
    FederationRealmMembers {
        realm_id: String,
        cursor: Option<String>,
        limit: Option<u32>,
    },
    FederationVerifyActor(FederationVerifyActorRequestBody),
    DirectoryDescribe,
    DirectorySearchRealms(DirectorySearchRealmsRequestBody),
    DirectoryResolveRealm(DirectoryResolveRealmRequestBody),
    DirectorySearchOrganizations(DirectorySearchOrganizationsRequestBody),
    DirectoryResolveOrganization(DirectoryResolveOrganizationRequestBody),
    DirectorySearchActors(DirectorySearchActorsRequestBody),
    DirectorySearchUsers(DirectorySearchUsersRequestBody),
    DirectoryResolveHandle(DirectoryResolveHandleRequestBody),
    BlobUpload {
        metadata: BlobUploadMetadata,
        bytes: Option<Vec<u8>>,
    },
    BlobHead {
        blob_ref: String,
    },
    BlobGet {
        blob_ref: String,
        range: Option<String>,
    },
    PushRegisterDevice(PushRegisterDeviceRequestBody),
    PushUnregisterDevice(PushUnregisterDeviceRequestBody),
    PushNotify(PushNotifyRequestBody),
    DeviceMessagesSend {
        txn_id: String,
        request: DeviceMessagesSendRequestBody,
    },
    DeviceMessagesGet {
        from: Option<String>,
        limit: Option<u32>,
    },
    DeviceMessagesAck(DeviceMessagesAckRequestBody),
    KeysUpload(KeysUploadRequestBody),
    KeysQuery(KeysQueryRequestBody),
    KeysClaim(KeysClaimRequestBody),
    AuthzEffectiveGrants {
        realm_id: String,
        subject: String,
        at: Option<String>,
    },
    AuthzInvites {
        subject: String,
        realm_id: Option<String>,
        cursor: Option<String>,
    },
    AuthzCheck(AuthzCheckRequestBody),
    PolicyCheck(PolicyCheckRequestBody),
    MediaIceConfig(MediaIceConfigRequestBody),
    ModerationReport(ModerationReportRequestBody),
    AppletPing,
    AppletDescribe,
    AppletTransaction {
        txn_id: String,
        request: AppletTransactionRequestBody,
    },
    AppletActor {
        actor_id: String,
    },
    AppletRealm {
        realm_id_or_alias: String,
    },
    AppletProtocol {
        protocol: String,
    },
    AppletThirdPartyUsers,
    AppletThirdPartyLocations,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ServerOutcome {
    ServerDescribe(Box<ServiceDescribe>),
    IdentityDescription(IdentityDescription),
    IdentityResolve(IdentityResolveOutcome),
    IdentityDocument(IdentityDocumentView),
    IdentityLog(IdentityLogListOutcome),
    SubmitDidOperation(DidOperationSubmitOutcome),
    ServiceRegistration(ServiceRegistrationOutcome),
    IdentityReceipts(IdentityReceiptListOutcome),
    AccountSubscribeFrame(AccountSubscribeFrame),
    AccountCursorRevoke(AccountCursorRevokeOutcome),
    EventsQuery(EventsQueryOutcome),
    SyncSnapshotHead(SnapshotManifest),
    FederationRealmMembers(FederationRealmMemberList),
    FederationVerifyActor(FederationVerifyActorOutcome),
    DirectoryDescribe(ServiceDescribe),
    DirectorySearchRealms(DirectoryRealmSearchOutcome),
    DirectoryResolveRealm(DirectoryRealmResolutionOutcome),
    DirectorySearchOrganizations(DirectoryOrganizationSearchOutcome),
    DirectoryResolveOrganization(DirectoryOrganizationResolutionOutcome),
    DirectorySearchActors(DirectoryActorSearchOutcome),
    DirectorySearchUsers(DirectoryUserSearchOutcome),
    DirectoryResolveHandle(Box<DirectoryHandleResolutionOutcome>),
    BlobUpload(BlobUploadOutcome),
    BlobHead(Blob),
    BlobBytes(Vec<u8>),
    PushRegisterDevice(PushRegisterDeviceOutcome),
    Ok(OkOutcome),
    PushNotify(PushNotifyOutcome),
    DeviceMessagesSend(DeviceMessagesSendOutcome),
    DeviceMessagesReceive(DeviceMessagesGetOutcome),
    DeviceMessagesAck(DeviceMessagesAckOutcome),
    KeysUpload(KeysUploadOutcome),
    KeysQuery(KeysQueryOutcome),
    KeysClaim(KeysClaimOutcome),
    EffectiveGrants(GrantList),
    AuthzInvites(AuthzInviteList),
    AuthzCheck(AuthzCheckOutcome),
    PolicyCheck(PolicyCheckOutcome),
    MediaIceConfig(MediaIceConfigOutcome),
    ModerationReport(ModerationReportOutcome),
    AppletPing(AppletPingOutcome),
    AppletDescribe(ServiceDescribe),
    AppletTransaction(AppletTransactionOutcome),
    AppletActor(AppletActorView),
    AppletRealm(AppletRealmView),
    AppletProtocol(AppletProtocolMetadata),
    AppletThirdPartyUsers(Value),
    AppletThirdPartyLocations(Value),
}

pub trait EndpointHandler {
    fn handle(&mut self, request: ServerRequestBody) -> Result<ServerOutcome>;
}
