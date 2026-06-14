//! Service description schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/service-describe.schema.json#/$defs/cidr`.
pub type Cidr = String;

/// Counterpart for `spec/v1/artifacts/schemas/service-operation-dtos.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceOperationDtos {
    AccountCursorRevokeRequestBody(AccountCursorRevokeRequestBody),
    AccountCursorRevokeOutcome(AccountCursorRevokeOutcome),
    AccountOidcCallbackRequestBody(crate::AccountOidcCallbackRequestBody),
    AccountOidcCallbackOutcome(crate::AccountOidcCallbackOutcome),
    AuthzCheckRequestBody(AuthzCheckRequestBody),
    AuthzCheckOutcome(AuthzCheckOutcome),
    BlobPresignRequestBody(BlobPresignRequestBody),
    BlobPresignOutcome(BlobPresignOutcome),
    CallMediaTokenExchangeRequestBody(CallMediaTokenExchangeRequestBody),
    CallMediaTokenExchangeOutcome(CallMediaTokenExchangeOutcome),
    DeviceMessagesGetOutcome(DeviceMessagesGetOutcome),
    DeviceMessagesAckRequestBody(DeviceMessagesAckRequestBody),
    DeviceMessagesAckOutcome(DeviceMessagesAckOutcome),
    DeviceMessagesSendRequestBody(DeviceMessagesSendRequestBody),
    DeviceMessagesSendOutcome(DeviceMessagesSendOutcome),
    DidOperationSubmitRequestBody(DidOperationSubmitRequestBody),
    DidOperationSubmitOutcome(DidOperationSubmitOutcome),
    DirectoryAnnounceRequestBody(DirectoryAnnounceRequestBody),
    DirectoryAnnounceOutcome(DirectoryAnnounceOutcome),
    DirectoryWithdrawRequestBody(DirectoryWithdrawRequestBody),
    DirectoryWithdrawOutcome(DirectoryWithdrawOutcome),
    EphemeralSubmitOutcome(crate::EphemeralSubmitOutcome),
    EventView(crate::EventView),
    EventsFrontierState(EventsFrontierState),
    EventsQueryPostRequestBody(EventsQueryPostRequestBody),
    EventsQueryOutcome(crate::EventsQueryOutcome),
    EventsResolveRequestBody(crate::EventsResolveRequestBody),
    EventsResolveOutcome(crate::EventsResolveOutcome),
    EventsSubmitRequestBody(crate::EventsSubmitRequestBody),
    EventsSubmitOutcome(crate::EventsSubmitOutcome),
    GrantList(GrantList),
    IdentityDocumentView(IdentityDocumentView),
    IdentityResolveRequestBody(IdentityResolveRequestBody),
    IdentityResolveOutcome(IdentityResolveOutcome),
    ModerationReportOutcome(ModerationReportOutcome),
    PolicyCheckRequestBody(PolicyCheckRequestBody),
    PolicyCheckOutcome(PolicyCheckOutcome),
    ProjectionStrandList(crate::ProjectionStrandList),
    ProjectionMorphList(crate::ProjectionMorphList),
    ProjectionSpaceList(crate::ProjectionSpaceList),
    SessionGrantRequestBody(crate::SessionGrantRequestBody),
    SessionGrantOutcome(crate::SessionGrantOutcome),
}
