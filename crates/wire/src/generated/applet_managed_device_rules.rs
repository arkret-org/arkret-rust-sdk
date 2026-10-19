//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/applet-managed-authority-registry.json; version=2026-10-16.1;
//! sha256=aae81144173ee5fff611d4fbe6862490e3b0a6e2b8bb85081c9ad31627472b1c Input: registry/
//! contract-registry.json; version=2026-10-19.3;
//! sha256=f60768abb5c36311f9ddbbc39d04c7f6c00c7722d0675358957ca541aec9c26f
//! Entries: managed_device_operations=21

use super::{CapabilityActionId, ServiceOperationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceControl {
    OwnExactPreviouslyDeliveredItemsAck,
    OwnExactKeypackageRevoke,
    OwnScopeBoundKeypackageUpload,
    OwnExactDurableWelcomeReceiptConsume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceScopeRule {
    AllActions(&'static [CapabilityActionId]),
    SubmittedBusinessActions,
    DeviceControl(ManagedDeviceControl),
}

/// Transport inventory only; every business gate remains mandatory.
pub const fn applet_managed_device_scope_rule(
    operation: ServiceOperationId,
) -> Option<ManagedDeviceScopeRule> {
    Some(match operation {
        ServiceOperationId::SelfBlobCommandPresignV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobCommandPresignV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobResourceGetV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobResourceGetV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobResourceHeadV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobResourceHeadV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobUploadCreateV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::SelfBlobUploadCreateV1])
        }
        ServiceOperationId::SelfDeviceMessagesCommandAckV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnExactPreviouslyDeliveredItemsAck,
            )
        }
        ServiceOperationId::SelfDeviceMessagesReadListV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesCommandClaimV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnExactDurableWelcomeReceiptConsume,
            )
        }
        ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1 => {
            ManagedDeviceScopeRule::DeviceControl(ManagedDeviceControl::OwnExactKeypackageRevoke)
        }
        ServiceOperationId::SelfKeysKeypackagesReadClaimV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesUploadCreateV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnScopeBoundKeypackageUpload,
            )
        }
        ServiceOperationId::SelfMlsReadGroupStateMaterialV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfMlsReadRosterAuthorityV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfSignerKeysReadResolveV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCurrentResultsReadExactV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventResourceGetV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventReadScanV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventStreamSubscribeV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfRealmStateSnapshotReadByRefV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfEventsCommandSubmitV1 => {
            ManagedDeviceScopeRule::SubmittedBusinessActions
        }
        _ => return None,
    })
}
