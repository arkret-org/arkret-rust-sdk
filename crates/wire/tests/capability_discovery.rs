use arkret_wire::{
    BindingKind, ServiceKind, ServiceOperationId, operation_binding_is_registered,
    operation_bundle_descriptor, role_describe_bundle_descriptor,
};

#[test]
fn every_describable_role_has_its_exact_mandatory_bundle() {
    for &service_kind in ServiceKind::ALL {
        let bundle = role_describe_bundle_descriptor(service_kind);
        if service_kind.valid_in("service_describe") {
            let bundle = bundle.expect("every describable role has a describe bundle");
            assert_eq!(bundle.service_kind, service_kind);
            assert_eq!(
                bundle.operation_bundle_id,
                format!("ak.operation_bundle.{}.describe.v1", service_kind.as_str())
            );
            assert!(bundle.contains(
                ServiceOperationId::ServerReadDescribeV1,
                BindingKind::HttpJson
            ));
        } else {
            assert!(bundle.is_none());
        }
    }
}

#[test]
fn alternate_carrier_membership_is_typed() {
    assert!(operation_binding_is_registered(
        ServiceOperationId::SelfCommittedEventStreamSubscribeV1,
        BindingKind::Websocket,
    ));
    assert!(operation_binding_is_registered(
        ServiceOperationId::SelfBlobUploadCreateV1,
        BindingKind::Tus,
    ));
    assert!(!operation_binding_is_registered(
        ServiceOperationId::ServerReadDescribeV1,
        BindingKind::Websocket,
    ));
}

#[test]
fn station_http_core_current_advertises_service_resolution() {
    let bundle = operation_bundle_descriptor("ak.operation_bundle.station.http_core_current.v1")
        .expect("Station HTTP core bundle must be registered");

    assert_eq!(bundle.service_kind, ServiceKind::Station);
    assert!(bundle.contains(
        ServiceOperationId::OpenServiceReadResolutionV1,
        BindingKind::HttpJson,
    ));
}

#[test]
fn station_device_pairing_handoff_bundle_closes_all_three_open_operations() {
    let bundle =
        operation_bundle_descriptor("ak.operation_bundle.station.device_pairing_handoff.v1")
            .expect("Station device-pairing handoff bundle must be registered");

    assert_eq!(bundle.service_kind, ServiceKind::Station);
    assert_eq!(bundle.members.len(), 3);
    assert!(bundle.contains(
        ServiceOperationId::OpenDevicePairingCommandStageV1,
        BindingKind::HttpJson,
    ));
    assert!(bundle.contains(
        ServiceOperationId::OpenDevicePairingReadResolveV1,
        BindingKind::HttpJson,
    ));
    assert!(bundle.contains(
        ServiceOperationId::OpenDevicePairingReadStatusV1,
        BindingKind::HttpJson,
    ));
}

#[test]
fn current_station_bundles_have_exact_optional_members() {
    assert!(operation_bundle_descriptor("ak.operation_bundle.station.http_core.v1").is_none());
    for (bundle_id, member) in [
        (
            "ak.operation_bundle.station.invite_delivery.v1",
            ServiceOperationId::SelfInvitesCommandDispatchV1,
        ),
        (
            "ak.operation_bundle.station.realm_authority_handoff.v1",
            ServiceOperationId::PeerRealmAuthorityCommandHandoffV1,
        ),
    ] {
        let bundle = operation_bundle_descriptor(bundle_id).unwrap();
        assert_eq!(bundle.service_kind, ServiceKind::Station);
        assert_eq!(bundle.members.len(), 1);
        assert!(bundle.contains(member, BindingKind::HttpJson));
    }
    let pairing =
        operation_bundle_descriptor("ak.operation_bundle.station.account_gate_pairing.v1").unwrap();
    assert_eq!(pairing.service_kind, ServiceKind::Station);
    assert_eq!(pairing.members.len(), 2);
    assert!(pairing.contains(
        ServiceOperationId::GateAccountCommandFinalizeDevicePairingV1,
        BindingKind::HttpJson,
    ));
    assert!(pairing.contains(
        ServiceOperationId::GateAccountReadClaimDevicePairingCodeV1,
        BindingKind::HttpJson,
    ));
}
