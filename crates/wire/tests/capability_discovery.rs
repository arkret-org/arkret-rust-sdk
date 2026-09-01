use arkret_wire::{
    BindingKind, ServiceKind, ServiceOperationId, feature_descriptor,
    operation_binding_is_registered, operation_bundle_descriptor, role_describe_bundle_descriptor,
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
        ServiceOperationId::SelfEventsStreamSubscribeV1,
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
fn station_http_core_advertises_service_resolution() {
    let bundle = operation_bundle_descriptor("ak.operation_bundle.station.http_core.v1")
        .expect("Station HTTP core bundle must be registered");

    assert_eq!(bundle.service_kind, ServiceKind::Station);
    assert!(bundle.contains(
        ServiceOperationId::OpenServiceReadResolutionV1,
        BindingKind::HttpJson,
    ));
}

#[test]
fn station_current_signer_evidence_bundle_closes_both_query_hops() {
    let bundle =
        operation_bundle_descriptor("ak.operation_bundle.station.current_signer_evidence.v1")
            .expect("Station current-signer evidence bundle must be registered");

    assert_eq!(bundle.service_kind, ServiceKind::Station);
    assert_eq!(bundle.members.len(), 2);
    assert!(bundle.contains(
        ServiceOperationId::SelfCurrentSignerEvidenceReadResolveV1,
        BindingKind::HttpJson,
    ));
    assert!(bundle.contains(
        ServiceOperationId::PeerCurrentSignerEvidenceReadResolveV1,
        BindingKind::HttpJson,
    ));
}

#[test]
fn station_history_key_recovery_bundle_closes_feature_requirements() {
    let bundle = operation_bundle_descriptor("ak.operation_bundle.station.history_key_recovery.v1")
        .expect("Station history-key recovery bundle must be registered");
    let feature = feature_descriptor("ak.feature.history_key_recovery.v1")
        .expect("history-key recovery feature must be registered");

    assert_eq!(bundle.service_kind, ServiceKind::Station);
    assert_eq!(bundle.members, feature.required_operation_pairs);
    assert_eq!(bundle.members.len(), 11);
    assert!(bundle.contains(
        ServiceOperationId::SelfHistoryKeyRequestsReadListV1,
        BindingKind::HttpJson,
    ));
}
