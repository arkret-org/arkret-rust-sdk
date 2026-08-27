use arkret_wire::{
    BindingKind, ServiceKind, ServiceOperationId, operation_binding_is_registered,
    role_describe_bundle_descriptor,
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
