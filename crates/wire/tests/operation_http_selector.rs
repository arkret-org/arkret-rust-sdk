use arkret_wire::ServiceOperationId;

#[test]
fn resolves_literal_and_templated_http_operations() {
    assert_eq!(
        ServiceOperationId::from_http_request("GET", "/_arkret/describe"),
        Some(ServiceOperationId::ServerReadDescribeV1)
    );
    assert_eq!(
        ServiceOperationId::from_http_request(
            "GET",
            "/_arkret/self/realms/ak%3Arealm%3Afixture/morphs/ak%3Amorph%3Afixture",
        ),
        Some(ServiceOperationId::SelfMorphResourceGetV1)
    );
    assert_eq!(
        ServiceOperationId::from_http_request("GET", "/_arkret/self/events/subscribe"),
        Some(ServiceOperationId::SelfEventsStreamSubscribeV1),
        "a literal route must beat the overlapping event_id placeholder"
    );
}

#[test]
fn resolves_internal_device_pairing_operations() {
    let cases = [
        (
            "/_arkret/gate/account/device-pairing/stages",
            ServiceOperationId::GateAccountCommandStageDevicePairingV1,
        ),
        (
            "/_arkret/gate/account/device-pairing/resolutions",
            ServiceOperationId::GateAccountReadResolveDevicePairingV1,
        ),
        (
            "/_arkret/gate/account/device-pairing/status-queries",
            ServiceOperationId::GateAccountReadDevicePairingStatusV1,
        ),
    ];

    for (path, expected) in cases {
        assert_eq!(
            ServiceOperationId::from_http_request("POST", path),
            Some(expected)
        );
        assert!(expected.matches_http_request("POST", path));
        assert_eq!(ServiceOperationId::from_http_request("GET", path), None);
    }
}

#[test]
fn internal_device_pairing_bindings_reuse_public_schemas() {
    let cases = [
        (
            ServiceOperationId::GateAccountCommandStageDevicePairingV1,
            ServiceOperationId::OpenDevicePairingCommandStageV1,
        ),
        (
            ServiceOperationId::GateAccountReadResolveDevicePairingV1,
            ServiceOperationId::OpenDevicePairingReadResolveV1,
        ),
        (
            ServiceOperationId::GateAccountReadDevicePairingStatusV1,
            ServiceOperationId::OpenDevicePairingReadStatusV1,
        ),
    ];

    for (internal, public) in cases {
        let internal = internal.descriptor();
        let public = public.descriptor();
        assert_eq!(internal.request_schema_ref, public.request_schema_ref);
        assert_eq!(internal.response_schema_ref, public.response_schema_ref);
        assert_eq!(internal.body_class, public.body_class);
        assert_eq!(internal.success_shape_kind, public.success_shape_kind);
    }
}

#[test]
fn internal_device_pairing_operation_ids_round_trip_as_wire_tokens() {
    for operation_id in [
        ServiceOperationId::GateAccountCommandStageDevicePairingV1,
        ServiceOperationId::GateAccountReadResolveDevicePairingV1,
        ServiceOperationId::GateAccountReadDevicePairingStatusV1,
    ] {
        let encoded = serde_json::to_string(&operation_id).expect("operation id serializes");
        let decoded: ServiceOperationId =
            serde_json::from_str(&encoded).expect("operation id deserializes");
        assert_eq!(decoded, operation_id);
        assert_eq!(encoded, format!("\"{}\"", operation_id.as_str()));
    }

    assert!(
        serde_json::from_str::<ServiceOperationId>(
            "\"ak.gate.account.read.unknown_device_pairing.v1\""
        )
        .is_err()
    );
}

#[test]
fn rejects_unknown_method_path_and_empty_placeholder() {
    assert_eq!(
        ServiceOperationId::from_http_request("POST", "/_arkret/describe"),
        None
    );
    assert_eq!(
        ServiceOperationId::from_http_request("GET", "/_arkret/not-registered"),
        None
    );
    assert_eq!(
        ServiceOperationId::from_http_request("GET", "/_arkret/self/events/"),
        None
    );
}

#[test]
fn exact_selector_must_belong_to_the_http_route_family() {
    assert!(
        ServiceOperationId::SelfEventsStreamSubscribeV1
            .matches_http_request("GET", "/_arkret/self/events/subscribe")
    );
    assert!(
        !ServiceOperationId::SelfAccountStreamSubscribeV1
            .matches_http_request("GET", "/_arkret/self/events/subscribe")
    );
}
