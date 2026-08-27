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
