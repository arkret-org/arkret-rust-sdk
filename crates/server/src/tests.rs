use super::*;
use crate::registry::service_routes;

#[test]
fn service_route_operation_ids_are_unique() {
    let mut ids = BTreeSet::new();
    for route in service_routes() {
        assert!(ids.insert(route.operation_id), "duplicate {}", route.operation_id);
        assert!(
            // All HTTP/JSON binding paths live under the negative-space root
            // `/_cokret/` with no version segment; the first segment is a
            // trust-circle name (self/gate/root/find/peer/open/edge/local),
            // per cokret-spec service-http-binding.md §2.1. Admin is the
            // deployment-local namespace at `/_cokret/local/admin/*`.
            route.path.starts_with("/_cokret/") || route.path.starts_with("/.well-known/"),
            "unexpected route namespace: {} ({})",
            route.path,
            route.operation_id,
        );
    }
}

#[test]
fn service_route_registry_matches_required_spec_operations() {
    let actual = service_routes()
        .iter()
        .map(|route| (route.operation_id, route.path))
        .collect::<BTreeMap<_, _>>();
    for (operation_id, path) in [
        ("ck.root.identity.resolve", "/_cokret/root/identity/resolve"),
        ("ck.self.account.subscribe", "/_cokret/self/account/subscribe"),
        ("ck.self.account.describe", "/_cokret/self/account/describe"),
        ("ck.self.events.describe", "/_cokret/self/events/describe"),
        ("ck.self.events.submit", "/_cokret/self/events"),
        ("ck.self.events.get", "/_cokret/self/events/{event_id}"),
        ("ck.self.events.resolve", "/_cokret/self/events/resolve"),
        ("ck.self.events.frontier", "/_cokret/self/events/frontier"),
        ("ck.self.events.subscribe", "/_cokret/self/events/subscribe"),
        ("ck.self.events.query", "/_cokret/self/events/query"),
        (
            "ck.find.directory.private_contact_discovery",
            "/_cokret/find/directory/private-contact-discovery",
        ),
        ("ck.self.blob.upload", "/_cokret/self/blob/upload"),
        ("ck.edge.push.register_device", "/_cokret/edge/push/register-device"),
        ("ck.self.keys.keypackages.claim", "/_cokret/self/keys/keypackages/claim"),
        ("ck.self.authz.check", "/_cokret/self/authz/check"),
        ("ck.self.policy.check", "/_cokret/self/policy/check"),
        ("ck.open.mimi.room_update", "/_cokret/open/mimi/flows/{flow_id}/update"),
        ("ck.gate.account.issue_session_grant", "/_cokret/gate/account/session-grants"),
        ("ck.admin.revoke_device", "/_cokret/local/admin/devices/{device_id}/revoke"),
        ("ck.edge.applet.transaction", "/_cokret/edge/applet/transactions"),
    ] {
        assert_eq!(actual.get(operation_id), Some(&path), "{operation_id}");
    }
}

#[test]
fn query_auth_and_wire_negative_vectors_are_available() {
    let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
    assert!(reject_query_auth(&query).is_err());

    let vectors = wire_negative_vectors();
    assert!(vectors.iter().any(|vector| vector.name == "query_auth_rejected"));
    assert!(vectors.iter().any(|vector| vector.expected_error_code == "digest_mismatch"));
    assert!(vectors.iter().any(|vector| vector.expected_error_code == "missing_param"));

    let golden = protocol_golden_vectors();
    assert!(golden.iter().any(|vector| vector.profile == "ck.conformance.digest.v1"));
}

#[test]
fn protocol_server_fixture_covers_core_flow_groups() {
    let report = ProtocolServerFixture::default().run().unwrap();

    for flow in [
        ProtocolFixtureFlow::Server,
        ProtocolFixtureFlow::Identity,
        ProtocolFixtureFlow::Sync,
        ProtocolFixtureFlow::Blob,
        ProtocolFixtureFlow::Authz,
        ProtocolFixtureFlow::Directory,
        ProtocolFixtureFlow::Push,
        ProtocolFixtureFlow::DeviceMessages,
        ProtocolFixtureFlow::Keys,
        ProtocolFixtureFlow::Policy,
        ProtocolFixtureFlow::Media,
        ProtocolFixtureFlow::Moderation,
        ProtocolFixtureFlow::Applet,
    ] {
        assert!(report.covers(flow));
    }
    assert!(
        report.steps.iter().any(
            |step| step.flow == ProtocolFixtureFlow::Blob && step.operation_id == "ck.self.blob.get"
        )
    );
    assert!(report.steps.iter().any(|step| {
        step.flow == ProtocolFixtureFlow::Sync && step.operation_id == "ck.self.events.submit"
    }));
}

#[test]
fn framework_independent_handler_shape_can_be_mocked() {
    struct MockHandler;

    impl EndpointHandler for MockHandler {
        fn handle(&mut self, request: ServerReqBody) -> Result<ServerResBody> {
            match request {
                ServerReqBody::ServerDescribe => {
                    Ok(ServerResBody::ServerDescription(Box::new(ServerDescription {
                        service_did: cokret_core::Did::new("did:web:svc.example").unwrap(),
                        trust_domain: cokret_core::TypedTrustDomainId::new(
                            "ck:trust_domain:example.net",
                        )
                        .unwrap(),
                        service_type: "principal_server".to_owned(),
                        protocol_version: cokret_core::PROTOCOL_VERSION.to_owned(),
                        supported_profiles: vec![],
                        supported_features: vec![],
                        supported_operations: service_routes()
                            .iter()
                            .map(|route| route.operation_id.to_owned())
                            .collect(),
                        supported_bindings: vec![],
                        auth_metadata: Value::Null,
                        limits: Value::Null,
                        plaintext_visibility: Value::Null,
                        implemented_features: vec![],
                        claimed_profiles: vec![],
                        verified_profiles: vec![],
                        experimental_features: vec![],
                        compat_surfaces: vec![],
                        development_mode: false,
                        rate_limit: Value::Null,
                        egress_network_policy: Some(
                            cokret_core::EgressNetworkPolicy::deny_private_defaults(),
                        ),
                        supported_reducer_profiles: vec![],
                        supported_schema_profiles: vec![],
                        frontier: Vec::new(),
                        snapshot_frontier: Vec::new(),
                        reducer_profile: None,
                        last_materialized_at: None,
                    })))
                }
                _ => Err(cokret_core::Error::Protocol("mock endpoint not implemented".to_owned())),
            }
        }
    }

    let mut handler = MockHandler;
    let response = handler.handle(ServerReqBody::ServerDescribe).unwrap();
    let ServerResBody::ServerDescription(description) = response else {
        panic!("unexpected response");
    };
    assert!(description.supported_operations.contains(&"ck.self.account.subscribe".to_owned()));
}
