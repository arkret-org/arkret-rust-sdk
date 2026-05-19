use super::*;
use crate::registry::service_routes;

#[test]
fn service_route_operation_ids_are_unique() {
    let mut ids = BTreeSet::new();
    for route in service_routes() {
        assert!(ids.insert(route.operation_id), "duplicate {}", route.operation_id);
        assert!(
            route.path.starts_with("/api/v1/")
                || route.path.starts_with("/contrix/v1/")
                || route.path.starts_with("/.well-known/")
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
        ("cx.identity.resolve", "/api/v1/identity/resolve"),
        ("cx.sync.account", "/api/v1/sync"),
        ("cx.events.describe", "/api/v1/events/describe"),
        ("cx.events.submit", "/api/v1/events"),
        ("cx.events.get", "/api/v1/events/{event_id}"),
        ("cx.events.batch_get", "/api/v1/events/batch-get"),
        ("cx.events.frontier", "/api/v1/events/frontier"),
        ("cx.events.subscribe", "/api/v1/events/subscribe"),
        ("cx.events.query", "/api/v1/events"),
        ("cx.agent_workspace.resolve_mirror_flow", "/api/v1/agent_workspace/mirror_flow"),
        ("cx.agent_workspace.list_pending_tasks", "/api/v1/agent_workspace/pending_tasks"),
        ("cx.directory.private_contact_discovery", "/api/v1/directory/private-contact-discovery"),
        ("cx.blob.upload", "/api/v1/blob/upload"),
        ("cx.push.register_device", "/api/v1/push/register-device"),
        ("cx.keys.keypackages.claim", "/api/v1/keys/keypackages/claim"),
        ("cx.authz.check", "/api/v1/authz/check"),
        ("cx.policy.check", "/contrix/v1/check"),
        ("cx.mimi.room_update", "/api/v1/mimi/rooms/{flow_id}/update"),
        ("cx.account.issue_session_grant", "/api/v1/auth/account/session-grants"),
        ("cx.admin.revoke_device", "/api/v1/admin/devices/{device_id}/revoke"),
        ("cx.applet.transaction", "/api/v1/applet/transactions"),
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
    assert!(golden.iter().any(|vector| vector.profile == "cx.conformance.digest.v1"));
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
            |step| step.flow == ProtocolFixtureFlow::Blob && step.operation_id == "cx.blob.get"
        )
    );
    assert!(report.steps.iter().any(|step| {
        step.flow == ProtocolFixtureFlow::Sync && step.operation_id == "cx.events.submit"
    }));
}

#[test]
fn framework_independent_handler_shape_can_be_mocked() {
    struct MockHandler;

    impl EndpointHandler for MockHandler {
        fn handle(&mut self, request: ServerReqBody) -> Result<ServerResBody> {
            match request {
                ServerReqBody::ServerDescribe => {
                    Ok(ServerResBody::ServerDescription(ServerDescription {
                        service_did: contrix_core::Did::new("did:web:svc.example").unwrap(),
                        service_type: "principal_server".to_owned(),
                        protocol_version: contrix_core::PROTOCOL_VERSION.to_owned(),
                        supported_profiles: vec![],
                        supported_features: vec![],
                        supported_operations: service_routes()
                            .iter()
                            .map(|route| route.operation_id.to_owned())
                            .collect(),
                        supported_bindings: vec![],
                        supported_reducer_profiles: vec![],
                        supported_schema_profiles: vec![],
                        auth_metadata: Value::Null,
                        limits: Value::Null,
                        frontier: Vec::new(),
                        snapshot_frontier: Vec::new(),
                        reducer_profile: None,
                        last_materialized_at: None,
                    }))
                }
                _ => Err(contrix_core::Error::Protocol("mock endpoint not implemented".to_owned())),
            }
        }
    }

    let mut handler = MockHandler;
    let response = handler.handle(ServerReqBody::ServerDescribe).unwrap();
    let ServerResBody::ServerDescription(description) = response else {
        panic!("unexpected response");
    };
    assert!(description.supported_operations.contains(&"cx.sync.account".to_owned()));
}
