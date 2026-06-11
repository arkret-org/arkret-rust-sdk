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
            // trust-circle name (self/gate/root/find/peer/open/edge),
            // per cokret-spec service-http-binding.md §2.1.
            route.path.starts_with("/_cokret/") || route.path.starts_with("/.well-known/"),
            "unexpected route namespace: {} ({})",
            route.path,
            route.operation_id,
        );
    }
}

/// Bidirectional drift guard: `SERVICE_ROUTES` must be exactly equal — by
/// operation_id, method, and path — to the `http` bindings of the canonical
/// spec operation registry (same discipline as the
/// `core_registry_matches_spec_operation_registry_when_available` test in
/// cokret-contracts).
#[test]
fn service_routes_match_spec_operation_registry() {
    let registry = read_spec_artifact("registry/operation-registry.json");
    let spec_routes = registry
        .get("operations")
        .and_then(Value::as_array)
        .expect("operation registry has an operations array")
        .iter()
        .map(|operation| {
            let operation_id = operation
                .get("operation_id")
                .and_then(Value::as_str)
                .expect("operation without operation_id");
            let http = operation
                .get("http")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("operation {operation_id} without http binding"));
            let (method, path) =
                http.split_once(' ').unwrap_or_else(|| panic!("malformed http binding {http}"));
            (operation_id, (method.to_ascii_lowercase(), path))
        })
        .collect::<BTreeMap<_, _>>();
    let sdk_routes = service_routes()
        .iter()
        .map(|route| (route.operation_id, (route.method.to_owned(), route.path)))
        .collect::<BTreeMap<_, _>>();

    let missing_from_sdk = spec_routes
        .keys()
        .filter(|operation_id| !sdk_routes.contains_key(*operation_id))
        .collect::<Vec<_>>();
    let extra_in_sdk = sdk_routes
        .keys()
        .filter(|operation_id| !spec_routes.contains_key(*operation_id))
        .collect::<Vec<_>>();
    assert!(missing_from_sdk.is_empty(), "service routes missing spec ops {missing_from_sdk:?}");
    assert!(extra_in_sdk.is_empty(), "service routes outside spec registry {extra_in_sdk:?}");

    for (operation_id, spec_binding) in &spec_routes {
        assert_eq!(
            sdk_routes.get(operation_id),
            Some(spec_binding),
            "http binding drift for {operation_id}"
        );
    }
}

/// Negative drift guard: operation ids removed from the canonical registry
/// (`hard_reject` and friends) must never reappear in the route table.
#[test]
fn service_routes_exclude_removed_operation_ids() {
    let removed = read_spec_artifact("../migration/removed-operation-ids.json");
    let removed_ids = removed
        .get("entries")
        .and_then(Value::as_array)
        .expect("removed-operation-ids has an entries array")
        .iter()
        .map(|entry| entry.get("id").and_then(Value::as_str).expect("entry without id"))
        .collect::<BTreeSet<_>>();
    for route in service_routes() {
        assert!(
            !removed_ids.contains(route.operation_id),
            "removed operation id {} is still advertised in service routes",
            route.operation_id
        );
    }
}

fn read_spec_artifact(relative: &str) -> Value {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = [
        manifest_dir.join("../../../cokret-spec/spec/v1/artifacts/registry").join(relative),
        std::path::PathBuf::from("../cokret-spec/spec/v1/artifacts/registry").join(relative),
    ]
    .into_iter()
    .find(|path| path.exists())
    .unwrap_or_else(|| {
        panic!(
            "spec artifact {relative} is required for drift tests; looked next to {}",
            manifest_dir.display()
        )
    });
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
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
fn protocol_golden_vectors_pass_real_validators() {
    for vector in protocol_golden_vectors() {
        match vector.profile.as_str() {
            "ck.conformance.cursor.v1" => {
                let token = vector.input["cursor"].as_str().expect("cursor vector input");
                cokret_core::Cursor::decode(token)
                    .unwrap_or_else(|err| panic!("golden cursor vector must decode: {err}"));
            }
            "ck.conformance.hlc.v1" => {
                let hlc = vector.input["hlc"].as_str().expect("hlc vector input");
                cokret_core::Hlc::new(hlc)
                    .unwrap_or_else(|err| panic!("golden HLC vector must validate: {err}"));
            }
            _ => {}
        }
    }
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
        report.steps.iter().any(|step| step.flow == ProtocolFixtureFlow::Blob
            && step.operation_id == "ck.self.blob.get")
    );
    assert!(report.steps.iter().any(|step| {
        step.flow == ProtocolFixtureFlow::Sync && step.operation_id == "ck.self.events.submit"
    }));
}

#[test]
fn framework_independent_handler_shape_can_be_mocked() {
    struct MockHandler;

    impl EndpointHandler for MockHandler {
        fn handle(&mut self, request: ServerRequestBody) -> Result<ServerOutcome> {
            match request {
                ServerRequestBody::ServerDescribe => {
                    Ok(ServerOutcome::ServerDescription(Box::new(ServerDescription {
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
    let response = handler.handle(ServerRequestBody::ServerDescribe).unwrap();
    let ServerOutcome::ServerDescription(description) = response else {
        panic!("unexpected response");
    };
    assert!(description.supported_operations.contains(&"ck.self.account.subscribe".to_owned()));
}
