use super::*;
use crate::registry::service_routes;

#[test]
fn query_auth_and_wire_negative_vectors_are_available() {
    let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
    assert!(reject_query_auth(&query).is_err());

    let vectors = wire_negative_vectors();
    assert!(
        vectors
            .iter()
            .any(|vector| vector.name == "query_auth_rejected")
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.expected_error_code == "digest_mismatch")
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.expected_error_code == "missing_param")
    );

    let golden = protocol_golden_vectors();
    assert!(
        golden
            .iter()
            .any(|vector| vector.profile == "ck.conformance.digest.v1")
    );
}

#[test]
fn protocol_golden_vectors_pass_real_validators() {
    for vector in protocol_golden_vectors() {
        match vector.profile.as_str() {
            "ck.conformance.cursor.v1" => {
                let token = vector.input["cursor"]
                    .as_str()
                    .expect("cursor vector input");
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
        report
            .steps
            .iter()
            .any(|step| step.flow == ProtocolFixtureFlow::Blob
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
                ServerRequestBody::ServerDescribe => Ok(ServerOutcome::ServerDescription(
                    Box::new(ServerDescription {
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
                    }),
                )),
                _ => Err(cokret_core::Error::Protocol(
                    "mock endpoint not implemented".to_owned(),
                )),
            }
        }
    }

    let mut handler = MockHandler;
    let response = handler.handle(ServerRequestBody::ServerDescribe).unwrap();
    let ServerOutcome::ServerDescription(description) = response else {
        panic!("unexpected response");
    };
    assert!(
        description
            .supported_operations
            .contains(&"ck.self.account.subscribe".to_owned())
    );
}
