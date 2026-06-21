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
fn protocol_server_fixture_covers_core_strand_groups() {
    let report = ProtocolServerFixture::default().run().unwrap();

    for strand in [
        ProtocolFixtureStrand::Server,
        ProtocolFixtureStrand::Identity,
        ProtocolFixtureStrand::Sync,
        ProtocolFixtureStrand::Blob,
        ProtocolFixtureStrand::Authz,
        ProtocolFixtureStrand::Directory,
        ProtocolFixtureStrand::Push,
        ProtocolFixtureStrand::DeviceMessages,
        ProtocolFixtureStrand::Keys,
        ProtocolFixtureStrand::Policy,
        ProtocolFixtureStrand::Media,
        ProtocolFixtureStrand::Moderation,
        ProtocolFixtureStrand::Applet,
    ] {
        assert!(report.covers(strand));
    }
    assert!(
        report
            .steps
            .iter()
            .any(|step| step.strand == ProtocolFixtureStrand::Blob
                && step.operation_id == "ck.self.blob.resource.get")
    );
    assert!(report.steps.iter().any(|step| {
        step.strand == ProtocolFixtureStrand::Sync
            && step.operation_id == "ck.self.events.command.submit"
    }));
}

#[test]
fn service_routes_match_embedded_operation_registry() {
    let registry = cokret_core::schema::SpecArtifactBundle::load_embedded()
        .unwrap()
        .operation_registry;
    let expected: Vec<(String, String, String)> = registry
        .get("operations")
        .and_then(Value::as_array)
        .expect("operation registry missing operations")
        .iter()
        .map(|operation| {
            let operation_id = operation
                .get("operation_id")
                .and_then(Value::as_str)
                .expect("operation missing operation_id");
            let http = operation
                .get("http")
                .and_then(Value::as_str)
                .expect("operation missing http binding");
            let (method, path) = http
                .split_once(' ')
                .expect("operation http binding must be '<METHOD> <path>'");
            (
                operation_id.to_owned(),
                method.to_ascii_lowercase(),
                path.to_owned(),
            )
        })
        .collect();
    let actual: Vec<(String, String, String)> = service_routes()
        .iter()
        .map(|route| {
            (
                route.operation_id.to_owned(),
                route.method.to_owned(),
                route.path.to_owned(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
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
                        auth_metadata: cokret_core::AuthMetadata::minimal("development"),
                        limits: Value::Null,
                        plaintext_visibility: cokret_core::PlaintextVisibility::none(),
                        privacy_derivation: None,
                        receive_policy_constraints: None,
                        implemented_features: vec![],
                        claimed_profiles: vec![],
                        verified_profiles: vec![],
                        experimental_features: vec![],
                        compat_surfaces: vec![],
                        development_mode: false,
                        rate_limit_policy: Some(cokret_core::RateLimitPolicy::unspecified()),
                        rate_limit_policy_id: None,
                        egress_network_policy: Some(
                            cokret_core::EgressNetworkPolicy::deny_private_defaults(),
                        ),
                        resource_types: vec![],
                        discovery_profiles: vec![],
                        restricted_query_proof: None,
                        ingest_modes: vec![],
                        accept_policy_kind: None,
                        accept_policy_ref: None,
                        default_ttl_seconds: None,
                        max_ttl_seconds: None,
                        revalidation_grace_seconds: None,
                        accepted_resource_kinds: vec![],
                        accepted_did_methods: vec![],
                        takedown_contact: None,
                        rate_limits: None,
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
            .contains(&"ck.self.account.stream.subscribe".to_owned())
    );
}
