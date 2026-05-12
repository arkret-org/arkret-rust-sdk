use super::registry::endpoint_parameter_from_api;
use super::*;

#[test]
fn endpoint_operation_ids_are_unique() {
    let mut ids = BTreeSet::new();
    for endpoint in endpoint_contracts() {
        assert!(ids.insert(endpoint.operation_id), "duplicate {}", endpoint.operation_id);
        assert!(
            endpoint.path.starts_with("/api/v1/")
                || endpoint.path.starts_with("/contrix/v1/")
                || endpoint.path.starts_with("/.well-known/")
        );
    }
}

#[test]
fn server_endpoint_registry_delegates_to_api_catalog() {
    assert_eq!(endpoint_contracts().len(), api::endpoints().len());

    for endpoint in endpoint_contracts() {
        let api_endpoint =
            api::endpoint_by_operation(endpoint.operation_id).expect("endpoint exists in api");
        assert_eq!(endpoint.method, endpoint_method_from_api(api_endpoint.method));
        assert_eq!(endpoint.path, api_endpoint.path);
        assert_eq!(
            endpoint_schema_binding(endpoint),
            endpoint_schema_binding_from_api(api::endpoint_schema_binding(*api_endpoint))
        );
        assert_eq!(
            endpoint_parameters(endpoint),
            api::endpoint_parameters(*api_endpoint)
                .into_iter()
                .map(endpoint_parameter_from_api)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn endpoint_registry_matches_required_spec_operations() {
    let actual = endpoint_contracts()
        .iter()
        .map(|endpoint| (endpoint.operation_id, endpoint.path))
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
        ("cx.directory.resolve_handle", "/api/v1/directory/resolve-handle"),
        ("cx.directory.private_contact_discovery", "/api/v1/directory/private-contact-discovery"),
        ("cx.blob.upload", "/api/v1/blob/upload"),
        ("cx.push.register_device", "/api/v1/push/register-device"),
        ("cx.device_messages.put", "/api/v1/device_messages"),
        ("cx.keys.upload", "/api/v1/keys/upload"),
        ("cx.keys.keypackages.upload", "/api/v1/keys/keypackages/upload"),
        ("cx.keys.keypackages.claim", "/api/v1/keys/keypackages/claim"),
        ("cx.keys.keypackages.consume", "/api/v1/keys/keypackages/consume"),
        ("cx.keys.keypackages.revoke", "/api/v1/keys/keypackages/revoke"),
        ("cx.authz.check", "/api/v1/authz/check"),
        ("cx.policy.check", "/contrix/v1/check"),
        ("cx.media.ice_config", "/contrix/v1/ice-config"),
        ("cx.moderation.report", "/api/v1/moderation/report"),
        ("cx.mimi.provider_directory", "/api/v1/mimi/provider-directory"),
        ("cx.mimi.key_material", "/api/v1/mimi/key-material"),
        ("cx.mimi.room_update", "/api/v1/mimi/rooms/{flow_id}/update"),
        ("cx.mimi.notify", "/api/v1/mimi/rooms/{flow_id}/notify"),
        ("cx.mimi.submit_message", "/api/v1/mimi/rooms/{flow_id}/messages"),
        ("cx.mimi.group_info", "/api/v1/mimi/rooms/{flow_id}/group-info"),
        ("cx.mimi.request_consent", "/api/v1/mimi/consent/request"),
        ("cx.mimi.update_consent", "/api/v1/mimi/consent/update"),
        ("cx.mimi.identifier_query", "/api/v1/mimi/identifiers/query"),
        ("cx.mimi.report_abuse", "/api/v1/mimi/report-abuse"),
        ("cx.mimi.proxy_download", "/api/v1/mimi/proxy-download"),
        ("cx.account.issue_session_grant", "/api/v1/auth/account/session-grants"),
        ("cx.account.device_pair", "/api/v1/auth/account/device-pair"),
        ("cx.account.oidc_callback", "/api/v1/auth/account/oidc/callback"),
        ("cx.admin.get_server_status", "/api/v1/admin/server/status"),
        ("cx.admin.update_account_status", "/api/v1/admin/accounts/{account_id}/status"),
        ("cx.admin.revoke_device", "/api/v1/admin/devices/{device_id}/revoke"),
        ("cx.admin.get_moderation_queue", "/api/v1/admin/moderation/queue"),
        ("cx.applet.transaction", "/api/v1/applet/transactions"),
    ] {
        assert_eq!(actual.get(operation_id), Some(&path), "{operation_id}");
    }
}

#[test]
fn openapi_document_contains_standard_error_envelope() {
    let document = openapi_document();
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["x-contrix-source"], "spec-artifact");
    assert!(default_spec_openapi_path().is_some_and(|path| path.exists()));
    assert!(document["paths"]["/sync"]["post"]["responses"]["200"].is_object());
    assert!(document["components"]["schemas"]["ErrorEnvelope"].is_object());
    assert!(document["components"]["responses"]["RateLimited"].is_object());
    assert!(document["components"]["responses"]["MethodNotAllowed"].is_object());
    assert!(document["components"]["securitySchemes"].get("queryToken").is_none());
    assert!(document["components"]["securitySchemes"]["bearerAuth"].is_object());
    assert!(document["components"]["securitySchemes"]["httpMessageSignature"].is_object());
    assert!(document["components"]["securitySchemes"]["mutualTls"].is_object());
}

#[test]
fn openapi_document_has_operation_binding_for_every_endpoint() {
    let document = openapi_document();
    for endpoint in endpoint_contracts() {
        let path = endpoint.path.strip_prefix("/api/v1").unwrap_or(endpoint.path);
        assert_eq!(
            document["paths"][path][endpoint.method.as_str()]["operationId"],
            endpoint.operation_id,
            "{} {}",
            endpoint.method.as_str(),
            path
        );
    }
    assert!(document["paths"]["/events"]["post"]["requestBody"].is_object());
}

#[cfg(feature = "salvo")]
#[test]
fn openapi_document_still_uses_spec_artifact_with_salvo_feature() {
    let document = openapi_document();
    assert_eq!(document["x-contrix-source"], "spec-artifact");
    assert!(document["components"]["schemas"]["OperationRequest"].is_object());
}

#[test]
fn endpoint_matcher_routes_post_applet_transactions() {
    let matched = match_endpoint(EndpointMethod::Post, "/api/v1/applet/transactions").unwrap();
    assert_eq!(matched.contract.operation_id, "cx.applet.transaction");
    assert!(matched.path_parameters.is_empty());
    assert!(match_endpoint(EndpointMethod::Get, "/api/v1/applet/transactions").is_none());
}

#[test]
fn tower_like_endpoint_service_can_wrap_framework_closure() {
    let mut service = |request: HttpAdapterRequest| {
        let matched = match_endpoint(request.method, &request.path)
            .ok_or_else(|| contrix_core::Error::Protocol("no route".to_owned()))?;
        Ok(HttpAdapterResponse {
            status: 200,
            headers: BTreeMap::from([(
                "X-Contrix-Operation-Id".to_owned(),
                matched.contract.operation_id.to_owned(),
            )]),
            body: Vec::new(),
        })
    };

    let response = TowerLikeEndpointService::call(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(response.headers["X-Contrix-Operation-Id"], "cx.server.describe");
}

#[test]
fn routed_http_dispatch_matches_registry_for_idempotency_keyed_post() {
    let mut service = |request: RoutedHttpAdapterRequest| {
        assert_eq!(request.operation_id, "cx.applet.transaction");
        assert!(request.path_parameters.is_empty());
        assert_eq!(
            request.request.headers.get("Idempotency-Key").map(String::as_str),
            Some("txn_123"),
        );
        Ok(HttpAdapterResponse {
            status: 202,
            headers: BTreeMap::new(),
            body: request.request.body,
        })
    };

    let response = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Post,
            path: "/api/v1/applet/transactions".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Idempotency-Key".to_owned(), "txn_123".to_owned())]),
            body: br#"{"ok":true}"#.to_vec(),
        },
    );

    assert_eq!(response.status, 202);
    assert_eq!(response.headers["X-Contrix-Operation-Id"], "cx.applet.transaction");
    assert_eq!(response.body, br#"{"ok":true}"#);
}

#[test]
fn routed_http_dispatch_rejects_query_auth_and_unknown_routes() {
    use std::cell::Cell;

    let called = Cell::new(false);
    let mut service = |_request: RoutedHttpAdapterRequest| {
        called.set(true);
        Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
    };

    let rejected = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]),
            headers: BTreeMap::new(),
            body: Vec::new(),
        },
    );
    assert_eq!(rejected.status, 400);
    assert!(!called.get());

    let missing = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/nope".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        },
    );
    assert_eq!(missing.status, 404);
    assert!(!called.get());
}

#[test]
fn server_middleware_allows_public_describe_without_auth() {
    use std::cell::Cell;

    let called = Cell::new(false);
    let service = |_request: RoutedHttpAdapterRequest| {
        called.set(true);
        Ok(HttpAdapterResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: br#"{"ok":true}"#.to_vec(),
        })
    };
    let mut service = ServerMiddlewareStack::new(service);

    let response = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        },
    );

    assert_eq!(response.status, 200);
    assert!(called.get());
}

#[test]
fn server_middleware_requires_auth_for_private_operations() {
    use std::cell::Cell;

    let called = Cell::new(false);
    let service = |_request: RoutedHttpAdapterRequest| {
        called.set(true);
        Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
    };
    let mut service = ServerMiddlewareStack::new(service);

    let response = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Post,
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: br#"{}"#.to_vec(),
        },
    );

    assert_eq!(response.status, 401);
    assert!(!called.get());
}

#[test]
fn server_middleware_enforces_operation_scope_and_idempotency() {
    use std::cell::Cell;

    let calls = Cell::new(0);
    let service = |_request: RoutedHttpAdapterRequest| {
        let call = calls.get() + 1;
        calls.set(call);
        Ok(HttpAdapterResponse {
            status: 202,
            headers: BTreeMap::new(),
            body: format!("call-{call}").into_bytes(),
        })
    };
    let authenticator = BearerTokenAuthenticator::new().with_token(
        "sync-token",
        AuthenticatedPrincipal::bearer(
            "did:web:alice.example",
            ["operation:cx.sync.account".to_owned()],
        ),
    );
    let mut service = ServerMiddlewareStack::new(service).with_authenticator(authenticator);

    let request = || HttpAdapterRequest {
        method: EndpointMethod::Post,
        path: "/api/v1/sync".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::from([
            ("Authorization".to_owned(), "Bearer sync-token".to_owned()),
            ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
        ]),
        body: br#"{"since":"s1"}"#.to_vec(),
    };

    let first = dispatch_routed_http_request(&mut service, request());
    let second = dispatch_routed_http_request(&mut service, request());
    assert_eq!(first.status, 202);
    assert_eq!(second.status, 202);
    assert_eq!(first.body, b"call-1");
    assert_eq!(second.body, b"call-1");
    assert_eq!(calls.get(), 1);

    let conflict = dispatch_routed_http_request(
        &mut service,
        HttpAdapterRequest { body: br#"{"since":"s2"}"#.to_vec(), ..request() },
    );
    assert_eq!(conflict.status, 409);
    assert_eq!(calls.get(), 1);
}

#[test]
fn server_middleware_rejects_missing_scope_and_missing_idempotency_key() {
    let service = |_request: RoutedHttpAdapterRequest| {
        Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
    };
    let authenticator = BearerTokenAuthenticator::new().with_token(
        "wrong-token",
        AuthenticatedPrincipal::bearer(
            "did:web:alice.example",
            ["operation:cx.events.query".to_owned()],
        ),
    );
    let mut missing_scope = ServerMiddlewareStack::new(service).with_authenticator(authenticator);

    let forbidden = dispatch_routed_http_request(
        &mut missing_scope,
        HttpAdapterRequest {
            method: EndpointMethod::Post,
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), "Bearer wrong-token".to_owned()),
                ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
            ]),
            body: br#"{}"#.to_vec(),
        },
    );
    assert_eq!(forbidden.status, 403);

    let authenticator = BearerTokenAuthenticator::new().with_token(
        "sync-token",
        AuthenticatedPrincipal::bearer(
            "did:web:alice.example",
            ["operation:cx.sync.account".to_owned()],
        ),
    );
    let service = |_request: RoutedHttpAdapterRequest| {
        Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
    };
    let mut missing_idempotency =
        ServerMiddlewareStack::new(service).with_authenticator(authenticator);
    let rejected = dispatch_routed_http_request(
        &mut missing_idempotency,
        HttpAdapterRequest {
            method: EndpointMethod::Post,
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer sync-token".to_owned())]),
            body: br#"{}"#.to_vec(),
        },
    );
    assert_eq!(rejected.status, 428);
}

#[test]
fn server_middleware_rate_limits_before_service_call() {
    use std::cell::Cell;

    let calls = Cell::new(0);
    let service = |_request: RoutedHttpAdapterRequest| {
        calls.set(calls.get() + 1);
        Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
    };
    let mut service = ServerMiddlewareStack::new(service)
        .with_rate_limiter(MemoryRateLimiter::new(1, Duration::from_secs(60)));

    let request = || HttpAdapterRequest {
        method: EndpointMethod::Get,
        path: "/api/v1/server/describe".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        body: Vec::new(),
    };

    let first = dispatch_routed_http_request(&mut service, request());
    let second = dispatch_routed_http_request(&mut service, request());
    assert_eq!(first.status, 200);
    assert_eq!(second.status, 429);
    let retry_after = second.headers["Retry-After"].parse::<u64>().unwrap();
    assert!((1..=60).contains(&retry_after));
    assert_eq!(calls.get(), 1);
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
    assert!(report.steps.iter().any(|step| {
        step.flow == ProtocolFixtureFlow::Blob
            && step.operation_id == "cx.blob.get"
            && step.response_schema == "BinaryBlobBody"
    }));
    assert!(report.steps.iter().any(|step| {
        step.flow == ProtocolFixtureFlow::Sync && step.operation_id == "cx.events.submit"
    }));
}

#[test]
fn framework_independent_handler_shape_can_be_mocked() {
    struct MockHandler;

    impl EndpointHandler for MockHandler {
        fn handle(&mut self, request: ServerRequest) -> Result<ServerResponse> {
            match request {
                ServerRequest::ServerDescribe => {
                    Ok(ServerResponse::ServerDescription(ServerDescription {
                        service_did: contrix_core::Did::new("did:web:svc.example").unwrap(),
                        service_type: "principal_server".to_owned(),
                        protocol_version: contrix_core::PROTOCOL_VERSION.to_owned(),
                        supported_profiles: vec![],
                        supported_features: vec![],
                        supported_operations: endpoint_contracts()
                            .iter()
                            .map(|endpoint| endpoint.operation_id.to_owned())
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
    let response = handler.handle(ServerRequest::ServerDescribe).unwrap();
    let ServerResponse::ServerDescription(description) = response else {
        panic!("unexpected response");
    };
    assert!(description.supported_operations.contains(&"cx.sync.account".to_owned()));
}
