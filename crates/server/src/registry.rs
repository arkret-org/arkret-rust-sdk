use super::*;

static API_ENDPOINT_CONTRACTS: LazyLock<Vec<EndpointContract>> =
    LazyLock::new(|| api::endpoints().iter().copied().map(endpoint_contract_from_api).collect());

pub(super) fn endpoint_method_from_api(method: api::EndpointMethod) -> EndpointMethod {
    match method {
        api::EndpointMethod::Get => EndpointMethod::Get,
        api::EndpointMethod::Head => EndpointMethod::Head,
        api::EndpointMethod::Post => EndpointMethod::Post,
        api::EndpointMethod::Put => EndpointMethod::Put,
    }
}

fn endpoint_method_to_api(method: EndpointMethod) -> api::EndpointMethod {
    match method {
        EndpointMethod::Get => api::EndpointMethod::Get,
        EndpointMethod::Head => api::EndpointMethod::Head,
        EndpointMethod::Post => api::EndpointMethod::Post,
        EndpointMethod::Put => api::EndpointMethod::Put,
    }
}

fn endpoint_parameter_location_from_api(
    location: api::EndpointParameterLocation,
) -> EndpointParameterLocation {
    match location {
        api::EndpointParameterLocation::Path => EndpointParameterLocation::Path,
        api::EndpointParameterLocation::Query => EndpointParameterLocation::Query,
        api::EndpointParameterLocation::Header => EndpointParameterLocation::Header,
    }
}

fn endpoint_contract_from_api(endpoint: api::Endpoint) -> EndpointContract {
    EndpointContract {
        operation_id: endpoint.operation_id,
        method: endpoint_method_from_api(endpoint.method),
        path: endpoint.path,
    }
}

pub(super) fn endpoint_schema_binding_from_api(
    binding: api::EndpointSchemaBinding,
) -> EndpointSchemaBinding {
    EndpointSchemaBinding {
        operation_id: binding.operation_id,
        request_schema: binding.request_schema,
        response_schema: binding.response_schema,
        request_body_content_type: binding.request_body_content_type,
        response_body_content_type: binding.response_body_content_type,
    }
}

pub(super) fn endpoint_parameter_from_api(parameter: api::EndpointParameter) -> EndpointParameter {
    EndpointParameter {
        name: parameter.name,
        location: endpoint_parameter_location_from_api(parameter.location),
        required: parameter.required,
        schema: parameter.schema,
    }
}

fn api_endpoint_for_contract(endpoint: &EndpointContract) -> api::Endpoint {
    let api_endpoint = api::endpoint_by_operation(endpoint.operation_id)
        .unwrap_or_else(|| panic!("missing api endpoint {}", endpoint.operation_id));
    debug_assert_eq!(endpoint.path, api_endpoint.path);
    debug_assert_eq!(endpoint.method, endpoint_method_from_api(api_endpoint.method));
    *api_endpoint
}

pub fn endpoint_contracts() -> &'static [EndpointContract] {
    API_ENDPOINT_CONTRACTS.as_slice()
}

pub fn endpoint_schema_bindings() -> Vec<EndpointSchemaBinding> {
    endpoint_contracts().iter().map(endpoint_schema_binding).collect()
}

pub fn endpoint_schema_binding(endpoint: &EndpointContract) -> EndpointSchemaBinding {
    endpoint_schema_binding_from_api(api::endpoint_schema_binding(api_endpoint_for_contract(
        endpoint,
    )))
}

pub fn endpoint_parameters(endpoint: &EndpointContract) -> Vec<EndpointParameter> {
    api::endpoint_parameters(api_endpoint_for_contract(endpoint))
        .into_iter()
        .map(endpoint_parameter_from_api)
        .collect()
}

pub fn match_endpoint(method: EndpointMethod, path: &str) -> Option<MatchedEndpoint<'static>> {
    api::match_endpoint(endpoint_method_to_api(method), path).map(|matched| MatchedEndpoint {
        contract: endpoint_contracts()
            .iter()
            .find(|endpoint| endpoint.operation_id == matched.endpoint.operation_id)
            .unwrap_or_else(|| panic!("missing server endpoint {}", matched.endpoint.operation_id)),
        path_parameters: matched.path_parameters,
    })
}

pub fn reject_query_auth(parameters: &BTreeMap<String, String>) -> Result<()> {
    for name in parameters.keys() {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "access_token"
                | "auth"
                | "authorization"
                | "bearer"
                | "device_proof"
                | "service_signature"
                | "signature"
        ) {
            return Err(contrix_core::Error::Protocol(
                "authentication material must be sent in headers, not query parameters".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn protocol_golden_vectors() -> Vec<ProtocolGoldenVector> {
    vec![
        ProtocolGoldenVector {
            name: "cursor_prefix".to_owned(),
            profile: "cx.conformance.cursor.v1".to_owned(),
            input: json!({"cursor": "cx:cursor:sync:01JS0SP000000000000000000"}),
            expected: json!({"valid": true}),
        },
        ProtocolGoldenVector {
            name: "canonical_digest_prefix".to_owned(),
            profile: "cx.conformance.digest.v1".to_owned(),
            input: json!({"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}),
            expected: json!({"valid": true, "algorithm": "sha256"}),
        },
        ProtocolGoldenVector {
            name: "canonical_json_object_order".to_owned(),
            profile: "cx.conformance.canonical_json.v1".to_owned(),
            input: json!({"b": 2, "a": 1}),
            expected: json!({"canonical": "{\"a\":1,\"b\":2}"}),
        },
        ProtocolGoldenVector {
            name: "hlc_shape".to_owned(),
            profile: "cx.conformance.hlc.v1".to_owned(),
            input: json!({"hlc": "2026-04-29T00:00:00.000Z-0000-node"}),
            expected: json!({"valid": true, "monotonic_components": ["wall_time", "counter", "node"]}),
        },
    ]
}

pub fn wire_negative_vectors() -> Vec<WireConformanceVector> {
    vec![
        WireConformanceVector {
            name: "query_auth_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::from([("access_token".to_owned(), "redacted".to_owned())]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 400,
            expected_errcode: "cx.error.query_auth_forbidden".to_owned(),
        },
        WireConformanceVector {
            name: "encoded_path_separator_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/federation/transactions/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_path_segment".to_owned(),
        },
        WireConformanceVector {
            name: "identity_invalid_did_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/identity/resolve".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"did": "alice.example"}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "sync_stale_cursor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"since": "cx:cursor:expired"}),
            expected_status: 410,
            expected_errcode: "cx.error.stale_cursor".to_owned(),
        },
        WireConformanceVector {
            name: "directory_invalid_handle_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/directory/resolve-handle".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"handle": ""}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_request".to_owned(),
        },
        WireConformanceVector {
            name: "stale_cursor_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/federation/pull-operations".to_owned(),
            query: BTreeMap::from([
                ("space_id".to_owned(), "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                ("after_cursor".to_owned(), "cx:cursor:expired".to_owned()),
            ]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 410,
            expected_errcode: "cx.error.stale_cursor".to_owned(),
        },
        WireConformanceVector {
            name: "bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/blob/upload".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Digest".to_owned(), "sha256:not-hex".to_owned())]),
            body: json!({"size": 4}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_digest".to_owned(),
        },
        WireConformanceVector {
            name: "push_bad_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/push/register-device".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer ".to_owned())]),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "device_messages_invalid_txn_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/device_messages/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"messages": {}}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_path_segment".to_owned(),
        },
        WireConformanceVector {
            name: "keys_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/keys/query".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({"device_keys": {}}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "authz_invalid_actor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/authz/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"actor_id": "alice", "action": "read", "resource": {}}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "policy_bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"request_canonical_hash": "sha256:not-hex"}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_digest".to_owned(),
        },
        WireConformanceVector {
            name: "media_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/ice-config".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "moderation_invalid_space_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/moderation/report".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"space_id": "room", "target_ref": "x", "reason": "spam", "reporter": "did:web:alice.example"}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "applet_missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/applet/transactions".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_errcode: "cx.error.idempotency_required".to_owned(),
        },
        WireConformanceVector {
            name: "missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_errcode: "cx.error.idempotency_required".to_owned(),
        },
        WireConformanceVector {
            name: "idempotency_conflict_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), "Bearer redacted".to_owned()),
                ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
            ]),
            body: json!({"conflict": true}),
            expected_status: 409,
            expected_errcode: "cx.error.idempotency_conflict".to_owned(),
        },
    ]
}
