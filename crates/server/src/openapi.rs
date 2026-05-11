use super::*;

pub fn openapi_document() -> Value {
    let mut paths = Map::new();
    for endpoint in endpoint_contracts() {
        let binding = endpoint_schema_binding(endpoint);
        let mut methods = paths
            .remove(endpoint.path)
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();

        let mut operation = Map::new();
        operation.insert("operationId".to_owned(), json!(endpoint.operation_id));
        operation.insert("tags".to_owned(), json!([endpoint_tag(endpoint.operation_id)]));
        operation.insert(
            "x-contrix-request-schema".to_owned(),
            json!(format!("#/components/schemas/{}", binding.request_schema)),
        );
        operation.insert(
            "x-contrix-response-schema".to_owned(),
            json!(format!("#/components/schemas/{}", binding.response_schema)),
        );
        operation.insert("security".to_owned(), operation_security(endpoint.operation_id));
        operation.insert(
            "parameters".to_owned(),
            Value::Array(
                endpoint_parameters(endpoint).into_iter().map(openapi_parameter).collect(),
            ),
        );

        if let Some(content_type) = binding.request_body_content_type {
            operation.insert(
                "requestBody".to_owned(),
                openapi_request_body(content_type, binding.request_schema, endpoint.operation_id),
            );
        }

        operation.insert(
            "responses".to_owned(),
            openapi_responses(binding.response_body_content_type, binding.response_schema),
        );

        methods.insert(endpoint.method.as_str().to_owned(), Value::Object(operation));
        paths.insert(endpoint.path.to_owned(), Value::Object(methods));
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Contrix v1 Service HTTP Binding",
            "version": "1.0"
        },
        "paths": paths,
        "components": {
            "schemas": openapi_schema_components(),
            "responses": openapi_response_components(),
            "parameters": openapi_parameter_components(),
            "examples": openapi_examples(),
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" },
                "bearerAuth": { "type": "http", "scheme": "bearer" },
                "deviceProof": { "type": "apiKey", "in": "header", "name": "X-Contrix-Device-Proof" },
                "serviceSignature": { "type": "apiKey", "in": "header", "name": "Signature" },
                "httpMessageSignature": { "type": "apiKey", "in": "header", "name": "Signature" },
                "mutualTls": { "type": "mutualTLS" }
            }
        }
    })
}

fn endpoint_tag(operation_id: &str) -> &str {
    operation_id
        .strip_prefix("cx.")
        .and_then(|rest| rest.split_once('.').map(|(tag, _)| tag))
        .unwrap_or("core")
}

fn operation_security(operation_id: &str) -> Value {
    if matches!(
        operation_id,
        "cx.server.describe"
            | "cx.identity.describe_registry"
            | "cx.sync.describe"
            | "cx.directory.describe"
            | "cx.applet.ping"
            | "cx.applet.describe"
    ) {
        json!([{}])
    } else {
        json!([{ "bearer": [] }, { "deviceProof": [] }, { "serviceSignature": [] }])
    }
}

fn openapi_parameter(parameter: EndpointParameter) -> Value {
    let schema = parameter_schema(parameter.schema);
    json!({
        "name": parameter.name,
        "in": parameter.location.as_str(),
        "required": parameter.required,
        "schema": schema
    })
}

fn parameter_schema(name: &str) -> Value {
    match name {
        "Bool" => json!({ "type": "boolean" }),
        "Limit" => json!({ "type": "integer", "minimum": 1, "maximum": 1000 }),
        "String" => json!({ "type": "string" }),
        _ => json!({ "$ref": format!("#/components/schemas/{name}") }),
    }
}

fn openapi_request_body(content_type: &str, schema: &str, operation_id: &str) -> Value {
    if operation_id == "cx.blob.upload" {
        return json!({
            "required": true,
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/BlobUploadMetadata" },
                    "examples": {
                        "blobUpload": { "$ref": "#/components/examples/BlobUploadMetadata" }
                    }
                },
                "application/octet-stream": {
                    "schema": { "$ref": "#/components/schemas/BinaryBlobBody" }
                }
            }
        });
    }

    let mut content = Map::new();
    let mut media = Map::new();
    media.insert("schema".to_owned(), json!({ "$ref": format!("#/components/schemas/{schema}") }));

    if let Some(example) = request_example_ref(operation_id) {
        media.insert("examples".to_owned(), json!({ "default": { "$ref": example } }));
    }

    content.insert(content_type.to_owned(), Value::Object(media));
    json!({ "required": true, "content": content })
}

fn openapi_responses(content_type: Option<&str>, schema: &str) -> Value {
    let success = if let Some(content_type) = content_type {
        json!({
            "description": "Successful Contrix response",
            "content": {
                content_type: {
                    "schema": { "$ref": format!("#/components/schemas/{schema}") }
                }
            }
        })
    } else {
        json!({ "description": "Successful Contrix response with headers only" })
    };

    json!({
        "200": success,
        "400": { "$ref": "#/components/responses/BadRequestError" },
        "401": { "$ref": "#/components/responses/UnauthorizedError" },
        "403": { "$ref": "#/components/responses/ForbiddenError" },
        "404": { "$ref": "#/components/responses/NotFoundPrivacyError" },
        "405": { "$ref": "#/components/responses/MethodNotAllowedError" },
        "409": { "$ref": "#/components/responses/IdempotencyConflictError" },
        "410": { "$ref": "#/components/responses/StaleCursorError" },
        "428": { "$ref": "#/components/responses/IdempotencyRequiredError" },
        "429": { "$ref": "#/components/responses/RateLimitedError" },
        "503": { "$ref": "#/components/responses/UnavailableError" }
    })
}

fn openapi_schema_components() -> Value {
    let mut schema_names = BTreeSet::from([
        "ApiConventionMetadata",
        "BinaryBlobBody",
        "BlobMetadataHeaders",
        "Bool",
        "Did",
        "ErrorEnvelope",
        "Hash",
        "HttpMessageSignature",
        "HttpTraceMetadata",
        "JsonValue",
        "Limit",
        "QuotaMetadata",
        "RateLimitMetadata",
        "ServiceDidAllowlist",
        "SpaceId",
        "String",
        "WellKnownContrixServer",
    ]);

    for binding in endpoint_schema_bindings() {
        schema_names.insert(binding.request_schema);
        schema_names.insert(binding.response_schema);
    }

    let mut schemas = openapi_seeded_schema_components();
    for name in schema_names {
        schemas.entry(name.to_owned()).or_insert_with(|| generic_schema(name));
    }

    schemas.insert("Did".to_owned(), json!({ "type": "string", "pattern": "^did:[a-z0-9]+:.+$" }));
    schemas.insert("SpaceId".to_owned(), json!({ "type": "string", "pattern": "^cx:space:.+$" }));
    schemas
        .insert("Hash".to_owned(), json!({ "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }));
    schemas.insert("String".to_owned(), json!({ "type": "string" }));
    schemas.insert("Bool".to_owned(), json!({ "type": "boolean" }));
    schemas.insert("Limit".to_owned(), json!({ "type": "integer", "minimum": 1, "maximum": 1000 }));
    schemas.insert(
        "JsonValue".to_owned(),
        json!({ "description": "Arbitrary JSON value accepted by extension points" }),
    );
    schemas.insert("BinaryBlobBody".to_owned(), json!({ "type": "string", "format": "binary" }));
    schemas.insert(
        "ErrorEnvelope".to_owned(),
        json!({
            "type": "object",
            "required": ["errcode", "error"],
            "properties": {
                "errcode": { "type": "string" },
                "error": { "type": "string" },
                "retry_after_ms": { "type": "integer", "minimum": 0 },
                "trace": { "$ref": "#/components/schemas/HttpTraceMetadata" },
                "rate_limit": { "$ref": "#/components/schemas/RateLimitMetadata" },
                "quota": { "$ref": "#/components/schemas/QuotaMetadata" }
            },
            "additionalProperties": true
        }),
    );
    schemas.insert(
        "ServerDescription".to_owned(),
        json!({
            "type": "object",
            "required": ["service_did", "service_type", "protocol_version"],
            "properties": {
                "service_did": { "$ref": "#/components/schemas/Did" },
                "service_type": { "type": "string" },
                "protocol_version": { "type": "string" },
                "supported_operations": { "type": "array", "items": { "type": "string" } },
                "auth_metadata": { "$ref": "#/components/schemas/JsonValue" },
                "limits": { "$ref": "#/components/schemas/JsonValue" }
            },
            "additionalProperties": true
        }),
    );
    schemas.insert(
        "FederationTransactionRequest".to_owned(),
        json!({
            "type": "object",
            "required": ["origin", "destination", "service_binding_ref", "operations"],
            "properties": {
                "origin": { "$ref": "#/components/schemas/Did" },
                "destination": { "$ref": "#/components/schemas/Did" },
                "service_binding_ref": { "type": "string" },
                "operations": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "receipts": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "frontier": { "type": "string" }
            },
            "additionalProperties": false
        }),
    );
    schemas.insert(
        "HttpTraceMetadata".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "request_id": { "type": "string" },
                "actor_id": { "$ref": "#/components/schemas/Did" },
                "device_id": { "type": "string" },
                "space_id": { "$ref": "#/components/schemas/SpaceId" },
                "operation_id": { "type": "string" }
            },
            "additionalProperties": false
        }),
    );

    Value::Object(schemas)
}

fn openapi_seeded_schema_components() -> Map<String, Value> {
    #[cfg(feature = "salvo")]
    {
        if let Ok(Value::Object(schemas)) =
            serde_json::to_value(salvo_adapter::contrix_oapi_components().schemas)
        {
            return schemas;
        }
    }

    Map::new()
}

fn generic_schema(name: &str) -> Value {
    json!({
        "type": "object",
        "description": format!("Contrix SDK model {name}. Field-level validation lives in the Rust type and protocol validators."),
        "x-contrix-rust-type": name,
        "additionalProperties": true
    })
}

fn openapi_response_components() -> Value {
    let error_response = |description: &str, example: &str| {
        json!({
            "description": description,
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorEnvelope" },
                    "examples": {
                        "default": { "$ref": format!("#/components/examples/{example}") }
                    }
                }
            }
        })
    };

    json!({
        "BadRequestError": error_response("Malformed request or protocol validation failure", "BadRequestError"),
        "UnauthorizedError": error_response("Authentication is missing or invalid", "UnauthorizedError"),
        "ForbiddenError": error_response("Authenticated principal is not authorized", "ForbiddenError"),
        "NotFoundPrivacyError": error_response("Resource is nonexistent or invisible under privacy-preserving not-found semantics", "NotFoundPrivacyError"),
        "MethodNotAllowedError": error_response("HTTP method is not registered for this endpoint", "MethodNotAllowedError"),
        "IdempotencyConflictError": error_response("Idempotency-Key was reused with different request bytes", "IdempotencyConflictError"),
        "StaleCursorError": error_response("Cursor is expired or no longer replayable", "StaleCursorError"),
        "IdempotencyRequiredError": error_response("Mutating endpoint requires Idempotency-Key", "IdempotencyRequiredError"),
        "RateLimitedError": error_response("Request was rate limited", "RateLimitedError"),
        "UnavailableError": error_response("Service is temporarily unavailable", "UnavailableError"),
        "ErrorEnvelope": error_response("Standard Contrix error envelope", "BadRequestError")
    })
}

fn openapi_parameter_components() -> Value {
    json!({
        "RequestId": {
            "name": "X-Contrix-Request-Id",
            "in": "header",
            "required": false,
            "schema": { "type": "string" }
        },
        "Traceparent": {
            "name": "Traceparent",
            "in": "header",
            "required": false,
            "schema": { "type": "string" }
        }
    })
}

fn openapi_examples() -> Value {
    json!({
        "ServerDescription": {
            "summary": "Principal service description",
            "value": {
                "service_did": "did:web:svc.example",
                "service_type": "principal_server",
                "protocol_version": contrix_core::PROTOCOL_VERSION,
                "supported_operations": ["cx.server.describe", "cx.sync.account"]
            }
        },
        "SyncRequest": {
            "summary": "Incremental sync request",
            "value": {
                "since": "cx:cursor:sync:01JS0SP000000000000000000",
                "space_ids": ["cx:space:01904100-0000-7000-8000-9b64700c6ee8"],
                "timeout_ms": 30000
            }
        },
        "FederationTransactionRequest": {
            "summary": "Federated operation transaction",
            "value": {
                "origin": "did:web:a.example",
                "destination": "did:web:b.example",
                "service_binding_ref": "did:web:a.example#contrix-federation",
                "operations": [],
                "frontier": "cx:cursor:federation:01JS0SP000000000000000000"
            }
        },
        "BlobUploadMetadata": {
            "summary": "Blob upload metadata",
            "value": {
                "space_id": "cx:space:01904100-0000-7000-8000-9b64700c6ee8",
                "size": 4,
                "media_type": "text/plain",
                "sha256": "sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
            }
        },
        "BadRequestError": {
            "value": { "errcode": "cx.error.bad_request", "error": "Malformed Contrix request" }
        },
        "UnauthorizedError": {
            "value": { "errcode": "cx.error.unauthorized", "error": "Authentication required" }
        },
        "ForbiddenError": {
            "value": { "errcode": "cx.error.forbidden", "error": "Not authorized" }
        },
        "NotFoundPrivacyError": {
            "value": { "errcode": "cx.error.not_found", "error": "Resource not found" }
        },
        "MethodNotAllowedError": {
            "value": { "errcode": "cx.error.method_not_allowed", "error": "Method not allowed" }
        },
        "IdempotencyConflictError": {
            "value": { "errcode": "cx.error.idempotency_conflict", "error": "Idempotency-Key was reused with different request bytes" }
        },
        "StaleCursorError": {
            "value": { "errcode": "cx.error.stale_cursor", "error": "Cursor is expired" }
        },
        "IdempotencyRequiredError": {
            "value": { "errcode": "cx.error.idempotency_required", "error": "Mutating Contrix endpoints require Idempotency-Key" }
        },
        "RateLimitedError": {
            "value": {
                "errcode": "cx.error.rate_limited",
                "error": "Too many requests",
                "retry_after_ms": 1000,
                "rate_limit": { "scope": "actor", "limit": 60, "remaining": 0 }
            }
        },
        "UnavailableError": {
            "value": { "errcode": "cx.error.unavailable", "error": "Service unavailable" }
        }
    })
}

fn request_example_ref(operation_id: &str) -> Option<&'static str> {
    match operation_id {
        "cx.sync.account" => Some("#/components/examples/SyncRequest"),
        "cx.blob.upload" => Some("#/components/examples/BlobUploadMetadata"),
        _ => None,
    }
}
